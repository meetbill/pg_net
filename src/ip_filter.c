#include <arpa/inet.h>
#include <string.h>

#include "pg_prelude.h"

#include "curl_prelude.h"

#include "core.h"
#include "ip_filter.h"

char *guc_allowed_cidrs = NULL;
char *guc_blocked_cidrs = NULL;

typedef struct {
  int     family;     // AF_INET or AF_INET6
  uint8_t addr[16];   // network bytes, already masked to prefix_len
  int     prefix_len; // number of significant leading bits
} CidrEntry;

typedef struct {
  CidrEntry *entries;
  int        count;
} CidrList;

// Parsed lists live for the lifetime of the process and are swapped on SIGHUP.
// They use malloc/free rather than palloc because their lifetime is not tied
// to any PostgreSQL memory context.
static CidrList allowed_list = {NULL, 0};
static CidrList blocked_list = {NULL, 0};

// Parse a single IP string into (family, 16-byte buffer). Handles IPv4,
// IPv6 and IPv4-mapped IPv6 (::ffff:a.b.c.d), normalizing the latter to
// plain IPv4 so a match against an IPv4 CIDR still succeeds.
static bool parse_ip(const char *ip, int *family, uint8_t addr[16]) {
  struct in_addr  v4;
  struct in6_addr v6;

  if (inet_pton(AF_INET, ip, &v4) == 1) {
    *family = AF_INET;
    memcpy(addr, &v4, 4);
    return true;
  }

  if (inet_pton(AF_INET6, ip, &v6) == 1) {
    if (IN6_IS_ADDR_V4MAPPED(&v6)) {
      *family = AF_INET;
      memcpy(addr, &v6.s6_addr[12], 4);
      return true;
    }
    *family = AF_INET6;
    memcpy(addr, &v6, 16);
    return true;
  }

  return false;
}

// Mask `addr` in place so only the leading `prefix_len` bits survive.
static void mask_addr(uint8_t addr[16], int family, int prefix_len) {
  int total_bytes = (family == AF_INET) ? 4 : 16;
  int full_bytes  = prefix_len / 8;
  int rem_bits    = prefix_len % 8;

  if (full_bytes < total_bytes) {
    if (rem_bits > 0) {
      uint8_t mask     = (uint8_t)(0xFFu << (8 - rem_bits));
      addr[full_bytes] = addr[full_bytes] & mask;
      full_bytes++;
    }
    for (int i = full_bytes; i < total_bytes; i++) {
      addr[i] = 0;
    }
  }
}

// Parse one CIDR of the form "ip" or "ip/prefix". Returns true on success.
static bool parse_cidr(const char *spec, CidrEntry *out, char *err, size_t err_len) {
  char  buf[80];
  char *slash;
  int   prefix_len;
  int   family;

  if (spec == NULL) return false;

  while (*spec == ' ' || *spec == '\t') spec++;

  size_t len = strlen(spec);
  while (len > 0 && (spec[len - 1] == ' ' || spec[len - 1] == '\t')) len--;
  if (len == 0 || len >= sizeof(buf)) {
    if (err) snprintf(err, err_len, "empty or overlong CIDR entry");
    return false;
  }

  memcpy(buf, spec, len);
  buf[len] = '\0';

  slash = strchr(buf, '/');
  if (slash) {
    char *endptr;
    *slash     = '\0';
    prefix_len = (int)strtol(slash + 1, &endptr, 10);
    if (*(slash + 1) == '\0' || *endptr != '\0' || prefix_len < 0) {
      if (err) snprintf(err, err_len, "invalid prefix in \"%s\"", spec);
      return false;
    }
  } else {
    prefix_len = -1;
  }

  uint8_t addr[16] = {0};
  if (!parse_ip(buf, &family, addr)) {
    if (err) snprintf(err, err_len, "invalid IP in \"%s\"", spec);
    return false;
  }

  int max_prefix = (family == AF_INET) ? 32 : 128;
  if (prefix_len < 0) prefix_len = max_prefix;
  if (prefix_len > max_prefix) {
    if (err) snprintf(err, err_len, "prefix out of range in \"%s\"", spec);
    return false;
  }

  mask_addr(addr, family, prefix_len);

  out->family     = family;
  out->prefix_len = prefix_len;
  memcpy(out->addr, addr, 16);
  return true;
}

// Parse a comma-separated CIDR list into a malloc'd CidrList. Returns NULL
// on parse failure and writes a short reason into `err`.
static CidrList *parse_cidr_list(const char *value, char *err, size_t err_len) {
  CidrList *list = (CidrList *)malloc(sizeof(CidrList));
  if (!list) {
    if (err) snprintf(err, err_len, "out of memory");
    return NULL;
  }
  list->entries = NULL;
  list->count   = 0;

  if (value == NULL) return list;

  // First pass: count non-empty entries.
  int         count = 0;
  const char *p     = value;
  while (*p) {
    while (*p == ',' || *p == ' ' || *p == '\t') p++;
    if (!*p) break;
    count++;
    while (*p && *p != ',') p++;
  }
  if (count == 0) return list;

  list->entries = (CidrEntry *)malloc(sizeof(CidrEntry) * count);
  if (!list->entries) {
    free(list);
    if (err) snprintf(err, err_len, "out of memory");
    return NULL;
  }

  // Second pass: parse each entry.
  int  idx = 0;
  char item[80];
  p = value;
  while (*p) {
    while (*p == ',' || *p == ' ' || *p == '\t') p++;
    if (!*p) break;
    const char *start = p;
    while (*p && *p != ',') p++;
    size_t itemlen = (size_t)(p - start);
    if (itemlen >= sizeof(item)) {
      free(list->entries);
      free(list);
      if (err) snprintf(err, err_len, "CIDR entry too long");
      return NULL;
    }
    memcpy(item, start, itemlen);
    item[itemlen] = '\0';

    if (!parse_cidr(item, &list->entries[idx], err, err_len)) {
      free(list->entries);
      free(list);
      return NULL;
    }
    idx++;
  }
  list->count = idx;
  return list;
}

static bool match_cidr_list(const CidrList *list, int family, const uint8_t addr[16]) {
  if (!list || list->count == 0) return false;

  for (int i = 0; i < list->count; i++) {
    const CidrEntry *e = &list->entries[i];
    if (e->family != family) continue;

    uint8_t masked[16];
    memcpy(masked, addr, 16);
    mask_addr(masked, family, e->prefix_len);

    int cmp_bytes = (family == AF_INET) ? 4 : 16;
    if (memcmp(masked, e->addr, cmp_bytes) == 0) return true;
  }
  return false;
}

int pg_net_prereq_cb(void *clientp, char *conn_primary_ip,
                     __attribute__((unused)) char *conn_local_ip,
                     __attribute__((unused)) int   conn_primary_port,
                     __attribute__((unused)) int   conn_local_port) {
  CurlHandle *handle = (CurlHandle *)clientp;
  int         family;
  uint8_t     addr[16];

  bool have_rules = (allowed_list.count > 0) || (blocked_list.count > 0);

  if (!conn_primary_ip || !parse_ip(conn_primary_ip, &family, addr)) {
    // Fail closed only when rules exist, otherwise preserve the pre-filter
    // default of "allow everything".
    if (have_rules) {
      if (handle) {
        snprintf(handle->block_reason, PG_NET_BLOCK_REASON_LEN,
                 "blocked by pg_net: could not parse destination IP");
      }
      return CURL_PREREQFUNC_ABORT;
    }
    return CURL_PREREQFUNC_OK;
  }

  // Allowlist wins.
  if (match_cidr_list(&allowed_list, family, addr)) {
    elog(DEBUG1, "pg_net: %s allowed by pg_net.allowed_cidrs", conn_primary_ip);
    return CURL_PREREQFUNC_OK;
  }

  // Blocklist next.
  if (match_cidr_list(&blocked_list, family, addr)) {
    if (handle) {
      snprintf(handle->block_reason, PG_NET_BLOCK_REASON_LEN,
               "blocked by pg_net.blocked_cidrs: destination %s", conn_primary_ip);
    }
    elog(WARNING, "pg_net: aborting request to %s (matched pg_net.blocked_cidrs)",
         conn_primary_ip);
    return CURL_PREREQFUNC_ABORT;
  }

  // Default allow.
  return CURL_PREREQFUNC_OK;
}

// -- GUC hooks ---------------------------------------------------------------
//
// check_hook only validates that the new value parses; it discards the
// resulting list. assign_hook re-parses and installs. This avoids ferrying
// a heap-allocated struct through PostgreSQL's `extra` pointer, which in
// recent PG versions is freed via pfree() and would crash on a plain
// malloc'd payload.

static void free_cidr_list(CidrList *list) {
  if (!list) return;
  if (list->entries) free(list->entries);
  free(list);
}

static bool check_cidrs(char **newval, __attribute__((unused)) void **extra) {
  char      err[128] = {0};
  CidrList *parsed   = parse_cidr_list(*newval, err, sizeof(err));
  if (!parsed) {
    GUC_check_errdetail("%s", err[0] ? err : "failed to parse CIDR list");
    return false;
  }
  free_cidr_list(parsed);
  return true;
}

static void install_list(CidrList *dest, const char *newval) {
  CidrList *parsed = parse_cidr_list(newval, NULL, 0);
  if (!parsed) {
    // check_hook already validated the string, so parse_cidr_list should not
    // fail here. If it does (OOM), keep the previous list in place.
    elog(WARNING, "pg_net: failed to re-parse validated CIDR list");
    return;
  }

  CidrEntry *old_entries = dest->entries;
  dest->entries          = parsed->entries;
  dest->count            = parsed->count;

  if (old_entries) free(old_entries);
  // Free the CidrList wrapper but not its entries (which we just stole).
  parsed->entries = NULL;
  free(parsed);
}

bool pg_net_check_allowed_cidrs(char **newval, void **extra,
                                __attribute__((unused)) GucSource source) {
  return check_cidrs(newval, extra);
}

bool pg_net_check_blocked_cidrs(char **newval, void **extra,
                                __attribute__((unused)) GucSource source) {
  return check_cidrs(newval, extra);
}

void pg_net_assign_allowed_cidrs(const char *newval, __attribute__((unused)) void *extra) {
  install_list(&allowed_list, newval);
}

void pg_net_assign_blocked_cidrs(const char *newval, __attribute__((unused)) void *extra) {
  install_list(&blocked_list, newval);
}
