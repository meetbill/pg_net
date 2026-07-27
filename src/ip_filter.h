#ifndef IP_FILTER_H
#define IP_FILTER_H

/*
 * IP-based access control for pg_net.
 *
 * Two GUCs are exposed:
 *
 *   pg_net.allowed_cidrs  - comma-separated list of CIDRs; if a request's
 *                           destination IP matches any entry here, the request
 *                           is allowed even if it would otherwise be blocked.
 *   pg_net.blocked_cidrs  - comma-separated list of CIDRs; if a request's
 *                           destination IP matches any entry here (and no
 *                           entry in allowed_cidrs), the request is aborted
 *                           before any data is sent on the wire.
 *
 * The check runs inside libcurl's CURLOPT_PREREQFUNCTION callback, which
 * fires after DNS resolution and TCP connect but before any request data is
 * transmitted. Because the callback also runs on every redirect hop, this
 * filter cannot be bypassed by returning a 3xx response pointing at an
 * internal IP.
 *
 * Matching order for each connection attempt:
 *   1. If allowed_cidrs matches -> ALLOW (do not consult blocked_cidrs).
 *   2. Otherwise if blocked_cidrs matches -> BLOCK.
 *   3. Otherwise -> ALLOW (both lists empty is the default, preserving
 *      the pre-filter behaviour).
 */

// GUC-visible strings (raw text, kept for `SHOW pg_net.allowed_cidrs`)
extern char *guc_allowed_cidrs;
extern char *guc_blocked_cidrs;

// libcurl CURLOPT_PREREQFUNCTION signature.
// Returns CURL_PREREQFUNC_OK to proceed, CURL_PREREQFUNC_ABORT to abort.
int pg_net_prereq_cb(void *clientp, char *conn_primary_ip, char *conn_local_ip,
                     int conn_primary_port, int conn_local_port);

// GUC hooks
bool pg_net_check_allowed_cidrs(char **newval, void **extra, GucSource source);
bool pg_net_check_blocked_cidrs(char **newval, void **extra, GucSource source);
void pg_net_assign_allowed_cidrs(const char *newval, void *extra);
void pg_net_assign_blocked_cidrs(const char *newval, void *extra);

#define PG_NET_BLOCK_REASON_LEN 160

#endif
