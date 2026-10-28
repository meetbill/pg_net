#ifndef IP_FILTER_H
#define IP_FILTER_H

#include "curl_prelude.h"

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
 *                           entry in allowed_cidrs), the request is rejected
 *                           before a connection is opened.
 *
 * The primary check runs inside libcurl's CURLOPT_OPENSOCKETFUNCTION callback,
 * which fires before a socket is created for each connection attempt (including
 * every redirect hop). It receives the resolved destination address, so a
 * blocked destination is never even connected to, and the decision cannot be
 * bypassed by returning a 3xx response pointing at an internal IP or by DNS
 * rebinding.
 *
 * CURLOPT_PREREQFUNCTION is kept as a backstop: it fires after connect for
 * connections that skip the opensocket callback (e.g. a reused keep-alive
 * connection), so tightening the rules at runtime (SIGHUP) also applies to
 * already-established connections.
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

// Stable, machine-readable error identifiers placed at the start of
// net._http_response.error_msg for IP-filter rejections. Clients and tests can
// match on these prefixes, so keep them stable across releases.
#define PG_NET_ERR_IP_BLOCKED "pg_net.ip_filter_blocked"
#define PG_NET_ERR_IP_UNPARSEABLE "pg_net.ip_filter_unparseable"

// libcurl CURLOPT_OPENSOCKETFUNCTION signature. Primary, pre-connect filter:
// inspects the resolved destination before a socket is created and returns
// CURL_SOCKET_BAD to block it (no connection is attempted).
curl_socket_t pg_net_opensocket_cb(void *clientp, curlsocktype purpose,
                                   struct curl_sockaddr *address);

// libcurl CURLOPT_PREREQFUNCTION signature, kept as a post-connect backstop for
// connections that skip the opensocket callback (notably reused connections).
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
