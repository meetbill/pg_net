"""IP filter (pg_net.allowed_cidrs / pg_net.blocked_cidrs) integration tests.

These tests exercise the pre-connect callback wired into libcurl. The prereq
hook runs after DNS + TCP but before any request bytes leave the process,
so a blocked request should surface as an error row in `net._http_response`
with a specific `error_msg`, not as a timeout or a successful response.

Notes:
- Both GUCs are PGC_SIGHUP; changes propagate to the worker via
  pg_reload_conf(). We drive the worker with net.worker_restart() to make
  the propagation deterministic.
- Every test restores the defaults (empty strings) in a finally block so
  cross-test contamination doesn't happen.
"""
import time

import pytest
from sqlalchemy import text


def _reset_ip_filters(autocommit_sess):
    autocommit_sess.execute(text("alter system reset pg_net.blocked_cidrs;"))
    autocommit_sess.execute(text("alter system reset pg_net.allowed_cidrs;"))
    autocommit_sess.execute(text("select net.worker_restart();"))
    autocommit_sess.execute(text("select net.wait_until_running();"))


def _apply_ip_filters(autocommit_sess, *, blocked=None, allowed=None):
    if blocked is not None:
        autocommit_sess.execute(
            text("alter system set pg_net.blocked_cidrs = :v;"), {"v": blocked}
        )
    if allowed is not None:
        autocommit_sess.execute(
            text("alter system set pg_net.allowed_cidrs = :v;"), {"v": allowed}
        )
    # Restart the worker so the new config is loaded before we send the
    # next request. worker_restart() reloads the config and cycles the
    # background worker in one step.
    autocommit_sess.execute(text("select net.worker_restart();"))
    autocommit_sess.execute(text("select net.wait_until_running();"))


def _collect(sess, request_id, timeout=5.0):
    """Wait for a response row to appear."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        row = sess.execute(
            text(
                "select status_code, error_msg, timed_out "
                "from net._http_response where id = :id"
            ),
            {"id": request_id},
        ).fetchone()
        if row is not None:
            return row
        time.sleep(0.1)
    pytest.fail(f"no response row for request {request_id} within {timeout}s")


def test_gucs_exist_with_empty_defaults(sess):
    """Both GUCs exist and default to empty strings (i.e. no filtering)."""
    (allowed,) = sess.execute(text("show pg_net.allowed_cidrs;")).fetchone()
    (blocked,) = sess.execute(text("show pg_net.blocked_cidrs;")).fetchone()
    assert allowed == ""
    assert blocked == ""


def test_blocked_cidr_aborts_request(sess, autocommit_sess):
    """A request whose destination IP matches pg_net.blocked_cidrs is aborted
    with a specific error_msg naming the destination and the responsible GUC."""
    try:
        _apply_ip_filters(autocommit_sess, blocked="127.0.0.0/8,::1/128")

        (request_id,) = sess.execute(
            text("select net.http_get('http://localhost:8080/');")
        ).fetchone()
        sess.commit()

        status_code, error_msg, timed_out = _collect(sess, request_id)

        assert status_code is None, "blocked request must not have an HTTP status"
        assert timed_out is False, "blocked request must not be reported as a timeout"
        assert error_msg is not None
        assert "blocked by pg_net.blocked_cidrs" in error_msg, (
            f"unexpected error_msg: {error_msg!r}"
        )
    finally:
        _reset_ip_filters(autocommit_sess)


def test_allowed_cidr_overrides_blocked(sess, autocommit_sess):
    """A destination IP matching pg_net.allowed_cidrs is allowed even when it
    would also match pg_net.blocked_cidrs (allowlist wins)."""
    try:
        _apply_ip_filters(
            autocommit_sess,
            blocked="127.0.0.0/8,::1/128",
            allowed="127.0.0.1/32",
        )

        (request_id,) = sess.execute(
            text(
                "select net.http_get("
                "'http://localhost:8080/pathological?status=200');"
            )
        ).fetchone()
        sess.commit()

        status_code, error_msg, _ = _collect(sess, request_id)

        assert status_code == 200, (
            f"whitelisted request should succeed, "
            f"got status={status_code}, error={error_msg!r}"
        )
        assert error_msg is None or "blocked by pg_net" not in (error_msg or "")
    finally:
        _reset_ip_filters(autocommit_sess)


def test_non_matching_ip_passes_through(sess, autocommit_sess):
    """When neither list matches, the request is allowed (default behaviour
    is preserved for traffic that isn't in scope of either rule)."""
    try:
        # Block only a range that doesn't include 127.x
        _apply_ip_filters(autocommit_sess, blocked="10.99.0.0/16")

        (request_id,) = sess.execute(
            text(
                "select net.http_get("
                "'http://localhost:8080/pathological?status=200');"
            )
        ).fetchone()
        sess.commit()

        status_code, error_msg, _ = _collect(sess, request_id)

        assert status_code == 200, (
            f"non-matching request should pass, "
            f"got status={status_code}, error={error_msg!r}"
        )
    finally:
        _reset_ip_filters(autocommit_sess)


def test_redirect_target_is_covered_by_the_filter(sess, autocommit_sess):
    """A request that would follow a redirect is still bound by the filter.

    The nginx harness serves both `/redirect_me` and its target `/to_here`
    on 127.0.0.1, so with 127/8 blocked the very first connect is aborted
    and the 3xx response is never seen. We assert only that the outcome is
    a block (not a 200 from following the redirect). The per-hop guarantee
    of CURLOPT_PREREQFUNCTION is a libcurl property; verifying it
    end-to-end would require a redirect target that resolves outside 127/8,
    which the local test harness doesn't provide.
    """
    try:
        _apply_ip_filters(autocommit_sess, blocked="127.0.0.0/8")

        (request_id,) = sess.execute(
            text("select net.http_get('http://localhost:8080/redirect_me');")
        ).fetchone()
        sess.commit()

        status_code, error_msg, _ = _collect(sess, request_id)

        assert status_code is None, (
            "redirect should not have been followed to success"
        )
        assert error_msg is not None
        assert "blocked by pg_net.blocked_cidrs" in error_msg
    finally:
        _reset_ip_filters(autocommit_sess)
