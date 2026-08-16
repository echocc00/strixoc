"""0.5.3.1: authorization URL-normalization attack suite.

Every case is a documented bypass attempt against ``allowed_targets``.
The matcher must fail closed on all of them - and, per DEV_PLAN 3.2, the
deny reason must be distinct enough for an auditor to reconstruct the
vector from the audit trail alone.

Reference vectors:
- SSRF filter bypass via authority confusion  - OWASP SSRF Prevention
  Cheat Sheet (userinfo ``@``, backslashes, scheme tricks)
- FQDN trailing-dot suffix bypass             - RFC 3986 sec 3.2.2 (dot is
  part of the host grammar; naive suffix matching treats it as a boundary)
- Mixed-case / Unicode-free case tricks       - RFC 3986 sec 6.2.2.1 (DNS
  names are case-insensitive)
- Alternative IP literal encodings (decimal / hex / octal)
  - CWE-706 (incorrectly resolved hostname); the classic SSRF numeric-form
    bypasses (e.g. 127.0.0.1 as 2130706433 / 0x7f000001 / 0177.0.0.1)
- Port-based scope escape                     - CWE-668 (resource exposure
  through an unintended port)
"""

from __future__ import annotations

import json

from plugin import authz


def denied(target: str, rules: list[str], reason: str) -> None:
    d = authz.target_allowed(target, rules)
    assert not d.allowed, f"{target!r} must be denied"
    assert d.reason == reason, f"{target!r}: expected {reason}, got {d.reason}"


def allowed(target: str, rules: list[str]) -> None:
    d = authz.target_allowed(target, rules)
    assert d.allowed, f"{target!r} must be allowed (got {d.reason})"


# --- 1. userinfo injection (OWASP SSRF bypass) -------------------------------

INTERNAL = ["localhost", "*.internal"]


def test_userinfo_prefix_disguise_is_denied():
    """``http://allowed.internal@evil.com/`` - a naive parser reads the
    text before ``@``; the real connection goes to evil.com."""
    denied("http://allowed.internal@evil.com/", INTERNAL, "userinfo_not_allowed")


def test_userinfo_suffix_form_also_denied():
    """``http://evil.com@allowed.internal/`` connects to the allowed host,
    but credentials-in-URL is never legitimate for a scan target - deny
    outright so no parser disagreement can be exploited."""
    denied("http://evil.com@allowed.internal/", INTERNAL, "userinfo_not_allowed")


def test_empty_userinfo_denied():
    denied("http://@allowed.internal/", INTERNAL, "userinfo_not_allowed")
    denied("http://:@10.0.0.5/", ["10.0.0.0/8"], "userinfo_not_allowed")


def test_bare_userinfo_denied():
    denied("user@allowed.internal", INTERNAL, "userinfo_not_allowed")


# --- 2. trailing-dot FQDN tricks ----------------------------------------------


def test_trailing_dot_normalizes_to_same_host():
    """``app.internal.`` IS app.internal (RFC 3986): normalization makes the
    match, so the operator does not need dot-variants in the allowlist."""
    allowed("http://app.internal./", INTERNAL)
    allowed("app.internal.", INTERNAL)


def test_dot_appended_to_attacker_domain_does_not_match_suffix():
    """Suffix rules stay anchored: ``x.evil.com.`` never matches *.internal."""
    denied("http://x.evil.com./", INTERNAL, "target_not_allowed")


def test_dot_inside_cannot_terminate_a_suffix_early():
    denied("http://internal.evil.com./", INTERNAL, "target_not_allowed")


# --- 3. case normalization ------------------------------------------------------


def test_mixed_case_target_matches_lowercase_rules():
    allowed("http://ALLOWED.internal/", INTERNAL)
    allowed("App.Internal", INTERNAL)
    denied("HTTP://EVIL.example.com", INTERNAL, "target_not_allowed")


# --- 4. scheme allowlist --------------------------------------------------------


def test_non_http_schemes_denied():
    """file/gopher/ftp fetchers are classic SSRF sinks (OWASP SSRF)."""
    denied("file:///etc/passwd", INTERNAL, "scheme_not_allowed")
    denied("gopher://allowed.internal/", INTERNAL, "scheme_not_allowed")
    denied("ftp://allowed.internal/", INTERNAL, "scheme_not_allowed")
    denied("dict://allowed.internal:6379/", INTERNAL, "scheme_not_allowed")


def test_javascript_uri_is_not_a_bare_host():
    denied("javascript:alert(1)", INTERNAL, "invalid_target")


# --- 5. port allowlisting (CWE-668) ----------------------------------------------


def test_unlisted_port_denied_under_host_rule():
    denied("http://allowed.internal:8042/", INTERNAL, "target_not_allowed")
    denied("allowed.internal:22", INTERNAL, "target_not_allowed")


def test_standard_web_ports_allowed_under_host_rule():
    allowed("http://allowed.internal/", INTERNAL)
    allowed("http://allowed.internal:80/", INTERNAL)
    allowed("https://allowed.internal:443/", INTERNAL)


def test_port_pinned_rule_matches_only_that_port():
    rules = ["allowed.internal:8042"]
    allowed("http://allowed.internal:8042/", rules)
    allowed("allowed.internal:8042", rules)
    denied("http://allowed.internal:8043/", rules, "target_not_allowed")
    denied("http://allowed.internal/", rules, "target_not_allowed")


def test_port_pinned_rule_satisfied_by_scheme_default():
    rules = ["allowed.internal:80"]
    allowed("http://allowed.internal/", rules)  # :80 is http's default
    denied("https://allowed.internal/", rules, "target_not_allowed")  # 443 != 80


def test_port_jumping_between_schemes_blocked():
    rules = ["http://allowed.internal"]  # URL rule pins http origin
    allowed("http://allowed.internal/x", rules)
    denied("https://allowed.internal/x", rules, "target_not_allowed")


# --- 6. path-prefix scope ---------------------------------------------------------


def test_url_rule_path_prefix_stays_on_path_component():
    rules = ["http://allowed.internal/api/v1"]
    allowed("http://allowed.internal/api/v1/scan", rules)
    allowed("http://allowed.internal/api/v1", rules)
    # sibling paths under the same host are out of scope
    denied("http://allowed.internal/api/v2", rules, "target_not_allowed")
    denied("http://allowed.internal/admin", rules, "target_not_allowed")


def test_url_rule_prefix_is_not_a_string_prefix():
    """``/api/v1-evil`` must not match rule ``/api/v1`` (boundary check)."""
    rules = ["http://allowed.internal/api/v1"]
    denied("http://allowed.internal/api/v1-evil", rules, "target_not_allowed")


def test_query_and_fragment_do_not_extend_the_rule():
    """Rule matches on path only - query/fragment never widen scope, and a
    path-like query (``?next=/admin``) cannot smuggle past the matcher."""
    rules = ["http://allowed.internal/api"]
    allowed("http://allowed.internal/api?next=/admin", rules)
    denied("http://allowed.internal/admin?next=/api", rules, "target_not_allowed")


def test_authority_at_sign_in_path_is_not_userinfo():
    """``http://allowed.internal/@evil.com`` - the ``@`` lives in the PATH
    (proper urlsplit); only authority userinfo is dangerous.  Documenting
    the boundary: this target genuinely goes to the allowed host."""
    allowed("http://allowed.internal/@evil.com", INTERNAL)


# --- 7. parser-confusion forms ------------------------------------------------------


def test_backslash_confusion_denied():
    """WHATWG treats ``\\`` as ``/`` in special schemes; Python does not.
    Any backslash is rejected rather than gambling on which parser the
    downstream stack uses (OWASP SSRF bypass family)."""
    denied("https:/\\evil.com", INTERNAL, "invalid_target")
    denied("http://allowed.internal\\@evil.com", INTERNAL, "invalid_target")
    denied("https://allowed.internal\\.evil.com", INTERNAL, "invalid_target")


def test_whitespace_and_control_forms_denied():
    # trailing/leading whitespace is stripped (chat input hygiene) and the
    # clean form then matches normally - evil.com is simply not allowed
    denied("http://evil.com\n", INTERNAL, "target_not_allowed")
    # whitespace *inside* the authority/host is unparseable -> invalid
    denied("http://ev il.com/", INTERNAL, "invalid_target")
    denied("http://evil.com\t/", INTERNAL, "invalid_target")
    denied("", INTERNAL, "invalid_target")


def test_bad_ports_denied():
    denied("http://allowed.internal:abc/", INTERNAL, "invalid_target")
    denied("http://allowed.internal:99999/", INTERNAL, "invalid_target")
    denied("allowed.internal:", INTERNAL, "invalid_target")


def test_percent_and_unicode_hosts_denied():
    denied("http://allowed%2f@evil.com/", INTERNAL, "userinfo_not_allowed")
    denied("http://ev%69l.com/", INTERNAL, "invalid_target")
    denied("http://evil。com/", INTERNAL, "invalid_target")  # U+3002 fullwidth dot


def test_bare_host_with_path_denied_use_url_form():
    denied("allowed.internal/admin", INTERNAL, "invalid_target")


# --- 8. alternative IP encodings (CWE-706 / SSRF numeric forms) ---------------------


def test_integer_ip_form_denied():
    denied("http://2130706433/", ["127.0.0.1"], "suspicious_ip_form")
    denied("http://3232235521/", ["192.168.1.1"], "suspicious_ip_form")


def test_hex_ip_form_denied():
    denied("http://0x7f000001/", ["127.0.0.1"], "suspicious_ip_form")
    denied("http://0x7f.0.0.1/", ["127.0.0.1"], "suspicious_ip_form")


def test_octal_ip_form_denied():
    """Python's ip_address rejects leading zeros (CVE-2021-29921 mindset);
    0177.0.0.1 is octal 127.0.0.1 to libc resolvers."""
    denied("http://0177.0.0.1/", ["127.0.0.1"], "suspicious_ip_form")
    denied("http://127.1/", ["127.0.0.1"], "suspicious_ip_form")


def test_valid_dotted_quad_and_ipv6_still_work():
    allowed("http://127.0.0.1/", ["127.0.0.1"])
    allowed("10.1.2.3", ["10.0.0.0/8"])
    allowed("http://[::1]/", ["::1"])
    allowed("[::1]:3000", ["[::1]:3000"])


def test_numeric_shaped_hostnames_do_not_crash_normal_domains():
    denied("http://1.2.3.999/", ["1.2.3.0/24"], "suspicious_ip_form")
    allowed("http://abc.example.com/", ["*.example.com"])  # letters fine


# --- 9. suffix anchoring (regression of the core rule) ------------------------------


def test_suffix_rules_remain_anchored():
    """The original DEV_PLAN 3.1 core: no string-prefix matching anywhere."""
    denied("evil-internal.com", INTERNAL, "target_not_allowed")
    denied("internal.evil.com", INTERNAL, "target_not_allowed")
    denied("xinternal", INTERNAL, "target_not_allowed")
    denied("notinternal.example.com", ["*.internal"], "target_not_allowed")


# --- 10. audit trail enrichment (DEV_PLAN 3.2) -------------------------------------


def test_hook_audits_raw_and_normalized_target(tmp_path):
    log = tmp_path / "audit.jsonl"
    cfg = {"audit_log": str(log), "allowed_targets": ["*.internal"]}
    out = authz.pre_tool_call_hook(
        cfg,
        tool_name="strix_scan",
        args={"target": "http://allowed.internal@evil.com/", "confirm_authorized": True},
        session_id="s1",
    )
    assert out is not None
    rec = json.loads(log.read_text(encoding="utf-8").strip())
    assert rec["target"] == "http://allowed.internal@evil.com/"
    assert rec["normalized_target"] == "evil.com"  # what the matcher saw
    assert rec["decision"] == "userinfo_not_allowed"


def test_audit_records_carry_plugin_version(tmp_path):
    log = tmp_path / "audit.jsonl"
    authz.audit({"audit_log": str(log)}, action="check", target="t")
    rec = json.loads(log.read_text(encoding="utf-8").strip())
    assert rec["plugin"] == authz.plugin_version()
    assert rec["plugin"].count(".") == 2  # semver x.y.z


def test_plugin_version_reads_yaml():
    v = authz.plugin_version()
    assert v and v != "unknown"
