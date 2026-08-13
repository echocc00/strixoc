---
name: pentest
description: Authorized Strix autonomous pentest — when to scan, authorization discipline, and how to read results. Use when the user asks for a security scan / pentest / vulnerability assessment, or before/strix_scan.
---

# Strix Autonomous Pentest (authorized)

You have a Strix pentest capability behind these tools: `strix_scan`,
`strix_status`, `strix_report`, `strix_cancel`, `strix_history`,
`strix_health`, and the `/pentest` slash command.

## Authorization discipline (read before EVERY scan)

- **Only scan targets the operator allowlisted** in `~/.hermes/strix.yaml`
  (`allowed_targets`: exact host, `*.domain`, `prefix.*`, CIDR, or full URL
  prefix). Anything else is blocked — including at the `pre_tool_call` hook.
- **Always pass `confirm_authorized=true`** unless the operator disabled
  `require_authorized_flag`. Without it the scan is refused.
- When the user proposes a target NOT in the allowlist, do NOT retry the
  scan — tell them how to add it (`allowed_targets` entry + restart or
  operator-level change). Do not attempt to bypass the hook.
- `max_budget_usd` defaults to `max_budget_default` and is capped at
  `max_budget_cap` in strix.yaml; stay within caps.
- Every decision/scan is recorded in the audit log
  `~/.hermes/logs/strix-audit.jsonl` — tell the user the audit trail exists.

## Scan workflow

1. `strix_health` — confirm the worker backend is configured.
2. `strix_scan(target=..., confirm_authorized=true, scan_mode=quick|standard|deep,
   max_budget_usd=..., user_instructions=...)` — start; get `scan_id`.
3. Poll `strix_status(scan_id)` until `status=finished` (or `failed`).
4. `strix_report(scan_id)` — summary with severity counts; then
   `section="report_md"` for the full executive report,
   `section="vulns_json"` for structured findings, `section="sarif"` for
   STIX-style SARIF 2.1.0.
5. Report back to the user: findings by severity, PoC availability,
   remediation guidance from the report. Never claim "no vulnerabilities"
   from a running or cancelled scan.

## Rules

- **Never cancel early.** A scan runs to completion on its own; cancel only
  on explicit user demand or budget runaway.
- **"No findings so far" is NOT "no vulnerabilities."** Only a finished scan's
  report is authoritative.
- **Resume-friendly:** `strix_scan` on the same target again creates a new
  scan; don't overwrite, reference prior `scan_id`s.
- Scans run in the background — you may continue the conversation and tell
  the user how to poll.