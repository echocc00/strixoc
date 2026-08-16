#!/usr/bin/env bash
# Render + install the feishu gateway systemd unit (DEV_PLAN 2.1).
#
# NAS reinstall recovery = run this one script; no hand-edited units under
# /etc/systemd/system (config drift eliminated at the source).
#
# Usage:
#   scripts/install_service.sh \
#     --hermes-home /volume1/soft/Hermes/.hermes \
#     --env-file    /volume1/soft/Hermes/.feishu-gateway.env \
#     --lock-dir    /volume1/soft/Hermes/locks-feishu-p0 \
#     [--hermes-bin /usr/local/bin/hermes] \
#     [--profile    feishu-p0] \
#     [--unit-name  hermes-strix-feishu] \
#     [--print | --output FILE]
#
# Default action: render the template, install to /etc/systemd/system/<unit>.service,
# run daemon-reload, enable (boot autostart) and start the service.
# --print renders to stdout without touching the system (DRY: test the render first).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="$SCRIPT_DIR/../runbook/systemd/hermes-strix-feishu.service.in"

HERMES_HOME=""
ENV_FILE=""
LOCK_DIR=""
HERMES_BIN="/usr/local/bin/hermes"
PROFILE="feishu-p0"
UNIT_NAME="hermes-strix-feishu"
MODE="install"
OUTPUT=""

usage() { grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --hermes-home) HERMES_HOME="$2"; shift 2 ;;
    --env-file)    ENV_FILE="$2";    shift 2 ;;
    --lock-dir)    LOCK_DIR="$2";    shift 2 ;;
    --hermes-bin)  HERMES_BIN="$2";  shift 2 ;;
    --profile)     PROFILE="$2";     shift 2 ;;
    --unit-name)   UNIT_NAME="$2";   shift 2 ;;
    --print)       MODE="print";     shift ;;
    --output)      MODE="output"; OUTPUT="$2"; shift 2 ;;
    -h|--help)     usage ;;
    *) echo "unknown option: $1" >&2; usage ;;
  esac
done

[[ -f "$TEMPLATE" ]] || { echo "template not found: $TEMPLATE" >&2; exit 1; }
[[ -n "$HERMES_HOME" && -n "$ENV_FILE" && -n "$LOCK_DIR" ]] || usage

render() {
  sed \
    -e "s|{{HERMES_HOME}}|${HERMES_HOME}|g" \
    -e "s|{{ENV_FILE}}|${ENV_FILE}|g" \
    -e "s|{{LOCK_DIR}}|${LOCK_DIR}|g" \
    -e "s|{{HERMES_BIN}}|${HERMES_BIN}|g" \
    -e "s|{{PROFILE}}|${PROFILE}|g" \
    "$TEMPLATE"
}

UNIT_TEXT="$(render)"
if grep -q '{{' <<<"$UNIT_TEXT"; then
  echo "render left unresolved placeholders:" >&2
  grep -n '{{' <<<"$UNIT_TEXT" >&2
  exit 1
fi

case "$MODE" in
  print)   printf '%s\n' "$UNIT_TEXT" ;;
  output)  printf '%s\n' "$UNIT_TEXT" > "$OUTPUT"; echo "rendered: $OUTPUT" ;;
  install)
    [[ $EUID -eq 0 ]] || { echo "install requires root (rerun with sudo)" >&2; exit 1; }
    UNIT_PATH="/etc/systemd/system/${UNIT_NAME}.service"
    printf '%s\n' "$UNIT_TEXT" > "$UNIT_PATH"
    chmod 644 "$UNIT_PATH"
    systemctl daemon-reload
    systemctl enable --now "$UNIT_NAME"
    echo "installed + enabled: $UNIT_PATH"
    echo "  logs: journalctl -u $UNIT_NAME -f"
    ;;
esac
