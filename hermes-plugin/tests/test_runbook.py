"""0.4.2.1: systemd unit template + installer contract.

The installer itself is bash/sed (NAS-side); these tests pin the template
contract the script depends on: exact placeholder set, clean render, valid
INI output.
"""

from __future__ import annotations

import configparser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "runbook" / "systemd" / "hermes-strix-feishu.service.in"
INSTALLER = ROOT / "scripts" / "install_service.sh"

VALUES = {
    "{{HERMES_HOME}}": "/volume1/soft/Hermes/.hermes",
    "{{ENV_FILE}}": "/volume1/soft/Hermes/.feishu-gateway.env",
    "{{LOCK_DIR}}": "/volume1/soft/Hermes/locks-feishu-p0",
    "{{HERMES_BIN}}": "/usr/local/bin/hermes",
    "{{PROFILE}}": "feishu-p0",
}


def test_template_exists_with_documented_placeholders():
    text = TEMPLATE.read_text(encoding="utf-8")
    for ph in VALUES:
        assert ph in text, f"placeholder {ph} missing from template"
    # no undocumented placeholders would silently leak into the render
    leftovers = [p for p in text.split("{{")[1:] if "]" not in p]
    assert all("}}" in p for p in leftovers), f"unbalanced placeholder in {leftovers}"


def test_render_is_complete_and_valid_ini():
    text = TEMPLATE.read_text(encoding="utf-8")
    rendered = text
    for ph, val in VALUES.items():
        rendered = rendered.replace(ph, val)
    assert "{{" not in rendered and "}}" not in rendered

    cp = configparser.ConfigParser(strict=False)
    cp.read_string(rendered)
    svc = cp["Service"]
    assert svc["Restart"] == "always"
    assert svc["RestartSec"] == "5"
    # configparser collapses repeated keys, so assert the Environment lines on
    # the raw render (systemd keeps every Environment= line)
    assert f"Environment=HERMES_HOME={VALUES['{{HERMES_HOME}}']}" in rendered
    assert f"Environment=HERMES_GATEWAY_LOCK_DIR={VALUES['{{LOCK_DIR}}']}" in rendered
    assert svc["EnvironmentFile"] == VALUES["{{ENV_FILE}}"]
    assert "gateway run" in svc["ExecStart"] and "--profile feishu-p0" in svc["ExecStart"]
    assert cp["Install"]["WantedBy"] == "multi-user.target"


def test_install_script_contract():
    """The bash installer must render the same template and finish the install
    (daemon-reload + enable) - static checks keep it honest."""
    sh = INSTALLER.read_text(encoding="utf-8")
    for ph in VALUES:
        assert ph in sh, f"installer does not substitute {ph}"
    assert "hermes-strix-feishu.service.in" in sh
    assert "daemon-reload" in sh
    assert "enable" in sh
    assert "--print" in sh  # render-only mode for safe inspection
    assert "EUID" in sh  # refuses to install without root
