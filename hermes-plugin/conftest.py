import sys
from pathlib import Path

import pytest

REPO_DIR = Path(__file__).resolve().parent
PLUGIN_DIR = REPO_DIR / "plugin"

# Parent dir first so `from plugin import ...` resolves as the real package
# (hermes loads the plugin this way; flat sys.path insertion would mask
# absolute-import bugs).  The plugin dir itself stays on path for
# worker-side modules (worker_runtime/backends are run as plain scripts in
# the worker venv, exactly like production).
for p in (REPO_DIR, PLUGIN_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))


@pytest.fixture()
def default_config():
    from plugin import config as cfgmod

    return cfgmod.load_config(path="__none__")