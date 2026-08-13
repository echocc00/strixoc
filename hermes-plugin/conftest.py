import sys
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent / "plugin"
if str(PLUGIN_DIR) not in sys.path:
    sys.path.insert(0, str(PLUGIN_DIR))


@pytest.fixture()
def default_config():
    import config as cfgmod

    return cfgmod.load_config(path="__none__")