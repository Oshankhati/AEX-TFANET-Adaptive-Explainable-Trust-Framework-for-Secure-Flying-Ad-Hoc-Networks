import sys
from types import SimpleNamespace

from aex_tfanet import dashboard


def test_dashboard_launcher_binds_to_localhost(monkeypatch, tmp_path):
    monkeypatch.setitem(sys.modules, "streamlit", SimpleNamespace())
    captured = {}

    def fake_call(args, *, env):
        captured["args"] = args
        captured["env"] = env
        return 0

    monkeypatch.setattr(dashboard.subprocess, "call", fake_call)

    assert dashboard.launch_dashboard(tmp_path) == 0
    assert captured["args"][-2:] == ["--server.address=127.0.0.1", "--server.headless=true"]
    assert captured["env"]["AEX_TFANET_RESULTS"] == str(tmp_path.resolve())
