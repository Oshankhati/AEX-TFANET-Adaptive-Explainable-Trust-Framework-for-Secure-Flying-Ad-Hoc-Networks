from __future__ import annotations

from aex_tfanet.cli import main


def test_env_command_succeeds() -> None:
    assert main(["env"]) == 0


def test_dashboard_command_dispatches_to_launcher(monkeypatch) -> None:
    calls = []

    def launch(results):
        calls.append(results)
        return 0

    monkeypatch.setattr("aex_tfanet.cli.launch_dashboard", launch)
    assert main(["dashboard"]) == 0
    assert calls == [None]
