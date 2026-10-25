from __future__ import annotations

from aex_tfanet.utils.environment import probe_environment


def test_probe_reports_python_and_does_not_invent_ns3() -> None:
    report = probe_environment()
    assert report.python_version.startswith("3.")
    assert report.package_version
    # This host had no NS-3 at Phase 0. If that changes, the probe must still be a bool.
    assert isinstance(report.ns3_available, bool)
    names = {p.name: p.available for p in report.packages}
    assert names["numpy"] is True
    assert names["yaml"] is True
