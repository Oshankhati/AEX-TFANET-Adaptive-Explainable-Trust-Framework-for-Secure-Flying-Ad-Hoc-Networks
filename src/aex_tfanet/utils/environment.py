"""Runtime environment probe. Never pretends NS-3 exists."""

from __future__ import annotations

import importlib
import os
import shutil
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from aex_tfanet import __phase__, __version__
from aex_tfanet.utils.paths import project_root


@dataclass(frozen=True)
class PackageStatus:
    name: str
    available: bool
    version: str | None


@dataclass(frozen=True)
class EnvironmentReport:
    python_version: str
    python_executable: str
    platform: str
    project_root: str
    package_version: str
    implementation_phase: str
    ns3_available: bool
    ns3_details: str
    gxx_available: bool
    gxx_path: str | None
    packages: tuple[PackageStatus, ...]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["packages"] = [asdict(p) for p in self.packages]
        return data


def _package_status(name: str) -> PackageStatus:
    try:
        module = importlib.import_module(name)
    except Exception:
        return PackageStatus(name=name, available=False, version=None)
    version = getattr(module, "__version__", None)
    return PackageStatus(name=name, available=True, version=str(version) if version else "unknown")


def _find_gxx() -> Path | None:
    which = shutil.which("g++")
    if which:
        return Path(which)
    candidates = (
        Path(r"D:\MinGW\bin\g++.exe"),
        Path(r"D:\Dev-Cpp\MinGW64\bin\g++.exe"),
    )
    for path in candidates:
        if path.is_file():
            return path
    return None


def _probe_ns3(ns3_install_path: Path | None = None) -> tuple[bool, str]:
    if shutil.which("ns3"):
        return True, "ns3 executable is on PATH"
    if ns3_install_path and Path(ns3_install_path).exists():
        return True, f"install_path exists: {ns3_install_path}"
    wsl = shutil.which("wsl")
    extra = " WSL is available; NS-3 may be installed inside WSL (not probed)." if wsl else ""
    return False, "NS-3 was not found on PATH or at simulation.ns3.install_path." + extra


def probe_environment(ns3_install_path: Path | None = None) -> EnvironmentReport:
    gxx = _find_gxx()
    ns3_ok, ns3_details = _probe_ns3(ns3_install_path)
    packages = tuple(
        _package_status(name)
        for name in (
            "numpy",
            "pandas",
            "sklearn",
            "yaml",
            "matplotlib",
            "networkx",
            "joblib",
            "shap",
            "lime",
            "streamlit",
            "pytest",
        )
    )
    return EnvironmentReport(
        python_version=sys.version.split()[0],
        python_executable=sys.executable,
        platform=sys.platform,
        project_root=str(project_root()),
        package_version=__version__,
        implementation_phase=__phase__,
        ns3_available=ns3_ok,
        ns3_details=ns3_details,
        gxx_available=gxx is not None,
        gxx_path=str(gxx) if gxx else None,
        packages=packages,
    )


def format_report(report: EnvironmentReport) -> str:
    lines = [
        f"AEX-TFANET {report.package_version} (phase {report.implementation_phase})",
        f"Python: {report.python_version} ({report.python_executable})",
        f"Platform: {report.platform}",
        f"Project root: {report.project_root}",
        f"NS-3 available: {report.ns3_available} - {report.ns3_details}",
        f"g++ available: {report.gxx_available} - {report.gxx_path}",
        f"PATH contains g++: {bool(shutil.which('g++'))}",
        "Packages:",
    ]
    for pkg in report.packages:
        mark = "yes" if pkg.available else "no"
        version = f" {pkg.version}" if pkg.version else ""
        lines.append(f"  - {pkg.name}: {mark}{version}")
    lines.append(f"PYTHONHASHSEED={os.environ.get('PYTHONHASHSEED', '<unset>')}")
    return "\n".join(lines)
