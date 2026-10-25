"""YAML configuration loading and validation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import yaml

from aex_tfanet.exceptions import ConfigError
from aex_tfanet.utils.paths import project_root

VALID_SOURCES = frozenset({"sample", "ns3", "python_fanet"})
VALID_ROUTING_MODES = frozenset({"baseline", "aex_tfanet"})


def _require_mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"'{name}' must be a mapping")
    return value


def _require(section: Mapping[str, Any], key: str, expected: type, *, path: str) -> Any:
    if key not in section:
        raise ConfigError(f"Missing required key '{path}.{key}'")
    value = section[key]
    if expected is float and isinstance(value, int):
        return float(value)
    if not isinstance(value, expected):
        raise ConfigError(
            f"Key '{path}.{key}' must be {expected.__name__}, got {type(value).__name__}"
        )
    return value


@dataclass(frozen=True)
class Ns3Config:
    install_path: Path | None
    scratch_name: str


@dataclass(frozen=True)
class SimulationConfig:
    source: str
    num_uavs: int
    duration_s: float
    seed: int
    communication_range_m: float
    area_x_m: float
    area_y_m: float
    area_z_m: float
    packet_interval_s: float
    packet_size_bytes: int
    time_step_s: float
    ns3: Ns3Config


@dataclass(frozen=True)
class MobilityConfig:
    model: str
    min_speed_mps: float
    max_speed_mps: float
    pause_time_s: float


@dataclass(frozen=True)
class TrustConfig:
    direct_weight: float
    indirect_weight: float
    history_weight: float
    update_rate: float
    decay_rate: float
    recovery_rate: float
    prior_success: float
    prior_failure: float
    min_recommendations: int
    history_lambda: float
    indirect_enabled: bool
    min_recommender_trust: float
    minimum_trust: float
    maximum_trust: float


@dataclass(frozen=True)
class TrustThresholds:
    highly_trusted: float
    trusted: float
    suspicious: float
    malicious: float


@dataclass(frozen=True)
class RoutingConfig:
    mode: str
    trust_weight: float
    link_weight: float
    delivery_weight: float
    delay_weight: float
    hop_weight: float


@dataclass(frozen=True)
class DetectionConfig:
    suspicious_threshold: float
    malicious_threshold: float
    min_observations: int
    window_s: float = 10.0
    drop_weight: float = 0.60
    trust_weight: float = 0.25
    forwarding_weight: float = 0.10
    instability_weight: float = 0.05


@dataclass(frozen=True)
class MLConfig:
    enabled: bool
    model: str
    test_size: float
    random_state: int


@dataclass(frozen=True)
class XAIConfig:
    enabled: bool
    shap: bool
    lime: bool


@dataclass(frozen=True)
class ExperimentConfig:
    output_directory: Path
    source: str


@dataclass(frozen=True)
class LoggingConfig:
    level: str
    format: str


@dataclass(frozen=True)
class PathConfig:
    sample_data: Path
    processed_data: Path
    ns3_results: Path


@dataclass(frozen=True)
class ProjectMeta:
    name: str
    version: str
    description: str


@dataclass(frozen=True)
class AppConfig:
    project: ProjectMeta
    simulation: SimulationConfig
    mobility: MobilityConfig
    trust: TrustConfig
    trust_thresholds: TrustThresholds
    routing: RoutingConfig
    detection: DetectionConfig
    ml: MLConfig
    xai: XAIConfig
    experiments: ExperimentConfig
    logging: LoggingConfig
    paths: PathConfig
    source_path: Path


def _deep_merge(base: dict[str, Any], overlay: Mapping[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in overlay.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _parse_ns3(raw: Mapping[str, Any]) -> Ns3Config:
    path_value = raw.get("install_path")
    install_path = Path(path_value) if path_value else None
    return Ns3Config(
        install_path=install_path,
        scratch_name=str(raw.get("scratch_name", "fanet_simulation")),
    )


def _validate_weights(name: str, *weights: float) -> None:
    for w in weights:
        if w < 0:
            raise ConfigError(f"{name} weights must be >= 0")


def _parse(raw: Mapping[str, Any], source_path: Path, root: Path) -> AppConfig:
    sim = _require_mapping(raw.get("simulation"), "simulation")
    source = _require(sim, "source", str, path="simulation")
    if source not in VALID_SOURCES:
        raise ConfigError(f"simulation.source must be one of {sorted(VALID_SOURCES)}")

    ns3_raw = sim.get("ns3") if isinstance(sim.get("ns3"), dict) else {}
    simulation = SimulationConfig(
        source=source,
        num_uavs=_require(sim, "num_uavs", int, path="simulation"),
        duration_s=_require(sim, "duration_s", float, path="simulation"),
        seed=_require(sim, "seed", int, path="simulation"),
        communication_range_m=_require(sim, "communication_range_m", float, path="simulation"),
        area_x_m=_require(sim, "area_x_m", float, path="simulation"),
        area_y_m=_require(sim, "area_y_m", float, path="simulation"),
        area_z_m=_require(sim, "area_z_m", float, path="simulation"),
        packet_interval_s=_require(sim, "packet_interval_s", float, path="simulation"),
        packet_size_bytes=_require(sim, "packet_size_bytes", int, path="simulation"),
        time_step_s=float(sim.get("time_step_s", 1.0)),
        ns3=_parse_ns3(ns3_raw),
    )
    if simulation.num_uavs < 2:
        raise ConfigError("simulation.num_uavs must be >= 2")
    if simulation.duration_s <= 0:
        raise ConfigError("simulation.duration_s must be > 0")

    mob = _require_mapping(raw.get("mobility"), "mobility")
    mobility = MobilityConfig(
        model=_require(mob, "model", str, path="mobility"),
        min_speed_mps=_require(mob, "min_speed_mps", float, path="mobility"),
        max_speed_mps=_require(mob, "max_speed_mps", float, path="mobility"),
        pause_time_s=_require(mob, "pause_time_s", float, path="mobility"),
    )

    tr = _require_mapping(raw.get("trust"), "trust")
    indirect_enabled = tr.get("indirect_enabled", True)
    if not isinstance(indirect_enabled, bool):
        raise ConfigError("trust.indirect_enabled must be a boolean")
    trust = TrustConfig(
        direct_weight=_require(tr, "direct_weight", float, path="trust"),
        indirect_weight=_require(tr, "indirect_weight", float, path="trust"),
        history_weight=_require(tr, "history_weight", float, path="trust"),
        update_rate=_require(tr, "update_rate", float, path="trust"),
        decay_rate=_require(tr, "decay_rate", float, path="trust"),
        recovery_rate=_require(tr, "recovery_rate", float, path="trust"),
        prior_success=_require(tr, "prior_success", float, path="trust"),
        prior_failure=_require(tr, "prior_failure", float, path="trust"),
        min_recommendations=_require(tr, "min_recommendations", int, path="trust"),
        history_lambda=float(tr.get("history_lambda", tr.get("update_rate", 0.3))),
        indirect_enabled=indirect_enabled,
        min_recommender_trust=float(tr.get("min_recommender_trust", 0.0)),
        minimum_trust=float(tr.get("minimum_trust", 0.0)),
        maximum_trust=float(tr.get("maximum_trust", 1.0)),
    )
    _validate_weights("trust", trust.direct_weight, trust.indirect_weight)
    if not 0.0 < trust.update_rate <= 1.0:
        raise ConfigError("trust.update_rate must be in (0, 1]")
    _validate_weights("trust", trust.direct_weight, trust.indirect_weight, trust.history_weight)
    if trust.direct_weight + trust.indirect_weight + trust.history_weight <= 0:
        raise ConfigError("trust direct/indirect/history weights must sum to > 0")
    if not 0.0 <= trust.history_lambda <= 1.0:
        raise ConfigError("trust.history_lambda must be in [0, 1]")
    if not 0.0 <= trust.min_recommender_trust <= 1.0:
        raise ConfigError("trust.min_recommender_trust must be in [0, 1]")
    if not (0.0 < trust.decay_rate <= 1.0 and 0.0 < trust.recovery_rate <= 1.0):
        raise ConfigError("trust.decay_rate and trust.recovery_rate must be in (0, 1]")
    if trust.prior_success <= 0 or trust.prior_failure <= 0 or trust.min_recommendations < 1:
        raise ConfigError("trust Beta priors must be > 0 and min_recommendations must be >= 1")
    if not 0.0 <= trust.minimum_trust < trust.maximum_trust <= 1.0:
        raise ConfigError("trust bounds must satisfy 0 <= minimum_trust < maximum_trust <= 1")

    th = _require_mapping(raw.get("trust_thresholds"), "trust_thresholds")
    thresholds = TrustThresholds(
        highly_trusted=_require(th, "highly_trusted", float, path="trust_thresholds"),
        trusted=_require(th, "trusted", float, path="trust_thresholds"),
        suspicious=_require(th, "suspicious", float, path="trust_thresholds"),
        malicious=_require(th, "malicious", float, path="trust_thresholds"),
    )
    ordered = (
        thresholds.malicious,
        thresholds.suspicious,
        thresholds.trusted,
        thresholds.highly_trusted,
    )
    if not all(0.0 <= v <= 1.0 for v in ordered):
        raise ConfigError("trust_thresholds must be in [0, 1]")
    if not (
        thresholds.malicious
        <= thresholds.suspicious
        <= thresholds.trusted
        <= thresholds.highly_trusted
    ):
        raise ConfigError(
            "trust_thresholds must satisfy malicious <= suspicious <= trusted <= highly_trusted"
        )

    rt = _require_mapping(raw.get("routing"), "routing")
    routing = RoutingConfig(
        mode=_require(rt, "mode", str, path="routing"),
        trust_weight=_require(rt, "trust_weight", float, path="routing"),
        link_weight=_require(rt, "link_weight", float, path="routing"),
        delivery_weight=_require(rt, "delivery_weight", float, path="routing"),
        delay_weight=_require(rt, "delay_weight", float, path="routing"),
        hop_weight=_require(rt, "hop_weight", float, path="routing"),
    )
    if routing.mode not in VALID_ROUTING_MODES:
        raise ConfigError(f"routing.mode must be one of {sorted(VALID_ROUTING_MODES)}")

    det = _require_mapping(raw.get("detection"), "detection")
    detection = DetectionConfig(
        suspicious_threshold=_require(det, "suspicious_threshold", float, path="detection"),
        malicious_threshold=_require(det, "malicious_threshold", float, path="detection"),
        min_observations=_require(det, "min_observations", int, path="detection"),
        window_s=float(det.get("window_s", 10.0)),
        drop_weight=float(det.get("drop_weight", 0.60)),
        trust_weight=float(det.get("trust_weight", 0.25)),
        forwarding_weight=float(det.get("forwarding_weight", 0.10)),
        instability_weight=float(det.get("instability_weight", 0.05)),
    )
    if not (0.0 <= detection.suspicious_threshold < detection.malicious_threshold <= 1.0):
        raise ConfigError("detection thresholds must satisfy 0 <= suspicious_threshold < malicious_threshold <= 1")
    if detection.min_observations < 1 or detection.window_s <= 0:
        raise ConfigError("detection.min_observations and detection.window_s must be > 0")
    _validate_weights("detection", detection.drop_weight, detection.trust_weight, detection.forwarding_weight, detection.instability_weight)
    if detection.drop_weight + detection.trust_weight + detection.forwarding_weight + detection.instability_weight <= 0:
        raise ConfigError("detection feature weights must sum to > 0")

    ml_raw = _require_mapping(raw.get("ml"), "ml")
    ml = MLConfig(
        enabled=_require(ml_raw, "enabled", bool, path="ml"),
        model=_require(ml_raw, "model", str, path="ml"),
        test_size=_require(ml_raw, "test_size", float, path="ml"),
        random_state=_require(ml_raw, "random_state", int, path="ml"),
    )

    xai_raw = _require_mapping(raw.get("xai"), "xai")
    xai = XAIConfig(
        enabled=_require(xai_raw, "enabled", bool, path="xai"),
        shap=_require(xai_raw, "shap", bool, path="xai"),
        lime=_require(xai_raw, "lime", bool, path="xai"),
    )

    exp = _require_mapping(raw.get("experiments"), "experiments")
    exp_source = _require(exp, "source", str, path="experiments")
    if exp_source not in VALID_SOURCES:
        raise ConfigError(f"experiments.source must be one of {sorted(VALID_SOURCES)}")
    experiments = ExperimentConfig(
        output_directory=(root / _require(exp, "output_directory", str, path="experiments")),
        source=exp_source,
    )

    log_raw = _require_mapping(raw.get("logging"), "logging")
    logging_cfg = LoggingConfig(
        level=_require(log_raw, "level", str, path="logging"),
        format=_require(log_raw, "format", str, path="logging"),
    )

    path_raw = _require_mapping(raw.get("paths"), "paths")
    paths = PathConfig(
        sample_data=root / _require(path_raw, "sample_data", str, path="paths"),
        processed_data=root / _require(path_raw, "processed_data", str, path="paths"),
        ns3_results=root / _require(path_raw, "ns3_results", str, path="paths"),
    )

    proj = _require_mapping(raw.get("project"), "project")
    project = ProjectMeta(
        name=_require(proj, "name", str, path="project"),
        version=_require(proj, "version", str, path="project"),
        description=_require(proj, "description", str, path="project"),
    )

    return AppConfig(
        project=project,
        simulation=simulation,
        mobility=mobility,
        trust=trust,
        trust_thresholds=thresholds,
        routing=routing,
        detection=detection,
        ml=ml,
        xai=xai,
        experiments=experiments,
        logging=logging_cfg,
        paths=paths,
        source_path=source_path,
    )


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ConfigError(f"Configuration file not found: {path}")
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"Malformed YAML in {path}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ConfigError(f"Configuration root in {path} must be a mapping")
    return loaded


def load_config(path: Path | None = None, *, overlay: Path | None = None) -> AppConfig:
    """Load default `config.yaml`, optionally merged with an experiment overlay."""

    root = project_root()
    base_path = path or (root / "config.yaml")
    raw = load_yaml(base_path)
    source_path = base_path
    if overlay is not None:
        raw = _deep_merge(raw, load_yaml(overlay))
        source_path = overlay
    return _parse(raw, source_path=source_path, root=root)
