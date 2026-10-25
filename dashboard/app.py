"""Interactive, read-only-first Streamlit window into AEX-TFANET artifacts."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st
import yaml

from aex_tfanet.dashboard_data import (
    ArtifactError,
    artifact_inventory,
    confined_path,
    discover_experiments,
    read_csv,
    read_json,
)


PAGES = [
    "Overview", "Simulation Monitor", "FANET Topology", "Trust Engine",
    "Threat Detection", "Secure Routing", "ML Detection", "Explainable AI",
    "Experiments", "Results & Comparison", "Raw Data / Artifacts", "Methodology",
    "System Architecture", "Limitations & Reproducibility", "Presentation Mode",
]
DEMO_STEPS = [
    "Normal FANET", "Packet-drop attack", "Observed packet outcomes", "Trust evolution",
    "Threat detection", "Trust-aware routing", "ML evaluation", "SHAP explanation",
    "Baseline comparison", "Final result",
]
ARTIFACTS = {
    "summary.json": "Simulation summary",
    "manifest.json": "Experiment manifest",
    "simulation/uav_events.csv": "UAV position and telemetry trace",
    "simulation/neighbor_events.csv": "Observed neighbor/link trace",
    "simulation/packet_events.csv": "Packet event trace",
    "simulation/route_decisions.csv": "Stored route decisions",
    "trust/trust_scores.csv": "Relational trust observations",
    "trust/trust_summary.json": "Trust class summary",
    "detection/detection_events.csv": "Detection windows",
    "detection/detection_metrics.json": "Node-level detection evaluation",
    "metrics/metrics.json": "Performance evaluation",
    "ml/ml_run_metrics.json": "Per-run ML inference metrics",
    "ml/ml_predictions.csv": "Per-run ML predictions",
    "xai/run_xai_status.json": "Per-run SHAP status",
    "xai/run_local_shap.csv": "Per-run local SHAP values",
}
PALETTE = {"background": "#f5f7fb", "panel": "#ffffff", "cyan": "#0369a1", "green": "#15803d",
           "yellow": "#a16207", "red": "#be123c", "purple": "#7e22ce", "muted": "#475569"}


def _root() -> Path:
    return Path(__file__).resolve().parents[1]


def _results_dir() -> Path:
    return Path(os.environ.get("AEX_TFANET_RESULTS", _root() / "results")).resolve()


@st.cache_data(ttl=5, show_spinner=False)
def _runs(root: str) -> list[str]:
    return [str(path) for path in discover_experiments(Path(root))]


@st.cache_data(ttl=300, show_spinner=False)
def _demo_run(root_text: str, run_paths: tuple[str, ...], scenario: str) -> str | None:
    """Pick a full-pipeline saved run for the requested guided-demo scenario."""
    root = Path(root_text)
    candidates = [Path(p) for p in run_paths if (Path(p) / "manifest.json").is_file()]
    candidates.extend(Path(p) for p in run_paths if not (Path(p) / "manifest.json").is_file())
    for candidate in candidates:
        try:
            summary = read_json(confined_path(root, candidate, "simulation/summary.json"))
        except (ArtifactError, OSError):
            continue
        actual = summary.get("attack_type") or "normal"
        if actual == scenario:
            return str(candidate)
    return None


@st.cache_data(show_spinner=False)
def _json(path: str, modified: float) -> dict[str, Any]:
    del modified
    return read_json(Path(path))


@st.cache_data(show_spinner=False)
def _csv(path: str, modified: float) -> pd.DataFrame:
    del modified
    return read_csv(Path(path))


def _load_json(run: Path, rel: str) -> dict[str, Any] | None:
    try:
        path = confined_path(_results_dir(), run, rel)
        if not path.is_file():
            raise ArtifactError(f"{Path(rel).name} was not generated for this experiment.")
        return _json(str(path), path.stat().st_mtime)
    except (ArtifactError, OSError) as exc:
        st.info(str(exc) if isinstance(exc, ArtifactError) else f"{Path(rel).name} is unavailable for this experiment.")
        return None


def _load_optional_json(run: Path, rel: str) -> dict[str, Any] | None:
    """Read optional metadata quietly; the view that needs it reports absence."""
    try:
        path = confined_path(_results_dir(), run, rel)
        if not path.is_file():
            return None
        return _json(str(path), path.stat().st_mtime)
    except (ArtifactError, OSError):
        return None


def _load_csv(run: Path, rel: str) -> pd.DataFrame | None:
    try:
        path = confined_path(_results_dir(), run, rel)
        if not path.is_file():
            raise ArtifactError(f"{Path(rel).name} was not generated for this experiment.")
        return _csv(str(path), path.stat().st_mtime)
    except (ArtifactError, OSError) as exc:
        st.info(str(exc) if isinstance(exc, ArtifactError) else f"{Path(rel).name} is unavailable for this experiment.")
        return None


def _read_csv_safe(path: Path, purpose: str) -> pd.DataFrame | None:
    try:
        return read_csv(path)
    except (ArtifactError, OSError) as exc:
        st.warning(f"{purpose} is unavailable: {exc}")
        return None


def _fmt(value: Any, digits: int = 3, suffix: str = "") -> str:
    if value is None or pd.isna(value):
        return "Not available"
    if isinstance(value, (float, int)):
        return f"{value:.{digits}f}{suffix}"
    return f"{value}{suffix}"


def _metric(label: str, value: Any, help_text: str | None = None, fmt: str = "number") -> None:
    if value is None or pd.isna(value):
        shown = "Not modeled" if label.lower() in {"delay", "signaling overhead", "routing overhead"} else "Not available"
    elif fmt == "percent":
        shown = f"{float(value) * 100:.2f}%"
    elif fmt == "decimal":
        shown = f"{float(value):.3f}"
    else:
        shown = f"{value:,}" if isinstance(value, int) else str(value)
    st.metric(label, shown, help=help_text)


def _provenance(run: Path, rel: str, summary: dict[str, Any] | None = None) -> None:
    with st.expander("View source and provenance"):
        relative = str(run.relative_to(_results_dir()))
        st.caption(f"Experiment: {relative} · artifact: {rel}")
        if summary:
            st.caption(
                f"Scenario: {summary.get('attack_type') or 'normal'} · seed: {summary.get('random_seed', 'unavailable')} · "
                f"backend: {summary.get('backend', 'unavailable')}"
            )
        st.caption("Values are loaded from the selected saved run; no values are generated by this view.")


def _set_style(presentation: bool = False) -> None:
    st.markdown("""<style>
    .stApp {background:#f5f7fb;color:#172033}
    [data-testid="stSidebar"] {background:#ffffff;border-right:1px solid #d8e0eb}
    [data-testid="stSidebar"] * {color:#172033}
    .stApp, .stApp p, .stApp label, .stApp span, .stApp li, .stApp small,
    .stApp [data-testid="stMarkdownContainer"], .stApp [data-testid="stCaptionContainer"] {
        color:#172033;
    }
    h1, h2, h3, h4, h5, h6 {color:#111827}
    [data-testid="stMetric"] {background:#ffffff;border:1px solid #d8e0eb;padding:16px;border-radius:12px}
    [data-testid="stMetric"] label, [data-testid="stMetricValue"], [data-testid="stMetricDelta"] {color:#172033}
    .block-container {padding-top:1.6rem;max-width:1500px}
    h1,h2,h3 {letter-spacing:-.02em}
    div[data-testid="stAlert"] {border-radius:10px}
    .aex-pill {display:inline-block;padding:4px 10px;border-radius:999px;border:1px solid #93c5fd;color:#075985;background:#eff6ff;font-size:.8rem}
    .stButton button, .stDownloadButton button {color:#172033;border-color:#cbd5e1;background:#ffffff}
    .stButton button:hover, .stDownloadButton button:hover {color:#0f172a;border-color:#64748b}
    .stApp input, .stApp textarea, .stApp [data-baseweb="select"] > div,
    .stApp [data-baseweb="input"] > div {color:#172033;background-color:#ffffff}
    .stApp input::placeholder, .stApp textarea::placeholder {color:#64748b}
    .stApp [data-testid="stDataFrame"], .stApp [data-testid="stTable"] {background:#ffffff}
    .stApp code, .stApp pre {color:#172033;background:#eef2f7}
    .stApp button svg, [data-testid="stSidebar"] svg, [data-testid="stExpander"] svg {
        color:#334155;fill:currentColor
    }
    .stApp [data-testid="stIconMaterial"] {color:#334155}
    </style>""", unsafe_allow_html=True)


def _topology(run: Path, summary: dict[str, Any]) -> tuple[pd.DataFrame | None, pd.DataFrame | None, pd.DataFrame | None]:
    telemetry = _load_csv(run, "simulation/uav_events.csv")
    neighbors = _load_csv(run, "simulation/neighbor_events.csv")
    if telemetry is None or telemetry.empty or not {"timestamp", "uav_id", "position_x", "position_y"}.issubset(telemetry.columns):
        st.warning("Topology cannot be drawn: the selected run has no valid position columns in uav_events.csv.")
        return None, None, None
    timestamps = sorted(pd.to_numeric(telemetry.timestamp, errors="coerce").dropna().unique().tolist())
    if not timestamps:
        st.warning("Topology telemetry has no usable timestamps.")
        return None, None, None
    state_key = f"time::{run}"
    default_ix = max(0, len(timestamps) - 1)
    if state_key not in st.session_state:
        st.session_state[state_key] = default_ix
    st.caption("SAVED EXPERIMENT REPLAY · recorded timestamps only · positions are not interpolated")
    playing_key = f"playing::{run}"
    speed_key = f"speed::{run}"
    playback = st.columns([1, 1, 1.5, 4])
    if playback[0].button("▶ Play", key=f"play::{run}", disabled=st.session_state.get(playing_key, False)):
        if st.session_state[state_key] >= len(timestamps) - 1:
            st.session_state[state_key] = 0
        st.session_state[playing_key] = True
        st.session_state[f"speed_accumulator::{run}"] = 0.0
        st.rerun()
    if playback[1].button("⏸ Pause", key=f"pause::{run}", disabled=not st.session_state.get(playing_key, False)):
        st.session_state[playing_key] = False
        st.rerun(scope="app")
    speed = playback[2].selectbox("Replay speed", ["0.5×", "1×", "10×"], index=1, key=speed_key)
    playback[3].caption("Playback visits saved samples; speed changes the number of recorded frames shown per second.")
    if st.session_state.get(playing_key, False):
        accumulator_key = f"speed_accumulator::{run}"
        speed_value = {"0.5×": 0.5, "1×": 1.0, "10×": 10.0}[speed]
        accumulated = float(st.session_state.get(accumulator_key, 0.0)) + speed_value * 0.5
        steps = int(accumulated)
        st.session_state[accumulator_key] = accumulated - steps
        if steps:
            st.session_state[state_key] = min(len(timestamps) - 1, int(st.session_state[state_key]) + steps)
        if st.session_state[state_key] >= len(timestamps) - 1:
            st.session_state[playing_key] = False
            st.rerun(scope="app")
    controls = st.columns([1, 6, 1, 1])
    if controls[0].button("◀", key=f"prev::{run}", help="Previous recorded timestamp"):
        st.session_state[state_key] = max(0, int(st.session_state[state_key]) - 1)
    selected_index = controls[1].slider("Recorded time (s)", 0, len(timestamps) - 1,
                                        int(st.session_state[state_key]), key=f"slider::{run}",
                                        format="frame %d")
    st.session_state[state_key] = selected_index
    if controls[2].button("▶ Next", key=f"next::{run}"):
        st.session_state[state_key] = min(len(timestamps) - 1, selected_index + 1)
    if controls[3].button("Reset", key=f"reset::{run}"):
        st.session_state[state_key] = 0
        st.session_state[playing_key] = False
        st.rerun(scope="app")
    timestamp = timestamps[selected_index]
    frame = telemetry[pd.to_numeric(telemetry.timestamp, errors="coerce") == timestamp].copy()
    trust = _load_csv(run, "trust/trust_scores.csv")
    detection = _load_csv(run, "detection/detection_events.csv")
    links = pd.DataFrame()
    if neighbors is not None and {"timestamp", "uav_id", "neighbor_id", "connected"}.issubset(neighbors.columns):
        links = neighbors[pd.to_numeric(neighbors.timestamp, errors="coerce") == timestamp].copy()
        links["connected"] = links.connected.astype(str).str.lower().isin(["true", "1"])
        links = links[links.connected]
    latest_detection = pd.DataFrame()
    if detection is not None and {"timestamp", "node_id", "status"}.issubset(detection.columns):
        eligible = detection[pd.to_numeric(detection.timestamp, errors="coerce") <= timestamp]
        if not eligible.empty:
            latest_detection = eligible.sort_values("timestamp").groupby("node_id", as_index=False).tail(1)
    latest_trust = pd.DataFrame()
    if trust is not None and {"timestamp", "target_id", "final_trust"}.issubset(trust.columns):
        eligible = trust[pd.to_numeric(trust.timestamp, errors="coerce") <= timestamp]
        if not eligible.empty:
            latest_trust = eligible.sort_values("timestamp").groupby("target_id", as_index=False).tail(1)
    attack_ids = {int(x) for x in summary.get("malicious_nodes", []) if str(x).isdigit()}
    status_map = latest_detection.set_index("node_id").status.to_dict() if not latest_detection.empty else {}
    trust_map = latest_trust.groupby("target_id").final_trust.mean().to_dict() if not latest_trust.empty else {}
    trust_components = {}
    if not latest_trust.empty:
        for component in ("direct_trust", "indirect_trust", "historical_trust"):
            if component in latest_trust:
                trust_components[component] = latest_trust.groupby("target_id")[component].mean().to_dict()
    detection_score_map = (latest_detection.set_index("node_id").detection_score.to_dict()
                           if not latest_detection.empty and "detection_score" in latest_detection else {})
    color_map = {"MALICIOUS": PALETTE["red"], "SUSPICIOUS": PALETTE["yellow"], "NORMAL": PALETTE["cyan"],
                 "INSUFFICIENT_DATA": PALETTE["muted"]}
    fig, ax = plt.subplots(figsize=(10, 6), facecolor=PALETTE["panel"])
    ax.set_facecolor(PALETTE["panel"])
    pos = {int(row.uav_id): (float(row.position_x), float(row.position_y)) for row in frame.itertuples()}
    for link in links.itertuples():
        a, b = int(link.uav_id), int(link.neighbor_id)
        if a in pos and b in pos and a < b:
            ax.plot([pos[a][0], pos[b][0]], [pos[a][1], pos[b][1]], color="#58718a", alpha=.55, linewidth=1.4)
    for row in frame.itertuples():
        node = int(row.uav_id)
        status = str(status_map.get(node, "NORMAL"))
        color = color_map.get(status, PALETTE["muted"])
        ax.scatter(row.position_x, row.position_y, s=210 if node in attack_ids else 125,
                   c=color, edgecolors=PALETTE["red"] if node in attack_ids else "white", linewidths=2 if node in attack_ids else .8, zorder=3)
        ax.annotate(f"UAV {node}", (row.position_x, row.position_y), xytext=(6, 6), textcoords="offset points", color="#172033", fontsize=9)
    ax.set_xlabel("X position (m)", color="#172033"); ax.set_ylabel("Y position (m)", color="#172033")
    ax.set_title(f"Observed UAV positions and connected neighbor links · t={timestamp:g}s", color="#172033")
    ax.tick_params(colors="#475569"); ax.grid(alpha=.35, color="#94a3b8")
    for spine in ax.spines.values(): spine.set_color("#cbd5e1")
    st.pyplot(fig, width="stretch"); plt.close(fig)
    st.caption("Node color reflects the latest saved detector status at or before this recorded time. Red outline marks configured simulation ground truth, not a detector prediction.")
    frame = frame.copy()
    frame["detector_status"] = frame.uav_id.map(status_map).fillna("Not available")
    frame["latest_final_trust"] = frame.uav_id.map(trust_map)
    frame["detection_score"] = frame.uav_id.map(detection_score_map)
    frame["configured_attack_target"] = frame.uav_id.astype(int).isin(attack_ids)
    for component, values in trust_components.items():
        frame[f"latest_{component}"] = frame.uav_id.map(values)
    return frame, links, detection


@st.fragment(run_every=0.5)
def _topology_playback(run_path: str, summary: dict[str, Any]) -> None:
    """Refresh only the replay view while it is explicitly playing."""
    _topology(Path(run_path), summary)


def _comparison(results: Path) -> pd.DataFrame | None:
    paths = sorted(results.glob("routing_comparison_*/aggregate_routing_metrics.csv"))
    if not paths:
        st.info("No saved paired baseline versus trust-aware routing comparison was found under results/.")
        return None
    selected = st.selectbox("Saved routing comparison", paths, format_func=lambda p: str(p.parent.relative_to(results)), key="routing_comparison")
    try:
        return read_csv(selected)
    except ArtifactError as exc:
        st.error(str(exc)); return None


def _show_presentation(summary: dict[str, Any], metrics: dict[str, Any] | None, run: Path) -> None:
    st.title("AEX-TFANET")
    st.subheader("Adaptive Explainable Trust Framework for Secure Flying Ad Hoc Networks")
    st.caption("A reproducible prototype linking observed forwarding behavior to trust, detection, route choice, ML analysis, and evaluation.")
    st.warning("Saved simulation replay · Simplified Python FANET Model — NOT NS-3")
    idx = st.session_state.get("demo_step", 0)
    nav = st.columns([1, 5, 1])
    if nav[0].button("← Previous", disabled=idx == 0): st.session_state.demo_step = max(0, idx - 1)
    nav[1].markdown(f"### Step {idx + 1} of {len(DEMO_STEPS)} · {DEMO_STEPS[idx]}")
    if nav[2].button("Next →", disabled=idx == len(DEMO_STEPS) - 1): st.session_state.demo_step = min(len(DEMO_STEPS) - 1, idx + 1)
    st.progress((idx + 1) / len(DEMO_STEPS))
    pipeline = ["UAV mobility", "Observed links + packet outcomes", "Relational adaptive trust", "Behavioral detection", "Trust-aware route selection", "Grouped offline ML", "SHAP explanations", "Performance evaluation"]
    st.markdown(" → ".join(f"**{x}**" for x in pipeline))
    if idx == 0:
        st.write(f"Selected saved scenario: **{summary.get('attack_type') or 'normal'}**. The overview metrics and topology come from this run's saved trace.")
    elif idx == 1:
        st.write(f"Selected saved scenario: **{summary.get('attack_type') or 'normal'}**. Ground-truth targets are listed separately from predictions.")
    elif idx == 2:
        st.write("Trust derives from saved observer-target forwarding evidence and configured trust components.")
    elif idx == 3:
        st.write("The deterministic detector uses causal telemetry/trust observations. Evaluation labels are not prediction inputs.")
    elif idx == 4:
        st.write("Route selections are read from saved route decisions. Paired aggregate results are loaded separately from the routing comparison artifacts.")
    elif idx in (5, 6):
        st.write("ML and SHAP are shown only when corresponding model and explanation artifacts were produced.")
    elif idx == 7:
        st.write("Only metrics recorded for this run are displayed. Delay and signaling overhead are not modeled by the current simulator.")
    elif idx == 8:
        st.write("Baseline comparison uses the paired routing experiment artifacts, when available.")
    else:
        st.write("Results are descriptive for this simplified model and do not establish radio-level realism or universal routing superiority.")
    if metrics:
        cols = st.columns(4)
        trust_mean = (metrics.get("trust") or {}).get("overall_final_trust_mean")
        for col, (label, value, fmt) in zip(cols, [("Packets", metrics.get("packets_generated"), "number"), ("Delivered", metrics.get("packets_delivered"), "number"), ("PDR", metrics.get("packet_delivery_ratio"), "percent"), ("Trust mean", trust_mean, "decimal")]):
            with col: _metric(label, value, fmt=fmt)
    with st.expander("Provenance", expanded=False):
        st.caption(f"Saved experiment: {run.name} · seed {summary.get('random_seed')} · backend {summary.get('backend')}")


def _render_runner(results: Path) -> None:
    st.subheader("Run a saved-artifact experiment")
    st.caption("The run executes the existing CLI pipeline in the background. Artifacts appear after completion; no intermediate packet stream is claimed.")
    if not results.is_dir():
        st.error("Results directory is unavailable; experiment execution is disabled."); return
    scenario = st.selectbox("Scenario", ["Normal", "Packet drop", "Blackhole"], key="run_scenario")
    seed = st.number_input("Random seed", min_value=0, max_value=2_147_483_647, value=42, step=1, key="run_seed")
    uav_count = st.number_input("UAV count", min_value=10, max_value=100, value=10, step=1, key="run_uav_count",
                                help="The integrated trust/detection pipeline needs a multi-relay topology; the backend supports larger networks.")
    duration = st.number_input("Simulation duration (seconds)", min_value=20.0, max_value=3600.0, value=100.0, step=10.0, key="run_duration")
    drop_probability = st.slider("Packet-drop probability", 0.0, 1.0, 0.8, 0.05, disabled=scenario != "Packet drop", key="run_drop_probability")
    st.selectbox("Backend", ["Simplified Python FANET Model"], help="The existing integrated runner validates the Python backend. NS-3 is not silently substituted.")
    start = st.button("▶ RUN EXPERIMENT", type="primary", disabled=bool(st.session_state.get("active_run")))
    if st.button("RESET RUN CONTROLS", disabled=bool(st.session_state.get("active_run"))):
        for key in ("run_scenario", "run_seed", "run_uav_count", "run_duration", "run_drop_probability"):
            st.session_state.pop(key, None)
        st.rerun()
    if start:
        profiles = {"Normal": "normal.yaml", "Packet drop": "packet_drop.yaml", "Blackhole": "blackhole.yaml"}
        profile = _root() / "experiments" / "configs" / profiles[scenario]
        if not profile.is_file():
            st.error(f"Scenario preset is missing: {profile.name}")
            return
        config = yaml.safe_load(profile.read_text(encoding="utf-8"))
        config.setdefault("simulation", {}).update({"seed": int(seed), "num_uavs": int(uav_count), "duration_s": float(duration)})
        if scenario == "Packet drop": config.setdefault("attack", {})["drop_probability"] = float(drop_probability)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        run_dir = results / f"dashboard_run_{stamp}"
        cfg_dir = results / ".dashboard_configs"; cfg_dir.mkdir(exist_ok=True)
        cfg_path = cfg_dir / f"{stamp}.yaml"
        cfg_path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
        log_path = run_dir.with_suffix(".log"); run_dir.mkdir()
        stream = log_path.open("w", encoding="utf-8")
        args = [sys.executable, "-m", "aex_tfanet", "experiment", "--config", str(cfg_path), "--output", str(run_dir)]
        try:
            proc = subprocess.Popen(args, cwd=_root(), stdout=stream, stderr=subprocess.STDOUT, shell=False)
        except OSError as exc:
            stream.close(); cfg_path.unlink(missing_ok=True); run_dir.rmdir()
            st.error(f"Could not start the Python experiment process: {exc}")
            return
        st.session_state.active_run = {"process": proc, "config": cfg_path, "log": log_path, "run": run_dir, "stream": stream,
                                       "scenario": scenario, "started": datetime.now(timezone.utc).isoformat()}
        st.session_state.monitor_refresh = True
        st.rerun()
    job = st.session_state.get("active_run")
    if job:
        process = job["process"]
        rc = process.poll()
        if rc is None:
            st.warning(f"RUNNING · {job['scenario']} · artifacts are written when the pipeline finishes.")
            if st.button("STOP RUN", type="secondary"):
                process.terminate(); process.wait(timeout=10)
                job["stream"].close(); job["config"].unlink(missing_ok=True)
                st.session_state.active_run = None
                st.error("Experiment process stopped by user.")
            if st.button("REFRESH STATUS"): st.rerun()
        else:
            job["stream"].close(); job["config"].unlink(missing_ok=True)
            if rc == 0 and (job["run"] / "manifest.json").is_file():
                st.success(f"COMPLETED · saved run: {job['run'].name}")
                st.session_state.preferred_run = str(job["run"])
                _runs.clear()
                if st.button("Open completed experiment"):
                    st.session_state.active_page = "Overview"
                    st.session_state.active_run = None
                    st.rerun()
            else:
                st.error(f"FAILED · process exit code {rc}. See the run log in the technical details below.")
                if job["log"].is_file(): st.code(job["log"].read_text(encoding="utf-8", errors="replace")[-4000:])
            if st.button("Clear run status"):
                st.session_state.active_run = None; st.rerun()
    st.info("NS-3 is unavailable / not executed in this integrated dashboard runner. The Python backend is named explicitly.")


def main() -> None:
    st.set_page_config(page_title="AEX-TFANET Research Dashboard", page_icon="🛰️", layout="wide", initial_sidebar_state="expanded")
    results = _results_dir(); _set_style()
    st.sidebar.markdown("# AEX-TFANET")
    st.sidebar.caption("Adaptive Explainable Trust Framework for Secure FANETs")
    page = st.sidebar.radio("Navigate", PAGES, key="active_page")
    presentation = page == "Presentation Mode"
    if st.sidebar.button("Start guided project demo", width="stretch"):
        st.session_state.demo_step = 0
        st.session_state.active_page = "Presentation Mode"
        st.rerun()
    if page != "Presentation Mode" and st.sidebar.button("Refresh saved experiments"):
        _runs.clear()
        st.rerun()
    runs = _runs(str(results))
    if not runs:
        st.title("AEX-TFANET")
        st.warning("No saved experiment containing simulation/summary.json was found under the configured results directory.")
        if page == "Simulation Monitor": _render_runner(results)
        st.caption("Simulation backend: Simplified Python FANET Model — NOT NS-3")
        return
    labels = {str(Path(path).relative_to(results)): Path(path) for path in runs}
    preferred = st.session_state.get("preferred_run")
    default = next((i for i, p in enumerate(labels.values()) if str(p) == preferred), 0)
    if presentation:
        selected = st.session_state.get("selected_experiment", list(labels)[default])
        if selected not in labels:
            selected = list(labels)[default]
    else:
        selected = st.sidebar.selectbox("Saved experiment", list(labels), index=default, key="selected_experiment")
    run = labels[selected]
    if presentation:
        step = int(st.session_state.get("demo_step", 0))
        scenario_for_step = "normal" if step == 0 else "packet_drop"
        guided_run = _demo_run(str(results), tuple(runs), scenario_for_step)
        if guided_run:
            run = Path(guided_run)
            selected = str(run.relative_to(results))
    summary = _load_optional_json(run, "simulation/summary.json") or {}
    manifest = _load_optional_json(run, "manifest.json")
    metrics_json = _load_optional_json(run, "metrics/metrics.json")
    st.title("AEX-TFANET Research Dashboard")
    status = "SAVED EXPERIMENT REPLAY" if run.is_dir() else "UNAVAILABLE"
    st.markdown(f'<span class="aex-pill">{status}</span> &nbsp; <span class="aex-pill">{summary.get("backend", "backend unavailable")}</span>', unsafe_allow_html=True)
    st.warning("Simulation backend status: Simplified Python FANET Model — NOT NS-3. All values shown are saved simulation outputs, not live or field data.")
    top = st.columns(5)
    for col, (label, value) in zip(top, [("Scenario", summary.get("attack_type") or "normal"), ("Seed", summary.get("random_seed", "Not available")), ("UAVs", summary.get("num_uavs")), ("Simulated duration", f"{summary.get('simulation_duration_s', 'Not available')} s"), ("Routing mode", summary.get("routing_mode", "Not available"))]):
        with col: st.markdown(f"**{label}**<br>{value}", unsafe_allow_html=True)
    if not presentation:
        st.caption(f"Current experiment: `{selected}` · Source: `{results.name}` · saved at {datetime.fromtimestamp(run.stat().st_mtime).astimezone().strftime('%Y-%m-%d %H:%M %Z')}")

    if page == "Overview":
        st.subheader("From observed network behavior to evaluated security decisions")
        st.markdown("**UAV mobility → observed links and packet outcomes → relational trust → behavioral detection → trust-aware routes → grouped ML → SHAP → performance evaluation**")
        perf = (metrics_json or {}).get("performance_metrics", metrics_json or {})
        if not perf:
            perf = {"packets_generated": summary.get("total_packets_generated"), "packets_delivered": summary.get("total_packets_delivered"), "packets_dropped": summary.get("total_packets_dropped"), "packet_delivery_ratio": summary.get("packet_delivery_ratio")}
        det_metrics = _load_json(run, "detection/detection_metrics.json")
        trust_sum = _load_json(run, "trust/trust_summary.json")
        kpis = st.columns(4)
        for col, (label, val, fmt) in zip(kpis, [("UAVs", summary.get("num_uavs"), "number"), ("Packets generated", perf.get("packets_generated", summary.get("total_packets_generated")), "number"), ("Packets delivered", perf.get("packets_delivered", summary.get("total_packets_delivered")), "number"), ("Packet delivery ratio", perf.get("packet_delivery_ratio", summary.get("packet_delivery_ratio")), "percent")]):
            with col: _metric(label, val, fmt=fmt)
        kpis = st.columns(4)
        trust_mean = (perf.get("trust") or {}).get("overall_final_trust_mean")
        if trust_mean is None and trust_sum: trust_mean = trust_sum.get("overall_final_trust_mean")
        if trust_mean is None:
            trust_rows = _load_csv(run, "trust/trust_scores.csv")
            if trust_rows is not None and "final_trust" in trust_rows:
                trust_mean = pd.to_numeric(trust_rows.final_trust, errors="coerce").mean()
        for col, (label, val, fmt) in zip(kpis, [("Packets dropped", perf.get("packets_dropped", summary.get("total_packets_dropped")), "number"), ("Mean final trust", trust_mean, "decimal"), ("Detection F1", (det_metrics or {}).get("F1"), "decimal"), ("Delay", perf.get("average_end_to_end_delay_s"), "decimal")]):
            with col: _metric(label, val, fmt=fmt)
        if det_metrics: _provenance(run, "detection/detection_metrics.json", summary)
        st.markdown("### System status")
        st.write("Saved trace available. The dashboard reads retained artifacts; it does not receive a live network stream.")
        st.info("Not modeled: PHY/MAC behavior, propagation, interference, energy, per-hop delay, and control/signaling overhead.")
    elif page == "Simulation Monitor":
        _render_runner(results)
        st.divider(); st.subheader("Selected saved-run monitor")
        st.caption("SAVED EXPERIMENT REPLAY · progress is not reconstructed from a completed trace.")
        c = st.columns(4)
        for col, (label, key) in zip(c, [("Generated", "total_packets_generated"), ("Delivered", "total_packets_delivered"), ("Dropped", "total_packets_dropped"), ("PDR", "packet_delivery_ratio")]):
            with col: _metric(label, summary.get(key), fmt="percent" if key == "packet_delivery_ratio" else "number")
        packet_events = _load_csv(run, "simulation/packet_events.csv")
        if packet_events is not None and {"timestamp", "action"}.issubset(packet_events.columns):
            activity = packet_events.groupby(["timestamp", "action"]).size().unstack(fill_value=0)
            st.markdown("**Saved packet activity by recorded timestamp and event action**")
            st.line_chart(activity)
            st.caption("Counts are event rows in packet_events.csv. A packet may have more than one action row.")
        else:
            st.info("Packet activity timeline unavailable: packet_events.csv lacks timestamp/action fields.")
        _provenance(run, "simulation/summary.json", summary)
    elif page == "FANET Topology":
        st.subheader("Recorded network topology")
        if st.session_state.get(f"playing::{run}", False):
            _topology_playback(str(run), summary)
            frame = None
        else:
            frame, links, detection = _topology(run, summary)
        if frame is not None:
            uavs = sorted(frame.uav_id.astype(int).unique())
            selected_node = st.selectbox("Inspect UAV", uavs, format_func=lambda x: f"UAV {x}")
            row = frame[frame.uav_id.astype(int) == int(selected_node)].iloc[0]
            details = st.columns(4)
            for col, (label, val, fmt) in zip(details, [("Detector status", row.detector_status, "text"), ("Configured attack target", "Yes" if row.configured_attack_target else "No", "text"), ("Detection score", row.get("detection_score"), "decimal"), ("Neighbors", row.get("neighbors"), "number")]):
                with col: _metric(label, val, fmt=fmt)
            available = [c for c in ["uav_id", "timestamp", "position_x", "position_y", "packets_generated", "packets_sent", "packets_forwarded", "packets_received", "packets_dropped", "forwarding_ratio", "delivery_ratio", "link_stability", "latest_direct_trust", "latest_indirect_trust", "latest_historical_trust", "latest_final_trust", "detector_status", "detection_score", "configured_attack_target"] if c in frame]
            st.dataframe(frame[available], width="stretch", hide_index=True)
            _provenance(run, "simulation/uav_events.csv", summary)
    elif page == "Trust Engine":
        st.subheader("Relational adaptive trust")
        trust = _load_csv(run, "trust/trust_scores.csv")
        if trust is not None and not trust.empty:
            required = {"observer_id", "target_id", "timestamp", "final_trust"}
            if not required.issubset(trust.columns): st.warning(f"Trust artifact is missing columns: {sorted(required - set(trust.columns))}")
            else:
                time = st.slider("Trust history through timestamp", float(trust.timestamp.min()), float(trust.timestamp.max()), float(trust.timestamp.max()))
                visible = trust[pd.to_numeric(trust.timestamp, errors="coerce") <= time]
                component_cols = [c for c in ["direct_trust", "indirect_trust", "historical_trust", "final_trust"] if c in visible]
                trend = visible.groupby(["timestamp", "target_id"], as_index=False)[component_cols].mean(numeric_only=True)
                if not trend.empty: st.line_chart(trend.pivot(index="timestamp", columns="target_id", values="final_trust"))
                latest = visible.sort_values("timestamp").groupby(["observer_id", "target_id"], as_index=False).tail(1)
                st.dataframe(latest, width="stretch", hide_index=True)
                if {"observer_id", "target_id", "final_trust"}.issubset(latest.columns):
                    matrix = latest.pivot_table(index="observer_id", columns="target_id", values="final_trust", aggfunc="mean")
                    st.markdown("**Observer → target final-trust matrix**"); st.dataframe(matrix.style.background_gradient(cmap="YlGnBu", vmin=0, vmax=1), width="stretch")
                c = st.columns(2)
                if "classification" in latest:
                    with c[0]: st.bar_chart(latest.classification.value_counts())
                if "final_trust" in latest:
                    values = latest.final_trust.dropna()
                    if not values.empty:
                        fig, ax = plt.subplots(figsize=(6, 3))
                        ax.hist(values, bins=10, color=PALETTE["cyan"], edgecolor="#cbd5e1", alpha=.85)
                        ax.set_xlabel("Final trust"); ax.set_ylabel("Observed relational records")
                        ax.set_title("Distribution of latest trust values")
                        ax.set_facecolor(PALETTE["panel"]); fig.patch.set_facecolor(PALETTE["panel"])
                        ax.tick_params(colors="#475569")
                        with c[1]: st.pyplot(fig, width="stretch")
                        plt.close(fig)
                st.info("Implementation formulation: Beta/Laplace direct trust; recommender-trust weighted indirect opinions; EWMA history; normalized available-component fusion and configured decay/recovery. These configurable equations and thresholds are project choices, not validated universal thresholds.")
                _provenance(run, "trust/trust_scores.csv", summary)
        else: st.info("Trust data is unavailable because trust/trust_scores.csv was not generated for this experiment.")
    elif page == "Threat Detection":
        st.subheader("Behavioral detection and saved evaluation")
        detection = _load_csv(run, "detection/detection_events.csv")
        det_metrics = _load_json(run, "detection/detection_metrics.json")
        if det_metrics:
            c = st.columns(4)
            for col, (label, key) in zip(c, [("TP", "TP"), ("TN", "TN"), ("FP", "FP"), ("FN", "FN")]):
                with col: _metric(label, det_metrics.get(key))
            c = st.columns(5)
            for col, (label, key) in zip(c, [("Precision", "precision"), ("Recall", "recall"), ("F1", "F1"), ("FPR", "false_positive_rate"), ("FNR", "false_negative_rate")]):
                with col: _metric(label, det_metrics.get(key), fmt="decimal")
            _provenance(run, "detection/detection_metrics.json", summary)
        if detection is not None and not detection.empty:
            if {"timestamp", "status"}.issubset(detection.columns):
                timeline = detection.groupby(["timestamp", "status"]).size().unstack(fill_value=0)
                st.markdown("**Observed detection-window counts over time**"); st.line_chart(timeline)
            if "status" in detection:
                alerts = detection[detection.status.isin(["SUSPICIOUS", "MALICIOUS"])]
                st.markdown(f"Alert windows: **{len(alerts)}** · flagged nodes: **{alerts.node_id.nunique() if 'node_id' in alerts else 'Not available'}**")
            st.dataframe(detection.tail(200), width="stretch", hide_index=True)
        elif not det_metrics: st.info("Detection data is unavailable for this saved run.")
        st.caption("Ground truth is separate evaluator metadata; it is not an input to detector predictions.")
    elif page == "Secure Routing":
        st.subheader("Saved route decisions")
        routes = _load_csv(run, "simulation/route_decisions.csv")
        if routes is not None:
            st.dataframe(routes.tail(250), width="stretch", hide_index=True)
            st.caption(f"{len(routes):,} stored route-decision rows. Empty paths remain unavailable; no route is inferred by the dashboard.")
            if "selected_path" in routes:
                recorded_paths = routes[routes.selected_path.notna() & routes.selected_path.astype(str).ne("")]
                if not recorded_paths.empty:
                    route_ix = st.selectbox("Inspect a stored route", recorded_paths.index.tolist(), format_func=lambda ix: f"packet {recorded_paths.loc[ix].get('packet_id', 'unknown')} · t={recorded_paths.loc[ix].get('timestamp', 'unknown')}s")
                    chosen_route = str(recorded_paths.loc[route_ix, "selected_path"])
                    nodes = [node.strip() for node in chosen_route.split(">") if node.strip()]
                    st.markdown("**Actual saved route path**")
                    st.markdown(" → ".join(f"`UAV {node}`" for node in nodes) if nodes else "Route path unavailable.")
                    if "routing_mode" in routes: st.caption(f"Routing mode: {recorded_paths.loc[route_ix].get('routing_mode', 'Unavailable')}")
            _provenance(run, "simulation/route_decisions.csv", summary)
        st.markdown("### Paired baseline versus AEX-TFANET routing")
        comparison = _comparison(results)
        if comparison is not None:
            if {"scenario", "routing_policy"}.issubset(comparison.columns):
                scenarios = sorted(comparison.scenario.dropna().unique())
                scenario = st.selectbox("Scenario", scenarios, key="route_scenario")
                subset = comparison[comparison.scenario == scenario].copy()
                columns = [c for c in ["scenario", "routing_policy", "run_count", "pdr_mean", "pdr_std", "malicious_exposure_rate_mean", "malicious_exposure_rate_std", "mean_route_hops_mean"] if c in subset]
                st.dataframe(subset[columns], width="stretch", hide_index=True)
                plot_cols = [c for c in ["pdr_mean", "malicious_exposure_rate_mean"] if c in subset]
                if plot_cols:
                    plot = subset.set_index("routing_policy")[plot_cols].rename(columns={"pdr_mean": "Mean PDR", "malicious_exposure_rate_mean": "Attacked-intermediate exposure"})
                    st.bar_chart(plot)
                st.caption("Aggregate routing metrics are loaded from the selected paired experiment CSV. Each mean is accompanied by the saved run count and standard deviation when available.")
    elif page == "ML Detection":
        st.subheader("Offline seed-grouped ML evaluation")
        candidates = sorted(results.glob("ml_*/ml_metrics.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        if candidates:
            path = st.selectbox("Saved model evaluation", candidates, format_func=lambda p: str(p.parent.relative_to(results)))
            ml = _load_json(path.parent, "ml_metrics.json") if path.parent.is_relative_to(results) else None
            if ml:
                c = st.columns(4)
                for col, (label, key) in zip(c, [("Accuracy", "accuracy"), ("Malicious precision", "precision_malicious"), ("Malicious recall", "recall_malicious"), ("Malicious F1", "f1_malicious")]):
                    with col: _metric(label, ml.get(key), fmt="percent" if key == "accuracy" else "decimal")
                st.caption(f"Train rows: {ml.get('train_rows', 'Not available')} · Test rows: {ml.get('test_rows', 'Not available')} · held-out seeds: {ml.get('test_seeds', 'Not available')}")
                matrix = ml.get("confusion_matrix_labels_0_1")
                if matrix: st.markdown("Confusion matrix · rows actual [benign, malicious], columns predicted [benign, malicious]"); st.dataframe(pd.DataFrame(matrix, index=["actual benign", "actual malicious"], columns=["predicted benign", "predicted malicious"]))
                importance_path = path.parent / "feature_importance.csv"
                if importance_path.is_file():
                    importance = _read_csv_safe(importance_path, "Feature importance")
                    if importance is None: return
                    st.markdown("**Saved model feature importance**")
                    importance_value = next((column for column in ("importance", "random_forest_impurity_importance") if column in importance), None)
                    if importance_value and "feature" in importance:
                        st.bar_chart(importance.set_index("feature").sort_values(importance_value, ascending=False)[importance_value].head(15))
                    st.dataframe(importance, width="stretch", hide_index=True)
                prediction_path = path.parent / "test_predictions.csv"
                if prediction_path.is_file():
                    predictions = _read_csv_safe(prediction_path, "Held-out ML predictions")
                    if predictions is not None and {"label_malicious", "probability_malicious"}.issubset(predictions.columns):
                        from sklearn.metrics import precision_recall_curve, roc_curve
                        y_true = pd.to_numeric(predictions.label_malicious, errors="coerce")
                        y_score = pd.to_numeric(predictions.probability_malicious, errors="coerce")
                        valid = y_true.notna() & y_score.notna()
                        if valid.any() and y_true[valid].nunique() == 2:
                            fpr, tpr, _ = roc_curve(y_true[valid], y_score[valid])
                            precision, recall, _ = precision_recall_curve(y_true[valid], y_score[valid])
                            figure, axes = plt.subplots(1, 2, figsize=(11, 4), facecolor=PALETTE["panel"])
                            for axis in axes: axis.set_facecolor(PALETTE["panel"]); axis.tick_params(colors="#475569"); axis.xaxis.label.set_color("#172033"); axis.yaxis.label.set_color("#172033"); axis.title.set_color("#172033")
                            axes[0].plot(fpr, tpr, color=PALETTE["purple"], linewidth=2); axes[0].plot([0, 1], [0, 1], color="#64748b", linestyle="--")
                            axes[0].set(xlabel="False positive rate", ylabel="True positive rate", title="Held-out ROC curve")
                            axes[1].plot(recall, precision, color=PALETTE["cyan"], linewidth=2)
                            axes[1].set(xlabel="Recall", ylabel="Precision", title="Held-out precision–recall curve")
                            st.pyplot(figure, width="stretch"); plt.close(figure)
                            st.caption(f"Curves computed from the saved held-out predictions: {int(valid.sum()):,} valid rows.")
                        else: st.info("ROC and precision–recall curves are unavailable because saved predictions do not contain both classes.")
                    else: st.info("Saved prediction artifact lacks label_malicious/probability_malicious columns; curves are unavailable.")
                st.info(f"Features exclude scenario/seed/time/attack labels. Split: {ml.get('split', 'details unavailable')}")
                st.caption("ML results are retrospective offline model evaluation; the Random Forest is not the online detector or routing input.")
                _provenance(path.parent, "ml_metrics.json")
        else: st.info("No saved results/ml_*/ml_metrics.json evaluation was found. Run the `ml` CLI to train/evaluate on retained Phase 4 traces.")
    elif page == "Explainable AI":
        st.subheader("SHAP explanations")
        candidates = sorted(results.glob("xai_*/xai_status.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        if candidates:
            path = st.selectbox("Saved SHAP evaluation", candidates, format_func=lambda p: str(p.parent.relative_to(results)))
            status = _load_json(path.parent, "xai_status.json") if path.parent.is_relative_to(results) else None
            if status:
                st.info(f"SHAP status: {status.get('shap_status', status.get('status', 'Not specified'))}")
                if status.get("lime_status"): st.caption(f"LIME: {status['lime_status']}")
                global_path = path.parent / str(status.get("global_importance_file", "global_shap_importance.csv"))
                local_path = path.parent / str(status.get("local_explanation_file", "local_shap_explanation.csv"))
                for artifact_path, title, value_col in [(global_path, "Global mean absolute SHAP", "mean_absolute_shap_value"), (local_path, "Local signed SHAP for saved example", "shap_value_for_malicious_class")]:
                    if artifact_path.is_file():
                        values = _read_csv_safe(artifact_path, title)
                        if values is None: continue
                        st.markdown(f"**{title}**")
                        if "feature" in values and value_col in values:
                            chart = values.head(20).set_index("feature")[value_col]
                            st.bar_chart(chart)
                        st.dataframe(values.head(100), width="stretch", hide_index=True)
                    else: st.info(f"{title} is unavailable because {artifact_path.name} is missing.")
                if status.get("local_example"): st.json(status["local_example"])
                st.caption("SHAP contributions explain this fitted model's output; they do not establish causal effects. LIME is not implemented.")
                _provenance(path.parent, "xai_status.json")
        else: st.info("No saved SHAP status was found. This page does not create explanation values on demand.")
        run_xai = _load_json(run, "xai/run_xai_status.json")
        if run_xai: st.markdown("**Selected run's inference explanation**"); st.json(run_xai)
    elif page == "Experiments":
        st.subheader("Experiment browser")
        st.caption(f"{len(runs):,} saved simulation experiment(s) discovered under configured results root.")
        run_rows = []
        for path_text in runs:
            path = Path(path_text)
            try:
                saved_summary = read_json(path / "simulation/summary.json")
                run_rows.append({"experiment": str(path.relative_to(results)), "modified": datetime.fromtimestamp(path.stat().st_mtime).astimezone().isoformat(timespec="minutes"), "seed": saved_summary.get("random_seed"), "scenario": saved_summary.get("attack_type") or "normal", "attack_probability": saved_summary.get("drop_probability"), "uavs": saved_summary.get("num_uavs"), "backend": saved_summary.get("backend")})
            except (ArtifactError, OSError) as exc:
                run_rows.append({"experiment": str(path.relative_to(results)), "modified": "Unavailable", "seed": "Unavailable", "scenario": f"Invalid summary: {exc}"})
        experiments = pd.DataFrame(run_rows)
        if not experiments.empty:
            f1, f2 = st.columns(2)
            scenario_options = ["All"] + sorted(experiments.scenario.astype(str).unique().tolist())
            scenario_filter = f1.selectbox("Filter by scenario", scenario_options)
            seed_options = ["All"] + sorted(experiments.seed.dropna().astype(str).unique().tolist())
            seed_filter = f2.selectbox("Filter by seed", seed_options)
            if scenario_filter != "All": experiments = experiments[experiments.scenario.astype(str) == scenario_filter]
            if seed_filter != "All": experiments = experiments[experiments.seed.astype(str) == seed_filter]
            page_count = max(1, (len(experiments) + 49) // 50)
            page_number = st.number_input("Experiment list page", min_value=1, max_value=page_count, value=1, step=1)
            start_ix = (int(page_number) - 1) * 50
            st.dataframe(experiments.iloc[start_ix:start_ix + 50], width="stretch", hide_index=True)
            st.caption(f"Showing {start_ix + 1 if len(experiments) else 0}–{min(start_ix + 50, len(experiments))} of {len(experiments):,} matching runs; 50 per page.")
        with st.expander("Selected run manifest and saved configuration"):
            if manifest: st.json(manifest)
            config_path = run / "config.yaml"
            if config_path.is_file(): st.code(config_path.read_text(encoding="utf-8"), language="yaml")
            env_path = run / "environment.json"
            if env_path.is_file(): st.json(read_json(env_path))
    elif page == "Results & Comparison":
        st.subheader("Measured results from retained artifacts")
        perf = (metrics_json or {}).get("performance_metrics", metrics_json or {})
        if perf: st.json(perf)
        else: st.info("Performance metrics file is not available for this selected run.")
        c = st.columns(2)
        with c[0]:
            ml_candidates = sorted(results.glob("ml_*/ml_metrics.json"), key=lambda p: p.stat().st_mtime, reverse=True)
            if ml_candidates:
                ml = read_json(ml_candidates[0]); st.markdown("**Latest saved seed-group ML metrics**"); st.json({k: ml.get(k) for k in ["accuracy", "precision_malicious", "recall_malicious", "f1_malicious", "roc_auc_malicious", "average_precision_malicious", "test_seeds"]})
        with c[1]:
            comparison = _comparison(results)
            if comparison is not None and {"scenario", "routing_policy", "pdr_mean", "malicious_exposure_rate_mean"}.issubset(comparison.columns):
                s = st.selectbox("Comparison scenario", sorted(comparison.scenario.unique()), key="results_scenario")
                st.dataframe(comparison[comparison.scenario == s][["routing_policy", "run_count", "pdr_mean", "pdr_std", "malicious_exposure_rate_mean", "malicious_exposure_rate_std"]], width="stretch", hide_index=True)
        st.info("Comparison charts use saved aggregate routing outputs. No metric is hardcoded in the dashboard.")
    elif page == "Raw Data / Artifacts":
        st.subheader("Artifact explorer")
        inventory = artifact_inventory(run)
        available = {item["artifact"].replace("\\", "/"): item for item in inventory}
        st.dataframe(pd.DataFrame(inventory), width="stretch", hide_index=True)
        choices = [rel for rel in ARTIFACTS if rel in available]
        if choices:
            selected_artifact = st.selectbox("Preview an allowlisted artifact", choices, format_func=lambda x: f"{ARTIFACTS[x]} · {x}")
            path = confined_path(results, run, selected_artifact)
            if path.suffix.lower() == ".csv":
                data = _load_csv(run, selected_artifact)
                if data is not None: st.dataframe(data.head(500), width="stretch", hide_index=True); st.caption(f"Showing at most 500 of {len(data):,} rows.")
            else:
                data = _load_json(run, selected_artifact)
                if data is not None: st.json(data)
            _provenance(run, selected_artifact, summary)
        else: st.info("No allowlisted artifacts were generated for this run.")
    elif page == "Methodology":
        st.subheader("Methodology · artifact-backed workflow")
        for title, body in [
            ("1 · UAV network and observations", "The configured Python simulator writes mobility, neighbor, packet, and route-decision CSVs at its saved time steps."),
            ("2 · Relational trust", "Trust consumes observed forwarding evidence and stores observer-target values over time. Indirect trust may be unavailable when evidence is insufficient."),
            ("3 · Behavioral detection", "The detector uses observed outcomes and causal trust/telemetry windows. Ground truth is read later by the evaluator."),
            ("4 · Secure routing", "Baseline shortest-hop and trust-aware route selection are compared in a paired runner; this dashboard reads its stored per-run and aggregate artifacts."),
            ("5 · Offline ML and SHAP", "A Random Forest is evaluated with seed-group holdout. SHAP explains the saved model's output; it is not a causal analysis."),
            ("6 · Performance", "Metrics are calculated from stored simulation traces. Delay and signaling overhead are unavailable because the current simulator does not model them.")]:
            with st.expander(title): st.write(body)
        st.caption("The precise configurable trust equations and thresholds are implementation choices; see docs/trust_model.md and docs/detection.md.")
    elif page == "System Architecture":
        st.subheader("Project architecture")
        st.graphviz_chart('''digraph AEX { rankdir=TB; bgcolor="#f5f7fb"; node [shape=box,style="rounded,filled",fillcolor="#ffffff",fontcolor="#172033",color="#0369a1"]; edge [color="#64748b",fontcolor="#334155"]; sim [label="Python FANET simulator\nUAV / neighbor / packet traces"]; trust [label="Relational adaptive trust\ntrust_scores.csv"]; detect [label="Behavioral detector\ndetection events + evaluation"]; route [label="Baseline / trust-aware routing\nroute decisions + paired study"]; ml [label="Grouped offline ML\nmetrics + predictions"]; xai [label="SHAP explanations"]; eval [label="Performance evaluation\nfigures + manifest"]; dash [label="Streamlit dashboard\nsaved artifact reader"]; sim->trust->detect->route->eval; sim->ml->xai->eval; eval->dash; }''')
        st.caption("Dashboard and CLI reuse existing package modules. No separate HTTP API is currently required or exposed.")
        st.code("simulation → trust → detection + route decisions → metrics / figures → optional offline ML → SHAP → saved-artifact dashboard", language="text")
    elif page == "Limitations & Reproducibility":
        st.subheader("Research scope and reproducibility")
        st.error("Simulation backend status: Simplified Python FANET Model — NOT NS-3")
        for item in ["No PHY/MAC stack, propagation, interference, realistic contention, retransmissions, or energy model.",
                     "Per-hop/queueing delay and control/signaling overhead are not modeled.",
                     "Saved trace playback uses only recorded timestamps; it does not interpolate positions or represent live simulation.",
                     "The current paired routing study and detector thresholds are limited to retained configurations, seeds, and attacker placement.",
                     "ML is retrospective offline evaluation; four held-out seed groups are represented in the retained evaluation.",
                     "SHAP is model explanation, not causal attribution. LIME is not implemented."]:
            st.markdown(f"- {item}")
        st.markdown("For full scope, reproducibility commands, and caveats, see `docs/limitations.md`, `docs/reproducibility.md`, and `docs/results.md`.")
        _provenance(run, "manifest.json", summary)
    else:
        _show_presentation(summary, (metrics_json or {}).get("performance_metrics", metrics_json), run)


if __name__ == "__main__":
    main()
