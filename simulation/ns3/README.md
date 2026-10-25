# NS-3 backend (source only)

NS-3 is the intended research simulation backend. The current environment does not have NS-3 installed; `fanet_simulation.cc` is an uncompiled starter source and must not be treated as validated or as having generated results. The Python backend is separately labelled **Simplified Python FANET Model — NOT NS-3**.

Install NS-3 in Linux/WSL following the official NS-3 installation guide, build this source inside its scratch workflow, and validate mobility, range, routing/forwarding, attack behavior, and CSV export against the Phase 2 schema before enabling execution. The starter currently exercises ad-hoc Wi-Fi, random waypoint mobility, UDP echo, and FlowMonitor XML; it does not yet implement the complete shared CSV schema or configurable malicious relays. Therefore the CLI reports `NS-3 unavailable` when no `ns3` executable is found and refuses to fabricate NS-3 output.
