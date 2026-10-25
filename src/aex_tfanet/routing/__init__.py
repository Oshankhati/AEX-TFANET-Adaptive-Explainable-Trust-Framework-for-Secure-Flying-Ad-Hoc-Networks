"""Baseline and online trust-aware path selection."""

from __future__ import annotations

import heapq
from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class RouteOption:
    path: tuple[int, ...]
    cost: float


@dataclass(frozen=True)
class RouteDecision:
    mode: str
    selected: RouteOption | None
    alternatives: tuple[RouteOption, ...]
    mean_intermediate_trust: float | None

    @property
    def available(self) -> bool:
        return self.selected is not None


def _score_path(path: tuple[int, ...], *, mode: str, trust: Mapping[int, float],
                link_stability: Mapping[tuple[int, int], float],
                weights: Mapping[str, float]) -> tuple[float, float | None]:
    if mode == "baseline":
        return float(len(path) - 1), None
    if mode != "aex_tfanet":
        raise ValueError("routing mode must be 'baseline' or 'aex_tfanet'")
    active = {key: float(weights.get(key, 0.0)) for key in ("hop", "trust", "link", "delivery")}
    active_total = sum(active.values())
    if active_total <= 0 or any(value < 0 for value in active.values()):
        raise ValueError("routing weights must be non-negative with a positive active total")
    hops = len(path) - 1
    relays = path[1:-1]
    trust_values = [min(1.0, max(0.0, float(trust.get(node, 0.5)))) for node in relays]
    trust_penalty = sum(1.0 - value for value in trust_values) / max(1, len(relays))
    # Link stability is observed from consecutive neighbor sets. Unseen links
    # have a neutral penalty of zero because a route can only use a live edge.
    links = list(zip(path, path[1:]))
    link_penalty = sum(1.0 - min(1.0, max(0.0, float(link_stability.get(edge, 1.0)))) for edge in links)
    # Forwarding trust is also the available empirical delivery estimate; the
    # separate weight is retained so experiments can express that preference.
    delivery_penalty = trust_penalty
    cost = (active["hop"] * hops + active["trust"] * sum(1.0 - value for value in trust_values)
            + active["link"] * link_penalty
            + active["delivery"] * sum(1.0 - value for value in trust_values))
    return cost, (sum(trust_values) / len(trust_values) if trust_values else 1.0)


def select_route(graph: Mapping[int, set[int]], source: int, destination: int, *,
                 mode: str = "baseline", trust: Mapping[int, float] | None = None,
                 link_stability: Mapping[tuple[int, int], float] | None = None,
                 weights: Mapping[str, float] | None = None, alternatives: int = 3) -> RouteDecision:
    """Select a deterministic route and up to K alternatives on a live graph.

    The route search enumerates simple paths in increasing policy cost. It stops
    after K destinations are found; disconnected endpoints return no route.
    Attack metadata is neither accepted nor consulted.
    """
    if source not in graph or destination not in graph:
        return RouteDecision(mode, None, (), None)
    if source == destination:
        raise ValueError("source and destination must differ")
    if alternatives < 1:
        raise ValueError("alternatives must be >= 1")
    trust = trust or {}
    link_stability = link_stability or {}
    weights = weights or {"hop": 0.1, "trust": 0.4, "link": 0.2, "delivery": 0.2}
    queue: list[tuple[float, tuple[int, ...]]] = [(0.0, (source,))]
    found: list[RouteOption] = []
    while queue and len(found) < alternatives:
        _, path = heapq.heappop(queue)
        node = path[-1]
        if node == destination:
            cost, _ = _score_path(path, mode=mode, trust=trust, link_stability=link_stability, weights=weights)
            found.append(RouteOption(path, cost))
            continue
        for neighbor in sorted(graph[node]):
            if neighbor not in path:
                extended = path + (neighbor,)
                cost, _ = _score_path(extended, mode=mode, trust=trust, link_stability=link_stability, weights=weights)
                heapq.heappush(queue, (cost, extended))
    selected = found[0] if found else None
    mean_trust = None
    if selected is not None and mode == "aex_tfanet":
        _, mean_trust = _score_path(selected.path, mode=mode, trust=trust, link_stability=link_stability, weights=weights)
    return RouteDecision(mode, selected, tuple(found), mean_trust)


__all__ = ["RouteDecision", "RouteOption", "select_route"]
