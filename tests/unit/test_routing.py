import pytest

from aex_tfanet.routing import select_route


def test_baseline_uses_shortest_hop_path_and_reports_alternatives():
    graph = {1: {2, 3}, 2: {1, 4}, 3: {1, 5}, 4: {2, 5}, 5: {3, 4}}
    route = select_route(graph, 1, 4, mode="baseline", alternatives=2)
    assert route.selected.path == (1, 2, 4)
    assert len(route.alternatives) == 2
    assert route.selected.cost == 2


def test_trust_aware_prefers_reliable_equal_hop_alternative():
    graph = {1: {2, 3}, 2: {1, 4}, 3: {1, 4}, 4: {2, 3}}
    trust = {2: 0.05, 3: 0.95}
    weights = {"hop": 0.1, "trust": 0.4, "link": 0.2, "delivery": 0.2}
    baseline = select_route(graph, 1, 4, mode="baseline")
    secure = select_route(graph, 1, 4, mode="aex_tfanet", trust=trust, weights=weights)
    assert baseline.selected.path == (1, 2, 4)
    assert secure.selected.path == (1, 3, 4)
    assert secure.mean_intermediate_trust == pytest.approx(0.95)


def test_route_unavailable_and_invalid_inputs():
    assert select_route({1: set(), 2: set()}, 1, 2).selected is None
    with pytest.raises(ValueError):
        select_route({1: {2}, 2: {1}}, 1, 2, mode="mystery")
