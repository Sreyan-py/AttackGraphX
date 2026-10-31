
from types import SimpleNamespace

import networkx as nx
import pytest

from app.services.attack_graph_service import (
    build_attack_graph,
    find_attack_paths,
)


def make_host(host_id, hostname=None, ip="192.168.56.10"):
    """Create a lightweight host record for testing."""
    return SimpleNamespace(
        id=host_id,
        hostname=hostname,
        ip_address=ip,
        os_name="Linux",
        status="up",
        ports=[],
        vulnerabilities=[],
    )


def test_build_graph_adds_host_nodes():
    hosts = [
        make_host(1, "web", "192.168.56.10"),
        make_host(2, "db", "192.168.56.20"),
    ]

    graph = build_attack_graph(hosts)

    assert isinstance(graph, nx.DiGraph)
    assert set(graph.nodes) == {"host_1", "host_2"}
    assert graph.number_of_edges() == 0


def test_explicit_connection_creates_edge():
    hosts = [
        make_host(1, "web"),
        make_host(2, "db", "192.168.56.20"),
    ]

    graph = build_attack_graph(
        hosts,
        connections=[
            {
                "source": 1,
                "target": 2,
                "relationship": "CONNECTED_TO",
                "verified": True,
            }
        ],
    )

    assert graph.has_edge("host_1", "host_2")
    assert graph["host_1"]["host_2"]["verified"] is True


def test_unknown_connection_host_is_rejected():
    hosts = [make_host(1, "web")]

    with pytest.raises(ValueError, match="Unknown target host"):
        build_attack_graph(
            hosts,
            connections=[{"source": 1, "target": 99}],
        )


def test_find_attack_path_when_edge_exists():
    hosts = [
        make_host(1, "web"),
        make_host(2, "db", "192.168.56.20"),
    ]

    graph = build_attack_graph(
        hosts,
        connections=[{"source": 1, "target": 2}],
    )

    paths = find_attack_paths(graph, "host_1", "host_2")

    assert len(paths) == 1
    assert paths[0]["path"] == ["host_1", "host_2"]
    assert paths[0]["path_length"] == 1


def test_disconnected_hosts_have_no_path():
    hosts = [
        make_host(1, "web"),
        make_host(2, "db", "192.168.56.20"),
    ]

    graph = build_attack_graph(hosts)

    paths = find_attack_paths(graph, "host_1", "host_2")

    assert paths == []


def test_missing_entry_host_is_rejected():
    graph = build_attack_graph([make_host(1, "web")])

    with pytest.raises(ValueError, match="Entry host not found"):
        find_attack_paths(graph, "host_99", "host_1")


def test_missing_target_host_is_rejected():
    graph = build_attack_graph([make_host(1, "web")])

    with pytest.raises(ValueError, match="Target host not found"):
        find_attack_paths(graph, "host_1", "host_99")
