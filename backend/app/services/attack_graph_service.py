
import networkx as nx


def build_attack_graph(hosts, connections=None):
    """
    Build a directed graph from database host records.

    Hosts contain service and vulnerability metadata.
    Edges are added only from explicitly supplied connections.
    """

    graph = nx.DiGraph()

    # Add host nodes.
    for host in hosts:
        host_id = f"host_{host.id}"

        graph.add_node(
            host_id,
            name=host.hostname or host.ip_address,
            ip_address=host.ip_address,
            os_name=host.os_name,
            type="HOST",
            vulnerabilities=[],
            services=[],
        )

        # Add service information.
        for port in host.ports:
            graph.nodes[host_id]["services"].append({
                "port": port.port,
                "protocol": port.protocol,
                "service": port.service,
                "version": port.version,
                "state": port.state,
            })

        # Add vulnerability information.
        for vulnerability in host.vulnerabilities:
            graph.nodes[host_id]["vulnerabilities"].append({
                "cve_id": vulnerability.cve_id,
                "title": vulnerability.title,
                "severity": vulnerability.severity,
                "cvss": vulnerability.cvss,
            })

    # Add each explicitly supplied connection exactly once.
    for connection in connections or []:
        source = connection["source"]
        target = connection["target"]

        if source not in graph or target not in graph:
            raise ValueError(
                f"Connection references an unknown host: "
                f"{source} -> {target}"
            )

        graph.add_edge(
            source,
            target,
            relationship=connection.get(
                "relationship", "CONNECTED_TO"
            ),
            verified=connection.get("verified", False),
        )

    return graph


def find_attack_paths(graph, entry_host_id, target_host_id):
    """
    Find simple paths through explicitly connected graph nodes.

    Paths are candidates for analysis, not proof of exploitability.
    """

    if entry_host_id not in graph:
        raise ValueError(f"Entry host not found: {entry_host_id}")

    if target_host_id not in graph:
        raise ValueError(f"Target host not found: {target_host_id}")

    paths = []

    for index, path in enumerate(
        nx.all_simple_paths(
            graph,
            entry_host_id,
            target_host_id,
        ),
        start=1,
    ):
        vulnerabilities = []
        critical_assets = []

        for node_id in path:
            node_data = graph.nodes[node_id]

            for vulnerability in node_data.get("vulnerabilities", []):
                vulnerabilities.append({
                    "host_id": node_id,
                    "cve_id": vulnerability.get("cve_id"),
                    "title": vulnerability.get("title"),
                    "severity": vulnerability.get("severity"),
                    "cvss": vulnerability.get("cvss"),
                })

            if node_data.get("critical_asset", False):
                critical_assets.append(node_id)

        paths.append({
            "id": f"PATH-{index:03d}",
            "entry_point": entry_host_id,
            "target": target_host_id,
            "path": path,
            "path_length": len(path) - 1,
            "vulnerabilities": vulnerabilities,
            "critical_assets": critical_assets,
        })

    return paths
