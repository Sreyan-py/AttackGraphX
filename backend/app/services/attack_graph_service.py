
import networkx as nx


def build_attack_graph(hosts, connections=None):
    """Build a directed graph from database Host records."""

    graph = nx.DiGraph()
    host_id_map = {}

    # Add hosts, services, and vulnerabilities.
    for host in hosts:
        node_id = f"host_{host.id}"
        host_id_map[host.id] = node_id

        graph.add_node(
            node_id,
            name=host.hostname or host.ip_address,
            ip_address=host.ip_address,
            os_name=host.os_name,
            status=host.status,
            type="HOST",
            critical_asset=False,
            services=[
                {
                    "port": port.port,
                    "protocol": port.protocol,
                    "service": port.service,
                    "version": port.version,
                    "state": port.state,
                }
                for port in host.ports
            ],
            vulnerabilities=[
                {
                    "id": vuln.id,
                    "cve_id": vuln.cve_id,
                    "title": vuln.title,
                    "severity": vuln.severity,
                    "cvss": vuln.cvss,
                    "description": vuln.description,
                }
                for vuln in host.vulnerabilities
            ],
        )

    # Add explicitly supplied connections only.
    for connection in connections or []:
        source = connection.get("source")
        target = connection.get("target")

        if isinstance(source, int):
            source = host_id_map.get(source)

        if isinstance(target, int):
            target = host_id_map.get(target)

        if source not in graph:
            raise ValueError(
                f"Unknown source host in connection: {source}"
            )

        if target not in graph:
            raise ValueError(
                f"Unknown target host in connection: {target}"
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
    """Find simple paths between two existing graph nodes."""

    if entry_host_id not in graph:
        raise ValueError(f"Entry host not found: {entry_host_id}")

    if target_host_id not in graph:
        raise ValueError(f"Target host not found: {target_host_id}")

    paths = nx.all_simple_paths(
        graph,
        source=entry_host_id,
        target=target_host_id,
        cutoff=10,
    )

    results = []

    for index, path in enumerate(paths, start=1):
        vulnerabilities = []
        critical_assets = []

        for node_id in path:
            node = graph.nodes[node_id]

            for vuln in node.get("vulnerabilities", []):
                vulnerabilities.append(
                    {
                        "host_id": node_id,
                        "cve_id": vuln.get("cve_id"),
                        "title": vuln.get("title"),
                        "severity": vuln.get("severity"),
                        "cvss": vuln.get("cvss"),
                    }
                )

            if node.get("critical_asset", False):
                critical_assets.append(node_id)

        results.append(
            {
                "id": f"PATH-{index:03d}",
                "entry_point": entry_host_id,
                "target": target_host_id,
                "path": path,
                "path_length": len(path) - 1,
                "vulnerabilities": vulnerabilities,
                "critical_assets": critical_assets,
            }
        )

    return results
