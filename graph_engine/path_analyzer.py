import networkx as nx


def find_attack_paths(graph, entry_point, target):

    paths = nx.all_simple_paths(
        graph,
        source=entry_point,
        target=target
    )

    results = []

    for index, path in enumerate(paths, start=1):

        vulnerabilities = []

        # Check every node in the attack path
        for node in path:

            node_data = graph.nodes[node]

            for vulnerability in node_data.get("vulnerabilities", []):

                vulnerabilities.append({
                    "id": vulnerability["id"],
                    "cvss": vulnerability["cvss"],
                    "severity": vulnerability["severity"]
                })

        results.append({
            "id": f"PATH-{index:03d}",
            "entry_point": entry_point,
            "target": target,
            "path": path,
            "path_length": len(path) - 1,
            "vulnerabilities": vulnerabilities
        })

    return results