import json
import networkx as nx


def load_data(file_path):
    with open(file_path, "r") as file:
        return json.load(file)


def build_attack_graph(data):

    graph = nx.DiGraph()

    # Add entry point
    entry = data["entry_point"]

    graph.add_node(
        entry["id"],
        name=entry["name"],
        type=entry["type"]
    )

    # Add hosts
    for host in data["hosts"]:

        graph.add_node(
            host["id"],
            name=host["name"],
            ip=host["ip"],
            type=host["type"],
            services=host["services"],
            vulnerabilities=host["vulnerabilities"]
        )

    # Add connections
    for connection in data["connections"]:

        graph.add_edge(
            connection["source"],
            connection["target"]
        )

    return graph