from graph_engine.graph_builder import load_data, build_attack_graph
from graph_engine.path_analyzer import find_attack_paths


# Load sample network data
data = load_data("data/sample_network.json")


# Build attack graph
graph = build_attack_graph(data)


# Print graph nodes
print("Nodes:")

for node, attributes in graph.nodes(data=True):
    print(node, attributes)


# Print connections
print("\nConnections:")

for source, target in graph.edges():
    print(source, "->", target)


# Find attack paths
paths = find_attack_paths(
    graph,
    "internet",
    "db01"
)


print("\nAttack Paths:")

for path in paths:
    print(path)