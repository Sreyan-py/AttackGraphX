
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Host
from ..services.attack_graph_service import (
    build_attack_graph,
    find_attack_paths,
)

router = APIRouter(tags=["Attack Graph"])


def create_graph(db: Session):
    """
    Build a graph from discovered hosts.

    No network connections are invented. Until verified connection
    data is available, the graph contains host nodes without edges.
    """
    hosts = db.query(Host).order_by(Host.id).all()

    try:
        graph = build_attack_graph(hosts, connections=[])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return graph


@router.get("/attack-graph")
def get_attack_graph(db: Session = Depends(get_db)):
    """Return graph nodes and explicitly known edges."""

    graph = create_graph(db)

    nodes = [
        {"id": node_id, **attributes}
        for node_id, attributes in graph.nodes(data=True)
    ]

    edges = [
        {"source": source, "target": target, **attributes}
        for source, target, attributes in graph.edges(data=True)
    ]

    return {
        "nodes": nodes,
        "edges": edges,
        "total_nodes": len(nodes),
        "total_edges": len(edges),
    }


@router.get("/attack-graph/paths")
def get_attack_paths(
    entry_host_id: str,
    target_host_id: str,
    db: Session = Depends(get_db),
):
    """Find candidate paths through known graph connections."""

    graph = create_graph(db)

    try:
        paths = find_attack_paths(
            graph,
            entry_host_id,
            target_host_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    return {
        "entry_host_id": entry_host_id,
        "target_host_id": target_host_id,
        "total_paths": len(paths),
        "paths": paths,
    }
