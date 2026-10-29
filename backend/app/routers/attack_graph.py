
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Host
from ..services.attack_graph_service import (
    build_attack_graph,
    find_attack_paths,
)

router = APIRouter(tags=["Attack Graph"])


def get_demo_connections():
    """Return a simulated connection for testing only."""
    return [
        {
            "source": "host_1",
            "target": "host_2",
            "verified": False,
        }
    ]


@router.get("/attack-graph")
def get_attack_graph(db: Session = Depends(get_db)):
    """Build an attack graph from discovered hosts."""

    hosts = db.query(Host).all()

    graph = build_attack_graph(
        hosts,
        connections=get_demo_connections(),
    )

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
    """Find paths between two host nodes."""

    hosts = db.query(Host).all()

    graph = build_attack_graph(
        hosts,
        connections=get_demo_connections(),
    )

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
