from sqlalchemy.orm import Session
from ..models import Host, Port

def upsert_scan_results(db: Session, results: list[dict]):
    saved=[]
    for item in results:
        host=db.query(Host).filter(Host.ip_address==item["ip_address"]).first()
        if host is None: host=Host(ip_address=item["ip_address"]); db.add(host); db.flush()
        host.hostname=item.get("hostname"); host.os_name=item.get("os_name"); host.status=item.get("status","unknown")
        host.ports.clear()
        for p in item.get("ports",[]): host.ports.append(Port(port=p["port"],protocol=p.get("protocol","tcp"),service=p.get("service"),version=p.get("version"),state=p.get("state","unknown")))
        saved.append(host)
    db.commit()
    return saved
