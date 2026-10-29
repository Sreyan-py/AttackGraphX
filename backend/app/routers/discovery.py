from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..database import get_db
from ..schemas import DiscoveryRequest
from ..services.database_service import upsert_scan_results
from ..services.nmap_service import NmapError, run_nmap_discovery
router=APIRouter(prefix="/discovery",tags=["Network Discovery"])
@router.post("")
def discovery(req: DiscoveryRequest, db: Session=Depends(get_db)):
    if not req.run_nmap: return {"mode":"safe-demo","message":"No live scan executed. Set run_nmap=true only for an authorized lab target.","target":req.target,"hosts":[]}
    try:
        hosts=upsert_scan_results(db,run_nmap_discovery(req.target))
        return {"mode":"nmap","target":req.target,"hosts_found":len(hosts),"hosts":[{"ip_address":h.ip_address,"hostname":h.hostname,"status":h.status,"ports":len(h.ports)} for h in hosts]}
    except ValueError as e: raise HTTPException(400,str(e))
    except NmapError as e: raise HTTPException(500,str(e))
