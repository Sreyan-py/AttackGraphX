from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import Vulnerability
from ..schemas import VulnerabilityOut
from ..services.vulnerability_service import list_vulnerabilities
router=APIRouter(prefix="/vulnerabilities",tags=["Vulnerability Assessment"])
@router.get("",response_model=list[VulnerabilityOut])
def get_vulnerabilities(db:Session=Depends(get_db)): return list_vulnerabilities(db)
@router.get("/summary")
def summary(db:Session=Depends(get_db)):
    rows=db.query(Vulnerability).all(); counts={x:0 for x in ["Critical","High","Medium","Low","Unknown"]}
    for r in rows: counts[r.severity]=counts.get(r.severity,0)+1
    return {"total":len(rows),"by_severity":counts}
