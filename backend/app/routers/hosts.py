from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import Host
from ..schemas import HostOut
router=APIRouter(prefix="/hosts",tags=["Hosts"])
@router.get("",response_model=list[HostOut])
def get_hosts(db:Session=Depends(get_db)): return db.query(Host).order_by(Host.ip_address).all()
