from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field

class DiscoveryRequest(BaseModel):
    target: str = Field(..., description="Authorized IP, hostname, CIDR, or range")
    run_nmap: bool = False

class PortOut(BaseModel):
    id: int; port: int; protocol: str; service: Optional[str] = None; version: Optional[str] = None; state: str
    class Config: from_attributes = True

class HostOut(BaseModel):
    id: int; ip_address: str; hostname: Optional[str] = None; os_name: Optional[str] = None; status: str; discovered_at: datetime; ports: list[PortOut] = []
    class Config: from_attributes = True

class VulnerabilityOut(BaseModel):
    id: int; host_id: int; cve_id: Optional[str]; title: str; severity: str; cvss: Optional[float]; description: Optional[str]; source: str; detected_at: datetime
    class Config: from_attributes = True
