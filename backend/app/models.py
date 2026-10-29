from datetime import datetime
from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship
from .database import Base

class Host(Base):
    __tablename__ = "hosts"
    id = Column(Integer, primary_key=True)
    ip_address = Column(String(45), unique=True, index=True, nullable=False)
    hostname = Column(String(255))
    os_name = Column(String(255))
    status = Column(String(32), default="unknown")
    discovered_at = Column(DateTime, default=datetime.utcnow)
    ports = relationship("Port", back_populates="host", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="host", cascade="all, delete-orphan")

class Port(Base):
    __tablename__ = "ports"
    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String(10), default="tcp")
    service = Column(String(100))
    version = Column(String(255))
    state = Column(String(32), default="open")
    host = relationship("Host", back_populates="ports")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False)
    cve_id = Column(String(50), index=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(32), nullable=False)
    cvss = Column(Float)
    description = Column(Text)
    source = Column(String(100), default="nmap")
    detected_at = Column(DateTime, default=datetime.utcnow)
    host = relationship("Host", back_populates="vulnerabilities")
