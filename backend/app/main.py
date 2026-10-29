
from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .database import Base, engine, get_db
from .models import Host, Port, Vulnerability

from .routers.discovery import router as discovery_router
from .routers.hosts import router as hosts_router
from .routers.vulnerabilities import router as vulnerabilities_router
from .routers.attack_graph import router as attack_graph_router


app = FastAPI(
    title="AttackGraphX API",
    version="1.0.0",
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database tables
Base.metadata.create_all(bind=engine)

# Register API routers
app.include_router(discovery_router, prefix="/api")
app.include_router(hosts_router, prefix="/api")
app.include_router(vulnerabilities_router, prefix="/api")
app.include_router(attack_graph_router, prefix="/api")


# Root endpoint
@app.get("/")
def root():
    return {
        "project": "AttackGraphX",
        "status": "running",
    }


# Health check endpoint
@app.get("/api/health")
def health():
    return {
        "status": "healthy",
        "database": "connected",
    }


# Insert demonstration data
@app.post("/api/demo/seed")
def seed_demo(db=Depends(get_db)):
    if db.query(Host).count():
        return {"message": "Demo data already exists"}

    h1 = Host(
        ip_address="192.168.56.10",
        hostname="lab-web",
        os_name="Linux",
        status="up",
    )

    h2 = Host(
        ip_address="192.168.56.20",
        hostname="lab-db",
        os_name="Linux",
        status="up",
    )

    db.add_all([h1, h2])
    db.flush()

    db.add_all([
        Port(
            host_id=h1.id,
            port=22,
            service="ssh",
            version="OpenSSH demo",
        ),
        Port(
            host_id=h1.id,
            port=80,
            service="http",
            version="Apache demo",
        ),
        Port(
            host_id=h2.id,
            port=3306,
            service="mysql",
            version="MySQL demo",
        ),
    ])

    db.add_all([
        Vulnerability(
            host_id=h1.id,
            cve_id="DEMO-CVE-001",
            title="Demo web-service finding",
            severity="High",
            cvss=8.1,
            description="Demo record",
            source="demo",
        ),
        Vulnerability(
            host_id=h2.id,
            cve_id="DEMO-CVE-002",
            title="Demo database-service finding",
            severity="Medium",
            cvss=6.5,
            description="Demo record",
            source="demo",
        ),
    ])

    db.commit()

    return {"message": "Demo data inserted"}
