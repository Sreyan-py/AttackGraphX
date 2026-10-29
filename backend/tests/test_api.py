from fastapi.testclient import TestClient
from app.main import app
client=TestClient(app)
def test_root(): assert client.get("/").status_code==200
def test_health(): assert client.get("/api/health").json()["status"]=="healthy"
def test_safe_discovery(): assert client.post("/api/discovery",json={"target":"192.168.56.0/24","run_nmap":False}).json()["mode"]=="safe-demo"
def test_bad_target(): assert client.post("/api/discovery",json={"target":"10.0.0.1;rm","run_nmap":True}).status_code==400
