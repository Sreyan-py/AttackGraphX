# AttackGraphX — Member 1

Completed: Nmap + host discovery, vulnerability module, SQLite/SQLAlchemy integration, FastAPI APIs, and automated tests.

## Run
```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```
Swagger: http://127.0.0.1:8000/docs

## Demo
POST `/api/demo/seed`, then GET `/api/hosts` and `/api/vulnerabilities`.

## Authorized Nmap
POST `/api/discovery` with `{"target":"192.168.56.0/24","run_nmap":true}` only for a network you are authorized to test. The implementation uses `nmap -Pn -sV --open` and XML parsing; it does not perform exploitation.

## Tests
`pytest -q`

Database file: `attackgraphx.db`
