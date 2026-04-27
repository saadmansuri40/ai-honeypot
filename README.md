# AI-Powered Cybersecurity Honeypot (MVP)

**Short (Sam-style):** Ek lightweight honeypot jo HTTP requests capture karega, unhe SQLite mein store karega, aur simple AI/heuristic se anomalous requests ko score karega. Dashboard/visualization future step hai — pehle MVP se data capture & detection ka loop banate hain.

## Features (MVP)
- Fake HTTP endpoints that mimic common web app responses.
- Request logging (method, path, headers, body, IP, timestamp) into SQLite.
- Lightweight anomaly detector (IsolationForest) that assigns anomaly scores to requests.
- Admin endpoints to fetch recent logs and anomaly stats.
- Simple fake response generator to confuse attackers.

## Tech stack
- Python 3.10+
- FastAPI (web)
- Uvicorn (ASGI server)
- scikit-learn (IsolationForest)
- pandas (data handling)
- sqlite3 (storage)

## Run locally (quick)
```bash
python -m venv venv
source venv/bin/activate   # or venv\Scripts\activate on Windows
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8080
```

## Endpoints (MVP)
- `GET /` -> fake homepage (honeypot)
- `GET /login` -> fake login page
- `POST /login` -> accepts credentials, logs attempt, returns fake "error" or "redirect"
- Any other path -> captured and logged
- `GET /admin/logs?limit=50` -> returns last logs (for dev only)
- `GET /admin/stats` -> anomaly stats and simple metrics

## Next steps (after MVP)
- Add Dockerfile + docker-compose for safe isolation
- Integrate packet-level capture (scapy / tshark) for network honeypot
- Frontend dashboard (React + charts)
- More advanced ML (LSTM on payloads / embeddings)
- Active deception: respond using GPT-like templates (careful with safety)
