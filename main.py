from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse, PlainTextResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import sqlite3
import time
import threading
import pandas as pd
import os
from sklearn.ensemble import IsolationForest
import numpy as np
from typing import Dict, Any

DB_PATH = 'honeypot.db'

app = FastAPI(title='AI Honeypot - MVP')
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------
# Database helpers
# ------------------------------

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL,
        ip TEXT,
        method TEXT,
        path TEXT,
        ua TEXT,
        content_length INTEGER,
        body_sample TEXT,
        anomaly_score REAL
    )
    ''')
    conn.commit()
    conn.close()

init_db()

# ------------------------------
# Simple Anomaly Detector
# ------------------------------
class AnomalyDetector:
    def __init__(self, retrain_interval=60):
        self.retrain_interval = retrain_interval
        self.lock = threading.Lock()
        self.model = None
        self.last_retrain = 0
        # start with a benign baseline dataset
        self.baseline = pd.DataFrame(columns=['content_length', 'ua_len'])

    def featurize(self, recs: pd.DataFrame) -> np.ndarray:
        # features: content length, user-agent length
        X = recs[['content_length', 'ua_len']].fillna(0).astype(float).values
        return X

    def maybe_retrain(self):
        with self.lock:
            now = time.time()
            if (now - self.last_retrain) < self.retrain_interval and self.model is not None:
                return
            try:
                conn = sqlite3.connect(DB_PATH)
                df = pd.read_sql_query('SELECT content_length, LENGTH(ua) as ua_len FROM requests', conn)
                conn.close()
                if len(df) < 30:
                    # not enough data — expand baseline with synthetic benign samples
                    if len(self.baseline) < 50:
                        # generate some benign-like rows
                        for _ in range(50):
                            self.baseline = pd.concat([self.baseline, pd.DataFrame({'content_length':[np.random.randint(0,200)], 'ua_len':[np.random.randint(20,120)]})], ignore_index=True)
                        X = self.featurize(self.baseline)
                    else:
                        X = self.featurize(self.baseline)
                else:
                    X = self.featurize(df.rename(columns={'LENGTH(ua)':'ua_len'})) if 'LENGTH(ua)' in df.columns else self.featurize(df)

                # train IsolationForest
                model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
                model.fit(X)
                self.model = model
                self.last_retrain = now
                print('[detector] retrained on', len(X), 'samples')
            except Exception as e:
                print('retrain failed', e)

    def score(self, rec: Dict[str,Any]) -> float:
        # return anomaly score: lower -> more anomalous in sklearn's decision_function
        with self.lock:
            if self.model is None:
                return 0.0
            x = np.array([[rec.get('content_length',0), rec.get('ua_len',0)]], dtype=float)
            try:
                s = self.model.decision_function(x)[0]
                # normalize to 0..1 (approx)
                return float((s - (-0.5)) / (0.5 - (-0.5)))
            except Exception as e:
                return 0.0

anomaly_detector = AnomalyDetector(retrain_interval=30)

# background retrain thread
def retrain_loop():
    while True:
        anomaly_detector.maybe_retrain()
        time.sleep(10)

threading.Thread(target=retrain_loop, daemon=True).start()

# ------------------------------
# Helpers: logging and fake responses
# ------------------------------

def log_request(ip, method, path, ua, content_length, body_sample, anomaly_score=None):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO requests (ts, ip, method, path, ua, content_length, body_sample, anomaly_score) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
              (time.time(), ip, method, path, ua, content_length, body_sample, anomaly_score))
    conn.commit()
    conn.close()

def load_decoy(filename, default=''):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(base_dir, 'decoys', filename)
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            return f.read()
    return default

FAKE_PAGES = {
    '/': '<html><head><title>Welcome</title></head><body><h1>Welcome</h1><p>Under construction...</p></body></html>',
    '/login': load_decoy('admin.html', '<h1>Login</h1>'),
    '/wp-login.php': load_decoy('wp-login.html', '<h1>WP Login</h1>'),
    '/phpmyadmin': load_decoy('phpmyadmin.html', '<h1>phpMyAdmin</h1>'),
    '/.env': 'DB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_PORT=3306\nDB_DATABASE=fake_db\nDB_USERNAME=root\nDB_PASSWORD=secret',
}

def fake_response_for_path(path: str) -> Response:
    # simple mapping + some unpredictability
    if path in FAKE_PAGES:
        return HTMLResponse(content=FAKE_PAGES[path], status_code=200)
    if path.startswith('/admin'):
        return JSONResponse({'error':'not found'}, status_code=404)
    # random fake 200 with some text
    return PlainTextResponse(content='OK', status_code=200)

# ------------------------------
# Catch-all honeypot routes
# ------------------------------

@app.middleware('http')
async def capture_requests(request: Request, call_next):
    # capture before handling
    ip = request.client.host if request.client else 'unknown'
    method = request.method
    path = request.url.path
    ua = request.headers.get('user-agent','')
    try:
        raw_body = await request.body()
        body = raw_body.decode('utf-8', errors='ignore')
        # Re-inject the body so that subsequent endpoints can consume it
        async def receive():
            return {"type": "http.request", "body": raw_body}
        request._receive = receive
    except Exception:
        body = ''
    content_length = len(body)
    body_sample = body[:500]

    # featurize for detector
    rec = {'content_length': content_length, 'ua_len': len(ua)}
    score = anomaly_detector.score(rec)

    # log
    log_request(ip, method, path, ua, content_length, body_sample, float(score))

    # If the path is admin endpoints, call the real handler; otherwise serve fake response
    if path.startswith('/admin'):
        response = await call_next(request)
        return response

    # serve fake response (deception)
    return fake_response_for_path(path)

# Admin endpoints
@app.get('/admin/logs')
async def get_logs(limit: int = 50):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, ts, ip, method, path, ua, content_length, SUBSTR(body_sample,1,200) as body_sample, anomaly_score FROM requests ORDER BY id DESC LIMIT ?', (limit,))
    rows = c.fetchall()
    conn.close()
    keys = ['id','ts','ip','method','path','ua','content_length','body_sample','anomaly_score']
    result = [dict(zip(keys, r)) for r in rows]
    return {'count': len(result), 'rows': result}

@app.get('/admin/stats')
async def stats():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query('SELECT anomaly_score FROM requests', conn)
    conn.close()
    if df.empty:
        return {'total':0, 'anomaly_mean':None, 'anomaly_max':None}
    return {'total': len(df), 'anomaly_mean': float(df['anomaly_score'].mean()), 'anomaly_max': float(df['anomaly_score'].max())}

@app.post('/login')
async def login(request: Request):
    # This route exists but capture middleware already logged
    try:
        form = await request.form()
        user = form.get('user')
        passwd = form.get('pass')
    except Exception:
        body = (await request.body()).decode('utf-8', errors='ignore')
        user = None
        passwd = None
    # respond with fake login error
    return JSONResponse({'status':'error','message':'Invalid credentials'}, status_code=401)

# Mount static files for dashboard
if os.path.exists('static'):
    app.mount('/admin/dashboard', StaticFiles(directory='static', html=True), name='dashboard')

# quick health
@app.get('/health')
async def health():
    return {'status':'ok'}

if __name__ == '__main__':
    import uvicorn
    uvicorn.run('main:app', host='0.0.0.0', port=8080, reload=True)
