import warnings
warnings.filterwarnings('ignore')

import os
import asyncio
import random
import pandas as pd
import numpy as np
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

app = FastAPI(title="AI Threat Detection WebSocket Server")

# --- 1. SET UP PATH & LOAD DATASET ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, "cicids2017.csv")

try:
    df_live = pd.read_csv(DATA_PATH)
    df_live.columns = df_live.columns.str.strip()

    features = [
        'Total Fwd Packets',
        'Total Backward Packets',
        'Total Length of Fwd Packets',
        'Fwd Packet Length Max',
        'Flow Bytes/s',
        'Flow Packets/s'
    ]

    df_clean = df_live[features + ['Label']].replace([np.inf, -np.inf], np.nan).dropna()
    print("[+] Dataset CICIDS2017 berjaya dimuatkan.")
except Exception as e:
    df_clean = None
    print(f"[!] Gagal memuatkan dataset: {e}")

def generate_live_packet():
    if df_clean is None:
        return "192.168.1.1", [0]*6, "Normal"
    
    sample = df_clean.sample(1).iloc[0]
    ip = f"192.168.1.{random.randint(2, 254)}"
    packet_features = sample[features].values.tolist()
    label = sample['Label']
    suspected_type = label if label != 'BENIGN' else 'Normal'
    
    return ip, packet_features, suspected_type

# --- 2. WEBSOCKET CONNECTION MANAGER ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            await connection.send_json(message)

manager = ConnectionManager()

# --- 3. ENDPOINTS ---
@app.get("/")
async def get_dashboard():
    # Antaramuka ringkas (HTML + JS) untuk menguji WebSocket secara live
    html_content = """
    <!DOCTYPE html>
    <html>
        <head>
            <title>AI Threat Streaming Dashboard</title>
            <style>
                body { font-family: monospace; background: #121212; color: #fff; padding: 20px; }
                h1 { color: #00ffcc; }
                #logs { background: #1e1e1e; padding: 15px; border-radius: 8px; height: 400px; overflow-y: scroll; }
                .alert { color: #ff5555; font-weight: bold; }
                .normal { color: #55ff55; }
            </style>
        </head>
        <body>
            <h1>🚨 Live AI Threat Detection Streaming</h1>
            <div id="logs"></div>
            <script>
                const ws = new WebSocket("ws://" + window.location.host + "/ws/stream");
                const logsDiv = document.getElementById("logs");

                ws.onmessage = function(event) {
                    const data = JSON.parse(event.data);
                    const item = document.createElement("p");
                    
                    if (data.status === "ALERT") {
                        item.className = "alert";
                        item.innerText = `[🚨 CRITICAL ALERT] IP: ${data.ip} | Type: ${data.threat} | Packet Size: ${data.metric}`;
                    } else {
                        item.className = "normal";
                        item.innerText = `[✓ PASS] IP: ${data.ip} | Status: Normal`;
                    }
                    
                    logsDiv.appendChild(item);
                    logsDiv.scrollTop = logsDiv.scrollHeight;
                };
            </script>
        </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.websocket("/ws/stream")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    packet_count = 1
    try:
        while True:
            ip, packet_features, suspected_type = generate_live_packet()
            
            if suspected_type != "Normal":
                data = {
                    "count": packet_count,
                    "status": "ALERT",
                    "ip": ip,
                    "threat": suspected_type,
                    "metric": round(packet_features[0], 2)
                }
            else:
                data = {
                    "count": packet_count,
                    "status": "PASS",
                    "ip": ip,
                    "threat": "Normal",
                    "metric": round(packet_features[0], 2)
                }
                
            await manager.broadcast(data)
            packet_count += 1
            await asyncio.sleep(1) # Hantar data setiap 1 saat
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)