
import os
import json
import random
import asyncio
import logging
import warnings
from contextlib import asynccontextmanager

import jwt
import torch
import torch.nn as nn
import numpy as np
import pandas as pd
import joblib

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

from auth import router as auth_router, SECRET_KEY, ALGORITHM


warnings.filterwarnings('ignore')

# Logging konfigurasi
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ThreatDetection")

def verify_websocket_token(token: str):
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )

        if not payload.get("sub") or not payload.get("role"):
            return None

        return payload

    except jwt.InvalidTokenError:
        return None

# -------------------------------------------------------------------
# --- 1. DEEP LSTM MODEL STRUCTURE (PYTORCH) ---
# -------------------------------------------------------------------
class DeepLSTM(nn.Module):
    def __init__(self, input_size, hidden_size, num_layers, num_classes):
        super(DeepLSTM, self).__init__()
        self.lstm = nn.LSTM(input_size, hidden_size, num_layers, batch_first=True, dropout=0.2)
        self.fc1 = nn.Linear(hidden_size, 32)
        self.relu = nn.ReLU()
        self.fc2 = nn.Linear(32, num_classes)
        
    def forward(self, x):
        out, _ = self.lstm(x)
        out = self.fc1(out[:, -1, :])
        out = self.relu(out)
        out = self.fc2(out)
        return out

# Dictionary global untuk menyimpan model & preprocessor
ml_resources = {}

# -------------------------------------------------------------------
# 2. WEBSOCKET CONNECTION MANAGER (MULTIPLE CLIENT BROADCAST)
# -------------------------------------------------------------------
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"[+] Klien terhubung. Jumlah klien aktif: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"[-] Klien terputus. Baki klien aktif: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

manager = ConnectionManager()

# -------------------------------------------------------------------
# 3. LIFESPAN HANDLER (Memuatkan Dataset, Model & Preprocessor)
# -------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- PROSES STARTUP ---
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DATA_DIR = os.path.join(BASE_DIR, "data")
  
    DATA_PATH = os.path.join(DATA_DIR, "traffic_data.csv")
    ALT_DATA_PATH = os.path.join(BASE_DIR, "cicids2017.csv")

    # Load the five features saved with the trained LSTM model
    features_path = os.path.join(BASE_DIR, "features.pkl")
    target_features = joblib.load(features_path)

    # 1. Load the scaler
    scaler_path = os.path.join(BASE_DIR, 'scaler_lstm.pkl') if os.path.exists(os.path.join(BASE_DIR, 'scaler_lstm.pkl')) else os.path.join(BASE_DIR, 'scaler.pkl')
    scaler = joblib.load(scaler_path)

    # 2. Load the label encoder
    encoder_path = os.path.join(BASE_DIR, 'label_encoder.pkl') if os.path.exists(os.path.join(BASE_DIR, 'label_encoder.pkl')) else os.path.join(BASE_DIR, 'label_encoder_lstm.pkl')
    label_encoder = joblib.load(encoder_path)

    
    # 3. Memuatkan Model PyTorch LSTM (.pth / .pt)
    model = DeepLSTM(len(target_features), 64, 2, len(label_encoder.classes_))
    model_path = (
        os.path.join(BASE_DIR, 'model_lstm.pth')
        if os.path.exists(os.path.join(BASE_DIR, 'model_lstm.pth'))
        else os.path.join(BASE_DIR, 'lstm_model.pth')
    )
    model.load_state_dict(torch.load(model_path, map_location=torch.device('cpu')))
    model.eval()

    # 1. Load the traffic dataset
    df_clean = None

    active_data_path = (
        DATA_PATH if os.path.exists(DATA_PATH)
        else ALT_DATA_PATH if os.path.exists(ALT_DATA_PATH)
        else None
    )

    if active_data_path:
        try:
            df_live = pd.read_csv(
                active_data_path,
                on_bad_lines="skip",
                engine="python"
            )

            df_live.columns = (
                df_live.columns.astype(str)
                .str.strip()
                .str.replace('"', '', regex=False)
                .str.replace("'", '', regex=False)
            )

            # Match dataset columns to the five trained model features
            column_mapping = {}

            for feature in target_features:
                for column in df_live.columns:
                    if column.lower() == feature.lower():
                        column_mapping[column] = feature
                        break

            missing_features = [
                feature for feature in target_features
                if feature not in column_mapping.values()
            ]

            if missing_features:
                logger.warning(
                    "Dataset is missing required features: %s",
                    missing_features
                )
            else:
                df_live = df_live.rename(columns=column_mapping)

                selected_columns = list(target_features)

                label_columns = [
                    column for column in df_live.columns
                    if column.lower() == "label"
                ]

                if label_columns:
                    selected_columns.append(label_columns[0])

                df_clean = (
                    df_live[selected_columns]
                    .replace([np.inf, -np.inf], np.nan)
                    .dropna(subset=target_features)
                )

                logger.info(
                    "Loaded %s traffic records from %s",
                    len(df_clean),
                    active_data_path
                )

        except Exception:
            logger.exception("Failed to load traffic dataset")

    # 2. Create sample data only if no usable dataset was loaded
    if df_clean is None or df_clean.empty:
        logger.warning(
            "No usable dataset found. Generating synthetic traffic data."
        )

        os.makedirs(DATA_DIR, exist_ok=True)

        sample_count = 1000

        df_clean = pd.DataFrame({
            "Total Fwd Packets": np.random.randint(
                1, 100, sample_count
            ),
            "Total Backward Packets": np.random.randint(
                0, 100, sample_count
            ),
            "Fwd Packet Length Max": np.random.uniform(
                10, 1500, sample_count
            ),
            "Flow Bytes/s": np.random.uniform(
                100, 100000, sample_count
            ),
            "Flow Packets/s": np.random.uniform(
                1, 1000, sample_count
            ),
        })

        # Do not overwrite an existing traffic dataset
        if not os.path.exists(DATA_PATH):
            df_clean.to_csv(DATA_PATH, index=False)

    # 3. Store the loaded AI resources
    ml_resources["scaler"] = scaler
    ml_resources["label_encoder"] = label_encoder
    ml_resources["model"] = model
    ml_resources["df_clean"] = df_clean
    ml_resources["target_features"] = target_features

    logger.info("LSTM model and traffic dataset initialized.")

    # 4. Start the background traffic generator
    traffic_task = asyncio.create_task(
        background_traffic_generator()
    )

    try:
        yield
    finally:
        # Stop the background task when FastAPI shuts down
        traffic_task.cancel()

        try:
            await traffic_task
        except asyncio.CancelledError:
            pass

        ml_resources.clear()
        logger.info("Threat detection resources released.")

# -------------------------------------------------------------------
# 4. INISIALISASI FASTAPI & MIDDLEWARE
# -------------------------------------------------------------------
app = FastAPI(title="AI Real-Time Threat Detection API", lifespan=lifespan)
app.include_router(auth_router)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------------------------
# 5. PENJANA TRAFIK & LATAR BELAKANG BROADCAST
# -------------------------------------------------------------------
def generate_live_packet():
    df_clean = ml_resources['df_clean']
    target_features = ml_resources['target_features']
    
    ip = f"192.168.1.{random.randint(2, 254)}"
    if df_clean is not None and not df_clean.empty:
        sample = df_clean.sample(1).iloc[0]
        raw_features = sample[target_features].values
        return ip, raw_features
    else:
        raw_features = [
            random.randint(1, 100), random.randint(1, 100),
            random.uniform(100, 5000), random.uniform(50, 1500),
            random.uniform(100.0, 50000.0), random.uniform(1.0, 500.0)
        ]
        return ip, np.array(raw_features)

async def background_traffic_generator():
    """Memancarkan data trafik secara berterusan kepada semua sambungan WebSocket."""
    packet_count = 1
    while True:
        if manager.active_connections:
            try:
                scaler = ml_resources['scaler']
                label_encoder = ml_resources['label_encoder']
                model = ml_resources['model']
                
                ip, raw_features = generate_live_packet()

                # Preprocessing & Inferens PyTorch Deep LSTM
                scaled = scaler.transform([raw_features])
                tensor_in = torch.tensor(scaled, dtype=torch.float32).unsqueeze(1)

                with torch.no_grad():
                    out = model(tensor_in)
                    _, pred = torch.max(out, 1)

                threat_name = label_encoder.inverse_transform([pred.item()])[0]
                is_threat = threat_name != "BENIGN"

                # Payload lengkap (sesuai untuk UI web mahupun React Dashboard)
                data_payload = {
                    "packet_id": packet_count,
                    "timestamp": pd.Timestamp.now().strftime("%H:%M:%S"),
                    "ip": ip,
                    "ip_address": ip,
                    "status": "CRITICAL" if is_threat else "NORMAL",
                    "threat_type": threat_name,
                    "packet_size": round(float(raw_features[2]), 2),
"flow_bytes_sec": round(float(raw_features[3]), 2),
                    "metrics": {
    "total_fwd_packets": float(raw_features[0]),
    "total_bwd_packets": float(raw_features[1]),
    "fwd_packet_length_max": float(raw_features[2]),
    "flow_bytes_s": float(raw_features[3]),
    "flow_packets_s": float(raw_features[4])
},
                    "alert": is_threat
                }

                await manager.broadcast(data_payload)
                packet_count += 1
            except Exception as e:
                logger.error(f"[!] Ralat pada background generator: {e}")
                
        await asyncio.sleep(1) # Hantar data setiap 1 saat

# -------------------------------------------------------------------
# 6. REST API, DASHBOARD UI & WEBSOCKET ENDPOINTS
# -------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    html_content = """
    <!DOCTYPE html>
    <html>
        <head>
            <title>AI Real-Time Threat Detection Dashboard</title>
            <style>
                body { font-family: monospace; background: #121212; color: #fff; padding: 20px; }
                h1 { color: #00ffcc; }
                #logs { background: #1e1e1e; padding: 15px; border-radius: 8px; height: 450px; overflow-y: scroll; border: 1px solid #333; }
                .alert-critical { color: #ff5555; font-weight: bold; }
                .alert-warning { color: #ffaa00; font-weight: bold; }
                .normal { color: #55ff55; }
            </style>
        </head>
        <body>
            <h1>🚨 AI Real-Time Deep LSTM Threat Detection</h1>
            <p>Status Engine: <strong style="color: #00ffcc;">Active (WebSocket Streaming)</strong></p>
            <div id="logs"></div>
            <script>
                const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
                const ws = new WebSocket(`${wsProtocol}//${window.location.host}/ws/stream`);
                const logsDiv = document.getElementById("logs");

                ws.onmessage = function(event) {
                    const data = JSON.parse(event.data);
                    const item = document.createElement("p");
                    
if (data.status === "CRITICAL" && data.alert === true) {
    item.className = "alert-critical";
    item.innerText =
        `[🚨 CRITICAL] #${data.packet_id} | ${data.timestamp} | IP: ${data.ip} | Threat: ${data.threat_type} | Flow: ${data.flow_bytes_sec} B/s`;
} else {
    item.className = "normal";
    item.innerText =
        `[✓ PASS] #${data.packet_id} | ${data.timestamp} | IP: ${data.ip} | Status: Normal (${data.threat_type || "BENIGN"})`;
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
@app.websocket("/ws/live-traffic")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Menguatkan talian tetap hidup
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)