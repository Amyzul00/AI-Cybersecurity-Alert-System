import asyncio
from collections import deque
import json
import logging
import os
import platform
import random
import subprocess
import time
import warnings

from fastapi import (
    BackgroundTasks,
    FastAPI,
    File,
    HTTPException,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import httpx
import ipaddress
import joblib
import numpy as np
import pandas as pd
from pydantic import BaseModel
from plyer import notification
import torch
import torch.nn as nn

warnings.filterwarnings('ignore')

logging.basicConfig(
    filename='security_malware_operations_threat_alerts.log',
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
)

# Initialize FastAPI App with Security Malware Operations Branding
app = FastAPI(title='Security Malware Operations - AI Real-Time Network Threat Detection API')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, 'static')
os.makedirs(STATIC_DIR, exist_ok=True)

# Mount static folder for logo assets
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

SEQ_LEN = 5
MALICIOUS_THRESHOLD = 0.3
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', 'YOUR_VIRUSTOTAL_API_KEY')


# -------------------------------------------------------------------
# 1. THREAT INTELLIGENCE & ENRICHMENT (VIRUSTOTAL)
# -------------------------------------------------------------------
async def check_virustotal_ip_async(ip_address: str) -> dict:
    if VIRUSTOTAL_API_KEY == 'YOUR_VIRUSTOTAL_API_KEY':
        return {
            'status': 'MOCK_RESPONSE (Set VIRUSTOTAL_API_KEY env variable)',
            'ip': ip_address,
            'malicious_votes': random.randint(5, 45),
            'harmless_votes': random.randint(10, 60),
            'reputation_score': -15,
            'threat_verdict': 'FLAGGED_MALICIOUS',
            'isp': 'Security Malware Operations Protected ISP',
            'country': 'US',
        }

    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers, timeout=5.0)
            if response.status_code == 200:
                data = response.json().get('data', {}).get('attributes', {})
                stats = data.get('last_analysis_stats', {})
                return {
                    'status': 'SUCCESS',
                    'ip': ip_address,
                    'malicious_votes': stats.get('malicious', 0),
                    'suspicious_votes': stats.get('suspicious', 0),
                    'harmless_votes': stats.get('harmless', 0),
                    'reputation_score': data.get('reputation', 0),
                    'isp': data.get('as_owner', 'Unknown ISP'),
                    'country': data.get('country', 'Unknown'),
                    'threat_verdict': (
                        'MALICIOUS' if stats.get('malicious', 0) > 0 else 'CLEAN'
                    ),
                }
            return {
                'status': 'ERROR',
                'code': response.status_code,
                'message': 'Failed to fetch VirusTotal data',
            }
        except Exception as e:
            return {'status': 'ERROR', 'message': str(e)}


def check_virustotal_ip_sync(ip_address: str) -> dict:
    try:
        return asyncio.run(check_virustotal_ip_async(ip_address))
    except RuntimeError:
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(check_virustotal_ip_async(ip_address))


# -------------------------------------------------------------------
# 2. AUTOMATED FIREWALL & SOAR CAPABILITIES
# -------------------------------------------------------------------
class QuarantineRequest(BaseModel):
    ip_address: str


def block_ip_system(ip_address: str):
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        raise ValueError('Invalid IP address format')

    os_name = platform.system()
    if os_name == 'Linux':
        cmd = ['sudo', 'iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP']
    elif os_name == 'Windows':
        cmd = [
            'netsh',
            'advfirewall',
            'firewall',
            'add',
            'rule',
            f'name=SecMalOps_Quarantine_{ip_address}',
            'dir=in',
            'action=block',
            f'remoteip={ip_address}',
        ]
    else:
        raise NotImplementedError(f'Unsupported OS for auto-quarantine: {os_name}')

    result = subprocess.run(cmd, captureoutput=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f'Failed to apply firewall rule: {result.stderr}')
    logging.info(f'[SOAR] Security Malware Operations successfully quarantined and blocked IP: {ip_address}')


@app.post('/api/quarantine')
def quarantine_ip(payload: QuarantineRequest, background_tasks: BackgroundTasks):
    try:
        background_tasks.add_task(block_ip_system, payload.ip_address)
        return {
            'status': 'success',
            'message': f'Security Malware Operations Firewall: IP {payload.ip_address} queued for quarantine.',
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# -------------------------------------------------------------------
# 3. DIRECTORY SETUP & DATASET FALLBACK CREATION
# -------------------------------------------------------------------
DATA_DIR = os.path.join(BASE_DIR, 'data')
DATA_PATH = os.path.join(DATA_DIR, 'traffic_data.csv')
os.makedirs(DATA_DIR, exist_ok=True)

if not os.path.exists(DATA_PATH):
    n_samples = 1000
    data = {
        'Total Fwd Packets': np.random.randint(1, 100, n_samples),
        'Total Backward Packets': np.random.randint(0, 100, n_samples),
        'Total Length of Fwd Packets': np.random.uniform(10, 5000, n_samples),
        'Fwd Packet Length Max': np.random.uniform(10, 1500, n_samples),
        'Flow Bytes/s': np.random.uniform(100, 100000, n_samples),
        'Flow Packets/s': np.random.uniform(1, 1000, n_samples),
        'Label': np.random.choice(
            ['BENIGN', 'Ransomware', 'Trojan', 'Spyware', 'Adware', 'DDoS', 'PortScan', 'Bot'],
            size=n_samples,
            p=[0.6, 0.05, 0.05, 0.05, 0.05, 0.1, 0.05, 0.05],
        ),
    }
    df_gen = pd.DataFrame(data)
    df_gen.to_csv(DATA_PATH, index=False)
    print(f'[+] Created synthetic dataset at: {DATA_PATH}')


# -------------------------------------------------------------------
# 4. DEEP LSTM MODEL ARCHITECTURE
# -------------------------------------------------------------------
class DeepLSTM(nn.Module):
    def __init__(self, input_size, hidden_size, num_layers, num_classes):
        super(DeepLSTM, self).__init__()
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.lstm = nn.LSTM(
            input_size,
            hidden_size,
            num_layers,
            batch_first=True,
            dropout=0.2 if num_layers > 1 else 0,
        )
        self.fc1 = nn.Linear(hidden_size, 32)
        self.relu = nn.ReLU()
        self.fc2 = nn.Linear(32, num_classes)

    def forward(self, x):
        h0 = torch.zeros(self.num_layers, x.size(0), self.hidden_size).to(x.device)
        c0 = torch.zeros(self.num_layers, x.size(0), self.hidden_size).to(x.device)
        out, _ = self.lstm(x, (h0, c0))
        out = self.fc1(out[:, -1, :])
        out = self.relu(out)
        out = self.fc2(out)
        return out


# -------------------------------------------------------------------
# 5. DATASET LOADING & WEIGHTS SETUP (DYNAMIC FEATURE MAPPING FIX)
# -------------------------------------------------------------------
try:
    features = joblib.load(os.path.join(BASE_DIR, 'features.pkl'))
except FileNotFoundError:
    features = [
        'Total Fwd Packets',
        'Total Backward Packets',
        'Total Length of Fwd Packets',
        'Fwd Packet Length Max',
        'Flow Bytes/s',
        'Flow Packets/s',
    ]

df_clean = None

if os.path.exists(DATA_PATH):
    try:
        df_live = pd.read_csv(DATA_PATH, nrows=100, on_bad_lines='skip', engine='python')
        df_live.columns = df_live.columns.str.strip().str.replace('"', '').str.replace("'", "")

        column_mapping = {}
        for feat in features:
            feat_lower = feat.lower()
            for col in df_live.columns:
                if col.lower() == feat_lower:
                    column_mapping[col] = feat
                    break

        if len(column_mapping) == len(features):
            df_live = df_live.rename(columns=column_mapping)
            matched_features = list(column_mapping.values())
            label_col = [c for c in df_live.columns if c.lower() == 'label']
            cols_to_use = matched_features + (label_col if label_col else [])

            df_clean = df_live[cols_to_use].replace([np.inf, -np.inf], np.nan).dropna()
            features = matched_features
    except Exception as e:
        logging.warning(f'Failed reading dataset: {e}. Running in Fallback Mode.')
        df_clean = None

try:
    scaler = joblib.load(os.path.join(BASE_DIR, 'scaler_lstm.pkl'))
except FileNotFoundError:
    scaler = joblib.load(os.path.join(BASE_DIR, 'scaler.pkl'))

try:
    label_encoder = joblib.load(os.path.join(BASE_DIR, 'label_encoder.pkl'))
except FileNotFoundError:
    label_encoder = joblib.load(os.path.join(BASE_DIR, 'label_encoder_lstm.pkl'))

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

# Dynamically initialize model based on loaded feature dimensions to prevent size mismatch
model = DeepLSTM(len(features), 64, 2, len(label_encoder.classes_)).to(device)

try:
    model.load_state_dict(torch.load(os.path.join(BASE_DIR, 'model_lstm.pth'), map_location=device))
except FileNotFoundError:
    model.load_state_dict(torch.load(os.path.join(BASE_DIR, 'lstm_model.pth'), map_location=device))

model.eval()
print(f'[+] Security Malware Operations Deep LSTM Model loaded successfully with input_size={len(features)}.')


# -------------------------------------------------------------------
# 6. SLIDING WINDOW & PACKET GENERATOR
# -------------------------------------------------------------------
class PacketSlidingWindow:
    def __init__(self, seq_len=5, num_features=6):
        self.seq_len = seq_len
        self.num_features = num_features
        self.buffer = deque([np.zeros(num_features) for _ in range(seq_len)], maxlen=seq_len)

    def add_packet(self, features_array):
        self.buffer.append(features_array)

    def get_sequence_tensor(self, scaler_obj):
        scaled_seq = scaler_obj.transform(np.array(self.buffer))
        return torch.tensor(scaled_seq, dtype=torch.float32).unsqueeze(0)


def generate_live_packet(custom_features=None, custom_label=None):
    ip = f'192.168.1.{random.randint(2, 254)}'
    if custom_features is not None:
        return ip, np.array(custom_features), custom_label if custom_label else 'SANDBOX_LOG'

    if df_clean is not None and not df_clean.empty:
        sample = df_clean.sample(1).iloc[0]
        return ip, sample[features].values.astype(float), sample['Label'] if 'Label' in sample else 'BENIGN'

    raw_features = [
        random.randint(1, 10),
        random.randint(1, 10),
        random.randint(100, 1000),
        random.randint(50, 200),
        random.uniform(10.0, 500.0),
        random.uniform(1.0, 20.0),
    ]
    return ip, np.array(raw_features[:len(features)]), 'BENIGN'


CRITICAL_FAMILIES = {'Ransomware', 'Trojan', 'DDoS', 'Bot', 'Worms', 'Botnet'}
WARNING_FAMILIES = {'Adware', 'Spyware', 'PortScan', 'Generic Malware'}


def classify_severity(threat_name, confidence_pct):
    clean_threat = str(threat_name).strip()
    if clean_threat.upper() == 'BENIGN':
        if confidence_pct >= 70.0:
            return 'NORMAL', '🟢 PASS'
        return 'WARNING', '⚠️ PASS (Low Confidence)'

    if clean_threat in CRITICAL_FAMILIES:
        if confidence_pct >= 50.0:
            return 'CRITICAL', f'🚨 ALERT ({clean_threat})'
        return 'WARNING', f'⚠️ SUSPICIOUS ({clean_threat})'

    if clean_threat in WARNING_FAMILIES:
        return 'WARNING', f'⚠ WARNING ({clean_threat})'

    if confidence_pct >= 70.0:
        return 'CRITICAL', f'🚨 ALERT ({clean_threat})'
    return 'WARNING', f'⚠️ SUSPICIOUS ({clean_threat})'


def trigger_alert(ip, threat_type):
    try:
        notification.notify(
            title='🛡️ Security Malware Operations: Threat Detected!',
            message=f'Protected IP: {ip}\nDetected Threat: {threat_type}',
            app_name='Security Malware Operations',
            timeout=4,
        )
    except Exception:
        pass


# -------------------------------------------------------------------
# 7. FASTAPI REST & WEBSOCKET ENDPOINTS
# -------------------------------------------------------------------
@app.get('/')
def read_root():
    return {
        'app_name': 'Security Malware Operations - AI Threat Protection',
        'status': 'Engine Active',
        'logo': '/static/logo.png',
        'websocket_url': '/ws/stream',
        'dashboard_url': '/dashboard'
    }


@app.get('/dashboard', response_class=HTMLResponse)
async def dashboard():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Security Malware Operations - Threat Monitoring Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #121212; color: #e0e0e0; margin: 0; padding: 20px; }
            .header { display: flex; align-items: center; background: #1e1e1e; padding: 15px 25px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
            .header img { height: 50px; width: 50px; border-radius: 50%; object-fit: cover; margin-right: 20px; border: 2px solid #4CAF50; }
            .header h1 { margin: 0; font-size: 24px; color: #ffffff; }
            .log-container { margin-top: 20px; background: #1e1e1e; padding: 20px; border-radius: 8px; height: 400px; overflow-y: auto; border: 1px solid #333; }
            .log-item { padding: 10px; margin-bottom: 8px; border-radius: 4px; font-family: monospace; }
            .CRITICAL { background: rgba(244, 67, 54, 0.2); border-left: 5px solid #f4433e; }
            .WARNING { background: rgba(255, 152, 0, 0.2); border-left: 5px solid #ff9800; }
            .NORMAL { background: rgba(76, 175, 80, 0.2); border-left: 5px solid #4CAF50; }
        </style>
    </head>
    <body>
        <div class="header">
            <img src="/static/logo.png" alt="Security Malware Operations Logo">
            <div>
                <h1>Security Malware Operations</h1>
                <p style="margin: 5px 0 0 0; color: #b0b0b0;">AI Real-Time Threat Detection & Defense Dashboard</p>
            </div>
        </div>
        
        <h2>Live Traffic Stream</h2>
        <div id="logs" class="log-container">Waiting for network stream...</div>

        <script>
            const ws = new WebSocket(`ws://${window.location.host}/ws/stream`);
            const logsDiv = document.getElementById('logs');

            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                if (logsDiv.innerText === 'Waiting for network stream...') {
                    logsDiv.innerHTML = '';
                }
                const item = document.createElement('div');
                item.className = `log-item ${data.status}`;
                item.innerHTML = `<b>[Packet #${data.packet_id}]</b> IP: ${data.ip} | Status: <b>${data.status_tag}</b> | Threat: <b>${data.threat_type}</b> | Confidence: ${data.confidence_pct}%`;
                logsDiv.prepend(item);
            };
        </script>
    </body>
    </html>
    """


@app.get('/virustotal/lookup/{ip_address}')
async def virustotal_ip_lookup(ip_address: str):
    return await check_virustotal_ip_async(ip_address)


@app.websocket('/ws/stream')
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    packet_count = 1
    window = PacketSlidingWindow(seq_len=SEQ_LEN, num_features=len(features))

    try:
        while True:
            ip, raw_features, _ = generate_live_packet()
            window.add_packet(raw_features)
            tensor_in = window.get_sequence_tensor(scaler).to(device)

            with torch.no_grad():
                out = model(tensor_in)
                probs = torch.softmax(out, dim=1)
                conf, pred = torch.max(probs, 1)

            threat_name = label_encoder.inverse_transform([pred.item()])[0]
            confidence_pct = conf.item() * 100.0
            severity, status_tag = classify_severity(threat_name, confidence_pct)

            if severity == 'CRITICAL' and confidence_pct >= 85.0:
                try:
                    block_ip_system(ip)
                except Exception as err:
                    logging.error(f'Security Malware Operations auto-quarantine failed for {ip}: {err}')

            vt_info = None
            if severity in ['CRITICAL', 'WARNING']:
                vt_info = await check_virustotal_ip_async(ip)
                if severity == 'CRITICAL':
                    trigger_alert(ip, threat_name)

            data_payload = {
                'brand': 'Security Malware Operations',
                'packet_id': packet_count,
                'ip': ip,
                'status': severity,
                'status_tag': status_tag,
                'threat_type': threat_name,
                'confidence_pct': round(confidence_pct, 2),
                'virustotal_intelligence': vt_info,
            }

            await websocket.send_text(json.dumps(data_payload))
            packet_count += 1
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        print('[!] Security Malware Operations WebSocket client disconnected.')


# -------------------------------------------------------------------
# 8. MAIN CLI EXECUTION LOOP
# -------------------------------------------------------------------
def main():
    print('\n==================================================')
    print(' SECURITY MALWARE OPERATIONS: AI NETWORK PROTECTION ')
    print('==================================================')

    packet_count = 1
    correct_predictions = 0
    window = PacketSlidingWindow(seq_len=SEQ_LEN, num_features=len(features))

    try:
        while packet_count <= 25:
            ip, raw_features, actual_label = generate_live_packet()
            window.add_packet(raw_features)
            tensor_input = window.get_sequence_tensor(scaler).to(device)

            with torch.no_grad():
                outputs = model(tensor_input)
                probabilities = torch.softmax(outputs, dim=1)[0]

            benign_idx = (
                list(label_encoder.classes_).index('BENIGN')
                if 'BENIGN' in label_encoder.classes_
                else 0
            )
            benign_prob = probabilities[benign_idx].item()
            malicious_prob = 1.0 - benign_prob

            if malicious_prob > MALICIOUS_THRESHOLD:
                probs_copy = probabilities.clone()
                probs_copy[benign_idx] = -1.0
                predicted_class = torch.argmax(probs_copy).item()
                confidence_pct = probabilities[predicted_class].item() * 100.0
            else:
                predicted_class = benign_idx
                confidence_pct = benign_prob * 100.0

            threat_name = label_encoder.inverse_transform([predicted_class])[0]
            severity, status_tag = classify_severity(threat_name, confidence_pct)

            if str(threat_name).strip().upper() == str(actual_label).strip().upper():
                correct_predictions += 1

            running_accuracy = (correct_predictions / packet_count) * 100.0
            msg = (
                f'{status_tag} IP: {ip} | Status: {severity} | Threat:'
                f' {threat_name} | Confidence: {confidence_pct:.1f}% | Acc:'
                f' {running_accuracy:.1f}%'
            )
            print(msg)

            if severity == 'CRITICAL' and confidence_pct >= 85.0:
                try:
                    block_ip_system(ip)
                except Exception as e:
                    logging.error(f'CLI auto-quarantine error: {e}')

            if severity in ['CRITICAL', 'WARNING']:
                vt_res = check_virustotal_ip_sync(ip)
                logging.warning(
                    f"{msg} | VT Verdict: {vt_res.get('threat_verdict', 'UNKNOWN')}"
                )
                if severity == 'CRITICAL':
                    trigger_alert(ip, threat_name)

            packet_count += 1
            time.sleep(0.5)

        final_acc = (correct_predictions / 25) * 100.0
        print('\n[+] Security Malware Operations finished processing 25 data sets.')
        print(f'[+] Total Model Accuracy: {final_acc:.2f}% ({correct_predictions}/25 correct)')
    except KeyboardInterrupt:
        print('\n[!] Security Malware Operations execution stopped by user.')


if __name__ == '__main__':
    main()