import os
import re
import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from collections import defaultdict, deque
import warnings

warnings.filterwarnings('ignore')

# ===================================================================
# PART 1: LOG-BASED HEURISTIC & REGEX THREAT DETECTION ENGINE
# ===================================================================

PATTERNS = {
    "SQL_INJECTION": r"(?i)(SELECT|INSERT|DELETE|DROP|UNION|OR\s+1=1|--|;)",
    "XSS_ATTACK": r"(?i)(<script>|javascript:|onload=|onerror=)",
    "PATH_TRAVERSAL": r"(\.\./|\.\.\\)",
    "FAILED_LOGIN": r"(?i)(failed password|authentication failure|login failed)",
}

FAILED_LOGIN_THRESHOLD = 5
SAMPLE_LOGS = [
    '2026-09-24 10:00:01 IP=192.168.1.50 Status="Failed password for admin"',
    '2026-09-24 10:00:02 IP=192.168.1.50 Status="Failed password for admin"',
    '2026-09-24 10:00:03 IP=192.168.1.50 Status="Failed password for admin"',
    '2026-09-24 10:00:04 IP=192.168.1.50 Status="Failed password for admin"',
    '2026-09-24 10:00:05 IP=192.168.1.50 Status="Failed password for admin"',
    '2026-09-24 10:00:06 IP=192.168.1.50 Status="Failed password for admin"',
    '2026-09-24 10:01:10 IP=10.0.0.12 GET /index.php?user=admin\' OR 1=1--',
    '2026-09-24 10:02:15 IP=10.0.0.15 GET /app/<script>alert(1)</script>',
    '2026-09-24 10:03:00 IP=172.16.0.4 GET /files/../../etc/passwd',
    '2026-09-24 10:04:22 IP=10.0.0.99 Status="Accepted password for john"',
]

def create_mock_logfile(filename="system_access.log"):
    with open(filename, "w") as f:
        for log in SAMPLE_LOGS:
            f.write(log + "\n")
    print(f"[+] Created mock log file: {filename}")

def analyze_logs(logfile):
    print("=" * 60)
    print("        LOG-BASED THREAT DETECTION ENGINE INITIALIZED       ")
    print("=" * 60)

    if not os.path.exists(logfile):
        print(f"[-] Error: File {logfile} not found.")
        return []

    failed_logins_per_ip = defaultdict(int)
    alerts = []
    ip_pattern = r"IP=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"

    with open(logfile, "r") as f:
        for line_num, line in enumerate(f, 1):
            ip_match = re.search(ip_pattern, line)
            ip_address = ip_match.group(1) if ip_match else "UNKNOWN_IP"

            for threat_name, pattern in PATTERNS.items():
                if re.search(pattern, line):
                    if threat_name == "FAILED_LOGIN":
                        failed_logins_per_ip[ip_address] += 1
                    else:
                        alerts.append({
                            "type": threat_name,
                            "ip": ip_address,
                            "line": line_num,
                            "details": line.strip(),
                        })

    for ip, count in failed_logins_per_ip.items():
        if count >= FAILED_LOGIN_THRESHOLD:
            alerts.append({
                "type": "BRUTE_FORCE_SSH_ATTACK",
                "ip": ip,
                "line": "N/A",
                "details": f"IP triggered {count} failed login attempts (Threshold: {FAILED_LOGIN_THRESHOLD})",
            })

    if alerts:
        print(f"[!] DETECTED {len(alerts)} LOG SECURITY THREAT(S):\n")
        for alert in alerts:
            print(f"  [ALERT] Threat Type: {alert['type']}")
            print(f"          Source IP  : {alert['ip']}")
            print(f"          Line Number: {alert['line']}")
            print(f"          Payload    : {alert['details']}")
            print("-" * 60)
    else:
        print("[+] No log threats detected.")

    return alerts


# ===================================================================
# PART 2: DEEP LEARNING LSTM NETWORK TRAFFIC THREAT DETECTOR
# ===================================================================

class DeepLSTM(nn.Module):
    def __init__(self, input_size, hidden_size, num_layers, num_classes):
        super(DeepLSTM, self).__init__()
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        
        self.lstm = nn.LSTM(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=0.2 if num_layers > 1 else 0
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


class DeepNetworkThreatDetector:
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.model_path = os.path.join(self.base_dir, 'model_lstm.pth')
        self.scaler_path = os.path.join(self.base_dir, 'scaler_lstm.pkl')
        self.encoder_path = os.path.join(self.base_dir, 'label_encoder.pkl')
        self.features_path = os.path.join(self.base_dir, 'features.pkl')

        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        print(f"\n[+] Deep Network Detector - Initializing on device: {self.device}")

        if not all(os.path.exists(p) for p in [self.model_path, self.scaler_path, self.encoder_path, self.features_path]):
            raise FileNotFoundError("[!] Missing required artifact files (.pth or .pkl). Run train_lstm.py first.")

        self.scaler = joblib.load(self.scaler_path)
        self.label_encoder = joblib.load(self.encoder_path)
        self.matched_features = joblib.load(self.features_path)

        self.input_size = len(self.matched_features)
        self.hidden_size = 64
        self.num_layers = 2
        self.num_classes = len(self.label_encoder.classes_)
        self.seq_len = 5

        # Load trained weights
        self.model = DeepLSTM(self.input_size, self.hidden_size, self.num_layers, self.num_classes).to(self.device)
        self.model.load_state_dict(torch.load(self.model_path, map_location=self.device))
        self.model.eval()
        print("[+] LSTM Model and preprocessors loaded successfully!")

    def process_traffic_sample(self, raw_df):
        """
        Maps features using exact training features, scales them, and performs sequence classification.
        """
        raw_df.columns = raw_df.columns.str.strip().str.replace('"', '').str.replace("'", "")
        
        # Build dynamic mapping to match exact training features
        column_mapping = {}
        for feat in self.matched_features:
            for col in raw_df.columns:
                if col.lower() == feat.lower():
                    column_mapping[col] = feat
                    break

        raw_df = raw_df.rename(columns=column_mapping)
        
        # Ensure exact columns and order are present
        X_subset = raw_df[self.matched_features].values
        scaled_features = self.scaler.transform(X_subset)
        
        window_buffer = deque(maxlen=self.seq_len)
        predictions = []

        for row in scaled_features:
            window_buffer.append(row)
            
            if len(window_buffer) == self.seq_len:
                window_array = np.array(list(window_buffer))
                tensor_input = torch.tensor(window_array, dtype=torch.float32).unsqueeze(0).to(self.device)
                
                with torch.no_grad():
                    output = self.model(tensor_input)
                    probabilities = torch.softmax(output, dim=1)
                    pred_idx = torch.argmax(probabilities, dim=1).item()
                    confidence = probabilities[0][pred_idx].item()
                    
                label_name = self.label_encoder.inverse_transform([pred_idx])[0]
                predictions.append({
                    "prediction": label_name,
                    "confidence": confidence
                })
            else:
                predictions.append({"prediction": "BUFFERING", "confidence": 0.0})
                
        return predictions


# ===================================================================
# 3. MAIN EXECUTION PIPELINE
# ===================================================================
if __name__ == "__main__":
    # 1. Run Log Analysis
    LOG_FILE = "system_access.log"
    create_mock_logfile(LOG_FILE)
    analyze_logs(LOG_FILE)

    # 2. Run Deep Learning Network Traffic Inference Test
    try:
        network_detector = DeepNetworkThreatDetector()
        
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        DATA_PATH = os.path.join(BASE_DIR, "data", "DDoS-Friday-no-metadata.parquet")
        if not os.path.exists(DATA_PATH):
            DATA_PATH = os.path.join(BASE_DIR, "data", "cicids2017.csv")

        print(f"\n[+] Running Deep LSTM test inference using data from: {DATA_PATH}...")
        if DATA_PATH.endswith('.parquet'):
            test_df = pd.read_parquet(DATA_PATH)
        else:
            test_df = pd.read_csv(DATA_PATH)

        label_col = [c for c in test_df.columns if c.lower() == 'label'][0]
        X_test_sample = test_df.drop(columns=[label_col]).head(10)

        results = network_detector.process_traffic_sample(X_test_sample)

        print("\n--- Deep LSTM Inference Test Results ---")
        for idx, res in enumerate(results):
            print(f"Packet/Flow {idx+1} -> Status: {res['prediction']} | Confidence: {res['confidence']:.4f}")

    except Exception as e:
        print(f"[-] Deep Network Detector skipped or failed: {e}")