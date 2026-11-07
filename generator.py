import os
import random
import numpy as np
import pandas as pd

# Setup direktori asas
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DATA_PATH = os.path.join(DATA_DIR, "traffic_data.csv")

# Cipta folder data jika belum wujud
os.makedirs(DATA_DIR, exist_ok=True)

# -------------------------------------------------------------------
# 1. JANA DATA DUMMY (Satu kali jika fail traffic_data.csv belum ada)
# -------------------------------------------------------------------
if not os.path.exists(DATA_PATH):
    n_samples = 1000
    data = {
        'Total Fwd Packets': np.random.randint(1, 100, n_samples),
        'Total Backward Packets': np.random.randint(0, 100, n_samples),
        'Total Length of Fwd Packets': np.random.uniform(10, 5000, n_samples),
        'Fwd Packet Length Max': np.random.uniform(10, 1500, n_samples),
        'Flow Bytes/s': np.random.uniform(100, 100000, n_samples),
        'Flow Packets/s': np.random.uniform(1, 1000, n_samples),
        'Label': np.random.choice(['BENIGN', 'DDoS', 'PortScan', 'Bot'], size=n_samples, p=[0.7, 0.1, 0.1, 0.1])
    }
    df_gen = pd.DataFrame(data)
    df_gen.to_csv(DATA_PATH, index=False)
    print(f"[+] Fail {DATA_PATH} berjaya dicipta!")

# -------------------------------------------------------------------
# 2. MUATKAN DATASET TRAFFIC_DATA.CSV
# -------------------------------------------------------------------
df_clean = None

if os.path.exists(DATA_PATH):
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
        # Pastikan ciri-ciri ini wujud dalam CSV
        existing_features = [f for f in features if f in df_live.columns]
        if existing_features:
            # Pelihara lajur 'Label' jika ada
            cols_to_use = existing_features + (['Label'] if 'Label' in df_live.columns else [])
            df_clean = df_live[cols_to_use].replace([np.inf, -np.inf], np.nan).dropna()
            print(f"[+] Berjaya memuatkan {len(df_clean)} baris daripada dataset traffic_data.csv.")
    except Exception as e:
        print(f"[!] Gagal membaca dataset: {e}")

# -------------------------------------------------------------------
# 3. PENJANA TRAFIK MASA NYATA (LIVE PACKET GENERATOR)
# -------------------------------------------------------------------
def generate_live_packet():
    ip = f"192.168.1.{random.randint(2, 254)}"
    
    # JIKA DATASET WUJUD: Ambil baris sampel dari dataset
    if df_clean is not None and not df_clean.empty:
        sample = df_clean.sample(1).iloc[0]
        feature_cols = [f for f in features if f in sample.index]
        packet_features = sample[feature_cols].values
        
        # Semak lajur Label
        suspected_type = "Normal"
        if "Label" in sample and sample["Label"] != "BENIGN":
            suspected_type = sample["Label"]
            
        return ip, packet_features, suspected_type
    
    # JIKA DATASET TIADA (FALLBACK): Jana data simulasi rawak secara automatik
    else:
        is_malware = random.random() < 0.15 # 15% peluang ancaman
        if is_malware:
            packet_size = round(random.uniform(300.0, 900.0), 1)
            req_per_min = random.randint(20, 60)
            threat_types = ["Worm", "Trojan", "Ransomware", "DDoS"]
            threat_type = random.choice(threat_types)
        else:
            packet_size = round(random.uniform(10.0, 150.0), 1)
            req_per_min = random.randint(1, 15)
            threat_type = "Normal"
            
        raw_features = [packet_size, req_per_min, random.randint(0, 5)]
        return ip, raw_features, threat_type