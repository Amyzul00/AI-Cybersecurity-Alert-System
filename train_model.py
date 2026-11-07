import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

print("[+] Membaca dataset CICIDS2017...")
os.makedirs("data", exist_ok=True)
data_path = "data/cicids2017.csv"

if os.path.exists(data_path):
    df = pd.read_csv(data_path)
    # Bersihkan nama lajur (buang ruang kosong pada nama lajur)
    df.columns = df.columns.str.strip()

    # Pilih ciri-ciri utama yang relevan untuk pengesanan ancaman
    features = [
        "Total Fwd Packets",
        "Total Backward Packets",
        "Total Length of Fwd Packets",
        "Fwd Packet Length Max",
        "Flow Bytes/s",
        "Flow Packets/s",
    ]

    # Pastikan lajur wujud dalam dataset
    available_features = [f for f in features if f in df.columns]

    if len(available_features) > 0:
        df_selected = (
            df[available_features].replace([np.inf, -np.inf], np.nan).dropna()
        )

        print("[+] Melatih Isolation Forest pada data sebenar...")
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(df_selected)

        model = IsolationForest(contamination=0.03, random_state=42)
        model.fit(X_scaled)

        # Simpan model dan scaler ke dalam fail
        joblib.dump(model, "model_cicids.pkl")
        joblib.dump(scaler, "scaler_cicids.pkl")
        print(
            "[!] Model dan Scaler berjaya disimpan ke dalam 'model_cicids.pkl'!"
        )
    else:
        print(
            "[-] Ralat: Tiada satu pun ciri yang dipilih ditemui dalam dataset CSV."
        )
else:
    print(
        f"[-] Amaran: Fail {data_path} tidak ditemui. Sila pastikan dataset diletakkan di dalam folder 'data/'."
    )