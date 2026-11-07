import os
import pandas as pd
import numpy as np

# Cipta folder data jika belum ada
os.makedirs("data", exist_ok=True)

# Bina data dummy berasaskan ciri CICIDS2017
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

df = pd.DataFrame(data)
df.to_csv("data/cicids2017.csv", index=False)
print("[+] Fail data/cicids2017.csv berjaya dicipta!")