import random
import numpy as np

def generate_live_packet():
    ip = f"192.168.1.{random.randint(2, 254)}"
    
    # Menjana ciri-ciri trafik
    packet_size = np.random.normal(loc=50, scale=10) # Saiz biasa dalam KB
    req_per_min = np.random.poisson(lam=5)
    suspicious_calls = random.randint(0, 1)
    
    # Menentukan jenis malware jika dikesan anomali
    malware_types = ["Ransomware", "Trojan", "Spyware", "Worm", "Adware"]
    
    # Contoh keadaan simulasi malware:
    if random.random() < 0.15:  # 15% peluang serangan malware
        packet_size = random.uniform(200, 500)  # Muat turun payload besar
        req_per_min = random.randint(20, 50)    # Sambungan C2 aktif
        suspicious_calls = random.randint(3, 10)
        suspected_type = random.choice(malware_types)
    else:
        suspected_type = "Normal"
        
    features = [packet_size, req_per_min, suspicious_calls]
    return ip, features, suspected_type

    