import joblib
import time
import collections
from scapy.all import sniff, IP, TCP, UDP
from database import init_db, log_threat

# Load your trained model and scaler (Update filename if your model is named differently, e.g., "model.pkl")
model = joblib.load("model.pkl")  
scaler = joblib.load("scaler.pkl")

# Initialize SQLite database on launch
init_db()

# Lightweight flow-tracking dictionary
# Format: key = (src_ip, dst_ip, dst_port, protocol)
flow_stats = collections.defaultdict(lambda: {
    'start_time': time.time(),
    'last_seen': time.time(),
    'pkt_count': 0,
    'total_bytes': 0,
    'pkt_lengths': []
})

def classify_flow(features):
    """
    features: dict containing extracted flow features.
    Returns: (is_threat: bool, threat_type: str, severity: str, confidence: float)
    """
    # 1. Arrange feature vector matching your training dataset order
    X = [[
        features['pkt_count'],
        features['total_bytes'],
        features['avg_pkt_len'],
        features['duration'],
        features['byte_rate']
    ]]

    # 2. Scale features if model requires it
    X_scaled = scaler.transform(X)

    # 3. Predict class & confidence score
    pred = model.predict(X_scaled)[0]
    probs = model.predict_proba(X_scaled)[0]
    confidence = float(max(probs))

    # 4. Return results if flagged as anomalous / attack
    if pred != 0:  # Assuming 0 = Normal, 1+ = Threat
        threat_names = {1: "DDoS Attack", 2: "Port Scan", 3: "Brute Force"}
        threat_type = threat_names.get(pred, "Suspicious Traffic")
        severity = "HIGH" if confidence > 0.85 else "MEDIUM"
        
        return True, threat_type, severity, confidence

    return False, "Normal", "LOW", confidence

def process_packet(packet):
    """Callback function executed for every intercepted packet."""
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    pkt_len = len(packet)
    
    # Protocol & Port Extraction
    protocol = "OTHER"
    dst_port = 0
    if packet.haslayer(TCP):
        protocol = "TCP"
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        protocol = "UDP"
        dst_port = packet[UDP].dport

    flow_key = (src_ip, dst_ip, dst_port, protocol)
    now = time.time()
    
    # Update flow features
    flow = flow_stats[flow_key]
    flow['last_seen'] = now
    flow['pkt_count'] += 1
    flow['total_bytes'] += pkt_len
    flow['pkt_lengths'].append(pkt_len)

    duration = max(now - flow['start_time'], 0.001)
    avg_pkt_len = flow['total_bytes'] / flow['pkt_count']
    byte_rate = flow['total_bytes'] / duration

    # Extract feature dictionary for ML evaluation
    extracted_features = {
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'dst_port': dst_port,
        'protocol': protocol,
        'pkt_count': flow['pkt_count'],
        'total_bytes': flow['total_bytes'],
        'avg_pkt_len': avg_pkt_len,
        'duration': duration,
        'byte_rate': byte_rate
    }

    # Pass aggregated features to the detector model
    is_threat, threat_type, severity, confidence = classify_flow(extracted_features)

    # Log to SQLite if a threat is flagged
    if is_threat:
        log_threat(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=f"{protocol}:{dst_port}",
            threat_type=threat_type,
            severity=severity,
            confidence_score=confidence,
            raw_features=f"pkts={flow['pkt_count']}, avg_len={avg_pkt_len:.1f}"
        )
        # Reset flow counter after logging to prevent flooding duplicate alerts
        flow_stats[flow_key]['pkt_count'] = 0

def start_sniffing(interface=None):
    """
    Start intercepting live packets.
    If interface=None, Scapy sniff on default active interface.
    """
    print(f"[*] Starting live network packet sniffer...")
    print(f"[*] Press Ctrl+C to stop.")
    
    try:
        sniff(iface=interface, prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\n[*] Sniffer stopped by user.")
    except Exception as e:
        print(f"[-] Sniffing error: {e}")

if __name__ == "__main__":
    # Pass interface name if required, e.g., start_sniffing(interface="eth0")
    start_sniffing()