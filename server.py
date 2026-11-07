import asyncio
import json
import logging
import logging.handlers
import time
import requests
import websockets
from scapy.all import IP, TCP, UDP, sniff
from websockets.server import serve

# ==========================================
# Security Malware Operations Syslog & Webhook Setup
# ==========================================
logger = logging.getLogger("SecMalOpsSecurityLogger")
logger.setLevel(logging.INFO)

syslog_handler = logging.handlers.SysLogHandler(address=("127.0.0.1", 514))
syslog_handler.setFormatter(
    logging.Formatter("SecMalOps [%(levelname)s]: %(message)s")
)
logger.addHandler(syslog_handler)

# Track last alert times per IP to prevent Slack 429 Rate Limits
alert_cooldowns = {}
COOLDOWN_SECONDS = 30  # Only 1 alert per IP every 30 seconds


def send_security_webhook(event_message, severity="HIGH"):
    webhook_url = (
        "https://hooks.slack.com/services/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"
    )
    payload = {"text": f"🚨 *Security Malware Operations Alert [{severity}]*: {event_message}"}

    try:
        response = requests.post(webhook_url, json=payload)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Failed to send Security Malware Operations webhook alert: {e}")


def handle_security_event(event_description, is_critical=False):
    logger.warning(event_description)
    if is_critical:
        send_security_webhook(event_description, severity="CRITICAL")


# ==========================================
# Packet Sniffing & WebSocket Server
# ==========================================
connected_clients = set()


def extract_features(packet):
    if IP in packet:
        flow_data = {
            "brand": "Security Malware Operations",
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "length": len(packet),
            "proto": packet[IP].proto,
        }

        if TCP in packet:
            flow_data["src_port"] = packet[TCP].sport
            flow_data["dst_port"] = packet[TCP].dport
            flow_data["protocol_name"] = "TCP"
        elif UDP in packet:
            flow_data["src_port"] = packet[UDP].sport
            flow_data["dst_port"] = packet[UDP].dport
            flow_data["protocol_name"] = "UDP"
        else:
            flow_data["protocol_name"] = "OTHER"

        return flow_data
    return None


async def packet_handler(websocket):
    connected_clients.add(websocket)
    try:
        await websocket.wait_closed()
    finally:
        connected_clients.remove(websocket)


async def broadcast_packets():
    def handle_packet(packet):
        features = extract_features(packet)
        if features:
            # Throttle alerts to prevent Slack 429 rate limits
            if features.get("length", 0) > 1200:
                src_ip = features["src_ip"]
                current_time = time.time()

                if (
                    src_ip not in alert_cooldowns
                    or (current_time - alert_cooldowns[src_ip]) > COOLDOWN_SECONDS
                ):
                    alert_cooldowns[src_ip] = current_time
                    handle_security_event(
                        f"Anomalous packet length detected from IP {src_ip}"
                        f" (Length: {features['length']} bytes)",
                        is_critical=True,
                    )

            if connected_clients:
                message = json.dumps(features)
                websockets.broadcast(connected_clients, message)

    print("Starting Security Malware Operations packet sniffer...")
    await asyncio.to_thread(sniff, prn=handle_packet, store=False)


async def main():
    async with serve(packet_handler, "localhost", 8765):
        print("Security Malware Operations WebSocket server started on ws://localhost:8765")
        await broadcast_packets()


if __name__ == "__main__":
    asyncio.run(main())