from flask import Blueprint, request, jsonify # type: ignore
from datetime import datetime
import os
import threading
import queue
import time
import pandas as pd # type: ignore

from src.routes.realtime_detector import DDoSDetector

ddos_bp = Blueprint("ddos", __name__)

detector = DDoSDetector()

detector.start_monitoring()

@ddos_bp.route("/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "healthy",
        "model_loaded": detector.model is not None,
        "detector_monitoring": detector.is_monitoring
    })

# Estatísticas em tempo real
@ddos_bp.route("/stats", methods=["GET"])
def get_stats():
    return jsonify(detector.get_stats())

# Detecção de um único pacote
@ddos_bp.route("/detect", methods=["POST"])
def detect_packet():
    packet_data = request.get_json()
    if not packet_data:
        return jsonify({"error": "Dados do pacote ausentes"}), 400

    # Normaliza chaves para o formato esperado pelo Detector
    normalized = {
        "Time": packet_data.get("time") or packet_data.get("Time"),
        "Length": packet_data.get("length") or packet_data.get("Length"),
        "Source": packet_data.get("source") or packet_data.get("Source"),
        "Destination": packet_data.get("destination") or packet_data.get("Destination"),
        "Protocol": packet_data.get("protocol") or packet_data.get("Protocol"),
        "Info": packet_data.get("info") or packet_data.get("Info"),
    }

    detector.add_packet(normalized)

    return jsonify({"message": "Pacote recebido para análise", "timestamp": datetime.now().isoformat()})

# Simular tráfego
@ddos_bp.route("/simulate_traffic", methods=["POST"])
def simulate_traffic_api():
    num_packets = request.json.get("num_packets", 100)
    delay = request.json.get("delay", 0.001)
    
    csv_path = os.path.join(os.path.dirname(__file__), "..", "processed_network_traffic.csv")

    if not os.path.exists(csv_path):
        return jsonify({"error": "Dados de simulação não encontrados. Verifique o caminho: " + csv_path}), 404
        
    df = pd.read_csv(csv_path) # type: ignore
    sample_data = df.sample(n=min(num_packets, len(df)))
    
    simulated_count = 0

    for _, row in sample_data.iterrows():
        packet_data = {
            "Time": row["Time"],
            "Length": row["Length"],
            "Source": row["Source"],
            "Destination": row["Destination"],
            "Protocol": row["Protocol"],
            "Info": row["Info"]
        }
        detector.add_packet(packet_data)
        simulated_count += 1
        time.sleep(delay)

    return jsonify({
        "message": "Simulação de tráfego iniciada",
        "simulated_packets_sent": simulated_count
    })

# Detecção em lote
@ddos_bp.route("/detect/batch", methods=["POST"])
def detect_batch():
    data = request.get_json()
    packets = data.get("packets", [])
    if not packets:
        return jsonify({"error": "Lista de pacotes vazia"}), 400

    for packet_data in packets:
        detector.add_packet(packet_data)

    return jsonify({"message": f"{len(packets)} pacotes recebidos para análise em lote"})

@ddos_bp.route("/reset-stats", methods=["POST"])
def reset_stats():
    detector.reset_stats()
    return jsonify({"message": "Estatísticas resetadas com sucesso"})