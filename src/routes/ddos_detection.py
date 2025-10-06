from flask import Blueprint, request, jsonify # type: ignore
from datetime import datetime
import os
import threading
import queue
import time
import pandas as pd # type: ignore

# Importar a classe DDoSDetector do arquivo correto
from src.routes.realtime_detector import DDoSDetector

# Criar blueprint para as rotas de detecção de DDoS
ddos_bp = Blueprint("ddos", __name__)

# Inicializar o detector de DDoS globalmente
detector = DDoSDetector()

# Iniciar o monitoramento do detector em uma thread separada
detector.start_monitoring()

# Endpoint de saúde da API
@ddos_bp.route("/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "healthy",
        "model_loaded": detector.model is not None,
        "detector_monitoring": detector.is_monitoring
    })

# Endpoint para obter estatísticas em tempo real
@ddos_bp.route("/stats", methods=["GET"])
def get_stats():
    return jsonify(detector.get_stats())

# Endpoint para detecção de um único pacote
@ddos_bp.route("/detect", methods=["POST"])
def detect_packet():
    packet_data = request.get_json()
    if not packet_data:
        return jsonify({"error": "Dados do pacote ausentes"}), 400

    # Adicionar o pacote à fila do detector para processamento assíncrono
    detector.add_packet(packet_data)

    # Retornar uma resposta imediata (a detecção real acontece na thread do detector)
    return jsonify({"message": "Pacote recebido para análise", "timestamp": datetime.now().isoformat()})

# Endpoint para simular tráfego (para testes)
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
            "time": row["Time"],
            "length": row["Length"],
            "source": row["Source"],
            "destination": row["Destination"],
            "protocol": row["Protocol"],
            "info": row["Info"]
        }
        detector.add_packet(packet_data) # Adiciona à fila do detector
        simulated_count += 1
        time.sleep(delay)

    # Retornar uma resposta imediata, as detecções serão atualizadas assincronamente
    return jsonify({
        "message": "Simulação de tráfego iniciada",
        "simulated_packets_sent": simulated_count
    })

# Endpoint para detecção em lote
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