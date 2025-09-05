from flask import Blueprint, request, jsonify
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
import os
import threading
import queue
import time

# Criar blueprint para as rotas de detecção de DDoS
ddos_bp = Blueprint("ddos", __name__)

# Carregar modelo e encoder na inicialização
model_path = os.path.join(os.path.dirname(__file__), "..", "ddos_model.pkl")
encoder_path = os.path.join(os.path.dirname(__file__), "..", "label_encoder.pkl")

try:
    model = joblib.load(model_path)
    label_encoder = joblib.load(encoder_path)
    print("Modelo de detecção DDoS carregado com sucesso!")
except Exception as e:
    print(f"Erro ao carregar modelo: {e}")
    model = None
    label_encoder = None

# Armazenamento em memória para estatísticas (em produção, usar banco de dados)
detection_stats = {
    "total_packets": 0,
    "attacks_detected": {"SynFlood": 0, "ICMPFlood": 0, "UDPFlood": 0},
    "last_detection": None,
    "detection_history": []
}

# Fila para processamento em tempo real
packet_queue = queue.Queue()
is_monitoring = False

def preprocess_packet(packet_data):
    """
    Pré-processa um pacote de rede para predição.

    Args:
        packet_data (dict): Dados do pacote

    Returns:
        np.array: Features processadas
    """
    try:
        # Extrair features que o modelo espera (Time e Length)
        time_val = float(packet_data.get("time", 0))
        length_val = int(packet_data.get("length", 0))

        features = np.array([[time_val, length_val]])
        return features
    except (ValueError, TypeError) as e:
        raise ValueError(f"Erro no pré-processamento: {e}")

def predict_attack(packet_data):
    """
    Prediz se um pacote representa um ataque DDoS.

    Args:
        packet_data (dict): Dados do pacote

    Returns:
        dict: Resultado da predição
    """
    if model is None or label_encoder is None:
        return {"error": "Modelo não carregado"}

    try:
        features = preprocess_packet(packet_data)

        # Fazer predição
        prediction = model.predict(features)[0]
        probabilities = model.predict_proba(features)[0]

        # Converter predição numérica de volta para rótulo
        attack_type = label_encoder.inverse_transform([prediction])[0]
        confidence = float(max(probabilities))

        return {
            "attack_type": attack_type,
            "confidence": confidence,
            "is_attack": confidence > 0.7,  # Limiar de confiança
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {"error": f"Erro na predição: {str(e)}"}

@ddos_bp.route("/detect", methods=["POST"])
def detect_ddos():
    """
    Endpoint para detecção de DDoS em um único pacote.

    Espera JSON com formato:
    {
        "time": float,
        "length": int,
        "source": str (opcional),
        "destination": str (opcional),
        "protocol": str (opcional),
        "info": str (opcional)
    }
    """
    try:
        packet_data = request.get_json()

        if not packet_data:
            return jsonify({"error": "Dados do pacote não fornecidos"}), 400

        # Validar campos obrigatórios
        if "time" not in packet_data or "length" not in packet_data:
            return jsonify({"error": "Campos obrigatórios: time, length"}), 400

        # Fazer predição
        result = predict_attack(packet_data)

        if "error" in result:
            return jsonify(result), 500

        # Atualizar estatísticas
        detection_stats["total_packets"] += 1

        if result["is_attack"]:
            attack_type = result["attack_type"]
            detection_stats["attacks_detected"][attack_type] += 1
            detection_stats["last_detection"] = result["timestamp"]

            # Adicionar ao histórico (manter apenas os últimos 100)
            detection_stats["detection_history"].append({
                "timestamp": result["timestamp"],
                "attack_type": attack_type,
                "confidence": result["confidence"],
                "source": packet_data.get("source", "N/A"),
                "destination": packet_data.get("destination", "N/A")
            })

            if len(detection_stats["detection_history"]) > 100:
                detection_stats["detection_history"].pop(0)

        return jsonify(result)

    except Exception as e:
        return jsonify({"error": f"Erro interno: {str(e)}"}), 500

@ddos_bp.route("/detect/batch", methods=["POST"])
def detect_ddos_batch():
    """
    Endpoint para detecção de DDoS em múltiplos pacotes.

    Espera JSON com formato:
    {
        "packets": [
            {"time": float, "length": int, ...},
            {"time": float, "length": int, ...}
        ]
    }
    """
    try:
        data = request.get_json()

        if not data or "packets" not in data:
            return jsonify({"error": "Lista de pacotes não fornecida"}), 400

        packets = data["packets"]
        results = []

        for i, packet_data in enumerate(packets):
            try:
                result = predict_attack(packet_data)
                result["packet_index"] = i
                results.append(result)

                # Atualizar estatísticas
                detection_stats["total_packets"] += 1

                if result.get("is_attack", False):
                    attack_type = result["attack_type"]
                    detection_stats["attacks_detected"][attack_type] += 1
                    detection_stats["last_detection"] = result["timestamp"]

            except Exception as e:
                results.append({
                    "packet_index": i,
                    "error": f"Erro no pacote {i}: {str(e)}"
                })

        return jsonify({
            "results": results,
            "total_processed": len(packets),
            "attacks_found": sum(1 for r in results if r.get("is_attack", False))
        })

    except Exception as e:
        return jsonify({"error": f"Erro interno: {str(e)}"}), 500

@ddos_bp.route("/stats", methods=["GET"])
def get_stats():
    """
    Endpoint para obter estatísticas de detecção.
    """
    try:
        # Calcular estatísticas adicionais
        total_attacks = sum(detection_stats["attacks_detected"].values())
        attack_rate = (total_attacks / detection_stats["total_packets"] * 100) if detection_stats["total_packets"] > 0 else 0

        stats = {
            "total_packets_analyzed": detection_stats["total_packets"],
            "total_attacks_detected": total_attacks,
            "attack_rate_percentage": round(attack_rate, 2),
            "attacks_by_type": detection_stats["attacks_detected"],
            "last_detection": detection_stats["last_detection"],
            "recent_detections": detection_stats["detection_history"][-10:],  # Últimas 10 detecções
            "system_status": "active" if model is not None else "error"
        }

        return jsonify(stats)

    except Exception as e:
        return jsonify({"error": f"Erro ao obter estatísticas: {str(e)}"}), 500

@ddos_bp.route("/health", methods=["GET"])
def health_check():
    """
    Endpoint para verificar a saúde da API.
    """
    return jsonify({
        "status": "healthy" if model is not None else "unhealthy",
        "model_loaded": model is not None,
        "encoder_loaded": label_encoder is not None,
        "timestamp": datetime.now().isoformat()
    })

@ddos_bp.route("/reset-stats", methods=["POST"])
def reset_stats():
    """
    Endpoint para resetar as estatísticas de detecção.
    """
    global detection_stats

    detection_stats = {
        "total_packets": 0,
        "attacks_detected": {"SynFlood": 0, "ICMPFlood": 0, "UDPFlood": 0},
        "last_detection": None,
        "detection_history": []
    }

    return jsonify({"message": "Estatísticas resetadas com sucesso"})

# Endpoint para simular tráfego (útil para testes)
@ddos_bp.route("/simulate", methods=["POST"])
def simulate_traffic():
    """
    Endpoint para simular tráfego de rede usando dados históricos.
    """
    try:
        data = request.get_json()
        num_packets = data.get("num_packets", 100)

        # Carregar dados processados
        csv_path = os.path.join(os.path.dirname(__file__), "..", "processed_network_traffic.csv")

        if not os.path.exists(csv_path):
            return jsonify({"error": "Dados de simulação não encontrados"}), 404

        df = pd.read_csv(csv_path)
        sample_data = df.sample(n=min(num_packets, len(df)))

        results = []
        for _, row in sample_data.iterrows():
            packet_data = {
                "time": row["Time"],
                "length": row["Length"],
                "source": row["Source"],
                "destination": row["Destination"],
                "protocol": row["Protocol"],
                "info": row["Info"]
            }

            result = predict_attack(packet_data)
            result["actual_label"] = row["Label"]  # Para comparação
            results.append(result)

            # Atualizar estatísticas
            detection_stats["total_packets"] += 1

            if result.get("is_attack", False):
                attack_type = result["attack_type"]
                detection_stats["attacks_detected"][attack_type] += 1
                detection_stats["last_detection"] = result["timestamp"]

        return jsonify({
            "simulated_packets": len(results),
            "attacks_detected": sum(1 for r in results if r.get("is_attack", False)),
            "results": results[:10]  # Retornar apenas os primeiros 10 para não sobrecarregar
        })

    except Exception as e:
        return jsonify({"error": f"Erro na simulação: {str(e)}"}), 500