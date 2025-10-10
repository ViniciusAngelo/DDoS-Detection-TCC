from flask import Blueprint, request, jsonify, current_app  # type: ignore
from datetime import datetime
import os
import time
import pandas as pd  # type: ignore
import json
import traceback

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


# 🚀 Detecção de um único pacote (com modo debug opcional)
@ddos_bp.route("/detect", methods=["POST"])
def detect_packet():
    try:
        debug = request.args.get("debug", "0") == "1"
        packet_data = request.get_json()

        if not packet_data:
            return jsonify({"error": "Dados do pacote ausentes"}), 400

        # Log básico
        current_app.logger.info(f"[DETECT-IN] Pacote recebido: {json.dumps(packet_data, default=str)[:500]}")

        # Enfileira o pacote como antes
        detector.add_packet(packet_data)

        # --- Modo Debug: tenta prever diretamente ---
        debug_info = {}
        if debug:
            try:
                df = pd.DataFrame([packet_data])
                current_app.logger.info(f"[DEBUG] df.shape = {df.shape}, colunas = {list(df.columns)}")

                if hasattr(detector, "model") and detector.model is not None:
                    # Usa pipeline semelhante à de treinamento se possível
                    X = df.copy()

                    # Verifica se há transformações de features
                    if hasattr(detector, "prepare_features"):
                        try:
                            X = detector.prepare_features(df)
                        except Exception as ex:
                            debug_info["feature_prepare_error"] = str(ex)

                    probs, pred, pred_label = None, None, None
                    try:
                        probs = detector.model.predict_proba(X).tolist()
                        pred = detector.model.predict(X).tolist()
                    except Exception as ex2:
                        debug_info["predict_error"] = str(ex2)

                    # Decodifica label se houver encoder
                    if hasattr(detector, "encoder") and detector.encoder is not None and pred is not None:
                        try:
                            pred_label = detector.encoder.inverse_transform(pred).tolist()
                        except Exception as ex3:
                            pred_label = None
                            debug_info["encoder_error"] = str(ex3)

                    debug_info.update({
                        "df_shape": df.shape,
                        "probs": probs,
                        "pred": pred,
                        "pred_label": pred_label
                    })
                else:
                    debug_info["model_status"] = "modelo não carregado"

            except Exception as debug_ex:
                debug_info["debug_exception"] = str(debug_ex)
                current_app.logger.error(traceback.format_exc())

        # --- resposta normal ---
        response = {
            "message": "Pacote recebido para análise",
            "timestamp": datetime.now().isoformat()
        }

        if debug:
            response["_debug"] = debug_info

        return jsonify(response)

    except Exception as e:
        current_app.logger.error("Erro no endpoint /detect: " + str(e))
        current_app.logger.error(traceback.format_exc())
        return jsonify({"error": "Erro interno", "detail": str(e)}), 500


# Simular tráfego
@ddos_bp.route("/simulate_traffic", methods=["POST"])
def simulate_traffic_api():
    num_packets = request.json.get("num_packets", 100)
    delay = request.json.get("delay", 0.001)

    csv_path = os.path.join(os.path.dirname(__file__), "..", "processed_network_traffic.csv")

    if not os.path.exists(csv_path):
        return jsonify({"error": "Dados de simulação não encontrados. Verifique o caminho: " + csv_path}), 404

    df = pd.read_csv(csv_path)  # type: ignore
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
