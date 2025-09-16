import joblib
import numpy as np
import pandas as pd
from datetime import datetime
import os
import threading
import queue
import time

# Caminhos para o modelo e encoder
MODEL_PATH = os.path.join(os.path.dirname(__file__), "/home/kali/ddos_detection_system/src/ddos_model_otimizado.pkl")
ENCODER_PATH = os.path.join(os.path.dirname(__file__), "/home/kali/ddos_detection_system/src/label_encoder_otimizado.pkl")

class DDoSDetector:
    def __init__(self):
        self.model = None
        self.label_encoder = None
        self.load_model()
        self.packet_queue = queue.Queue() # Fila para pacotes a serem processados
        self.is_monitoring = False
        self.monitoring_thread = None
        self.detection_stats = {
            "total_packets": 0,
            "attacks_detected": {"SynFlood": 0, "ICMPFlood": 0, "UDPFlood": 0, "Normal": 0},
            "last_detection": None,
            "detection_history": []
        }
        self.stats_lock = threading.Lock() # Lock para proteger detection_stats

    def load_model(self):
        try:
            self.model = joblib.load(MODEL_PATH)
            self.label_encoder = joblib.load(ENCODER_PATH)
            print("DDoSDetector: Modelo e encoder carregados com sucesso!")
        except Exception as e:
            print(f"DDoSDetector: Erro ao carregar modelo ou encoder: {e}")
            self.model = None
            self.label_encoder = None

    def preprocess_packet(self, packet_data):
        try:
            # Extrair as 8 features que o modelo espera
            # Baseado nos arquivos preprocess_data.py e train_model.py do contexto original
            # As features esperadas são: Time, Length, SourcePort, DestPort, Protocol_ICMP, Protocol_TCP, Protocol_UDP, Protocol_Other
            
            time_val = float(packet_data.get("time", 0.0))
            length_val = int(packet_data.get("length", 0))
            
            # Para SourcePort e DestPort, vamos tentar extrair do 'info' ou usar um valor padrão
            # Isso é uma simplificação, idealmente tshark deveria extrair esses campos diretamente
            source_port = 0
            dest_port = 0
            info = packet_data.get("info", "")
            if "\u2192" in info: # Verifica se há o separador de porta
                try:
                    parts = info.split(" ")
                    if len(parts) > 0 and parts[0].isdigit():
                        source_port = int(parts[0])
                    if len(parts) > 2 and parts[2].isdigit():
                        dest_port = int(parts[2])
                except ValueError:
                    pass # Ignora erro de conversão e mantém 0

            # Features one-hot encoded para Protocolo
            protocol = packet_data.get("protocol", "Other").upper()
            protocol_icmp = 1 if protocol == "ICMP" else 0
            protocol_tcp = 1 if protocol == "TCP" else 0
            protocol_udp = 1 if protocol == "UDP" else 0
            protocol_other = 1 if protocol not in ["ICMP", "TCP", "UDP"] else 0

            features = np.array([[time_val, length_val, source_port, dest_port, 
                                  protocol_icmp, protocol_tcp, protocol_udp, protocol_other]])
            return features
        except Exception as e:
            raise ValueError(f"Erro no pré-processamento do pacote: {e}")

    def predict_attack(self, packet_data):
        if self.model is None or self.label_encoder is None:
            return {"error": "Modelo não carregado no detector"}
        
        try:
            features = self.preprocess_packet(packet_data)
            prediction = self.model.predict(features)[0]
            probabilities = self.model.predict_proba(features)[0]
            
            attack_type = self.label_encoder.inverse_transform([prediction])[0]
            confidence = float(max(probabilities))
            
            return {
                "attack_type": attack_type,
                "confidence": confidence,
                "is_attack": attack_type != "Normal",
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return {"error": f"Erro na predição do pacote: {str(e)}"}

    def add_packet(self, packet_data):
        self.packet_queue.put(packet_data)

    def _monitor_packets(self):
        while self.is_monitoring:
            try:
                packet_data = self.packet_queue.get(timeout=1) # Espera por 1 segundo
                result = self.predict_attack(packet_data)
                
                with self.stats_lock:
                    self.detection_stats["total_packets"] += 1
                    if "attack_type" in result:
                        self.detection_stats["attacks_detected"][result["attack_type"]] += 1
                        if result["is_attack"]:
                            self.detection_stats["last_detection"] = result["timestamp"]
                        
                        # Adicionar ao histórico
                        self.detection_stats["detection_history"].append({
                            "timestamp": result["timestamp"],
                            "type": result["attack_type"],
                            "confidence": result["confidence"],
                            "source": packet_data.get("source", "N/A"),
                            "destination": packet_data.get("destination", "N/A")
                        })
                        # Manter histórico limitado a 100 entradas
                        if len(self.detection_stats["detection_history"]) > 100:
                            self.detection_stats["detection_history"].pop(0)
                    else:
                        print(f"DDoSDetector: Erro ao processar pacote: {result.get('error', 'Erro desconhecido')}")

            except queue.Empty:
                continue # Nenhuma pacote na fila, continua esperando
            except Exception as e:
                print(f"DDoSDetector: Erro inesperado no monitoramento: {e}")

    def start_monitoring(self):
        if not self.is_monitoring:
            self.is_monitoring = True
            self.monitoring_thread = threading.Thread(target=self._monitor_packets)
            self.monitoring_thread.daemon = True # Permite que a thread termine com o programa principal
            self.monitoring_thread.start()
            print("DDoSDetector: Monitoramento de pacotes iniciado.")

    def stop_monitoring(self):
        if self.is_monitoring:
            self.is_monitoring = False
            if self.monitoring_thread and self.monitoring_thread.is_alive():
                self.monitoring_thread.join() # Espera a thread terminar
            print("DDoSDetector: Monitoramento de pacotes parado.")

    def get_stats(self):
        with self.stats_lock:
            return self.detection_stats

    def reset_stats(self):
        with self.stats_lock:
            self.detection_stats = {
                "total_packets": 0,
                "attacks_detected": {"SynFlood": 0, "ICMPFlood": 0, "UDPFlood": 0, "Normal": 0},
                "last_detection": None,
                "detection_history": []
            }
            print("DDoSDetector: Estatísticas resetadas.")