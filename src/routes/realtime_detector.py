import joblib
import numpy as np
import pandas as pd
from datetime import datetime
import os
import threading
import queue
import time

# --- CAMINHOS PARA O MODELO E ENCODER ---
# Use caminhos absolutos para garantir que o serviço encontre os arquivos.
# ATENÇÃO: Verifique se este caminho está correto para o seu ambiente.
BASE_DIR = "/home/kali/ddos_detection_system/src" 
MODEL_PATH = os.path.join(BASE_DIR, "ddos_model_final_v12.pkl")
ENCODER_PATH = os.path.join(BASE_DIR, "label_encoder_final_v12.pkl")

class DDoSDetector:
    def __init__(self, window_size=1.0):
        """
        Inicializa o detector com uma janela de tempo para agregação de pacotes.
        """
        self.model = None
        self.label_encoder = None
        self.load_model()

        self.window_size = window_size  # Duração da janela em segundos
        self.packet_buffer = []         # Buffer para armazenar pacotes da janela atual
        self.packet_queue = queue.Queue() # Fila para pacotes brutos vindos do tshark
        
        self.is_monitoring = False
        self.monitoring_thread = None
        
        self.detection_stats = {
            "total_packets_processed": 0,
            "attacks_detected": {"SynFlood": 0, "ICMPFlood": 0, "UDPFlood": 0, "Normal": 0},
            "last_detection_label": "Normal",
            "last_detection_timestamp": None,
            "detection_history": []
        }
        self.stats_lock = threading.Lock()

    def load_model(self):
        try:
            self.model = joblib.load(MODEL_PATH)
            self.label_encoder = joblib.load(ENCODER_PATH)
            print(f"DDoSDetector: Modelo '{MODEL_PATH}' e encoder '{ENCODER_PATH}' carregados com sucesso!")
        except FileNotFoundError as e:
            print(f"DDoSDetector: ERRO CRÍTICO - Arquivo de modelo ou encoder não encontrado: {e}")
            self.model = None
            self.label_encoder = None
        except Exception as e:
            print(f"DDoSDetector: Erro ao carregar modelo ou encoder: {e}")
            self.model = None
            self.label_encoder = None

    def add_packet(self, packet_data):
        """ Adiciona um pacote bruto à fila de processamento. """
        self.packet_queue.put(packet_data)

# No seu realtime_detector.py

    def _process_window(self):
        """
        Versão final, correta e testada: Atualiza o dicionário de estatísticas
        aninhado corretamente para que o dashboard possa exibir os dados.
        """
        if not self.packet_buffer:
            return

        df_window = pd.DataFrame(self.packet_buffer)
        num_packets_in_window = len(df_window)

        proto_map = {'1': 'ICMP', '6': 'TCP', '17': 'UDP'}
        df_window['protocol'] = df_window['protocol'].map(proto_map)
        
        protocol_counts = df_window['protocol'].value_counts()
        tcp_packets = int(protocol_counts.get('TCP', 0))
        udp_packets = int(protocol_counts.get('UDP', 0))
        icmp_packets = int(protocol_counts.get('ICMP', 0))

        feature_names = ['TCP', 'UDP', 'ICMP']
        features_values = [[tcp_packets, udp_packets, icmp_packets]]
        features_df = pd.DataFrame(features_values, columns=feature_names)

        if self.model and self.label_encoder:
            try:
                print(f"[DEBUG] Features Finais: {features_values}")
                
                prediction_code = self.model.predict(features_df)[0]
                attack_type = self.label_encoder.inverse_transform([prediction_code])[0]
                
                # --- CORREÇÃO FINAL E DEFINITIVA ---
                with self.stats_lock:
                    self.detection_stats["total_packets_processed"] += num_packets_in_window
                    
                    # Acessa o dicionário aninhado 'attacks_detected' para incrementar
                    if attack_type in self.detection_stats["attacks_detected"]:
                        self.detection_stats["attacks_detected"][attack_type] += 1
                    
                    self.detection_stats["last_detection_label"] = attack_type
                    
                    # (O resto do seu código de histórico pode ser adicionado aqui se você o tiver)
                    
                    if attack_type != "Normal":
                        self.detection_stats["last_detection_timestamp"] = datetime.now().isoformat()
                        print(f"!!! ALERTA DE ATAQUE DETECTADO: {attack_type} !!!")
                # --- FIM DA CORREÇÃO ---

            except Exception as e:
                print(f"Erro na predição da janela: {e}")

        self.packet_buffer.clear()

    def _monitor_packets(self):
        """
        Thread principal que coleta pacotes da fila e os agrupa em janelas de tempo.
        """
        last_window_time = time.time()
        
        while self.is_monitoring:
            try:
                # Tenta pegar um pacote da fila (sem bloquear por muito tempo)
                packet_data = self.packet_queue.get(timeout=0.1)
                self.packet_buffer.append(packet_data)
            except queue.Empty:
                # Se a fila estiver vazia, não faz nada e continua o loop
                pass

            # Verifica se a janela de tempo expirou
            current_time = time.time()
            if current_time - last_window_time >= self.window_size:
                self._process_window()
                last_window_time = current_time # Inicia a nova janela

    def start_monitoring(self):
        if not self.is_monitoring:
            self.is_monitoring = True
            self.monitoring_thread = threading.Thread(target=self._monitor_packets)
            self.monitoring_thread.daemon = True
            self.monitoring_thread.start()
            print("DDoSDetector: Monitoramento em janelas de tempo iniciado.")

    def stop_monitoring(self):
        if self.is_monitoring:
            self.is_monitoring = False
            if self.monitoring_thread and self.monitoring_thread.is_alive():
                self.monitoring_thread.join()
            print("DDoSDetector: Monitoramento parado.")

    def get_stats(self):
        with self.stats_lock:
            # Retorna uma cópia para evitar problemas de concorrência
            return dict(self.detection_stats)

    def reset_stats(self):
        with self.stats_lock:
            self.detection_stats = {
                "total_packets_processed": 0,
                "attacks_detected": {"SynFlood": 0, "ICMPFlood": 0, "UDPFlood": 0, "Normal": 0},
                "last_detection_label": "Normal",
                "last_detection_timestamp": None,
                "detection_history": []
            }
            print("DDoSDetector: Estatísticas resetadas.")