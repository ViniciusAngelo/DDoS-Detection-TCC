import joblib # type: ignore
import numpy as np # type: ignore
import pandas as pd # type: ignore
from datetime import datetime
import os
import threading
import queue
import time

BASE_DIR = "/home/kali/ddos_detection_system/src" 
MODEL_PATH = os.path.join(BASE_DIR, "/home/kali/ddos_detection_system/src/ddos_model_v28.pkl")
ENCODER_PATH = os.path.join(BASE_DIR, "/home/kali/ddos_detection_system/src/label_encoder_v28.pkl")

class DDoSDetector:
    def __init__(self, window_size=1.0):
        self.model = None
        self.label_encoder = None
        self.load_model()

        self.window_size = window_size
        self.packet_buffer = []
        self.packet_queue = queue.Queue()
        
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
        self.packet_queue.put(packet_data)

    def _process_window(self):
        if not self.packet_buffer:
            return

        print(f"\n[DEBUG] Iniciando _process_window com {len(self.packet_buffer)} pacotes no buffer.")

        df_window = pd.DataFrame(self.packet_buffer)
        
        df_window['Length'] = pd.to_numeric(df_window['Length'], errors='coerce')
        
        print(f"[DEBUG] Antes do dropna, df_window tem {len(df_window)} linhas.")
        print("[DEBUG] Verificando valores nulos:")
        print(df_window.isnull().sum())

        df_window.dropna(subset=['Protocol', 'Info', 'Length'], inplace=True)

        print(f"[DEBUG] Depois do dropna, df_window tem {len(df_window)} linhas.")

        if df_window.empty:
            print("[DEBUG] df_window está VAZIO após o dropna. Saindo da função.")
            self.packet_buffer.clear()
            return

        def correct_protocol(row):
            info_str = str(row['Info']).lower()
            if 'proto=udp' in info_str or 'udp' in str(row['Protocol']).lower(): return 'UDP'
            if 'proto=icmp' in info_str or 'icmp' in str(row['Protocol']).lower(): return 'ICMP'
            if 'proto=tcp' in info_str or '[syn]' in info_str or 'tcp' in str(row['Protocol']).lower(): return 'TCP'
            return 'Other'
        df_window['Protocol'] = df_window.apply(correct_protocol, axis=1)

        df_window['Is_SYN'] = df_window['Info'].str.contains('[SYN]', regex=False).astype(int)
        df_window['Is_Fragmented'] = df_window['Info'].str.contains('Fragmented', regex=False).astype(int)

        num_packets_in_window = len(df_window)
        packet_rate = num_packets_in_window / self.window_size
        
        protocol_counts = df_window['Protocol'].value_counts()
        tcp_packets = int(protocol_counts.get('TCP', 0))
        udp_packets = int(protocol_counts.get('UDP', 0))
        icmp_packets = int(protocol_counts.get('ICMP', 0))
        
        syn_flag_count = int(df_window['Is_SYN'].sum())
        fragmented_packet_count = int(df_window['Is_Fragmented'].sum())
        avg_packet_length = float(df_window['Length'].mean()) if num_packets_in_window > 0 else 0.0

        NORMAL_THRESHOLD = 10
        attack_type = "Normal" 

        is_potentially_attack = (tcp_packets > NORMAL_THRESHOLD or 
                                 udp_packets > NORMAL_THRESHOLD or 
                                 icmp_packets > NORMAL_THRESHOLD)

        if is_potentially_attack:
            if self.model and self.label_encoder:
                try:
                    feature_names = ['TCP', 'UDP', 'ICMP', 'Avg_Packet_Length', 'SYN_Flag_Count', 'Fragmented_Packet_Count', 'Packet_Rate']
                    features_values = [[
                        tcp_packets, udp_packets, icmp_packets, 
                        avg_packet_length, syn_flag_count, fragmented_packet_count, packet_rate
                    ]]
                    
                    features_df = pd.DataFrame(features_values, columns=feature_names)
                    
                    print(f"[DEBUG] Acionando modelo ML v26. Features: {features_values}")
                    
                    prediction_code = self.model.predict(features_df)[0]
                    attack_type = self.label_encoder.inverse_transform([prediction_code])[0]

                except Exception as e:
                    print(f"Erro na predição do modelo ML: {e}")
                    attack_type = "Unknown Attack"
        
        with self.stats_lock:
            self.detection_stats["total_packets_processed"] += num_packets_in_window
            
            if attack_type in self.detection_stats["attacks_detected"]:
                self.detection_stats["attacks_detected"][attack_type] += 1
            
            self.detection_stats["last_detection_label"] = attack_type
            
            if attack_type != "Normal":
                print(f"!!! ALERTA DETECTADO ({'MODELO ML' if is_potentially_attack else 'REGRA'}): {attack_type} !!!")
            else:
                print(f"--- Tráfego processado. Resultado: {attack_type} ---")

        self.packet_buffer.clear()

    def _monitor_packets(self):
        last_window_time = time.time()
        
        while self.is_monitoring:
            try:
                packet_data = self.packet_queue.get(timeout=0.1)
                self.packet_buffer.append(packet_data)
            except queue.Empty:
                pass

            current_time = time.time()
            if current_time - last_window_time >= self.window_size:
                self._process_window()
                last_window_time = current_time

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