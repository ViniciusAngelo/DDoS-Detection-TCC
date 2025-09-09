import pandas as pd
import joblib
import time
import numpy as np
from datetime import datetime
import threading
import queue
import collections

class DDoSDetector:
    def __init__(self, model_path="/home/kali/ddos_detection_system/src/ddos_model.pkl", encoder_path="/home/kali/ddos_detection_system/src/label_encoder.pkl", window_size=1.0):
        """
        Inicializa o detector de DDoS carregando o modelo treinado.
        """
        self.model = joblib.load(model_path)
        self.label_encoder = joblib.load(encoder_path)
        self.packet_queue = queue.Queue()
        self.is_monitoring = False
        self.detection_threshold = 0.9  # Limiar de confiança para detecção
        self.window_size = window_size # Tamanho da janela em segundos
        self.packet_history = collections.deque() # Usar deque para histórico eficiente
        self.lock = threading.Lock() # Para acesso seguro ao histórico

    def _extract_features_from_window(self, current_packet_time):
        """
        Extrai features de uma janela de tempo do histórico de pacotes.
        """
        with self.lock:
            # Remover pacotes antigos fora da janela
            while self.packet_history and self.packet_history[0]["time"] < (current_packet_time - self.window_size):
                self.packet_history.popleft()
            
            # Criar um DataFrame temporário a partir do histórico
            if not self.packet_history:
                # Se não há histórico, retornar features zeradas ou padrão
                return np.array([[0, 0, 0, 0, 0, 0, 0, 0]])

            window_df = pd.DataFrame(list(self.packet_history))

            # Calcular features
            num_packets = len(window_df)
            total_length = window_df["length"].sum()
            avg_length = window_df["length"].mean()
            std_length = window_df["length"].std() if num_packets > 1 else 0
            
            protocol_counts = window_df["protocol"].value_counts()
            tcp_packets = protocol_counts.get("TCP", 0)
            udp_packets = protocol_counts.get("UDP", 0)
            icmp_packets = protocol_counts.get("ICMP", 0)

            num_unique_src_ips = len(window_df["source"].unique())

            features = np.array([[
                num_packets,
                total_length,
                avg_length,
                std_length,
                tcp_packets,
                udp_packets,
                icmp_packets,
                num_unique_src_ips
            ]])
            return features

    def predict_attack(self, packet_data):
        """
        Prediz se um pacote representa um ataque DDoS usando features de janela.
        
        Args:
            packet_data (dict): Dados do pacote (deve incluir 'time', 'length', 'protocol', 'source')
            
        Returns:
            tuple: (tipo_ataque, probabilidade, is_attack)
        """
        # Adicionar o pacote atual ao histórico ANTES de extrair features para ele
        with self.lock:
            self.packet_history.append(packet_data)

        features = self._extract_features_from_window(packet_data["time"])
        
        if self.model is None or self.label_encoder is None:
            return "Unknown", 0.0, False

        probabilities = self.model.predict_proba(features)[0]
        predicted_label_encoded = self.model.predict(features)[0]
        
        predicted_label = self.label_encoder.inverse_transform([predicted_label_encoded])[0]
        confidence = probabilities[predicted_label_encoded]

        is_attack = predicted_label != "Normal" and confidence >= self.detection_threshold
        
        return predicted_label, confidence, is_attack

    def add_packet(self, packet_data):
        """
        Adiciona um pacote à fila para processamento assíncrono.
        """
        self.packet_queue.put(packet_data)

    def _monitor_thread(self):
        """
        Thread que processa pacotes da fila e atualiza estatísticas.
        """
        while self.is_monitoring:
            try:
                packet = self.packet_queue.get(timeout=1) # Espera por 1 segundo
                
                # Adicionar timestamp se não tiver (para simulações)
                if "time" not in packet:
                    packet["time"] = time.time()
                if "protocol" not in packet:
                    packet["protocol"] = "Unknown"
                if "source" not in packet:
                    packet["source"] = "Unknown"
                if "length" not in packet:
                    packet["length"] = 0

                predicted_attack, confidence, is_attack = self.predict_attack(packet)
                
                # Atualizar estatísticas globais (usadas pela API)
                from src.routes.ddos_detection import detection_stats # Importar aqui para evitar circular
                
                with detection_stats["lock"]:
                    detection_stats["total_packets"] += 1
                    if is_attack:
                        detection_stats["attacks_detected"][predicted_attack] += 1
                        detection_stats["last_detection"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        detection_stats["detection_history"].append({
                            "timestamp": detection_stats["last_detection"],
                            "type": predicted_attack,
                            "confidence": f"{confidence:.2%}",
                            "source": packet.get("source", "N/A"),
                            "destination": packet.get("destination", "N/A")
                        })
                        # Manter histórico limitado
                        if len(detection_stats["detection_history"]) > 50:
                            detection_stats["detection_history"].pop(0)

            except queue.Empty:
                continue # Nenhuma pacote na fila, continua esperando
            except Exception as e:
                print(f"Erro no processamento do pacote: {e}")

    def start_monitoring(self):
        """
        Inicia a thread de monitoramento.
        """
        if not self.is_monitoring:
            self.is_monitoring = True
            self.monitor_thread = threading.Thread(target=self._monitor_thread)
            self.monitor_thread.daemon = True # Permite que a thread termine com o programa principal
            self.monitor_thread.start()
            print("Monitoramento de DDoS iniciado.")

    def stop_monitoring(self):
        """
        Para a thread de monitoramento.
        """
        if self.is_monitoring:
            self.is_monitoring = False
            self.monitor_thread.join(timeout=5) # Espera a thread terminar
            if self.monitor_thread.is_alive():
                print("Aviso: Thread de monitoramento não terminou em tempo.")
            print("Monitoramento de DDoS parado.")

# Função de simulação de tráfego (para teste local do realtime_detector.py)
def simulate_network_traffic(detector, data_file="processed_network_traffic.csv"):
    """
    Simula tráfego de rede em tempo real usando os dados processados.
    
    Args:
        detector (DDoSDetector): Instância do detector
        data_file (str): Caminho para o arquivo de dados processados
    """
    print("Carregando dados para simulação...")
    df = pd.read_csv(data_file)
    
    print(f"Simulando {len(df)} pacotes de rede...")
    
    for index, row in df.iterrows():
        packet_data = {
            "time": row["Time"],
            "length": row["Length"],
            "protocol": row["Protocol"],
            "source": row["Source"],
            "destination": row["Destination"],
            "info": row["Info"]
        }
        
        # Adicionar pacote ao detector
        detector.add_packet(packet_data)
        
        # Simular delay entre pacotes (ajustável)
        time.sleep(0.001)  # 1ms entre pacotes
        
        # Parar após um número específico de pacotes para demonstração
        if index >= 1000:  # Simular apenas os primeiros 1000 pacotes
            break
    
    print("Simulação de tráfego concluída.")

if __name__ == "__main__":
    # Criar detector
    detector = DDoSDetector()
    
    # Iniciar monitoramento
    detector.start_monitoring()
    
    # Simular tráfego de rede
    simulate_network_traffic(detector)
    
    # Aguardar um pouco para processar todos os pacotes
    time.sleep(5)
    
    # Parar monitoramento
    detector.stop_monitoring()
