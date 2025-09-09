import subprocess
import requests
import json
import time

# URL da sua API de detecção
API_URL = "http://localhost:5002/api/ddos/detect" # OU "https://ddos-attack-detector.streamlit.app/api/ddos/detect"

# Comando tshark para capturar e extrair os campos necessários
TSHARK_COMMAND = [
    'sudo',
    'tshark',
    '-i', 'eth0',  # <-- MUDE AQUI para sua interface (ex: eth0, wlan0 )
    '-l',
    '-T', 'fields',
    '-e', 'frame.time_epoch',
    '-e', 'ip.src',
    '-e', 'ip.dst',
    '-e', '_ws.col.Protocol',
    '-e', 'frame.len',
    '-e', '_ws.col.Info'
]

def start_realtime_capture():
    """
    Inicia a captura com tshark e envia os pacotes para a API em tempo real.
    """
    print(f"Iniciando captura na interface 'eth0'...")
    print(f"Enviando dados para a API em {API_URL}")

    try:
        # Inicia o processo tshark
        process = subprocess.Popen(
            TSHARK_COMMAND, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True
        )

        # Lê a saída do tshark linha por linha
        for line in iter(process.stdout.readline, ''):
            if not line.strip():
                continue

            # A saída do tshark é separada por tabs
            parts = line.strip().split('\t')
            
            if len(parts) < 6:
                continue

            # Monta o dicionário do pacote para enviar à API
            packet_data = {
                'time': float(parts[0]) if parts[0] else 0.0,
                'source': parts[1] if parts[1] else 'N/A',
                'destination': parts[2] if parts[2] else 'N/A',
                'protocol': parts[3] if parts[3] else 'N/A',
                'length': int(parts[4]) if parts[4] else 0,
                'info': parts[5] if parts[5] else 'N/A'
            }

            try:
                # Envia o pacote para a API
                response = requests.post(API_URL, json=packet_data, timeout=2)
                response.raise_for_status() # Lança exceção para erros HTTP (4xx ou 5xx)
                
                result = response.json()
                if result.get('is_attack'):
                    print(f"[ALERTA] Ataque detectado: {result['attack_type']} | Origem: {packet_data['source']}")
                else:
                    # Descomente a linha abaixo para ver o tráfego normal
                    print(f"[OK] Tráfego normal: {packet_data['protocol']} | {packet_data['source']} -> {packet_data['destination']}")
                    pass

            except requests.exceptions.RequestException as e:
                print(f"Erro ao enviar para a API: {e}")
            
    except FileNotFoundError:
        print("Erro: 'tshark' não encontrado. Certifique-se de que o Wireshark está instalado e no PATH do sistema.")
    except PermissionError:
        print("Erro de permissão. Execute este script com 'sudo'.")
    except KeyboardInterrupt:
        print("\nCaptura interrompida pelo usuário.")
    finally:
        if 'process' in locals() and process.poll() is None:
            process.terminate()
            process.wait()
        print("Captura finalizada.")

if __name__ == '__main__':
    start_realtime_capture()


