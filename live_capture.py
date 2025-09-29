import subprocess
import requests
import json
import time

# URL da sua API de detecção
API_URL = "http://localhost:5002/api/ddos/detect" 

# --- COMANDO TSHARK CORRIGIDO ---
# Usando 'ip.proto' em vez de '_ws.col.Protocol' para uma identificação de protocolo mais confiável.
TSHARK_COMMAND = [
    'sudo',
    'tshark',
    '-i', 'eth0',  # <-- MUDE AQUI para sua interface (ex: eth0, wlan0 )
    '-l',
    '-T', 'fields',
    '-e', 'frame.time_epoch',
    '-e', 'ip.src',
    '-e', 'ip.dst',
    '-e', 'ip.proto',  # <-- MUDANÇA CRÍTICA AQUI
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
        process = subprocess.Popen(
            TSHARK_COMMAND, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True
        )

        for line in iter(process.stdout.readline, ''):
            if not line.strip():
                continue

            parts = line.strip().split('\t')
            
            if len(parts) < 6:
                continue

            # Monta o dicionário do pacote para enviar à API
            # O campo 'protocol' agora conterá um número (ex: '6' para TCP)
# Em live_capture.py

# ... (dentro do loop 'for line in iter(...)')

            # Monta o dicionário do pacote com as chaves CORRETAS (Primeira letra maiúscula)
            packet_data = {
                'Time': float(parts[0]) if parts[0] else 0.0,
                'Source': parts[1] if parts[1] else 'N/A',
                'Destination': parts[2] if parts[2] else 'N/A',
                'Protocol': parts[3] if parts[3] else 'N/A',
                'Length': int(parts[4]) if parts[4] else 0,   # <-- CORRIGIDO
                'Info': parts[5] if parts[5] else 'N/A'
            }

            try:
                response = requests.post(API_URL, json=packet_data, timeout=2)
                response.raise_for_status()
            except requests.exceptions.RequestException as e:
                print(f"Erro ao enviar para a API: {e}")

# ... (resto do arquivo)
            
    except FileNotFoundError:
        print("Erro: 'tshark' não encontrado.")
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