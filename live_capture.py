import subprocess
import requests # type: ignore
import json
import time
import os
import signal
import threading
import queue
from typing import Optional

API_URL = "http://localhost:5002/api/ddos/detect"
INTERFACE = "eth0"           
CAPTURE_DURATION = 10 # segundos antes de reiniciar a captura
TSHARK_COMMAND = [
    'sudo',
    'tshark',
    '-i', INTERFACE,
    '-l',
    '-T', 'fields',
    '-e', 'frame.time_epoch',
    '-e', 'ip.src',
    '-e', 'ip.dst',
    '-e', 'ip.proto',
    '-e', 'frame.len',
    '-e', '_ws.col.Info'
]

def _reader_thread(process: subprocess.Popen, q: queue.Queue):
    try:
        for line in iter(process.stdout.readline, ''):
            if line == '' and process.poll() is not None:
                break
            q.put(line)
    except Exception as e:
        
        q.put(f"__READER_ERROR__\t{e}\n")
    finally:
        try:
            process.stdout.close()
        except Exception:
            pass

def start_realtime_capture_once(duration: int) -> None:
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Iniciando captura na interface '{INTERFACE}' por {duration} segundos...")
    q: queue.Queue = queue.Queue()
    process: Optional[subprocess.Popen] = None

    try:
        process = subprocess.Popen(
            TSHARK_COMMAND,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            preexec_fn=os.setsid  
        )
    except FileNotFoundError:
        print("Erro: 'tshark' não encontrado. Instale o tshark ou verifique o PATH.")
        return
    except PermissionError:
        print("Erro de permissão. Execute este script com 'sudo' ou garanta permissões adequadas.")
        return
    except Exception as e:
        print(f"Erro ao iniciar tshark: {e}")
        return

    reader = threading.Thread(target=_reader_thread, args=(process, q), daemon=True)
    reader.start()

    start_time = time.time()

    try:
        while True:
            elapsed = time.time() - start_time
            if elapsed >= duration:
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Tempo de captura ({duration}s) atingido — reiniciando...")
                break

            try:
                line = q.get(timeout=1.0)
            except queue.Empty:
                if process.poll() is not None:
                    stderr = process.stderr.read() if process.stderr else ""
                    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] tshark terminou inesperadamente (returncode={process.returncode}). Stderr: {stderr.strip()}")
                    break
                continue

            if isinstance(line, str) and line.startswith("__READER_ERROR__"):
                print("Erro na thread leitora:", line)
                continue

            if not line.strip():
                continue

            parts = line.strip().split('\t')
            if len(parts) < 6:
                
                continue

            packet_data = {
                'Time': float(parts[0]) if parts[0] else 0.0,
                'Source': parts[1] if parts[1] else 'N/A',
                'Destination': parts[2] if parts[2] else 'N/A',
                'Protocol': parts[3] if parts[3] else 'N/A',
                'Length': int(parts[4]) if parts[4] else 0,
                'Info': parts[5] if parts[5] else 'N/A'
            }

            try:
                response = requests.post(API_URL, json=packet_data, timeout=2)
                response.raise_for_status()
            except requests.exceptions.RequestException as e:
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Erro ao enviar para a API: {e}")

    except KeyboardInterrupt:
        print("\nCaptura interrompida pelo usuário (KeyboardInterrupt).")
    finally:
        if process and process.poll() is None:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            except Exception:
                try:
                    process.terminate()
                except Exception:
                    pass

            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                except Exception:
                    pass
                process.wait()

        try:
            reader.join(timeout=1)
        except Exception:
            pass

        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Captura finalizada.")

def start_realtime_capture_loop(cycle_seconds: int):
    try:
        while True:
            start_realtime_capture_once(cycle_seconds)
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\nLoop principal interrompido pelo usuário. Encerrando.")

if __name__ == '__main__':
    start_realtime_capture_loop(CAPTURE_DURATION)
