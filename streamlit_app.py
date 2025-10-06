import time
import requests # type: ignore
import streamlit as st # type: ignore
from typing import Dict, Any, Optional
import pandas as pd # type: ignore

try:
    import plotly.express as px # type: ignore
except Exception:
    px = None  # Gráfico de pizza ficará indisponível se plotly não estiver instalado

# Tenta usar um auto-refresh mais suave (evita blink) se disponível
try:
    from streamlit_extras.st_autorefresh import st_autorefresh  # type: ignore
except Exception:
    st_autorefresh = None  # fallback para sleep + rerun

# Configurações iniciais
st.set_page_config(page_title="DDoS Detection Dashboard", page_icon="🛡️", layout="wide")


def get_api_base_default() -> str:
    return "http://localhost:5002/api/ddos"


if "api_base" not in st.session_state:
    st.session_state.api_base = get_api_base_default()

if "auto_refresh" not in st.session_state:
    st.session_state.auto_refresh = True

if "refresh_interval" not in st.session_state:
    st.session_state.refresh_interval = 2.0

# Sidebar
st.sidebar.header("Configurações")
# st.session_state.api_base = st.sidebar.text_input(
#     "URL da API (backend Flask)",
#     value=st.session_state.api_base,
#     help="Ex.: http://localhost:5002/api/ddos"
# )

st.session_state.auto_refresh = st.sidebar.checkbox(
    "Atualizar automaticamente", value=st.session_state.auto_refresh
)
st.session_state.refresh_interval = st.sidebar.number_input(
    "Intervalo de atualização (s)", min_value=0.5, max_value=30.0, value=float(st.session_state.refresh_interval), step=0.5
)


def api_get(path: str) -> Dict[str, Any]:
    url = f"{st.session_state.api_base}{path}"
    r = requests.get(url, timeout=10)
    r.raise_for_status()
    return r.json()


def api_post(path: str, json: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    url = f"{st.session_state.api_base}{path}"
    r = requests.post(url, json=json or {}, timeout=60)
    r.raise_for_status()
    return r.json()


def fetch_stats() -> Dict[str, Any]:
    try:
        return api_get("/stats")
    except Exception as e:
        st.error(f"Falha ao buscar estatísticas: {e}")
        return {}


def simulate_traffic(num_packets: int, delay: float):
    try:
        resp = api_post("/simulate_traffic", {"num_packets": num_packets, "delay": delay})
        st.success(f"Simulação iniciada: {resp}")
    except Exception as e:
        st.error(f"Erro ao iniciar simulação: {e}")


def reset_stats():
    try:
        resp = api_post("/reset-stats")
        st.info(resp.get("message", "Estatísticas resetadas."))
    except Exception as e:
        st.error(f"Erro ao resetar estatísticas: {e}")

# Cabeçalho
st.title("🛡️ DDoS Detection Dashboard")

# Ações rápidas
with st.container():
    colA, colB, colC = st.columns([1, 1, 1])
    # with colA:
    #     if st.button("Atualizar agora", type="primary"):
    #         st.rerun()
    with colA:
        if st.button("Resetar estatísticas", help="Chama /reset-stats"):
            reset_stats()
            st.rerun()
    # with colC:
    #     if st.button("Verificar Saúde", help="Chama /health"):
    #         try:
    #             health = api_get("/health")
    #             st.success(health)
    #         except Exception as e:
    #             st.error(f"Falha na verificação de saúde: {e}")

# Estatísticas e gráfico
stats = fetch_stats()

total_packets = stats.get("total_packets_processed") or stats.get("total_packets") or 0
attacks_detected = stats.get("attacks_detected", {})
last_detection = stats.get("last_detection_label") or stats.get("last_detection") or "N/A"
last_detection_ts = stats.get("last_detection_timestamp")
history = stats.get("detection_history", []) or []

col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Total de Pacotes Processados", f"{total_packets}")
with col2:
    total_attacks = sum(attacks_detected.get(k, 0) for k in ["SynFlood", "ICMPFlood", "UDPFlood"]) if attacks_detected else 0
    st.metric("Ataques Detectados", f"{total_attacks}")
with col3:
    normal_traffic = attacks_detected.get("Normal", 0) if attacks_detected else 0
    st.metric("Tráfego Normal", f"{normal_traffic}")
with col4:
    subtitle = last_detection
    if last_detection_ts:
        subtitle += f" ({last_detection_ts})"
    st.metric("Última Detecção", subtitle)


with st.container():
    st.subheader("Distribuição de Ataques Detectados")
    if attacks_detected and any(v > 0 for v in attacks_detected.values()):
        labels = list(attacks_detected.keys())
        values = list(attacks_detected.values())
        if px:
            fig = px.pie(values=values, names=labels, hole=0.3,
                         color=labels,
                         color_discrete_map={
                             "SynFlood": "#FF6384",
                             "ICMPFlood": "#36A2EB",
                             "UDPFlood": "#FFCE56",
                             "Normal": "#4BC0C0"
                         })
            fig.update_traces(textposition='inside', textinfo='percent+label')
            st.plotly_chart(fig, use_container_width=True)
        else:
            df_chart = pd.DataFrame({"Quantidade": values}, index=labels)
            st.bar_chart(df_chart)
    else:
        st.info("Sem dados suficientes para o gráfico ainda.")

# Auto-refresh
if st.session_state.auto_refresh:
    interval_ms = int(float(st.session_state.refresh_interval) * 1000)
    if st_autorefresh:
        st_autorefresh(interval=interval_ms, key="ddos_auto_refresh")
    else:
        time.sleep(float(st.session_state.refresh_interval))
        st.rerun()
