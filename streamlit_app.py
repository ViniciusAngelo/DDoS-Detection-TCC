import time
import requests # type: ignore
import streamlit as st # type: ignore
from typing import Dict, Any, Optional
import pandas as pd # type: ignore

try:
    import plotly.express as px # type: ignore
except Exception:
    px = None  # Gráfico de pizza ficará indisponível se plotly não estiver instalado

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
st.session_state.api_base = st.sidebar.text_input(
    "URL da API (backend Flask)",
    value=st.session_state.api_base,
    help="Ex.: http://localhost:5002/api/ddos"
)

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
st.caption("Visual em Streamlit mantendo as funcionalidades do frontend original.")

# Ações rápidas
with st.container():
    colA, colB, colC = st.columns([1, 1, 1])
    with colA:
        if st.button("Atualizar agora", type="primary"):
            st.rerun()
    with colB:
        if st.button("Resetar estatísticas", help="Chama /reset-stats"):
            reset_stats()
            st.rerun()
    with colC:
        if st.button("Verificar Saúde", help="Chama /health"):
            try:
                health = api_get("/health")
                st.success(health)
            except Exception as e:
                st.error(f"Falha na verificação de saúde: {e}")

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

# Log de detecções
st.subheader("Log de Detecções Recentes")
if not history:
    st.write("Nenhuma detecção registrada ainda.")
else:
    for item in reversed(history):  # mais recentes primeiro
        tipo = item.get("type") or item.get("label") or "?"
        timestamp = item.get("timestamp") or ""
        src = item.get("source") or item.get("src") or "?"
        dst = item.get("destination") or item.get("dst") or "?"
        conf = item.get("confidence")
        badge_color = "red" if (tipo and tipo != "Normal") else "green"
        st.markdown(
            f"<div style='border:1px solid #e5e7eb;border-radius:8px;padding:8px;margin-bottom:8px;display:flex;gap:8px;align-items:center'>"
            f"<span style='color:#7f8c8d;font-weight:600'>[{timestamp}]</span>"
            f"<span style='background:{badge_color};color:white;padding:2px 8px;border-radius:8px;font-weight:700'>{tipo}</span>"
            f"<span style='color:#f39c12;font-weight:700'>{'(' + str(conf) + ')' if conf else ''}</span>"
            f"<span>{src} → {dst}</span>"
            f"</div>",
            unsafe_allow_html=True
        )


# Controles de Simulação
st.subheader("Controles de Simulação")
colS1, colS2, colS3 = st.columns([1, 1, 2])
with colS1:
    num_packets = st.number_input("Pacotes", min_value=1, value=100, step=10)
with colS2:
    delay = st.number_input("Delay (s)", min_value=0.0, value=0.01, step=0.001, format="%.3f")
with colS3:
    start_sim = st.button("Iniciar Simulação", type="primary")

if start_sim:
    simulate_traffic(int(num_packets), float(delay))

st.caption("A simulação é executada em lote e não pode ser interrompida após iniciada.")


# Auto-refresh simples controlado por checkbox
if st.session_state.auto_refresh:
    time.sleep(float(st.session_state.refresh_interval))
    st.rerun()
