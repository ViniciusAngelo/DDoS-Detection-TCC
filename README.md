# DDoS-Detection-TCC — Dashboard com Streamlit

Este projeto possui um backend em Flask para detecção de DDoS e agora um frontend moderno feito em Streamlit, substituindo o HTML estático anterior.

## Pré-requisitos
- Python 3.9+ (recomendado)
- Windows PowerShell (você já está usando)

## Configurar ambiente (Windows PowerShell)

```powershell
# 1) (Opcional, recomendado) Criar e ativar um ambiente virtual
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 2) Instalar dependências
pip install --upgrade pip
pip install -r requirements.txt
```

## Rodar o backend (Flask)

```powershell
# Na raiz do projeto
python .\src\main.py
# O backend subirá em http://localhost:5002
```

Mantenha esse terminal aberto.

## Rodar o frontend (Streamlit)

Abra um novo terminal PowerShell na raiz do projeto e execute:

```powershell
streamlit run .\streamlit_app.py
```

O Streamlit abrirá no navegador (algo como http://localhost:8501). No canto esquerdo (sidebar), verifique o campo "URL da API (backend Flask)" — deve estar como:

```
http://localhost:5002/api/ddos
```

Se necessário, ajuste e ative o "Atualizar automaticamente". O dashboard exibirá:
- Métricas: total de pacotes, ataques detectados, tráfego normal e última detecção
- Gráfico de distribuição (pizza ou barras)
- Log de detecções recentes
- Controles de simulação (nº de pacotes e delay)

## Simulação de tráfego
No Streamlit, em "Controles de Simulação", defina a quantidade de pacotes e o delay e clique em "Iniciar Simulação". A API buscará os dados em `src/processed_network_traffic.csv`. Se o arquivo não existir, a API retornará um erro informando o caminho esperado.

## Observações
- CORS já está habilitado no Flask, então o Streamlit consegue se comunicar com a API local.
- Se o modelo/encoder não forem encontrados (caminhos em `src/routes/realtime_detector.py`), o backend continuará processando regras básicas, mas pode não classificar via ML. Ajuste os caminhos do `MODEL_PATH` e `ENCODER_PATH` se necessário.
- Para parar os serviços: encerre os terminais do Flask e do Streamlit (Ctrl+C em cada um).

## Problemas comuns
- "Não foi possível resolver a importação ...": garanta que o ambiente virtual está ativado e que você rodou `pip install -r requirements.txt`.
- Porta já em uso: feche processos que estejam usando 5002 (Flask) ou 8501 (Streamlit) ou troque as portas.