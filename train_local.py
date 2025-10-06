import pandas as pd # type: ignore
import numpy as np # type: ignore
import os
from sklearn.ensemble import RandomForestClassifier # type: ignore
from sklearn.preprocessing import LabelEncoder # type: ignore
from sklearn.model_selection import train_test_split # type: ignore
from sklearn.metrics import classification_report, confusion_matrix # type: ignore
import joblib # type: ignore
import seaborn as sns # type: ignore
import matplotlib.pyplot as plt # type: ignore
import warnings

warnings.simplefilter(action='ignore', category=FutureWarning)

def preprocess_robust(file_paths, window_size=1.0):
    """
    Versão final e robusta do pré-processamento.
    """
    print("Iniciando pré-processamento ROBUSTO (v28)...")
    column_names = ['Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info']
    all_dfs = []
    for path, label in file_paths.items():
        if os.path.exists(path) and os.path.getsize(path) > 0:
            df = pd.read_csv(path, engine='python', sep='|', header=None, names=column_names, on_bad_lines='skip')
            df["Label"] = label
            all_dfs.append(df)
            print(f"Arquivo {path} lido com sucesso.")

    if not all_dfs:
        print("ERRO: Nenhum arquivo de dados de ataque encontrado.")
        return None

    df_combined = pd.concat(all_dfs, ignore_index=True)
    df_combined["Time"] = pd.to_numeric(df_combined["Time"], errors="coerce")
    df_combined["Length"] = pd.to_numeric(df_combined["Length"], errors="coerce")
    df_combined.dropna(subset=["Time", "Protocol", "Info", "Length"], inplace=True)

    def correct_protocol_final(row):
        proto_num = str(row['Protocol'])
        info_str = str(row['Info']).lower()
        
        if proto_num == '6' or '[syn]' in info_str:
            return 'TCP'
        if proto_num == '17':
            return 'UDP'
        if proto_num == '1':
            return 'ICMP'
        
        # Fallback para pacotes fragmentados onde o protocolo está na Info
        if 'proto=udp' in info_str: return 'UDP'
        if 'proto=icmp' in info_str: return 'ICMP'
        
        return 'Other'

    df_combined['Protocol'] = df_combined.apply(correct_protocol_final, axis=1)

    df_combined['Is_SYN'] = df_combined['Info'].str.contains('[SYN]', regex=False).astype(int)
    df_combined['Is_Fragmented'] = df_combined['Info'].str.contains('Fragmented', regex=False).astype(int)

    start_time, end_time = df_combined['Time'].min(), df_combined['Time'].max()
    bins = np.arange(start_time, end_time + window_size, window_size)
    df_combined['TimeWindow'] = pd.cut(df_combined['Time'], bins=bins, right=False, labels=bins[:-1])
    df_combined.dropna(subset=['TimeWindow'], inplace=True)

    grouped = df_combined.groupby('TimeWindow')
    protocol_counts = grouped['Protocol'].value_counts().unstack(fill_value=0)
    agg_features = grouped.agg(
        Packet_Count=('Time', 'count'),
        SYN_Flag_Count=('Is_SYN', 'sum'),
        Fragmented_Packet_Count=('Is_Fragmented', 'sum'),
        Avg_Packet_Length=('Length', 'mean'),
        Label=('Label', 'first')
    )

    df_agg = pd.concat([protocol_counts, agg_features], axis=1)
    df_agg.dropna(subset=['Label'], inplace=True)
    df_agg['Packet_Rate'] = df_agg['Packet_Count'] / window_size

    feature_order = ['TCP', 'UDP', 'ICMP', 'Avg_Packet_Length', 'SYN_Flag_Count', 'Fragmented_Packet_Count', 'Packet_Rate']
    for col in ['TCP', 'UDP', 'ICMP', 'Other']:
        if col not in df_agg.columns:
            df_agg[col] = 0
    
    df_agg = df_agg.fillna(0)
    
    print("\n--- Validação dos Dados de Treinamento Processados ---")
    summary = df_agg.groupby('Label')[['TCP', 'UDP', 'ICMP', 'SYN_Flag_Count', 'Fragmented_Packet_Count']].mean()
    print(summary)
    
    # Verifica se a contagem de UDP para UDPFlood é maior que zero
    if summary.loc['UDPFlood']['UDP'] == 0:
        print("\nERRO CRÍTICO DE PRÉ-PROCESSAMENTO: A contagem de pacotes UDP para a classe UDPFlood é zero. Verifique a lógica `correct_protocol_final`.")
        return None
    else:
        print("\nVALIDAÇÃO BEM-SUCEDIDA: A contagem de pacotes UDP para UDPFlood é maior que zero.")

    return df_agg[feature_order + ['Label']]

def train_final_model(df_features):
    """
    Treina e avalia o modelo final (v28).
    """
    le = LabelEncoder()
    df_features["Label_Encoded"] = le.fit_transform(df_features["Label"])

    features = ['TCP', 'UDP', 'ICMP', 'Avg_Packet_Length', 'SYN_Flag_Count', 'Fragmented_Packet_Count', 'Packet_Rate']
    X = df_features[features]
    y = df_features["Label_Encoded"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)

    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)

    print("\nTreinando o modelo final (v28)...")
    model.fit(X_train, y_train)

    output_dir = 'src'
    os.makedirs(output_dir, exist_ok=True)
    joblib.dump(model, os.path.join(output_dir, "ddos_model_v28.pkl"))
    joblib.dump(le, os.path.join(output_dir, "label_encoder_v28.pkl"))
    print(f"\nModelo final (v28) e LabelEncoder salvos na pasta '{output_dir}'.")

    print("\n--- Avaliação Final do Modelo ---")
    y_pred = model.predict(X_test)
    print("\nRelatório de Classificação:")
    print(classification_report(y_test, y_pred, target_names=le.classes_))
    
    print("\nMatriz de Confusão:")
    cm = confusion_matrix(y_test, y_pred)
    sns.heatmap(cm, annot=True, fmt='d', xticklabels=le.classes_, yticklabels=le.classes_)
    plt.xlabel('Predito')
    plt.ylabel('Verdadeiro')
    plt.show()

    print("\nImportância das Features:")
    feature_importances = pd.Series(model.feature_importances_, index=features).sort_values(ascending=False)
    print(feature_importances)
    
    # VERIFICAÇÃO FINAL COM CENÁRIOS MANUAIS
    print("\n--- Verificação Final com Cenários Manuais ---")
    # Cenário de teste para SynFlood: Muitos pacotes TCP, pequenos, alta contagem de SYN.
    syn_test_data = pd.DataFrame([[100, 5, 5,   60,  100,  0,  110]], columns=features)
    # Cenário de teste para ICMPFlood: Muitos pacotes ICMP, grandes, muitos fragmentos.
    icmp_test_data = pd.DataFrame([[5, 5, 100, 1400,  0,  100, 110]], columns=features)
    # Cenário de teste para UDPFlood: Muitos pacotes UDP, médios, SEM fragmentos.
    udp_test_data = pd.DataFrame([[5, 100, 5,  500,  0,  0,  110]], columns=features)

    syn_pred = le.inverse_transform(model.predict(syn_test_data))[0]
    icmp_pred = le.inverse_transform(model.predict(icmp_test_data))[0]
    udp_pred = le.inverse_transform(model.predict(udp_test_data))[0]

    print(f"Predição para cenário de SynFlood: '{syn_pred}'")
    print(f"Predição para cenário de ICMPFlood: '{icmp_pred}'")
    print(f"Predição para cenário de UDPFlood: '{udp_pred}'")

    if "SynFlood" in syn_pred and "ICMPFlood" in icmp_pred and "UDPFlood" in udp_pred:
        print("\nVERIFICAÇÃO FINAL BEM-SUCEDIDA! O modelo classifica corretamente todos os cenários manuais.")
    else:
        print("\nVERIFICAÇÃO FINAL FALHOU. Revise a importância das features e a validação dos dados.")

# EXECUÇÃO
if __name__ == '__main__':
    attack_files = {
        "SynFlood_V16.csv": "SynFlood",
        "ICMPFlood_V16.csv": "ICMPFlood",
        "UDPFlood_V16.csv": "UDPFlood",
    }

    processed_features = preprocess_robust(attack_files)

    if processed_features is not None:
        train_final_model(processed_features)