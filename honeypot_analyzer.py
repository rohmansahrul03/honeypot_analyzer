# honeypot_analyzer.py

import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt
from sklearn.cluster import KMeans
from sklearn.ensemble import IsolationForest

st.set_page_config(page_title="Honeypot Attack Analyzer", layout="wide")
st.title("🛡️ Honeypot Attack Analyzer with Machine Learning")

# ---- Load Dataset ----
uploaded_file = st.file_uploader("sample_logs", type=["csv"])

if uploaded_file:
    df = pd.read_csv(uploaded_file)
    st.subheader("📄 Data Preview")
    st.dataframe(df.head())

    # ---- Preprocessing ----
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["hour"] = df["timestamp"].dt.hour

    # IP to integer
    def ip_to_int(ip):
        parts = list(map(int, ip.split(".")))
        return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]

    df["ip_int"] = df["src_ip"].apply(ip_to_int)
    df = df.drop(columns=["src_ip", "timestamp", "command", "malware_url"])
    df = pd.get_dummies(df, columns=["protocol", "country"])

    st.subheader("✅ Processed Data")
    st.write(df.head())

    # ---- Clustering (KMeans) ----
    kmeans = KMeans(n_clusters=3, random_state=42).fit(df)
    df["cluster"] = kmeans.labels_

    st.subheader("📊 KMeans Clustering")
    fig1, ax1 = plt.subplots()
    scatter = ax1.scatter(df["hour"], df["ip_int"], c=df["cluster"], cmap="viridis")
    ax1.set_xlabel("Hour of Attack")
    ax1.set_ylabel("IP Address (int)")
    ax1.set_title("Cluster of Attacks")
    st.pyplot(fig1)

    # ---- Anomaly Detection ----
    clf = IsolationForest(contamination=0.05, random_state=42)
    df["anomaly"] = clf.fit_predict(df)

    st.subheader("🚨 Anomaly Detection")
    st.write(df[df["anomaly"] == -1])

    fig2, ax2 = plt.subplots()
    ax2.scatter(df["hour"], df["ip_int"], c=df["anomaly"], cmap="coolwarm")
    ax2.set_xlabel("Hour")
    ax2.set_ylabel("IP Address (int)")
    ax2.set_title("Anomalous vs Normal Attacks")
    st.pyplot(fig2)
else:
    st.info("⬆️ Upload a honeypot log CSV file to start analysis.")
