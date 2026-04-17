import streamlit as st
import re
import pandas as pd
import time
import os

st.set_page_config(page_title="SOC Live Dashboard", layout="wide")

st.title("🛡️ SOC Live Threat Dashboard")
st.caption("Real-Time Monitoring | MITRE ATT&CK Mapping")

log_path = "logs/auth.log"

refresh = st.sidebar.slider("Refresh every seconds", 1, 10, 3)

run_monitor = st.sidebar.checkbox("Enable Live Monitoring", value=True)


def analyze_logs(lines):
    failed_login = {}
    port_scan = {}
    alerts = []
    mitre = []

    for line in lines:

        if "Failed password" in line:
            match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)

            if match:
                ip = match.group(1)

                if ip in failed_login:
                    failed_login[ip] += 1
                else:
                    failed_login[ip] = 1

        if "scanned port" in line:
            match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)

            if match:
                ip = match.group(1)

                if ip in port_scan:
                    port_scan[ip] += 1
                else:
                    port_scan[ip] = 1

    for ip in failed_login:
        if failed_login[ip] >= 3:
            alerts.append("[HIGH] Brute-force suspected from " + ip)
            mitre.append("T1110 - Brute Force")

    for ip in port_scan:
        if port_scan[ip] >= 3:
            alerts.append("[MEDIUM] Port scan suspected from " + ip)
            mitre.append("TA0043 - Reconnaissance")

    return failed_login, port_scan, alerts, mitre


if os.path.exists(log_path):

    while run_monitor:

        with open(log_path, "r") as file:
            lines = file.readlines()

        failed_login, port_scan, alerts, mitre = analyze_logs(lines)

        col1, col2, col3 = st.columns(3)

        col1.metric("Total Alerts", len(alerts))
        col2.metric("Failed Login IPs", len(failed_login))
        col3.metric("Scanning IPs", len(port_scan))

        st.divider()

        st.subheader("🚨 Live Alerts")

        if alerts:
            for item in alerts:
                st.error(item)
        else:
            st.success("No suspicious activity detected.")

        st.divider()

        st.subheader("🎯 MITRE ATT&CK Mapping")

        if mitre:
            for item in set(mitre):
                st.info(item)
        else:
            st.write("No mapped techniques.")

        st.divider()

        c1, c2 = st.columns(2)

        with c1:
            st.subheader("Failed Login Attempts")
            if failed_login:
                df = pd.DataFrame(
                    list(failed_login.items()),
                    columns=["IP", "Attempts"]
                )
                st.dataframe(df, use_container_width=True)

        with c2:
            st.subheader("Port Scan Activity")
            if port_scan:
                df2 = pd.DataFrame(
                    list(port_scan.items()),
                    columns=["IP", "Ports"]
                )
                st.dataframe(df2, use_container_width=True)

        time.sleep(refresh)
        st.rerun()

else:
    st.error("Log file not found: logs/auth.log")