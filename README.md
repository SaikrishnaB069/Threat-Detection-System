# 🛡️ SOC Threat Detection Dashboard

## Overview

A live cybersecurity monitoring dashboard built using Python and Streamlit that analyzes authentication logs to detect suspicious activity such as brute-force attacks and port scanning attempts.

## Live Demo

https://threat-detection-system-g9cf5b5xitupvpmrwyqfb2.streamlit.app/

## Features

- Real-time log monitoring
- Failed login detection
- Brute-force attack alerts
- Port scan detection
- MITRE ATT&CK mapping
- Downloadable incident reports
- Interactive dashboard UI

## Technologies Used

- Python
- Streamlit
- Pandas
- Regex
- GitHub
- Streamlit Cloud

## How It Works

The application reads authentication logs, extracts suspicious patterns, applies threshold-based detection logic, and displays alerts visually through a dashboard.

## Run Locally

```bash
pip install -r requirements.txt
streamlit run app.py
