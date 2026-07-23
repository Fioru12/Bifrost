# <div align="center">Bifrost 🌈</div>
<div align="center">
  <sub><i>Il ponte di Luce &mdash; Network Telemetry & Port Analysis</i></sub>
</div>

<br/>

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![AES-128](https://img.shields.io/badge/Encryption-AES--128-FF4500?style=for-the-badge&logo=lock&logoColor=white)
![CI](https://github.com/Fioru12/Bifrost/actions/workflows/pytest.yml/badge.svg?style=for-the-badge)

</div>

<br/>

> [!IMPORTANT]
> **Bifrost** è il terzo modulo della **suite Asgard**. 
> Fornisce visibilità totale sulla rete, analizzando traffico live e identificando anomalie o tentativi di scansione.

---

## 🧠 Executive Summary
Non puoi difendere ciò che non puoi vedere. **Bifrost** chiude il cerchio della sicurezza aziendale monitorando attivamente il layer di rete, identificando C2 (Command & Control), scansioni di rete e anomalie di traffico, cifrando poi i report per la massima riservatezza.

```
  Port Scanner ──▶ Traffic Analyzer ──▶ Encrypted Report
```

---

## 🚀 Funzionalit&agrave;

| Modulo | Cosa fa |
|:---|:---|
| 📡 **Port Scanner** | TCP Scan parallelo + fingerprinting + banner grabbing |
| 📊 **Traffic Analyzer** | Snapshot live + anomaly detection (Port scan, TIME_WAIT flood) |
| 🔒 **Encrypted Report** | Report Markdown cifrati con AES-128 (Fernet) |

> [!TIP]
> Il modulo di reportistica usa una derivazione di chiave PBKDF2 per rendere i report leggibili solo a chi possiede la password.

---

## 🛠️ Quickstart

```bash
# Installazione
git clone https://github.com/Fioru12/Bifrost.git
cd Bifrost
pip install -r requirements.txt

# Test
pytest

# Analisi completa + report cifrato
python main.py full --host 127.0.0.1 --password "segreto"
```

---

## 🔗 Suite Asgard

| Modulo | Ruolo | Stato |
|:---|:---|:---:|
| **Heimdall** | HIDS &middot; Rilevamento & Response | `Fatto` |
| **Mjolnir** | IR &middot; Triage & Forensics | `Fatto` |
| **Bifrost** | Rete &middot; Telemetria & Report Cifrati | `Fatto` |

---

<div align="center">

**[Fioru12](https://github.com/Fioru12)** &middot; MIT License

</div>
