<div align="center">

# BIFROST

### Asgard Cybersecurity Suite - Module III

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![AES-128](https://img.shields.io/badge/Encryption-AES--128-FF4500?style=for-the-badge&logo=lock&logoColor=white)
![CI](https://github.com/Fioru12/Bifrost/actions/workflows/pytest.yml/badge.svg?style=for-the-badge)

> **Bifrost** - *Il ponte di Luce che collega Midgard ad Asgard* - e' un toolkit di **Network Security Analysis**.
> Scansiona porte, analizza il traffico di rete in tempo reale, rileva anomalie e genera report di telemetria cifrati con AES pronti per il team di sicurezza.

</div>

---

## Executive Summary

Non puoi difendere cio che non puoi vedere. Bifrost fornisce visibilita completa sul layer di rete, identificando C2 (Command & Control), scansioni di rete e anomalie di traffico.

```
  Port Scanner --> Traffic Analyzer --> Encrypted Reporter
                       |                     |
                 Anomaly Detection      AES-128 + Markdown
                       |                     |
                  Alerting              Report Cifrato
```

---

## Caratteristiche Tecniche

| Modulo | Descrizione |
|:---|:---|
| **Port Scanner** | TCP connect scan parallelo con 25+ servizi pre-identificati, banner grabbing, latenza misurata |
| **Traffic Analyzer** | Snapshot live connessioni, rilevamento port scan anomali, porte sospette (C2/malware), TIME_WAIT flood |
| **Encrypted Reporter** | Report Markdown + cifratura AES-128 con password (PBKDF2 key derivation) per telemetria sicura |
| **REST API** | Endpoint FastAPI per scan, analisi, report e full analysis combinata |

### Servizi riconosciuti dallo scanner

FTP - SSH - Telnet - SMTP - DNS - HTTP - HTTPS - SMB - RDP - MySQL - PostgreSQL - MSSQL - Redis - MongoDB - VNC - IMAP - POP3 - NetBIOS - e altri 7 porte comuni

### Anomalie rilevate

| Anomalia | Severita | Cosa rileva |
|:---|:---:|:---|
| PORT_SCAN_PATTERN | HIGH | Un IP con 15+ connessioni verso porte diverse |
| SUSPICIOUS_PORT | MEDIUM | Servizi su porte note per C2/malware (4444, 6666, 31337) |
| EXCESSIVE_TIMEWAIT | MEDIUM | 50+ connessioni TIME_WAIT (possibile SYN flood) |
| HIGH_CONNECTION_VOLUME | LOW | IP con 10+ connessioni attive (movimento laterale) |

---

## Struttura del Progetto

```
Bifrost/
+-- core/
|   +-- colors.py         ANSI colori per output terminale
|   +-- scanner.py        TCP port scanner con service fingerprinting
|   +-- analyzer.py       Traffic analyzer con anomaly detection (psutil)
|   +-- reporter.py       Report generator con cifratura AES (Fernet/PBKDF2)
|
+-- api/
|   +-- server.py         FastAPI REST API per scan, analysis e reports
|
+-- tests/
|   +-- test_bifrost.py   8 test pytest
|
+-- main.py               CLI: scan | analyze | full
+-- SECURITY.md           Security policy
+-- requirements.txt
```

---

## Quickstart

```bash
# Clone e installa
git clone https://github.com/Fioru12/Bifrost.git
cd Bifrost
pip install -r requirements.txt

# Esegui i test
pytest tests/ -v

# Scansiona porte comuni su un host
python main.py scan 127.0.0.1

# Analisi traffico live
python main.py analyze

# Analisi completa + report cifrato
python main.py full --host 127.0.0.1 --password "segreto"
```

---

## API Endpoints

| Method | Endpoint | Descrizione |
|:---:|:---|:---|
| GET | / | Stato del servizio e lista endpoint |
| POST | /api/v1/scan | Scansiona un host (body: {host, ports?, common?}) |
| GET | /api/v1/analyze | Snapshot live + anomaly detection |
| POST | /api/v1/report | Genera report Markdown/cifrato |
| GET | /api/v1/full?host= | Scan + Analyze + Report in un unico call |

Documentazione Swagger disponibile su http://127.0.0.1:8000/docs dopo l'avvio.

---

## Demo: Output Terminale

```
=================================================================
 Bifrost - Network Port Scanner
=================================================================
[*] Target: 127.0.0.1
[*] Ports scanned: 25
[*] Open ports: 2
[*] Scan duration: 1.01s

 Open Ports:
 PORT     SERVICE         LATENCY    BANNER
 ------   ------------   --------   ------------------------------
 135      MSRPC           0.38ms     -
 445      SMB             0.33ms     -
=================================================================

=================================================================
 Bifrost - Live Traffic Analyzer
=================================================================
[*] Snapshot time: 2026-07-23 12:29:23
[*] Total connections: 244
[*] Unique remote IPs: 52
[*] Anomalies detected: 1

 Anomalies Found:
  [HIGH] PORT_SCAN_PATTERN: IP 127.0.0.1 has 28 connections
=================================================================
```

---

## Suite Asgard

| Modulo | Ruolo | Stato |
|:---|:---|:---:|
| **Heimdall** | HIDS - Rilevamento & Active Response | Fatto |
| **Mjolnir** | Incident Response - Triage & Forensics | Fatto |
| **Bifrost** | Network Telemetry - Port Analysis & Encryption | Fatto |

---

<div align="center">

**[Fioru12](https://github.com/Fioru12)** - MIT License

</div>
