<div align="center">

```
    ██╗  ██╗██╗███████╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
    ██║  ██║██║██╔════╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
    ███████║██║█████╗  ███████╗██║     ██║   ██║██║  ██║█████╗  
    ██╔══██║██║██╔══╝  ╚════██║██║     ██║   ██║██║  ██║██╔══╝  
    ██║  ██║██║███████╗███████║╚██████╗╚██████╔╝██████╔╝███████╗
    ╚═╝  ╚═╝╚═╝╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝
```

### **Asgard Cybersecurity Suite** &mdash; Module III

<br/>

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=flat-square&logo=fastapi&logoColor=white)
![cryptography](https://img.shields.io/badge/cryptography-41+-FF4500?style=flat-square&logo=lock&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-orange?style=flat-square)

<br/>

**Bifrost** &mdash; *il ponte di Luce che collega Midgard ad Asgard* &mdash; &egrave; un toolkit di **Network Security Analysis**.
Scansiona porte, analizza il traffico di rete in tempo reale, rileva anomalie e genera report di telemetria cifrati con AES pronti per il team di sicurezza.

</div>

---

## Il problema che risolve

Un SOC non pu&ograve; difendere ci&ograve; che non pu&ograve; vedere. **Bifrost** fornisce visibilit&agrave; completa sul layer di rete:

```
   Port Scanner          Traffic Analyzer         Encrypted Reporter
        │                        │                        │
        ▼                        ▼                        ▼
  ┌──────────────┐       ┌──────────────┐       ┌──────────────┐
  │  Host/port   │       │  Connessioni │       │  Report AES  │
  │  open + svc  │       │  live + anom │       │  + Markdown  │
  └──────────────┘       └──────────────┘       └──────────────┘
        │                        │                        │
        └────────────────────────┴────────────────────────┘
                                 │
                          API REST / CLI
```

---

## Architettura

<details>
<summary><b>Struttura completa del progetto</b></summary>

```
Bifrost/
├── core/
│   ├── scanner.py       TCP port scanner con service fingerprinting e banner grabbing
│   ├── analyzer.py      Traffic analyzer con anomaly detection (psutil)
│   └── reporter.py      Report generator con cifratura AES (Fernet/PBKDF2)
│
├── api/
│   └── server.py        FastAPI REST API per scan, analysis e reports
│
├── tests/
│   └── test_bifrost.py  Suite pytest completa
│
├── main.py              CLI: scan | analyze | full
├── requirements.txt
├── config.yaml
└── README.md
```

</details>

---

## Funzionalit&agrave;

| Modulo | Cosa fa |
|:---|:---|
| **Port Scanner** | TCP connect scan parallelo con 25+ servizi pre-identificati, banner grabbing, latenza misurata |
| **Traffic Analyzer** | Snapshot live connessioni, rilevamento port scan anomali, porte sospette (C2/malware), TIME_WAIT flood |
| **Encrypted Reporter** | Report Markdown + cifratura AES-128 con password (PBKDF2 key derivation) per telemetria sicura |
| **REST API** | Endpoint per scan, analisi, report e full analysis combinata |

### Servizi riconosciuti dallo scanner

`FTP` &middot; `SSH` &middot; `Telnet` &middot; `SMTP` &middot; `DNS` &middot; `HTTP` &middot; `HTTPS` &middot; `SMB` &middot; `RDP` &middot; `MySQL` &middot; `PostgreSQL` &middot; `MSSQL` &middot; `Redis` &middot; `MongoDB` &middot; `VNC` &middot; `IMAP` &middot; `POP3` &middot; `NetBIOS` &middot; e altri 7 porte comuni

### Anomalie rilevate

- **PORT_SCAN_PATTERN** &mdash; un IP con troppe connessioni attive verso porte diverse
- **SUSPICIOUS_PORT** &mdash; servizi in ascolto su porte note per C2/malware (4444, 6666, 31337...)
- **EXCESSIVE_TIMEWAIT** &mdash; possibile SYN flood o esaurimento porte
- **HIGH_CONNECTION_VOLUME** &mdash; IP con volume anomalo di connessioni (movimento laterale)

---

## Quickstart

```bash
# Clona e installa
git clone https://github.com/Fioru12/Bifrost.git
cd Bifrost
pip install -r requirements.txt

# Test
pytest tests/ -v

# Scansiona porte comuni su localhost
python main.py scan 127.0.0.1

# Analisi traffico live
python main.py analyze

# Analisi completa + report
python main.py full --host 127.0.0.1

# Analisi completa + report cifrato
python main.py full --host 127.0.0.1 --password "mia_password"
```

### Output della scansione

```
=================================================================
 Bifrost - Network Port Scanner
=================================================================
[*] Target: 127.0.0.1
[*] Ports scanned: 25
[*] Open ports: 3
[*] Scan duration: 0.12s

 Open Ports:
 PORT     SERVICE         LATENCY    BANNER
 ------   -----------   ----------   ------------------------------
 80       HTTP           0.5ms       Microsoft-IIS/10.0
 443      HTTPS          0.3ms       -
 3306     MySQL          1.2ms       8.0.35
=================================================================
```

---

## API

| Method | Endpoint | Descrizione |
|:---:|:---|:---|
| `GET` | `/` | Stato del servizio |
| `POST` | `/api/v1/scan` | Scansiona un host per porte aperte |
| `GET` | `/api/v1/analyze` | Analisi live del traffico di rete |
| `POST` | `/api/v1/report` | Genera report Markdown/cifrato |
| `GET` | `/api/v1/full` | Scan + Analisi + Report in un unico endpoint |

---

## Suite Asgard

Bifrost completa la **suite Asgard** &mdash; l'intero stack di sicurezza di un SOC in tre strumenti:

| Modulo | Ruolo | Stato |
|:---|:---|:---:|
| **Heimdall** | HIDS &middot; Rilevamento & Active Response | `Fatto` |
| **Mjolnir** | Incident Response &middot; Triage & Forensics | `Fatto` |
| **Bifrost** | Network Telemetry &middot; Port Analysis & Encrypted Reports | `Fatto` |

---

<div align="center">

*Costruito come progetto portfolio dimostrativo &mdash; pronto per essere mostrato ai recruiter e ai technical lead.*

**[Fioru12](https://github.com/Fioru12)** &middot; MIT License

</div>
