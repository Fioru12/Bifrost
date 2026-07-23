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
![pytest](https://img.shields.io/badge/pytest-7+-0A9EDC?style=flat-square&logo=pytest&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-orange?style=flat-square)

<br/>

**Bifrost** &mdash; *il ponte di Luce che collega Midgard ad Asgard* &mdash; &egrave; un toolkit di **Network Security Analysis** costruito da zero in Python.
Scansiona porte con fingerprinting parallelo, cattura e analizza il traffico di rete in tempo reale per rilevare anomalie, e genera report di telemetria cifrati con **AES-128** pronti per il team di sicurezza.

<br/>

```
  ┌─────────────┐       ┌──────────────┐       ┌──────────────────┐
  │ Port Scanner │──────▶│   Traffic    │──────▶│    Encrypted     │
  │  + Banner    │       │  Analyzer    │       │    Reporter      │
  │  Grabbing    │       │  + Anomaly   │       │  (AES-128/PBKDF2)│
  └─────────────┘       │  Detection   │       └──────────────────┘
                        └──────────────┘               │
                                              ┌────────┴────────┐
                                              ▼                 ▼
                                         REST API          .md + .enc
```

</div>

---

## Perch&egrave; Bifrost esiste

> *Un SOC non pu&ograve; difendere ci&ograve; che non pu&ograve; vedere.*

**Bifrost** chiude il terzo pilastro della suite **Asgard**: la visibilit&agrave; sulla rete.

```
  Heimdall              Mjolnir               Bifrost
  (Endpoint)            (Incident)            (Network)
     │                      │                      │
     ▼                      ▼                      ▼
  Log → Alert          Alert → Triage         Host → Ports → Anomalie
  Parser → SIEM        IOC → Report           Scan → Analyze → Encrypt
  Blocco IP            Forensics PDF          Telemetria sicura
```

---

## Architettura

<details>
<summary><b>Struttura completa del progetto</b></summary>

```
Bifrost/
├── core/
│   ├── scanner.py       TCP connect scan + service fingerprinting + banner grabbing
│   ├── analyzer.py      Live traffic snapshot + anomaly detection (psutil)
│   └── reporter.py      Markdown + AES-128 encrypted reports (Fernet/PBKDF2)
│
├── api/
│   └── server.py        FastAPI REST: scan | analyze | report | full
│
├── tests/
│   └── test_bifrost.py  8 test (scanner, analyzer, reporter, encryption)
│
├── main.py              CLI: scan | analyze | full [--password]
└── requirements.txt
```

</details>

---

## I tre moduli

### 1. Port Scanner

Scansione TCP parallela con **100 thread** identifica porte aperte, servizi e banner.

| Porta | Servizio | Cosa rileva |
|:---:|:---|:---|
| 22 | SSH | Server SSH + versione |
| 80 | HTTP | Web server + banner |
| 443 | HTTPS | TLS/SSL endpoint |
| 445 | SMB | File sharing Windows |
| 3306 | MySQL | Database server |
| 3389 | RDP | Desktop remoto |
| 5432 | PostgreSQL | Database server |
| 6379 | Redis | Cache/key-value store |
| 27017 | MongoDB | NoSQL database |

+ 17 altri servizi pre-identificati. Banner grabbing: cattura la prima risposta del servizio per identificare versione e software.

### 2. Traffic Analyzer

Cattura snapshot live delle connessioni di rete e rileva **4 tipi di anomalie**:

| Anomalia | Severit&agrave; | Cosa rileva |
|:---|:---:|:---|
| `PORT_SCAN_PATTERN` | HIGH | Un IP con 15+ connessioni verso porte diverse |
| `SUSPICIOUS_PORT` | MEDIUM | Servizi su porte note per C2/malware (4444, 6666, 31337) |
| `EXCESSIVE_TIMEWAIT` | MEDIUM | 50+ connessioni TIME_WAIT (possibile SYN flood) |
| `HIGH_CONNECTION_VOLUME` | LOW | IP con 10+ connessioni attive (movimento laterale) |

### 3. Encrypted Reporter

Genera report Markdown con tabelle formattate e, se fornita una password, salva anche una copia **cifrata AES-128** (PBKDF2 key derivation, 480k iterations) pronta per essere condivisa in modo sicuro.

---

## Quickstart

```bash
git clone https://github.com/Fioru12/Bifrost.git
cd Bifrost
pip install -r requirements.txt

# Test (8 test, tutti passano)
pytest tests/ -v

# Scansiona porte comuni su un host
python main.py scan 127.0.0.1

# Analisi traffico live
python main.py analyze

# Analisi completa + report cifrato
python main.py full --host 127.0.0.1 --password "segreto"
```

### Output della scansione

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
```

### Output dell'analisi completa

```
=================================================================
 Bifrost - Full Network Security Analysis
=================================================================
[*] Scanning 25 common ports on 127.0.0.1...
[*] Open ports found: 2
[*] Analyzing live traffic...
[*] Total connections: 244
[*] Anomalies detected: 1
  [HIGH] PORT_SCAN_PATTERN: IP 127.0.0.1 has 28 connections

[*] Generating encrypted report...
[SUCCESS] Report saved at: reports/Bifrost_Report_2026-07-23.md
=================================================================
```

---

## API

| Method | Endpoint | Descrizione |
|:---:|:---|:---|
| `GET` | `/` | Stato del servizio e lista endpoint |
| `POST` | `/api/v1/scan` | Scansiona un host (body: `{host, ports?, common?}`) |
| `GET` | `/api/v1/analyze` | Snapshot live + anomaly detection |
| `POST` | `/api/v1/report` | Genera report Markdown/cifrato |
| `GET` | `/api/v1/full?host=` | Scan + Analyze + Report in un unico call |

Swagger interattivo: `http://127.0.0.1:8000/docs`

---

## Suite Asgard

Bifrost completa la trilogia &mdash; l'intero stack di sicurezza di un SOC in tre strumenti:

```
  ┌─────────────────────────────────────────────────────────────┐
  │                    ASGARD SUITE                             │
  │                                                             │
  │   Heimdall ──────── Mjolnir ──────── Bifrost               │
  │   Endpoint IR       Incident Resp.    Network Analysis      │
  │   Log Detection     Triage/Forensics  Port Scan             │
  │   Active Response   IOC Hunting       Traffic Anomaly       │
  │   Firewall Block    Report Builder    Encrypted Telemetry   │
  │                                                             │
  └─────────────────────────────────────────────────────────────┘
```

| Modulo | Ruolo | Stack | Stato |
|:---|:---|:---|:---:|
| **Heimdall** | HIDS &middot; Rilevamento & Active Response | Python, FastAPI, SQLite, YAML | `Fatto` |
| **Mjolnir** | Incident Response &middot; Triage & Forensics | Python, psutil, Markdown | `Fatto` |
| **Bifrost** | Network Telemetry &middot; Port Analysis & Encryption | Python, FastAPI, cryptography | `Fatto` |

---

<div align="center">

*Costruito come progetto portfolio dimostrativo &mdash; pronto per essere mostrato ai recruiter e ai technical lead.*

**[Fioru12](https://github.com/Fioru12)** &middot; MIT License

</div>
