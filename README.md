<div align="center">

# BIFROST

### **Asgard Cybersecurity Suite — Module III**

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![Cryptography](https://img.shields.io/badge/AES--128-Fernet-yellow?style=for-the-badge)
![CI Pipeline](https://github.com/Fioru12/Bifrost/actions/workflows/pytest.yml/badge.svg?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)

</div>

> **Perché ho costruito Bifrost?**  
> Durante un'analisi di rete o un pentest rapido, spesso non serve un nmap mastodontico con mille script NSE che attirano l'attenzione dei sistemi di difesa. Serviva uno strumento di network telemetry agile, capace di scansionare le porte più comuni con banner grabbing, analizzare anomalie di traffico in tempo reale, arricchire gli IP con dati Whois/GeoIP e cifrare i report di scansione prima di salvarli su disco.

---

## Filosofia del Progetto

- **Multi-threaded TCP Scanner**: Progettato per essere veloce ed efficiente senza sovraccaricare la rete, identificando oltre 25 servizi standard tramite banner grabbing. Supporta sia IPv4 che IPv6 (la famiglia di indirizzi viene risolta dinamicamente con `getaddrinfo`, non assunta come IPv4).
- **IP Intelligence Integrata**: Non si limita a trovare un IP aperto: lo interroga per capire se appartiene a un datacenter, un VPN/proxy o un paese ad alto rischio.
- **Reporting Sicuro**: I report di rete contengono dati sensibili sui servizi esposti. Bifrost li cifra nativamente con AES-128 (Fernet) protetti da password prima di salvarli.

---

## Quick Start

```bash
# Clona e installa
git clone https://github.com/Fioru12/Bifrost.git
cd Bifrost
pip install -r requirements.txt

# Esegui scansione completa con arricchimento GeoIP
python main.py full --host 127.0.0.1 --enrich

# Esegui i test unitari
pytest -v
```

---

## API

L'API FastAPI (`api/server.py`) richiede una API key per tutti gli endpoint che eseguono scan, analisi o generazione di report (`/api/v1/scan`, `/api/v1/analyze`, `/api/v1/report`, `/api/v1/full`). L'endpoint di health-check (`/`) resta pubblico.

```bash
# Imposta la tua API key prima di avviare il server
export BIFROST_API_KEY="una-chiave-segreta-lunga-e-casuale"   # PowerShell: $env:BIFROST_API_KEY = "..."
uvicorn api.server:app --reload

# Chiamata autenticata
curl -X POST http://127.0.0.1:8000/api/v1/scan \
  -H "X-API-Key: una-chiave-segreta-lunga-e-casuale" \
  -H "Content-Type: application/json" \
  -d '{"host": "127.0.0.1", "ports": [80, 443]}'
```

Se `BIFROST_API_KEY` non è impostata, all'avvio viene generata una chiave casuale e stampata a console con un warning: usala solo per sviluppo locale, non in produzione. Le richieste senza header `X-API-Key` valido ricevono `401 Unauthorized`. Ogni richiesta di scan è inoltre limitata a un massimo di 1024 porte e l'host target deve essere un IP valido o un hostname con caratteri alfanumerici, punti e trattini (altrimenti `422 Unprocessable Entity`).

---

## Limitazioni note

- **OS fingerprinting (`discover`)**: il campo `os_guess`/`local_ttl` restituito da `LANDiscovery` **non** è un vero fingerprint remoto. Un socket TCP standard può leggere solo il TTL *in uscita* impostato dal proprio sistema operativo (`getsockopt(IP_TTL)`), non il TTL del pacchetto ricevuto dal target: leggere quest'ultimo richiederebbe un raw socket con privilegi root/Administrator (es. tramite `scapy`), cosa che Bifrost evita intenzionalmente per restare uno strumento leggero e senza privilegi elevati. Il valore va quindi trattato come un'euristica grezza e inaffidabile (marcata `os_guess_reliable: False` nel risultato), mai come una rilevazione OS affidabile.
- **Banner grabbing**: per la maggior parte dei servizi (SSH, FTP, SMTP, ecc.) il banner grabbing resta puramente passivo, in attesa che il servizio parli per primo. Per le porte HTTP più comuni (80, 8080, 8000), se non arriva nulla entro il timeout, viene inviata una probe attiva minima (`HEAD / HTTP/1.0`) e la lettura viene ritentata una volta. Gli altri protocolli non hanno probe attive dedicate.

---

<div align="center">

**Sviluppato da [Fioru12](https://github.com/Fioru12)** — Parte della Suite Asgard.

</div>
