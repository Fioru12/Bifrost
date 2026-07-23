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

- **Multi-threaded TCP Scanner**: Progettato per essere veloce ed efficiente senza sovraccaricare la rete, identificando oltre 25 servizi standard tramite banner grabbing.
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

<div align="center">

**Sviluppato da [Fioru12](https://github.com/Fioru12)** — Parte della Suite Asgard.

</div>
