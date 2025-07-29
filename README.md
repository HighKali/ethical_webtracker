# EthicalWebTracker

**EthicalWebTracker** è uno strumento per il monitoraggio etico e legale del traffico web aziendale, ottimizzato per Kali Linux e distribuzioni offensive/security.  
Permette di loggare, analizzare e generare report sulle richieste HTTP/S, con geolocalizzazione, user agent, IP, ASN, e detection di eventi anomali.

---

## Requisiti

- Kali Linux (o altra Linux con Python 3.8+)
- python3-pip
- mitmproxy (opzionale per sniffing proxy HTTP/S)
- tcpdump/wireshark (opzionali)
- Python package: requests

Installa tutto con:
```bash
sudo apt update
sudo apt install python3 python3-pip mitmproxy tcpdump wireshark
pip3 install -r requirements.txt
```

---

## Utilizzo

### Verifica requisiti
```bash
python3 ethical_webtracker.py --check
```

### Demo logging manuale (simulazione)
```bash
python3 ethical_webtracker.py --demo
```

### Logging di un evento (manuale o da script/proxy web)
```bash
python3 ethical_webtracker.py --log '{"client_ip": "2.196.16.26", "method": "GET", "host": "example.com", "url": "/dashboard", "user_agent": "Mozilla/5.0 ..."}'
# oppure
python3 ethical_webtracker.py --log evento.json
```

### Analisi dei log e report
```bash
python3 ethical_webtracker.py --analyze
```

---

## Integrazione

- Integra il logging con proxy Python, reverse proxy, gateway, server web (Flask, Django, mitmproxy).
- Automatizza l’analisi schedulando con cron o systemd.
- Log e report generati nella cartella `./logs`.

---

## Privacy & Legal

- Usare solo su reti/dispositivi aziendali propri e con consenso.
- Conforme GDPR: limita dati sensibili, retention e maschera IP se necessario.
- Ideale per auditing, compliance, cyber security, SOC, blue team.

---

## Magia extra

- Geolocalizzazione, ASN, ISP, timezone, ZIP in automatico
- Analisi automatica di anomalie (accessi fuori paese)
- Pronto per automazioni e dashboard future!

---
