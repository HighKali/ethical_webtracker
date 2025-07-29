#!/usr/bin/env python3
"""
EthicalWebTracker
Monitoraggio, logging e analisi del traffico web HTTP/S in uscita, ideale per auditing aziendale,
cyber security e compliance. Compatibile con Kali Linux, pronto per essere usato come listener per proxy,
reverse proxy, gateway o integrazione con server web.

Requisiti:
- Kali Linux (o distribuzione Linux con Python 3.8+)
- python3-pip
- mitmproxy (per sniffing proxy HTTP/S, opzionale)
- tcpdump/wireshark (per network capture, opzionale)
- Dipendenze Python: vedi requirements.txt

Installazione (Kali):
    sudo apt update
    sudo apt install python3 python3-pip mitmproxy tcpdump wireshark
    pip3 install -r requirements.txt

Avvio (Standalone demo):
    python3 ethical_webtracker.py

Configurazione avanzata:
- Puoi integrarlo in un proxy Python (Flask, mitmproxy, etc) per logging real-time.
- Puoi schedulare l’analisi/report con cron o systemd.
"""

import json
import requests
from datetime import datetime
import os
import sys
import socket

# ====== CONFIGURAZIONI ======
LOG_FOLDER = "./logs"
os.makedirs(LOG_FOLDER, exist_ok=True)
LOG_FILE = os.path.join(LOG_FOLDER, "webtracker_log.jsonl")

# ====== REQUISITI NETWORK E SISTEMA ======
def check_prerequisites():
    print("[*] Verifica prerequisiti di sistema per Kali Linux...")
    essentials = [
        ("python3", "Python 3"),
        ("pip3", "pip3"),
        ("mitmproxy", "mitmproxy (opzionale, per proxy sniffing)"),
        ("tcpdump", "tcpdump (opzionale, per packet capture)"),
        ("wireshark", "wireshark (opzionale, per analisi avanzata)"),
    ]
    path_missing = []
    for binary, descr in essentials:
        if not shutil_which(binary):
            path_missing.append((binary, descr))
    if path_missing:
        print("[!] Mancano alcuni prerequisiti:")
        for binary, descr in path_missing:
            print(f"    - {descr} ({binary})")
        print("    Installa con: sudo apt install " + ' '.join([b for b, _ in path_missing]))
    else:
        print("[+] Tutti i prerequisiti di sistema sono presenti.")

def shutil_which(cmd):
    from shutil import which
    return which(cmd) is not None

# ====== GEOLOCALIZZAZIONE IP ======
def geolocate_ip(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,org,as,query,zip,timezone")
        data = r.json()
        if data.get("status") == "success":
            return {
                "country": data.get("country"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "zip": data.get("zip"),
                "timezone": data.get("timezone"),
                "org": data.get("org"),
                "as": data.get("as"),
                "ip": data.get("query")
            }
        return {}
    except Exception:
        return {}

# ====== LOGGING ======
def log_request(event):
    ip = event.get('client_ip')
    geo = geolocate_ip(ip)
    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "client_ip": ip,
        "method": event.get('method'),
        "host": event.get('host'),
        "url": event.get('url'),
        "user_agent": event.get('user_agent'),
        "geo": geo
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
    print(json.dumps(log_entry, ensure_ascii=False, indent=2))

# ====== ANALISI E REPORT ======
def analyze_logs():
    print("\n[*] Analisi dei log raccolti:")
    from collections import Counter, defaultdict
    if not os.path.isfile(LOG_FILE):
        print("Nessun log trovato.")
        return
    user_agents = Counter()
    countries = Counter()
    hosts = Counter()
    suspicious = []
    with open(LOG_FILE) as f:
        for line in f:
            try:
                entry = json.loads(line)
                user_agents[entry.get("user_agent", "")] += 1
                geo = entry.get("geo", {})
                countries[geo.get("country", "N/A")] += 1
                hosts[entry.get("host", "")] += 1
                # Esempio semplice di pattern sospetti
                if geo.get("country") not in ["Italia", "San Marino", "Vaticano"] and geo.get("country") != "N/A":
                    suspicious.append(entry)
            except Exception:
                continue
    print(f"\nTop User Agents:\n{user_agents.most_common(5)}")
    print(f"\nTop Paesi di accesso:\n{countries.most_common(5)}")
    print(f"\nTop Host richiesti:\n{hosts.most_common(5)}")
    if suspicious:
        print(f"\n[!] Accessi da paesi non ITA/SM/VA (possibili anomalie): {len(suspicious)}")
        for e in suspicious[:3]:
            print(json.dumps(e, indent=2))
    else:
        print("\nNessun accesso sospetto rilevato.")

# ====== DEMO: Simulazione logging manuale ======
def demo():
    print("\n[*] Demo logging. Puoi integrare il codice con proxy/server web reali per loggare traffico reale.")
    sample_events = [
        {
            "client_ip": "2.196.16.26",
            "method": "GET",
            "host": "example.com",
            "url": "/dashboard",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, come Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0"
        },
        {
            "client_ip": "185.199.111.153",
            "method": "POST",
            "host": "github.com",
            "url": "/login",
            "user_agent": "curl/7.88.1"
        }
    ]
    for ev in sample_events:
        log_request(ev)
    print("\n[*] Fine demo logging.")

# ====== MAIN ======
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="EthicalWebTracker - Monitoraggio e logging web etico aziendale (Kali Ready)")
    parser.add_argument("--check", action="store_true", help="Verifica prerequisiti di sistema")
    parser.add_argument("--demo", action="store_true", help="Esegui demo logging")
    parser.add_argument("--analyze", action="store_true", help="Analizza i log raccolti")
    parser.add_argument("--log", type=str, help="Logga un evento HTTP (JSON come stringa o path file)")
    args = parser.parse_args()

    if args.check:
        check_prerequisites()
        sys.exit(0)
    if args.demo:
        demo()
    if args.analyze:
        analyze_logs()
    if args.log:
        try:
            if os.path.isfile(args.log):
                with open(args.log) as f:
                    event = json.load(f)
            else:
                event = json.loads(args.log)
            log_request(event)
        except Exception as e:
            print(f"Errore log: {e}")
