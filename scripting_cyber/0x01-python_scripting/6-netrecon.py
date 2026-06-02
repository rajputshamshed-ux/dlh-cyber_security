#!/usr/bin/env python3
"""Network Reconnaissance Module"""

import socket
import urllib.request
from html.parser import HTMLParser


# ✅ Parser pour compter les liens HTML
class LinkCounter(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = 0

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.links += 1


# ✅ DNS RECON
def dns_recon(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"IP Address: {ip}")
    except Exception:
        print("Could not resolve IP address")

    try:
        # MX (méthode simple via getaddrinfo fallback)
        print("\nMX Records:")
        mx_records = socket.getaddrinfo(f"mail.{domain}", 0)
        if mx_records:
            print(f"  mail.{domain}")
    except Exception:
        print("  Could not retrieve MX records")


# ✅ WEB RECON
def web_recon(domain):
    try:
        url = f"http://{domain}"
        response = urllib.request.urlopen(url, timeout=3)

        print(f"\nStatus Code: {response.getcode()}")

        print("\nImportant Headers:")
        headers = response.headers

        for key in ["Server", "Content-Type"]:
            if key in headers:
                print(f"  {key}: {headers[key]}")

        # Lire HTML
        html = response.read().decode(errors="ignore")

        parser = LinkCounter()
        parser.feed(html)

        print(f"\nTotal Links Found: {parser.links}")

    except Exception:
        print("Web recon failed")


# ✅ PORT SCAN
def port_scan(domain):
    ports = [80, 443]

    print(f"\nScanning common ports on {domain}...")
    print("Open ports:")

    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)

            result = s.connect_ex((domain, port))
            s.close()

            if result == 0:
                print(f"  Port {port}: OPEN")

        except Exception:
            continue
