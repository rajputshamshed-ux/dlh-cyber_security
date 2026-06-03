#!/usr/bin/env python3
"""Network reconnaissance test script"""

import socket
import requests
from bs4 import BeautifulSoup

try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

from urllib.parse import urlparse


# ✅ Liste des sites à tester
test_urls = [
    "https://www.google.com",
    "https://github.com",
    "https://example.com",
    "https://holbertonschool.com",
    "https://this-site-does-not-exist.com"
]


def dns_recon(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"IP Address: {ip}")
    except socket.gaierror:
        print("IP Address: Could not resolve")

    print("\nMX Records:")
    if DNS_AVAILABLE:
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            for answer in answers:
                print(f"  {answer.preference} {answer.exchange}")
        except dns.exception.DNSException:
            print("  No MX records found")


def web_recon(domain):
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        print(f"\nStatus Code: {response.status_code}")

        print("\nImportant Headers:")
        for header in ['Server', 'Content-Type']:
            if header in response.headers:
                print(f"  {header}: {response.headers[header]}")

        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all('a')
        print(f"\nTotal Links Found: {len(links)}")

    except requests.exceptions.RequestException as e:
        print(f"Web recon failed: {e}")


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
        except socket.error:
            pass


# ✅ Lancement automatique
if __name__ == "__main__":
    for url in test_urls:
        host = urlparse(url).netloc

        print("\n" + "=" * 50)
        print(f"🌐 Target: {host}")
        print("=" * 50)

        print("\nDNS RECONNAISSANCE")
        dns_recon(host)

        print("\nWEB RECONNAISSANCE")
        web_recon(host)

        print("\nPORT SCANNING")
        port_scan(host)

    print("\n" + "=" * 50)
    print("RECONNAISSANCE COMPLETE")
    print("=" * 50)
