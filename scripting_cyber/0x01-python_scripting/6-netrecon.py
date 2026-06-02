#!/usr/bin/env python3
import socket
import requests
from bs4 import BeautifulSoup

try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


def dns_recon(domain):
    # Resolve IP
    try:
        ip = socket.gethostbyname(domain)
        print(f"IP Address: {ip}")
    except socket.gaierror:
        print("IP Address: Could not resolve")

    # MX records
    print("\nMX Records:")
    if DNS_AVAILABLE:
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            for answer in answers:
                print(f"  {answer.preference} {answer.exchange}")
        except dns.exception.DNSException:
            print("  No MX records found")


def web_recon(domain):
    url = f"http://{domain}"
    try:
        response = requests.get(url, timeout=5)
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


if __name__ == "__main__":
    target = input("Enter target domain: ")

    print("\n" + "=" * 50)
    print("DNS RECONNAISSANCE")
    print("=" * 50)
    dns_recon(target)

    print("\n" + "=" * 50)
    print("WEB RECONNAISSANCE")
    print("=" * 50)
    web_recon(target)

    print("\n" + "=" * 50)
    print("PORT SCANNING")
    print("=" * 50)
    port_scan(target)

    print("\n" + "=" * 50)
    print("RECONNAISSANCE COMPLETE")
    print("=" * 50)
