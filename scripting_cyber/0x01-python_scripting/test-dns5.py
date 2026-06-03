#!/usr/bin/env python3
"""Port scanner simple - mode automatique"""

import socket
from urllib.parse import urlparse


def check_port(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)

        result = s.connect_ex((host, port))
        s.close()

        return result == 0
    except socket.error:
        return False


# ✅ Liste des sites à tester
test_urls = [
    "https://www.google.com",
    "https://github.com",
    "https://example.com",
    "https://holbertonschool.com",
    "https://this-site-does-not-exist.com"
]

# ✅ Ports à tester (web)
ports = [80, 443]


if __name__ == "__main__":

    print("\n🔎 Scan automatique des sites...\n")

    for url in test_urls:
        parsed = urlparse(url)
        host = parsed.netloc

        print(f"\n🌐 Test de {host}")

        for port in ports:
            if check_port(host, port):
                print(f"✅ Port {port} ouvert")
            else:
                print(f"❌ Port {port} fermé ou inaccessible")
