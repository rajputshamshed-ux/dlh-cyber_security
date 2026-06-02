#!/usr/bin/env python3
"""Module docstring"""

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


# ✅ Liste des sites
test_urls = [
    "https://www.google.com",
    "https://github.com",
    "https://example.com",
    "https://holbertonschool.com",
    "https://this-site-does-not-exist.com"
]

ports = [80, 443]


if __name__ == "__main__":
    import sys

    # ✅ MODE 1 : ligne de commande
    if len(sys.argv) == 3:
        host = sys.argv[1]
        port = int(sys.argv[2])

        status = "OPEN" if check_port(host, port) else "CLOSED"
        print(f"Port {port} on {host}: {status}")

    # ✅ MODE 2 : scan automatique
    else:
        print("\n🔎 Scan des sites...\n")

        for url in test_urls:
            parsed = urlparse(url)
            host = parsed.netloc

            print(f"\n🌐 Test de {host}")

            for port in ports:
                status = "OPEN" if check_port(host, port) else "CLOSED"
                print(f"Port {port}: {status}")
