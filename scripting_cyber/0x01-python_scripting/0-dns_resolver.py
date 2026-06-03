#!/usr/bin/env python3

import socket

def resolve_domain_to_ipv4(domain_name):
    try:
        # Résolution DNS → IPv4
        ip_address = socket.gethostbyname(domain_name)
        return ip_address

    except socket.gaierror:
        # Si le domaine n'existe pas
        return None

    except Exception as e:
        # Autres erreurs
        return str(e)
