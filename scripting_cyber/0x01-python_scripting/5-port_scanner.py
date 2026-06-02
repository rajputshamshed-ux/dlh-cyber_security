#!/usr/bin/env python3

import socket

def check_port(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        
       host, port))
        
        s.close()

        return result == 0

    except Exception:
        return False
