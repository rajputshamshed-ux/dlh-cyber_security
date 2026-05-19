#!/bin/bash
john --wordlist=/usr/share/wordlists/rockyou.txt "$1"
john --show "$1" | tail -n1 | cut -d ':' -f2 | cut -d ' ' -f1 > 5-password.txt