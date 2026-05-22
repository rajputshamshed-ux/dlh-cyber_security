#!/bin/bash
hashcat --show -m 0 "$1" | cut -d ':' -f2 > 7-password.txt
