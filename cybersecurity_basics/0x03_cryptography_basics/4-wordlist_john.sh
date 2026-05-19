#!/bin/bash
cd /tmp/john/run
./john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt /workspaces/dlh-cyber_security/cybersecurity_basics/0x03_cryptography_basics/hash.txt
./john --show /workspaces/dlh-cyber_security/cybersecurity_basics/0x03_cryptography_basics/hash.txt | grep -v "password hash" | cut -d ':' -f2 | cut -d ' ' -f1 > /workspaces/dlh-cyber_security/cybersecurity_basics/0x03_cryptography_basics/4-password.txt
cat /workspaces/dlh-cyber_security/cybersecurity_basics/0x03_cryptography_basics/4-password.txt
