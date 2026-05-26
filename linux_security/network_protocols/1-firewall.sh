#!/bin/bash
iptables -A INPUT -p tcp --dport ssh -j ACCEPT
iptables -A OUTPUT -p tcp --dport ssh -j ACCEPT
