#!/bin/bah
sudo iptables -A  INPUT -p tcp --dport 22 - j ACCEPT
sudo iptables -A OUTPUT -p tcp --dport 22 - j ACCEPT
