#!/bin/bash
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT && sudo ip6tables -A INPUT -p tcp --dport 80 -j ACCEPT