#!/bin/bash                    # 1. Dis à l'ordi : "Parle en bash"
# Autoriser uniquement...     # 2. Petit rappel pour toi (ignoré)
sudo iptables -A INPUT \       # 3. Ajoute une règle pour connexions entrantes
       -p tcp \                #    - protocole TCP
       --dport 80 \            #    - porte destination 80
       -j ACCEPT               #    - laisse passer
sudo ip6tables -A INPUT \      # 4. La même chose pour les nouvelles adresses (IPv6)
       -p tcp \
       --dport 80 \
       -j ACCEPT
