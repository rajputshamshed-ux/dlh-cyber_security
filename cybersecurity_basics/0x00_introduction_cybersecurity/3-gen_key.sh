#!/bin/bash

ls
echo "🔐 Génération d'une clé SSH RSA 4096"

# Nom de la clé (tu peux changer)
NOM_CLE="ma_cle_rsa"

# La commande magique
ssh-keygen -t rsa -b 4096 -f "$NOM_CLE" -N ""

# Message de fin
echo "✅ Clé générée avec succès !"
echo "📁 Clé privée : $NOM_CLE"
echo "📁 Clé publique : $NOM_CLE.pub"

# Affiche les fichiers créés
ls -l "$NOM_CLE"*