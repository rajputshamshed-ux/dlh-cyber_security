#!/bin/bash

# On prend le mot de passe que tu as donné
password="$1"

# On utilise la formule magique MD5
hash=$(echo -n "$password" | md5sum)

# On nettoie un peu (enlève le " -" à la fin)
hash=${hash%% *}

# On écrit le résultat dans le fichier
echo "$hash" > 2_hash.txt