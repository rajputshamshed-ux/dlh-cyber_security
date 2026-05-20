# Étape 1 : choisir un mot de passe
password="chocolat"

# Étape 2 : générer son hash SHA-256
hash=$(echo -n "$password" | sha256sum | cut -d' ' -f1)

# Étape 3 : écrire le hash dans crack.txt
echo "$hash" > crack.txt