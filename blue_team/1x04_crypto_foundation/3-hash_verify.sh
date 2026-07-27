#!/bin/bash
# Script: 3-hash_verify.sh
# Usage: ./3-hash_verify.sh <file> <expected_hash>
# Returns: 0 if integrity OK, 1 if failed

# Vérifier qu'il y a 2 arguments
if [ $# -ne 2 ]; then
    echo "Usage: $0 <file> <expected_hash>"
    exit 1
fi

FILE=$1
EXPECTED=$2

# Vérifier que le fichier existe
if [ ! -f "$FILE" ]; then
    echo "Error: File '$FILE' not found"
    exit 1
fi

# Calculer le hash SHA-256 du fichier
HASH=$(sha256sum "$FILE" | awk '{print $1}')

# Comparer le hash calculé avec le hash attendu
if [ "$HASH" = "$EXPECTED" ]; then
    echo "INTEGRITY OK"
    exit 0
else
    echo "INTEGRITY FAILED - expected $EXPECTED got $HASH"
    exit 1
fi
