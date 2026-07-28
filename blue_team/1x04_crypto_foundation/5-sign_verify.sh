#!/bin/bash
# Script: 5-sign_verify.sh
# Usage: 
#   Sign:   ./5-sign_verify.sh sign <file> <private_key>
#   Verify: ./5-sign_verify.sh verify <file> <signature> <public_key>

if [ $# -lt 2 ]; then
    echo "Usage:"
    echo "  Sign:   $0 sign <file> <private_key>"
    echo "  Verify: $0 verify <file> <signature> <public_key>"
    exit 1
fi

MODE=$1

if [ "$MODE" = "sign" ]; then
    if [ $# -ne 3 ]; then
        echo "Usage: $0 sign <file> <private_key>"
        exit 1
    fi
    FILE=$2
    KEY=$3
    SIG="${FILE}.sig"
    
    if [ ! -f "$FILE" ]; then
        echo "Error: File '$FILE' not found"
        exit 1
    fi
    if [ ! -f "$KEY" ]; then
        echo "Error: Key '$KEY' not found"
        exit 1
    fi
    
    openssl dgst -sha256 -sign "$KEY" -out "$SIG" "$FILE"
    
    if [ $? -eq 0 ]; then
        echo "SUCCESS: Signed $FILE -> $SIG"
    else
        echo "ERROR: Signing failed"
        exit 1
    fi

elif [ "$MODE" = "verify" ]; then
    if [ $# -ne 4 ]; then
        echo "Usage: $0 verify <file> <signature> <public_key>"
        exit 1
    fi
    FILE=$2
    SIG=$3
    KEY=$4
    
    if [ ! -f "$FILE" ]; then
        echo "Error: File '$FILE' not found"
        exit 1
    fi
    if [ ! -f "$SIG" ]; then
        echo "Error: Signature '$SIG' not found"
        exit 1
    fi
    if [ ! -f "$KEY" ]; then
        echo "Error: Public key '$KEY' not found"
        exit 1
    fi
    
    openssl dgst -sha256 -verify "$KEY" -signature "$SIG" "$FILE"
    
    if [ $? -eq 0 ]; then
        echo "VERIFICATION: OK - Signature is valid"
    else
        echo "VERIFICATION: FAILED - Signature is NOT valid"
        exit 1
    fi

else
    echo "Error: Invalid mode. Use 'sign' or 'verify'"
    exit 1
fi
