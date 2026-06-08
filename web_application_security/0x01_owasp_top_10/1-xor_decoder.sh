#!/bin/bash

# Check input
if [ -z "$1" ]; then
    echo "Usage: $0 {xor}encoded_string"
    exit 1
fi

# Remove the {xor} prefix
encoded="${1#\{xor\}}"

# Decode Base64, convert bytes to decimal, one per line
printf "%s" "$encoded" \
    | base64 -d \
    | od -An -t u1 \
    | tr -s " " "\n" \
    | while read -r byte; do
        if [ -n "$byte" ]; then
            value=$((byte ^ 95))
            printf "\x$(printf "%x" "$value")"
        fi
    done

echo
