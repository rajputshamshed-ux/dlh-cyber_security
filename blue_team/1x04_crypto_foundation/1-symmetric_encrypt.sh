#!/bin/bash
# Script: 1-symmetric_encrypt.sh
# Usage: ./1-symmetric_encrypt.sh <input_file> <output_file> <mode>

if [ $# -ne 3 ]; then
    echo "Usage: $0 <input_file> <output_file> <mode>"
    echo "Modes: cbc or gcm"
    exit 1
fi

INPUT=$1
OUTPUT=$2
MODE=$3

if [ ! -f "$INPUT" ]; then
    echo "Error: File '$INPUT' not found"
    exit 1
fi

if [ "$MODE" = "cbc" ]; then
    openssl enc -aes-256-cbc -in "$INPUT" -out "$OUTPUT"
elif [ "$MODE" = "gcm" ]; then
    openssl enc -aes-256-gcm -in "$INPUT" -out "$OUTPUT"
else
    echo "Error: Invalid mode. Use 'cbc' or 'gcm'"
    exit 1
fi

if [ $? -eq 0 ]; then
    echo "Success: $INPUT encrypted to $OUTPUT"
else
    echo "Error: Encryption failed"
    exit 1
fi
