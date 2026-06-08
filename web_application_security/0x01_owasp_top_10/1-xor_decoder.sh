#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: $0 {xor}HASH"
  exit 1
fi

echo "$1" | sed 's/{xor}//' | base64 -d | perl -pe '$_ ^= "\x5A" x length($_)'
