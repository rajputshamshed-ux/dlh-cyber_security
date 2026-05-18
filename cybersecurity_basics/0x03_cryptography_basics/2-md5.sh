#!/bin/bash
password="$1"
echo -n "$password" | md5sum | cut -d' ' -f1 > 2_hash.txt
echo "" >> 2_hash.txt