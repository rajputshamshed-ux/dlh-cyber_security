#!/bin/bash
if [ $# -ne 1 ]; then
    echo "Usage: $0 <utilisateur>"
    exit 1
fi
ps -u "$1" -o pid,vsz,rss,comm | grep -v " 0     0 "