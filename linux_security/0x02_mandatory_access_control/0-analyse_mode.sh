#!/bin/bash
echo "SELinux status:                 $(sestatus | grep 'Current mode' | awk '{print $3}' | tr '[:upper:]' '[:lower:]')"