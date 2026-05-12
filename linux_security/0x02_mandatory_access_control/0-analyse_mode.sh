#!/bin/bash
echo "SELinux status:                 $(getenforce | tr '[:upper:]' '[:lower:]')"

