#!/bin/bash
grep "^ID=" /etc/os-release | cut -d'=' -f2 | tr -d '"' | sed 's/kali/Kali/'
