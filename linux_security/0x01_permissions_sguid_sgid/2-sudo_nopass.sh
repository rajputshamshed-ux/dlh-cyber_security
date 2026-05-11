#!/bin/bash
echo $1 ALL=(ALL) NOPASSWD:ALL >> /etc/sudoers.d/$1 &&chmod 440 /etc/sudoers.d/$1