#!/bin/bash
# Script: 10-generate_csr.sh
# Usage: ./10-generate_csr.sh
# Automates key generation and CSR creation for MedDefense patient portal

# Exit on error
set -e

echo "=========================================="
echo "MedDefense - CSR Generation Script"
echo "=========================================="
echo ""

# Step 1: Generate ECC P-256 key
echo "[1] Generating ECC P-256 private key..."
openssl ecparam -genkey -name prime256v1 -out portal_key.pem
echo "    Key saved to: portal_key.pem"
echo ""

# Step 2: Create OpenSSL configuration
echo "[2] Creating OpenSSL configuration..."
cat > openssl.cnf << 'EOF'
[ req ]
default_bits = 2048
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[ req_distinguished_name ]
countryName = US
stateOrProvinceName = California
localityName = San Francisco
organizationName = MedDefense Health Systems
organizationalUnitName = Information Technology
commonName = portal.meddefense.local

[ v3_req ]
keyUsage = keyEncipherment, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = portal.meddefense.local
DNS.2 = meddefense.local
DNS.3 = www.meddefense.local
DNS.4 = patient.meddefense.local
EOF
echo "    Config saved to: openssl.cnf"
echo ""

# Step 3: Generate CSR
echo "[3] Generating CSR..."
openssl req -new -key portal_key.pem -out portal.csr -config openssl.cnf
echo "    CSR saved to: portal.csr"
echo ""

# Step 4: Display CSR
echo "[4] CSR Contents:"
echo "------------------------------------------"
openssl req -text -noout -in portal.csr
echo "------------------------------------------"
echo ""

# Step 5: Verification
echo "[5] Verification:"
echo "    Key file: portal_key.pem"
echo "    CSR file: portal.csr"
echo "    Config: openssl.cnf"
echo ""
echo "=========================================="
echo "SUCCESS: CSR generated successfully!"
echo "To view CSR: openssl req -text -noout -in portal.csr"
echo "=========================================="
