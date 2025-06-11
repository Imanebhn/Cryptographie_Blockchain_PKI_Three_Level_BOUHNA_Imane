#!/bin/bash

# === Initialisation des dossiers PKI ===
mkdir -p pki-three-level/{root-ca,intermediate-ca,leaf-certs}

# === Initialisation Root CA ===
cd pki-three-level/root-ca
mkdir -p certs crl newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial

# openssl.cnf pour root (simple exemple minimal)
cat > openssl.cnf <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = .
certs             = \$dir/certs
crl_dir           = \$dir/crl
database          = \$dir/index.txt
new_certs_dir     = \$dir/newcerts
certificate       = \$dir/certs/root.cert.pem
serial            = \$dir/serial
private_key       = \$dir/private/root.key.pem
default_days      = 3650
default_md        = sha256
policy            = policy_strict

[ policy_strict ]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
commonName              = supplied

[ req ]
distinguished_name = req_distinguished_name
prompt = no

[ req_distinguished_name ]
C  = FR
ST = France
O  = MyRootCA
CN = My Root CA
EOF

# Génération de la clé et certificat Root
openssl genrsa -aes256 -out private/root.key.pem 4096
chmod 400 private/root.key.pem
openssl req -config openssl.cnf -key private/root.key.pem -new -x509 \
    -days 3650 -sha256 -extensions v3_ca -out certs/root.cert.pem

# === Initialisation Intermediate CA ===
cd ../intermediate-ca
mkdir -p certs crl csr newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial

# openssl.cnf pour intermediate
cat > openssl.cnf <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = .
certs             = \$dir/certs
crl_dir           = \$dir/crl
database          = \$dir/index.txt
new_certs_dir     = \$dir/newcerts
certificate       = \$dir/certs/intermediate.cert.pem
serial            = \$dir/serial
private_key       = \$dir/private/intermediate.key.pem
default_days      = 1000
default_md        = sha256
policy            = policy_loose

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
organizationName        = optional
commonName              = supplied

[ req ]
distinguished_name = req_distinguished_name
prompt = no

[ req_distinguished_name ]
C  = FR
ST = France
O  = MyIntermediateCA
CN = Intermediate CA
EOF

# Génération clé + CSR pour Intermediate
openssl genrsa -aes256 -out private/intermediate.key.pem 4096
chmod 400 private/intermediate.key.pem
openssl req -config openssl.cnf -new -sha256 \
    -key private/intermediate.key.pem -out csr/intermediate.csr.pem

# Signature par Root
cd ../root-ca
openssl ca -config openssl.cnf \
    -in ../intermediate-ca/csr/intermediate.csr.pem \
    -out ../intermediate-ca/certs/intermediate.cert.pem \
    -extensions v3_intermediate_ca -days 1000 -notext -md sha256

# Créer chaîne de certificats
cat ../intermediate-ca/certs/intermediate.cert.pem certs/root.cert.pem \
    > ../intermediate-ca/certs/ca-chain.cert.pem

cd ../../
