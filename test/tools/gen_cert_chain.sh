#!/bin/bash
set -euo pipefail

dir="$1"

umask 077

function new_ca {
    # Create $1.key $1.crt
    openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -out "$1".key
    # Self sign
    openssl req -x509 -key "$1".key -new -days 90 -out "$1".crt -subj "/CN=DO NOT TRUST"
}

function new_key {
    # For client or server
    # Create $1.key $1.csr
    openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -out "$1".key
    openssl req -key "$1".key -new -out "$1".csr -subj "/CN=localhost"
}

function sign_with {
    # $1:ca $2:server/client
    openssl x509 -req -CA "$1".crt -CAkey "$1".key -CAcreateserial -in "$2".csr -days 90 -out "$2".crt -sha256
}

[ -d "${dir}" ] || mkdir -p "${dir}"

# Create server cert chain
new_ca "${dir}/ca-s"
new_key "${dir}/server"
sign_with "${dir}/ca-s" "${dir}/server"
cat "${dir}/server".{key,crt} > "${dir}/server".pem

# Create client cert chain
new_ca "${dir}/ca-c"
new_key "${dir}/client"
sign_with "${dir}/ca-c" "${dir}/client"
cat "${dir}/client".{key,crt} > "${dir}/client".pem

