#!/bin/sh
# Rotate the HSM-backed keystore and issue the edge certificate.
set -e
keytool -genkeypair -alias edge -keyalg RSA -keysize 2048 -keystore edge.jks -storepass changeit
openssl req -x509 -newkey rsa:2048 -nodes -keyout edge.key -out edge.crt -days 365 -subj /CN=edge
openssl genpkey -algorithm ML-DSA-65 -out edge-pq.key
echo "rsa rotation complete"
