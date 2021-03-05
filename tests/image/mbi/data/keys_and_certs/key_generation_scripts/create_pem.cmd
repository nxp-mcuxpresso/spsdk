:: Copyright 2020 NXP
@echo "Script to generate public certificates in DER format for MIB certificate block - in 2048, 3072 and 4096 bit lengths"

openssl genrsa -out private_rsa2048.pem 2048
openssl genrsa -out private_rsa3072.pem 3072
openssl genrsa -out private_rsa4096.pem 4096
