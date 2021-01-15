:: Copyright 2020 NXP
@echo "Script to generate rsa private keys - in 2048, 3072 and 4096 bit lengths"

openssl genrsa -out private_rsa2048_0.pem 2048
openssl genrsa -out private_rsa2048_1.pem 2048
openssl genrsa -out private_rsa2048_2.pem 2048
openssl genrsa -out private_rsa2048_3.pem 2048
::openssl genrsa -out private_rsa3072.pem 3072
::openssl genrsa -out private_rsa4096.pem 4096
