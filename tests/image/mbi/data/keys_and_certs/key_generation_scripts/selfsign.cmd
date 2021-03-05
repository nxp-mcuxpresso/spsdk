:: Copyright 2020 NXP
@echo "Script to generate private keys for MIB with 2048, 3073 and 4096 bits length"

set OPENSSL_CONF=./openssl.cnf

openssl req -new -key private_rsa2048.pem -out selfsign2048_v3.csr -extensions v3_ca
openssl x509 -req -days 7300 -in selfsign_2048_v3.csr -signkey private_rsa2048.pem -sha256 -outform der -out selfsign_2048_v3.der.crt -extfile v3_noca.ext -set_serial 0x3cc30000babadeda


openssl req -new -key private_rsa3072.pem -out selfsign3072_v3.csr -extensions v3_ca
openssl x509 -req -days 7300 -in selfsign_3072_v3.csr -signkey private_rsa3072.pem -sha256 -outform der -out selfsign_3072_v3.der.crt -extfile v3_noca.ext -set_serial 0x3cc30000babadeda


openssl req -new -key private_rsa4096.pem -out selfsign4096_v3.csr -extensions v3_ca
openssl x509 -req -days 7300 -in selfsign_4096_v3.csr -signkey private_rsa4096.pem -sha256 -outform der -out selfsign_4096_v3.der.crt -extfile v3_noca.ext -set_serial 0x3cc30000babadeda
