:: Copyright 2020 NXP
@echo "Script to generate private keys for MIB with 2048, 3073 and 4096 bits length"

set OPENSSL_CONF=./openssl.cnf

openssl req -new -key private_rsa2048_0.pem -out selfsign2048_v3_0.csr -extensions v3_ca
openssl x509 -req -days 7300 -in selfsign2048_v3_0.csr -signkey private_rsa2048_0.pem -sha256 -outform der -out selfsign_2048_v3_0.der.crt -extfile v3_noca.ext -set_serial 0x3cc30000babadeda

openssl req -new -key private_rsa2048_1.pem -out selfsign2048_v3_1.csr -extensions v3_ca
openssl x509 -req -days 7300 -in selfsign2048_v3_1.csr -signkey private_rsa2048_1.pem -sha256 -outform der -out selfsign_2048_v3_1.der.crt -extfile v3_noca.ext -set_serial 0x3cc30000babadeda

openssl req -new -key private_rsa2048_2.pem -out selfsign2048_v3_2.csr -extensions v3_ca
openssl x509 -req -days 7300 -in selfsign2048_v3_2.csr -signkey private_rsa2048_2.pem -sha256 -outform der -out selfsign_2048_v3_2.der.crt -extfile v3_noca.ext -set_serial 0x3cc30000babadeda

openssl req -new -key private_rsa2048_3.pem -out selfsign2048_v3_3.csr -extensions v3_ca
openssl x509 -req -days 7300 -in selfsign2048_v3_3.csr -signkey private_rsa2048_3.pem -sha256 -outform der -out selfsign_2048_v3_3.der.crt -extfile v3_noca.ext -set_serial 0x3cc30000babadeda

::openssl req -new -key private_rsa3072.pem -out selfsign3072_v3.csr -extensions v3_ca
::openssl x509 -req -days 7300 -in selfsign3072_v3.csr -signkey private_rsa3072.pem -sha256 -outform der -out selfsign_3072_v3.der.crt -extfile v3_noca.ext -set_serial 0x3cc30000babadeda


::openssl req -new -key private_rsa4096.pem -out selfsign4096_v3.csr -extensions v3_ca
::openssl x509 -req -days 7300 -in selfsign4096_v3.csr -signkey private_rsa4096.pem -sha256 -outform der -out selfsign_4096_v3.der.crt -extfile v3_noca.ext -set_serial 0x3cc30000babadeda
