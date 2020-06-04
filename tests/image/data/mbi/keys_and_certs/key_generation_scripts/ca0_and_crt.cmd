:: Copyright 2020 NXP
set OPENSSL_CONF=./openssl.cnf

::------Two certs:
::self-signed certificate
openssl req -new -key ca0_privatekey_rsa2048.pem -out ca0_v3.csr -extensions v3_ca
openssl x509 -req -days 7300 -in ca0_v3.csr -signkey ca0_privatekey_rsa2048.pem -set_serial 0x1 -sha256 -outform der -out ca0_v3.der.crt -extfile v3_ca.ext
openssl x509 -req -days 7300 -in ca0_v3.csr -signkey ca0_privatekey_rsa2048.pem -set_serial 0x1 -sha256              -out ca0_v3.pem.crt -extfile v3_ca.ext

::chain certificate signed by private key of first certificate
openssl req -new -key crt_privatekey_rsa2048.pem -out crt_v3.csr -extensions v3_ca
openssl x509 -req -days 7300 -in crt_v3.csr -CA ca0_v3.pem.crt -CAkey ca0_privatekey_rsa2048.pem -set_serial 0x3cc30000babadeda -sha256 -outform der -out crt_v3.der.crt -extfile v3_noca.ext

@pause

::------Three certs:
::self-signed certificate (note: this is same as above)
::openssl req -new -key ca0_privatekey_rsa2048.pem -out ca0_v3.csr -extensions v3_ca
::openssl x509 -req -days 7300 -in ca0_v3.csr -signkey ca0_privatekey_rsa2048.pem -set_serial 0x1 -sha256 -outform der -out ca0_v3.der.crt -extfile v3_ca.ext
::openssl x509 -req -days 7300 -in ca0_v3.csr -signkey ca0_privatekey_rsa2048.pem -set_serial 0x1 -sha256              -out ca0_v3.pem.crt -extfile v3_ca.ext

::first chain certificate signed by private key of first certificate
openssl req -new -key crt_privatekey_rsa2048.pem -out crt_v3.csr -extensions v3_ca
openssl x509 -req -days 7300 -in crt_v3.csr -CA ca0_v3.pem.crt -CAkey ca0_privatekey_rsa2048.pem -set_serial 0x2 -sha256 -outform der -out ch3_crt_v3.der.crt -extfile v3_ca.ext
openssl x509 -req -days 7300 -in crt_v3.csr -CA ca0_v3.pem.crt -CAkey ca0_privatekey_rsa2048.pem -set_serial 0x2 -sha256              -out ch3_crt_v3.pem.crt -extfile v3_ca.ext

::second chain certificate signed by private key of second certificate
openssl req -new -key crt2_privatekey_rsa2048.pem -out crt2_v3.csr -extensions v3_ca
openssl x509 -req -days 7300 -in crt2_v3.csr -CA ch3_crt_v3.pem.crt -CAkey crt_privatekey_rsa2048.pem -set_serial 0x3cc30000babadeda -sha256 -outform der -out ch3_crt2_v3.der.crt -extfile v3_noca.ext
