================
Crypto
================
SPSDK crypto backend provides unified API for all crypto operations needed for secure and trust provisioning like key and certificate generation, signing, encryption, hashing and others.

It is mostly based on python package cryptography https://cryptography.io/ which is then based on OpenSSL. OpenSSL is the de facto standard for cryptographic libraries and provides high performance along with various certifications that may be relevant to developers.
In the addition to the cryptography it also implements some other less known standards for example OSCCA and CMS signatures.

.. toctree::
    :maxdepth: 1

    keys
    certificates
