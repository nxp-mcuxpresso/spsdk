#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import os
from binascii import unhexlify

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from spsdk import SPSDKError
from spsdk.utils.crypto.backend_openssl import openssl_backend


def test_random_bytes():
    random_bytes = openssl_backend.random_bytes(16)
    assert isinstance(random_bytes, bytes)
    assert len(random_bytes) == 16
    assert random_bytes != openssl_backend.random_bytes(16)


def test_hash():
    plain_text = b"testestestestestestestestestestestestestestestestestestestest"
    text_sha256 = unhexlify("41116FE4EFB90A050AABB83419E19BF2196A0E76AB8E3034C8D674042EE23621")
    calc_sha256 = openssl_backend.hash(plain_text, "sha256")
    assert calc_sha256 == text_sha256


def test_hmac():
    key = b"12345678"
    plain_text = b"testestestestestestestestestestestestestestestestestestestest"
    text_hmac_sha256 = unhexlify("d785d886a750c999aa86802697dd4a9934facac72614cbfa66bbf657b74eb1d5")
    calc_hmac_sha256 = openssl_backend.hmac(key, plain_text, "sha256")
    assert calc_hmac_sha256 == text_hmac_sha256


def test_aes_key_wrap():
    kek = unhexlify("000102030405060708090A0B0C0D0E0F")
    plain_key = unhexlify("00112233445566778899AABBCCDDEEFF")
    wrapped_key = unhexlify("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
    calc_wrapped_key = openssl_backend.aes_key_wrap(kek, plain_key)
    assert calc_wrapped_key == wrapped_key


def test_aes_key_unwrap():
    kek = unhexlify("000102030405060708090A0B0C0D0E0F")
    plain_key = unhexlify("00112233445566778899AABBCCDDEEFF")
    wrapped_key = unhexlify("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
    calc_plain_key = openssl_backend.aes_key_unwrap(kek, wrapped_key)
    assert calc_plain_key == plain_key


def test_aes_ctr_encrypt():
    key = b"1234567812345678"
    nonce = b"\x00" * 16
    plain_text = b"\x0A" * 16
    cipher_text = b'\x90\xe2\xf7\x08\xb9J"\x80\x04q\xb5\xfa\xfa\xb0^\xdc'
    calc_cipher_text = openssl_backend.aes_ctr_encrypt(key, plain_text, nonce)
    assert calc_cipher_text == cipher_text


def test_aes_ctr_decrypt():
    key = b"1234567812345678"
    nonce = b"\x00" * 16
    plain_text = b"\x0A" * 16
    cipher_text = b'\x90\xe2\xf7\x08\xb9J"\x80\x04q\xb5\xfa\xfa\xb0^\xdc'
    calc_plain_text = openssl_backend.aes_ctr_decrypt(key, cipher_text, nonce)
    assert calc_plain_text == plain_text


def test_rsa_sign(data_dir):
    with open(os.path.join(data_dir, "selfsign_privatekey_rsa2048.pem"), "rb") as key_file:
        key_data = key_file.read()

    private_key = serialization.load_pem_private_key(
        data=key_data, password=None, backend=default_backend()
    )

    signature = (
        b"\xc2!b\xf9\xb7$<i><2\x07|\x86,\xdd\x003\x93\x95\x1a\x92?\xf5\x1c\xfce\xfd#\x02\x1b\xd5&\xec\xf8`"
        b"\xe1\x1ex\xfd=Ls\xaf\x81\x12[\xe8\x80n\xc17\x8b\x9a\xba\x86N\xcbCd\xfb\xe7\xfei\xcc\x90\x02\xbf)"
        b'\x05\x81\t\xbb\xed+dW\xc8\xb6BG\xb3\x9eW\xc40PUf\xb3\xadU\xf0q\xaf\xe3"\xd5\n\xf9?\x1d\xf6\xd1\xc5'
        b"\xcd\x18\x8b\xe8u\xd7\xa0\n\xfaR4\x1fY|g\xf1\xee\r\xd8\xed\x16D\x19\xcdbo1\x1c\xdeP<H\xcf\x8aT\xae"
        b"\xea\x8d8\xb8\xb7[U,\x1a\x05\xb8\xb6\xbd\xcaWi\xc7\x11\x96s\x16I\xe0\x8a\xdc\xd7\xa3F] \xf7:r"
        b'\x1405y"\xa3\xbf\x97\x94@\xa5\xa4\x8a\xd1\x8d\xb2\x91\x0b\xe2\xd0\x03\xf4=\xeb\x0fT\xa8\x8cn\x9d'
        b";O\xa2eT\xcf\xdffd0?\xbd\xf6\xe2\xb6m\x0b\xe34V5Z\xca\x831\xae\x7f\x94C\x0e<?fI\xf1\xedS\xe8K\xd9"
        b"\xd0S\xf0\xf6\xf5e\xb6\xb1Z\x85\x1e!"
    )
    data = bytes([v % 256 for v in range(0, 512)])
    # specify key using KEY data in PEM format
    calc_signature = openssl_backend.rsa_sign(key_data, data)
    assert len(calc_signature) == 256
    assert calc_signature == signature
    # specify key using RSAPrivateKey class
    calc_signature = openssl_backend.rsa_sign(private_key, data)
    assert len(calc_signature) == 256
    assert calc_signature == signature


def test_rsa_verify(data_dir):
    with open(os.path.join(data_dir, "selfsign_privatekey_rsa2048.pem"), "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            data=key_file.read(), password=None, backend=default_backend()
        )

    signature = (
        b"\xc2!b\xf9\xb7$<i><2\x07|\x86,\xdd\x003\x93\x95\x1a\x92?\xf5\x1c\xfce\xfd#\x02\x1b\xd5&\xec\xf8`"
        b"\xe1\x1ex\xfd=Ls\xaf\x81\x12[\xe8\x80n\xc17\x8b\x9a\xba\x86N\xcbCd\xfb\xe7\xfei\xcc\x90\x02\xbf)"
        b'\x05\x81\t\xbb\xed+dW\xc8\xb6BG\xb3\x9eW\xc40PUf\xb3\xadU\xf0q\xaf\xe3"\xd5\n\xf9?\x1d\xf6\xd1\xc5'
        b"\xcd\x18\x8b\xe8u\xd7\xa0\n\xfaR4\x1fY|g\xf1\xee\r\xd8\xed\x16D\x19\xcdbo1\x1c\xdeP<H\xcf\x8aT\xae"
        b"\xea\x8d8\xb8\xb7[U,\x1a\x05\xb8\xb6\xbd\xcaWi\xc7\x11\x96s\x16I\xe0\x8a\xdc\xd7\xa3F] \xf7:r"
        b'\x1405y"\xa3\xbf\x97\x94@\xa5\xa4\x8a\xd1\x8d\xb2\x91\x0b\xe2\xd0\x03\xf4=\xeb\x0fT\xa8\x8cn\x9d'
        b";O\xa2eT\xcf\xdffd0?\xbd\xf6\xe2\xb6m\x0b\xe34V5Z\xca\x831\xae\x7f\x94C\x0e<?fI\xf1\xedS\xe8K\xd9"
        b"\xd0S\xf0\xf6\xf5e\xb6\xb1Z\x85\x1e!"
    )
    data = bytes([v % 256 for v in range(0, 512)])
    pub_nums = private_key.public_key().public_numbers()
    is_valid = openssl_backend.rsa_verify(pub_nums.n, pub_nums.e, signature, data)
    assert is_valid


def test_ecc_sign_verify(data_dir):
    with open(os.path.join(data_dir, "ecc_secp256r1_priv_key.pem"), "rb") as key_file:
        private_key_data = key_file.read()
    with open(os.path.join(data_dir, "ecc_secp256r1_pub_key.pem"), "rb") as key_file:
        public_key_data = key_file.read()

    private_key = serialization.load_pem_private_key(
        data=private_key_data, password=None, backend=default_backend()
    )
    data = b"THIS IS MESSAGE TO BE SIGNED"
    calc_signature = openssl_backend.ecc_sign(private_key_data, data)
    calc_signature2 = openssl_backend.ecc_sign(private_key, data)
    # openssl utilize randomized signature thus two signatures are different
    assert calc_signature != calc_signature2

    public_key = serialization.load_pem_public_key(data=public_key_data, backend=default_backend())
    is_valid = openssl_backend.ecc_verify(
        public_key=public_key, signature=calc_signature, data=data
    )
    is_valid2 = openssl_backend.ecc_verify(
        public_key=public_key_data, signature=calc_signature2, data=data
    )
    # randomized signatures are still valid
    assert is_valid == is_valid2 == True


def test_ecc_sign_verify_incorrect(data_dir):
    with open(os.path.join(data_dir, "ecc_secp256r1_priv_key.pem"), "rb") as key_file:
        private_key_data = key_file.read()
    with open(os.path.join(data_dir, "ecc_secp256r1_pub_key.pem"), "rb") as key_file:
        public_key_data = key_file.read()

    private_key = serialization.load_pem_private_key(
        data=private_key_data, password=None, backend=default_backend()
    )
    data = b"THIS IS MESSAGE TO BE SIGNED"
    calc_signature = openssl_backend.ecc_sign(private_key_data, data)

    # malform the signature
    bad_signature = calc_signature[:-2] + bytes(2)
    is_valid = openssl_backend.ecc_verify(
        public_key=public_key_data, signature=bad_signature, data=data
    )
    assert is_valid == False

    # make signature bigger than expected
    with pytest.raises(SPSDKError):
        bad_signature = calc_signature + bytes(2)
        openssl_backend.ecc_verify(public_key=public_key_data, signature=bad_signature, data=data)
