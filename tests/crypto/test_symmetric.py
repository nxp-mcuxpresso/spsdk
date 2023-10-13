#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


from binascii import unhexlify

from spsdk.crypto.symmetric import (
    aes_ctr_decrypt,
    aes_ctr_encrypt,
    aes_key_unwrap,
    aes_key_wrap,
    sm4_cbc_decrypt,
    sm4_cbc_encrypt,
)


def test_aes_key_wrap():
    kek = unhexlify("000102030405060708090A0B0C0D0E0F")
    plain_key = unhexlify("00112233445566778899AABBCCDDEEFF")
    wrapped_key = unhexlify("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
    calc_wrapped_key = aes_key_wrap(kek, plain_key)
    assert calc_wrapped_key == wrapped_key


def test_aes_key_unwrap():
    kek = unhexlify("000102030405060708090A0B0C0D0E0F")
    plain_key = unhexlify("00112233445566778899AABBCCDDEEFF")
    wrapped_key = unhexlify("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
    calc_plain_key = aes_key_unwrap(kek, wrapped_key)
    assert calc_plain_key == plain_key


def test_aes_ctr_encrypt():
    key = b"1234567812345678"
    nonce = b"\x00" * 16
    plain_text = b"\x0A" * 16
    cipher_text = b'\x90\xe2\xf7\x08\xb9J"\x80\x04q\xb5\xfa\xfa\xb0^\xdc'
    calc_cipher_text = aes_ctr_encrypt(key, plain_text, nonce)
    assert calc_cipher_text == cipher_text


def test_aes_ctr_decrypt():
    key = b"1234567812345678"
    nonce = b"\x00" * 16
    plain_text = b"\x0A" * 16
    cipher_text = b'\x90\xe2\xf7\x08\xb9J"\x80\x04q\xb5\xfa\xfa\xb0^\xdc'
    calc_plain_text = aes_ctr_decrypt(key, cipher_text, nonce)
    assert calc_plain_text == plain_text


def test_aes_sm4_encrypt():
    key = b"1234567812345678"
    nonce = b"\x00" * 16
    plain_text = b"\x0A" * 16
    cipher_text = b"\xb1\x0ca\xa0\x1en\xe5>c\xf7e?\xb0\xa4\x1e\xd7"
    calc_cipher_text = sm4_cbc_encrypt(key, plain_text, nonce)
    assert calc_cipher_text == cipher_text


def test_aes_sm4_decrypt():
    key = b"1234567812345678"
    nonce = b"\x00" * 16
    plain_text = b"\x0A" * 16
    cipher_text = b"\xb1\x0ca\xa0\x1en\xe5>c\xf7e?\xb0\xa4\x1e\xd7"
    calc_plain_text = sm4_cbc_decrypt(key, cipher_text, nonce)
    assert calc_plain_text == plain_text
