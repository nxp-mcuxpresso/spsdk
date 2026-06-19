#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Tests for crypto modules: cmac, lms, symmetric extras."""

from typing import Any

import pytest

from spsdk.crypto.cmac import cmac, cmac_validate
from spsdk.crypto.symmetric import (
    Counter,
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    aes_ccm_decrypt,
    aes_ccm_encrypt,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    aes_xts_decrypt,
    aes_xts_encrypt,
    sm4_cbc_decrypt,
    sm4_cbc_encrypt,
)
from spsdk.exceptions import SPSDKError
from spsdk.utils.misc import Endianness

# ---------------------------------------------------------------------------
# cmac.py
# ---------------------------------------------------------------------------


def test_cmac_validate_valid() -> None:
    """validate_cmac returns True when signature matches."""
    key = b"\x00" * 16
    data = b"hello world"
    sig = cmac(key, data)
    assert cmac_validate(key, data, sig) is True


def test_cmac_validate_invalid_signature() -> None:
    """validate_cmac returns False when signature is wrong (covers lines 48-54)."""
    key = b"\x00" * 16
    data = b"hello world"
    bad_sig = b"\xff" * 16
    assert cmac_validate(key, data, bad_sig) is False


# ---------------------------------------------------------------------------
# symmetric.py – Counter
# ---------------------------------------------------------------------------


def test_counter_bad_nonce_raises() -> None:
    """Counter raises SPSDKError when nonce is not 16 bytes (line 63)."""
    with pytest.raises(SPSDKError):
        Counter(b"\x00" * 8)


def test_counter_bad_nonce_not_bytes_raises() -> None:
    """Counter raises SPSDKError when nonce is not bytes."""
    with pytest.raises(SPSDKError):
        Counter("not bytes")  # type: ignore[arg-type]


def test_counter_value_little_endian() -> None:
    """Counter encodes counter in little-endian by default."""
    nonce = b"\xaa" * 12 + b"\x01\x00\x00\x00"
    ctr = Counter(nonce, ctr_byteorder_encoding=Endianness.LITTLE)
    val = ctr.value
    assert len(val) == 16
    # last 4 bytes should be 0x01 in little-endian
    assert val[12:] == (1).to_bytes(4, "little")


def test_counter_value_big_endian() -> None:
    """Counter encodes counter in big-endian when requested."""
    nonce = b"\xbb" * 12 + b"\x00\x00\x00\x02"
    ctr = Counter(nonce, ctr_byteorder_encoding=Endianness.BIG)
    val = ctr.value
    assert val[12:] == (2).to_bytes(4, "big")


def test_counter_ctr_value_offset() -> None:
    """Counter adds optional ctr_value offset to the counter."""
    # In little-endian, b"\x01\x00\x00\x00" decodes to integer 1
    nonce = b"\x00" * 12 + b"\x01\x00\x00\x00"
    ctr = Counter(nonce, ctr_value=5, ctr_byteorder_encoding=Endianness.LITTLE)
    # initial counter = 1, offset = 5 → 6
    assert ctr.value[12:] == (6).to_bytes(4, "little")


def test_counter_increment() -> None:
    """Counter.increment() increases the counter value."""
    nonce = b"\x00" * 16
    ctr = Counter(nonce)
    ctr.increment()
    assert ctr.value[12:] == (1).to_bytes(4, "little")
    ctr.increment(4)
    assert ctr.value[12:] == (5).to_bytes(4, "little")


# ---------------------------------------------------------------------------
# symmetric.py – aes_cbc_encrypt / aes_cbc_decrypt error paths
# ---------------------------------------------------------------------------


def test_aes_cbc_encrypt_bad_key_raises() -> None:
    """aes_cbc_encrypt raises SPSDKError for invalid key length (line 141)."""
    with pytest.raises(SPSDKError):
        aes_cbc_encrypt(b"\x00" * 7, b"plaintext padded")


def test_aes_cbc_encrypt_bad_iv_raises() -> None:
    """aes_cbc_encrypt raises SPSDKError for invalid IV length (line 147)."""
    with pytest.raises(SPSDKError):
        aes_cbc_encrypt(b"\x00" * 16, b"plaintext padded", iv_data=b"\x00" * 8)


def test_aes_cbc_decrypt_bad_key_raises() -> None:
    """aes_cbc_decrypt raises SPSDKError for invalid key length (line 169)."""
    with pytest.raises(SPSDKError):
        aes_cbc_decrypt(b"\x00" * 7, b"\x00" * 16)


def test_aes_cbc_decrypt_bad_iv_raises() -> None:
    """aes_cbc_decrypt raises SPSDKError for invalid IV length (line 175)."""
    with pytest.raises(SPSDKError):
        aes_cbc_decrypt(b"\x00" * 16, b"\x00" * 16, iv_data=b"\x00" * 8)


# ---------------------------------------------------------------------------
# symmetric.py – aes_xts_decrypt (lines 238-240)
# ---------------------------------------------------------------------------


def test_aes_xts_roundtrip() -> None:
    """aes_xts_encrypt/decrypt round-trips successfully (covers lines 238-240)."""
    # XTS key must be 32 bytes with non-duplicated halves
    key = b"\x01" * 16 + b"\x02" * 16
    tweak = b"\x00" * 16
    plain = b"\xab" * 16
    encrypted = aes_xts_encrypt(key, plain, tweak)
    assert aes_xts_decrypt(key, encrypted, tweak) == plain


# ---------------------------------------------------------------------------
# symmetric.py – aes_ccm_decrypt (lines 279-280)
# ---------------------------------------------------------------------------


def test_aes_ccm_roundtrip() -> None:
    """aes_ccm_encrypt/decrypt round-trips (covers lines 279-280)."""
    key = b"\x11" * 16
    nonce = b"\x22" * 11  # CCM nonce: 7-13 bytes
    aad = b"header"
    plain = b"secret message!"
    encrypted = aes_ccm_encrypt(key, plain, nonce, aad)
    decrypted = aes_ccm_decrypt(key, encrypted, nonce, aad)
    assert decrypted == plain


# ---------------------------------------------------------------------------
# symmetric.py – sm4_cbc_encrypt / sm4_cbc_decrypt error paths
# ---------------------------------------------------------------------------


def test_sm4_cbc_encrypt_bad_key_raises() -> None:
    """sm4_cbc_encrypt raises SPSDKError for invalid key length (line 297)."""
    with pytest.raises(SPSDKError):
        sm4_cbc_encrypt(b"\x00" * 8, b"plaintext data!!")


def test_sm4_cbc_encrypt_bad_iv_raises() -> None:
    """sm4_cbc_encrypt raises SPSDKError for invalid IV length (line 303)."""
    with pytest.raises(SPSDKError):
        sm4_cbc_encrypt(b"\x00" * 16, b"plaintext data!!", iv_data=b"\x00" * 8)


def test_sm4_cbc_decrypt_bad_key_raises() -> None:
    """sm4_cbc_decrypt raises SPSDKError for invalid key length (line 322)."""
    with pytest.raises(SPSDKError):
        sm4_cbc_decrypt(b"\x00" * 8, b"\x00" * 16)


def test_sm4_cbc_decrypt_bad_iv_raises() -> None:
    """sm4_cbc_decrypt raises SPSDKError for invalid IV length (line 328)."""
    with pytest.raises(SPSDKError):
        sm4_cbc_decrypt(b"\x00" * 16, b"\x00" * 16, iv_data=b"\x00" * 8)


# ---------------------------------------------------------------------------
# symmetric.py – aes_gcm_encrypt error paths (lines 350, 356)
# ---------------------------------------------------------------------------


def test_aes_gcm_encrypt_bad_key_raises() -> None:
    """aes_gcm_encrypt raises SPSDKError for invalid key length (line 350)."""
    with pytest.raises(SPSDKError):
        aes_gcm_encrypt(b"\x00" * 7, b"data")


def test_aes_gcm_encrypt_bad_iv_raises() -> None:
    """aes_gcm_encrypt raises SPSDKError for invalid IV length (line 356)."""
    with pytest.raises(SPSDKError):
        aes_gcm_encrypt(b"\x00" * 16, b"data", init_vector=b"\x00" * 8)


# ---------------------------------------------------------------------------
# symmetric.py – aes_gcm_decrypt (lines 381-392)
# ---------------------------------------------------------------------------


def test_aes_gcm_decrypt_roundtrip() -> None:
    """aes_gcm_encrypt/decrypt round-trips (covers lines 388-390)."""
    key = b"\x33" * 16
    iv = b"\x44" * 12
    aad = b"associated"
    plain = b"top secret data"
    encrypted = aes_gcm_encrypt(key, plain, iv, aad)
    decrypted = aes_gcm_decrypt(key, encrypted, iv, aad)
    assert decrypted == plain


def test_aes_gcm_decrypt_bad_key_raises() -> None:
    """aes_gcm_decrypt raises SPSDKError for invalid key length (lines 381-385)."""
    with pytest.raises(SPSDKError):
        aes_gcm_decrypt(b"\x00" * 7, b"\x00" * 32, b"\x00" * 12)


def test_aes_gcm_decrypt_bad_iv_raises() -> None:
    """aes_gcm_decrypt raises SPSDKError for invalid IV length (lines 386-387)."""
    with pytest.raises(SPSDKError):
        aes_gcm_decrypt(b"\x00" * 16, b"\x00" * 32, b"\x00" * 8)


def test_aes_gcm_decrypt_tampered_raises() -> None:
    """aes_gcm_decrypt raises SPSDKError when ciphertext is tampered (lines 389-392)."""
    key = b"\x55" * 16
    iv = b"\x66" * 12
    plain = b"authentic data!"
    encrypted = aes_gcm_encrypt(key, plain, iv)
    corrupted = bytes([encrypted[0] ^ 0xFF]) + encrypted[1:]
    with pytest.raises(SPSDKError):
        aes_gcm_decrypt(key, corrupted, iv)


# ---------------------------------------------------------------------------
# lms.py – LMSParams (only run when pyhsslms is available)
# ---------------------------------------------------------------------------

pyhsslms = pytest.importorskip("pyhsslms")


def _make_params() -> Any:
    """Return a basic LMSParams instance (sha256, n=32, h=5, w=8)."""
    from spsdk.crypto.lms import LMSParams

    return LMSParams(hash_length=32, height=5, w=8)


def test_lms_params_repr() -> None:
    """LMSParams.__repr__ returns expected string (line 51)."""
    params = _make_params()
    r = repr(params)
    assert "sha256" in r
    assert "32" in r
    assert "5" in r
    assert "8" in r


def test_lms_params_get_lmots_param() -> None:
    """LMSParams.get_lmots_param returns correct bytes constant (line 55)."""
    import pyhsslms as _pyhsslms

    params = _make_params()
    assert params.get_lmots_param() == _pyhsslms.lmots_sha256_n32_w8


def test_lms_params_get_lms_param() -> None:
    """LMSParams.get_lms_param returns correct bytes constant (line 59)."""
    import pyhsslms as _pyhsslms

    params = _make_params()
    assert params.get_lms_param() == _pyhsslms.lms_sha256_m32_h5


def test_lms_params_from_params() -> None:
    """LMSParams.from_params reconstructs params from integer identifiers (lines 66-72)."""
    from spsdk.crypto.lms import LMSParams

    # lms_sha256_m32_h5 = int 5, lmots_sha256_n32_w8 = int 4
    p = LMSParams.from_params(lms_param=5, lmots_param=4)
    assert p.hash_alg == "sha256"
    assert p.hash_length == 32
    assert p.height == 5
    assert p.w == 8


def test_lms_params_from_data_valid() -> None:
    """LMSParams.from_data parses the first 8 bytes to reconstruct params (lines 92, 100)."""
    from spsdk.crypto.lms import LMSParams

    # lms type = 5, lmots type = 4, padded with zeros
    data = (5).to_bytes(4, "big") + (4).to_bytes(4, "big") + b"\x00" * 40
    p = LMSParams.from_data(data)
    assert p.hash_alg == "sha256"
    assert p.height == 5
    assert p.w == 8


def test_lms_params_from_data_too_short_raises() -> None:
    """LMSParams.from_data raises SPSDKError when data is too short (lines 104-106)."""
    from spsdk.crypto.lms import LMSParams

    with pytest.raises(SPSDKError):
        LMSParams.from_data(b"\x00" * 4)


def test_lms_params_get_private_key_length() -> None:
    """LMSParams.get_private_key_length returns correct value (lines 113-120)."""
    params = _make_params()
    # 4 + 4 + 32 + 16 + 4 = 60
    assert params.get_private_key_length() == 60


def test_lms_params_get_public_key_length() -> None:
    """LMSParams.get_public_key_length returns correct value (lines 122-132)."""
    params = _make_params()
    # 4 + 4 + 16 + 32 = 56
    assert params.get_public_key_length() == 56


def test_lms_params_generate_private_key() -> None:
    """LMSParams.generate_private_key creates an LmsPrivateKey (lines 137-142)."""
    from pyhsslms import LmsPrivateKey

    params = _make_params()
    priv = params.generate_private_key()
    assert isinstance(priv, LmsPrivateKey)


def test_lms_params_from_key_private() -> None:
    """LMSParams.from_key reconstructs params from an LmsPrivateKey."""
    from spsdk.crypto.lms import LMSParams

    params = _make_params()
    priv = params.generate_private_key()
    recovered = LMSParams.from_key(priv)
    assert recovered.hash_alg == "sha256"
    assert recovered.hash_length == 32
    assert recovered.height == 5
    assert recovered.w == 8
    assert recovered.seed == priv.SEED
    assert recovered.q == priv.q


def test_lms_params_calc_signature_length() -> None:
    """LMSParams.calc_signature_length returns expected size."""
    from spsdk.crypto.lms import LMSParams

    params = _make_params()
    priv = params.generate_private_key()
    sig_len = LMSParams.calc_signature_length(priv)
    # n=32, p=34 → lmots=4+32*35=1124; total=4+1124+4+5*32=1292
    assert sig_len == 1292
