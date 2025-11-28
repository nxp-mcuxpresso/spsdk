#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Dilithium cryptographic algorithm tests.

This module contains unit tests for the Dilithium post-quantum digital signature
algorithm implementation in SPSDK, verifying key operations and cryptographic
functionality.
"""

import pytest

pytest.importorskip("spsdk_pqc")
from spsdk.crypto.keys import PrivateKeyDilithium  # noqa: E402


@pytest.mark.parametrize("level", PrivateKeyDilithium.SUPPORTED_LEVELS)
def test_sign_verify(level: int) -> None:
    """Test Dilithium digital signature generation and verification.

    This test verifies that a Dilithium private key can generate a signature
    of the expected size and that the corresponding public key can successfully
    verify that signature.

    :param level: Dilithium security level (1, 2, 3, or 5) determining key size and security strength.
    """
    data = b"message to sign"

    prk = PrivateKeyDilithium.generate_key(level=level)
    puk = prk.get_public_key()
    signature = prk.sign(data=data)
    assert len(signature) == prk.signature_size

    assert puk.verify_signature(signature=signature, data=data)
