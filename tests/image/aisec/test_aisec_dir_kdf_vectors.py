#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Known-answer tests of the AISEC dir-v5 key derivation.

The vectors in ``data/kdf_vectors.json`` were produced by the AISEC dir-v5 reference
implementation and cover the KDF base context of every backend with and without device
binding, the AUTH_DKEY / ENC_DKEY derivation for both KDFs and all key sizes, and the
SP 800-108 AES-CMAC counter KDF for output lengths on and off the AES block boundary.
"""

import json
from pathlib import Path
from typing import Any

import pytest

from spsdk.image.aisec.aisec_dir_crypto import (
    derive_auth_key,
    derive_enc_key,
    kdf_base_context,
    sp800_108_cmac_counter,
)
from spsdk.image.aisec.aisec_dir_types import AisecKdfAlg

VECTORS: dict[str, Any] = json.loads(
    (Path(__file__).parent / "data" / "kdf_vectors.json").read_text(encoding="utf-8")
)
SALT = bytes.fromhex(VECTORS["container_salt"])


@pytest.mark.parametrize("vector", VECTORS["base_context"])
def test_kdf_base_context(vector: dict[str, Any]) -> None:
    """The KDF base context matches the reference for every backend and binding.

    :param vector: Known-answer vector.
    """
    srkh = bytes.fromhex(vector["srkh"]) if vector["srkh"] is not None else None
    assert kdf_base_context(vector["mode"], srkh).hex() == vector["base_ctx"]


@pytest.mark.parametrize("vector", VECTORS["keys"])
def test_derived_keys(vector: dict[str, Any]) -> None:
    """AUTH_DKEY and ENC_DKEY match the reference for both KDFs and all key sizes.

    :param vector: Known-answer vector.
    """
    kdf = AisecKdfAlg.from_label(vector["kdf"])
    mmk = bytes.fromhex(vector["mmk"])
    base_ctx = kdf_base_context(VECTORS["key_mode"], bytes.fromhex(VECTORS["binding_srkh"]))
    length = vector["length"]
    assert derive_auth_key(kdf, mmk, base_ctx, SALT, length).hex() == vector["auth_key"]
    for member_id, expected in vector["enc_keys"].items():
        key = derive_enc_key(kdf, mmk, base_ctx, SALT, int(member_id), length)
        assert key.hex() == expected


@pytest.mark.parametrize("vector", VECTORS["sp800_108_cmac"])
def test_sp800_108_cmac_counter(vector: dict[str, Any]) -> None:
    """The SP 800-108 AES-CMAC counter KDF matches the reference byte for byte.

    :param vector: Known-answer vector.
    """
    output = sp800_108_cmac_counter(
        bytes.fromhex(vector["key"]),
        bytes([vector["label"]]),
        bytes.fromhex(vector["context"]),
        vector["length"],
    )
    assert output.hex() == vector["output"]
