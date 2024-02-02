#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import pytest

from spsdk.tp.data_container import AuthenticationType, Container
from spsdk.tp.data_container.data_container_auth import get_auth_data_len
from spsdk.tp.exceptions import SPSDKTpError
from spsdk.utils.misc import load_binary
from spsdk.utils.spsdk_enum import SpsdkEnum

KEY_STR = "0123456789ABCDEF0123456789ABCDEF"
KEY = bytes.fromhex(KEY_STR)


@pytest.mark.parametrize(
    "auth_type, key",
    [
        (AuthenticationType.AES_CMAC, KEY),
        (AuthenticationType.HMAC_256, KEY),
        (AuthenticationType.CRC32, None),
    ],
)
def test_auth(sample_container: Container, auth_type: AuthenticationType, key: bytes):
    sample_container.add_auth_entry(auth_type=auth_type, key=key)
    assert sample_container.validate(key=key)

    data = sample_container.export()
    assert len(data) % 8 == 0

    parsed_container = Container.parse(data=data)
    assert sample_container == parsed_container
    assert parsed_container.validate(key=key)

    # corrupt the signature (reverse it)
    signature = parsed_container._entries[-1].payload
    parsed_container._entries[-1].payload = signature[::-1]
    assert not parsed_container.validate(key=key)


def test_ecdsa_256_auth(sample_container: Container, data_dir):
    private_key = load_binary(f"{data_dir}/ecc_p256_prk.pem")
    public_key = load_binary(f"{data_dir}/ecc_p256_prk.pub")

    sample_container.add_auth_entry(AuthenticationType.ECDSA_256, private_key)
    assert sample_container.validate(public_key)


def test_auth_no_dataauth_entry(sample_container: Container):
    with pytest.raises(SPSDKTpError):
        sample_container.validate(bytes(10))


def test_auth_multiple_dataauth_entries(sample_container: Container):
    sample_container.add_auth_entry(AuthenticationType.AES_CMAC, KEY)
    with pytest.raises(SPSDKTpError):
        sample_container.add_auth_entry(AuthenticationType.AES_CMAC, KEY)


def test_unknown_authenticators():
    class TestAuthenticationType(SpsdkEnum):
        """Available Authentication types."""

        NON_EXISTING = (1, "non_existing", "Non existing")

    with pytest.raises(SPSDKTpError) as error:
        get_auth_data_len(TestAuthenticationType.NON_EXISTING)
    assert "Unknown AUTH TYPE" in error.value.description
