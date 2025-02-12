#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Support for OSCCA SM2/SM3."""

import importlib.util

IS_OSCCA_SUPPORTED = importlib.util.find_spec("gmssl") is not None


if IS_OSCCA_SUPPORTED:
    import base64
    from typing import NamedTuple

    import spsdk.crypto._oscca_asn1 as oscca_asn1
    from spsdk.exceptions import SPSDKError
    from spsdk.utils.misc import SingletonMeta  # pylint:disable=unused-import

    class SM2PrivateKey(NamedTuple):
        """Bare-bone representation of a SM2 Key."""

        private: str
        public: str

    class SM2PublicKey(NamedTuple):
        """Bare-bone representation of a SM2 Public Key."""

        public: str

    class SM2Encoder(metaclass=SingletonMeta):
        """ASN1 Encoder/Decoder for SM2 keys and signature."""

        def decode_private_key(self, data: bytes) -> SM2PrivateKey:
            """Parse private SM2 key set from binary data."""
            private, public = oscca_asn1.decode_private_key(data=data)
            if len(public) != 128:
                raise SPSDKError(f"Invalid length of public key data: {len(public)} expected 128")

            return SM2PrivateKey(private=private, public=public)

        def decode_public_key(self, data: bytes) -> SM2PublicKey:
            """Parse public SM2 key set from binary data."""
            result = oscca_asn1.decode_public_key(data=data)
            if len(result) != 128:
                raise SPSDKError(f"Invalid length of public key data: {len(data)} expected 128")
            return SM2PublicKey(public=result)

        def encode_private_key(self, keys: SM2PrivateKey) -> bytes:
            """Encode private SM2 key set from keyset."""
            return oscca_asn1.encode_private_key(private=keys.private, public=keys.public)

        def encode_public_key(self, key: SM2PublicKey) -> bytes:
            """Encode public SM2 key from SM2PublicKey."""
            return oscca_asn1.encode_public_key(data=key.public)

        def decode_signature(self, data: bytes) -> bytes:
            """Decode BER signature into r||s coordinates."""
            return oscca_asn1.decode_signature(data=data)

        def encode_signature(self, data: bytes) -> bytes:
            """Encode raw r||s signature into BER format."""
            return oscca_asn1.encode_signature(data=data)

    def sanitize_pem(data: bytes) -> bytes:
        """Covert PEM data into DER."""
        if b"---" not in data:
            return data

        capture_data = False
        base64_data = b""
        for line in data.splitlines(keepends=False):
            if capture_data:
                base64_data += line
            # PEM data may contain EC PARAMS, thus capture trigger should be the word KEY
            if b"KEY" in line:
                capture_data = not capture_data
        # in the end the `capture_data` flag should be false signaling proper END * KEY
        # and we should have some data
        try:
            if capture_data is False and len(base64_data) > 0:
                der_data = base64.b64decode(base64_data)
                return der_data
        except base64.binascii.Error as e:  # type: ignore[attr-defined]
            raise SPSDKError("PEM data are corrupted") from e
        raise SPSDKError("PEM data are corrupted")
