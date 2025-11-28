#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK OSCCA cryptographic algorithms support utilities.

This module provides support detection and utilities for OSCCA (Office of State
Commercial Cryptography Administration) algorithms including SM2 elliptic curve
cryptography and SM3 hash functions used in Chinese cryptographic standards.
"""

import importlib.util

IS_OSCCA_SUPPORTED = importlib.util.find_spec("gmssl") is not None


if IS_OSCCA_SUPPORTED:
    import base64
    from typing import NamedTuple

    import spsdk.crypto._oscca_asn1 as oscca_asn1
    from spsdk.exceptions import SPSDKError
    from spsdk.utils.misc import SingletonMeta  # pylint:disable=unused-import

    class SM2PrivateKey(NamedTuple):
        """SM2 private key representation for OSCCA cryptographic operations.

        This class provides a simple container for SM2 private and public key pairs
        used in Chinese cryptographic standards. It stores both the private key value
        and its corresponding public key as string representations.
        """

        private: str
        public: str

    class SM2PublicKey(NamedTuple):
        """SM2 Public Key representation for OSCCA cryptographic operations.

        This class provides a simple structure for holding SM2 public key data
        as a string representation, used in Chinese cryptographic standards.
        """

        public: str

    class SM2Encoder(metaclass=SingletonMeta):
        """ASN.1 encoder and decoder for SM2 cryptographic keys and signatures.

        This singleton class provides comprehensive ASN.1 encoding and decoding functionality
        for SM2 (ShangMi 2) cryptographic operations, supporting both private and public key
        formats as well as signature data conversion between raw and BER formats.
        """

        def decode_private_key(self, data: bytes) -> SM2PrivateKey:
            """Decode private SM2 key from binary data.

            The method parses the binary data to extract private and public key components
            and validates the public key length.

            :param data: Binary data containing the encoded SM2 private key.
            :raises SPSDKError: Invalid length of public key data.
            :return: SM2PrivateKey object containing the decoded private and public keys.
            """
            private, public = oscca_asn1.decode_private_key(data=data)
            if len(public) != 128:
                raise SPSDKError(f"Invalid length of public key data: {len(public)} expected 128")

            return SM2PrivateKey(private=private, public=public)

        def decode_public_key(self, data: bytes) -> SM2PublicKey:
            """Parse public SM2 key set from binary data.

            Decodes binary data containing a public SM2 key and creates an SM2PublicKey object.
            The method validates that the decoded key data has the expected length of 128 bytes.

            :param data: Binary data containing the encoded SM2 public key.
            :raises SPSDKError: Invalid length of public key data (expected 128 bytes).
            :return: SM2PublicKey object containing the decoded public key.
            """
            result = oscca_asn1.decode_public_key(data=data)
            if len(result) != 128:
                raise SPSDKError(f"Invalid length of public key data: {len(data)} expected 128")
            return SM2PublicKey(public=result)

        def encode_private_key(self, keys: SM2PrivateKey) -> bytes:
            """Encode private SM2 key set from keyset.

            The method encodes both private and public keys from the SM2 key pair into a binary format
            using OSCCA ASN.1 encoding standards.

            :param keys: SM2 private key object containing both private and public key components.
            :return: Encoded private key data in binary format.
            """
            return oscca_asn1.encode_private_key(private=keys.private, public=keys.public)

        def encode_public_key(self, key: SM2PublicKey) -> bytes:
            """Encode public SM2 key from SM2PublicKey.

            :param key: SM2 public key object to be encoded.
            :return: Encoded public key as bytes.
            """
            return oscca_asn1.encode_public_key(data=key.public)

        def decode_signature(self, data: bytes) -> bytes:
            """Decode BER signature into r||s coordinates.

            :param data: BER encoded signature data to be decoded.
            :return: Decoded signature as concatenated r||s coordinates in bytes format.
            """
            return oscca_asn1.decode_signature(data=data)

        def encode_signature(self, data: bytes) -> bytes:
            """Encode raw r||s signature into BER format.

            :param data: Raw signature data containing concatenated r and s values.
            :return: BER-encoded signature bytes.
            """
            return oscca_asn1.encode_signature(data=data)

    def sanitize_pem(data: bytes) -> bytes:
        """Convert PEM data into DER format.

        Extracts the base64-encoded data between PEM markers containing 'KEY' and converts
        it to DER (Distinguished Encoding Rules) format. The method handles various PEM
        key formats by looking for lines containing 'KEY' as start/end markers.

        :param data: Input data that may be in PEM or DER format.
        :raises SPSDKError: When PEM data is corrupted or cannot be decoded.
        :return: DER-formatted data as bytes.
        """
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
