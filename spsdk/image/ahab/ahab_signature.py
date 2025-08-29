#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Implementation of AHAB container signature support.

This module provides functionality for creating, parsing, and verifying signatures
in AHAB containers. It supports both SRK table-based signatures and CMAC signatures,
allowing for secure image signing with or without an SRK table. The CMAC signature
type is specifically used in Device HSM procedures where hardware security modules
handle the cryptographic operations.
"""
import logging
from struct import pack, unpack
from typing import Optional

from typing_extensions import Self

from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.crypto.signature_provider import SignatureProvider, get_signature_provider
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.image.ahab.ahab_abstract_interfaces import HeaderContainer, HeaderContainerData
from spsdk.image.ahab.ahab_data import RESERVED, UINT8, UINT16, AHABTags, SignatureType
from spsdk.image.ahab.ahab_srk import SRKTable
from spsdk.utils.config import Config
from spsdk.utils.misc import BinaryPattern, bytes_to_print
from spsdk.utils.verifier import Verifier, VerifierResult

logger = logging.getLogger(__name__)


class ContainerSignature(HeaderContainer):
    """Class representing the signature in AHAB container as part of the signature block.

    Signature::

        +-----+--------------+--------------+----------------+----------------+
        |Off  |    Byte 3    |    Byte 2    |      Byte 1    |     Byte 0     |
        +-----+--------------+--------------+----------------+----------------+
        |0x00 |    Tag       | Length (MSB) | Length (LSB)   |     Version    |
        +-----+--------------+--------------+----------------+----------------+
        |0x04 |                        Reserved              |  Sign. Type    |
        +-----+----------------------------------------------+----------------+
        |0x08 |                      Signature Data                           |
        +-----+---------------------------------------------------------------+

    """

    TAG = AHABTags.SIGNATURE.tag
    VERSION = 0x00

    DIFF_ATTRIBUTES_VALUES = ["_signature_data"]

    def __init__(
        self,
        signature_data: Optional[bytes] = None,
        signature_provider: Optional[SignatureProvider] = None,
        signature_type: SignatureType = SignatureType.SRK_TABLE,
    ) -> None:
        """Initialize ContainerSignature object.

        :param signature_data: Signature data.
        :param signature_provider: Signature provider used to sign the image.
        :param signature_type: Type of signature (default is SRK_TABLE).
        """
        super().__init__(tag=self.TAG, length=-1, version=self.VERSION)
        self._signature_data = signature_data or b""
        self.signature_provider = signature_provider
        self.signature_type = signature_type
        self.length = len(self)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, ContainerSignature):
            if (
                super().__eq__(other)
                and self._signature_data == other._signature_data
                and self.signature_type == other.signature_type
            ):
                return True

        return False

    def __len__(self) -> int:
        if (not self._signature_data or len(self._signature_data) == 0) and self.signature_provider:
            return super().__len__() + self.signature_provider.signature_length

        sign_data_len = len(self._signature_data)
        if sign_data_len == 0:
            return 0

        return super().__len__() + sign_data_len

    def __repr__(self) -> str:
        return "AHAB Container Signature"

    def __str__(self) -> str:
        return (
            "AHAB Container Signature:\n"
            f"  Signature provider: {self.signature_provider.info() if self.signature_provider else 'Not available'}\n"
            f"  Signature type:     {self.signature_type.name}\n"
            f"  Signature:          {bytes_to_print(self.signature_data)}"
        )

    @property
    def signature_data(self) -> bytes:
        """Get the signature data.

        :return: Signature data.
        """
        return self._signature_data

    @signature_data.setter
    def signature_data(self, value: bytes) -> None:
        """Set the signature data.

        :param value: Signature data.
        """
        self._signature_data = value
        self.length = len(self)

    @classmethod
    def format(cls) -> str:
        """Get format of binary representation.

        :return: Format string for struct operations.
        """
        return super().format() + UINT8 + UINT8 + UINT16  # signature type, reserved, reserved

    def sign(self, data_to_sign: bytes) -> None:
        """Sign the data and store signature into class.

        :param data_to_sign: Data to be signed by stored private key.
        :raises SPSDKError: Missing private key or raw signature data.
        """
        if self.signature_type == SignatureType.CMAC:
            logger.debug("Skipping signature generation for CMAC type")
            return

        if not self.signature_provider and len(self._signature_data) == 0:
            raise SPSDKError(
                "The Signature container doesn't have specified the private key to sign."
            )

        if self.signature_provider:
            self._signature_data = self.signature_provider.get_signature(data_to_sign)

    def export(self) -> bytes:
        """Export signature data that is part of Signature Block.

        :return: Bytes representing container signature content.
        """
        if len(self) == 0:
            return b""

        data = (
            pack(
                self.format(),
                self.version,
                self.length,
                self.tag,
                self.signature_type.tag,
                RESERVED,
                RESERVED,
            )
            + self._signature_data
        )

        return data

    def verify(self) -> Verifier:
        """Verify container signature data.

        :return: Verifier object with verification results.
        """

        def verify_data() -> None:
            if self._signature_data is None:
                ret.add_record("Data", VerifierResult.ERROR, "Not exists signature data")
            elif len(self._signature_data) < 16:  # Minimum signature length check
                ret.add_record(
                    "Data",
                    VerifierResult.ERROR,
                    f"Not sufficient length: {len(self._signature_data)}",
                )
            elif self.signature_data == self.get_dummy_signature(len(self.signature_data)):
                ret.add_record(
                    "Data",
                    VerifierResult.WARNING,
                    "The signature data are dummy. The container Must be re-signed!",
                )
            else:
                ret.add_record(
                    "Data", VerifierResult.SUCCEEDED, bytes_to_print(self.signature_data)
                )

        ret = Verifier("Container signature", description="")
        ret.add_child(self.verify_parsed_header())
        ret.add_child(self.verify_header())
        ret.add_record_enum("Signature Type", self.signature_type, SignatureType)
        verify_data()

        return ret

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse input binary chunk to the container object.

        :param data: Binary data with Container signature block to parse.
        :return: Object recreated from the binary data.
        """
        ContainerSignature.check_container_head(data).validate()
        fix_len = ContainerSignature.fixed_length()

        _, container_length, _, signature_type_int, _, _ = unpack(
            ContainerSignature.format(), data[:fix_len]
        )
        signature_data = data[fix_len:container_length]
        signature_type = SignatureType.from_tag(signature_type_int)

        cnt_signature = cls(signature_data=signature_data, signature_type=signature_type)
        cnt_signature.length = container_length
        cnt_signature._parsed_header = HeaderContainerData.parse(binary=data)
        return cnt_signature

    @staticmethod
    def get_dummy_signature(size: int) -> bytes:
        """Get dummy signature used as placeholder.

        :param size: Size of signature.
        :return: Dummy signature in bytes.
        """
        return BinaryPattern("inc").get_block(size)

    @classmethod
    def load_from_config(
        cls,
        config: Config,
        srk_table: Optional[SRKTable] = None,
    ) -> Self:
        """Convert the configuration options into a ContainerSignature object.

        :param config: Array of AHAB containers configuration dictionaries.
        :param srk_table: SRK table, used to determine length of the signature if the
            signature_provider or private key is not used.
        :return: Container signature object.
        :raises SPSDKValueError: When srk_table is not defined but needed.
        """
        signature_provider = None
        signature_data = None
        hash_alg = (
            EnumHashAlgorithm.from_label(srk_table.srk_records[0].hash_algorithm.label)
            if srk_table
            else None
        )
        if "signer" in config:
            signature_provider = get_signature_provider(config, pss_padding=True, hash_alg=hash_alg)
        else:
            if not srk_table:
                raise SPSDKValueError(
                    "In case that private key neither signature provider is used, "
                    "the srk table must be defined to recognize the length of signature."
                )
            signature_data = cls.get_dummy_signature(srk_table.get_source_keys()[0].signature_size)
            logger.warning(
                "The AHAB configuration has not defined signing resources. "
                "Instead of signature, the place holder will be used. "
                "The AHAB has to be signed later by re-sign command."
            )

        return cls(signature_data=signature_data, signature_provider=signature_provider)
