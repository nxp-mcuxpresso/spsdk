#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Implementation of AHAB container signature block support."""


import logging
from struct import calcsize, pack, unpack
from typing import Any, Dict, List, Optional, Union

from typing_extensions import Self

from spsdk.exceptions import SPSDKError, SPSDKParsingError
from spsdk.image.ahab.ahab_abstract_interfaces import HeaderContainer, HeaderContainerData
from spsdk.image.ahab.ahab_blob import AhabBlob
from spsdk.image.ahab.ahab_certificate import AhabCertificate
from spsdk.image.ahab.ahab_data import CONTAINER_ALIGNMENT, RESERVED, UINT16, UINT32, AHABTags
from spsdk.image.ahab.ahab_signature import ContainerSignature
from spsdk.image.ahab.ahab_srk import SRKTable
from spsdk.utils.misc import align, load_binary, load_configuration
from spsdk.utils.schema_validator import check_config
from spsdk.utils.verifier import Verifier, VerifierResult

logger = logging.getLogger(__name__)


class SignatureBlock(HeaderContainer):
    """Class representing signature block in the AHAB container.

    Signature Block::

        +---------------+----------------+----------------+----------------+-----+
        |    Byte 3     |     Byte 2     |      Byte 1    |     Byte 0     | Fix |
        |---------------+----------------+----------------+----------------+ len |
        |      Tag      |              Length             |    Version     |     |
        |---------------+---------------------------------+----------------+     |
        |       SRK Table Offset         |         Certificate Offset      |     |
        |--------------------------------+---------------------------------+     |
        |          Blob Offset           |          Signature Offset       |     |
        |--------------------------------+---------------------------------+     |
        |              Key identifier in case that Blob is present         |     |
        +------------------------------------------------------------------+-----+ Starting offset
        |                             SRK Table                            |     |
        +------------------------------------------------------------------+-----+ Padding length
        |                          64 bit alignment                        |     |
        +------------------------------------------------------------------+-----+ Starting offset
        |                              Signature                           |     |
        +------------------------------------------------------------------+-----+ Padding length
        |                          64 bit alignment                        |     |
        +------------------------------------------------------------------+-----+ Starting offset
        |                              Certificate                         |     |
        +------------------------------------------------------------------+-----+ Padding length
        |                          64 bit alignment                        |     |
        +------------------------------------------------------------------+-----+ Starting offset
        |                              Blob                                |     |
        +------------------------------------------------------------------+-----+

    """

    TAG = AHABTags.SIGNATURE_BLOCK.tag
    VERSION = 0x00

    def __init__(
        self,
        srk_table: Optional["SRKTable"] = None,
        container_signature: Optional[ContainerSignature] = None,
        certificate: Optional[AhabCertificate] = None,
        blob: Optional[AhabBlob] = None,
    ):
        """Class object initializer.

        :param srk_table: SRK table.
        :param container_signature: container signature.
        :param certificate: container certificate.
        :param blob: container blob.
        """
        super().__init__(tag=self.TAG, length=-1, version=self.VERSION)
        self._srk_table_offset = 0
        self._certificate_offset = 0
        self._blob_offset = 0
        self.signature_offset = 0
        self.srk_table = srk_table
        self.signature = container_signature
        self.certificate = certificate
        self.blob = blob

    def __eq__(self, other: object) -> bool:
        """Compares for equality with other Signature Block objects.

        :param other: object to compare with.
        :return: True on match, False otherwise.
        """
        if isinstance(other, SignatureBlock):
            if (
                super().__eq__(other)  # pylint: disable=too-many-boolean-expressions
                and self._srk_table_offset == other._srk_table_offset
                and self._certificate_offset == other._certificate_offset
                and self._blob_offset == other._blob_offset
                and self.signature_offset == other.signature_offset
                and self.srk_table == other.srk_table
                and self.signature == other.signature
                and self.certificate == other.certificate
                and self.blob == other.blob
            ):
                return True

        return False

    def __len__(self) -> int:
        self.update_fields()
        return self.length

    def __repr__(self) -> str:
        return "AHAB Signature Block"

    def __str__(self) -> str:
        return (
            "AHAB Signature Block:\n"
            f"  SRK Table:          {bool(self.srk_table)}\n"
            f"  Certificate:        {bool(self.certificate)}\n"
            f"  Signature:          {bool(self.signature)}\n"
            f"  Blob:               {bool(self.blob)}"
        )

    @classmethod
    def format(cls) -> str:
        """Format of binary representation."""
        return (
            super().format()
            + UINT16  # certificate offset
            + UINT16  # SRK table offset
            + UINT16  # signature offset
            + UINT16  # blob offset
            + UINT32  # key_identifier if blob is used
        )

    def update_fields(self) -> None:
        """Update all fields depended on input values."""
        # 1: Update SRK Table
        # Nothing to do with SRK Table
        last_offset = 0
        last_block_size = align(calcsize(self.format()), CONTAINER_ALIGNMENT)
        if self.srk_table:
            self.srk_table.update_fields()
            last_offset = self._srk_table_offset = last_offset + last_block_size
            last_block_size = align(len(self.srk_table), CONTAINER_ALIGNMENT)
        else:
            self._srk_table_offset = 0

        # 2: Update Signature (at least length)
        # Nothing to do with Signature - in this time , it MUST be ready
        if self.signature:
            last_offset = self.signature_offset = last_offset + last_block_size
            last_block_size = align(len(self.signature), CONTAINER_ALIGNMENT)
        else:
            self.signature_offset = 0
        # 3: Optionally update Certificate
        if self.certificate:
            self.certificate.update_fields()
            last_offset = self._certificate_offset = last_offset + last_block_size
            last_block_size = align(len(self.certificate), CONTAINER_ALIGNMENT)
        else:
            self._certificate_offset = 0
        # 4: Optionally update Blob
        if self.blob:
            last_offset = self._blob_offset = last_offset + last_block_size
            last_block_size = align(len(self.blob), CONTAINER_ALIGNMENT)
        else:
            self._blob_offset = 0

        # 5: Update length of Signature block
        self.length = last_offset + last_block_size

    def export(self) -> bytes:
        """Export Signature block.

        :raises SPSDKLengthError: if exported data length doesn't match container length.
        :return: bytes signature block content.
        """
        extended_header = pack(
            self.format(),
            self.version,
            self.length,
            self.tag,
            self._certificate_offset,
            self._srk_table_offset,
            self.signature_offset,
            self._blob_offset,
            self.blob.key_identifier if self.blob else RESERVED,
        )

        signature_block = bytearray(len(self))
        signature_block[0 : self.fixed_length()] = extended_header
        if self.srk_table:
            signature_block[
                self._srk_table_offset : self._srk_table_offset + len(self.srk_table)
            ] = self.srk_table.export()
        if self.signature:
            signature_block[self.signature_offset : self.signature_offset + len(self.signature)] = (
                self.signature.export()
            )
        if self.certificate:
            signature_block[
                self._certificate_offset : self._certificate_offset + len(self.certificate)
            ] = self.certificate.export()
        if self.blob:
            signature_block[self._blob_offset : self._blob_offset + len(self.blob)] = (
                self.blob.export()
            )

        return signature_block

    def verify(self) -> Verifier:
        """Verify container signature block data.

        :return: Verifier object
        """

        def verify_block(
            name: str,
            obj: Optional[Union[SRKTable, ContainerSignature, AhabCertificate, AhabBlob]],
            min_offset: int,
            offset: int,
            verify_data: Optional[Any] = None,
        ) -> Verifier:
            ver = Verifier(name)
            if bool(offset) != bool(obj):
                if bool(offset):
                    msg = "Offset is defined, but the block doesn't exists"
                else:
                    msg = "Block exists, but the offset is not defined"
                ver.add_record("Block validity", VerifierResult.ERROR, msg)
            if obj:
                if isinstance(obj, AhabCertificate):
                    ver.add_child(obj.verify(verify_data))
                else:
                    ver.add_child(obj.verify())
            else:
                ver.add_record("Block", VerifierResult.SUCCEEDED, "Not used")
                return ver

            if offset < min_offset:
                ver.add_record(
                    "Offset",
                    VerifierResult.ERROR,
                    f"Invalid: {offset} < minimal offset {min_offset}",
                )
            elif offset != align(offset, CONTAINER_ALIGNMENT):
                ver.add_record(
                    "Offset",
                    VerifierResult.ERROR,
                    f"Invalid alignment: {offset} is not aligned to {CONTAINER_ALIGNMENT*8} bits!",
                )
            else:
                ver.add_record_bit_range("Offset", offset, 16)

            return ver

        ret = Verifier("Signature Block", description="")
        ret.add_child(self.verify_parsed_header())
        ret.add_child(self.verify_header())
        min_offset = self.fixed_length()
        ret.add_child(verify_block("SRK Table", self.srk_table, min_offset, self._srk_table_offset))
        if self.srk_table:
            min_offset = self._srk_table_offset + len(self.srk_table)
        ret.add_child(verify_block("Signature", self.signature, min_offset, self.signature_offset))
        if self.signature:
            min_offset = self.signature_offset + len(self.signature)
        ret.add_child(
            verify_block(
                "Certificate",
                self.certificate,
                min_offset,
                self._certificate_offset,
                verify_data=self.srk_table,
            )
        )
        if self.certificate:
            min_offset = self._certificate_offset + len(self.certificate)
        ret.add_child(verify_block("Blob", self.blob, min_offset, self._blob_offset))
        if self.blob:
            ret.add_record_bit_range("Key identifier", self.blob.key_identifier)

        return ret

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse input binary chunk to the container object.

        :param data: Binary data with Signature block to parse.
        :return: Object recreated from the binary data.
        """
        SignatureBlock.check_container_head(data).validate()
        (
            _,  # version
            _,  # container_length
            _,  # tag
            certificate_offset,
            srk_table_offset,
            signature_offset,
            blob_offset,
            key_identifier,
        ) = unpack(SignatureBlock.format(), data[: SignatureBlock.fixed_length()])

        signature_block = cls()
        try:
            signature_block.srk_table = (
                SRKTable.parse(data[srk_table_offset:]) if srk_table_offset else None
            )
        except SPSDKParsingError:
            signature_block.srk_table = None
        try:
            signature_block.certificate = (
                AhabCertificate.parse(data[certificate_offset:]) if certificate_offset else None
            )
        except SPSDKParsingError:
            signature_block.certificate = None
        try:
            signature_block.signature = (
                ContainerSignature.parse(data[signature_offset:]) if signature_offset else None
            )
        except SPSDKParsingError:
            signature_block.signature = None

        try:
            signature_block.blob = AhabBlob.parse(data[blob_offset:]) if blob_offset else None
            if signature_block.blob:
                signature_block.blob.key_identifier = key_identifier
        except SPSDKParsingError as exc:
            logger.warning(
                "AHAB Blob parsing error. In case that no encrypted images"
                " are presented in container, it should not be an big issue."
                f"\n{str(exc)}"
            )
            signature_block.blob = None

        signature_block._parsed_header = HeaderContainerData.parse(binary=data)

        return signature_block

    @classmethod
    def pre_parse_verify(cls, data: bytes) -> Verifier:
        """Pre-Parse verify of AHAB Signature Block.

        :param data: Binary data with Signature block to pre-parse.
        :return: Verifier of pre-parsed binary data.
        """
        ret = cls.check_container_head(data)
        if ret.has_errors:
            return ret
        (
            _,  # version
            _,  # container_length
            _,  # tag
            certificate_offset,
            srk_table_offset,
            signature_offset,
            blob_offset,
            _,  # key_identifier
        ) = unpack(SignatureBlock.format(), data[: SignatureBlock.fixed_length()])

        if certificate_offset:
            ret.add_child(AhabCertificate.check_container_head(data[certificate_offset:]))
        if srk_table_offset:
            ret.add_child(SRKTable.pre_parse_verify(data[srk_table_offset:]))
        if signature_offset:
            ret.add_child(ContainerSignature.check_container_head(data[signature_offset:]))
        if blob_offset:
            ret.add_child(AhabBlob.check_container_head(data[blob_offset:]))
        return ret

    @staticmethod
    def load_from_config(
        config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> "SignatureBlock":
        """Converts the configuration option into an AHAB Signature block object.

        "config" content of container configurations.

        :param config: array of AHAB signature block configuration dictionaries.
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: AHAB Signature block object.
        """
        signature_block = SignatureBlock()
        # SRK Table
        srk_table_cfg = config.get("srk_table")
        signature_block.srk_table = (
            SRKTable.load_from_config(srk_table_cfg, search_paths) if srk_table_cfg else None
        )

        # Container Signature
        srk_set = config.get("srk_set", "none")
        signature_block.signature = (
            ContainerSignature.load_from_config(config, search_paths, signature_block.srk_table)
            if srk_set != "none"
            else None
        )

        # Certificate Block
        signature_block.certificate = None
        certificate_cfg = config.get("certificate")

        if certificate_cfg:
            try:
                cert_cfg = load_configuration(certificate_cfg)
                check_config(
                    cert_cfg, AhabCertificate.get_validation_schemas(), search_paths=search_paths
                )
                signature_block.certificate = AhabCertificate.load_from_config(cert_cfg)
            except SPSDKError:
                # this could be pre-exported binary certificate :-)
                signature_block.certificate = AhabCertificate.parse(
                    load_binary(certificate_cfg, search_paths)
                )

        # DEK blob
        blob_cfg = config.get("blob")
        signature_block.blob = (
            AhabBlob.load_from_config(blob_cfg, search_paths) if blob_cfg else None
        )

        return signature_block
