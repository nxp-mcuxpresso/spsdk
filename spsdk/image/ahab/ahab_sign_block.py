#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Implementation of AHAB container signature block support."""


import logging
import os
from struct import calcsize, pack, unpack
from typing import Any, Optional, Union

from typing_extensions import Self

from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.exceptions import SPSDKError, SPSDKParsingError, SPSDKUnsupportedOperation
from spsdk.image.ahab.ahab_abstract_interfaces import HeaderContainer, HeaderContainerData
from spsdk.image.ahab.ahab_blob import AhabBlob
from spsdk.image.ahab.ahab_certificate import (
    AhabCertificate,
    AhabCertificateMcuPqc,
    get_ahab_certificate_class,
)
from spsdk.image.ahab.ahab_data import (
    CONTAINER_ALIGNMENT,
    RESERVED,
    UINT16,
    UINT32,
    AhabChipContainerConfig,
    AHABTags,
    FlagsSrkSet,
    SignatureType,
)
from spsdk.image.ahab.ahab_signature import ContainerSignature
from spsdk.image.ahab.ahab_srk import SRKRecordV2, SRKTable, SRKTableArray
from spsdk.utils.config import Config
from spsdk.utils.misc import align, bytes_to_print, load_binary, write_file
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
    SUPPORTED_SIGNATURES_CNT = 1

    DIFF_ATTRIBUTES_VALUES = [
        "_srk_assets_offset",
        "_certificate_offset",
        "_blob_offset",
        "_signature_offset",
    ]
    DIFF_ATTRIBUTES_OBJECTS = ["srk_assets", "signature", "certificate", "blob"]

    def __init__(
        self,
        chip_config: AhabChipContainerConfig,
        srk_assets: Optional[SRKTable] = None,
        container_signature: Optional[ContainerSignature] = None,
        certificate: Optional[AhabCertificate] = None,
        blob: Optional[AhabBlob] = None,
    ):
        """Initialize the signature block object.

        :param chip_config: AHAB container chip configuration.
        :param srk_assets: SRK table.
        :param container_signature: Container signature.
        :param certificate: Container certificate.
        :param blob: Container blob.
        """
        super().__init__(tag=self.TAG, length=-1, version=self.VERSION)
        self._srk_assets_offset = 0
        self._certificate_offset = 0
        self._blob_offset = 0
        self._signature_offset = 0
        self.srk_assets = srk_assets
        self.signature = container_signature
        self.certificate = certificate
        self.blob = blob
        self.chip_config = chip_config

    def __eq__(self, other: object) -> bool:
        """Compare for equality with other Signature Block objects.

        :param other: Object to compare with.
        :return: True on match, False otherwise.
        """
        if isinstance(other, SignatureBlock):
            if (
                super().__eq__(other)  # pylint: disable=too-many-boolean-expressions
                and self._srk_assets_offset == other._srk_assets_offset
                and self._certificate_offset == other._certificate_offset
                and self._blob_offset == other._blob_offset
                and self._signature_offset == other._signature_offset
                and self.srk_assets == other.srk_assets
                and self.signature == other.signature
                and self.certificate == other.certificate
                and self.blob == other.blob
            ):
                return True

        return False

    def __len__(self) -> int:
        """Get the length of the signature block.

        :return: Length of the signature block in bytes.
        """
        if self.length <= 0:
            self.update_fields()
        return self.length

    def __repr__(self) -> str:
        """Get the string representation of the object.

        :return: String representation.
        """
        return "AHAB Signature Block"

    def __str__(self) -> str:
        """Get the readable string representation of the object.

        :return: Readable string representation.
        """
        return (
            "AHAB Signature Block:\n"
            f"  SRK Table:          {bool(self.srk_assets)}\n"
            f"  Certificate:        {bool(self.certificate)}\n"
            f"  Signature:          {bool(self.signature)}\n"
            f"  Blob:               {bool(self.blob)}"
        )

    @classmethod
    def format(cls) -> str:
        """Get the format of binary representation.

        :return: Format string for struct operations.
        """
        return (
            super().format()
            + UINT16  # certificate offset
            + UINT16  # SRK table offset
            + UINT16  # signature offset
            + UINT16  # blob offset
            + UINT32  # key_identifier if blob is used
        )

    def update_fields(self) -> None:
        """Update all fields dependent on input values."""
        # 1: Update SRK Table
        # Nothing to do with SRK Table
        last_offset = 0
        last_block_size = align(calcsize(self.format()), CONTAINER_ALIGNMENT)
        if self.srk_assets:
            self.srk_assets.update_fields()
            last_offset = self._srk_assets_offset = align(
                last_offset + last_block_size, CONTAINER_ALIGNMENT
            )
            last_block_size = len(self.srk_assets)
        else:
            self._srk_assets_offset = 0

        # 2: Update Signature (at least length)
        # Nothing to do with Signature - in this time , it MUST be ready
        if self.signature:
            last_offset = self._signature_offset = align(
                last_offset + last_block_size, CONTAINER_ALIGNMENT
            )
            last_block_size = len(self.signature)
        else:
            self._signature_offset = 0
        # 3: Optionally update Certificate
        if self.certificate:
            self.certificate.update_fields()
            last_offset = self._certificate_offset = align(
                last_offset + last_block_size, CONTAINER_ALIGNMENT
            )
            last_block_size = len(self.certificate)
        else:
            self._certificate_offset = 0
        # 4: Optionally update Blob
        if self.blob:
            last_offset = self._blob_offset = align(
                last_offset + last_block_size, CONTAINER_ALIGNMENT
            )
            last_block_size = len(self.blob)
        else:
            self._blob_offset = 0

        # 5: Update length of Signature block
        self.length = last_offset + last_block_size

    def sign_itself(self, data_to_sign: bytes) -> None:
        """Sign the container with provided data.

        :param data_to_sign: Data to be signed.
        :raises SPSDKError: When signature container is missing.
        """
        if not self.signature:
            raise SPSDKError("Cannot sign because the Signature container is missing.")
        if self.signature.signature_type == SignatureType.SRK_TABLE:
            self.signature.sign(data_to_sign)

    def export(self) -> bytes:
        """Export signature block as binary data.

        :return: Binary representation of the signature block.
        :raises SPSDKLengthError: If exported data length doesn't match container length.
        """
        extended_header = pack(
            self.format(),
            self.version,
            self.length,
            self.tag,
            self._certificate_offset,
            self._srk_assets_offset,
            self._signature_offset,
            self._blob_offset,
            self.blob.key_identifier if self.blob else RESERVED,
        )

        signature_block = bytearray(len(self))
        signature_block[0 : self.fixed_length()] = extended_header
        if self.srk_assets:
            signature_block[
                self._srk_assets_offset : self._srk_assets_offset + len(self.srk_assets)
            ] = self.srk_assets.export()
        if self.signature:
            signature_block[
                self._signature_offset : self._signature_offset + len(self.signature)
            ] = self.signature.export()
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

        :return: Verifier object with verification results.
        """

        def verify_block(
            name: str,
            obj: Optional[
                Union[SRKTable, SRKTableArray, ContainerSignature, AhabCertificate, AhabBlob]
            ],
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
                return ver

            if obj is None:
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

            if isinstance(obj, (AhabCertificate, AhabCertificateMcuPqc)):
                ver.add_child(obj.verify(verify_data))
            else:
                ver.add_child(obj.verify())

            return ver

        ret = Verifier("Signature Block", description="")
        ret.add_child(self.verify_parsed_header())
        ret.add_child(self.verify_header())
        min_offset = self.fixed_length()
        ret.add_child(
            verify_block("SRK Table", self.srk_assets, min_offset, self._srk_assets_offset)
        )
        if self.srk_assets:
            min_offset = self._srk_assets_offset + len(self.srk_assets)
        ret.add_child(verify_block("Signature", self.signature, min_offset, self._signature_offset))
        if self.signature:
            min_offset = self._signature_offset + len(self.signature)
        ret.add_child(
            verify_block(
                "Certificate",
                self.certificate,
                min_offset,
                self._certificate_offset,
                verify_data=self.srk_assets,
            )
        )
        if self.certificate:
            min_offset = self._certificate_offset + len(self.certificate)
        ret.add_child(verify_block("Blob", self.blob, min_offset, self._blob_offset))
        if self.blob:
            ret.add_record_bit_range("Key identifier", self.blob.key_identifier)

        return ret

    def verify_container_authenticity(self, data_to_sign: bytes) -> Verifier:
        """Verify container authenticity using signature verification.

        :param data_to_sign: Data to verify signature against, provided by container.
        :return: Verifier object with verification results.
        """

        def verify_signature() -> None:
            # Verify signature
            # Check if we're using DEVHSM with CMAC signature type
            is_devhsm = self.chip_config.srk_set == FlagsSrkSet.DEVHSM

            # For DEVHSM with CMAC, SRK assets are not required
            if not self.srk_assets and not is_devhsm:
                ver_sign.add_record("Signature", VerifierResult.ERROR, "Missing SRK table")
            elif used_image_key and not self.certificate:
                ver_sign.add_record("Signature", VerifierResult.ERROR, "Missing Certificate")
            elif used_image_key and self.certificate and not self.certificate.public_key_0:
                ver_sign.add_record(
                    "Signature", VerifierResult.ERROR, "Missing Certificate public key"
                )
            elif not self.signature:
                ver_sign.add_record(
                    "Signature", VerifierResult.ERROR, "Missing Signature Container"
                )
            elif not self.signature.signature_data:
                ver_sign.add_record("Signature", VerifierResult.ERROR, "Missing Signature data")
            # Add verification for DEVHSM with CMAC case
            elif is_devhsm:
                if self.signature.signature_type == SignatureType.SRK_TABLE:
                    ver_sign.add_record(
                        "Signature type for Device HSM",
                        VerifierResult.ERROR,
                        "Signature block has incorrect signature type for Device HSM",
                    )
                else:
                    ver_sign.add_record(
                        "Signature type for Device HSM",
                        VerifierResult.SUCCEEDED,
                        "Signature block has valid signature type for Device HSM",
                    )
            else:
                assert self.srk_assets
                try:
                    if used_image_key:
                        assert isinstance(
                            self.certificate, (AhabCertificate, AhabCertificateMcuPqc)
                        )
                        assert isinstance(self.certificate.public_key_0, SRKRecordV2)
                        public_key = self.certificate.public_key_0.get_public_key()

                    else:
                        public_key = self.srk_assets.get_source_keys()[self.chip_config.used_srk_id]
                except SPSDKError as exc:
                    error_type = VerifierResult.ERROR
                    if type(exc) is SPSDKUnsupportedOperation:
                        error_type = VerifierResult.WARNING
                    ver_sign.add_record(
                        "Signature",
                        error_type,
                        (
                            "Cannot restore public key to verify signature."
                            f" The key is restoring from {'certificate' if used_image_key else 'SRK'}. "
                            f"The problem raised with this reason: {str(exc)}"
                        ),
                    )
                if self.signature.signature_data == self.signature.get_dummy_signature(
                    len(self.signature.signature_data)
                ):
                    ver_sign.add_record(
                        "Signature",
                        VerifierResult.WARNING,
                        "The container has dummy signature. Must be re-signed!",
                    )
                else:
                    sign_ok = public_key.verify_signature(
                        self.signature.signature_data,
                        data_to_sign,
                        algorithm=EnumHashAlgorithm.from_label(
                            self.srk_assets.srk_records[0].hash_algorithm.label
                        ),
                        pss_padding=True,
                    )
                    ver_sign.add_record(
                        "Signature",
                        sign_ok,
                        self.signature.signature_data.hex(),
                    )

        ver_sign = Verifier("Container signing")
        # Show revoke keys
        if self.chip_config.srk_revoke_keys:
            msg = ""
            for x in range(4):
                if (self.chip_config.srk_revoke_keys >> x) & 0x01:
                    msg += f"SRK{x}"
            ver_sign.add_record("Revoke keys", VerifierResult.SUCCEEDED, msg)
        else:
            ver_sign.add_record("Revoke keys", VerifierResult.SUCCEEDED, "No SRK key is revoked")
        # Check the SRK ID against revoke keys
        if (1 << self.chip_config.used_srk_id) & self.chip_config.srk_revoke_keys:
            ver_sign.add_record(
                "Used SRK key ID",
                VerifierResult.ERROR,
                f"SRK ID {self.chip_config.used_srk_id} is revoked",
            )
        else:
            ver_sign.add_record(
                "Used SRK key ID",
                VerifierResult.SUCCEEDED,
                f"SRK ID {self.chip_config.used_srk_id}",
            )

        ver_sign.add_record(
            "SRK Table & Signature block presence", bool(self.srk_assets and self.signature)
        )
        used_image_key = bool(self.certificate and self.certificate.permission_to_sign_container)
        ver_sign.add_record(
            "Signed source", True, "Certificate image key" if used_image_key else "SRK key"
        )

        verify_signature()

        return ver_sign

    # pylint: disable=arguments-differ
    @classmethod
    def parse(cls, data: bytes, chip_config: AhabChipContainerConfig) -> Self:  # type: ignore[override]
        """Parse input binary chunk to the container object.

        :param data: Binary data with Signature block to parse.
        :param chip_config: AHAB container chip configuration.
        :return: Object recreated from the binary data.
        """
        cls.check_container_head(data).validate()
        (
            _,  # version
            container_length,
            _,  # tag
            certificate_offset,
            srk_table_offset,
            signature_offset,
            blob_offset,
            key_identifier,
        ) = unpack(cls.format(), data[: cls.fixed_length()])

        signature_block = cls(chip_config=chip_config)
        signature_block.length = container_length
        signature_block._srk_assets_offset = srk_table_offset
        signature_block._signature_offset = signature_offset
        signature_block._certificate_offset = certificate_offset
        signature_block._blob_offset = blob_offset
        try:
            signature_block.srk_assets = (
                SRKTable.parse(data[srk_table_offset:]) if srk_table_offset else None
            )
        except SPSDKParsingError:
            signature_block.srk_assets = None
        try:
            signature_block.certificate = (
                get_ahab_certificate_class(chip_config.base.family).parse(
                    data[certificate_offset:], chip_config.base.family
                )
                if certificate_offset
                else None
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
            srk_assets_offset,
            signature_offset,
            blob_offset,
            _,  # key_identifier
        ) = unpack(SignatureBlock.format(), data[: SignatureBlock.fixed_length()])

        if srk_assets_offset:
            ret.add_record(
                "SRK Table offset 64-bit alignment",
                srk_assets_offset == align(srk_assets_offset, CONTAINER_ALIGNMENT),
                str(srk_assets_offset),
            )
            ret.add_child(SRKTable.pre_parse_verify(data[srk_assets_offset:]))
            if not signature_offset:
                ret.add_record(
                    "Signature",
                    VerifierResult.ERROR,
                    "Signature is missing, although the SRK Table (Array) is present",
                )
            else:
                ret.add_record(
                    "Signature container offset 64-bit alignment",
                    signature_offset == align(signature_offset, CONTAINER_ALIGNMENT),
                    str(signature_offset),
                )
                ret.add_child(ContainerSignature.check_container_head(data[signature_offset:]))
        elif signature_offset:
            ret.add_record(
                "Signature",
                VerifierResult.ERROR,
                "Signature is present, although the SRK Table (Array) is missing",
            )
        if certificate_offset:
            ret.add_record(
                "Certificate container offset 64-bit alignment",
                certificate_offset == align(certificate_offset, CONTAINER_ALIGNMENT),
                str(certificate_offset),
            )
            ret.add_child(AhabCertificate.check_container_head(data[certificate_offset:]))
        if blob_offset:
            ret.add_record(
                "Blob container offset 64-bit alignment",
                blob_offset == align(blob_offset, CONTAINER_ALIGNMENT),
                str(blob_offset),
            )
            ret.add_child(AhabBlob.check_container_head(data[blob_offset:]))
        return ret

    @classmethod
    def load_from_config(cls, config: Config, chip_config: AhabChipContainerConfig) -> Self:
        """Converts the configuration option into an AHAB Signature block object.

        "config" content of container configurations.

        :param config: array of AHAB signature block configuration dictionaries.
        :param chip_config: AHAB container chip configuration.
        :return: AHAB Signature block object.
        """
        signature_block = cls(chip_config=chip_config)
        # SRK Table
        signature_block.srk_assets = (
            SRKTable.load_from_config(config.get_config("srk_table"))
            if "srk_table" in config
            else None
        )

        # Container Signature
        srk_set = config.get_str("srk_set", "none")
        signature_block.signature = (
            ContainerSignature.load_from_config(config, signature_block.srk_assets)
            if srk_set != "none"
            else None
        )

        # Certificate Block
        signature_block.certificate = None

        if "certificate" in config:
            try:
                cert_cfg = config.load_sub_config("certificate")
                cert_cfg.check(
                    get_ahab_certificate_class(chip_config.base.family).get_validation_schemas(
                        family=chip_config.base.family
                    ),
                    check_unknown_props=True,
                )
                signature_block.certificate = get_ahab_certificate_class(
                    chip_config.base.family
                ).load_from_config(cert_cfg)
            except SPSDKError:
                # this could be pre-exported binary certificate :-)
                signature_block.certificate = get_ahab_certificate_class(
                    chip_config.base.family
                ).parse(
                    load_binary(config.get_input_file_name("certificate")), chip_config.base.family
                )

        # DEK blob
        signature_block.blob = (
            AhabBlob.load_from_config(config.get_config("blob")) if "blob" in config else None
        )

        return signature_block

    def get_config(self, index: int, data_path: str) -> Config:
        """Create configuration of the AHAB Image.

        :param index: Container index.
        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        cfg = Config()

        if self.signature:
            cfg["signer"] = "N/A"

        if self.srk_assets:
            cfg["srk_table"] = self.srk_assets.get_config(data_path, index)

        if self.certificate:
            write_file(
                self.certificate.get_config_yaml(
                    data_path, index=index, srk_set=self.chip_config.srk_set
                ),
                os.path.join(data_path, "certificate.yaml"),
            )
            cfg["certificate"] = "certificate.yaml"

        if self.blob:
            cfg["blob"] = self.blob.get_config(data_path, index)

        return cfg


class SignatureBlockV2(HeaderContainer):
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
        |                          SRK Table  Array                        |     |
        +------------------------------------------------------------------+-----+ Starting offset
        |                              Signature                           |     |
        +------------------------------------------------------------------+-----+ Starting offset
        |                              Certificate                         |     |
        +------------------------------------------------------------------+-----+ Starting offset
        |                              Blob                                |     |
        +------------------------------------------------------------------+-----+

    """

    TAG = AHABTags.SIGNATURE_BLOCK.tag
    VERSION = 0x01

    SUPPORTED_SIGNATURES_CNT = 2
    # DIFF_ATTRIBUTES_VALUES = [
    #     "_srk_assets_offset",
    #     "_certificate_offset",
    #     "_blob_offset",
    #     "_signature_offset",
    # ]
    DIFF_ATTRIBUTES_OBJECTS = ["srk_assets", "signature", "signature_2", "certificate", "blob"]

    def __init__(
        self,
        chip_config: AhabChipContainerConfig,
        srk_assets: Optional[SRKTableArray] = None,
        container_signature: Optional[ContainerSignature] = None,
        certificate: Optional[AhabCertificate] = None,
        blob: Optional[AhabBlob] = None,
        container_signature_2: Optional[ContainerSignature] = None,
    ):
        """Class object initializer.

        :param chip_config: AHAB container chip configuration.
        :param srk_assets: SRK table.
        :param chip_config: AHAB container chip configuration.
        :param container_signature: Container signature # 1.
        :param certificate: container certificate.
        :param blob: container blob.
        :param container_signature_2: Container signature # 2, defaults to None
        """
        super().__init__(tag=self.TAG, length=-1, version=self.VERSION)
        self._srk_assets_offset = 0
        self._certificate_offset = 0
        self._blob_offset = 0
        self._signature_offset = 0
        self.srk_assets = srk_assets
        self.signature = container_signature
        self.signature_2 = container_signature_2
        self.certificate = certificate
        self.blob = blob
        self.chip_config = chip_config

    def __eq__(self, other: object) -> bool:
        """Compares for equality with other Signature Block objects.

        :param other: object to compare with.
        :return: True on match, False otherwise.
        """
        if isinstance(other, SignatureBlockV2):
            if (
                super().__eq__(other)  # pylint: disable=too-many-boolean-expressions
                and self._srk_assets_offset == other._srk_assets_offset
                and self._certificate_offset == other._certificate_offset
                and self._blob_offset == other._blob_offset
                and self._signature_offset == other._signature_offset
                and self.srk_assets == other.srk_assets
                and self.signature == other.signature
                and self.signature_2 == other.signature_2
                and self.certificate == other.certificate
                and self.blob == other.blob
            ):
                return True

        return False

    def __len__(self) -> int:
        if self.length <= 0:
            self.update_fields()
        return self.length

    def __repr__(self) -> str:
        return "AHAB Signature Block V2"

    def __str__(self) -> str:
        return (
            "AHAB Signature Block:\n"
            f"  SRK Table Array:    {bool(self.srk_assets)}\n"
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
        last_block_size = calcsize(self.format())
        if self.srk_assets:
            self.srk_assets.update_fields()
            last_offset = self._srk_assets_offset = last_offset + last_block_size
            last_block_size = len(self.srk_assets)
        else:
            self._srk_assets_offset = 0

        # 2: Update Signature (at least length)
        # Nothing to do with Signature - in this time , it MUST be ready
        if self.signature:
            last_offset = self._signature_offset = last_offset + last_block_size
            last_block_size = len(self.signature)
            if self.signature_2:
                last_block_size += len(self.signature_2)
        else:
            self._signature_offset = 0
        # 3: Optionally update Certificate
        if self.certificate:
            self.certificate.update_fields()
            last_offset = self._certificate_offset = last_offset + last_block_size
            last_block_size = len(self.certificate)
        else:
            self._certificate_offset = 0
        # 4: Optionally update Blob
        if self.blob:
            last_offset = self._blob_offset = last_offset + last_block_size
            last_block_size = len(self.blob)
        else:
            self._blob_offset = 0

        # 5: Update length of Signature block
        self.length = last_offset + last_block_size

    def sign_itself(self, data_to_sign: bytes) -> None:
        """Sign the container with provided data.

        Signs both the primary and secondary (PQC) signatures if applicable.

        :param data_to_sign: Data to be signed.
        :raises SPSDKError: When signature container or SRK table array is missing.
        """
        if not self.signature:
            raise SPSDKError("Cannot sign because the Signature container is missing.")
        if self.signature.signature_type == SignatureType.CMAC:
            logger.debug("Skipping signature for CMAC type")
            return
        if not self.srk_assets:
            raise SPSDKError("Cannot sign because the SRK table array container is missing.")

        self.signature.sign(data_to_sign)
        if len(self.srk_assets._srk_tables) == 2:
            if not self.signature_2:
                raise SPSDKError("Cannot sign because the Signature 2 (PQC) container is missing.")
            self.signature_2.sign(data_to_sign)

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
            self._srk_assets_offset,
            self._signature_offset,
            self._blob_offset,
            self.blob.key_identifier if self.blob else RESERVED,
        )

        signature_block = bytearray(len(self))
        signature_block[0 : self.fixed_length()] = extended_header
        if self.srk_assets:
            signature_block[
                self._srk_assets_offset : self._srk_assets_offset + len(self.srk_assets)
            ] = self.srk_assets.export()

        if self.signature:
            signature_block[
                self._signature_offset : self._signature_offset + len(self.signature)
            ] = self.signature.export()
            if self.signature_2:
                signature_offset_2 = self._signature_offset + len(self.signature)
                signature_block[signature_offset_2 : signature_offset_2 + len(self.signature_2)] = (
                    self.signature_2.export()
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
            obj: Optional[
                Union[SRKTable, SRKTableArray, ContainerSignature, AhabCertificate, AhabBlob]
            ],
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
                return ver

            if obj is None:
                ver.add_record("Block", VerifierResult.SUCCEEDED, "Not used")
                return ver

            if offset < min_offset:
                ver.add_record(
                    "Offset",
                    VerifierResult.ERROR,
                    f"Invalid: {offset} < minimal offset {min_offset}",
                )
            else:
                ver.add_record_bit_range("Offset", offset, 16)

            if isinstance(obj, (AhabCertificate, AhabCertificateMcuPqc)):
                ver.add_child(obj.verify(verify_data))
            else:
                ver.add_child(obj.verify())

            return ver

        ret = Verifier("Signature Block", description="")
        ret.add_child(self.verify_parsed_header())
        ret.add_child(self.verify_header())
        min_offset = self.fixed_length()
        ret.add_child(
            verify_block("SRK Table", self.srk_assets, min_offset, self._srk_assets_offset)
        )
        if self.srk_assets:
            min_offset = self._srk_assets_offset + len(self.srk_assets)
        ret.add_child(verify_block("Signature", self.signature, min_offset, self._signature_offset))
        if self.signature:
            min_offset = self._signature_offset + len(self.signature)

        signature_cnt = 0
        if self.srk_assets:
            signature_cnt = len(self.srk_assets._srk_tables)

        target_ver = ret

        if signature_cnt < 2:
            if self.signature_2:
                target_ver.add_record(
                    "PQC Signature",
                    VerifierResult.ERROR,
                    "Should not be present, because is not mentioned in SRK Table Array",
                )
            else:
                target_ver.add_record(
                    "PQC Signature",
                    VerifierResult.SUCCEEDED,
                    "Not present, as SRK Table Array declare",
                )
        else:
            if self.signature_2:
                target_ver.add_child(self.signature_2.verify(), prefix_name="PQC Signature")
                min_offset += len(self.signature_2)
            else:
                target_ver.add_record("PQC Signature", VerifierResult.ERROR, "Missing")

        ret.add_child(
            verify_block(
                "Certificate",
                self.certificate,
                min_offset,
                self._certificate_offset,
                verify_data=self.srk_assets,
            )
        )
        if self.certificate:
            min_offset = self._certificate_offset + len(self.certificate)
        ret.add_child(verify_block("Blob", self.blob, min_offset, self._blob_offset))
        if self.blob:
            ret.add_record_bit_range("Key identifier", self.blob.key_identifier)

        return ret

    def verify_container_authenticity(self, data_to_sign: bytes) -> Verifier:
        """Verify container authenticity.

        :param data_to_sign: Data to sign provided by container.
        :return: Verifier object with result.
        """
        # Define used_image_key at the beginning
        used_image_key = False

        def verify_signature(ix: int) -> Verifier:
            # Verify signature
            ver_sign = Verifier(f"Signature #{ix}")
            signature_container = self.signature if ix == 0 else self.signature_2
            # Check if we're using DEVHSM with CMAC signature type
            is_devhsm = self.chip_config.srk_set == FlagsSrkSet.DEVHSM

            # For DEVHSM with CMAC, SRK assets are not required
            if not self.srk_assets and not is_devhsm:
                ver_sign.add_record("Signature", VerifierResult.ERROR, "Missing SRK table array")
            elif not is_devhsm and len(self.srk_assets._srk_tables) < (ix + 1):  # type: ignore
                assert self.srk_assets
                ver_sign.add_record("Signature", VerifierResult.ERROR, f"Missing SRK table {ix}")
            elif not is_devhsm and used_image_key and not self.certificate:
                ver_sign.add_record("Signature", VerifierResult.ERROR, "Missing Certificate")
            elif (
                not is_devhsm
                and used_image_key
                and self.certificate
                and self.certificate.verify(self.srk_assets).has_errors
            ):
                ver_sign.add_record("Signature", VerifierResult.ERROR, "Invalid Certificate")
            elif not signature_container:
                ver_sign.add_record(
                    "Signature", VerifierResult.ERROR, "Missing Signature Container"
                )
            elif not signature_container.signature_data:
                ver_sign.add_record("Signature", VerifierResult.ERROR, "Missing Signature data")
            # Add verification for DEVHSM with CMAC case
            elif is_devhsm:
                if signature_container.signature_type == SignatureType.SRK_TABLE:
                    ver_sign.add_record(
                        "Signature type for Device HSM",
                        VerifierResult.ERROR,
                        "Signature block has incorrect signature type for Device HSM",
                    )
                else:
                    ver_sign.add_record(
                        "Signature type for Device HSM",
                        VerifierResult.SUCCEEDED,
                        "Signature block has valid signature type for Device HSM",
                    )
            else:
                public_key = None
                assert self.srk_assets
                try:
                    if used_image_key:
                        assert isinstance(
                            self.certificate, (AhabCertificate, AhabCertificateMcuPqc)
                        )
                        if ix == 0:
                            assert isinstance(self.certificate.public_key_0, SRKRecordV2)
                            public_key = self.certificate.public_key_0.get_public_key()
                        else:
                            assert isinstance(self.certificate.public_key_1, SRKRecordV2)
                            public_key = self.certificate.public_key_1.get_public_key()

                    else:
                        public_key = (
                            self.srk_assets._srk_tables[ix]
                            .srk_records[self.chip_config.used_srk_id]
                            .get_public_key()
                        )

                except SPSDKError as exc:
                    error_type = VerifierResult.ERROR
                    if type(exc) is SPSDKUnsupportedOperation:
                        error_type = VerifierResult.WARNING
                    ver_sign.add_record(
                        "Signature",
                        error_type,
                        (
                            "Cannot restore public key to verify signature."
                            f" The key is restoring from {'certificate' if used_image_key else 'SRK'}. "
                            f"The problem raised with this reason: {str(exc)}"
                        ),
                    )
                if signature_container.signature_data == signature_container.get_dummy_signature(
                    len(signature_container.signature_data)
                ):
                    ver_sign.add_record(
                        "Signature",
                        VerifierResult.WARNING,
                        "The container has dummy signature. Must be re-signed!",
                    )
                elif public_key is not None:
                    sign_ok = public_key.verify_signature(
                        signature_container.signature_data,
                        data_to_sign,
                        algorithm=EnumHashAlgorithm.from_label(
                            self.srk_assets._srk_tables[ix].srk_records[0].hash_algorithm.label
                        ),
                        pss_padding=True,
                    )

                    ver_sign.add_record(
                        "Signature",
                        sign_ok,
                        bytes_to_print(signature_container.signature_data),
                    )
            return ver_sign

        ret = Verifier("Container signing")
        if self.chip_config.srk_set == FlagsSrkSet.DEVHSM:
            sign_count = 1  # in case of devhsm there is just only ony symmetrical signature
        else:
            # Show revoke keys
            if self.chip_config.srk_revoke_keys:
                msg = ""
                for x in range(4):
                    if (self.chip_config.srk_revoke_keys >> x) & 0x01:
                        msg += f"SRK{x}"
                ret.add_record("Revoke keys", VerifierResult.SUCCEEDED, msg)
            else:
                ret.add_record("Revoke keys", VerifierResult.SUCCEEDED, "No SRK key is revoked")
            # Check the SRK ID against revoke keys
            if (1 << self.chip_config.used_srk_id) & self.chip_config.srk_revoke_keys:
                ret.add_record(
                    "Used SRK key ID",
                    VerifierResult.ERROR,
                    f"SRK ID {self.chip_config.used_srk_id} is revoked",
                )
            else:
                ret.add_record(
                    "Used SRK key ID",
                    VerifierResult.SUCCEEDED,
                    f"SRK ID {self.chip_config.used_srk_id}",
                )
            if self.signature and self.signature.signature_type == SignatureType.SRK_TABLE:
                assert self.srk_assets
                ret.add_record(
                    "SRK Table & Signature block presence", bool(self.srk_assets and self.signature)
                )
                used_image_key = bool(
                    self.certificate and self.certificate.permission_to_sign_container
                )
                ret.add_record(
                    "Signed source", True, "Certificate image key" if used_image_key else "SRK key"
                )
                sign_count = len(self.srk_assets._srk_tables)
                ret.add_record_range("Signature counts", value=sign_count, min_val=1, max_val=2)

                for i in range(sign_count):
                    ret.add_child(verify_signature(i))
            else:
                ret.add_record("SRK Table block presence", not bool(self.srk_assets))
                ret.add_record("Certificate block presence", not bool(self.certificate))
                ret.add_record("Signature 2 block presence", not bool(self.signature_2))
                ret.add_child(verify_signature(0))

        return ret

    # pylint: disable=arguments-differ
    @classmethod
    def parse(cls, data: bytes, chip_config: AhabChipContainerConfig) -> Self:  # type: ignore[override]
        """Parse input binary chunk to the container object.

        :param data: Binary data with Signature block to parse.
        :param chip_config: AHAB container chip configuration.
        :return: Object recreated from the binary data.
        """
        cls.check_container_head(data).validate()
        (
            _,  # version
            container_length,
            _,  # tag
            certificate_offset,
            srk_assets_offset,
            signature_offset,
            blob_offset,
            key_identifier,
        ) = unpack(cls.format(), data[: cls.fixed_length()])

        signature_block = cls(chip_config=chip_config)
        signature_block.length = container_length
        signature_block._srk_assets_offset = srk_assets_offset
        signature_block._signature_offset = signature_offset
        signature_block._certificate_offset = certificate_offset
        signature_block._blob_offset = blob_offset
        try:
            signature_block.srk_assets = (
                SRKTableArray.parse(data[srk_assets_offset:], chip_config=chip_config)
                if srk_assets_offset
                else None
            )
        except SPSDKParsingError:
            signature_block.srk_assets = None

        try:
            signature_block.certificate = (
                get_ahab_certificate_class(chip_config.base.family).parse(
                    data[certificate_offset:], chip_config.base.family
                )
                if certificate_offset
                else None
            )
        except SPSDKParsingError:
            signature_block.certificate = None

        try:
            signature_block.signature = None
            signature_block.signature_2 = None
            if signature_offset:
                signature_block.signature = ContainerSignature.parse(data[signature_offset:])
                if signature_block.srk_assets and len(signature_block.srk_assets._srk_tables) == 2:
                    signature_block.signature_2 = ContainerSignature.parse(
                        data[signature_offset + len(signature_block.signature) :]
                    )
        except SPSDKParsingError:
            signature_block.signature = None
            signature_block.signature_2 = None

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
            srk_assets_offset,
            signature_offset,
            blob_offset,
            _,  # key_identifier
        ) = unpack(SignatureBlock.format(), data[: SignatureBlock.fixed_length()])

        if srk_assets_offset:
            ret.add_child(SRKTableArray.pre_parse_verify(data[srk_assets_offset:]))
            if not signature_offset:
                ret.add_record(
                    "Signature",
                    VerifierResult.ERROR,
                    "Signature is missing, although the SRK Table (Array) is present",
                )
            else:
                ret.add_child(ContainerSignature.check_container_head(data[signature_offset:]))
                srk_tab_arr_header_size = SRKTableArray.fixed_length()
                _, _, _, _, _, tables_cnt = unpack(
                    SRKTableArray.format(),
                    data[srk_assets_offset : srk_assets_offset + srk_tab_arr_header_size],
                )
                if tables_cnt == 2:
                    # Get length of first signature
                    _, length, _ = ContainerSignature.parse_head(data[signature_offset:])
                    # Add to verifier second signature pre parse verifier
                    ret.add_child(
                        ContainerSignature.check_container_head(data[signature_offset + length :]),
                        prefix_name="PQC Signature",
                    )

        elif signature_offset:
            ret.add_record(
                "Signature",
                VerifierResult.ERROR,
                "Signature is present, although the SRK Table (Array) is missing",
            )

        if certificate_offset:
            ret.add_child(AhabCertificate.check_container_head(data[certificate_offset:]))

        if blob_offset:
            ret.add_child(AhabBlob.check_container_head(data[blob_offset:]))
        return ret

    @classmethod
    def load_from_config(cls, config: Config, chip_config: AhabChipContainerConfig) -> Self:
        """Converts the configuration option into an AHAB Signature block object.

        "config" content of container configurations.

        :param config: array of AHAB signature block configuration dictionaries.
        :param chip_config: AHAB container chip configuration.
        :return: AHAB Signature block object.
        """
        signature_block = cls(chip_config=chip_config)
        # SRK Table Array
        signature_block.srk_assets = (
            SRKTableArray.load_from_config(config.get_config("srk_table"), chip_config=chip_config)
            if "srk_table" in config
            else None
        )

        # Container Signature
        srk_set = config.get_str("srk_set", "none")
        signature_block.signature = None
        if srk_set != "none":
            if signature_block.srk_assets is None:
                raise SPSDKError(
                    "Cannot load Container signature configuration"
                    " when the SRK keys are not defined."
                )
            signature_block.signature = ContainerSignature.load_from_config(
                config, signature_block.srk_assets._srk_tables[0]
            )
            if len(signature_block.srk_assets._srk_tables) == 2:
                temp_cfg = Config()
                temp_cfg.search_paths = config.search_paths
                if "signer_#2" in config:
                    temp_cfg["signer"] = config["signer_#2"]
                signature_block.signature_2 = ContainerSignature.load_from_config(
                    temp_cfg, signature_block.srk_assets._srk_tables[1]
                )

        # Certificate Block
        signature_block.certificate = None
        if "certificate" in config:
            try:
                cert_cfg = config.load_sub_config("certificate")
                cert_cfg.check(
                    get_ahab_certificate_class(chip_config.base.family).get_validation_schemas(
                        family=chip_config.base.family
                    ),
                    check_unknown_props=True,
                )
                signature_block.certificate = get_ahab_certificate_class(
                    chip_config.base.family
                ).load_from_config(cert_cfg)
            except SPSDKError:
                # this could be pre-exported binary certificate :-)
                signature_block.certificate = get_ahab_certificate_class(
                    chip_config.base.family
                ).parse(
                    load_binary(config.get_input_file_name("certificate")), chip_config.base.family
                )

        # DEK blob
        signature_block.blob = (
            AhabBlob.load_from_config(config.get_config("blob")) if "blob" in config else None
        )

        return signature_block

    def get_config(self, index: int, data_path: str) -> Config:
        """Create configuration of the AHAB Image.

        :param index: Container index.
        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        cfg = Config()

        if self.signature:
            cfg["signer"] = "N/A"

        if self.signature_2:
            cfg["signer_#2"] = "N/A"

        if self.srk_assets:
            cfg["srk_table"] = self.srk_assets.get_config(data_path, index)

        if self.certificate:
            write_file(
                self.certificate.get_config_yaml(
                    data_path, index=index, srk_set=self.chip_config.srk_set
                ),
                os.path.join(data_path, "certificate.yaml"),
            )
            cfg["certificate"] = "certificate.yaml"

        if self.blob:
            cfg["blob"] = self.blob.get_config(data_path, index)

        return cfg
