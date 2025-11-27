#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK SB2 boot image generation and management utilities.

This module provides functionality for creating and managing Secure Binary version 2.0
and 2.1 boot images, including advanced parameter configuration and image processing
capabilities for NXP MCU secure provisioning.
"""

import logging
import os
from datetime import datetime
from typing import Any, Iterator, Optional

from typing_extensions import Self

from spsdk.crypto.certificate import Certificate
from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.crypto.rng import random_bytes
from spsdk.crypto.signature_provider import SignatureProvider, get_signature_provider
from spsdk.crypto.spsdk_hmac import hmac
from spsdk.crypto.symmetric import Counter, aes_key_unwrap, aes_key_wrap
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.image.cert_block.cert_blocks import CertBlockV1
from spsdk.sbfile.misc import SecBootBlckSize
from spsdk.sbfile.sb2 import sly_bd_parser as bd_parser
from spsdk.sbfile.sb2.commands import CmdHeader
from spsdk.sbfile.sb2.headers import ImageHeaderV2
from spsdk.sbfile.sb2.sb_21_helper import SB21Helper
from spsdk.sbfile.sb2.sections import BootSectionV2, CertSectionV2
from spsdk.utils.abstract import BaseClass
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, get_db, get_families, update_validation_schema_family
from spsdk.utils.misc import (
    find_first,
    load_hex_string,
    load_text,
    value_to_bool,
    value_to_bytes,
    value_to_int,
    write_file,
)
from spsdk.utils.schema_validator import CommentedConfig

logger = logging.getLogger(__name__)


class SBV2xAdvancedParams:
    """SBV2x Advanced Parameters Manager.

    This class manages advanced encryption parameters for SB file generation including
    DEK/MAC keys, nonce, timestamp, and padding. Primarily used for testing scenarios
    where deterministic values are needed, while production usage typically relies on
    default random values and current timestamps.
    """

    @staticmethod
    def _create_nonce() -> bytes:
        """Generate a random 16-byte nonce with specific bit clearing.

        Creates a cryptographically secure random nonce where bits at positions 31 and 63
        are cleared to zero. This ensures compatibility with specific cryptographic
        protocols that require these bits to be unset.

        :return: 16-byte random nonce with cleared bits at positions 31 and 63.
        """
        nonce = bytearray(random_bytes(16))
        # clear nonce bit at offsets 31 and 63
        nonce[9] &= 0x7F
        nonce[13] &= 0x7F
        return bytes(nonce)

    def __init__(
        self,
        dek: Optional[bytes] = None,
        mac: Optional[bytes] = None,
        nonce: Optional[bytes] = None,
        timestamp: Optional[datetime] = None,
        padding: Optional[bytes] = None,
    ):
        """Initialize SBV2xAdvancedParams.

        Creates advanced parameters for SB2.x file generation with encryption keys, nonce, timestamp and padding.
        If parameters are not provided, secure random values or current timestamp will be used.

        :param dek: DEK (Data Encryption Key) - must be 32 bytes if provided.
        :param mac: MAC (Message Authentication Code) key - must be 32 bytes if provided.
        :param nonce: Cryptographic nonce - must be 16 bytes if provided.
        :param timestamp: Fixed timestamp for the header; use None to use current date/time.
        :param padding: Header padding (8 bytes) for testing purpose; None to use random values
            (recommended).
        :raises SPSDKError: Invalid dek or mac key length.
        :raises SPSDKError: Invalid length of nonce.
        """
        self._dek: bytes = dek if dek else random_bytes(32)
        self._mac: bytes = mac if mac else random_bytes(32)
        self._nonce: bytes = nonce if nonce else SBV2xAdvancedParams._create_nonce()
        self._padding: bytes = padding if padding else random_bytes(8)
        if timestamp is None:
            timestamp = datetime.now()
        self._timestamp = datetime.fromtimestamp(int(timestamp.timestamp()))
        if len(self._dek) != 32 and len(self._mac) != 32:
            raise SPSDKError("Invalid dek or mac")
        if len(self._nonce) != 16:
            raise SPSDKError("Invalid length of nonce")

    def __str__(self) -> str:
        """String representation of advanced parameters.

        Returns a formatted string containing DEK, MAC, nonce, timestamp, and padding values
        in hexadecimal format for debugging and display purposes.

        :return: Formatted string with all advanced parameters and their values.
        """
        return (
            f"Advanced params: \nDEK: {self.dek.hex()}\n"
            + f"MAC: {self.mac.hex()}\n"
            + f"nonce: {self.nonce.hex()}\n"
            + f"timestamp: {self.timestamp}\n"
            + f"padding: {self.padding.hex()}\n"
        )

    @property
    def dek(self) -> bytes:
        """Get DEK (Data Encryption Key).

        :return: The DEK key as bytes.
        """
        return self._dek

    @property
    def mac(self) -> bytes:
        """Get MAC key.

        :return: MAC key as bytes.
        """
        return self._mac

    @property
    def nonce(self) -> bytes:
        """Get the NONCE value.

        :return: The NONCE as bytes.
        """
        return self._nonce

    @property
    def timestamp(self) -> datetime:
        """Get the timestamp of the SB2 image.

        :return: Timestamp when the image was created.
        """
        return self._timestamp

    @property
    def padding(self) -> bytes:
        """Get the padding bytes for the image.

        :return: Padding bytes as a byte string.
        """
        return self._padding

    @property
    def zero_padding(self) -> bool:
        """Check if the padding bytes are all zeros.

        :return: True if padding consists of 8 zero bytes, False otherwise.
        """
        return self._padding == b"\x00" * 8


########################################################################################################################
# Secure Binary Image Class (Version 2.0)
########################################################################################################################
class BootImageV20(BaseClass):
    """Secure Binary Image V2.0 container for NXP MCU secure provisioning.

    This class manages the creation and manipulation of Secure Binary (SB) version 2.0 image files,
    including encryption, signing, and section management for secure firmware deployment on NXP
    microcontrollers.

    :cvar HEADER_MAC_SIZE: Size of the MAC key in bytes (32).
    :cvar DEK_MAC_SIZE: Size of AES encrypted DEK and MAC including padding (80).
    :cvar KEY_BLOB_SIZE: Size of the key blob structure (80).
    """

    # Image specific data
    # size of the MAC key
    HEADER_MAC_SIZE = 32
    # AES encrypted DEK and MAC, including padding
    DEK_MAC_SIZE = 32 + 32 + 16

    KEY_BLOB_SIZE = 80

    def __init__(
        self,
        signed: bool,
        kek: bytes,
        *sections: BootSectionV2,
        product_version: str = "1.0.0",
        component_version: str = "1.0.0",
        build_number: int = 0,
        advanced_params: SBV2xAdvancedParams = SBV2xAdvancedParams(),
    ) -> None:
        """Initialize Secure Binary Image V2.0.

        Creates a new instance of Secure Binary Image version 2.0 with specified configuration
        parameters and boot sections.

        :param signed: True if image is signed, False otherwise
        :param kek: Key for wrapping DEK and MAC keys
        :param sections: Boot sections to be included in the image
        :param product_version: The product version (default: 1.0.0)
        :param component_version: The component version (default: 1.0.0)
        :param build_number: The build number value (default: 0)
        :param advanced_params: Advanced parameters for encryption of the SB file, use for tests only
        :raises SPSDKError: Invalid dek or mac
        """
        self._kek = kek
        # Set Flags value
        self._signed = signed
        self.signature_provider: Optional[SignatureProvider] = None
        flags = 0x08 if self.signed else 0x04
        # Set private attributes
        self._dek: bytes = advanced_params.dek
        self._mac: bytes = advanced_params.mac
        if (
            len(self._dek) != self.HEADER_MAC_SIZE and len(self._mac) != self.HEADER_MAC_SIZE
        ):  # pragma: no cover # condition checked in SBV2xAdvancedParams constructor
            raise SPSDKError("Invalid dek or mac")
        self._header = ImageHeaderV2(
            version="2.0",
            product_version=product_version,
            component_version=component_version,
            build_number=build_number,
            flags=flags,
            nonce=advanced_params.nonce,
            timestamp=advanced_params.timestamp,
        )
        self._cert_section: Optional[CertSectionV2] = None
        self._boot_sections: list[BootSectionV2] = []
        # Generate nonce
        if self._header.nonce is None:
            nonce = bytearray(random_bytes(16))
            # clear nonce bit at offsets 31 and 63
            nonce[9] &= 0x7F
            nonce[13] &= 0x7F
            self._header.nonce = bytes(nonce)
        # Sections
        for section in sections:
            self.add_boot_section(section)

    @property
    def header(self) -> ImageHeaderV2:
        """Get image header.

        :return: Image header containing metadata and configuration information.
        """
        return self._header

    @property
    def dek(self) -> bytes:
        """Get data encryption key.

        :return: Data encryption key as bytes.
        """
        return self._dek

    @property
    def mac(self) -> bytes:
        """Get message authentication code.

        :return: Message authentication code as bytes.
        """
        return self._mac

    @property
    def kek(self) -> bytes:
        """Return key for wrapping DEK and MAC keys.

        :return: KEK (Key Encryption Key) used for wrapping DEK and MAC keys.
        """
        return self._kek

    @property
    def signed(self) -> bool:
        """Check whether SB file is signed and encrypted or only encrypted.

        :return: True if the SB file is signed and encrypted, False if only encrypted.
        """
        return self._signed

    @property
    def cert_block(self) -> Optional[CertBlockV1]:
        """Get certificate block from the SB file.

        The method retrieves the certificate block from the certificate section if the SB file
        is signed and the block has been assigned.

        :return: Certificate block if available, None if SB file is not signed or block is not
            assigned yet.
        """
        cert_sect = self._cert_section
        if cert_sect is None:
            return None

        return cert_sect.cert_block

    @cert_block.setter
    def cert_block(self, value: Optional[CertBlockV1]) -> None:
        """Set certificate block for the SB file.

        Assigns a certificate block to the SB file or removes previously assigned block.
        The certificate block can only be used when the SB file is configured as signed.

        :param value: Certificate block to be assigned; None to remove previously assigned block
        :raises SPSDKError: When certificate block is used when SB file is not signed
        """
        if value is not None:
            if not self.signed:
                raise SPSDKError("Certificate block cannot be used unless SB file is signed")
        self._cert_section = CertSectionV2(value) if value else None

    @property
    def cert_header_size(self) -> int:
        """Calculate the raw size (not aligned) for certificate header.

        The size includes the image header, MAC, key blob, and all boot sections.

        :return: Total raw size in bytes for the certificate header.
        """
        size = ImageHeaderV2.SIZE + self.HEADER_MAC_SIZE + self.KEY_BLOB_SIZE
        for boot_section in self._boot_sections:
            size += boot_section.raw_size
        return size

    @property
    def raw_size_without_signature(self) -> int:
        """Return image raw size without signature, used to calculate image blocks.

        The method calculates the total size including header, HMAC, key blob,
        certificates section (if signed), and all boot sections.

        :raises SPSDKError: When certification block is not present for signed image.
        :return: Total raw size in bytes without signature.
        """
        # Header, HMAC and KeyBlob
        size = ImageHeaderV2.SIZE + self.HEADER_MAC_SIZE + self.KEY_BLOB_SIZE
        # Certificates Section
        if self.signed:
            size += self.DEK_MAC_SIZE
            cert_block = self.cert_block
            if not cert_block:
                raise SPSDKError("Certification block not present")
            size += cert_block.raw_size
        # Boot Sections
        for boot_section in self._boot_sections:
            size += boot_section.raw_size
        return size

    @property
    def raw_size(self) -> int:
        """Get the total raw size of the image including signature if present.

        The method calculates the complete raw size by adding the signature size
        to the base raw size when the image is signed.

        :raises SPSDKError: Certificate block not present for signed image.
        :return: Total raw size of the image in bytes.
        """
        size = self.raw_size_without_signature

        if self.signed:
            cert_block = self.cert_block
            if not cert_block:  # pragma: no cover # already checked in raw_size_without_signature
                raise SPSDKError("Certificate block not present")
            size += cert_block.signature_size

        return size

    def __len__(self) -> int:
        """Get the number of boot sections in the image.

        :return: Number of boot sections.
        """
        return len(self._boot_sections)

    def __getitem__(self, key: int) -> BootSectionV2:
        """Get boot section at specified index.

        :param key: Index of the boot section to retrieve.
        :raises IndexError: If the index is out of range.
        :return: Boot section at the specified index.
        """
        return self._boot_sections[key]

    def __setitem__(self, key: int, value: BootSectionV2) -> None:
        """Set boot section at specified index.

        Assigns a boot section to the specified index in the boot sections collection.

        :param key: Index where to store the boot section.
        :param value: Boot section to be stored at the specified index.
        """
        self._boot_sections[key] = value

    def __iter__(self) -> Iterator[BootSectionV2]:
        """Return iterator over boot sections.

        Provides iteration capability over the collection of boot sections in the SB2 image.

        :return: Iterator yielding BootSectionV2 objects from the internal boot sections collection.
        """
        return self._boot_sections.__iter__()

    def update(self) -> None:
        """Update boot image header and internal structures.

        This method recalculates and updates various header fields including boot section IDs,
        block sizes, offsets, and MAC counts. It also updates certificate block headers if
        present and sets appropriate flags based on whether the image is signed.
        """
        if self._boot_sections:
            self._header.first_boot_section_id = self._boot_sections[0].uid
            # calculate first boot tag block
            data_size = self._header.SIZE + self.HEADER_MAC_SIZE + self.KEY_BLOB_SIZE
            if self._cert_section is not None:
                data_size += self._cert_section.raw_size
            self._header.first_boot_tag_block = SecBootBlckSize.to_num_blocks(data_size)
        # ...
        self._header.flags = 0x08 if self.signed else 0x04
        self._header.image_blocks = SecBootBlckSize.to_num_blocks(self.raw_size_without_signature)
        self._header.header_blocks = SecBootBlckSize.to_num_blocks(self._header.SIZE)
        self._header.max_section_mac_count = 0
        if self.signed:
            self._header.offset_to_certificate_block = (
                self._header.SIZE + self.HEADER_MAC_SIZE + self.KEY_BLOB_SIZE
            )
            self._header.offset_to_certificate_block += CmdHeader.SIZE + CertSectionV2.HMAC_SIZE * 2
            self._header.max_section_mac_count = 1
        for boot_sect in self._boot_sections:
            boot_sect.is_last = True  # this is unified with elftosb
            self._header.max_section_mac_count += boot_sect.hmac_count
        # Update certificates block header
        cert_blk = self.cert_block
        if cert_blk is not None:
            cert_blk.header.build_number = self._header.build_number
            cert_blk.header.image_length = self.cert_header_size

    def __repr__(self) -> str:
        """Return string representation of SB2 image.

        Provides a human-readable string indicating the SB file version and whether
        it is signed or plain (unsigned).

        :return: String representation in format "SB2.0, Signed/Plain".
        """
        return f"SB2.0, {'Signed' if self.signed else 'Plain'} "

    def __str__(self) -> str:
        """Return text description of the SB2 image instance.

        Generates a formatted string representation containing the image header,
        certificates block (if present), and all boot sections with their UIDs.
        The method automatically updates the instance before generating the description.

        :return: Formatted multi-line string with complete image information.
        """
        self.update()
        nfo = "\n"
        nfo += ":::::::::::::::::::::::::::::::::: IMAGE HEADER ::::::::::::::::::::::::::::::::::::::\n"
        nfo += str(self._header)
        if self._cert_section is not None:
            nfo += "::::::::::::::::::::::::::::::: CERTIFICATES BLOCK ::::::::::::::::::::::::::::::::::::\n"
            nfo += str(self._cert_section)
        nfo += "::::::::::::::::::::::::::::::::::: BOOT SECTIONS ::::::::::::::::::::::::::::::::::::\n"
        for index, section in enumerate(self._boot_sections):
            nfo += f"[ SECTION: {index} | UID: 0x{section.uid:08X} ]\n"
            nfo += str(section)
        return nfo

    def add_boot_section(self, section: BootSectionV2) -> None:
        """Add new Boot section into image.

        :param section: Boot section to be added to the image
        :raises SPSDKError: Raised when section is not instance of BootSectionV2 class
        :raises SPSDKError: Raised when boot section has duplicate UID
        """
        if not isinstance(section, BootSectionV2):
            raise SPSDKError("Section is not instance of BootSectionV2 class")
        duplicate_uid = find_first(self._boot_sections, lambda bs: bs.uid == section.uid)
        if duplicate_uid is not None:
            raise SPSDKError(f"Boot section with duplicate UID: {str(section.uid)}")
        self._boot_sections.append(section)

    def export(self, padding: Optional[bytes] = None) -> bytes:
        """Export image object to binary format.

        The method serializes the complete SB2 image including header, certificates,
        boot sections, and signature into a binary representation ready for deployment.

        :param padding: Header padding (8 bytes) for testing purpose; None to use random
                        values (recommended)
        :return: Exported bytes representing the complete SB2 image
        :raises SPSDKError: No boot sections available
        :raises SPSDKError: Invalid DEK or MAC key length (must be 32 bytes each)
        :raises SPSDKError: Certificate section required for signed images
        :raises SPSDKError: Signature provider not assigned for signed image
        :raises SPSDKError: Certificate block not assigned for signed image
        :raises SPSDKError: Header nonce is missing
        :raises SPSDKError: Invalid length of exported data
        """
        if len(self.dek) != 32 or len(self.mac) != 32:
            raise SPSDKError("Invalid dek or mac")
        # validate params
        if not self._boot_sections:
            raise SPSDKError("No boot section")
        if self.signed and (self._cert_section is None):
            raise SPSDKError("Certificate section is required for signed images")
        # update internals
        self.update()
        # Add Image Header data
        data = self._header.export(padding=padding)
        # Add Image Header HMAC data
        data += hmac(self.mac, data)
        # Add DEK and MAC keys
        data += aes_key_wrap(self.kek, self.dek + self.mac)
        # Add Padding
        data += padding if padding else random_bytes(8)
        # Add Certificates data
        if not self._header.nonce:
            raise SPSDKError("There is no nonce in the header")
        counter = Counter(self._header.nonce)
        counter.increment(SecBootBlckSize.to_num_blocks(len(data)))
        if self._cert_section is not None:
            cert_sect_bin = self._cert_section.export(dek=self.dek, mac=self.mac, counter=counter)
            counter.increment(SecBootBlckSize.to_num_blocks(len(cert_sect_bin)))
            data += cert_sect_bin
        # Add Boot Sections data
        for sect in self._boot_sections:
            data += sect.export(dek=self.dek, mac=self.mac, counter=counter)
        # Add Signature data
        if self.signed:
            if self.signature_provider is None:
                raise SPSDKError("Signature provider is not assigned, cannot sign the image.")
            if self.cert_block is None:
                raise SPSDKError("Certificate block is not assigned.")

            public_key = self.cert_block.certificates[-1].get_public_key()
            self.signature_provider.try_to_verify_public_key(public_key)
            data += self.signature_provider.get_signature(data)

        if len(data) != self.raw_size:
            raise SPSDKError("Invalid length of exported data")
        return data

    # pylint: disable=too-many-locals
    @classmethod
    def parse(cls, data: bytes, kek: bytes = bytes()) -> Self:
        """Parse SB2.x image from raw bytes data.

        This method parses a Secure Binary 2.x image from binary data, validates the header MAC,
        decrypts the content using the provided KEK, and reconstructs the image object with
        all its sections including certificate and boot sections.

        :param data: Raw binary data containing the SB2.x image to be parsed
        :param kek: Key Encryption Key for unwrapping DEK and MAC keys (required for decryption)
        :return: Parsed SB2.x image object with all sections loaded
        :raises SPSDKError: Invalid or corrupted header format
        :raises SPSDKError: Unsupported header version (not 2.0)
        :raises SPSDKError: Header MAC validation failed
        :raises SPSDKError: KEK parameter is empty or not provided
        :raises SPSDKError: Header nonce field is missing
        :raises SPSDKError: Certificate section signature verification failed
        """
        if not kek:
            raise SPSDKError("kek cannot be empty")
        index = 0
        header_raw_data = data[index : index + ImageHeaderV2.SIZE]
        index += ImageHeaderV2.SIZE
        header_mac_data = data[index : index + cls.HEADER_MAC_SIZE]
        index += cls.HEADER_MAC_SIZE
        key_blob = data[index : index + cls.KEY_BLOB_SIZE]
        index += cls.KEY_BLOB_SIZE
        key_blob_unwrap = aes_key_unwrap(kek, key_blob[:-8])
        dek = key_blob_unwrap[:32]
        mac = key_blob_unwrap[32:]
        header_mac_data_calc = hmac(mac, header_raw_data)
        if header_mac_data != header_mac_data_calc:
            raise SPSDKError("Invalid header MAC data")
        # Parse Header
        header = ImageHeaderV2.parse(header_raw_data)
        if header.version != "2.0":
            raise SPSDKError(f"Invalid Header Version: {header.version} instead 2.0")
        image_size = header.image_blocks * 16
        # Initialize counter
        if not header.nonce:
            raise SPSDKError("Header's nonce not present")
        counter = Counter(header.nonce)
        counter.increment(SecBootBlckSize.to_num_blocks(index))
        # ...
        signed = header.flags == 0x08
        adv_params = SBV2xAdvancedParams(
            dek=dek, mac=mac, nonce=header.nonce, timestamp=header.timestamp
        )
        obj = cls(
            signed,
            kek=kek,
            product_version=str(header.product_version),
            component_version=str(header.component_version),
            build_number=header.build_number,
            advanced_params=adv_params,
        )
        # Parse Certificate section
        if header.flags == 0x08:
            cert_sect = CertSectionV2.parse(data, index, dek=dek, mac=mac, counter=counter)
            obj._cert_section = cert_sect
            index += cert_sect.raw_size
            # Check Signature
            if not cert_sect.cert_block.verify_data(data[image_size:], data[:image_size]):
                raise SPSDKError("Parsing Certification section failed")
        # Parse Boot Sections
        while index < (image_size):
            boot_section = BootSectionV2.parse(data, index, dek=dek, mac=mac, counter=counter)
            obj.add_boot_section(boot_section)
            index += boot_section.raw_size
        return obj


########################################################################################################################
# Secure Binary Image Class (Version 2.1)
########################################################################################################################
class BootImageV21(BaseClass):
    """Secure Binary Image V2.1 container for NXP MCU secure provisioning.

    This class represents a Secure Binary Image version 2.1 that encapsulates boot sections
    with encryption and authentication capabilities. It manages the image header, cryptographic
    keys, and provides functionality for creating signed and encrypted boot images.

    :cvar HEADER_MAC_SIZE: Size of the header MAC in bytes (32).
    :cvar KEY_BLOB_SIZE: Size of the key blob in bytes (80).
    :cvar SHA_256_SIZE: Size of SHA-256 hash in bytes (32).
    :cvar FLAGS_SHA_PRESENT_BIT: Flag indicating SHA-256 presence (0x8000).
    :cvar FLAGS_ENCRYPTED_SIGNED_BIT: Flag for signed and encrypted image (0x0008).
    """

    # Image specific data
    HEADER_MAC_SIZE = 32
    KEY_BLOB_SIZE = 80
    SHA_256_SIZE = 32

    # defines
    FLAGS_SHA_PRESENT_BIT = 0x8000  # image contains SHA-256
    FLAGS_ENCRYPTED_SIGNED_BIT = 0x0008  # image is signed and encrypted

    def __init__(
        self,
        kek: bytes,
        *sections: BootSectionV2,
        product_version: str = "1.0.0",
        component_version: str = "1.0.0",
        build_number: int = 0,
        advanced_params: SBV2xAdvancedParams = SBV2xAdvancedParams(),
        flags: int = FLAGS_SHA_PRESENT_BIT | FLAGS_ENCRYPTED_SIGNED_BIT,
    ) -> None:
        """Initialize Secure Binary Image V2.1.

        Creates a new Secure Binary Image V2.1 instance with the specified encryption key and configuration
        parameters. The image can contain multiple boot sections that will be processed during secure boot.

        :param kek: Key encryption key used to wrap DEK and MAC keys.
        :param sections: Variable number of boot sections to include in the image.
        :param product_version: Product version string in format "x.y.z".
        :param component_version: Component version string in format "x.y.z".
        :param build_number: Build number for the image.
        :param advanced_params: Advanced encryption parameters including DEK, MAC, nonce, and timestamp.
        :param flags: Image flags controlling SHA presence and encryption/signing behavior.
        """
        self._kek = kek
        self.signature_provider: Optional[SignatureProvider] = (
            None  # this should be assigned for export, not needed for parsing
        )
        self._dek = advanced_params.dek
        self._mac = advanced_params.mac
        self._header = ImageHeaderV2(
            version="2.1",
            product_version=product_version,
            component_version=component_version,
            build_number=build_number,
            flags=flags,
            nonce=advanced_params.nonce,
            timestamp=advanced_params.timestamp,
            padding=advanced_params.padding,
        )
        self._cert_block: Optional[CertBlockV1] = None
        self.boot_sections: list[BootSectionV2] = []
        # ...
        for section in sections:
            self.add_boot_section(section)

    @property
    def header(self) -> ImageHeaderV2:
        """Get image header.

        :return: Image header containing metadata and configuration information.
        """
        return self._header

    @property
    def dek(self) -> bytes:
        """Get the data encryption key.

        :return: Data encryption key as bytes.
        """
        return self._dek

    @property
    def mac(self) -> bytes:
        """Get the message authentication code.

        :return: Message authentication code as bytes.
        """
        return self._mac

    @property
    def kek(self) -> bytes:
        """Return key to wrap DEC and MAC keys.

        :return: Key encryption key as bytes.
        """
        return self._kek

    @property
    def cert_block(self) -> Optional[CertBlockV1]:
        """Get certificate block from SB file.

        Returns the certificate block if the SB file is signed and the block has been assigned,
        otherwise returns None.

        :return: Certificate block instance or None if not available.
        """
        return self._cert_block

    @cert_block.setter
    def cert_block(self, value: CertBlockV1) -> None:
        """Set certificate block for the image.

        The method assigns a certificate block and sets its alignment to 16 bytes.

        :param value: Certificate block to be assigned to the image.
        :raises AssertionError: If value is not an instance of CertBlockV1.
        """
        assert isinstance(value, CertBlockV1)
        self._cert_block = value
        self._cert_block.alignment = 16

    @property
    def signed(self) -> bool:
        """Check if the SB file is signed.

        SB2.1 format files are always signed by design.

        :return: True as SB2.1 files are always signed.
        """
        return True  # SB2.1 is always signed

    @property
    def cert_header_size(self) -> int:
        """Calculate the raw size of the certificate header section.

        The method computes the total size including the image header, MAC, key blob,
        and certificate block if present. The size is not aligned to any boundary.

        :return: Raw size in bytes of the certificate header section.
        """
        size = ImageHeaderV2.SIZE + self.HEADER_MAC_SIZE
        size += self.KEY_BLOB_SIZE
        # Certificates Section
        cert_blk = self.cert_block
        if cert_blk:
            size += cert_blk.raw_size
        return size

    @property
    def raw_size(self) -> int:
        """Return image raw size (not aligned).

        Calculates the total raw size of the image including header, HMAC, key blob,
        certificate block (if present with signature), and all boot sections.

        :raises SPSDKError: If certificate block exists but is not signed.
        :return: Total raw size in bytes of the image components.
        """
        # Header, HMAC and KeyBlob
        size = ImageHeaderV2.SIZE + self.HEADER_MAC_SIZE
        size += self.KEY_BLOB_SIZE
        # Certificates Section
        cert_blk = self.cert_block
        if cert_blk:
            size += cert_blk.raw_size
            if not self.signed:  # pragma: no cover # SB2.1 is always signed
                raise SPSDKError("Certificate block is not signed")
            size += cert_blk.signature_size
        # Boot Sections
        for boot_section in self.boot_sections:
            size += boot_section.raw_size
        return size

    def __len__(self) -> int:
        """Get the number of boot sections in the image.

        :return: Number of boot sections.
        """
        return len(self.boot_sections)

    def __getitem__(self, key: int) -> BootSectionV2:
        """Get boot section by index.

        :param key: Index of the boot section to retrieve.
        :return: Boot section at the specified index.
        """
        return self.boot_sections[key]

    def __setitem__(self, key: int, value: BootSectionV2) -> None:
        """Set boot section at specified index.

        Assigns a boot section to the specified index position in the boot sections collection.

        :param key: Index position where to set the boot section.
        :param value: Boot section object to be assigned at the specified index.
        """
        self.boot_sections[key] = value

    def __iter__(self) -> Iterator[BootSectionV2]:
        """Iterate over boot sections in the image.

        Provides an iterator interface to access all boot sections contained
        in this SB2 image sequentially.

        :return: Iterator yielding BootSectionV2 objects.
        """
        return self.boot_sections.__iter__()

    def update(self) -> None:
        """Update the BootImageV21 internal structure and header fields.

        This method recalculates and updates various header fields including boot section IDs,
        block sizes, offsets, and MAC counts. It also updates the certificate block header
        if present. The method ensures all internal structures are synchronized with the
        current state of boot sections and certificate blocks.

        :raises SPSDKError: When certificate block exists but is not signed.
        """
        if self.boot_sections:
            self._header.first_boot_section_id = self.boot_sections[0].uid
            # calculate first boot tag block
            data_size = self._header.SIZE + self.HEADER_MAC_SIZE + self.KEY_BLOB_SIZE
            cert_blk = self.cert_block
            if cert_blk is not None:
                data_size += cert_blk.raw_size
                if not self.signed:  # pragma: no cover # SB2.1 is always signed
                    raise SPSDKError("Certificate block is not signed")
                data_size += cert_blk.signature_size
            self._header.first_boot_tag_block = SecBootBlckSize.to_num_blocks(data_size)
        # ...
        self._header.image_blocks = SecBootBlckSize.to_num_blocks(self.raw_size)
        self._header.header_blocks = SecBootBlckSize.to_num_blocks(self._header.SIZE)
        self._header.offset_to_certificate_block = (
            self._header.SIZE + self.HEADER_MAC_SIZE + self.KEY_BLOB_SIZE
        )
        # Get HMAC count
        self._header.max_section_mac_count = 0
        for boot_sect in self.boot_sections:
            boot_sect.is_last = True  # unified with elftosb
            self._header.max_section_mac_count += boot_sect.hmac_count
        # Update certificates block header
        cert_clk = self.cert_block
        if cert_clk is not None:
            cert_clk.header.build_number = self._header.build_number
            cert_clk.header.image_length = self.cert_header_size

    def __repr__(self) -> str:
        """Return string representation of SB2.1 image.

        Provides a human-readable string indicating the SB2.1 format and whether
        the image is signed or plain (unsigned).

        :return: String representation showing format and signing status.
        """
        return f"SB2.1, {'Signed' if self.signed else 'Plain'} "

    def __str__(self) -> str:
        """Return text description of the SB2 image instance.

        Generates a comprehensive string representation including the image header,
        certificates block (if present), and all boot sections with their UIDs.

        :return: Formatted string containing detailed image information.
        """
        self.update()
        nfo = "\n"
        nfo += ":::::::::::::::::::::::::::::::::: IMAGE HEADER ::::::::::::::::::::::::::::::::::::::\n"
        nfo += str(self._header)
        if self.cert_block is not None:
            nfo += "::::::::::::::::::::::::::::::: CERTIFICATES BLOCK ::::::::::::::::::::::::::::::::::::\n"
            nfo += str(self.cert_block)
        nfo += "::::::::::::::::::::::::::::::::::: BOOT SECTIONS ::::::::::::::::::::::::::::::::::::\n"
        for index, section in enumerate(self.boot_sections):
            nfo += f"[ SECTION: {index} | UID: 0x{section.uid:08X} ]\n"
            nfo += str(section)
        return nfo

    def add_boot_section(self, section: BootSectionV2) -> None:
        """Add new Boot section into image.

        :param section: Boot section to be added
        :raises SPSDKError: Raised when section is not instance of BootSectionV2 class
        """
        if not isinstance(section, BootSectionV2):
            raise SPSDKError("Section is not instance of BootSectionV2 class")
        self.boot_sections.append(section)

    # pylint: disable=too-many-locals
    def export(self, padding: Optional[bytes] = None) -> bytes:
        """Export SB2 image to binary format.

        The method validates all required components, updates internal structures, and exports
        the complete SB2 image including header, certificates, boot sections, and signature.

        :param padding: Header padding (8 bytes) for testing purpose; None to use random values
        :return: Complete SB2 image as binary data
        :raises SPSDKError: No boot section available for export
        :raises SPSDKError: Certificate block not assigned
        :raises SPSDKError: Signature provider not assigned
        :raises SPSDKError: Invalid header nonce value
        """
        # validate params
        if not self.boot_sections:
            raise SPSDKError("At least one Boot Section must be added")
        if self.cert_block is None:
            raise SPSDKError("Certificate is not assigned")
        if self.signature_provider is None:
            raise SPSDKError("Signature provider is not assigned, cannot sign the image")
        # Update internals
        self.update()
        # Export Boot Sections
        bs_data = bytes()
        bs_offset = (
            ImageHeaderV2.SIZE
            + self.HEADER_MAC_SIZE
            + self.KEY_BLOB_SIZE
            + self.cert_block.raw_size
            + self.cert_block.signature_size
        )
        if self.header.flags & self.FLAGS_SHA_PRESENT_BIT:
            bs_offset += self.SHA_256_SIZE

        if not self._header.nonce:
            raise SPSDKError("Invalid header's nonce")
        counter = Counter(self._header.nonce, SecBootBlckSize.to_num_blocks(bs_offset))
        for sect in self.boot_sections:
            bs_data += sect.export(dek=self.dek, mac=self.mac, counter=counter)
        # Export Header
        signed_data = self._header.export(padding=padding)
        #  Add HMAC data
        first_bs_hmac_count = self.boot_sections[0].hmac_count
        hmac_data = bs_data[CmdHeader.SIZE : CmdHeader.SIZE + (first_bs_hmac_count * 32) + 32]
        hmac_bytes = hmac(self.mac, hmac_data)
        signed_data += hmac_bytes
        # Add KeyBlob data
        key_blob = aes_key_wrap(self.kek, self.dek + self.mac)
        key_blob += b"\00" * (self.KEY_BLOB_SIZE - len(key_blob))
        signed_data += key_blob
        # Add Certificates data
        signed_data += self.cert_block.export()
        # Add SHA-256 of Bootable sections if requested
        if self.header.flags & self.FLAGS_SHA_PRESENT_BIT:
            signed_data += get_hash(bs_data)
        # Add Signature data
        signature = self.signature_provider.get_signature(signed_data)

        return signed_data + signature + bs_data

    # pylint: disable=too-many-locals
    @classmethod
    def parse(
        cls,
        data: bytes,
        offset: int = 0,
        kek: bytes = bytes(),
        plain_sections: bool = False,
    ) -> "BootImageV21":
        """Parse SB2.1 boot image from binary data.

        This method parses a Secure Binary 2.1 image from raw bytes, verifying signatures,
        unwrapping encryption keys, and reconstructing the boot image structure with all
        its components including certificate blocks and boot sections.

        :param data: Raw binary data containing the SB2.1 image to parse
        :param offset: Starting offset within the data where parsing begins
        :param kek: Key Encryption Key used for unwrapping DEK and MAC keys
        :param plain_sections: Whether sections are unencrypted (debug mode only, not ROM supported)
        :return: Parsed BootImageV21 object with all components initialized
        :raises SPSDKError: When KEK is empty or missing
        :raises SPSDKError: When header format is invalid or offset mismatch occurs
        :raises SPSDKError: When certificate block signature verification fails
        :raises SPSDKError: When header nonce is not present
        :raises SPSDKError: When bootable section SHA-256 verification fails
        """
        if not kek:
            raise SPSDKError("kek cannot be empty")
        index = offset
        header_raw_data = data[index : index + ImageHeaderV2.SIZE]
        index += ImageHeaderV2.SIZE
        # Not used right now: hmac_data = data[index: index + cls.HEADER_MAC_SIZE]
        index += cls.HEADER_MAC_SIZE
        key_blob = data[index : index + cls.KEY_BLOB_SIZE]
        index += cls.KEY_BLOB_SIZE
        key_blob_unwrap = aes_key_unwrap(kek, key_blob[:-8])
        dek = key_blob_unwrap[:32]
        mac = key_blob_unwrap[32:]
        # Parse Header
        header = ImageHeaderV2.parse(header_raw_data)
        if header.offset_to_certificate_block != (index - offset):
            raise SPSDKError("Invalid offset")
        # Parse Certificate Block
        cert_block = CertBlockV1.parse(data[index:])
        index += cert_block.raw_size

        # Verify Signature
        signature_index = index
        # The image may contain SHA, in such a case the signature is placed
        # after SHA. Thus we must shift the index by SHA size.
        if header.flags & BootImageV21.FLAGS_SHA_PRESENT_BIT:
            signature_index += BootImageV21.SHA_256_SIZE
        result = cert_block.verify_data(
            data[signature_index : signature_index + cert_block.signature_size],
            data[offset:signature_index],
        )

        if not result:
            raise SPSDKError("Verification failed")
        # Check flags, if 0x8000 bit is set, the SB file contains SHA-256 between
        # certificate and signature.
        if header.flags & BootImageV21.FLAGS_SHA_PRESENT_BIT:
            bootable_section_sha256 = data[index : index + BootImageV21.SHA_256_SIZE]
            index += BootImageV21.SHA_256_SIZE
        index += cert_block.signature_size
        # Check first Boot Section HMAC
        # Not implemented yet
        # hmac_data_calc = hmac(mac, data[index + CmdHeader.SIZE: index + CmdHeader.SIZE + ((2) * 32)])
        # if hmac_data != hmac_data_calc:
        #    raise SPSDKError("HMAC failed")
        if not header.nonce:
            raise SPSDKError("Header's nonce not present")
        counter = Counter(header.nonce)
        counter.increment(SecBootBlckSize.to_num_blocks(index - offset))
        boot_section = BootSectionV2.parse(
            data, index, dek=dek, mac=mac, counter=counter, plain_sect=plain_sections
        )
        if header.flags & BootImageV21.FLAGS_SHA_PRESENT_BIT:
            computed_bootable_section_sha256 = get_hash(
                data[index:], algorithm=EnumHashAlgorithm.SHA256
            )

            if bootable_section_sha256 != computed_bootable_section_sha256:
                raise SPSDKError(
                    desc=(
                        "Error: invalid Bootable section SHA."
                        f"Expected {bootable_section_sha256.decode('utf-8')},"
                        f"got {computed_bootable_section_sha256.decode('utf-8')}"
                    )
                )
        adv_params = SBV2xAdvancedParams(
            dek=dek, mac=mac, nonce=header.nonce, timestamp=header.timestamp
        )
        obj = cls(
            kek=kek,
            product_version=str(header.product_version),
            component_version=str(header.component_version),
            build_number=header.build_number,
            advanced_params=adv_params,
        )
        obj.cert_block = cert_block
        obj.add_boot_section(boot_section)
        return obj

    @staticmethod
    def get_supported_families() -> list[FamilyRevision]:
        """Get supported families for SB2.1 format.

        This method retrieves all device families that support the SB2.1 secure boot file format
        from the database manager.

        :return: List of supported family revisions for SB2.1 format.
        """
        return get_families(DatabaseManager.SB21)

    @classmethod
    def get_commands_validation_schemas(
        cls, family: Optional[FamilyRevision] = None
    ) -> list[dict[str, Any]]:
        """Create the list of validation schemas for SB2.1 commands.

        The method retrieves the base SB2.1 schema and optionally filters commands
        based on the specified device family. When a family is provided, only
        commands supported by that family are included in the validation schema.

        :param family: Device family filter, if None all commands are returned.
        :return: List of validation schemas for SB2.1 commands.
        """
        sb2_sch_cfg = get_schema_file(DatabaseManager.SB21)

        schemas: list[dict[str, Any]] = [sb2_sch_cfg["sb2_sections"]]
        if family:
            db = get_db(family)
            # remove unused command for current family
            supported_commands = db.get_list(DatabaseManager.SB21, "supported_commands")
            list_of_commands: list[dict] = schemas[0]["properties"]["sections"]["items"][
                "properties"
            ]["commands"]["items"]["oneOf"]

            schemas[0]["properties"]["sections"]["items"]["properties"]["commands"]["items"][
                "oneOf"
            ] = [
                command
                for command in list_of_commands
                if list(command["properties"].keys())[0] in supported_commands
            ]

        return schemas

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Create the list of validation schemas for SB2 image configuration.

        The method builds a comprehensive list of validation schemas by combining family-specific
        schemas, MBI schemas, SB2 schemas, and optionally keyblob schemas based on device
        family capabilities.

        :param family: Device family revision to get validation schemas for.
        :return: List of validation schema dictionaries for configuration validation.
        """
        sb2_schema = get_schema_file(DatabaseManager.SB21)
        mbi_schema = get_schema_file(DatabaseManager.MBI)
        family_schema = get_schema_file("general")["family"]
        update_validation_schema_family(
            family_schema["properties"], cls.get_supported_families(), family
        )

        schemas: list[dict[str, Any]] = [family_schema]
        schemas.extend([mbi_schema[x] for x in ["signer", "cert_block_v1"]])
        schemas.extend([sb2_schema[x] for x in ["sb2_output", "common", "sb2", "sb2_test"]])

        add_keyblob = True

        if family:
            add_keyblob = get_db(family).get_bool(DatabaseManager.SB21, "keyblobs", default=True)

        if add_keyblob:
            schemas.append(sb2_schema["keyblobs"])
        schemas.extend(cls.get_commands_validation_schemas(family))

        return schemas

    @classmethod
    def get_config_template(cls, family: FamilyRevision) -> str:
        """Generate configuration template for Secure Binary v2.1.

        Creates a configuration template with validation schemas for the specified device family.
        The template includes all necessary configuration options and their descriptions.

        :param family: Device family revision to generate template for.
        :return: Configuration template as a string with comments and validation schemas.
        """
        title = "Secure Binary v2.1 Configuration template"
        if family in cls.get_supported_families():
            title += f" for {family}"
        return CommentedConfig(
            title,
            cls.get_validation_schemas(family),
        ).get_template()

    @classmethod
    def parse_sb21_config(
        cls,
        config_path: str,
        external_files: Optional[list[str]] = None,
    ) -> Config:
        """Parse SB2.1 configuration file and create configuration object.

        The method attempts to parse the configuration file as a BD (Boot Data) file first.
        If that fails, it falls back to parsing as a YAML configuration file with validation.

        :param config_path: Path to configuration file either BD or YAML formatted.
        :param external_files: Optional list of external files for BD processing.
        :raises SPSDKError: Invalid BD file or configuration parsing error.
        :raises SPSDKValueError: Missing required options or family key in BD file.
        :return: Parsed configuration object with family and revision information.
        """
        try:
            bd_file_content = load_text(config_path)
            parser = bd_parser.BDParser()
            parsed_conf = Config(parser.parse(text=bd_file_content, extern=external_files))
            if parsed_conf is None:
                raise SPSDKError("Invalid bd file, secure binary file generation terminated")
            if "options" not in parsed_conf:
                raise SPSDKValueError("Missing 'options' block in BD file.")
            options: dict[str, Any] = parsed_conf["options"]
            if "family" not in options:
                raise SPSDKValueError("Missing 'family' key in BD file options block.")
            parsed_conf["family"] = options.pop("family")
            parsed_conf["revision"] = options.pop("revision", "latest")
            parsed_conf.config_dir = os.path.dirname(config_path)
            parsed_conf.search_paths = [parsed_conf.config_dir]
        except SPSDKError:
            parsed_conf = Config.create_from_file(config_path)

            family = FamilyRevision.load_from_config(parsed_conf)
            schemas = BootImageV21.get_validation_schemas(family)
            parsed_conf.check(schemas, check_unknown_props=True)

        return parsed_conf

    @classmethod
    def get_advanced_params(cls, config: dict[str, Any]) -> SBV2xAdvancedParams:
        """Get advanced parameters from configuration.

        Extracts and processes advanced SB 2.x parameters including timestamp, DEK, MAC,
        nonce, and zero padding settings from the provided configuration dictionary.

        :param config: Configuration dictionary containing advanced parameter settings.
        :return: Advanced parameters object for SB 2.x file generation.
        """
        # Test params
        timestamp = config.get("timestamp")
        if timestamp:  # re-format it
            timestamp = datetime.fromtimestamp(value_to_int(timestamp))
        dek = config.get("dek")
        dek = value_to_bytes("0x" + dek, byte_cnt=32) if dek else None
        mac = config.get("mac")
        mac = value_to_bytes("0x" + mac, byte_cnt=32) if mac else None
        nonce = config.get("nonce")
        nonce = value_to_bytes("0x" + nonce, byte_cnt=16) if nonce else None
        zero_padding = bytes(8) if value_to_bool(config.get("zeroPadding", False)) else None
        advanced_params = SBV2xAdvancedParams(dek, mac, nonce, timestamp, zero_padding)
        logger.debug(f"Loading advanced parameters for SB 2.1 {str(advanced_params)}")
        return advanced_params

    @classmethod
    def load_from_config(
        cls,
        config: Config,
        key_file_path: Optional[str] = None,
        signature_provider: Optional[SignatureProvider] = None,
        signing_certificate_file_paths: Optional[list[str]] = None,
        root_key_certificate_paths: Optional[list[str]] = None,
        rkth_out_path: Optional[str] = None,
    ) -> Self:
        """Create an instance of BootImageV21 from configuration.

        This method constructs a Secure Binary V2.1 image by parsing the provided configuration,
        setting up certificate blocks, loading encryption keys, processing sections and commands,
        and configuring signature providers. It also handles root key hash generation and output.

        :param config: Input standard configuration containing image settings and sections.
        :param key_file_path: Path to key file for SB-KEK encryption key.
        :param signature_provider: Signature provider instance to sign the final image.
        :param signing_certificate_file_paths: List of paths to signing certificate chain files.
        :param root_key_certificate_paths: List of paths to root key certificate files for
            verifying other certificates. Maximum 4 certificates allowed, extras ignored.
            One certificate must match the first in signing_certificate_file_paths.
        :param rkth_out_path: Output path for root key hash table file. If None, uses
            'hash.bin' in working directory or config-specified path.
        :return: Configured BootImageV21 instance ready for image generation.
        """
        options = config.get_config("options")
        flags = options.get_int(
            "flags", BootImageV21.FLAGS_SHA_PRESENT_BIT | BootImageV21.FLAGS_ENCRYPTED_SIGNED_BIT
        )

        product_version = options.get_str("productVersion", "1.0.0")
        component_version = options.get_str("componentVersion", "1.0.0")

        if signing_certificate_file_paths and root_key_certificate_paths:
            build_number = options.get_int("buildNumber", 1)
            cert_block = CertBlockV1(family=FamilyRevision("Unknown"), build_number=build_number)
            for cert_path in signing_certificate_file_paths:
                cert = Certificate.load(cert_path)
                cert_block.add_certificate(cert)
            for cert_idx, cert_path in enumerate(root_key_certificate_paths):
                cert = Certificate.load(cert_path)
                cert_block.set_root_key_hash(cert_idx, cert)
        else:
            cert_block = CertBlockV1.load_from_config(config)

        if key_file_path:
            sb_kek = load_hex_string(key_file_path, expected_size=32)
        else:
            sb_kek = config.load_symmetric_key("containerKeyBlobEncryptionKey", expected_size=32)

        # validate keyblobs and perform appropriate actions
        keyblobs = config.get("keyblobs", [])

        # get advanced params
        advanced_params = cls.get_advanced_params(options)

        sb21_helper = SB21Helper(config.search_paths, zero_filling=advanced_params.zero_padding)
        sb_sections = []
        sections = config["sections"]
        for section_id, section in enumerate(sections):
            commands = []
            for cmd in section["commands"]:
                for key, value in cmd.items():
                    # we use a helper function, based on the key ('load', 'erase'
                    # etc.) to create a command object. The helper function knows
                    # how to handle the parameters of each command.
                    cmd_fce = sb21_helper.get_command(key)
                    if key in ("keywrap", "encrypt"):
                        keyblob = {"keyblobs": keyblobs}
                        value.update(keyblob)
                    cmd = cmd_fce(value)
                    commands.append(cmd)

            sb_sections.append(
                BootSectionV2(section_id, *commands, zero_filling=advanced_params.zero_padding)
            )

        # We have a list of sections and their respective commands, lets create
        # a boot image v2.1 object
        secure_binary = cls(
            sb_kek,
            *sb_sections,
            product_version=product_version,
            component_version=component_version,
            build_number=cert_block.header.build_number,
            flags=flags,
            advanced_params=advanced_params,
        )

        # We have our secure binary, now we attach to it the certificate block and
        # the private key content
        secure_binary.cert_block = cert_block

        if not signature_provider:
            signature_provider = get_signature_provider(config)

        secure_binary.signature_provider = signature_provider

        if secure_binary.cert_block:
            if not rkth_out_path:
                if "RKTHOutputPath" in config:
                    rkth_out_path = config.get_output_file_name("RKTHOutputPath")
                    # Only write the file if a path was explicitly provided
                    write_file(secure_binary.cert_block.rkth, rkth_out_path, mode="wb")
            else:
                # rkth_out_path was provided, so write the file
                assert isinstance(rkth_out_path, str), "Hash of hashes path must be string"
                write_file(secure_binary.cert_block.rkth, rkth_out_path, mode="wb")

        return secure_binary

    @staticmethod
    def validate_header(binary: bytes) -> None:
        """Validate SB2.1 header in binary data.

        :param binary: Binary data to be validated
        :raises SPSDKError: Invalid header of SB2.1 data
        """
        ImageHeaderV2.parse(binary)
