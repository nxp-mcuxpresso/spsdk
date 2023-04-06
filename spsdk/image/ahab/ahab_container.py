#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Implementation of raw AHAB container support.

This module represents a generic AHAB container implementation. You can set the
containers values at will. From this perspective, consult with your reference
manual of your device for allowed values.
"""
# pylint: disable=too-many-lines
import datetime
import logging
import math
import os
from struct import calcsize, pack, unpack
from typing import Any, Dict, List, Optional, Tuple

from ruamel.yaml import CommentedMap as CM
from ruamel.yaml import CommentedSeq as CS

from spsdk import version as spsdk_version
from spsdk.apps.utils.utils import get_key
from spsdk.crypto import (
    EllipticCurvePublicKey,
    Encoding,
    PrivateKey,
    PublicKey,
    RSAPrivateKey,
    RSAPublicKey,
    _PrivateKeyTuple,
)
from spsdk.crypto.keys_management import (
    recreate_ecc_public_key,
    recreate_rsa_public_key,
    save_ecc_public_key,
    save_rsa_public_key,
)
from spsdk.crypto.loaders import extract_public_key, load_private_key, load_private_key_from_data
from spsdk.exceptions import SPSDKError, SPSDKLengthError, SPSDKParsingError, SPSDKValueError
from spsdk.image.ahab import AHAB_DATABASE_FILE, AHAB_SCH_FILE
from spsdk.image.ahab.ahab_abstract_interfaces import (
    Container,
    HeaderContainer,
    HeaderContainerInversed,
)
from spsdk.utils.crypto.common import crypto_backend, get_matching_key_id
from spsdk.utils.database import Database
from spsdk.utils.easy_enum import Enum
from spsdk.utils.images import BinaryImage
from spsdk.utils.misc import (
    align,
    align_block,
    check_range,
    extend_block,
    find_file,
    load_binary,
    reverse_bytes_in_longs,
    value_to_bytes,
    value_to_int,
    write_file,
)
from spsdk.utils.schema_validator import ConfigTemplate, ValidationSchemas

logger = logging.getLogger(__name__)

LITTLE_ENDIAN = "<"
UINT8 = "B"
UINT16 = "H"
UINT32 = "L"
UINT64 = "Q"
RESERVED = 0
CONTAINER_ALIGNMENT = 8
START_IMAGE_ADDRESS = 0x2000


IMAGE_TYPE_XIP = "xip"
IMAGE_TYPE_NON_XIP = "non_xip"
IMAGE_TYPE_SERIAL_DOWNLOADER = "serial_downloader"


class AHABTags(Enum):
    """AHAB container related tags."""

    BLOB = (0x81, "Blob (Wrapped Data Encryption Key).")
    CONTAINER_HEADER = (0x87, "Container header.")
    SIGNATURE_BLOCK = (0x90, "Signature block.")
    CERTIFICATE_UUID = (0xA0, "Certificate with UUID.")
    CERTIFICATE_NON_UUID = (0xAF, "Certificate without UUID.")
    SRK_TABLE = (0xD7, "SRK table.")
    SIGNATURE = (0xD8, "Signature part of signature block.")
    SRK_RECORD = (0xE1, "SRK record.")


def get_key_by_val(dictionary: Dict, val: Any) -> str:
    """Get Dictionary key by its value or default.

    :param dictionary: Dictionary to search in.
    :param val: Value to search
    :raises SPSDKValueError: In case that dictionary doesn't contains the value.
    :return: Key.
    """
    for key, value in dictionary.items():
        if value == val:
            return key
    raise SPSDKValueError(
        f"The requested value [{val}] in dictionary [{dictionary}] is not available."
    )


class ImageArrayEntry(Container):
    """Class representing image array entry as part of image array in the AHAB container.

    Image Array Entry content::

        +-----+---------------------------------------------------------------+
        |Off  |    Byte 3    |    Byte 2    |      Byte 1    |     Byte 0     |
        +-----+---------------------------------------------------------------+
        |0x00 |                        Image Offset                           |
        +-----+---------------------------------------------------------------+
        |0x04 |                        Image Size                             |
        +-----+---------------------------------------------------------------+
        |0x08 |                                                               |
        |-----+                        Load Address (64 bits)                 |
        |0x0C |                                                               |
        +-----+---------------------------------------------------------------+
        |0x10 |                                                               |
        |-----+                        Entry Point (64 bits)                  |
        |0x14 |                                                               |
        +-----+---------------------------------------------------------------+
        |0x18 |                        Flags                                  |
        +-----+---------------------------------------------------------------+
        |0x1C |                        Image meta data                        |
        +-----+---------------------------------------------------------------+
        |0x20 |                                                               |
        |-----+                        Hash (512 bits)                        |
        |.... |                                                               |
        +-----+---------------------------------------------------------------+
        |0x60 |                        IV (256 bits)                          |
        +-----+---------------------------------------------------------------+

    """

    IMAGE_OFFSET_LEN = 4
    IMAGE_SIZE_LEN = 4
    LOAD_ADDRESS_LEN = 8
    ENTRY_POINT_ADDRESS_LEN = 8
    FLAGS_LEN = 4
    IMAGE_META_DATA_LEN = 4
    HASH_LEN = 64
    IV_LEN = 32
    FLAGS_TYPE_OFFSET = 0
    FLAGS_TYPE_SIZE = 4
    FLAGS_TYPES = {
        "executable": 0x3,
        "data": 0x4,
        "dcd_image": 0x5,
        "seco": 0x6,
        "provisioning_image": 0x7,
        "provisioning_data": 0x9,
    }
    FLAGS_CORE_ID_OFFSET = 4
    FLAGS_CORE_ID_SIZE = 4
    FLAGS_HASH_OFFSET = 8
    FLAGS_HASH_SIZE = 3
    FLAGS_IS_ENCRYPTED_OFFSET = 11
    FLAGS_IS_ENCRYPTED_SIZE = 1
    FLAGS_BOOT_FLAGS_OFFSET = 16
    FLAGS_BOOT_FLAGS_SIZE = 15
    METADATA_START_CPU_ID_OFFSET = 0
    METADATA_START_CPU_ID_SIZE = 10
    METADATA_MU_CPU_ID_OFFSET = 10
    METADATA_MU_CPU_ID_SIZE = 10
    METADATA_START_PARTITION_ID_OFFSET = 20
    METADATA_START_PARTITION_ID_SIZE = 8

    def __init__(
        self,
        parent: "AHABContainer",
        image: Optional[bytes] = None,
        image_offset: int = 0,
        load_address: int = 0,
        entry_point: int = 0,
        flags: int = 0,
        image_meta_data: int = 0,
        image_hash: Optional[bytes] = None,
        image_iv: Optional[bytes] = None,
        already_encrypted_image: bool = False,
    ) -> None:
        """Class object initializer.

        :param parent: Parent AHAB Container object.
        :param image: Image in bytes.
        :param image_offset: Offset in bytes from start of container to beginning of image.
        :param load_address: Address the image is written to in memory (absolute address in system memory map).
        :param entry_point: Entry point of image (absolute address). Only valid for executable image types.
            For other image types the value is irrelevant.
        :param flags: flags.
        :param image_meta_data: image meta-data.
        :param image_hash: SHA of image (512 bits) in big endian. Left
            aligned and padded with zeroes for hash sizes below 512 bits.
        :param image_iv: SHA256 of plain text image (256 bits) in big endian.
        :param already_encrypted_image: The input image is already encrypted.
            Used only for encrypted images.
        """
        self.parent = parent
        self.flags = flags
        input_image = align_block(data=image or b"", alignment=16, padding=RESERVED)
        self.plain_image = input_image if not already_encrypted_image else b""
        self.encrypted_image = input_image if already_encrypted_image else b""
        self.already_encrypted_image = already_encrypted_image
        self.image_offset = image_offset
        self.image_size = len(input_image) if image else 0
        self.load_address = load_address
        self.entry_point = entry_point
        self.image_meta_data = image_meta_data
        self.image_hash = image_hash
        self.image_iv = (
            image_iv or crypto_backend().hash(self.plain_image, algorithm="sha256")
            if self.flags_is_encrypted
            else bytes(self.IV_LEN)
        )

    def __eq__(self, other: object) -> bool:
        if isinstance(other, ImageArrayEntry):
            if (
                self.image_offset  # pylint: disable=too-many-boolean-expressions
                == other.image_offset
                and self.image_size == other.image_size
                and self.load_address == other.load_address
                and self.entry_point == other.entry_point
                and self.flags == other.flags
                and self.image_meta_data == other.image_meta_data
                and self.image_hash == other.image_hash
                and self.image_iv == other.image_iv
            ):
                return True

        return False

    @property
    def image(self) -> bytes:
        """Image data for this Image array entry.

        The class decide by flags if encrypted of plain data has been returned.

        :raises SPSDKError: Invalid Image - Image is not encrypted yet.
        :return: Image bytes.
        """
        if self.flags_is_encrypted and not self.already_encrypted_image:
            raise SPSDKError("Image is NOT encrypted, yet.")

        if self.flags_is_encrypted:
            return self.encrypted_image
        return self.plain_image

    # We need to extend the format, as the base provides only endianness.
    @classmethod
    def _format(cls) -> str:
        return (
            super()._format()  # endianness from base class
            + UINT32  # Image Offset
            + UINT32  # Image Size
            + UINT64  # Load Address
            + UINT64  # Entry Point
            + UINT32  # Flags
            + UINT32  # Image Meta Data
            + "64s"  # HASH
            + "32s"  # Input Vector
        )

    def update_fields(self) -> None:
        """Updates the image fields in container based on provided image."""
        self.image_size = len(self.image)
        algorithm = self.get_hash_from_flags(self.flags)
        self.image_hash = extend_block(
            crypto_backend().hash(self.image, algorithm=algorithm),
            self.HASH_LEN,
            padding=0,
        )
        if not self.image_iv and self.flags_is_encrypted:
            self.image_iv = crypto_backend().hash(self.plain_image, algorithm="sha256")

    @staticmethod
    def create_meta(start_cpu_id: int = 0, mu_cpu_id: int = 0, start_partition_id: int = 0) -> int:
        """Create meta data field.

        :param start_cpu_id: ID of CPU to start, defaults to 0
        :param mu_cpu_id: ID of MU for selected CPU to start, defaults to 0
        :param start_partition_id: ID of partition to start, defaults to 0
        :return: Image meta data field.
        """
        meta_data = start_cpu_id
        meta_data |= mu_cpu_id << 10
        meta_data |= start_partition_id << 20
        return meta_data

    @staticmethod
    def create_flags(
        image_type: str = "executable",
        core_id: str = "cortex-m33",
        hash_type: str = "sha256",
        is_encrypted: bool = False,
        boot_flags: int = 0,
    ) -> int:
        """Create flags field.

        :param image_type: Type of image, defaults to "executable"
        :param core_id: Core ID, defaults to "cortex-m33"
        :param hash_type: Hash type, defaults to "sha256"
        :param is_encrypted: Is image encrypted, defaults to False
        :param boot_flags: Boot flags controlling the SCFW boot, defaults to 0
        :return: Image flags data field.
        """
        flags_data = ImageArrayEntry.FLAGS_TYPES[image_type]
        flags_data |= {"cortex-m33": 0x1, "cortex-m7": 0x02, "cortex-a55": 0x02}[core_id] << 4
        flags_data |= {"sha256": 0x0, "sha384": 0x1, "sha512": 0x2}[
            hash_type
        ] << ImageArrayEntry.FLAGS_HASH_OFFSET
        flags_data |= 1 << 11 if is_encrypted else 0
        flags_data |= boot_flags << 16
        return flags_data

    @staticmethod
    def get_hash_from_flags(flags: int) -> str:
        """Get Hash algorithm name from flags.

        :param flags: Value of flags.
        :return: Hash name.
        """
        hash_val = (flags >> ImageArrayEntry.FLAGS_HASH_OFFSET) & (
            (1 << ImageArrayEntry.FLAGS_HASH_SIZE) - 1
        )
        return {0x00: "sha256", 0x01: "sha384", 0x02: "sha512"}[hash_val]

    @property
    def flags_image_type(self) -> str:
        """Get Image type name from flags.

        :return: Image type name
        """
        image_type_val = (self.flags >> ImageArrayEntry.FLAGS_TYPE_OFFSET) & (
            (1 << ImageArrayEntry.FLAGS_TYPE_SIZE) - 1
        )
        try:
            return get_key_by_val(ImageArrayEntry.FLAGS_TYPES, image_type_val)
        except SPSDKValueError:
            return f"Unknown Image Type {image_type_val}"

    @property
    def flags_core_id(self) -> int:
        """Get Core ID from flags.

        :return: Core ID
        """
        return (self.flags >> ImageArrayEntry.FLAGS_CORE_ID_OFFSET) & (
            (1 << ImageArrayEntry.FLAGS_CORE_ID_SIZE) - 1
        )

    @property
    def flags_is_encrypted(self) -> bool:
        """Get Is encrypted property from flags.

        :return: True if is encrypted, false otherwise
        """
        return bool(
            (self.flags >> ImageArrayEntry.FLAGS_IS_ENCRYPTED_OFFSET)
            & ((1 << ImageArrayEntry.FLAGS_IS_ENCRYPTED_SIZE) - 1)
        )

    @property
    def flags_boot_flags(self) -> int:
        """Get boot flags property from flags.

        :return: Boot flags
        """
        return (self.flags >> ImageArrayEntry.FLAGS_BOOT_FLAGS_OFFSET) & (
            (1 << ImageArrayEntry.FLAGS_BOOT_FLAGS_SIZE) - 1
        )

    @property
    def metadata_start_cpu_id(self) -> int:
        """Get CPU ID property from Meta data.

        :return: Start CPU ID
        """
        return (self.image_meta_data >> ImageArrayEntry.METADATA_START_CPU_ID_OFFSET) & (
            (1 << ImageArrayEntry.METADATA_START_CPU_ID_SIZE) - 1
        )

    @property
    def metadata_mu_cpu_id(self) -> int:
        """Get Start CPU Memory Unit ID property from Meta data.

        :return: Start CPU MU ID
        """
        return (self.image_meta_data >> ImageArrayEntry.METADATA_MU_CPU_ID_OFFSET) & (
            (1 << ImageArrayEntry.METADATA_MU_CPU_ID_SIZE) - 1
        )

    @property
    def metadata_start_partition_id(self) -> int:
        """Get Start Partition ID property from Meta data.

        :return: Start Partition ID
        """
        return (self.image_meta_data >> ImageArrayEntry.METADATA_START_PARTITION_ID_OFFSET) & (
            (1 << ImageArrayEntry.METADATA_START_PARTITION_ID_SIZE) - 1
        )

    def export(self) -> bytes:
        """Serializes container object into bytes in little endian.

        The hash and IV are kept in big endian form.

        :return: bytes representing container content.
        """
        # hash: fixed at 512 bits, left aligned and padded with zeros for hash below 512 bits.
        # In case the hash is shorter, the pack() (in little endian mode) should grant, that the
        # hash is left aligned and padded with zeros due to the '64s' formatter.
        # iv: fixed at 256 bits.

        data = pack(
            self._format(),
            self.image_offset,
            self.image_size,
            self.load_address,
            self.entry_point,
            self.flags,
            self.image_meta_data,
            self.image_hash,
            self.image_iv,
        )

        return data

    def validate(self) -> None:
        """Validate object data.

        :raises SPSDKValueError: Invalid any value of Image Array entry
        """
        if self.image is None or len(self.image) != self.image_size:
            raise SPSDKValueError("Image Entry: Invalid Image binary.")
        if self.image_offset is None or not check_range(self.image_offset, end=(1 << 32) - 1):
            raise SPSDKValueError(f"Image Entry: Invalid Image Offset: {self.image_offset}")
        if self.image_size is None or not check_range(self.image_size, end=(1 << 32) - 1):
            raise SPSDKValueError(f"Image Entry: Invalid Image Size: {self.image_size}")
        if self.load_address is None or not check_range(self.load_address, end=(1 << 64) - 1):
            raise SPSDKValueError(f"Image Entry: Invalid Image Load address: {self.load_address}")
        if self.entry_point is None or not check_range(self.entry_point, end=(1 << 64) - 1):
            raise SPSDKValueError(f"Image Entry: Invalid Image Entry point: {self.entry_point}")
        if self.flags is None or not check_range(self.flags, end=(1 << 32) - 1):
            raise SPSDKValueError(f"Image Entry: Invalid Image Flags: {self.flags}")
        if self.image_meta_data is None or not check_range(self.image_meta_data, end=(1 << 32) - 1):
            raise SPSDKValueError(f"Image Entry: Invalid Image Meta data: {self.image_meta_data}")
        if (
            self.image_hash is None
            or not any(self.image_hash)
            or len(self.image_hash) != self.HASH_LEN
        ):
            raise SPSDKValueError("Image Entry: Invalid Image Hash.")

    @staticmethod
    def parse(parent: "AHABContainer", binary: bytes, offset: int = 0) -> "ImageArrayEntry":
        """Parse input binary chunk to the container object.

        :param parent: Parent AHABContainer object.
        :param binary: Binary data with Image Array Entry block to parse.
        :param offset: Offset to Image Array Entry block data, default is 0.
        :raises SPSDKLengthError: If invalid length of image is detected.
        :raises SPSDKValueError: Invalid hash for image.
        :return: Object recreated from the binary data.
        """
        binary_size = len(binary)
        # Just updates offsets from AHAB Image start As is feature of none xip containers
        container_offset = (
            parent.container_offset
            if parent.parent.image_type in (IMAGE_TYPE_NON_XIP, IMAGE_TYPE_SERIAL_DOWNLOADER)
            else 0
        )

        ImageArrayEntry._check_fixed_input_length(binary[offset:])
        (
            image_offset,
            image_size,
            load_address,
            entry_point,
            flags,
            image_meta_data,
            image_hash,
            image_iv,
        ) = unpack(
            ImageArrayEntry._format(), binary[offset : offset + ImageArrayEntry.fixed_length()]
        )

        if image_offset + image_size - 1 > binary_size:
            raise SPSDKLengthError(
                "Container data image is out of loaded binary:"
                f"Image entry record has end of image at 0x{hex(image_offset+image_size-1)},"
                f" but the loaded image length has only 0x{hex(binary_size)}B size."
            )
        image = binary[
            container_offset + image_offset : container_offset + image_offset + image_size
        ]
        image_hash_cmp = extend_block(
            crypto_backend().hash(image, algorithm=ImageArrayEntry.get_hash_from_flags(flags)),
            ImageArrayEntry.HASH_LEN,
            padding=0,
        )
        if image_hash != image_hash_cmp:
            raise SPSDKValueError("Parsed Container data image has invalid HASH!")

        return ImageArrayEntry(
            parent=parent,
            image_offset=image_offset,
            image=image,
            load_address=load_address,
            entry_point=entry_point,
            flags=flags,
            image_meta_data=image_meta_data,
            image_hash=image_hash,
            image_iv=image_iv,
            already_encrypted_image=bool(
                (flags >> ImageArrayEntry.FLAGS_IS_ENCRYPTED_OFFSET)
                & ((1 << ImageArrayEntry.FLAGS_IS_ENCRYPTED_SIZE) - 1)
            ),
        )

    @staticmethod
    def load_from_config(parent: "AHABContainer", config: Dict[str, Any]) -> "ImageArrayEntry":
        """Converts the configuration option into an AHAB image array entry object.

        "config" content of container configurations.

        :param parent: Parent AHABContainer object.
        :param config: Configuration of ImageArray.
        :return: Container Header Image Array Entry object.
        """
        image_path = config.get("image_path")
        search_paths = parent.search_paths
        assert isinstance(image_path, str)
        is_encrypted = config.get("is_encrypted", False)
        meta_data = ImageArrayEntry.create_meta(
            value_to_int(config.get("meta_data_start_cpu_id", 0)),
            value_to_int(config.get("meta_data_mu_cpu_id", 0)),
            value_to_int(config.get("meta_data_start_partition_id", 0)),
        )
        image_data = load_binary(image_path, search_paths=search_paths)
        flags = ImageArrayEntry.create_flags(
            image_type=config.get("image_type", "executable"),
            core_id=config.get("core_id", "cortex-m33"),
            hash_type=config.get("hash_type", "sha256"),
            is_encrypted=is_encrypted,
            boot_flags=value_to_int(config.get("boot_flags", 0)),
        )
        return ImageArrayEntry(
            parent=parent,
            image=image_data,
            image_offset=value_to_int(config.get("image_offset", 0)),
            load_address=value_to_int(config.get("load_address", 0)),
            entry_point=value_to_int(config.get("entry_point", 0)),
            flags=flags,
            image_meta_data=meta_data,
            image_iv=None,  # IV data are updated by UpdateFields function
        )

    def create_config(self, index: int, image_index: int, data_path: str) -> CM:
        """Create configuration of the AHAB Image data blob.

        :param index: Container index.
        :param image_index: Data Image index.
        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        ret_cfg = CM()
        image_name = "N/A"
        if self.plain_image:
            image_name = f"container{index}_image{image_index}_{self.flags_image_type}.bin"
            write_file(self.plain_image, os.path.join(data_path, image_name), "wb")
        if self.encrypted_image:
            image_name_encrypted = (
                f"container{index}_image{image_index}_{self.flags_image_type}_encrypted.bin"
            )
            write_file(self.encrypted_image, os.path.join(data_path, image_name_encrypted), "wb")
            if image_name == "N/A":
                image_name = image_name_encrypted

        ret_cfg["image_path"] = image_name
        ret_cfg["image_offset"] = hex(self.image_offset)
        ret_cfg["load_address"] = hex(self.load_address)
        ret_cfg["entry_point"] = hex(self.entry_point)
        ret_cfg["image_type"] = self.flags_image_type
        ret_cfg["core_id"] = {0x1: "cortex-m33", 0x02: "cortex-m7"}.get(
            self.flags_core_id, f"Unknown ID: {self.flags_core_id}"
        )
        ret_cfg["is_encrypted"] = bool(self.flags_is_encrypted)
        ret_cfg["boot_flags"] = self.flags_boot_flags
        ret_cfg["meta_data_start_cpu_id"] = self.metadata_start_cpu_id
        ret_cfg["meta_data_mu_cpu_id"] = self.metadata_mu_cpu_id
        ret_cfg["meta_data_start_partition_id"] = self.metadata_start_partition_id
        ret_cfg["hash_type"] = self.get_hash_from_flags(self.flags)

        return ret_cfg


class SRKRecord(HeaderContainerInversed):
    """Class representing SRK (Super Root Key) record as part of SRK table in the AHAB container.

    The class holds information about RSA/ECDSA encryption algorithms.

    SRK Record::

        +-----+---------------------------------------------------------------+
        |Off  |    Byte 3    |    Byte 2      |    Byte 1    |     Byte 0     |
        +-----+---------------------------------------------------------------+
        |0x00 |    Tag       |         Length of SRK         | Signing Algo   |
        +-----+---------------------------------------------------------------+
        |0x04 |    Hash Algo | Key Size/Curve |    Not Used  |   SRK Flags    |
        +-----+---------------------------------------------------------------+
        |0x08 | RSA modulus len / ECDSA X len | RSA exponent len / ECDSA Y len|
        +-----+---------------------------------------------------------------+
        |0x0C | RSA modulus (big endian) / ECDSA X (big endian)               |
        +-----+---------------------------------------------------------------+
        |...  | RSA exponent (big endian) / ECDSA Y (big endian)              |
        +-----+---------------------------------------------------------------+

    """

    TAG = AHABTags.SRK_RECORD
    VERSION = [0x21, 0x27]  # type: ignore
    VERSION_ALGORITHMS = {"rsa": 0x21, "ecdsa": 0x27}
    HASH_ALGORITHM = {"sha256": 0x0, "sha384": 0x1, "sha512": 0x2}
    ECC_KEY_TYPE = {"secp521r1": 0x3, "secp384r1": 0x2, "secp256r1": 0x1, "prime256v1": 0x1}
    RSA_KEY_TYPE = {2048: 0x5, 4096: 0x7}
    KEY_SIZES = {0x1: (32, 32), 0x2: (48, 48), 0x3: (66, 66), 0x5: (128, 128), 0x7: (256, 256)}

    def __init__(
        self,
        src_key: Optional[PublicKey] = None,
        signing_algorithm: str = "rsa",
        hash_type: str = "sha256",
        key_size: int = 0,
        srk_flags: int = 0,
        crypto_param1: bytes = b"",
        crypto_param2: bytes = b"",
    ):
        """Class object initializer.

        :param src_key: Optional source public key used to create the SRKRecord
        :param signing_algorithm: signing algorithm type.
        :param hash_type: hash algorithm type.
        :param key_size: key (curve) size.
        :param srk_flags: flags.
        :param crypto_param1: RSA modulus (big endian) or ECDSA X (big endian)
        :param crypto_param2: RSA exponent (big endian) or ECDSA Y (big endian)
        """
        super().__init__(
            tag=self.TAG, length=-1, version=self.VERSION_ALGORITHMS[signing_algorithm]
        )
        self.src_key = src_key
        self.hash_algorithm = self.HASH_ALGORITHM[hash_type]
        self.key_size = key_size
        self.srk_flags = srk_flags
        self.crypto_param1 = crypto_param1
        self.crypto_param2 = crypto_param2

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SRKRecord):
            if (
                super().__eq__(other)  # pylint: disable=too-many-boolean-expressions
                and self.hash_algorithm == other.hash_algorithm
                and self.key_size == other.key_size
                and self.srk_flags == other.srk_flags
                and self.crypto_param1 == other.crypto_param1
                and self.crypto_param2 == other.crypto_param2
            ):
                return True

        return False

    def __len__(self) -> int:
        return super().__len__() + len(self.crypto_param1) + len(self.crypto_param2)

    @classmethod
    def _format(cls) -> str:
        return (
            super()._format()
            + UINT8  # Hash Algorithm
            + UINT8  # Key Size / Curve
            + UINT8  # Not Used
            + UINT8  # SRK Flags
            + UINT16  # crypto_param2_len
            + UINT16  # crypto_param1_len
        )

    def update_fields(self) -> None:
        """Update all fields depended on input values."""
        self.length = len(self)

    def export(self) -> bytes:
        """Export one SRK record, little big endian format.

        The crypto parameters (X/Y for ECDSA or modulus/exponent) are kept in
        big endian form.

        :return: bytes representing container content.
        """
        return (
            pack(
                self._format(),
                self.tag,
                self.length,
                self.version,
                self.hash_algorithm,
                self.key_size,
                RESERVED,
                self.srk_flags,
                len(self.crypto_param1),
                len(self.crypto_param2),
            )
            + self.crypto_param1
            + self.crypto_param2
        )

    def validate(self) -> None:
        """Validate object data.

        :raises SPSDKValueError: Invalid any value of Image Array entry
        """
        self.validate_header()
        if self.hash_algorithm is None or not check_range(self.hash_algorithm, end=2):
            raise SPSDKValueError(f"SRK record: Invalid Hash algorithm: {self.hash_algorithm}")

        if self.srk_flags is None or not check_range(self.srk_flags, end=0xFF):
            raise SPSDKValueError(f"SRK record: Invalid Flags: {self.srk_flags}")

        if self.version == 0x21:  # Signing algorithm RSA
            if self.key_size not in self.RSA_KEY_TYPE.values():
                raise SPSDKValueError(
                    f"SRK record: Invalid Key size in match to RSA signing algorithm: {self.key_size}"
                )
        elif self.version == 0x27:  # Signing algorithm ECDSA
            if self.key_size not in self.ECC_KEY_TYPE.values():
                raise SPSDKValueError(
                    f"SRK record: Invalid Key size in match to ECDSA signing algorithm: {self.key_size}"
                )
        else:
            raise SPSDKValueError(f"SRK record: Invalid Signing algorithm: {self.version}")

        # Check lengths

        if (
            self.crypto_param1 is None
            or len(self.crypto_param1) != self.KEY_SIZES[self.key_size][0]
        ):
            raise SPSDKValueError(
                f"SRK record: Invalid Crypto parameter 1: 0x{self.crypto_param1.hex()}"
            )

        if (
            self.crypto_param2 is None
            or len(self.crypto_param2) != self.KEY_SIZES[self.key_size][1]
        ):
            raise SPSDKValueError(
                f"SRK record: Invalid Crypto parameter 2: 0x{self.crypto_param2.hex()}"
            )

        computed_length = (
            self.fixed_length()
            + self.KEY_SIZES[self.key_size][0]
            + self.KEY_SIZES[self.key_size][1]
        )
        if self.length != len(self) or self.length != computed_length:
            raise SPSDKValueError(
                f"SRK record: Invalid Length: Length of SRK:{self.length}"
                f", Computed Length of SRK:{computed_length}"
            )

    @staticmethod
    def create_from_key(public_key: PublicKey, srk_flags: int = 0) -> "SRKRecord":
        """Create instance from key data.

        :param public_key: Loaded public key.
        :param srk_flags: SRK flags for key.
        :raises SPSDKValueError: Unsupported keys size is detected.
        """
        if isinstance(public_key, RSAPublicKey):
            par_n: int = public_key.public_numbers().n
            par_e: int = public_key.public_numbers().e
            key_size = SRKRecord.RSA_KEY_TYPE[public_key.key_size]
            return SRKRecord(
                src_key=public_key,
                signing_algorithm="rsa",
                hash_type="sha256",
                key_size=key_size,
                srk_flags=srk_flags,
                crypto_param1=par_n.to_bytes(
                    length=SRKRecord.KEY_SIZES[key_size][0], byteorder="big"
                ),
                crypto_param2=par_e.to_bytes(
                    length=SRKRecord.KEY_SIZES[key_size][1], byteorder="big"
                ),
            )

        assert isinstance(public_key, EllipticCurvePublicKey)
        par_x: int = public_key.public_numbers().x
        par_y: int = public_key.public_numbers().y
        key_size = SRKRecord.ECC_KEY_TYPE[public_key.curve.name]

        if not public_key.key_size in [256, 384, 521]:
            raise SPSDKValueError(f"Unsupported ECC key for AHAB container: {public_key.key_size}")
        hash_type = {256: "sha256", 384: "sha384", 521: "sha512"}[public_key.key_size]

        return SRKRecord(
            signing_algorithm="ecdsa",
            hash_type=hash_type,
            key_size=key_size,
            srk_flags=srk_flags,
            crypto_param1=par_x.to_bytes(length=SRKRecord.KEY_SIZES[key_size][0], byteorder="big"),
            crypto_param2=par_y.to_bytes(length=SRKRecord.KEY_SIZES[key_size][1], byteorder="big"),
        )

    @staticmethod
    def parse(binary: bytes, offset: int = 0) -> "SRKRecord":
        """Parse input binary chunk to the container object.

        :param binary: Binary data with SRK record block to parse.
        :param offset: Offset to SRK record block data, default is 0.
        :raises SPSDKLengthError: Invalid length of SRK record data block.
        :return: SRK record recreated from the binary data.
        """
        SRKRecord._check_container_head(binary[offset:])
        (
            _,  # tag
            container_length,
            signing_algo,
            hash_algo,
            key_size_curve,
            _,  # reserved
            srk_flags,
            crypto_param1_len,
            crypto_param2_len,
        ) = unpack(SRKRecord._format(), binary[offset : offset + SRKRecord.fixed_length()])

        # Although we know from the total length, that we have enough bytes,
        # the crypto param lengths may be set improperly and we may get into trouble
        # while parsing. So we need to check the lengths as well.
        param_length = SRKRecord.fixed_length() + crypto_param1_len + crypto_param2_len
        if container_length < param_length:
            raise SPSDKLengthError(
                "Parsing error of SRK Record data."
                "SRK record lengths mismatch. Sum of lengths declared in container "
                f"({param_length} (= {SRKRecord.fixed_length()} + {crypto_param1_len} + "
                f"{crypto_param2_len})) doesn't match total length declared in container ({container_length})!"
            )
        crypto_param1 = binary[
            offset
            + SRKRecord.fixed_length() : offset
            + SRKRecord.fixed_length()
            + crypto_param1_len
        ]
        crypto_param2 = binary[
            offset
            + SRKRecord.fixed_length()
            + crypto_param1_len : offset
            + SRKRecord.fixed_length()
            + crypto_param1_len
            + crypto_param2_len
        ]

        return SRKRecord(
            signing_algorithm=get_key_by_val(SRKRecord.VERSION_ALGORITHMS, signing_algo),
            hash_type=get_key_by_val(SRKRecord.HASH_ALGORITHM, hash_algo),
            key_size=key_size_curve,
            srk_flags=srk_flags,
            crypto_param1=crypto_param1,
            crypto_param2=crypto_param2,
        )

    def get_key_name(self) -> str:
        """Get text key name in SRK record.

        :return: Key name.
        """
        if get_key_by_val(self.VERSION_ALGORITHMS, self.version) == "rsa":
            return f"rsa{get_key_by_val(self.RSA_KEY_TYPE, self.key_size)}"
        if get_key_by_val(self.VERSION_ALGORITHMS, self.version) == "ecdsa":
            return get_key_by_val(self.ECC_KEY_TYPE, self.key_size)
        return "Unknown Key name!"

    def store_public_key(self, filename: str, encoding: Encoding = Encoding.PEM) -> None:
        """Store the SRK public key as a file.

        :param filename: Filename path of new public key.
        :param encoding: Public key encoding style, default is PEM.
        """
        par1 = int.from_bytes(self.crypto_param1, "big")
        par2 = int.from_bytes(self.crypto_param2, "big")
        if get_key_by_val(self.VERSION_ALGORITHMS, self.version) == "rsa":
            # RSA Key to store
            rsa_pub_key = recreate_rsa_public_key(par1, par2)
            save_rsa_public_key(public_key=rsa_pub_key, file_path=filename, encoding=encoding)
        else:
            # ECDSA Key to store
            curve = get_key_by_val(self.ECC_KEY_TYPE, self.key_size)
            ecc_pub_key = recreate_ecc_public_key(par1, par2, curve=curve)
            save_ecc_public_key(ec_public_key=ecc_pub_key, file_path=filename, encoding=encoding)


class SRKTable(HeaderContainerInversed):
    """Class representing SRK (Super Root Key) table in the AHAB container as part of signature block.

    SRK Table::

        +-----+---------------------------------------------------------------+
        |Off  |    Byte 3    |    Byte 2      |    Byte 1    |     Byte 0     |
        +-----+---------------------------------------------------------------+
        |0x00 |    Tag       |         Length of SRK Table   |     Version    |
        +-----+---------------------------------------------------------------+
        |0x04 |    SRK Record 1                                               |
        +-----+---------------------------------------------------------------+
        |...  |    SRK Record 2                                               |
        +-----+---------------------------------------------------------------+
        |...  |    SRK Record 3                                               |
        +-----+---------------------------------------------------------------+
        |...  |    SRK Record 4                                               |
        +-----+---------------------------------------------------------------+

    """

    TAG = AHABTags.SRK_TABLE
    VERSION = 0x42
    SRK_RECORDS_CNT = 4

    def __init__(self, srk_records: Optional[List[SRKRecord]] = None) -> None:
        """Class object initializer.

        :param srk_records: list of SRKRecord objects.
        """
        super().__init__(tag=self.TAG, length=-1, version=self.VERSION)
        self._srk_records: List[SRKRecord] = srk_records or []
        self.length = len(self)

    def clear(self) -> None:
        """Clear the SRK Table Object."""
        self._srk_records.clear()
        self.length = -1

    def add_record(self, public_key: PublicKey) -> None:
        """Add SRK table record.

        :param public_key: Loaded public key.
        """
        self._srk_records.append(SRKRecord.create_from_key(public_key))
        self.length = len(self)

    def __eq__(self, other: object) -> bool:
        """Compares for equality with other SRK Table objects.

        :param other: object to compare with.
        :return: True on match, False otherwise.
        """
        if isinstance(other, SRKTable):
            if super().__eq__(other) and self._srk_records == other._srk_records:
                return True

        return False

    def __len__(self) -> int:
        records_len = 0
        for record in self._srk_records:
            records_len += len(record)
        return super().__len__() + records_len

    def update_fields(self) -> None:
        """Update all fields depended on input values."""
        for rec in self._srk_records:
            rec.update_fields()
        self.length = len(self)

    def compute_srk_hash(self) -> bytes:
        """Computes a SHA256 out of all SRK records.

        :return: SHA256 computed over SRK records.
        """
        return crypto_backend().hash(data=self.export(), algorithm="sha256")

    def get_source_keys(self) -> Optional[List[PublicKey]]:
        """Optionally return list of source public keys.

        :return: List of public keys.
        """
        ret = []
        for srk in self._srk_records:
            if not srk.src_key:
                return None
            ret.append(srk.src_key)
        return ret

    def export(self) -> bytes:
        """Serializes container object into bytes in little endian.

        :return: bytes representing container content.
        """
        data = pack(self._format(), self.tag, self.length, self.version)

        for srk_record in self._srk_records:
            data += srk_record.export()

        return data

    def validate(self, data: Dict[str, Any]) -> None:
        """Validate object data.

        :param data: Additional validation data.
        :raises SPSDKValueError: Invalid any value of Image Array entry
        """
        self.validate_header()
        if self._srk_records is None or len(self._srk_records) != self.SRK_RECORDS_CNT:
            raise SPSDKValueError(f"SRK table: Invalid SRK records: {self._srk_records}")

        # Validate individual SRK records
        for srk_rec in self._srk_records:
            srk_rec.validate()

        # Check if all SRK records has same type
        srk_records_info = [
            (x.version, x.hash_algorithm, x.key_size, x.length) for x in self._srk_records
        ]

        messages = ["Signing algorithm", "Hash algorithm", "Key Size", "Length"]
        for i in range(4):
            if not all(srk_records_info[0][i] == x[i] for x in srk_records_info):
                raise SPSDKValueError(
                    f"SRK table: SRK records haven't same {messages[i]}: {[x[i] for x in srk_records_info]}"
                )

        if "srkh_sha_supports" in data.keys():
            if (
                get_key_by_val(SRKRecord.HASH_ALGORITHM, self._srk_records[0].hash_algorithm)
                not in data["srkh_sha_supports"]
            ):
                raise SPSDKValueError(
                    "SRK table: SRK records haven't supported hash algorithm:"
                    f" Used:{self._srk_records[0].hash_algorithm} is not member of"
                    f" {data['srkh_sha_supports']}"
                )
        # Check container length
        if self.length != len(self):
            raise SPSDKValueError(
                f"SRK table: Invalid Length of SRK table: {self.length} != {len(self)}"
            )

    @staticmethod
    def parse(binary: bytes, offset: int = 0) -> "SRKTable":
        """Parse input binary chunk to the container object.

        :param binary: Binary data with SRK table block to parse.
        :param offset: Offset to SRK table block data, default is 0.
        :raises SPSDKLengthError: Invalid length of SRK table data block.
        :return: Object recreated from the binary data.
        """
        SRKTable._check_container_head(binary[offset:])
        srk_rec_offset = SRKTable.fixed_length()
        _, container_length, _ = unpack(
            SRKTable._format(), binary[offset : offset + srk_rec_offset]
        )
        if ((container_length - srk_rec_offset) % SRKTable.SRK_RECORDS_CNT) != 0:
            raise SPSDKLengthError("SRK table: Invalid length of SRK records data.")
        srk_rec_size = math.ceil((container_length - srk_rec_offset) / SRKTable.SRK_RECORDS_CNT)

        # try to parse records
        srk_records: List[SRKRecord] = []
        for _ in range(SRKTable.SRK_RECORDS_CNT):
            srk_record = SRKRecord.parse(binary, offset + srk_rec_offset)
            srk_rec_offset += srk_rec_size
            srk_records.append(srk_record)

        return SRKTable(srk_records=srk_records)

    def create_config(self, index: int, data_path: str) -> CM:
        """Create configuration of the AHAB Image SRK Table.

        :param index: Container Index.
        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        ret_cfg = CM()
        cfg_srks = CS()

        for ix_srk, srk in enumerate(self._srk_records):
            filename = f"container{index}_srk_public_key{ix_srk}_{srk.get_key_name()}.PEM"
            srk.store_public_key(os.path.join(data_path, filename))
            cfg_srks.append(filename)

        ret_cfg["image_array"] = cfg_srks
        return ret_cfg

    @staticmethod
    def load_from_config(
        config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> "SRKTable":
        """Converts the configuration option into an AHAB image object.

        "config" content of container configurations.

        :param config: array of AHAB containers configuration dictionaries.
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: SRK Table object.
        """
        srk_table = SRKTable()
        srk_list = config.get("srk_array")
        assert isinstance(srk_list, list)
        for srk_key in srk_list:
            assert isinstance(srk_key, str)
            srk_key_path = find_file(srk_key, search_paths=search_paths)
            srk_table.add_record(extract_public_key(srk_key_path))
        return srk_table


class ContainerSignature(HeaderContainer):
    """Class representing the signature in AHAB container as part of the signature block.

    Signature::

        +-----+--------------+--------------+----------------+----------------+
        |Off  |    Byte 3    |    Byte 2    |      Byte 1    |     Byte 0     |
        +-----+--------------+--------------+----------------+----------------+
        |0x00 |    Tag       | Length (MSB) | Length (LSB)   |     Version    |
        +-----+--------------+--------------+----------------+----------------+
        |0x04 |                        Reserved                               |
        +-----+---------------------------------------------------------------+
        |0x08 |                      Signature Data                           |
        +-----+---------------------------------------------------------------+

    """

    TAG = AHABTags.SIGNATURE
    VERSION = 0x00

    def __init__(
        self, signature_data: Optional[bytes] = None, signing_key: Optional[PrivateKey] = None
    ) -> None:
        """Class object initializer.

        :param signature_data: signature.
        :param signing_key: Key use to sign the image.
        """
        super().__init__(tag=self.TAG, length=-1, version=self.VERSION)
        self._signature_data = signature_data or b""
        self._signing_key = signing_key
        self.length = len(self)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, ContainerSignature):
            if super().__eq__(other) and self._signature_data == other._signature_data:
                return True

        return False

    def __len__(self) -> int:
        if (not self._signature_data or len(self._signature_data) == 0) and self._signing_key:
            return super().__len__() + crypto_backend().sign_size(self._signing_key)

        sign_data_len = len(self._signature_data)
        if sign_data_len == 0:
            return 0

        return super().__len__() + sign_data_len

    @property
    def signature_data(self) -> bytes:
        """Get the signature data.

        :return: signature data.
        """
        return self._signature_data

    @signature_data.setter
    def signature_data(self, value: bytes) -> None:
        """Set the signature data.

        :param value: signature data.
        """
        self._signature_data = value
        self.length = len(self)

    @classmethod
    def _format(cls) -> str:
        return super()._format() + UINT32  # reserved

    def sign(self, data_to_sign: bytes) -> None:
        """Sign the data_to_sign and store signature into class.

        :param data_to_sign: Data to be signed by store private key
        :raises SPSDKError: Missing private key or raw signature data.
        """
        if not self._signing_key and len(self._signature_data) == 0:
            raise SPSDKError(
                "The Signature container doesn't have specified the private tey to sign."
            )

        if self._signing_key:
            if isinstance(self._signing_key, RSAPrivateKey):
                self._signature_data = crypto_backend().rsa_sign(self._signing_key, data_to_sign)  # type: ignore
            else:
                self._signature_data = crypto_backend().ecc_sign(
                    self._signing_key, data_to_sign  # type: ignore
                )

    def export(self) -> bytes:
        """Export signature data that is part of Signature Block.

        :return: bytes representing container signature content.
        """
        if len(self) == 0:
            return b""

        data = (
            pack(
                self._format(),
                self.version,
                self.length,
                self.tag,
                RESERVED,
            )
            + self._signature_data
        )

        return data

    def validate(self) -> None:
        """Validate object data.

        :raises SPSDKValueError: Invalid any value of Image Array entry
        """
        self.validate_header()
        if self._signature_data is None or len(self._signature_data) < 20:
            raise SPSDKValueError(
                f"Signature: Invalid Signature data: 0x{self.signature_data.hex()}"
            )
        if self.length != len(self):
            raise SPSDKValueError(
                f"Signature: Invalid Signature length: {self.length} != {len(self)}."
            )

    @staticmethod
    def parse(binary: bytes, offset: int = 0) -> "ContainerSignature":
        """Parse input binary chunk to the container object.

        :param binary: Binary data with Container signature block to parse.
        :param offset: Offset to Container signature block data, default is 0.
        :return: Object recreated from the binary data.
        """
        ContainerSignature._check_container_head(binary[offset:])
        fix_len = ContainerSignature.fixed_length()

        _, container_length, _, _ = unpack(
            ContainerSignature._format(), binary[offset : offset + fix_len]
        )
        signature_data = binary[offset + fix_len : offset + container_length]

        return ContainerSignature(signature_data=signature_data)

    @staticmethod
    def load_from_config(
        config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> "ContainerSignature":
        """Converts the configuration option into an AHAB image object.

        "config" content of container configurations.

        :param config: array of AHAB containers configuration dictionaries.
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: Container signature object.
        """
        signing_key_cfg = config.get("signing_key")
        assert signing_key_cfg
        signing_key_path = find_file(signing_key_cfg, search_paths=search_paths)
        return ContainerSignature(signing_key=load_private_key(signing_key_path))


class Certificate(HeaderContainer):
    """Class representing certificate in the AHAB container as part of the signature block.

    The Certificate comes in two forms - with and without UUID.

    Certificate format 1::

        +-----+--------------+--------------+----------------+----------------+
        |Off  |    Byte 3    |    Byte 2    |      Byte 1    |     Byte 0     |
        +-----+--------------+--------------+----------------+----------------+
        |0x00 |    Tag       | Length (MSB) | Length (LSB)   |     Version    |
        +-----+--------------+--------------+----------------+----------------+
        |0x04 | Permissions  | Perm (invert)|      Signature offset           |
        +-----+--------------+--------------+---------------------------------+
        |0x08 |                        Public Key                             |
        +-----+---------------------------------------------------------------+
        |...  |                        Signature                              |
        +-----+---------------------------------------------------------------+

    Certificate format 2::

        +-----+--------------+--------------+----------------+----------------+
        |Off  |    Byte 3    |    Byte 2    |      Byte 1    |     Byte 0     |
        +-----+--------------+--------------+----------------+----------------+
        |0x00 |    Tag       | Length (MSB) | Length (LSB)   |     Version    |
        +-----+--------------+--------------+----------------+----------------+
        |0x04 | Permissions  | Perm (invert)|      Signature offset           |
        +-----+--------------+--------------+---------------------------------+
        |0x08 |                            UUID                               |
        +-----+---------------------------------------------------------------+
        |...  |                        Public Key                             |
        +-----+---------------------------------------------------------------+
        |...  |                        Signature                              |
        +-----+---------------------------------------------------------------+

    """

    TAG = [AHABTags.CERTIFICATE_UUID, AHABTags.CERTIFICATE_NON_UUID]  # type: ignore
    UUID_LEN = 16
    UUID_OFFSET = 0x08
    VERSION = 0x00
    PERM_NXP = {
        "secure_enclave_debug": 0x02,
        "hdmi_debug": 0x04,
        "life_cycle": 0x10,
        "hdcp_fuses": 0x20,
    }
    PERM_OEM = {
        "container": 0x01,
        "phbc_debug": 0x02,
        "soc_debug_domain_1": 0x04,
        "soc_debug_domain_2": 0x08,
        "life_cycle": 0x10,
        "monotonic_counter": 0x20,
    }
    PERM_SIZE = 8

    def __init__(
        self,
        permissions: int = 0,
        uuid: Optional[bytes] = None,
        public_key: Optional[SRKRecord] = None,
        signing_key: Optional[PrivateKey] = None,
    ):
        """Class object initializer.

        :param permissions: used to indicate what a certificate can be used for.
        :param uuid: optional 128-bit unique identifier.
        :param public_key: public Key. SRK record entry describing the key.
        :param signing_key: signing key for certificate. Signature is calculated over
            all data from beginning of the certificate up to but not including the signature.
        """
        tag = AHABTags.CERTIFICATE_UUID if uuid else AHABTags.CERTIFICATE_NON_UUID
        super().__init__(tag=tag, length=-1, version=self.VERSION)
        self._permissions = permissions
        self.signature_offset = -1
        self._uuid = uuid
        self.public_key = public_key
        self._signing_key = signing_key
        self.signature = b""

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Certificate):
            if (
                super().__eq__(other)  # pylint: disable=too-many-boolean-expressions
                and self._permissions == other._permissions
                and self.signature_offset == other.signature_offset
                and self._uuid == other._uuid
                and self.public_key == other.public_key
                and self.signature == other.signature
            ):
                return True

        return False

    @classmethod
    def _format(cls) -> str:
        return (
            super()._format()  # endianness, header: version, length, tag
            + UINT16  # signature offset
            + UINT8  # inverted permissions
            + UINT8  # permissions
        )

    def __len__(self) -> int:
        assert self.public_key
        uuid_len = len(self._uuid) if self._uuid else 0
        sign_size = (
            crypto_backend().sign_size(self._signing_key)
            if self._signing_key
            else len(self.signature)
        )
        return super().__len__() + uuid_len + len(self.public_key) + sign_size

    @staticmethod
    def create_permissions(permissions: List[str]) -> int:
        """Create integer representation of permission field.

        :param permissions: List of string permissions.
        :return: Integer representation of permissions.
        """
        ret = 0
        permission_map = {}
        permission_map.update(Certificate.PERM_NXP)
        permission_map.update(Certificate.PERM_OEM)
        for permission in permissions:
            ret |= permission_map[permission]

        return ret

    def create_config_permissions(self, srk_set: str) -> List[str]:
        """Create list of string representation of permission field.

        :param srk_set: SRK set to get proper string values.
        :return: List of string representation of permissions.
        """
        ret = []
        perm_maps = {"nxp": self.PERM_NXP, "oem": self.PERM_OEM}
        perm_map = perm_maps.get(srk_set)

        for i in range(self.PERM_SIZE):
            if self._permissions & (1 << i):
                ret.append(
                    get_key_by_val(perm_map, 1 << i)
                    if perm_map and (1 << i) in perm_map.values()
                    else f"Unknown permission {hex(1<<i)}"
                )

        return ret

    def self_sign(self) -> None:
        """Sign self by the signature key and store result into _signature field."""
        assert self.public_key
        if self._signing_key:
            data_to_sign = (
                pack(
                    self._format(),
                    self.version,
                    self.length,
                    self.tag,
                    self.signature_offset,
                    ~self._permissions & 0xFF,
                    self._permissions,
                )
                + self.public_key.export()
            )
            if isinstance(self._signing_key, RSAPrivateKey):
                self.signature = crypto_backend().rsa_sign(self._signing_key, data_to_sign)  # type: ignore
            else:
                self.signature = crypto_backend().ecc_sign(
                    self._signing_key, data_to_sign  # type: ignore
                )

    def update_fields(self) -> None:
        """Update all fields depended on input values."""
        assert self.public_key
        self.public_key.update_fields()
        self.tag = AHABTags.CERTIFICATE_UUID if self._uuid else AHABTags.CERTIFICATE_NON_UUID
        self.signature_offset = (
            super().__len__() + len(self._uuid) if self._uuid else 0 + len(self.public_key)
        )
        self.length = (
            crypto_backend().sign_size(self._signing_key)
            if self._signing_key
            else len(self.signature) + self.signature_offset
        )
        self.self_sign()

    def export(self) -> bytes:
        """Export container certificate object into bytes.

        :return: bytes representing container content.
        """
        assert self.public_key
        cert = (
            pack(
                self._format(),
                self.version,
                self.length,
                self.tag,
                self.signature_offset,
                ~self._permissions & 0xFF,
                self._permissions,
            )
            + self.public_key.export()
            + self.signature
        )
        # if uuid is present, insert it into the cert data
        if self._uuid:
            cert = cert[: self.UUID_OFFSET] + self._uuid + cert[self.UUID_OFFSET :]

        return cert

    def validate(self) -> None:
        """Validate object data.

        :raises SPSDKValueError: Invalid any value of Image Array entry
        """
        self.validate_header()
        if self._permissions is None or not check_range(self._permissions, end=0xFF):
            raise SPSDKValueError(f"Certificate: Invalid Permission data: {self._permissions}")
        if self.public_key is None:
            raise SPSDKValueError("Certificate: Missing public key.")
        self.public_key.validate()

        if not (self._signing_key and self.signature):
            if self._signing_key is None or not isinstance(self._signing_key, _PrivateKeyTuple):
                raise SPSDKValueError(f"Certificate: Invalid signing key. {str(self._signing_key)}")
            if self.signature is None or len(self.signature) != crypto_backend().sign_size(
                self._signing_key
            ):
                raise SPSDKValueError(f"Certificate: Missing signature. {str(self._signing_key)}")
            if len(self.signature) != crypto_backend().sign_size(self._signing_key):
                raise SPSDKValueError(
                    f"Certificate: Invalid signature length. "
                    f"{len(self.signature)} != {crypto_backend().sign_size(self._signing_key)}"
                )
        expected_signature_offset = (
            super().__len__() + len(self._uuid) if self._uuid else 0 + len(self.public_key)
        )
        if self.signature_offset != expected_signature_offset:
            raise SPSDKValueError(
                f"Certificate: Invalid signature offset. "
                f"{self.signature_offset} != {expected_signature_offset}"
            )
        if self._uuid and len(self._uuid) != self.UUID_LEN:
            raise SPSDKValueError(
                f"Certificate: Invalid UUID size. {len(self._uuid)} != {self.UUID_LEN}"
            )

    @staticmethod
    def parse(binary: bytes, offset: int = 0) -> "Certificate":
        """Parse input binary chunk to the container object.

        :param binary: Binary data with Certificate block to parse.
        :param offset: Offset to Certificate block data, default is 0.
        :raises SPSDKValueError: Certificate permissions are invalid.
        :return: Object recreated from the binary data.
        """
        Certificate._check_container_head(binary[offset:])
        certificate_data_offset = Certificate.fixed_length()
        image_format = Certificate._format()
        (
            _,  # version,
            container_length,
            tag,
            signature_offset,
            inverted_permissions,
            permissions,
        ) = unpack(image_format, binary[offset : offset + certificate_data_offset])

        if inverted_permissions != ~permissions & 0xFF:
            raise SPSDKValueError("Certificate parser: Invalid permissions record.")

        uuid = None

        if AHABTags.CERTIFICATE_UUID == tag:
            uuid = binary[
                offset
                + certificate_data_offset : offset
                + certificate_data_offset
                + Certificate.UUID_LEN
            ]
            certificate_data_offset += Certificate.UUID_LEN

        public_key = SRKRecord.parse(binary[offset + certificate_data_offset :])

        signature = binary[offset + signature_offset : offset + container_length]

        cert = Certificate(
            permissions=permissions,
            uuid=uuid,
            public_key=public_key,
        )
        cert.signature = signature
        return cert

    def create_config(self, index: int, data_path: str, srk_set: str = "none") -> CM:
        """Create configuration of the AHAB Image Certificate.

        :param index: Container Index.
        :param data_path: Path to store the data files of configuration.
        :param srk_set: SRK set to know how to create certificate permissions.
        :return: Configuration dictionary.
        """
        ret_cfg = CM()
        assert self.public_key
        ret_cfg["permissions"] = CS(self.create_config_permissions(srk_set))
        if self._uuid:
            ret_cfg["uuid"] = "0x" + self._uuid.hex()
        filename = f"container{index}_certificate_public_key_{self.public_key.get_key_name()}.PEM"
        self.public_key.store_public_key(os.path.join(data_path, filename))
        ret_cfg["public_key"] = filename
        ret_cfg["signing_key"] = "N/A"

        return ret_cfg

    @staticmethod
    def load_from_config(
        config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> "Certificate":
        """Converts the configuration option into an AHAB image signature block certificate object.

        "config" content of container configurations.

        :param config: array of AHAB containers configuration dictionaries.
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: Certificate object.
        """
        cert_permissions_list = config.get("permissions") or []
        cert_uuid_raw = config.get("uuid")
        cert_uuid = value_to_bytes(cert_uuid_raw) if cert_uuid_raw else None
        cert_public_key_path = config.get("public_key")
        assert isinstance(cert_public_key_path, str)
        cert_signing_key_path = config.get("signing_key")
        assert isinstance(cert_signing_key_path, str)
        cert_public_key_path = find_file(cert_public_key_path, search_paths=search_paths)
        cert_public_key = extract_public_key(cert_public_key_path)
        cert_signing_key = load_binary(cert_signing_key_path, search_paths=search_paths)
        cert_srk_rec = SRKRecord.create_from_key(cert_public_key)
        return Certificate(
            permissions=Certificate.create_permissions(cert_permissions_list),
            uuid=cert_uuid,
            public_key=cert_srk_rec,
            signing_key=load_private_key_from_data(cert_signing_key),
        )


class Blob(HeaderContainer):
    """The Blob object used in Signature Container.

    Blob (DEK) content::

        +-----+--------------+--------------+----------------+----------------+
        |Off  |    Byte 3    |    Byte 2    |      Byte 1    |     Byte 0     |
        +-----+--------------+--------------+----------------+----------------+
        |0x00 |    Tag       | Length (MSB) | Length (LSB)   |     Version    |
        +-----+--------------+--------------+----------------+----------------+
        |0x04 |    Mode      | Algorithm    |      Size      |     Flags      |
        +-----+--------------+--------------+----------------+----------------+
        |0x08 |                        Wrapped Key                            |
        +-----+--------------+--------------+----------------+----------------+

    """

    TAG = AHABTags.BLOB
    VERSION = 0x00
    FLAGS = 0x80  # KEK key flag
    SUPPORTED_KEY_SIZES = [128, 192, 256]

    def __init__(
        self,
        flags: int = 0x80,
        size: int = 0,
        dek: Optional[bytes] = None,
        mode: Optional[int] = None,
        algorithm: Optional[int] = None,
        dek_keyblob: Optional[bytes] = None,
    ) -> None:
        """Class object initializer.

        :param flags: Keyblob flags
        :param size: key size [128,192,256]
        :param dek: DEK key
        :param mode: DEK BLOB mode
        :param algorithm: Encryption algorithm
        :param dek_keyblob: DEK keyblob
        """
        super().__init__(tag=self.TAG, length=56 + size // 8, version=self.VERSION)
        self.mode = mode
        self.algorithm = algorithm
        self._size = size
        self.flags = flags
        self.dek = dek
        self.dek_keyblob = dek_keyblob or b""

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Blob):
            if (
                super().__eq__(other)  # pylint: disable=too-many-boolean-expressions
                and self.mode == other.mode
                and self.algorithm == other.algorithm
                and self._size == other._size
                and self.flags == other.flags
                and self.dek_keyblob == other.dek_keyblob
            ):
                return True

        return False

    @staticmethod
    def compute_keyblob_size(key_size: int) -> int:
        """Compute Keyblob size.

        :param key_size: Input RSA key size in bits
        :return: Keyblob size in bytes.
        """
        return (key_size // 8) + 48

    @classmethod
    def _format(cls) -> str:
        return (
            super()._format()  # endianness, header: tag, length, version
            + UINT8  # mode
            + UINT8  # algorithm
            + UINT8  # size
            + UINT8  # flags
        )

    def __len__(self) -> int:
        # return super()._total_length() + len(self.dek_keyblob)
        return self.length

    def export(self) -> bytes:
        """Export Signature Block Blob.

        :return: bytes representing Signature Block Blob.
        """
        blob = (
            pack(
                self._format(),
                self.version,
                self.length,
                self.tag,
                self.flags,
                self._size // 8,
                self.algorithm,
                self.mode,
            )
            + self.dek_keyblob
        )

        return blob

    def validate(self) -> None:
        """Validate object data.

        :raises SPSDKValueError: Invalid any value of AHAB Blob
        """
        self.validate_header()

        if self._size not in self.SUPPORTED_KEY_SIZES:
            raise SPSDKValueError("AHAB Blob: Invalid key size.")
        if self.mode is None:
            raise SPSDKValueError("AHAB Blob: Invalid mode.")
        if self.algorithm is None:
            raise SPSDKValueError("AHAB Blob: Invalid algorithm.")
        if self.dek and len(self.dek) != self._size // 8:
            raise SPSDKValueError("AHAB Blob: Invalid DEK key size.")
        if self.dek_keyblob is None or len(self.dek_keyblob) != self.compute_keyblob_size(
            self._size
        ):
            raise SPSDKValueError("AHAB Blob: Invalid Wrapped key.")

    @staticmethod
    def parse(binary: bytes, offset: int = 0) -> "Blob":
        """Parse input binary chunk to the container object.

        :param binary: Binary data with Blob block to parse.
        :param offset: Offset to Blob block data, default is 0.
        :return: Object recreated from the binary data.
        """
        Blob._check_container_head(binary[offset:])
        (
            _,  # version
            container_length,
            _,  # tag
            flags,
            size,
            algorithm,  # algorithm
            mode,  # mode
        ) = unpack(Blob._format(), binary[offset : offset + Blob.fixed_length()])

        dek_keyblob = binary[offset + Blob.fixed_length() : offset + container_length]

        return Blob(
            size=size * 8, flags=flags, dek_keyblob=dek_keyblob, mode=mode, algorithm=algorithm
        )

    def create_config(self, index: int, data_path: str) -> CM:
        """Create configuration of the AHAB Image Blob.

        :param index: Container Index.
        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        ret_cfg = CM()
        assert self.dek_keyblob
        filename = f"container{index}_dek_keyblob.bin"
        write_file(self.export(), os.path.join(data_path, filename), "wb")
        ret_cfg["dek_key_size"] = self._size
        ret_cfg["dek_key"] = "N/A"
        ret_cfg["dek_keyblob"] = filename

        return ret_cfg

    @staticmethod
    def load_from_config(
        config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> "Blob":
        """Converts the configuration option into an AHAB image signature block blob object.

        "config" content of container configurations.

        :param config: Blob configuration
        :param search_paths: List of paths where to search for the file, defaults to None
        :raises SPSDKValueError: Invalid configuration - Invalid DEK KeyBlob
        :return: Blob object.
        """
        dek_size = value_to_int(config.get("dek_key_size", 128))
        dek_input = config.get("dek_key")
        dek_keyblob_input = config.get("dek_keyblob")
        assert dek_input, "Missing DEK value"
        assert dek_keyblob_input, "Missing DEK KEYBLOB value"

        dek = get_key(dek_input, dek_size // 8, search_paths)
        dek_keyblob_value = get_key(
            dek_keyblob_input, Blob.compute_keyblob_size(dek_size) + 8, search_paths
        )
        if not dek_keyblob_value:
            raise SPSDKValueError("Invalid DEK KeyBlob.")

        keyblob = Blob.parse(dek_keyblob_value)
        keyblob.dek = dek
        return keyblob

    def encrypt_data(self, iv: bytes, data: bytes) -> bytes:
        """Encrypt data.

        :param iv: Initial vector 128 bits length
        :param data: Data to encrypt
        :raises SPSDKError: Missing DEK
        :return: Encrypted data
        """
        if not self.dek:
            raise SPSDKError("The AHAB keyblob hasn't defined DEK to encrypt data")

        return crypto_backend().aes_cbc_encrypt(self.dek, data, iv)

    def decrypt_data(self, iv: bytes, encrypted_data: bytes) -> bytes:
        """Encrypt data.

        :param iv: Initial vector 128 bits length
        :param encrypted_data: Data to decrypt
        :raises SPSDKError: Missing DEK
        :return: Plain data
        """
        if not self.dek:
            raise SPSDKError("The AHAB keyblob hasn't defined DEK to encrypt data")

        return crypto_backend().aes_cbc_decrypt(self.dek, encrypted_data, iv)


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
        |                             Reserved                             |     |
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

    TAG = AHABTags.SIGNATURE_BLOCK
    VERSION = 0x00

    def __init__(
        self,
        srk_table: Optional["SRKTable"] = None,
        container_signature: Optional["ContainerSignature"] = None,
        certificate: Optional["Certificate"] = None,
        blob: Optional["Blob"] = None,
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

    @classmethod
    def _format(cls) -> str:
        return (
            super()._format()
            + UINT16  # certificate offset
            + UINT16  # SRK table offset
            + UINT16  # signature offset
            + UINT16  # blob offset
            + UINT32  # reserved
        )

    def update_fields(self) -> None:
        """Update all fields depended on input values."""
        # 1: Update SRK Table
        # Nothing to do with SRK Table
        last_offset = 0
        last_block_size = align(calcsize(self._format()), CONTAINER_ALIGNMENT)
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
            self._format(),
            self.version,
            self.length,
            self.tag,
            self._certificate_offset,
            self._srk_table_offset,
            self.signature_offset,
            self._blob_offset,
            RESERVED,
        )

        signature_block = bytearray(len(self))
        signature_block[0 : self.fixed_length()] = extended_header
        if self.srk_table:
            signature_block[
                self._srk_table_offset : self._srk_table_offset + len(self.srk_table)
            ] = self.srk_table.export()
        if self.signature:
            signature_block[
                self.signature_offset : self.signature_offset + len(self.signature)
            ] = self.signature.export()
        if self.certificate:
            signature_block[
                self._certificate_offset : self._certificate_offset + len(self.certificate)
            ] = self.certificate.export()
        if self.blob:
            signature_block[
                self._blob_offset : self._blob_offset + len(self.blob)
            ] = self.blob.export()

        return signature_block

    def validate(self, data: Dict[str, Any]) -> None:
        """Validate object data.

        :param data: Additional validation data.
        :raises SPSDKValueError: Invalid any value of Image Array entry
        """

        def check_offset(name: str, min_offset: int, offset: int) -> None:
            if offset < min_offset:
                raise SPSDKValueError(
                    f"Signature Block: Invalid {name} offset: {offset} < minimal offset {min_offset}"
                )
            if offset != align(offset, CONTAINER_ALIGNMENT):
                raise SPSDKValueError(
                    f"Signature Block: Invalid {name} offset alignment: {offset} is not aligned to 64 bits!"
                )

        self.validate_header()
        if self.length != len(self):
            raise SPSDKValueError(
                f"Signature Block: Invalid block length: {self.length} != {len(self)}"
            )
        if bool(self._srk_table_offset) != bool(self.srk_table):
            raise SPSDKValueError("Signature Block: Invalid setting of SRK table offset.")
        if bool(self.signature_offset) != bool(self.signature):
            raise SPSDKValueError("Signature Block: Invalid setting of Signature offset.")
        if bool(self._certificate_offset) != bool(self.certificate):
            raise SPSDKValueError("Signature Block: Invalid setting of Certificate offset.")
        if bool(self._blob_offset) != bool(self.blob):
            raise SPSDKValueError("Signature Block: Invalid setting of Blob offset.")

        min_offset = self.fixed_length()
        if self.srk_table:
            self.srk_table.validate(data)
            check_offset("SRK table", min_offset, self._srk_table_offset)
            min_offset = self._srk_table_offset + len(self.srk_table)
        if self.signature:
            self.signature.validate()
            check_offset("Signature", min_offset, self.signature_offset)
            min_offset = self.signature_offset + len(self.signature)
        if self.certificate:
            self.certificate.validate()
            check_offset("Certificate", min_offset, self._certificate_offset)
            min_offset = self._certificate_offset + len(self.certificate)
        if self.blob:
            self.blob.validate()
            check_offset("Blob", min_offset, self._blob_offset)
            min_offset = self._blob_offset + len(self.blob)

        if "flag_used_srk_id" in data.keys() and self.signature and self.srk_table:
            public_keys = self.srk_table.get_source_keys()
            if public_keys:
                assert self.signature._signing_key
                srk_pair_id = get_matching_key_id(public_keys, self.signature._signing_key)
                if srk_pair_id != data["flag_used_srk_id"]:
                    raise SPSDKValueError(
                        f"Signature Block: Configured SRK ID ({data['flag_used_srk_id']})"
                        f" doesn't match detected SRK ID for signing key ({srk_pair_id})."
                    )

    @staticmethod
    def parse(binary: bytes, offset: int = 0) -> "SignatureBlock":
        """Parse input binary chunk to the container object.

        :param binary: Binary data with Signature block to parse.
        :param offset: Offset to Signature block data, default is 0.
        :return: Object recreated from the binary data.
        """
        SignatureBlock._check_container_head(binary[offset:])
        (
            _,  # version
            _,  # container_length
            _,  # tag
            certificate_offset,
            srk_table_offset,
            signature_offset,
            blob_offset,
            _,  # reserved
        ) = unpack(
            SignatureBlock._format(), binary[offset : offset + SignatureBlock.fixed_length()]
        )

        signature_block = SignatureBlock()
        signature_block.srk_table = (
            SRKTable.parse(binary, offset + srk_table_offset) if srk_table_offset else None
        )
        signature_block.certificate = (
            Certificate.parse(binary, offset + certificate_offset) if certificate_offset else None
        )
        signature_block.signature = (
            ContainerSignature.parse(binary, offset + signature_offset)
            if signature_offset
            else None
        )
        signature_block.blob = Blob.parse(binary, offset + blob_offset) if blob_offset else None

        return signature_block

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
        signing_key_cfg = config.get("signing_key")
        signature_block.signature = (
            ContainerSignature.load_from_config(config, search_paths) if signing_key_cfg else None
        )

        # Certificate Block
        certificate_cfg = config.get("certificate")
        signature_block.certificate = (
            Certificate.load_from_config(certificate_cfg, search_paths) if certificate_cfg else None
        )
        # DEK blob
        blob_cfg = config.get("blob")
        signature_block.blob = Blob.load_from_config(blob_cfg, search_paths) if blob_cfg else None

        return signature_block


class AHABContainerBase(HeaderContainer):
    """Class representing AHAB container base class (common for Signed messages and AHAB Image).

    Container header::

        +---------------+----------------+----------------+----------------+
        |    Byte 3     |     Byte 2     |      Byte 1    |     Byte 0     |
        +---------------+----------------+----------------+----------------+
        |      Tag      |              Length             |    Version     |
        +---------------+---------------------------------+----------------+
        |                              Flags                               |
        +---------------+----------------+---------------------------------+
        |  # of images  |  Fuse version  |             SW version          |
        +---------------+----------------+---------------------------------+
        |              Reserved          |       Signature Block Offset    |
        +--------------------------------+---------------------------------+
        |             Payload (Signed Message or Image Array)              |
        +------------------------------------------------------------------+
        |                      Signature block                             |
        +------------------------------------------------------------------+

    """

    TAG = 0x00  # Need to be updated by child class
    VERSION = 0x00
    FLAGS_SRK_SET_OFFSET = 0
    FLAGS_SRK_SET_SIZE = 2
    FLAGS_SRK_SET_VAL = {"none": 0, "nxp": 1, "oem": 2}
    FLAGS_USED_SRK_ID_OFFSET = 4
    FLAGS_USED_SRK_ID_SIZE = 2
    FLAGS_SRK_REVOKE_MASK_OFFSET = 8
    FLAGS_SRK_REVOKE_MASK_SIZE = 4

    def __init__(
        self,
        flags: int = 0,
        fuse_version: int = 0,
        sw_version: int = 0,
        signature_block: Optional["SignatureBlock"] = None,
    ):
        """Class object initializer.

        :param flags: flags.
        :param fuse_version: value must be equal to or greater than the version
            stored in the fuses to allow loading this container.
        :param sw_version: used by PHBC (Privileged Host Boot Companion) to select
            between multiple images with same fuse version field.
        :param signature_block: signature block.
        """
        super().__init__(tag=self.TAG, length=-1, version=self.VERSION)
        self.flags = flags
        self.fuse_version = fuse_version
        self.sw_version = sw_version
        self.signature_block = signature_block or SignatureBlock()
        self.search_paths: List[str] = []

    def __eq__(self, other: object) -> bool:
        if isinstance(other, AHABContainerBase):
            if (
                super().__eq__(other)
                and self.flags == other.flags
                and self.fuse_version == other.fuse_version
                and self.sw_version == other.sw_version
            ):
                return True

        return False

    def set_flags(
        self, srk_set: str = "none", used_srk_id: int = 0, srk_revoke_mask: int = 0
    ) -> None:
        """Set the flags value.

        :param srk_set: Super Root Key (SRK) set, defaults to "none"
        :param used_srk_id: Which key from SRK set is being used, defaults to 0
        :param srk_revoke_mask: SRK revoke mask, defaults to 0
        """
        flags = self.FLAGS_SRK_SET_VAL[srk_set.lower()]
        flags |= used_srk_id << 4
        flags |= srk_revoke_mask << 8
        self.flags = flags

    @property
    def flag_srk_set(self) -> str:
        """SRK set flag in string representation.

        :return: Name of SRK Set flag.
        """
        srk_set = (self.flags >> self.FLAGS_SRK_SET_OFFSET) & ((1 << self.FLAGS_SRK_SET_SIZE) - 1)
        return get_key_by_val(self.FLAGS_SRK_SET_VAL, srk_set)

    @property
    def flag_used_srk_id(self) -> int:
        """Used SRK ID flag.

        :return: Index of Used SRK ID.
        """
        return (self.flags >> self.FLAGS_USED_SRK_ID_OFFSET) & (
            (1 << self.FLAGS_USED_SRK_ID_SIZE) - 1
        )

    @property
    def flag_srk_revoke_mask(self) -> str:
        """SRK Revoke mask flag.

        :return: SRK revoke mask in HEX.
        """
        srk_revoke_mask = (self.flags >> self.FLAGS_SRK_REVOKE_MASK_OFFSET) & (
            (1 << self.FLAGS_SRK_REVOKE_MASK_SIZE) - 1
        )
        return hex(srk_revoke_mask)

    @property
    def _signature_block_offset(self) -> int:
        """Returns current signature block offset.

        :return: Offset in bytes of Signature block.
        """
        # Constant size of Container header + Image array Entry table
        return align(
            super().__len__(),
            CONTAINER_ALIGNMENT,
        )

    @property
    def image_array_len(self) -> int:
        """Get image array length if available.

        :return: Length of image array.
        """
        return 0

    def __len__(self) -> int:
        """Get total length of AHAB container.

        :return: Size in bytes of AHAB Container.
        """
        # If there are no images just return length of header
        return self.header_length()

    def header_length(self) -> int:
        """Length of AHAB Container header.

        :return: Length in bytes of AHAB Container header.
        """
        return super().__len__() + len(  # This returns the fixed length of the container header
            self.signature_block
        )

    # We need to extend the format, as the parent provides only endianness,
    # and length.
    @classmethod
    def _format(cls) -> str:
        return (
            super()._format()
            + UINT32  # Flags
            + UINT16  # SW version
            + UINT8  # Fuse version
            + UINT8  # Number of Images
            + UINT16  # Signature Block Offset
            + UINT16  # Reserved
        )

    def update_fields(self) -> None:
        """Updates all volatile information in whole container structure.

        :raises SPSDKError: When inconsistent image array length is detected.
        """
        # Update the signature block to get overall size of it
        self.signature_block.update_fields()
        # Update the Container header length
        self.length = self.header_length()
        # Sign the image header
        if self.flag_srk_set != "none":
            assert self.signature_block.signature
            self.signature_block.signature.sign(self.get_signature_data())

    def get_signature_data(self) -> bytes:
        """Returns binary data to be signed.

        The container must be properly initialized, so the data are valid for
        signing, i.e. the offsets, lengths etc. must be set prior invoking this
        method, otherwise improper data will be signed.

        The whole container gets serialized first. Afterwards the binary data
        is sliced so only data for signing get's returned. The signature data
        length is evaluated based on offsets, namely the signature block offset,
        the container signature offset and the container signature fixed data length.

        Signature data structure::

            +---------------------------------------------------+----------------+
            |                  Container header                 |                |
            +---+---+-----------+---------+--------+------------+     Data       |
            | S |   |    tag    | length  | length | version    |                |
            | i |   +-----------+---------+--------+------------+                |
            | g |   |                  flags                    |      to        |
            | n |   +---------------------+---------------------+                |
            | a |   |  srk table offset   | certificate offset  |                |
            | t |   +---------------------+---------------------+     Sign       |
            | u |   |     blob offset     | signature offset    |                |
            | r |   +---------------------+---------------------+                |
            | e |   |                   SRK Table               |                |
            |   +---+-----------+---------+--------+------------+----------------+
            | B | S |   tag     | length  | length | version    | Signature data |
            | l | i +-----------+---------+--------+------------+ fixed length   |
            | o | g |               Reserved                    |                |
            | c | n +-------------------------------------------+----------------+
            | k | a |               Signature data              |
            |   | t |                                           |
            |   | u |                                           |
            |   | r |                                           |
            |   | e |                                           |
            +---+---+-------------------------------------------+

        :raises SPSDKValueError: if Signature Block or SRK Table is missing.
        :return: bytes representing data to be signed.
        """
        if not self.signature_block.signature or not self.signature_block.srk_table:
            raise SPSDKValueError(
                "Can't retrieve data block to sign. Signature or SRK table is missing!"
            )

        signature_offset = self._signature_block_offset + self.signature_block.signature_offset
        return self._export()[:signature_offset]

    def _export(self) -> bytes:
        """Export container header into bytes.

        :return: bytes representing container header content including the signature block.
        """
        return pack(
            self._format(),
            self.version,
            self.length,
            self.tag,
            self.flags,
            self.sw_version,
            self.fuse_version,
            self.image_array_len,
            self._signature_block_offset,
            RESERVED,  # Reserved field
        )

    def export(self) -> bytes:
        """Export the binary images into one chunk on respective offsets.

        The fist image starts at offset 0. To append the serialized images to
        the serialized container header, the container header must be padded with
        extra zeros to have the images at proper offset.

        If the container has no images, the serializer returns empty binary.

        :raises SPSDKValueError: if the number of images doesn't correspond the the number of
            entries in image array info.
        :return: images exported into single binary
        """
        return self._export()

    def validate(self, data: Dict[str, Any]) -> None:
        """Validate object data.

        :param data: Additional validation data.
        :raises SPSDKValueError: Invalid any value of Image Array entry
        """
        self.validate_header()

        if self.flags is None or not check_range(self.flags, end=(1 << 32) - 1):
            raise SPSDKValueError(f"Container Header: Invalid flags: {hex(self.flags)}")
        if self.sw_version is None or not check_range(self.sw_version, end=(1 << 16) - 1):
            raise SPSDKValueError(f"Container Header: Invalid SW version: {hex(self.sw_version)}")
        if self.fuse_version is None or not check_range(self.fuse_version, end=(1 << 8) - 1):
            raise SPSDKValueError(
                f"Container Header: Invalid Fuse version: {hex(self.fuse_version)}"
            )
        self.signature_block.validate(data)

    @staticmethod
    def _parse(binary: bytes, offset: int = 0) -> Tuple[int, int, int, int, int]:
        """Parse input binary chunk to the container object.

        :param parent: AHABImage object.
        :param binary: Binary data with Container block to parse.
        :param offset: Offset to Container block data, default is 0.
        :return: Object recreated from the binary data.
        """
        AHABContainer._check_container_head(binary[offset:])
        image_format = AHABContainer._format()
        (
            _,  # version
            _,  # container_length
            _,  # tag
            flags,
            sw_version,
            fuse_version,
            number_of_images,
            signature_block_offset,
            _,  # reserved
        ) = unpack(image_format, binary[offset : offset + AHABContainer.fixed_length()])

        return (flags, sw_version, fuse_version, number_of_images, signature_block_offset)

    def _create_config(self, index: int, data_path: str) -> CM:
        """Create configuration of the AHAB Image.

        :param index: Container index.
        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        cfg = CM()

        cfg["srk_set"] = self.flag_srk_set
        cfg["used_srk_id"] = self.flag_used_srk_id
        cfg["srk_revoke_mask"] = self.flag_srk_revoke_mask
        cfg["fuse_version"] = self.fuse_version
        cfg["sw_version"] = self.sw_version
        cfg["signing_key"] = "N/A"

        if self.signature_block.srk_table:
            cfg["srk_table"] = self.signature_block.srk_table.create_config(index, data_path)

        if self.signature_block.certificate:
            cfg["certificate"] = self.signature_block.certificate.create_config(
                index, data_path, self.flag_srk_set
            )

        if self.signature_block.blob:
            cfg["blob"] = self.signature_block.blob.create_config(index, data_path)

        return cfg

    def load_from_config_generic(self, config: Dict[str, Any]) -> None:
        """Converts the configuration option into an AHAB image object.

        "config" content of container configurations.

        :param config: array of AHAB containers configuration dictionaries.
        """
        self.set_flags(
            srk_set=config.get("srk_set", "none"),
            used_srk_id=value_to_int(config.get("used_srk_id", 0)),
            srk_revoke_mask=value_to_int(config.get("srk_revoke_mask", 0)),
        )
        self.fuse_version = value_to_int(config.get("fuse_version", 0))
        self.sw_version = value_to_int(config.get("sw_version", 0))

        self.signature_block = SignatureBlock.load_from_config(
            config, search_paths=self.search_paths
        )


class AHABContainer(AHABContainerBase):
    """Class representing AHAB container.

    Container header::

        +---------------+----------------+----------------+----------------+
        |    Byte 3     |     Byte 2     |      Byte 1    |     Byte 0     |
        +---------------+----------------+----------------+----------------+
        |      Tag      |              Length             |    Version     |
        +---------------+---------------------------------+----------------+
        |                              Flags                               |
        +---------------+----------------+---------------------------------+
        |  # of images  |  Fuse version  |             SW version          |
        +---------------+----------------+---------------------------------+
        |              Reserved          |       Signature Block Offset    |
        +----+---------------------------+---------------------------------+
        | I  |image0: Offset, Size, LoadAddr, EntryPoint, Flags, Hash, IV  |
        + m  |-------------------------------------------------------------+
        | g  |image1: Offset, Size, LoadAddr, EntryPoint, Flags, Hash, IV  |
        + .  |-------------------------------------------------------------+
        | A  |...                                                          |
        | r  |...                                                          |
        | r  |                                                             |
        + a  |-------------------------------------------------------------+
        | y  |imageN: Offset, Size, LoadAddr, EntryPoint, Flags, Hash, IV  |
        +----+-------------------------------------------------------------+
        |                      Signature block                             |
        +------------------------------------------------------------------+
        |                                                                  |
        |                                                                  |
        |                                                                  |
        +------------------------------------------------------------------+
        |                      Data block_0                                |
        +------------------------------------------------------------------+
        |                                                                  |
        |                                                                  |
        +------------------------------------------------------------------+
        |                      Data block_n                                |
        +------------------------------------------------------------------+

    """

    TAG = AHABTags.CONTAINER_HEADER

    def __init__(
        self,
        parent: "AHABImage",
        flags: int = 0,
        fuse_version: int = 0,
        sw_version: int = 0,
        image_array: Optional[List["ImageArrayEntry"]] = None,
        signature_block: Optional["SignatureBlock"] = None,
        container_offset: int = 0,
    ):
        """Class object initializer.

        :parent: Parent AHABImage object.
        :param flags: flags.
        :param fuse_version: value must be equal to or greater than the version
            stored in the fuses to allow loading this container.
        :param sw_version: used by PHBC (Privileged Host Boot Companion) to select
            between multiple images with same fuse version field.
        :param image_array: array of image entries, must be `number of images` long.
        :param signature_block: signature block.
        """
        super().__init__(
            flags=flags,
            fuse_version=fuse_version,
            sw_version=sw_version,
            signature_block=signature_block,
        )
        self.parent = parent
        assert self.parent is not None
        self.image_array = image_array or []
        self.container_offset = container_offset
        self.search_paths: List[str] = []

    def __eq__(self, other: object) -> bool:
        if isinstance(other, AHABContainer):
            if super().__eq__(other) and self.image_array == other.image_array:
                return True

        return False

    @property
    def image_array_len(self) -> int:
        """Get image array length if available.

        :return: Length of image array.
        """
        return len(self.image_array)

    @property
    def _signature_block_offset(self) -> int:
        """Returns current signature block offset.

        :return: Offset in bytes of Signature block.
        """
        # Constant size of Container header + Image array Entry table
        return align(
            super().fixed_length() + len(self.image_array) * ImageArrayEntry.fixed_length(),
            CONTAINER_ALIGNMENT,
        )

    def __len__(self) -> int:
        """Get total length of AHAB container.

        :return: Size in bytes of AHAB Container.
        """
        # Get image which has biggest offset
        max_offset = max([x.image_offset for x in self.image_array])
        # Find the size of image
        for image_array in self.image_array:
            if image_array.image_offset == max_offset:
                return align(max_offset + image_array.image_size)
        # If there are no images just return length of header
        return self.header_length()

    def header_length(self) -> int:
        """Length of AHAB Container header.

        :return: Length in bytes of AHAB Container header.
        """
        return (
            super().fixed_length()  # This returns the fixed length of the container header
            # This returns the total length of all image array entries
            + len(self.image_array) * ImageArrayEntry.fixed_length()
            # This returns the length of signature block (including SRK table,
            # blob etc. if present)
            + len(self.signature_block)
        )

    def update_fields(self) -> None:
        """Updates all volatile information in whole container structure.

        :raises SPSDKError: When inconsistent image array length is detected.
        """
        # 1. Encrypt all images if applicable
        for image_entry in self.image_array:
            if (
                image_entry.flags_is_encrypted
                and not image_entry.already_encrypted_image
                and self.signature_block.blob
            ):
                image_entry.encrypted_image = self.signature_block.blob.encrypt_data(
                    image_entry.image_iv[16:], image_entry.plain_image
                )
                image_entry.already_encrypted_image = True

        # 2. Update the signature block to get overall size of it
        self.signature_block.update_fields()
        # 3. Updates Image Entries
        for image_entry in self.image_array:
            image_entry.update_fields()
        # 4. Update the Container header length
        self.length = self.header_length()
        # 5. Sign the image header
        if self.flag_srk_set != "none":
            assert self.signature_block.signature
            self.signature_block.signature.sign(self.get_signature_data())

    def decrypt_data(self) -> None:
        """Decrypt all images if possible."""
        for ix, image_entry in enumerate(self.image_array):
            if image_entry.flags_is_encrypted and self.signature_block.blob:
                decrypted_data = self.signature_block.blob.decrypt_data(
                    image_entry.image_iv[16:], image_entry.encrypted_image
                )
                if image_entry.image_iv == crypto_backend().hash(
                    decrypted_data, algorithm="sha256"
                ):
                    image_entry.plain_image = decrypted_data
                    logger.info(
                        f" Image{ix} from AHAB container at offset {hex(self.container_offset)} has been decrypted."
                    )
                else:
                    logger.warning(
                        f" Image{ix} from AHAB container at offset {hex(self.container_offset)} decryption failed."
                    )

        # TODO Add validation of decrypted data

    def _export(self) -> bytes:
        """Export container header into bytes.

        :return: bytes representing container header content including the signature block.
        """
        container_header = bytearray(align(self.header_length(), CONTAINER_ALIGNMENT))
        container_header_only = super()._export()

        for image_array_entry in self.image_array:
            container_header_only += image_array_entry.export()

        container_header[: self._signature_block_offset] = container_header_only
        # Add Signature Block
        container_header[
            self._signature_block_offset : self._signature_block_offset
            + align(len(self.signature_block), CONTAINER_ALIGNMENT)
        ] = self.signature_block.export()

        return container_header

    def export(self) -> bytes:
        """Export the binary images into one chunk on respective offsets.

        The fist image starts at offset 0. To append the serialized images to
        the serialized container header, the container header must be padded with
        extra zeros to have the images at proper offset.

        If the container has no images, the serializer returns empty binary.

        :raises SPSDKValueError: if the number of images doesn't correspond the the number of
            entries in image array info.
        :return: images exported into single binary
        """
        ahab_container = bytearray(len(self))
        ahab_container[: self.header_length()] = self._export()
        for image_entry in self.image_array:
            ahab_container[
                image_entry.image_offset : align(
                    image_entry.image_offset + image_entry.image_size, CONTAINER_ALIGNMENT
                )
            ] = image_entry.image

        return ahab_container

    def validate(self, data: Dict[str, Any]) -> None:
        """Validate object data.

        :param data: Additional validation data.
        :raises SPSDKValueError: Invalid any value of Image Array entry
        """
        data["flag_used_srk_id"] = self.flag_used_srk_id
        self.validate_header()
        if self.length != self.header_length():
            raise SPSDKValueError(
                f"Container Header: Invalid block length: {self.length} != {self.header_length()}"
            )

        super().validate(data)

        if self.image_array is None or len(self.image_array) == 0:
            raise SPSDKValueError(f"Container Header: Invalid Image Array: {self.image_array}")

        for container, offset in zip(self.parent.ahab_containers, self.parent.ahab_address_map):
            if self == container:
                if self.container_offset != offset:
                    raise SPSDKValueError("AHAB Container: Invalid Container Offset.")

        for image in self.image_array:
            image.validate()

    @staticmethod
    def parse(parent: "AHABImage", binary: bytes, offset: int = 0) -> "AHABContainer":
        """Parse input binary chunk to the container object.

        :param parent: AHABImage object.
        :param binary: Binary data with Container block to parse.
        :param offset: Offset to Container block data, default is 0.
        :return: Object recreated from the binary data.
        """
        (
            flags,
            sw_version,
            fuse_version,
            number_of_images,
            signature_block_offset,
        ) = AHABContainerBase._parse(binary, offset)

        parsed_container = AHABContainer(
            parent=parent,
            flags=flags,
            fuse_version=fuse_version,
            sw_version=sw_version,
            container_offset=offset,
        )
        parsed_container.signature_block = SignatureBlock.parse(
            binary, offset + signature_block_offset
        )

        for i in range(number_of_images):
            image_array_entry = ImageArrayEntry.parse(
                parsed_container,
                binary,
                offset + AHABContainer.fixed_length() + i * ImageArrayEntry.fixed_length(),
            )
            parsed_container.image_array.append(image_array_entry)

        return parsed_container

    def create_config(self, index: int, data_path: str) -> CM:
        """Create configuration of the AHAB Image.

        :param index: Container index.
        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        ret_cfg = CM()
        cfg = self._create_config(index, data_path)
        images_cfg = CS()

        for img_ix, image in enumerate(self.image_array):
            images_cfg.append(image.create_config(index, img_ix, data_path))
        cfg["images"] = images_cfg

        ret_cfg["container"] = cfg
        return ret_cfg

    @staticmethod
    def load_from_config(parent: "AHABImage", config: Dict[str, Any]) -> "AHABContainer":
        """Converts the configuration option into an AHAB image object.

        "config" content of container configurations.

        :param parent: AHABImage object.
        :param config: array of AHAB containers configuration dictionaries.
        :return: AHAB Container object.
        """
        ahab_container = AHABContainer(parent)
        ahab_container.search_paths = parent.search_paths or []
        ahab_container.load_from_config_generic(config)
        images = config.get("images")
        assert isinstance(images, list)
        for image in images:
            ahab_container.image_array.append(
                ImageArrayEntry.load_from_config(ahab_container, image)
            )

        ahab_container.signature_block = SignatureBlock.load_from_config(
            config, parent.search_paths
        )

        return ahab_container

    def image_info(self) -> BinaryImage:
        """Get Image info object.

        :return: AHAB Container Info object.
        """
        ret = BinaryImage(
            name="AHAB Container",
            size=self.header_length(),
            offset=0,
            binary=self.export(),
            description=(f"AHAB Container for {self.flag_srk_set}" f"_SWver:{self.sw_version}"),
        )
        return ret


class AHABImage:
    """Class representing an AHAB image.

    The image consists of multiple AHAB containers.
    """

    IMAGE_TYPES = [IMAGE_TYPE_XIP, IMAGE_TYPE_NON_XIP, IMAGE_TYPE_SERIAL_DOWNLOADER]

    def __init__(
        self,
        family: str,
        revision: str = "latest",
        image_type: str = IMAGE_TYPE_XIP,
        ahab_containers: Optional[List[AHABContainer]] = None,
        search_paths: Optional[List[str]] = None,
    ) -> None:
        """AHAB Image constructor.

        :param family: Name of device family.
        :param revision: Device silicon revision, defaults to "latest"
        :param image_type: Type of image [xip, non_xip, serial_downloader], defaults to "xip"
        :param ahab_containers: _description_, defaults to None
        :param search_paths: List of paths where to search for the file, defaults to None
        :raises SPSDKValueError: Invalid input configuration.
        """
        if image_type not in self.IMAGE_TYPES:
            raise SPSDKValueError(
                f"Invalid AHAB image type [{image_type}]."
                f" The list of supported images: [{','.join(self.IMAGE_TYPES)}]"
            )
        self.image_type = image_type
        self.family = family
        self.search_paths = search_paths
        self._database = Database(AHAB_DATABASE_FILE)
        self.revision = self._database.devices.get_by_name(family).revisions.get(revision).name
        self.ahab_address_map: List[int] = self._database.get_device_value(
            "ahab_map", self.family, self.revision
        )
        self.data_images_start: int = self._database.get_device_value(
            "images_start", self.family, self.revision
        )
        self.containers_max_cnt: int = self._database.get_device_value(
            "containers_max_cnt", self.family, self.revision
        )
        self.images_max_cnt: int = self._database.get_device_value(
            "oem_images_max_cnt", self.family, self.revision
        )
        self.srkh_sha_supports: List[str] = self._database.get_device_value(
            "srkh_sha_supports", self.family, self.revision
        )
        self.ahab_containers: List[AHABContainer] = ahab_containers or []

    def add_container(self, container: AHABContainer) -> None:
        """Add new container into AHAB Image.

        The order of the added images is important.
        :param container: New AHAB Container to be added.
        :raises SPSDKLengthError: The container count in image is overflowed.
        """
        if len(self.ahab_containers) >= self.containers_max_cnt:
            raise SPSDKLengthError(
                "Cannot add new container because the AHAB Image already reached"
                f" the maximum count: {self.containers_max_cnt}"
            )

        self.ahab_containers.append(container)

    def clear(self) -> None:
        """Clear list of containers."""
        self.ahab_containers.clear()

    def update_fields(self) -> None:
        """Automatically updates all volatile fields in every AHAB container."""
        for ahab_container in self.ahab_containers:
            ahab_container.update_fields()

        if self.image_type == IMAGE_TYPE_SERIAL_DOWNLOADER:
            # Update the Image offsets to be without gaps
            offset = START_IMAGE_ADDRESS
            for ahab_container in self.ahab_containers:
                for image in ahab_container.image_array:
                    image.image_offset = offset - ahab_container.container_offset
                    offset += align(image.image_size, CONTAINER_ALIGNMENT)

                ahab_container.update_fields()

    def __len__(self) -> int:
        """Get maximal size of AHAB Image.

        :return: Size in Bytes of AHAB Image.
        """
        lengths = [0]
        for container in self.ahab_containers:
            length = len(container)
            if self.image_type in (IMAGE_TYPE_NON_XIP, IMAGE_TYPE_SERIAL_DOWNLOADER):
                # Just updates offsets from AHAB Image start As is feature of none xip containers
                length += container.container_offset
            lengths.append(length)

        return max(lengths)

    def get_containers_size(self) -> int:
        """Get maximal containers size.

        In fact get the offset where could be stored first data.

        :return: Size of containers.
        """
        if len(self.ahab_containers) == 0:
            return 0
        sizes = [
            container.header_length() + address
            for container, address in zip(self.ahab_containers, self.ahab_address_map)
        ]
        return align(max(sizes), CONTAINER_ALIGNMENT)

    def get_first_data_image_address(self) -> int:
        """Get first data image address.

        :return: Address of first data image.
        """
        addresses = []
        for container in self.ahab_containers:
            addresses.extend([x.image_offset for x in container.image_array])
        return min(addresses)

    def export(self) -> bytes:
        """Export AHAB Image.

        :raises SPSDKValueError: mismatch between number of containers and offsets.
        :raises SPSDKValueError: number of images mismatch.
        :return: bytes AHAB  Image.
        """
        self.update_fields()
        self.validate()
        return self.image_info().export()

    def image_info(self) -> BinaryImage:
        """Get Image info object."""
        ret = BinaryImage(
            name="AHAB Image",
            size=len(self),
            offset=self.ahab_address_map[0],
            description=f"AHAB Image for {self.family}_{self.revision}",
        )
        for cnt_ix, (container, address) in enumerate(
            zip(self.ahab_containers, self.ahab_address_map)
        ):
            container_image = container.image_info()
            container_image.name = container_image.name + f" {cnt_ix}"
            container_image.offset = address
            # Add also all data images
            for img_ix, image_entry in enumerate(container.image_array):
                offset = image_entry.image_offset
                if self.image_type in (IMAGE_TYPE_NON_XIP, IMAGE_TYPE_SERIAL_DOWNLOADER):
                    # Just updates offsets from AHAB Image start As is feature of none xip containers
                    offset += container.container_offset
                data_image = BinaryImage(
                    name=f"Container {cnt_ix} AHAB Data Image {img_ix}",
                    binary=image_entry.image,
                    size=image_entry.image_size,
                    offset=offset,
                    description=(
                        f"AHAB {'encrypted ' if image_entry.flags_is_encrypted else ''}"
                        f"data block with {image_entry.flags_image_type} Image Type."
                    ),
                )

                ret.add_image(data_image)
            ret.add_image(container_image)

        return ret

    def validate(self) -> None:
        """Validate object data.

        :raises SPSDKValueError: Invalid any value of Image Array entry.
        :raises SPSDKError: In case of Binary Image validation fail.
        """
        if self.ahab_containers is None or len(self.ahab_containers) == 0:
            raise SPSDKValueError("AHAB Image: Missing Containers.")
        if len(self.ahab_containers) > self.containers_max_cnt:
            raise SPSDKValueError(
                "AHAB Image: Too much AHAB containers in image."
                f" {len(self.ahab_containers)} > {self.containers_max_cnt}"
            )
        # prepare additional validation data
        data = {}
        data["srkh_sha_supports"] = self.srkh_sha_supports

        for cnt_ix, container in enumerate(self.ahab_containers):
            container.validate(data)
            if len(container.image_array) > self.images_max_cnt:
                raise SPSDKValueError(
                    f"AHAB Image: Too much binary images in AHAB Container [{cnt_ix}]."
                    f" {len(container.image_array)} > {self.images_max_cnt}"
                )
            if self.image_type != IMAGE_TYPE_SERIAL_DOWNLOADER:
                for img_ix, image_entry in enumerate(container.image_array):
                    if image_entry.image_offset < self.data_images_start:
                        raise SPSDKValueError(
                            "AHAB Data Image: The offset of data image (container"
                            f"{cnt_ix}/image{img_ix}) is under minimal allowed value."
                            f" 0x{hex(image_entry.image_offset)} < {hex(self.data_images_start)}"
                        )
        # Validate also overlapped images
        try:
            self.image_info().validate()
        except SPSDKError as exc:
            logger.error(self.image_info().draw())
            raise SPSDKError("Validation failed") from exc

    @staticmethod
    def load_from_config(
        config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> "AHABImage":
        """Converts the configuration option into an AHAB image object.

        "config" content array of containers configurations.

        :raises SPSDKValueError: if the count of AHAB containers is invalid.
        :param config: array of AHAB containers configuration dictionaries.
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: initialized AHAB Image.
        """
        containers_config: List[Dict[str, Any]] = config["containers"]
        family = config["family"]
        revision = config.get("revision", "latest")
        image_type = config["image_type"]
        ahab = AHABImage(
            family=family, revision=revision, image_type=image_type, search_paths=search_paths
        )
        for i, container_config in enumerate(containers_config):
            binary_container = container_config.get("binary_container")
            if binary_container:
                assert isinstance(binary_container, dict)
                path = binary_container.get("path")
                assert path
                container = AHABContainer.parse(ahab, load_binary(path, search_paths=search_paths))
            else:
                container = AHABContainer.load_from_config(ahab, container_config["container"])
            container.container_offset = ahab.ahab_address_map[i]
            ahab.add_container(container)

        return ahab

    def parse(self, binary: bytes) -> None:
        """Parse input binary chunk to the container object.

        :raises SPSDKError: No AHAB container found in binary data.
        """
        self.clear()

        for address in self.ahab_address_map:
            try:
                container = AHABContainer.parse(self, binary, address)
                self.ahab_containers.append(container)
            except SPSDKParsingError:
                pass
            except SPSDKError as exc:
                raise SPSDKError(f"AHAB Container parsing failed: {str(exc)}.") from exc
        if len(self.ahab_containers) == 0:
            raise SPSDKError("No AHAB Container has been found in binary data.")

    @staticmethod
    def get_supported_families() -> List[str]:
        """Get all supported families for AHAB container.

        :return: List of supported families.
        """
        database = Database(AHAB_DATABASE_FILE)
        return database.devices.device_names

    @staticmethod
    def get_validation_schemas() -> List[Dict[str, Any]]:
        """Get list of validation schemas.

        :return: Validation list of schemas.
        """
        return [ValidationSchemas.get_schema_file(AHAB_SCH_FILE)]

    @staticmethod
    def generate_config_template(family: str) -> Dict[str, Any]:
        """Generate AHAB configuration template.

        :param family: Family for which the template should be generated.
        :return: Dictionary of individual templates (key is name of template, value is template itself).
        """
        val_schemas = AHABImage.get_validation_schemas()

        if family in AHABImage.get_supported_families():
            yaml_data = ConfigTemplate(
                f"Advanced High-Assurance Boot Configuration template for {family}.",
                val_schemas,
            ).export_to_yaml()

            return {f"{family}_ahab": yaml_data}

        return {}

    def create_config(self, data_path: str) -> CM:
        """Create configuration of the AHAB Image.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        cfg = CM()
        cfg.yaml_set_start_comment(
            "AHAB Image recreated configuration from :"
            f"{datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}."
        )
        cfg["family"] = self.family
        cfg["revision"] = self.revision
        cfg["image_type"] = self.image_type
        cfg["output"] = "N/A"
        cfg_containers = CS()
        for cnt_ix, container in enumerate(self.ahab_containers):
            cfg_containers.append(container.create_config(cnt_ix, data_path))
        cfg["containers"] = cfg_containers

        return cfg

    def create_srk_hash_blhost_script(self, container_ix: int = 0) -> str:
        """Create BLHOST script to load SRK hash into fuses.

        :param container_ix: Container index.
        :raises SPSDKValueError: Invalid input value - Non existing container or unsupported type.
        :raises SPSDKError: Invalid SRK hash.
        :return: Script used by BLHOST to load SRK hash.
        """
        if container_ix > len(self.ahab_containers):
            raise SPSDKValueError(f"Invalid Container index: {container_ix}.")
        container_type = self.ahab_containers[container_ix].flag_srk_set

        fuses_start = self._database.get_device_value(
            f"{container_type}_srkh_fuses_start", self.family, self.revision
        )
        fuses_count = self._database.get_device_value(
            f"{container_type}_srkh_fuses_count", self.family, self.revision
        )
        fuses_size = self._database.get_device_value(
            f"{container_type}_srkh_fuses_size", self.family, self.revision
        )
        if fuses_start is None or fuses_count is None or fuses_size is None:
            raise SPSDKValueError(
                f"Unsupported container type({container_type}) to create BLHOST script"
            )

        srk_table = self.ahab_containers[container_ix].signature_block.srk_table
        if srk_table is None:
            raise SPSDKError("The selected AHAB container doesn't contain SRK table.")

        srkh = srk_table.compute_srk_hash()

        if len(srkh) != fuses_count * fuses_size:
            SPSDKError(
                f"The SRK hash length ({len(srkh)}) doesn't fit to fuses space ({fuses_count*fuses_size})."
            )
        ret = (
            "# BLHOST SRK Hash fuses programming script\n"
            f"# Generated by SPSDK {spsdk_version}\n"
            f"# Chip: {self.family} rev:{self.revision}\n"
            f"# SRK Hash(Big Endian): {srkh.hex()}\n\n"
        )
        srkh_rev = reverse_bytes_in_longs(srkh)
        for fuse_ix in range(fuses_count):
            value = srkh_rev[fuse_ix * 4 : fuse_ix * 4 + 4]
            ret += f"#  OEM SRKH{fuses_count-1-fuse_ix} fuses.\n"
            ret += f"efuse-program-once {hex(fuses_start+fuse_ix)} 0x{value.hex()}\n"

        return ret
