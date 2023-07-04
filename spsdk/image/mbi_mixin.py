#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


"""Master Boot Image."""

import logging
import os
import struct
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, TypeVar, Union

from crcmod.predefined import mkPredefinedCrcFun

from spsdk import SPSDKError
from spsdk.apps.utils.utils import get_key
from spsdk.crypto.signature_provider import SignatureProvider, get_signature_provider
from spsdk.exceptions import SPSDKParsingError, SPSDKUnsupportedOperation, SPSDKValueError
from spsdk.image.keystore import KeySourceType, KeyStore
from spsdk.image.trustzone import TrustZone, TrustZoneType
from spsdk.utils.crypto import crypto_backend
from spsdk.utils.crypto.cert_blocks import CertBlockV2, CertBlockV31
from spsdk.utils.crypto.common import serialize_ecc_signature
from spsdk.utils.easy_enum import Enum
from spsdk.utils.images import BinaryImage
from spsdk.utils.misc import (
    align_block,
    find_file,
    load_binary,
    load_configuration,
    value_to_int,
    write_file,
)

logger = logging.getLogger(__name__)


class MasterBootImageManifest:
    """MasterBootImage Manifest used in LPC55s3x."""

    MAGIC = b"imgm"
    FORMAT = "<4s4L"
    FORMAT_VERSION = 0x0001_0000
    DIGEST_PRESENT_FLAG = 0x8000_0000
    HASH_TYPE_MASK = 0x0F
    SUPPORTED_ALGORITHMS = ["sha256", "sha384", "sha512"]

    def __init__(
        self,
        firmware_version: int,
        trust_zone: Optional[TrustZone],
        digest_hash_algo: Optional[str] = None,
    ) -> None:
        """Initialize MBI Manifest object.

        :param firmware_version: firmware version
        :param digest_hash_algo: Digest hash algorithm, defaults to None
        :param trust_zone: TrustZone instance, defaults to None
        """
        self.firmware_version = firmware_version
        if digest_hash_algo and digest_hash_algo not in self.SUPPORTED_ALGORITHMS:
            raise SPSDKValueError(f"Unsupported digest hash algorithm: {digest_hash_algo}")
        self.digest_hash_algo = digest_hash_algo
        self.trust_zone = trust_zone
        self.flags = self._calculate_flags()
        self.total_length = self._calculate_length()

    def _calculate_length(self) -> int:
        length = struct.calcsize(self.FORMAT)
        if self.trust_zone:
            length += len(self.trust_zone.export())
        return length

    def _calculate_flags(self) -> int:
        if not self.digest_hash_algo:
            return 0
        hash_algo_types = {None: 0, "sha256": 1, "sha384": 2, "sha512": 3}
        return self.DIGEST_PRESENT_FLAG | hash_algo_types[self.digest_hash_algo]

    @staticmethod
    def get_hash_size(algorithm: str) -> int:
        """Get hash size by used algorithm."""
        return {"sha256": 32, "sha384": 48, "sha512": 64}.get(algorithm, 0)

    def export(self) -> bytes:
        """Serialize MBI Manifest."""
        data = struct.pack(
            self.FORMAT,
            self.MAGIC,
            self.FORMAT_VERSION,
            self.firmware_version,
            self.total_length,
            self.flags,
        )
        if self.trust_zone:
            data += self.trust_zone.export()
        return data

    @staticmethod
    def parse(family: str, data: bytes) -> "MasterBootImageManifest":
        """Parse the binary to Master Boot Image Manifest.

        :param family: Device family.
        :param data: Binary Image with MBI Manifest.
        :raises SPSDKParsingError: Invalid header is detected.
        :return: MBI Manifest object
        """
        (magic, version, fw_version, total_length, flags) = struct.unpack(
            MasterBootImageManifest.FORMAT, data[: struct.calcsize(MasterBootImageManifest.FORMAT)]
        )
        assert isinstance(magic, bytes)
        if magic != MasterBootImageManifest.MAGIC:
            raise SPSDKParsingError(
                "MBI Manifest: Invalid MAGIC marker detected when parsing:"
                f" {magic.hex()} != {MasterBootImageManifest.MAGIC.hex()}"
            )
        if version != MasterBootImageManifest.FORMAT_VERSION:
            raise SPSDKParsingError(
                "MBI Manifest: Invalid MANIFEST VERSION detected when parsing:"
                f" {version} != {MasterBootImageManifest.FORMAT_VERSION}"
            )
        if total_length >= len(data):
            raise SPSDKParsingError(
                "MBI Manifest: Invalid Input data length:" f" {total_length} < {len(data)}"
            )

        manifest_len = struct.calcsize(MasterBootImageManifest.FORMAT)
        tz_data_len = total_length - manifest_len
        tz = None
        if tz_data_len > 0:
            tz = TrustZone.from_binary(family=family, raw_data=data[manifest_len:total_length])

        hash_algo = None
        if flags & MasterBootImageManifest.DIGEST_PRESENT_FLAG:
            hash_algo = {0: None, 1: "sha256", 2: "sha384", 3: "sha512"}[
                flags & MasterBootImageManifest.HASH_TYPE_MASK
            ]

        return MasterBootImageManifest(
            firmware_version=fw_version, trust_zone=tz, digest_hash_algo=hash_algo
        )


class MasterBootImageManifestMcxNx(MasterBootImageManifest):
    """MasterBootImage Manifest used in mcxnx devices."""

    def __init__(
        self,
        firmware_version: int,
        trust_zone: Optional[TrustZone],
        digest_hash_algo: Optional[str] = None,
    ) -> None:
        """Initialize MBI Manifest object.

        :param firmware_version: firmware version
        :param digest_hash_algo: Digest hash algorithm, defaults to None
        :param trust_zone: TrustZone instance, defaults to None
        """
        super().__init__(firmware_version, trust_zone, digest_hash_algo)
        self.crc = 0

    def export(self) -> bytes:
        """Serialize MBI Manifest."""
        data = super().export()
        data += struct.pack("<L", self.crc)
        return data

    @staticmethod
    def parse(family: str, data: bytes) -> "MasterBootImageManifestMcxNx":
        """Parse the binary to Master Boot Image Manifest.

        :param family: Device family.
        :param data: Binary Image with MBI Manifest.
        :raises SPSDKParsingError: Invalid header is detected.
        :return: MBI Manifest object
        """
        manifest = MasterBootImageManifest.parse(family=family, data=data)
        crc = int.from_bytes(data[manifest.total_length - 4 : manifest.total_length], "little")
        mcx_manifest = MasterBootImageManifestMcxNx(
            firmware_version=manifest.firmware_version,
            trust_zone=manifest.trust_zone,
            digest_hash_algo=manifest.digest_hash_algo,
        )
        mcx_manifest.crc = crc
        return mcx_manifest

    def _calculate_length(self) -> int:
        return super()._calculate_length() + 4

    def compute_crc(self, image: bytes) -> None:
        """Compute and add CRC field.

        :param image: Image data to be used to compute CRC
        """
        self.crc = mkPredefinedCrcFun("crc-32-mpeg")(image)


T_Manifest = TypeVar("T_Manifest", MasterBootImageManifest, MasterBootImageManifestMcxNx)


class MultipleImageEntry:
    """The class represents an entry in relocation table.

    It also contains a corresponding image (binary)
    """

    # flag to simply copy load segment into target memory
    LTI_LOAD = 1 << 0

    def __init__(self, img: bytes, dst_addr: int, flags: int = LTI_LOAD):
        """Constructor.

        :param img: binary image data
        :param dst_addr: destination address
        :param flags: see LTI constants
        :raises SPSDKError: If invalid destination address
        :raises SPSDKError: Other section types (INIT) are not supported
        """
        if dst_addr < 0 or dst_addr > 0xFFFFFFFF:
            raise SPSDKError("Invalid destination address")
        if flags != self.LTI_LOAD:
            raise SPSDKError("For now, other section types than LTI_LOAD, are not supported")
        self._img = img
        self._src_addr = 0
        self._dst_addr = dst_addr
        self._flags = flags

    @property
    def image(self) -> bytes:
        """Binary image data."""
        return self._img

    @property
    def src_addr(self) -> int:
        """Source address; this value is calculated automatically when building the image."""
        return self._src_addr

    @src_addr.setter
    def src_addr(self, value: int) -> None:
        """Setter.

        :param value: to set
        """
        self._src_addr = value

    @property
    def dst_addr(self) -> int:
        """Destination address."""
        return self._dst_addr

    @property
    def size(self) -> int:
        """Size of the image (not aligned)."""
        return len(self.image)

    @property
    def flags(self) -> int:
        """Flags, currently not used."""
        return self._flags

    @property
    def is_load(self) -> bool:
        """True if entry represents LOAD section."""
        return (self.flags & self.LTI_LOAD) != 0

    def export_entry(self) -> bytes:
        """Export relocation table entry in binary form."""
        result = bytes()
        result += struct.pack("<I", self.src_addr)  # source address
        result += struct.pack("<I", self.dst_addr)  # dest address
        result += struct.pack("<I", self.size)  # length
        result += struct.pack("<I", self.flags)  # flags
        return result

    @staticmethod
    def parse(data: bytes) -> "MultipleImageEntry":
        """Parse relocation table entry from binary form."""
        (src_addr, dst_addr, size, flags) = struct.unpack("<4I", data[: 4 * 4])
        if src_addr + size > len(data):
            raise SPSDKParsingError("The image doesn't fit into given data")

        return MultipleImageEntry(data[src_addr : src_addr + size], dst_addr, flags)

    def export_image(self) -> bytes:
        """Binary image aligned to the 4-bytes boundary."""
        return align_block(self.image, 4)


class MultipleImageTable:
    """The class allows to merge several images into single image and add relocation table.

    It can be used for multicore images (one image for each core)
    or trustzone images (merging secure and non-secure image)
    """

    def __init__(self) -> None:
        """Initialize the Multiple Image Table."""
        self._entries: List[MultipleImageEntry] = []
        self.start_address = 0

    @property
    def header_version(self) -> int:
        """Format version of the structure for the header."""
        return 0

    @property
    def entries(self) -> Sequence[MultipleImageEntry]:
        """List of all entries."""
        return self._entries

    def add_entry(self, entry: MultipleImageEntry) -> None:
        """Add entry into relocation table.

        :param entry: to add
        """
        self._entries.append(entry)

    def reloc_table(self, start_addr: int) -> bytes:
        """Relocate table.

        :param start_addr: start address of the relocation table
        :return: export relocation table in binary form
        """
        result = bytes()
        # export relocation entries table
        for entry in self.entries:
            result += entry.export_entry()
        # export relocation table header
        result += struct.pack("<I", 0x4C54424C)  # header marker
        result += struct.pack("<I", self.header_version)  # version
        result += struct.pack("<I", len(self._entries))  # number of entries
        result += struct.pack("<I", start_addr)  # pointer to entries
        return result

    def export(self, start_addr: int) -> bytes:
        """Export.

        :param start_addr: start address where the images are exported;
                        the value matches source address for the first image
        :return: images with relocation table
        :raises SPSDKError: If there is no entry for export
        """
        if not self._entries:
            raise SPSDKError("There must be at least one entry for export")
        self.start_address = start_addr
        src_addr = start_addr
        result = bytes()
        for entry in self.entries:
            if entry.is_load:
                entry.src_addr = src_addr
                entry_img = entry.export_image()
                result += entry_img
                src_addr += len(entry_img)
        result += self.reloc_table(start_addr + len(result))
        return result

    @staticmethod
    def parse(data: bytes) -> Optional["MultipleImageTable"]:
        """Parse binary to get the Multiple application table.

        :param data: Data bytes where the application is looked for
        :raises SPSDKParsingError: The application table parsing fails.

        :return: Multiple application table if detected.
        """
        (marker, header_version, n_entries, start_address) = struct.unpack(
            "<4I", data[-struct.calcsize("<4I") :]
        )
        if marker != 0x4C54424C or header_version != MultipleImageTable().header_version:
            return None

        app_table = MultipleImageTable()
        app_table.start_address = start_address
        for n in range(n_entries):
            app_table.add_entry(MultipleImageEntry.parse(data[: -16 * (1 + n)]))

        return app_table


# ****************************************************************************************************
#                                             Mbi Mixins
# ****************************************************************************************************


# pylint: disable=invalid-name
class Mbi_Mixin:
    """Base class for Master BOtt Image Mixin classes."""

    VALIDATION_SCHEMAS: List[str] = []
    NEEDED_MEMBERS: List[str] = []
    PRE_PARSED: List[str] = []

    def mix_len(self) -> int:  # pylint: disable=no-self-use
        """Compute length of individual mixin.

        :return: Length of atomic Mixin.
        """
        return 0

    def mix_app_len(self) -> int:  # pylint: disable=no-self-use
        """Compute application data length of individual mixin.

        :return: Application data length of atomic Mixin.
        """
        return -1

    @classmethod
    def mix_get_extra_validation_schemas(cls) -> List[Dict[str, Any]]:
        """Get extra-non standard validation schemas from mixin.

        :return: List of additional validation schemas.
        """
        return []

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration of mixin from dictionary.

        :param config: Dictionary with configuration fields.
        """

    def mix_validate(self) -> None:
        """Validate the setting of image."""

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """

    def mix_get_config(self, output_folder: str) -> Dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        return {}


class Mbi_MixinApp(Mbi_Mixin):
    """Master Boot Image Trust Zone class."""

    VALIDATION_SCHEMAS: List[str] = ["app"]
    NEEDED_MEMBERS: List[str] = ["app"]

    app: Optional[bytes]
    app_ext_memory_align: int
    search_paths: Optional[List[str]]

    def mix_len(self) -> int:
        """Get size of plain input application image.

        :return: Length of application.
        """
        assert self.app
        return len(self.app)

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        self.load_binary_image_file(config["inputImageFile"])

    def mix_get_config(self, output_folder: str) -> Dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        filename = "application.bin"
        assert self.app
        write_file(self.app, os.path.join(output_folder, filename), mode="wb")
        config: Dict[str, Any] = {}
        config["inputImageFile"] = filename
        return config

    def load_binary_image_file(self, path: str) -> None:
        """Load binary image from file (S19,HEX,BIN).

        :param path: File path
        :raises SPSDKError: If invalid data file is detected.
        """
        app_align = self.app_ext_memory_align if hasattr(self, "app_ext_memory_align") else 0
        image = BinaryImage.load_binary_image(find_file(path, search_paths=self.search_paths))
        if app_align == 0 and image.absolute_address != 0:
            raise SPSDKError(f"Invalid input binary file {path}. It MUST begins at 0 address.")
        if app_align and image.absolute_address % app_align != 0:
            raise SPSDKError(
                f"Invalid input binary file {path}. It has to be aligned to {hex(app_align)}."
            )
        self.app = align_block(image.export())


class Mbi_MixinTrustZone(Mbi_Mixin):
    """Master Boot Image Trust Zone class."""

    VALIDATION_SCHEMAS: List[str] = ["tz"]
    NEEDED_MEMBERS: List[str] = ["tz", "family"]
    PRE_PARSED: List[str] = ["cert_block"]

    family: str
    tz: TrustZone
    search_paths: Optional[List[str]]
    cert_block: Optional[Union[CertBlockV2, CertBlockV31]]

    def mix_len(self) -> int:
        """Get length of TrustZone array.

        :return: Length of TrustZone.
        """
        return len(self.tz.export())

    def _load_preset_file(self, preset_file: str) -> None:
        _preset_file = find_file(preset_file, search_paths=self.search_paths)
        try:
            tz_config = load_configuration(_preset_file)
            self.tz = TrustZone.from_config(tz_config)
        except SPSDKError:
            tz_bin = load_binary(_preset_file)
            self.tz = TrustZone.from_binary(family=self.family, raw_data=tz_bin)

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        enabled_trustzone = config.get("enableTrustZone", False)
        if enabled_trustzone:
            trustzone_preset_file = config.get("trustZonePresetFile", None)
            if trustzone_preset_file:
                self._load_preset_file(trustzone_preset_file)
            else:
                self.tz = TrustZone.enabled()
        else:
            self.tz = TrustZone.disabled()

    def mix_get_config(self, output_folder: str) -> Dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        config: Dict[str, Any] = {}
        config["enableTrustZone"] = False if self.tz.type == TrustZoneType.DISABLED else True
        if self.tz.type == TrustZoneType.CUSTOM:
            filename = "trust_zone.bin"
            write_file(self.tz.export(), os.path.join(output_folder, filename), mode="wb")
            config["trustZonePresetFile"] = filename

        return config

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        tz_type = Mbi_MixinIvt.get_tz_type(data)
        if tz_type not in TrustZoneType:
            raise SPSDKParsingError("Invalid TrustZone type")

        if tz_type == TrustZoneType.CUSTOM:
            # load custom data
            tz_data_size = TrustZone.get_preset_data_size(self.family)
            if hasattr(self, "cert_block"):
                assert self.cert_block
                tz_offset = Mbi_MixinIvt.get_cert_block_offset(data) + self.cert_block.expected_size
                tz_data = data[tz_offset : tz_offset + tz_data_size]
            else:
                tz_data = data[-tz_data_size:]
            tz = TrustZone.from_binary(family=self.family, raw_data=tz_data)
        elif tz_type == TrustZoneType.ENABLED:
            tz = TrustZone.enabled()
        else:
            tz = TrustZone.disabled()

        self.tz = tz


class Mbi_MixinTrustZoneMandatory(Mbi_MixinTrustZone):
    """Master Boot Image Trust Zone class for LPC55s3x family."""

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        trustzone_preset_file = config.get("trustZonePresetFile", None)
        if trustzone_preset_file:
            self._load_preset_file(trustzone_preset_file)
        else:
            self.tz = TrustZone.enabled()

    def mix_validate(self) -> None:
        """Validate the setting of image.

        :raises SPSDKError: The TrustZone configuration is invalid.
        """
        if not self.tz or self.tz.type == TrustZoneType.DISABLED:
            raise SPSDKError("The Trust Zone MUST be used.")


class Mbi_MixinLoadAddress(Mbi_Mixin):
    """Master Boot Image load address class."""

    VALIDATION_SCHEMAS: List[str] = ["load_addr"]
    NEEDED_MEMBERS: List[str] = ["load_address"]

    load_address: Optional[int]

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        value = config.get("outputImageExecutionAddress")
        assert value is not None
        self.load_address = value_to_int(value)

    def mix_get_config(self, output_folder: str) -> Dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        config: Dict[str, Any] = {}
        assert self.load_address is not None
        config["outputImageExecutionAddress"] = hex(self.load_address)
        return config

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        self.load_address = Mbi_MixinIvt.get_load_address(data)


class Mbi_MixinFwVersion(Mbi_Mixin):
    """Master Boot Image FirmWare Version class."""

    VALIDATION_SCHEMAS: List[str] = ["firmware_version"]
    NEEDED_MEMBERS: List[str] = ["firmware_version", "firmware_version_to_image_type"]
    firmware_version_to_image_type: bool = True

    firmware_version: Optional[int]

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        self.firmware_version = value_to_int(config.get("firmwareVersion", 0))

    def mix_get_config(self, output_folder: str) -> Dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        config: Dict[str, Any] = {}
        config["firmwareVersion"] = self.firmware_version
        return config

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        self.firmware_version = Mbi_MixinIvt.get_fw_version(data)


class Mbi_MixinImageSubType(Mbi_Mixin):
    """Master Boot Image SubType class."""

    class Mbi_ImageSubTypeKw45xx(Enum):
        """Supported MAIN and NBU subtypes for KW45xx and K32W1xx."""

        MAIN = (0x00, "MAIN", "Default (main) application image")
        NBU = (0x01, "NBU", "NBU (Narrowband Unit) image")

    class Mbi_ImageSubTypeMcxn9xx(Enum):
        """Supported MAIN and NBU subtypes for MCXN9xx."""

        MAIN = (0x00, "MAIN", "Default (main) application image")
        RECOVERY = (0x01, "RECOVERY", "Recovery image")

    VALIDATION_SCHEMAS: List[str] = ["image_subtype"]
    NEEDED_MEMBERS: List[str] = ["image_subtype"]

    image_subtype: Optional[int]

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        self.set_image_subtype(config.get("outputImageSubtype", "MAIN"))

    def mix_get_config(self, output_folder: str) -> Dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.mb_xip_384_384_recovery_crctest
        """
        config: Dict[str, Any] = {}
        assert self.image_subtype is not None
        config["outputImageSubtype"] = Mbi_MixinImageSubType.Mbi_ImageSubTypeKw45xx.name(
            self.image_subtype
        )
        return config

    def set_image_subtype(self, image_subtype: Optional[Union[str, int]]) -> None:
        """Convert string value to int by enum table and store to class."""
        if image_subtype is None:
            self.image_subtype = (
                Mbi_MixinImageSubType.Mbi_ImageSubTypeKw45xx.MAIN
                or Mbi_MixinImageSubType.Mbi_ImageSubTypeMcxn9xx.MAIN
            )
        else:
            image_subtype = Mbi_MixinImageSubType.Mbi_ImageSubTypeKw45xx.get(
                image_subtype
            ) or Mbi_MixinImageSubType.Mbi_ImageSubTypeMcxn9xx.get(image_subtype)

            self.image_subtype = (
                image_subtype
                if isinstance(image_subtype, int)
                else Mbi_MixinImageSubType.Mbi_ImageSubTypeKw45xx.MAIN
                or Mbi_MixinImageSubType.Mbi_ImageSubTypeMcxn9xx.MAIN
            )

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        self.image_subtype = Mbi_MixinIvt.get_sub_type(data)


class Mbi_MixinIvt(Mbi_Mixin):
    """Master Boot Image Interrupt Vector table class."""

    # IVT table offsets
    IVT_IMAGE_LENGTH_OFFSET = 0x20
    IVT_IMAGE_FLAGS_OFFSET = 0x24
    IVT_CRC_CERTIFICATE_OFFSET = 0x28
    IVT_LOAD_ADDR_OFFSET = 0x34

    IVT_IMAGE_FLAGS_IMAGE_TYPE_MASK = 0x3F
    IVT_IMAGE_FLAGS_TZ_TYPE_MASK = 0x03
    IVT_IMAGE_FLAGS_TZ_TYPE_SHIFT = 13
    IVT_IMAGE_FLAGS_FW_VER_MASK = 0xFFFF
    IVT_IMAGE_FLAGS_FW_VER_SHIFT = 16
    IVT_IMAGE_FLAGS_SUB_TYPE_MASK = 0x03
    IVT_IMAGE_FLAGS_SUB_TYPE_SHIFT = 6

    # flag indication presence of boot image version (Used by LPC55s3x)
    _BOOT_IMAGE_VERSION_FLAG = 0x400
    # flag that image contains relocation table
    _RELOC_TABLE_FLAG = 0x800
    # enableHwUserModeKeys : flag for controlling secure hardware key bus. If enabled(1), then it is possible to access
    # keys on hardware secure bus from non-secure application, else non-secure application will read zeros.
    _HW_USER_KEY_EN_FLAG = 0x1000
    # flag for image type, if the image contains key-store
    _KEY_STORE_FLAG = 0x8000

    tz: TrustZone
    IMAGE_TYPE: Tuple[int, str]
    load_address: Optional[int]
    user_hw_key_enabled: Optional[bool]
    app_table: Optional["MultipleImageTable"]
    key_store: Optional[KeyStore]
    firmware_version: Optional[int]
    firmware_version_to_image_type: bool
    image_subtype: Optional[int]

    def create_flags(self) -> int:
        """Create flags of image.

        :return: Image type flags
        """
        flags = (self.tz.type << self.IVT_IMAGE_FLAGS_TZ_TYPE_SHIFT) + int(self.IMAGE_TYPE[0])

        if hasattr(self, "image_subtype"):
            assert self.image_subtype is not None
            flags |= self.image_subtype << self.IVT_IMAGE_FLAGS_SUB_TYPE_SHIFT

        if hasattr(self, "user_hw_key_enabled") and self.user_hw_key_enabled:
            flags |= self._HW_USER_KEY_EN_FLAG

        if hasattr(self, "key_store") and self.key_store and len(self.key_store.export()) > 0:
            flags |= self._KEY_STORE_FLAG

        if hasattr(self, "app_table") and self.app_table:
            flags |= self._RELOC_TABLE_FLAG

        if (
            hasattr(self, "firmware_version")
            and self.firmware_version
            and hasattr(self, "firmware_version_to_image_type")
            and self.firmware_version_to_image_type
        ):
            flags |= self._BOOT_IMAGE_VERSION_FLAG
            flags |= self.firmware_version << 16
        return flags

    def update_ivt(
        self,
        app_data: bytes,
        total_len: int,
        crc_val_cert_offset: int = 0,
    ) -> bytes:
        """Update IVT table in application image.

        :param app_data: Application data that should be modified.
        :param total_len: Total length of bootable image
        :param crc_val_cert_offset: CRC value or Certification block offset
        :return: Updated whole application image
        """
        data = bytearray(app_data)
        # Total length of image
        data[self.IVT_IMAGE_LENGTH_OFFSET : self.IVT_IMAGE_LENGTH_OFFSET + 4] = struct.pack(
            "<I", total_len
        )
        # flags
        data[self.IVT_IMAGE_FLAGS_OFFSET : self.IVT_IMAGE_FLAGS_OFFSET + 4] = struct.pack(
            "<I", self.create_flags()
        )
        # CRC value or Certification block offset
        data[self.IVT_CRC_CERTIFICATE_OFFSET : self.IVT_CRC_CERTIFICATE_OFFSET + 4] = struct.pack(
            "<I", crc_val_cert_offset
        )
        # Execution address
        load_addr = self.load_address if hasattr(self, "load_address") else 0
        data[self.IVT_LOAD_ADDR_OFFSET : self.IVT_LOAD_ADDR_OFFSET + 4] = struct.pack(
            "<I", load_addr
        )

        return bytes(data)

    def clean_ivt(self, app_data: bytes) -> bytes:
        """Clean IVT table from added information.

        :param app_data: Application data that should be cleaned.
        :return: Cleaned application image
        """
        data = bytearray(app_data)
        # Total length of image
        data[self.IVT_IMAGE_LENGTH_OFFSET : self.IVT_IMAGE_LENGTH_OFFSET + 4] = bytes(4)
        # flags
        data[self.IVT_IMAGE_FLAGS_OFFSET : self.IVT_IMAGE_FLAGS_OFFSET + 4] = bytes(4)
        # CRC value or Certification block offset
        data[self.IVT_CRC_CERTIFICATE_OFFSET : self.IVT_CRC_CERTIFICATE_OFFSET + 4] = bytes(4)
        # Execution address
        data[self.IVT_LOAD_ADDR_OFFSET : self.IVT_LOAD_ADDR_OFFSET + 4] = bytes(4)

        return bytes(data)

    def update_crc_val_cert_offset(self, app_data: bytes, crc_val_cert_offset: int) -> bytes:
        """Update value just of CRC/Certificate offset field.

        :param app_data: Input binary array.
        :param crc_val_cert_offset: CRC/Certificate offset value.
        :return: Updated binary array.
        """
        data = bytearray(app_data)
        data[self.IVT_CRC_CERTIFICATE_OFFSET : self.IVT_CRC_CERTIFICATE_OFFSET + 4] = struct.pack(
            "<I", crc_val_cert_offset
        )
        return data

    @staticmethod
    def check_total_length(data: bytes) -> None:
        """Check total length field from raw data.

        :param data: Raw MBI image data.
        :raises SPSDKParsingError: Insufficient length of image has been detected.
        """
        total_len = int.from_bytes(
            data[Mbi_MixinIvt.IVT_IMAGE_LENGTH_OFFSET : Mbi_MixinIvt.IVT_IMAGE_LENGTH_OFFSET + 4],
            "little",
        )

        if total_len < len(data):
            raise SPSDKParsingError("Insufficient length of input raw data!")

    @staticmethod
    def get_flags(data: bytes) -> int:
        """Get the Image flags from raw data.

        During getting of flags, the length is also validated.

        :param data: Raw MBI image data.
        :return: Image Flags
        """
        Mbi_MixinIvt.check_total_length(data)

        flags = int.from_bytes(
            data[Mbi_MixinIvt.IVT_IMAGE_FLAGS_OFFSET : Mbi_MixinIvt.IVT_IMAGE_FLAGS_OFFSET + 4],
            "little",
        )

        return flags

    @staticmethod
    def get_cert_block_offset(data: bytes) -> int:
        """Get the certificate block offset from raw data.

        During getting of flags, the length is also validated.

        :param data: Raw MBI image data.
        :return: Certificate block offset
        """
        Mbi_MixinIvt.check_total_length(data)

        return int.from_bytes(
            data[
                Mbi_MixinIvt.IVT_CRC_CERTIFICATE_OFFSET : Mbi_MixinIvt.IVT_CRC_CERTIFICATE_OFFSET
                + 4
            ],
            "little",
        )

    @staticmethod
    def get_load_address(data: bytes) -> int:
        """Get the load address from raw data.

        During getting of flags, the length is also validated.

        :param data: Raw MBI image data.
        :return: Load address
        """
        Mbi_MixinIvt.check_total_length(data)

        return int.from_bytes(
            data[Mbi_MixinIvt.IVT_LOAD_ADDR_OFFSET : Mbi_MixinIvt.IVT_LOAD_ADDR_OFFSET + 4],
            "little",
        )

    @staticmethod
    def get_image_type(data: bytes) -> int:
        """Get the Image type from raw data.

        :param data: Raw MBI image data.
        :return: Image type
        """
        return Mbi_MixinIvt.get_flags(data) & Mbi_MixinIvt.IVT_IMAGE_FLAGS_IMAGE_TYPE_MASK

    @staticmethod
    def get_tz_type(data: bytes) -> int:
        """Get the Image TrustZone type settings from raw data.

        :param data: Raw MBI image data.
        :return: TrustZone type.
        """
        flags = Mbi_MixinIvt.get_flags(data)
        return (
            flags >> Mbi_MixinIvt.IVT_IMAGE_FLAGS_TZ_TYPE_SHIFT
        ) & Mbi_MixinIvt.IVT_IMAGE_FLAGS_TZ_TYPE_MASK

    @staticmethod
    def get_fw_version(data: bytes) -> int:
        """Get the Image firmware version from raw data.

        :param data: Raw MBI image data.
        :return: Firmware version.
        """
        flags = Mbi_MixinIvt.get_flags(data)
        if flags & Mbi_MixinIvt._BOOT_IMAGE_VERSION_FLAG == 0:
            return 0

        return (
            flags >> Mbi_MixinIvt.IVT_IMAGE_FLAGS_FW_VER_SHIFT
        ) & Mbi_MixinIvt.IVT_IMAGE_FLAGS_FW_VER_MASK

    @staticmethod
    def get_sub_type(data: bytes) -> int:
        """Get the Image sub type from raw data.

        :param data: Raw MBI image data.
        :return: Image sub type.
        """
        flags = Mbi_MixinIvt.get_flags(data)

        return (
            flags >> Mbi_MixinIvt.IVT_IMAGE_FLAGS_SUB_TYPE_SHIFT
        ) & Mbi_MixinIvt.IVT_IMAGE_FLAGS_SUB_TYPE_MASK

    @staticmethod
    def get_hw_key_enabled(data: bytes) -> bool:
        """Get the HW key enabled setting from raw data.

        :param data: Raw MBI image data.
        :return: HW key enabled or not.
        """
        flags = Mbi_MixinIvt.get_flags(data)

        return bool(flags & Mbi_MixinIvt._HW_USER_KEY_EN_FLAG)

    @staticmethod
    def get_key_store_presented(data: bytes) -> int:
        """Get the KeyStore present flag from raw data.

        :param data: Raw MBI image data.
        :return: KeyStore is included or not.
        """
        flags = Mbi_MixinIvt.get_flags(data)

        return bool(flags & Mbi_MixinIvt._KEY_STORE_FLAG)

    @staticmethod
    def get_app_table_presented(data: bytes) -> int:
        """Get the Multiple Application table present flag from raw data.

        :param data: Raw MBI image data.
        :return: Multiple Application table is included or not.
        """
        flags = Mbi_MixinIvt.get_flags(data)

        return bool(flags & Mbi_MixinIvt._RELOC_TABLE_FLAG)


class Mbi_MixinRelocTable(Mbi_Mixin):
    """Master Boot Image Relocation table class."""

    VALIDATION_SCHEMAS: List[str] = ["app_table"]
    NEEDED_MEMBERS: List[str] = ["app_table", "app"]

    app_table: Optional[MultipleImageTable]
    app: Optional[bytes]
    search_paths: Optional[List[str]]

    def mix_len(self) -> int:
        """Get length of additional binaries block.

        :return: Length of additional binaries block.
        """
        return len(self.app_table.export(0)) if self.app_table else 0

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        app_table = config.get("applicationTable", None)
        if app_table:
            self.app_table = MultipleImageTable()
            for entry in app_table:
                image = load_binary(entry.get("binary"), search_paths=self.search_paths)
                dst_addr = value_to_int(entry.get("destAddress"))
                load = entry.get("load")
                image_entry = MultipleImageEntry(
                    image, dst_addr, MultipleImageEntry.LTI_LOAD if load else 0
                )
                self.app_table.add_entry(image_entry)

    def mix_get_config(self, output_folder: str) -> Dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        config: Dict[str, Any] = {}
        if self.app_table:
            cfg_table = []
            for entry in self.app_table.entries:
                entry_cfg: Dict[str, Union[str, int]] = {}
                entry_cfg["destAddress"] = entry.dst_addr
                filename = f"mit_{hex(entry.dst_addr)}.bin"
                write_file(entry.image, os.path.join(output_folder, filename))
                entry_cfg["binary"] = filename
                entry_cfg["load"] = entry.is_load
                cfg_table.append(entry_cfg)
            config["applicationTable"] = cfg_table
        return config

    def mix_validate(self) -> None:
        """Validate the setting of image.

        :raises SPSDKError: Application table configuration is invalid.
        """
        if self.app_table and len(self.app_table.entries) == 0:
            raise SPSDKError("The application relocation table MUST has at least one record.")

    def get_app_length(self) -> int:
        """Compute full application length.

        :return: Length of application with relocated data.
        """
        assert self.app
        return len(self.app) + (len(self.app_table.export(0)) if self.app_table else 0)

    def get_app_data(self) -> bytes:
        """Fold the application data.

        :return: Whole application data.
        """
        assert self.app
        ret = bytearray()
        ret += self.app
        if self.app_table:
            ret += self.app_table.export(len(self.app))
        return ret

    def disassembly_app_data(self, data: bytes) -> bytes:
        """Disassembly Application data to application and optionally Multiple Application Table.

        :return: Application data without Multiple Application Table which will be stored in class.
        """
        app_size = len(data)
        app_table = MultipleImageTable.parse(data)
        if app_table:
            self.app_table = app_table
            app_size = app_table.start_address
        return data[:app_size]


class Mbi_MixinManifest(Mbi_MixinTrustZoneMandatory):
    """Master Boot Image Manifest class."""

    manifest_class = MasterBootImageManifest
    manifest: Optional[MasterBootImageManifest]

    VALIDATION_SCHEMAS: List[str] = ["tz", "firmware_version", "digest_hash_algo"]
    NEEDED_MEMBERS: List[str] = ["manifest", "firmware_version", "cert_block", "family"]
    PRE_PARSED: List[str] = ["cert_block"]

    family: str
    cert_block: Optional[Union[CertBlockV2, CertBlockV31]]
    firmware_version: Optional[int]

    def mix_len(self) -> int:
        """Get length of Manifest block.

        :return: Length of Manifest block.
        """
        assert self.manifest

        hash_length = 0
        if self.manifest.flags & self.manifest.DIGEST_PRESENT_FLAG:
            hash_algo = {1: "sha256", 2: "sha384", 3: "sha512"}[
                self.manifest.flags & self.manifest.HASH_TYPE_MASK
            ]
            hash_length = self.manifest.get_hash_size(hash_algo)
        return self.manifest.total_length + hash_length

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        super().mix_load_from_config(config)
        self.firmware_version = value_to_int(config.get("firmwareVersion", 0))
        digest_hash_algorithm = config.get("manifestDigestHashAlgorithm", None)
        # Backward compatibility code (in case that new manifestDigestHashAlgorithm doesn't exist
        # try to load old one ):
        if not digest_hash_algorithm:
            digest_hash_algorithm_length = config.get("manifestSigningHashLength", None)
            if digest_hash_algorithm_length:
                digest_hash_algorithm = {32: "sha256", 48: "sha384", 64: "sha512"}[
                    digest_hash_algorithm_length
                ]

        self.manifest = self.manifest_class(
            self.firmware_version, self.tz, digest_hash_algo=digest_hash_algorithm
        )

    def mix_get_config(self, output_folder: str) -> Dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        assert self.manifest
        config = super().mix_get_config(output_folder=output_folder)
        config["firmwareVersion"] = self.firmware_version
        config["manifestDigestHashAlgorithm"] = self.manifest.digest_hash_algo
        return config

    def mix_validate(self) -> None:
        """Validate the setting of image.

        :raises SPSDKError: The manifest configuration is invalid.
        """
        super().mix_validate()
        if not self.manifest:
            raise SPSDKError("The Image manifest must exists.")

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        assert isinstance(self.cert_block, CertBlockV31)
        manifest_offset = Mbi_MixinIvt.get_cert_block_offset(data) + self.cert_block.expected_size
        self.manifest = self.manifest_class.parse(self.family, data[manifest_offset:])
        self.firmware_version = self.manifest.firmware_version
        if self.manifest.trust_zone:
            self.tz = self.manifest.trust_zone
        else:
            super().mix_parse(data)


class Mbi_MixinManifestMcxNx(Mbi_MixinManifest):
    """Master Boot Image Manifest class for mcxn9xx device."""

    manifest_class = MasterBootImageManifestMcxNx
    manifest: Optional[MasterBootImageManifestMcxNx]


class Mbi_MixinCertBlockV2(Mbi_Mixin):
    """Master Boot Image certification block V2 class."""

    VALIDATION_SCHEMAS: List[str] = ["cert_prv_key"]
    NEEDED_MEMBERS: List[str] = ["cert_block", "signature_provider"]

    cert_block: Optional[Union[CertBlockV2, CertBlockV31]]
    signature_provider: Optional[SignatureProvider]
    search_paths: Optional[List[str]]
    total_len: Any
    key_store: Optional[KeyStore]
    HMAC_SIZE: int

    def mix_len(self) -> int:
        """Get length of Certificate Block V2.

        :return: Length of Certificate Block V2.
        """
        return len(self.cert_block.export()) if self.cert_block else 0

    @classmethod
    def mix_get_extra_validation_schemas(cls) -> List[Dict[str, Any]]:
        """Get additional validation schemas - directly from Certificate block object.

        :return: Certificate block schemas.
        """
        return CertBlockV2.get_validation_schemas()

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        self.cert_block = CertBlockV2.from_config(config, self.search_paths)
        self.signature_provider = get_signature_provider(
            sp_cfg=config.get("signProvider"),
            local_file_key=config.get("mainCertPrivateKeyFile"),
            search_paths=self.search_paths,
        )

    def mix_get_config(self, output_folder: str) -> Dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        assert self.cert_block
        config = self.cert_block.get_config(output_folder=output_folder)
        config["mainCertPrivateKeyFile"] = "Cannot get from parse"
        return config

    def mix_validate(self) -> None:
        """Validate the setting of image.

        :raises SPSDKError: Configuration of Certificate block v2 is invalid.
        """
        if not self.cert_block:
            raise SPSDKError("Certification block is missing")
        if not self.signature_provider:
            raise SPSDKError("Signature provider is not defined")
        assert isinstance(self.cert_block, CertBlockV2)
        public_key = self.cert_block.certificates[-1].public_key
        try:
            result = self.signature_provider.verify_public_key(public_key.dump())
            if not result:
                raise SPSDKError(
                    "Signature verification failed, public key does not match to private key"
                )
            logger.debug("The verification of private key pair integrity has been successful.")
        except SPSDKUnsupportedOperation:
            logger.warning("Signature provider could not verify the integrity of private key pair.")

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        offset = Mbi_MixinIvt.get_cert_block_offset(data)
        if hasattr(self, "hmac_key"):
            offset += self.HMAC_SIZE
            if Mbi_MixinIvt.get_key_store_presented(data):
                offset += KeyStore.KEY_STORE_SIZE

        self.cert_block = CertBlockV2.parse(data, offset)
        self.cert_block.alignment = 4
        self.signature_provider = None


class Mbi_MixinCertBlockV31(Mbi_Mixin):
    """Master Boot Image certification block V3.1 class."""

    VALIDATION_SCHEMAS: List[str] = [
        "signing_root_prv_key",
        "signature_provider",
        "signing_prv_key_lpc55s3x",
    ]
    NEEDED_MEMBERS: List[str] = ["cert_block", "signature_provider"]

    cert_block: Optional[Union[CertBlockV2, CertBlockV31]]
    signature_provider: Optional[SignatureProvider]
    search_paths: Optional[List[str]]

    def mix_len(self) -> int:
        """Get length of Certificate Block V3.1.

        :return: Length of Certificate Block V3.1.
        """
        assert self.cert_block and self.signature_provider
        return self.cert_block.expected_size + self.signature_provider.signature_length

    @classmethod
    def mix_get_extra_validation_schemas(cls) -> List[Dict[str, Any]]:
        """Get additional validation schemas - directly from Certificate block object.

        :return: Certificate block schemas.
        """
        return CertBlockV31.get_validation_schemas()

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        self.cert_block = CertBlockV31.from_config(config, search_paths=self.search_paths)

        private_key_file_name = (
            config.get("signingCertificatePrivateKeyFile")
            if self.cert_block and self.cert_block.isk_certificate
            else config.get("mainRootCertPrivateKeyFile")
        )
        self.signature_provider = get_signature_provider(
            sp_cfg=config.get("signProvider"),
            local_file_key=private_key_file_name,
            search_paths=self.search_paths,
        )

    def mix_get_config(self, output_folder: str) -> Dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        assert self.cert_block
        config = self.cert_block.get_config(output_folder)
        return config

    def mix_validate(self) -> None:
        """Validate the setting of image.

        :raises SPSDKError: The configuration of Certificate v3.1 is invalid.
        """
        if not self.cert_block:
            raise SPSDKError("Certification block is missing")

        if not self.signature_provider:
            raise SPSDKError("Signature provider is missing")

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        self.cert_block = CertBlockV31.parse(data, Mbi_MixinIvt.get_cert_block_offset(data))
        self.signature_provider = None


class Mbi_MixinHwKey(Mbi_Mixin):
    """Master Boot Image HW key user modes enable class."""

    VALIDATION_SCHEMAS: List[str] = ["hw_key"]
    NEEDED_MEMBERS: List[str] = ["user_hw_key_enabled"]

    user_hw_key_enabled: Optional[bool]

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        self.user_hw_key_enabled = config["enableHwUserModeKeys"]

    def mix_get_config(self, output_folder: str) -> Dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        config: Dict[str, Any] = {}
        config["enableHwUserModeKeys"] = True if self.user_hw_key_enabled else False
        return config

    def mix_validate(self) -> None:
        """Validate the setting of image.

        raise SPSDKError: Invalid HW key enabled member type.
        """
        if not isinstance(self.user_hw_key_enabled, bool):
            raise SPSDKError("User HW Key is not Boolean type.")

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        self.user_hw_key_enabled = Mbi_MixinIvt.get_hw_key_enabled(data)


class Mbi_MixinKeyStore(Mbi_Mixin):
    """Master Boot Image KeyStore class."""

    VALIDATION_SCHEMAS: List[str] = ["key_store"]
    NEEDED_MEMBERS: List[str] = ["key_store", "hmac_key"]

    key_store: Optional[KeyStore]
    hmac_key: Optional[bytes]
    search_paths: Optional[List[str]]
    HMAC_OFFSET: int
    HMAC_SIZE: int

    def mix_len(self) -> int:
        """Get length of KeyStore block.

        :return: Length of KeyStore block.
        """
        return (
            len(self.key_store.export())
            if self.key_store and self.key_store.key_source == KeySourceType.KEYSTORE
            else 0
        )

    def mix_app_len(self) -> int:  # pylint: disable=no-self-use
        """Compute application data length of individual mixin.

        :return: Application data length of atomic Mixin.
        """
        return 0

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        key_store_file = config.get("keyStoreFile", None)

        self.key_store = None
        if key_store_file:
            key_store_data = load_binary(key_store_file, search_paths=self.search_paths)
            self.key_store = KeyStore(KeySourceType.KEYSTORE, key_store_data)

    def mix_get_config(self, output_folder: str) -> Dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        config: Dict[str, Any] = {}
        file_name = None
        if self.key_store:
            file_name = "key_store.bin"
            write_file(self.key_store.export(), os.path.join(output_folder, file_name), mode="wb")

        config["keyStoreFile"] = file_name
        return config

    def mix_validate(self) -> None:
        """Validate the setting of image.

        raise SPSDKError: Invalid HW key enabled member type.
        """
        if self.key_store and not self.hmac_key:  # pylint: disable=no-member
            raise SPSDKError("When is used KeyStore, the HMAC key MUST by also used.")

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        key_store_present = Mbi_MixinIvt.get_key_store_presented(data)
        self.key_store = None
        if key_store_present:
            key_store_offset = self.HMAC_OFFSET + self.HMAC_SIZE
            self.key_store = KeyStore(
                KeySourceType.KEYSTORE,
                data[key_store_offset : key_store_offset + KeyStore.KEY_STORE_SIZE],
            )


class Mbi_MixinHmac(Mbi_Mixin):
    """Master Boot Image HMAC class."""

    VALIDATION_SCHEMAS: List[str] = ["hmac"]
    NEEDED_MEMBERS: List[str] = ["hmac_key"]
    # offset in the image, where the HMAC table is located
    HMAC_OFFSET = 64
    # size of HMAC table in bytes
    HMAC_SIZE = 32
    # length of user key or master key, in bytes
    _HMAC_KEY_LENGTH = 32

    hmac_key: Optional[bytes]
    search_paths: Optional[List[str]]
    dek: Optional[str]

    def mix_len(self) -> int:
        """Get length of HMAC block.

        :return: Length of HMAC block.
        """
        return self.HMAC_SIZE if self.hmac_key else 0

    def mix_app_len(self) -> int:  # pylint: disable=no-self-use
        """Compute application data length of individual mixin.

        :return: Application data length of atomic Mixin.
        """
        return 0

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        hmac_key_raw = config.get("outputImageEncryptionKeyFile")
        if hmac_key_raw:
            self.hmac_key = get_key(
                hmac_key_raw, expected_size=self.HMAC_SIZE, search_paths=self.search_paths
            )

    def mix_get_config(self, output_folder: str) -> Dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        config: Dict[str, Any] = {}
        config["outputImageEncryptionKeyFile"] = "The HMAC key cannot be restored"
        return config

    def mix_validate(self) -> None:
        """Validate the setting of image.

        raise SPSDKError: Invalid HW key enabled member type.
        """
        if self.hmac_key:
            length = len(self.hmac_key)
            if length != self._HMAC_KEY_LENGTH:
                raise SPSDKError(f"Invalid size of HMAC key 32 != {length}.")

    def compute_hmac(self, data: bytes) -> bytes:
        """Compute HMAC hash.

        :param data: Data to be hashed.
        :return: Result HMAC hash of input data.
        """
        if not self.hmac_key:
            return bytes()

        key = KeyStore.derive_hmac_key(self.hmac_key)
        result = crypto_backend().hmac(key, data)
        assert len(result) == self.HMAC_SIZE
        return result

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        if self.dek:
            self.hmac_key = get_key(
                key_source=self.dek,
                expected_size=self._HMAC_KEY_LENGTH,
                search_paths=self.search_paths,
            )


class Mbi_MixinHmacMandatory(Mbi_MixinHmac):
    """Master Boot Image HMAC class (Mandatory use)."""

    VALIDATION_SCHEMAS: List[str] = ["hmac_mandatory"]

    def mix_validate(self) -> None:
        """Validate the setting of image.

        raise SPSDKError: Invalid HW key enabled member type.
        """
        if not self.hmac_key:  # pylint: disable=no-member
            raise SPSDKError("HMAC Key MUST exists.")
        super().mix_validate()


class Mbi_MixinCtrInitVector(Mbi_Mixin):
    """Master Boot Image initial vector for encryption counter."""

    VALIDATION_SCHEMAS: List[str] = ["ctr_init_vector"]
    NEEDED_MEMBERS: List[str] = ["ctr_init_vector"]
    PRE_PARSED: List[str] = ["cert_block"]
    # length of counter initialization vector
    _CTR_INIT_VECTOR_SIZE = 16

    ctr_init_vector: bytes
    search_paths: Optional[List[str]]
    cert_block: Optional[Union[CertBlockV2, CertBlockV31]]
    HMAC_SIZE: int

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        ctr_init_vector_cfg = config.get("CtrInitVector", None)
        ctr_init_vector = (
            get_key(ctr_init_vector_cfg, self._CTR_INIT_VECTOR_SIZE, self.search_paths)
            if ctr_init_vector_cfg
            else None
        )
        self.store_ctr_init_vector(ctr_init_vector)

    def mix_get_config(self, output_folder: str) -> Dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        config: Dict[str, Any] = {}
        config["CtrInitVector"] = self.ctr_init_vector.hex()
        return config

    def mix_validate(self) -> None:
        """Validate the setting of image.

        raise SPSDKError: Invalid HW key enabled member type.
        """
        if not self.ctr_init_vector:
            raise SPSDKError("Initial vector for encryption counter MUST exists.")
        if len(self.ctr_init_vector) != self._CTR_INIT_VECTOR_SIZE:
            raise SPSDKError("Invalid size of Initial vector for encryption counter.")

    def store_ctr_init_vector(self, ctr_iv: Optional[bytes] = None) -> None:
        """Stores the Counter init vector, if not specified the random value is used.

        param ctr_iv: Counter Initial Vector.
        """
        self.ctr_init_vector = ctr_iv or crypto_backend().random_bytes(self._CTR_INIT_VECTOR_SIZE)

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        assert isinstance(self.cert_block, CertBlockV2)
        iv_offset = Mbi_MixinIvt.get_cert_block_offset(data) + self.cert_block.expected_size + 56
        if hasattr(self, "hmac_key"):
            iv_offset += self.HMAC_SIZE
            if Mbi_MixinIvt.get_key_store_presented(data):
                iv_offset += KeyStore.KEY_STORE_SIZE
        self.ctr_init_vector = data[iv_offset : iv_offset + self._CTR_INIT_VECTOR_SIZE]


class Mbi_MixinNoSignature(Mbi_Mixin):
    """Master Boot Image No Signature."""

    VALIDATION_SCHEMAS: List[str] = ["no_signature"]
    NEEDED_MEMBERS: List[str] = ["no_signature"]

    no_signature: Optional[bool]

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        self.no_signature = config.get("noSignature", False)


########################################################################################################################
# Export image Mixins
########################################################################################################################


class Mbi_ExportMixin:
    """Base MBI Export Mixin class."""

    def collect_data(self) -> bytes:  # pylint: disable=no-self-use
        """Collect basic data to create image.

        :return: Collected raw image.
        """
        return bytes()

    def disassemble_image(self, image: bytes) -> None:  # pylint: disable=no-self-use
        """Disassemble image to individual parts from image.

        :param image: Image.
        """

    def encrypt(self, image: bytes, revert: bool = False) -> bytes:  # pylint: disable=no-self-use
        """Encrypt image if needed.

        :param image: Input raw image to encrypt.
        :param revert: Revert the operation if possible.
        :return: Encrypted image.
        """
        return image

    def post_encrypt(
        self, image: bytes, revert: bool = False
    ) -> bytes:  # pylint: disable=no-self-use
        """Optionally do some post encrypt image updates.

        :param image: Encrypted image.
        :param revert: Revert the operation if possible.
        :return: Updated encrypted image.
        """
        return image

    def sign(self, image: bytes, revert: bool = False) -> bytes:  # pylint: disable=no-self-use
        """Sign image (by signature or CRC).

        :param image: Image to sign.
        :param revert: Revert the operation if possible.
        :return: Optionally signed image.
        """
        return image

    def finalize(self, image: bytes, revert: bool = False) -> bytes:  # pylint: disable=no-self-use
        """Finalize the image for export.

        This part could add HMAC/KeyStore etc.

        :param image: Input image.
        :param revert: Revert the operation if possible.
        :return: Finalized image suitable for export.
        """
        return image


class Mbi_ExportMixinAppTrustZone(Mbi_ExportMixin):
    """Export Mixin to handle simple application data and TrustZone."""

    app: Optional[bytes]
    tz: TrustZone
    total_len: Any
    update_ivt: Callable[[bytes, int, int], bytes]
    clean_ivt: Callable[[bytes], bytes]
    get_app_data: Callable[[], bytes]
    disassembly_app_data: Callable[[bytes], bytes]

    def collect_data(self) -> bytes:
        """Collect application data and TrustZone including update IVT.

        :return: Image with updated IVT and added TrustZone.
        """
        assert self.app and self.tz
        app = self.get_app_data() if hasattr(self, "get_app_data") else self.app
        return self.update_ivt(app + self.tz.export(), self.total_len, 0)

    def disassemble_image(self, image: bytes) -> None:  # pylint: disable=no-self-use
        """Disassemble image to individual parts from image.

        :param image: Image.
        """
        tz_len = len(self.tz.export())
        if tz_len:
            image = image[:-tz_len]
        if hasattr(self, "disassembly_app_data"):
            image = self.disassembly_app_data(image)
        self.app = self.clean_ivt(image)


class Mbi_ExportMixinAppTrustZoneCertBlock(Mbi_ExportMixin):
    """Export Mixin to handle simple application data, TrustZone and Certification block."""

    app: Optional[bytes]
    tz: TrustZone
    total_len: Any
    app_len: Any
    update_ivt: Callable[[bytes, int, int], bytes]
    clean_ivt: Callable[[bytes], bytes]
    cert_block: Optional[Union[CertBlockV2, CertBlockV31]]
    get_app_data: Callable[[], bytes]
    disassembly_app_data: Callable[[bytes], bytes]

    def collect_data(self) -> bytes:
        """Collect application data and TrustZone including update IVT.

        :return: Image with updated IVT and added TrustZone.
        """
        assert self.app and self.tz and self.cert_block and isinstance(self.cert_block, CertBlockV2)
        self.cert_block.alignment = 4
        self.cert_block.image_length = self.app_len
        logger.info(f"RKTH: {self.cert_block.rkht.hex()}")
        app = self.get_app_data() if hasattr(self, "get_app_data") else self.app
        return self.update_ivt(
            app + self.cert_block.export() + self.tz.export(),
            self.total_len + self.cert_block.signature_size,
            len(app),
        )

    def disassemble_image(self, image: bytes) -> None:  # pylint: disable=no-self-use
        """Disassemble image to individual parts from image.

        :param image: Image.
        """
        image = image[: -Mbi_MixinIvt.get_cert_block_offset(image)]
        if hasattr(self, "disassembly_app_data"):
            image = self.disassembly_app_data(image)
        self.app = self.clean_ivt(image)


class Mbi_ExportMixinAppCertBlockManifest(Mbi_ExportMixin):
    """Export Mixin to handle simple application data, Certification block and Manifest."""

    app: Optional[bytes]
    total_len: Any
    update_ivt: Callable[[bytes, int, int], bytes]
    clean_ivt: Callable[[bytes], bytes]
    get_app_data: Callable[[], bytes]
    cert_block: Optional[Union[CertBlockV2, CertBlockV31]]
    manifest: Optional[T_Manifest]  # type: ignore  # we don't use regular bound method
    disassembly_app_data: Callable[[bytes], bytes]

    def collect_data(self) -> bytes:
        """Collect application data, Certification Block and Manifest including update IVT.

        :raises SPSDKError: When either application data or certification block or manifest is missing
        :return: Image with updated IVT and added Certification Block with Manifest.
        """
        if not (self.app and self.manifest and self.cert_block):
            raise SPSDKError(
                "Either application data or certification block or manifest is missing"
            )
        app = self.get_app_data() if hasattr(self, "get_app_data") else self.app
        assert len(self.manifest.export()) == self.manifest.total_length
        image = self.update_ivt(
            app + self.cert_block.export() + self.manifest.export(),
            self.total_len,
            len(app),
        )

        # in case of McuNx manifest add crc
        if isinstance(self.manifest, MasterBootImageManifestMcxNx):
            self.manifest.compute_crc(image[:-4])
            image = self.update_ivt(
                app + self.cert_block.export() + self.manifest.export(),
                self.total_len,
                len(app),
            )
        return image

    def disassemble_image(self, image: bytes) -> None:  # pylint: disable=no-self-use
        """Disassemble image to individual parts from image.

        :param image: Image.
        """
        image = image[: -Mbi_MixinIvt.get_cert_block_offset(image)]
        if hasattr(self, "disassembly_app_data"):
            image = self.disassembly_app_data(image)
        self.app = self.clean_ivt(image)

    def finalize(self, image: bytes, revert: bool = False) -> bytes:
        """Finalize the image for export by adding HMAC a optionally KeyStore.

        :param image: Input image.
        :param revert: Revert the operation if possible.
        :return: Finalized image suitable for export.
        """
        ret = image
        if (
            self.manifest
            and self.manifest.flags
            and self.manifest.DIGEST_PRESENT_FLAG
            and self.manifest.digest_hash_algo
        ):
            if revert:
                ret = ret[: -self.manifest.get_hash_size(self.manifest.digest_hash_algo)]
            else:
                ret += crypto_backend().hash(image, self.manifest.digest_hash_algo)
        return ret


class Mbi_ExportMixinCrcSign(Mbi_ExportMixin):
    """Export Mixin to handle sign by CRC."""

    IVT_CRC_CERTIFICATE_OFFSET: int
    update_crc_val_cert_offset: Callable[[bytes, int], bytes]

    def sign(self, image: bytes, revert: bool = False) -> bytes:
        """Do simple calculation of CRC and return updated image with it.

        :param image: Input raw image.
        :param revert: Revert the operation if possible.
        :return: Image enriched by CRC in IVT table.
        """
        if revert:
            return image

        # calculate CRC using MPEG2 specification over all of data (app and trustzone)
        # expect for 4 bytes at CRC_BLOCK_OFFSET
        crc32_function = mkPredefinedCrcFun("crc-32-mpeg")
        crc = crc32_function(image[: self.IVT_CRC_CERTIFICATE_OFFSET])
        crc = crc32_function(image[self.IVT_CRC_CERTIFICATE_OFFSET + 4 :], crc)

        # Recreate data with valid CRC value
        return self.update_crc_val_cert_offset(image, crc)


class Mbi_ExportMixinRsaSign(Mbi_ExportMixin):
    """Export Mixin to handle sign by RSA."""

    signature_provider: Optional[SignatureProvider]
    no_signature: Optional[bool]
    cert_block: Optional[Union[CertBlockV31, CertBlockV2]]

    def sign(self, image: bytes, revert: bool = False) -> bytes:
        """Do calculation of RSA signature and return updated image with it.

        :param image: Input raw image.
        :param revert: Revert the operation if possible.
        :return: Image enriched by RSA signature at end of image.
        """
        if hasattr(self, "no_signature") and self.no_signature:
            return image

        if revert:
            assert self.cert_block and isinstance(self.cert_block, CertBlockV2)
            return image[: -self.cert_block.signature_size]

        assert self.signature_provider
        signature = self.signature_provider.sign(image)
        return image + signature


class Mbi_ExportMixinEccSign(Mbi_ExportMixin):
    """Export Mixin to handle sign by ECC."""

    signature_provider: Optional[SignatureProvider]
    no_signature: Optional[bool]
    cert_block: Optional[Union[CertBlockV31, CertBlockV2]]

    def sign(self, image: bytes, revert: bool = False) -> bytes:
        """Do calculation of ECC signature and return updated image with it.

        :param image: Input raw image.
        :param revert: Revert the operation if possible.
        :return: Image enriched by ECC signature at end of image.
        """
        if hasattr(self, "no_signature") and self.no_signature:
            return image

        if revert:
            assert self.cert_block and isinstance(self.cert_block, CertBlockV31)
            if self.cert_block.signature_size == 0:
                return image

            return image[: -self.cert_block.signature_size]

        assert self.signature_provider
        signature = self.signature_provider.sign(image)
        assert signature
        return image + serialize_ecc_signature(
            signature, self.signature_provider.signature_length // 2
        )


class Mbi_ExportMixinHmacKeyStoreFinalize(Mbi_ExportMixin):
    """Export Mixin to handle finalize by HMAC and optionally KeyStore."""

    compute_hmac: Callable[[bytes], bytes]
    HMAC_OFFSET: int
    HMAC_SIZE: int
    key_store: Optional[KeyStore]

    def finalize(self, image: bytes, revert: bool = False) -> bytes:
        """Finalize the image for export by adding HMAC a optionally KeyStore.

        :param image: Input image.
        :param revert: Revert the operation if possible.
        :return: Finalized image suitable for export.
        """
        if revert:
            end_of_hmac_keystore = self.HMAC_OFFSET + self.HMAC_SIZE
            if Mbi_MixinIvt.get_key_store_presented(image):
                end_of_hmac_keystore += KeyStore.KEY_STORE_SIZE
            return image[: self.HMAC_OFFSET] + image[end_of_hmac_keystore:]

        hmac_keystore = self.compute_hmac(image[: self.HMAC_OFFSET])
        if self.key_store:
            hmac_keystore += self.key_store.export()

        return image[: self.HMAC_OFFSET] + hmac_keystore + image[self.HMAC_OFFSET :]
