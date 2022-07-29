#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


"""Master Boot Image."""

import struct
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

from crcmod.predefined import mkPredefinedCrcFun

from spsdk import SPSDKError
from spsdk.crypto import SignatureProvider
from spsdk.image import IMG_DATA_FOLDER
from spsdk.image.keystore import KeySourceType, KeyStore
from spsdk.image.trustzone import TrustZone, TrustZoneType
from spsdk.utils.crypto import crypto_backend
from spsdk.utils.crypto.cert_blocks import CertBlockV2, CertBlockV31
from spsdk.utils.crypto.common import serialize_ecc_signature
from spsdk.utils.easy_enum import Enum
from spsdk.utils.images import BinaryImage
from spsdk.utils.misc import align_block, find_file, load_binary, load_configuration, value_to_int

SCHEMA_FILE = IMG_DATA_FOLDER + "/sch_mbimg.yml"


class MasterBootImageManifest:
    """MasterBootImage Manifest used in LPC55s3x."""

    MAGIC = b"imgm"
    FORMAT = "<4s4L"
    FORMAT_VERSION = 0x0001_0000
    DIGEST_PRESENT_FLAG = 0x8000_0000

    def __init__(
        self, firmware_version: int, trust_zone: TrustZone, sign_hash_len: int = None
    ) -> None:
        """Initialize MBI Manifest object.

        :param firmware_version: firmware version
        :param sign_hash_len: length of hash used for singing, defaults to None
        :param trust_zone: TrustZone instance, defaults to None
        """
        self.firmware_version = firmware_version
        self.sign_hash_len = sign_hash_len
        self.trust_zone = trust_zone
        self.total_length = self._calculate_length()
        self.flags = self._calculate_flags()

    def _calculate_length(self) -> int:
        length = struct.calcsize(self.FORMAT)
        length += len(self.trust_zone.export())
        return length

    def _calculate_flags(self) -> int:
        if not self.sign_hash_len:
            return 0
        hash_len_types = {0: 0, 32: 1, 48: 2, 64: 3}
        return self.DIGEST_PRESENT_FLAG | hash_len_types[self.sign_hash_len]

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
        return data + self.trust_zone.export()


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


# ****************************************************************************************************
#                                             Mbi Mixins
# ****************************************************************************************************

# pylint: disable=invalid-name
class Mbi_Mixin:
    """Base class for Master BOtt Image Mixin classes."""

    VALIDATION_SCHEMAS: List[str] = []
    NEEDED_MEMBERS: List[str] = []

    def mix_len(self) -> int:  # pylint: disable=no-self-use
        """Compute length of individual mixin.

        :return: Length of atomic Mixin.
        """
        return 0

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

    VALIDATION_SCHEMAS: List[str] = ["tz", "family"]
    NEEDED_MEMBERS: List[str] = ["tz"]

    tz: TrustZone
    search_paths: Optional[List[str]]

    def mix_len(self) -> int:
        """Get length of TrustZone array.

        :return: Length of TrustZone.
        """
        return len(self.tz.export())

    def _load_preset_file(self, preset_file: str, family: str) -> None:
        _preset_file = find_file(preset_file, search_paths=self.search_paths)
        try:
            tz_config = load_configuration(_preset_file)
            self.tz = TrustZone.from_config(tz_config)
        except SPSDKError:
            tz_bin = load_binary(_preset_file)
            self.tz = TrustZone.from_binary(family=family, raw_data=tz_bin)

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        enabled_trustzone = config.get("enableTrustZone", False)
        if enabled_trustzone:
            trustzone_preset_file = config.get("trustZonePresetFile", None)
            if trustzone_preset_file:
                family = config.get("family", None)
                self._load_preset_file(trustzone_preset_file, family)
            else:
                self.tz = TrustZone.enabled()
        else:
            self.tz = TrustZone.disabled()


class Mbi_MixinTrustZoneMandatory(Mbi_MixinTrustZone):
    """Master Boot Image Trust Zone class for LPC55s3x family."""

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        trustzone_preset_file = config.get("trustZonePresetFile", None)
        if trustzone_preset_file:
            family = config.get("family", None)
            self._load_preset_file(trustzone_preset_file, family)
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


class Mbi_MixinImageSubType(Mbi_Mixin):
    """Master Boot Image SubType class."""

    class Mbi_ImageSubType(Enum):
        """List of supported subtypes."""

        MAIN = (0x00, "MAIN", "Default (main) application image")

    VALIDATION_SCHEMAS: List[str] = ["image_subtype"]
    NEEDED_MEMBERS: List[str] = ["image_subtype"]

    image_subtype: Optional[int]

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        self.set_image_subtype(config.get("outputImageSubtype", "MAIN"))

    def set_image_subtype(self, image_subtype: Optional[Union[str, int]]) -> None:
        """Convert string value to int by enum table and store to class."""
        if image_subtype is None:
            self.image_subtype = Mbi_MixinImageSubType.Mbi_ImageSubType.MAIN
        else:
            image_subtype = Mbi_MixinImageSubType.Mbi_ImageSubType.get(
                image_subtype, Mbi_MixinImageSubType.Mbi_ImageSubType.MAIN
            )

            self.image_subtype = (
                image_subtype
                if isinstance(image_subtype, int)
                else Mbi_MixinImageSubType.Mbi_ImageSubType.MAIN
            )


class Mbi_MixinIvt(Mbi_Mixin):
    """Master Boot Image Interrupt Vector table class."""

    # IVT table offsets
    IVT_IMAGE_LENGTH_OFFSET = 0x20
    IVT_IMAGE_FLAGS_OFFSET = 0x24
    IVT_CRC_CERTIFICATE_OFFSET = 0x28
    IVT_LOAD_ADDR_OFFSET = 0x34

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
        flags = (self.tz.type << 8) + int(self.IMAGE_TYPE[0])

        if hasattr(self, "image_subtype"):
            assert self.image_subtype is not None
            flags |= self.image_subtype << 4

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


class Mbi_MixinManifest(Mbi_MixinTrustZoneMandatory):
    """Master Boot Image Manifest class."""

    VALIDATION_SCHEMAS: List[str] = ["tz", "family", "firmware_version", "sign_hash_len"]
    NEEDED_MEMBERS: List[str] = ["manifest", "firmware_version"]

    manifest: Optional[MasterBootImageManifest]
    firmware_version: Optional[int]

    def mix_len(self) -> int:
        """Get length of Manifest block.

        :return: Length of Manifest block.
        """
        assert self.manifest
        return self.manifest.total_length

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        super().mix_load_from_config(config)
        self.firmware_version = value_to_int(config.get("firmwareVersion", 0))
        sign_hash_len_raw = config.get("manifestSigningHashLength", None)
        sign_hash_len = value_to_int(sign_hash_len_raw) if sign_hash_len_raw else None
        self.manifest = MasterBootImageManifest(
            self.firmware_version, self.tz, sign_hash_len=sign_hash_len
        )

    def mix_validate(self) -> None:
        """Validate the setting of image.

        :raises SPSDKError: The manifest configuration is invalid.
        """
        super().mix_validate()
        if not self.manifest:
            raise SPSDKError("The Image manifest must exists.")


class Mbi_MixinCertBlockV2(Mbi_Mixin):
    """Master Boot Image certification block V2 class."""

    VALIDATION_SCHEMAS: List[str] = ["cert_prv_key"]
    NEEDED_MEMBERS: List[str] = ["cert_block", "priv_key_data"]

    cert_block: Optional[CertBlockV2]
    priv_key_data: Optional[bytes]
    search_paths: Optional[List[str]]

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
        self.priv_key_data = load_binary(
            config["mainCertPrivateKeyFile"], search_paths=self.search_paths
        )

    def mix_validate(self) -> None:
        """Validate the setting of image.

        :raises SPSDKError: Configuration of Certificate block v2 is invalid.
        """
        if not self.cert_block:
            raise SPSDKError("Certification block is missing")

        if not self.priv_key_data:
            raise SPSDKError("Certification block Private key is missing")

        if not self.cert_block.verify_private_key(self.priv_key_data):  # type: ignore
            raise SPSDKError(
                "Signature verification failed, private key does not match to certificate"
            )


class Mbi_MixinCertBlockV31(Mbi_Mixin):
    """Master Boot Image certification block V3.1 class."""

    VALIDATION_SCHEMAS: List[str] = [
        "use_isk",
        "signing_cert_prv_key",
        "signing_root_prv_key",
        "signing_prv_key_lpc55s3x",
    ]
    NEEDED_MEMBERS: List[str] = ["cert_block", "signature_provider"]

    cert_block: Optional[CertBlockV31]
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
        # if ISK is used, we use for signing the ISK certificate instead of root
        if self.cert_block.isk_certificate:
            signing_private_key_path = config.get("signingCertificatePrivateKeyFile")
        else:
            signing_private_key_path = config.get("mainRootCertPrivateKeyFile")
        assert signing_private_key_path
        signing_private_key_path = find_file(
            signing_private_key_path, search_paths=self.search_paths
        )
        self.signature_provider = SignatureProvider.create(
            f"type=file;file_path={signing_private_key_path}"
        )

    def mix_validate(self) -> None:
        """Validate the setting of image.

        :raises SPSDKError: The configuration of Certificate v3.1 is invalid.
        """
        if not self.cert_block:
            raise SPSDKError("Certification block is missing")

        if not self.signature_provider:
            raise SPSDKError("Signature provider is missing")


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

    def mix_validate(self) -> None:
        """Validate the setting of image.

        raise SPSDKError: Invalid HW key enabled member type.
        """
        if not isinstance(self.user_hw_key_enabled, bool):
            raise SPSDKError("User HW Key is not Boolean type.")


class Mbi_MixinKeyStore(Mbi_Mixin):
    """Master Boot Image KeyStore class."""

    VALIDATION_SCHEMAS: List[str] = ["key_store"]
    NEEDED_MEMBERS: List[str] = ["key_store", "hmac_key"]

    key_store: Optional[KeyStore]
    hmac_key: Optional[bytes]
    search_paths: Optional[List[str]]

    def mix_len(self) -> int:
        """Get length of KeyStore block.

        :return: Length of KeyStore block.
        """
        return (
            len(self.key_store.export())
            if self.key_store and self.key_store.key_source == KeySourceType.KEYSTORE
            else 0
        )

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        key_source = KeySourceType.get(config.get("deviceKeySource", "OTP"))
        use_key_store = config.get("useKeyStore", False)
        key_store_file = config.get("keyStoreFile", None)

        if use_key_store and key_source == KeySourceType.KEYSTORE:
            key_store_data = (
                load_binary(key_store_file, search_paths=self.search_paths)
                if key_store_file
                else bytes(KeyStore.KEY_STORE_SIZE)
            )
            self.key_store = KeyStore(key_source, key_store_data)  # type: ignore

    def mix_validate(self) -> None:
        """Validate the setting of image.

        raise SPSDKError: Invalid HW key enabled member type.
        """
        if self.key_store and not self.hmac_key:  # pylint: disable=no-member
            raise SPSDKError("When is used KeyStore, the HMAC key MUST by also used.")


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

    def mix_len(self) -> int:
        """Get length of HMAC block.

        :return: Length of HMAC block.
        """
        return self.HMAC_SIZE if self.hmac_key else 0

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        hmac_key_raw = config.get("outputImageEncryptionKeyFile")
        if hmac_key_raw:
            hmac_key = load_binary(hmac_key_raw, search_paths=self.search_paths)
            if len(hmac_key) == (2 * self.HMAC_SIZE):
                self.hmac_key = bytes.fromhex(hmac_key.decode("utf-8"))
            else:
                self.hmac_key = hmac_key

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
    # length of counter initialization vector
    _CTR_INIT_VECTOR_SIZE = 16

    ctr_init_vector: bytes

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        hex_val = config.get("CtrInitVector", None)
        ctr_init_vector = bytes.fromhex(hex_val.replace("0x", "")) if hex_val else None
        self.store_ctr_init_vector(ctr_init_vector)

    def mix_validate(self) -> None:
        """Validate the setting of image.

        raise SPSDKError: Invalid HW key enabled member type.
        """
        if not self.ctr_init_vector:
            raise SPSDKError("Initial vector for encryption counter MUST exists.")
        if len(self.ctr_init_vector) != self._CTR_INIT_VECTOR_SIZE:
            raise SPSDKError("Invalid size of Initial vector for encryption counter.")

    def store_ctr_init_vector(self, ctr_iv: bytes = None) -> None:
        """Stores the Counter init vector, if not specified the random value is used.

        param ctr_iv: Counter Initial Vector.
        """
        self.ctr_init_vector = ctr_iv or crypto_backend().random_bytes(self._CTR_INIT_VECTOR_SIZE)


class Mbi_MixinSignDigest(Mbi_Mixin):
    """Master Boot Image Signature Digest."""

    VALIDATION_SCHEMAS: List[str] = ["attach_sign_digest", "use_isk", "elliptic_curves"]
    NEEDED_MEMBERS: List[str] = ["attach_sign_digest"]
    SIGN_DIGEST_VALUES: Dict[str, int] = {"sha256": 32, "sha384": 48}

    attach_sign_digest: Optional[str]
    signature_provider: Optional[SignatureProvider]

    def mix_len(self) -> int:
        """Get length of Signature digest block.

        :return: Length of Signature digest block.
        """
        return self.SIGN_DIGEST_VALUES[self.attach_sign_digest] if self.attach_sign_digest else 0

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        attach_sign_digest = config.get("attachSignDigest", False)
        use_isk = config.get("useIsk", False)
        if attach_sign_digest:
            cfg_root_curve = config.get(
                "iskCertificateEllipticCurve" if use_isk else "rootCertificateEllipticCurve"
            )
            self.attach_sign_digest = "sha256" if cfg_root_curve == "secp256r1" else "sha384"
        else:
            self.attach_sign_digest = None

    def mix_validate(self) -> None:
        """Validate the setting of image.

        raise SPSDKError: Invalid HW key enabled member type.
        """
        if self.attach_sign_digest and self.attach_sign_digest not in ["sha256", "sha384"]:
            raise SPSDKError(
                f"Invalid value for Signature Digest: {self.attach_sign_digest} MUST be one of ['sha256', 'sha384']."
            )

    def get_sign_digest(self) -> Optional[str]:
        """Get sign digest type from signature provider.

        :return: Type of signature digest.
        """
        if self.signature_provider:
            return "sha256" if self.signature_provider.signature_length == 32 else "sha384"

        return None


class Mbi_MixinNXPImage(Mbi_Mixin):
    """Master Boot Image 'Image Type Changer' to NXP Image type."""

    VALIDATION_SCHEMAS: List[str] = ["nxp_image"]
    NEEDED_MEMBERS: List[str] = ["IMAGE_TYPE"]
    SIGNED_XIP_NXP_IMAGE = (0x08, "Plain Signed XIP Image NXP Key")

    IMAGE_TYPE: Tuple[int, str]

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        nxp_image_type = config.get("IsNxpImage", False)
        if nxp_image_type:
            self.change_to_nxp_image()

    def change_to_nxp_image(self) -> None:
        """Calling this changed to NXP image."""
        self.IMAGE_TYPE = self.SIGNED_XIP_NXP_IMAGE


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

    def encrypt(self, raw_image: bytes) -> bytes:  # pylint: disable=no-self-use
        """Encrypt image if needed.

        :param raw_image: Input raw image to encrypt.
        :return: Encrypted image.
        """
        return raw_image

    def post_encrypt(self, image: bytes) -> bytes:  # pylint: disable=no-self-use
        """Optionally do some post encrypt image updates.

        :param image: Encrypted image.
        :return: Updated encrypted image.
        """
        return image

    def sign(self, image: bytes) -> bytes:  # pylint: disable=no-self-use
        """Sign image (by signature or CRC).

        :param image: Image to sign.
        :return: Optionally signed image.
        """
        return image

    def finalize(self, image: bytes) -> bytes:  # pylint: disable=no-self-use
        """Finalize the image for export.

        This part could add HMAC/KeyStore etc.

        :param image: Input image.
        :return: Finalized image suitable for export.
        """
        return image


class Mbi_ExportMixinAppTrustZone(Mbi_ExportMixin):
    """Export Mixin to handle simple application data and TrustZone."""

    app: Optional[bytes]
    tz: TrustZone
    total_len: Any
    update_ivt: Callable
    get_app_data: Callable

    def collect_data(self) -> bytes:
        """Collect application data and TrustZone including update IVT.

        :return: Image with updated IVT and added TrustZone.
        """
        # reveal_type(self.update_ivt)
        assert self.app and self.tz
        app = self.get_app_data() if hasattr(self, "get_app_data") else self.app
        return self.update_ivt(app + self.tz.export(), self.total_len, 0)


class Mbi_ExportMixinAppTrustZoneCertBlock(Mbi_ExportMixin):
    """Export Mixin to handle simple application data, TrustZone and Certification block."""

    app: Optional[bytes]
    tz: TrustZone
    total_len: Any
    app_len: Any
    update_ivt: Callable
    cert_block: Optional[CertBlockV2]
    get_app_data: Callable

    def collect_data(self) -> bytes:
        """Collect application data and TrustZone including update IVT.

        :return: Image with updated IVT and added TrustZone.
        """
        assert self.app and self.tz and self.cert_block
        self.cert_block.alignment = 4
        self.cert_block.image_length = self.app_len
        app = self.get_app_data() if hasattr(self, "get_app_data") else self.app
        return self.update_ivt(
            app + self.cert_block.export() + self.tz.export(),
            self.total_len + self.cert_block.signature_size,
            len(app),
        )


class Mbi_ExportMixinAppCertBlockManifest(Mbi_ExportMixin):
    """Export Mixin to handle simple application data, Certification block and Manifest."""

    app: Optional[bytes]
    total_len: Any
    app_len: Any
    update_ivt: Callable
    get_app_data: Callable
    cert_block: Optional[CertBlockV31]
    manifest: Optional[MasterBootImageManifest]

    def collect_data(self) -> bytes:
        """Collect application data, Certification Block and Manifest including update IVT.

        :return: Image with updated IVT and added Certification Block with Manifest.
        """
        assert self.app and self.manifest and self.cert_block
        app = self.get_app_data() if hasattr(self, "get_app_data") else self.app
        return self.update_ivt(
            app + self.cert_block.export() + self.manifest.export(),
            self.total_len,
            len(app),
        )


class Mbi_ExportMixinCrcSign(Mbi_ExportMixin):
    """Export Mixin to handle sign by CRC."""

    IVT_CRC_CERTIFICATE_OFFSET: int
    update_crc_val_cert_offset: Callable

    def sign(self, image: bytes) -> bytes:
        """Do simple calculation of CRC and return updated image with it.

        :param image: Input raw image.
        :return: Image enriched by CRC in IVT table.
        """
        # calculate CRC using MPEG2 specification over all of data (app and trustzone)
        # expect for 4 bytes at CRC_BLOCK_OFFSET
        crc32_function = mkPredefinedCrcFun("crc-32-mpeg")
        crc = crc32_function(image[: self.IVT_CRC_CERTIFICATE_OFFSET])
        crc = crc32_function(image[self.IVT_CRC_CERTIFICATE_OFFSET + 4 :], crc)

        # Recreate data with valid CRC value
        return self.update_crc_val_cert_offset(image, crc)


class Mbi_ExportMixinRsaSign(Mbi_ExportMixin):
    """Export Mixin to handle sign by RSA."""

    priv_key_data: Optional[bytes]

    def sign(self, image: bytes) -> bytes:
        """Do calculation of RSA signature and return updated image with it.

        :param image: Input raw image.
        :return: Image enriched by RSA signature at end of image.
        """
        assert self.priv_key_data
        return image + crypto_backend().rsa_sign(self.priv_key_data, image)


class Mbi_ExportMixinEccSign(Mbi_ExportMixin):
    """Export Mixin to handle sign by ECC."""

    signature_provider: Optional[SignatureProvider]
    no_signature: Optional[bool]

    def sign(self, image: bytes) -> bytes:
        """Do calculation of ECC signature and return updated image with it.

        :param image: Input raw image.
        :return: Image enriched by ECC signature at end of image.
        """
        if hasattr(self, "no_signature") and self.no_signature:
            return image
        assert self.signature_provider
        signature = self.signature_provider.sign(image)
        assert signature
        return image + serialize_ecc_signature(
            signature, self.signature_provider.signature_length // 2
        )


class Mbi_ExportMixinHmacKeyStoreFinalize(Mbi_ExportMixin):
    """Export Mixin to handle finalize by HMAC and optionally KeyStore."""

    compute_hmac: Callable
    HMAC_OFFSET: int
    key_store: Optional[KeyStore]

    def finalize(self, image: bytes) -> bytes:
        """Finalize the image for export by adding HMAC a optionally KeyStore.

        :param image: Input image.
        :return: Finalized image suitable for export.
        """
        hmac_keystore = self.compute_hmac(image[: self.HMAC_OFFSET])
        if self.key_store:
            hmac_keystore += self.key_store.export()

        return image[: self.HMAC_OFFSET] + hmac_keystore + image[self.HMAC_OFFSET :]


class Mbi_ExportMixinSignDigestFinalize(Mbi_ExportMixin):
    """Export Mixin to handle finalize by Signature digest."""

    attach_sign_digest: Optional[str]

    def finalize(self, image: bytes) -> bytes:
        """Finalize the image for export by adding HMAC a optionally KeyStore.

        :param image: Input image.
        :return: Finalized image suitable for export.
        """
        ret = image
        if self.attach_sign_digest:
            ret += crypto_backend().hash(image, self.attach_sign_digest)
        return ret
