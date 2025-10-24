#!/usr/bin/env python
# -*- coding: utf-8 -*-
## Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""HSE (Hardware Security Engine) specific mixins for Master Boot Image.

This module provides HSE-specific implementations for the Master Boot Image (MBI),
including IVT (Image Vector Table), Application Boot Header, and signature handling.
"""
import logging
import struct
from typing import Any, Optional

from typing_extensions import Self

from spsdk.crypto.hash import get_hash
from spsdk.crypto.rng import random_bytes
from spsdk.crypto.symmetric import aes_gcm_encrypt
from spsdk.exceptions import SPSDKError, SPSDKVerificationError
from spsdk.image.mbi.mbi_mixin import Mbi_ExportMixin, Mbi_Mixin, Mbi_MixinApp
from spsdk.utils.binary_image import BinaryImage
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision, get_db
from spsdk.utils.misc import Endianness, align_block, extend_block
from spsdk.utils.spsdk_enum import SpsdkEnum
from spsdk.utils.verifier import Verifier, VerifierResult

logger = logging.getLogger(__name__)


class BootConfig:
    """Boot Configuration for HSE IVT."""

    # Bit positions for Boot Configuration
    CM7_0_ENABLE_BIT = 0
    BOOT_SEQ_BIT = 3
    APP_SWT_INIT_BIT = 5

    def __init__(self, value: int = 0) -> None:
        """Initialize Boot Configuration.

        :param value: Initial boot config value
        """
        # Bitfield values
        self.cm7_0_enable = True
        self.boot_seq = False
        self.app_swt_init = False

        # Internal value storage
        self._value = 0

        if value:
            self.value = value

    @property
    def value(self) -> int:
        """Get the boot config value.

        :return: Boot config value as integer
        """
        # Calculate the value from bit fields
        value = 0
        if self.cm7_0_enable:
            value |= 1 << self.CM7_0_ENABLE_BIT
        if self.boot_seq:
            value |= 1 << self.BOOT_SEQ_BIT
        if self.app_swt_init:
            value |= 1 << self.APP_SWT_INIT_BIT

        self._value = value
        return self._value

    @value.setter
    def value(self, value: int) -> None:
        """Set the boot config value and update bitfields.

        :param value: Boot config value
        """
        self._value = value
        # Update bit fields from value
        self.cm7_0_enable = bool(value & (1 << self.CM7_0_ENABLE_BIT))
        self.boot_seq = bool(value & (1 << self.BOOT_SEQ_BIT))
        self.app_swt_init = bool(value & (1 << self.APP_SWT_INIT_BIT))

    def __str__(self) -> str:
        """Return string representation of Boot Config.

        :return: String representation
        """
        result = [f"Boot Config: 0x{self.value:08X}"]
        result.append(f"  CM7_0 Enable: {self.cm7_0_enable}")
        result.append(f"  Boot Sequence: {'Secure Boot' if self.boot_seq else 'Non-Secure Boot'}")
        result.append(f"  APP SWT Init: {self.app_swt_init}")

        return "\n".join(result)

    def get_config(self) -> Config:
        """Get configuration of the boot config.

        :return: Configuration dictionary
        """
        return Config(
            {
                "cm7_0Enable": self.cm7_0_enable,
                "bootSeq": self.boot_seq,
                "appSwtInit": self.app_swt_init,
            }
        )


class Ivt:
    """HSE Image Vector Table class."""

    FORMAT = "<IIIIIIIIIIIII204s"
    SIZE = struct.calcsize(FORMAT)
    DEFAULT_IVT_MARKER = 0x5AA55AA5

    def __init__(self, family: FamilyRevision) -> None:
        """Initialize HSE IVT.

        :param family: Family revision
        """
        self.family = family
        self._ivt_marker = self.DEFAULT_IVT_MARKER
        self.boot_config = BootConfig()
        self.app_start_addr = 0x0
        self.lc_config_addr = 0x0
        self.hse_fw_addr = 0x0
        self.app_boot_header_addr = 0x0
        self.authentication_tag = bytes()

    def __len__(self) -> int:
        """Calculate the length of the IVT.

        :return: Length of the IVT in bytes
        """
        return struct.calcsize(self.FORMAT)

    def __str__(self) -> str:
        """Return string representation of HSE IVT.

        :return: String representation
        """
        result = ["HSE Image Vector Table:"]
        result.append(f"  IVT Marker: 0x{self._ivt_marker:08X}")
        result.append(str(self.boot_config))
        result.append(f"  Start Address: 0x{self.app_start_addr:08X}")
        result.append(f"  LC Config Address: 0x{self.lc_config_addr:08X}")
        result.append(f"  HSE FW Address: 0x{self.hse_fw_addr:08X}")
        result.append(f"  App Boot Header Address: 0x{self.app_boot_header_addr:08X}")
        if self.authentication_tag:
            result.append(f"  Authentication Tag: {self.authentication_tag.hex()}")
        return "\n".join(result)

    def __repr__(self) -> str:
        """Return representation of HSE IVT.

        :return: Object representation
        """
        return (
            f"Ivt(marker=0x{self._ivt_marker:08X}, "
            f"boot_config={self.boot_config.value}, "
            f"cm7_0_app_start=0x{self.app_start_addr:08X}, "
            f"lc_config_addr=0x{self.lc_config_addr:08X}, "
            f"hse_fw_addr=0x{self.hse_fw_addr:08X}, "
            f"app_boot_header_addr=0x{self.app_boot_header_addr:08X})"
        )

    @property
    def is_signed(self) -> bool:
        """Check if the image is signed.

        :return: True if the image is signed (secure boot), False otherwise
        """
        return self.boot_config.boot_seq

    def verify(self) -> Verifier:
        """Verifier object data."""
        ret = Verifier("HSE IVT verification")
        if self._ivt_marker != self.DEFAULT_IVT_MARKER:
            ret.add_record(
                name="IVT marker",
                result=VerifierResult.ERROR,
                value=f"Wrong IVT marker: {hex(self._ivt_marker)}, expected {hex(self.DEFAULT_IVT_MARKER)}",
            )
        return ret

    def export(self) -> bytes:
        """Export IVT as bytes.

        :return: Binary representation of IVT
        """
        # Pack all IVT fields in one go
        return struct.pack(
            self.FORMAT,
            self._ivt_marker,
            self.boot_config.value,
            0,  # reserved0
            self.app_start_addr,
            0,  # reserved1
            0,  # reserved2
            0,  # reserved3
            0,  # reserved4
            0,  # reserved5
            self.lc_config_addr,
            0,  # reserved6
            self.hse_fw_addr,
            self.app_boot_header_addr,
            bytes(204),  # reserved7
        )

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision = FamilyRevision("Unknown")) -> Self:
        """Parse binary data into HSE IVT object.

        :param data: Binary data to parse
        :param family: Family revision
        :return: Initialized HSE IVT object
        :raises SPSDKValueError: If IVT marker is invalid
        """
        ivt = cls(family)

        (
            ivt._ivt_marker,
            boot_config_value,
            _,  # reserved0
            ivt.app_start_addr,
            _,  # reserved1
            _,  # reserved2
            _,  # reserved3
            _,  # reserved4
            _,  # reserved5
            ivt.lc_config_addr,
            _,  # reserved6
            ivt.hse_fw_addr,
            ivt.app_boot_header_addr,
            _,  # reserved7
        ) = struct.unpack_from(cls.FORMAT, data)

        # Validate IVT marker
        ivt.verify().validate()

        # Parse boot config
        ivt.boot_config = BootConfig(boot_config_value)

        return ivt

    @property
    def start_address(self) -> int:
        """Get the start address for the HSE image.

        Determines the appropriate start address based on the application start address
        and the possible start addresses defined in the database for the family.

        :return: The start address for the HSE image
        :raises SPSDKError: If no suitable start address can be found
        """
        blocks = get_db(self.family).device.info.memory_map.find_memory_blocks()
        start_addresses = [block.base_address for block in blocks]
        start_addresses.sort(reverse=True)
        for start_addr in start_addresses:
            if self.app_start_addr > start_addr:
                return start_addr
        raise SPSDKError("No start address could be found.")

    @property
    def app_offset(self) -> int:
        """Get the offset of the application within the HSE image.

        This property calculates the relative offset of the application from the start address.

        :return: Offset of the application in bytes
        """
        return self.app_start_addr - self.start_address

    @property
    def app_boot_header_offset(self) -> Optional[int]:
        """Get the offset of the application boot header within the HSE image.

        This property calculates the relative offset of the application boot header from the start address.
        If the application boot header address is not set, returns None.

        :return: Offset of the application boot header in bytes, or None if not set
        """
        if not self.app_boot_header_addr:
            return None
        return self.app_boot_header_addr - self.start_address

    @property
    def lifecycle_config_offset(self) -> Optional[int]:
        """Get the offset of the lifecycle configuration within the HSE image.

        This property calculates the relative offset of the lifecycle configuration from the start address.
        If the lifecycle configuration address is not set, returns None.

        :return: Offset of the lifecycle configuration in bytes, or None if not set
        """
        if not self.lc_config_addr:
            return None
        return self.lc_config_addr - self.start_address


class Mbi_MixinHseIvt(Mbi_Mixin):
    """Master Boot Image Image Vector table class for HSE."""

    IVT_IMAGE_NAME = "HSE Image Vector Table"
    VALIDATION_SCHEMAS: list[str] = ["hse_ivt"]
    NEEDED_MEMBERS: dict[str, Any] = {"hse_ivt": None}

    ivt: Ivt

    def mix_len(self) -> int:
        """Compute length of individual mixin.

        :return: Length of atomic Mixin.
        """
        return len(self.ivt)

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration of mixin from dictionary.

        :param config: Dictionary with configuration fields.
        """
        boot_cfg = BootConfig()
        is_signed = config.get_str("outputImageAuthenticationType") == "signed"
        boot_cfg.boot_seq = is_signed
        self.ivt = Ivt(family=FamilyRevision.load_from_config(config))
        self.ivt.boot_config = boot_cfg
        self.ivt.app_start_addr = config.get_int("appStartAddress", 0)
        self.ivt.lc_config_addr = config.get_int("lcConfigAddr", 0)
        self.ivt.hse_fw_addr = config.get_int("hseFwAddr", 0)
        self.ivt.app_boot_header_addr = (
            self.ivt.app_start_addr - AppBootHeader.ALIGNMENT if is_signed else 0
        )

    def mix_validate(self) -> None:
        """Validate the setting of image."""
        self.ivt.verify().validate()

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        self.ivt = Ivt.parse(data, self.family)

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        cfg = Config({"appStartAddress": hex(self.ivt.app_start_addr)})
        if self.ivt.lc_config_addr:
            cfg["lcConfigAddr"] = hex(self.ivt.lc_config_addr)
        if self.ivt.hse_fw_addr:
            cfg["hseFwAddr"] = hex(self.ivt.hse_fw_addr)
        return cfg

    def export(self) -> bytes:
        """Export IVT as bytes.

        :return: Binary representation of IVT
        """
        return self.ivt.export()

    @classmethod
    def get_image_type(cls, data: bytes) -> int:
        """Get image type from raw data."""
        if Ivt.parse(data).boot_config.boot_seq:
            return 4
        return 0


class AppBootHeader:
    """HSE Application Boot Header class."""

    class CoreId(SpsdkEnum):
        """Core ID enumeration for HSE."""

        CORE_CM7_0 = (0x00, "cm7_0", "CM7 0 core")

    # Format string for struct packing/unpacking
    FORMAT = "<BBBBIIII11I"
    TAG = 0xD5
    VERSION = 0x60
    SIZE = struct.calcsize(FORMAT)
    ALIGNMENT = 0x40

    def __init__(self, family: FamilyRevision) -> None:
        """Initialize HSE Application Boot Header."""
        self.family = family
        self._tag = self.TAG
        self._version = self.VERSION
        self.start_address: int = 0
        self.app_size: int = 0
        self.core_id = self.CoreId.CORE_CM7_0

    def verify(self) -> Verifier:
        """Verifier object data."""
        ret = Verifier("HSE IVT verification")
        if self._tag != self.TAG:
            ret.add_record(
                name="Header marker",
                result=VerifierResult.ERROR,
                value=f"Invalid AppBL Header tag: 0x{self._tag:02X}, expected {self.TAG:02X}",
            )
        if self._version != self.VERSION:
            ret.add_record(
                name="Version",
                result=VerifierResult.ERROR,
                value=f"Unsupported AppBL Header version: 0x{self._version:02X}",
            )
        return ret

    def export(self) -> bytes:
        """Export Application Boot Header as bytes.

        :return: Binary representation of AppBL Header
        """
        header = struct.pack(
            self.FORMAT,
            self._tag,
            0,  # reserved
            0,  # reserved
            self._version,
            0,  # reserved
            self.start_address,
            self.app_size,
            self.core_id.tag,
            *([0] * 11),  # reserved
        )
        return extend_block(header, self.ALIGNMENT)

    @property
    def size(self) -> int:
        """Get the size of the Application Boot Header.

        :return: Size of the Application Boot Header in bytes
        """
        return len(self.export())

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision = FamilyRevision("Unknown")) -> Self:
        """Parse binary data into HSE Application Boot Header object.

        :param data: Binary data to parse
        :param family: Family revision
        :return: Initialized HSE Application Boot Header object
        :raises SPSDKValueError: If tag or version is invalid
        """
        header = cls(family)
        (
            header._tag,
            _,  # reserved
            _,  # reserved
            header._version,
            _,  # reserved
            header.start_address,
            header.app_size,
            core_id,
            *_,  # reserved
        ) = struct.unpack_from(cls.FORMAT, data)

        header.core_id = cls.CoreId.from_tag(core_id)
        header.verify().validate()

        return header


class Mbi_MixinHseAppBootHeader(Mbi_Mixin):
    """Master Boot Image Application Boot Header class."""

    APP_BOOT_HEADER_IMAGE_NAME = "Boot Header"
    VALIDATION_SCHEMAS: list[str] = ["hse_app_boot_header"]
    NEEDED_MEMBERS: dict[str, Any] = {"hse_app_boot_header": None}

    ivt: Ivt
    hse_app_boot_header: AppBootHeader
    app: Optional[bytes]

    def mix_len(self) -> int:
        """Compute length of individual mixin.

        :return: Length of atomic Mixin.
        """
        return self.hse_app_boot_header.size if self.hse_app_boot_header else 0

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration of mixin from dictionary.

        :param config: Dictionary with configuration fields.
        """
        if not config.get_str("outputImageAuthenticationType") == "signed":
            return
        self.hse_app_boot_header = AppBootHeader(FamilyRevision.load_from_config(config))
        self.hse_app_boot_header.app_size = len(
            align_block(
                BinaryImage.load_binary_image(
                    (config.get_input_file_name("inputImageFile"))
                ).export()
            )
        )
        self.hse_app_boot_header.start_address = config.get_int("appStartAddress")

    def mix_validate(self) -> None:
        """Validate the setting of image."""
        if self.hse_app_boot_header:
            self.hse_app_boot_header.verify().validate()

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        if not self.ivt.app_boot_header_offset:
            return
        self.hse_app_boot_header = AppBootHeader.parse(
            data[self.ivt.app_boot_header_offset :], self.family
        )

    def export(self) -> bytes:
        """Export AppBL Header as bytes.

        :return: Binary representation of AppBL Header
        """
        if not self.hse_app_boot_header:
            return b""
        return self.hse_app_boot_header.export()


class Mbi_ExportMixinHseSignature(Mbi_Mixin):
    """Master Boot Image HSE Signature Mixin class."""

    VALIDATION_SCHEMAS: list[str] = ["hse_signature"]
    GMAC_SIZE: int = 16
    IV_SIZE: int = 12
    SIGNATURE_SIZE = IV_SIZE + GMAC_SIZE

    adkp: Optional[bytes]
    initial_vector: bytes
    app: Optional[bytes]
    ivt: Ivt
    hse_app_boot_header: AppBootHeader

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        self.adkp = config.load_symmetric_key("adkp", expected_size=self.GMAC_SIZE)
        self.initial_vector = (
            config.load_symmetric_key("initialVector", expected_size=self.IV_SIZE)
            if "initialVector" in config
            else random_bytes(self.IV_SIZE)
        )

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        if not self.ivt.is_signed:
            return
        offset = self.ivt.app_offset + self.hse_app_boot_header.app_size
        self.adkp = None
        self.initial_vector = data[offset : offset + self.IV_SIZE]

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        return {
            "adkp": self.adkp.hex() if self.adkp else "Unknown",
            "initialVector": self.initial_vector.hex() if self.initial_vector else "Unknown",
        }


class Mbi_ExportMixinHseApp(Mbi_ExportMixin):
    """Export Mixin to handle simple application data."""

    APP_BLOCK_NAME = "Application Block"
    APP_IMAGE_NAME = "Application"

    app: Optional[bytes]
    ivt: Ivt
    hse_app_boot_header: AppBootHeader
    lifecycle: Optional["Mbi_MixinHseLifecycle.LifecycleState"]

    def collect_data(self) -> BinaryImage:
        """Collect application data."""
        if not self.app:
            raise SPSDKError("Application data is missing")
        ret = BinaryImage(name=self.APP_BLOCK_NAME)
        ret.append_image(BinaryImage(name=Mbi_MixinHseIvt.IVT_IMAGE_NAME, binary=self.ivt.export()))
        if self.ivt.app_boot_header_offset:
            ret.add_image(
                BinaryImage(
                    name=Mbi_MixinHseAppBootHeader.APP_BOOT_HEADER_IMAGE_NAME,
                    binary=self.hse_app_boot_header.export(),
                    offset=self.ivt.app_boot_header_offset,
                )
            )
        ret.add_image(
            BinaryImage(
                name=self.APP_IMAGE_NAME,
                binary=self.app,
                offset=self.ivt.app_offset,
            )
        )
        if self.lifecycle:
            if self.ivt.lifecycle_config_offset:
                lc_offset = self.ivt.lifecycle_config_offset
            else:

                lc_offset = len(ret)
                if self.ivt.is_signed:
                    lc_offset += Mbi_ExportMixinHseSignature.SIGNATURE_SIZE
                lc_config_addr = self.ivt.start_address + lc_offset
                self.ivt.lc_config_addr = lc_config_addr
                logger.info(
                    f"Lifecycle address {lc_config_addr:08X} was calculated. The IVT was updated."
                )
                ret.find_sub_image(Mbi_MixinHseIvt.IVT_IMAGE_NAME).binary = self.ivt.export()
            ret.add_image(
                BinaryImage(
                    name="Lifecycle",
                    binary=self.lifecycle.tag.to_bytes(
                        Mbi_MixinHseLifecycle.LC_VALUE_LENGTH, Endianness.LITTLE.value
                    ),
                    offset=lc_offset,
                )
            )

        return ret

    def disassemble_image(self, image: bytes) -> None:  # pylint: disable=no-self-use
        """Disassemble image to individual parts from image.

        :param image: Image.
        """
        end_offset = None
        if hasattr(self, "hse_app_boot_header"):
            end_offset = self.ivt.app_offset + self.hse_app_boot_header.app_size
        elif self.ivt.lc_config_addr:
            end_offset = self.ivt.lc_config_addr - self.ivt.start_address
        self.app = image[self.ivt.app_offset : end_offset]


class Mbi_ExportMixinHseAppSigned(Mbi_ExportMixinHseApp):
    """Export Mixin to handle signed application data."""

    adkp: Optional[bytes]
    initial_vector: Optional[bytes]

    def sign(self, image: BinaryImage, revert: bool = False) -> BinaryImage:
        """Do calculation of signature and return updated image with it.

        :param image: Input raw image.
        :param revert: Revert the operation if possible.
        :return: Image enriched by signature at end of image.
        """
        if revert:
            return image
        if not self.adkp:
            raise SPSDKError("Application Debug/Key Password is missing")
        if not self.initial_vector:
            raise SPSDKError("Initial vector is missing")
        if not self.app:
            raise SPSDKError("Application data is missing")
        adkp_hash = get_hash(self.adkp)
        data_to_sign = self.hse_app_boot_header.export() + self.app + self.initial_vector
        encrypted_data = aes_gcm_encrypt(
            key=adkp_hash,
            plain_data=b"",
            init_vector=self.initial_vector,
            associated_data=data_to_sign,
        )
        auth_tag = encrypted_data[-16:]
        app_img = image.find_sub_image(self.APP_IMAGE_NAME)
        image.add_image(
            BinaryImage(
                name="Authentication Tag",
                binary=self.initial_vector + auth_tag,
                offset=app_img.offset + len(app_img),
            )
        )
        return image


class Mbi_MixinHseLifecycle(Mbi_Mixin):
    """Master Boot Image Lifecycle class."""

    class LifecycleState(SpsdkEnum):
        """Lifecycle state enum."""

        NONE = (0x0, "none", "Do not advance Lifecycle")
        OEM_PROD = (0xDADA_DADA, "oem_prod", "OEM Production Lifecycle")
        IN_FIELD = (0xBABA_BABA, "in_field", "In field Lifecycle")

    APP_BOOT_HEADER_IMAGE_NAME = "Lifecycle"
    VALIDATION_SCHEMAS: list[str] = ["hse_lifecycle"]
    NEEDED_MEMBERS: dict[str, Any] = {"lifecycle": None}
    LC_VALUE_LENGTH = 4

    ivt: Ivt
    app: bytes
    lifecycle: Optional[LifecycleState]

    def mix_len(self) -> int:
        """Compute length of individual mixin.

        :return: Length of atomic Mixin.
        """
        return self.LC_VALUE_LENGTH if self.lifecycle else 0

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration of mixin from dictionary.

        :param config: Dictionary with configuration fields.
        """
        if "lifecycle" in config:
            try:
                self.lifecycle = self.LifecycleState.from_label(config["lifecycle"])
            except SPSDKError as exc:
                raise SPSDKError(f"Invalid lifecycle state: {config['lifecycle']}") from exc
        else:
            if self.ivt.lc_config_addr:
                logger.warning(
                    "Lifecycle configuration address is set, but no lifecycle state provided."
                )

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        if not self.ivt.lc_config_addr:
            return
        lc_offset = self.ivt.lc_config_addr - self.ivt.start_address
        lc_value = int.from_bytes(
            data[lc_offset : lc_offset + self.LC_VALUE_LENGTH], byteorder="little"
        )
        if lc_value not in self.LifecycleState.tags():
            logger.warning(f"Unknown lifecycle state: {lc_value}")
            return
        self.lifecycle = self.LifecycleState.from_tag(lc_value)

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        lc = self.lifecycle.label if self.lifecycle else self.LifecycleState.NONE.label
        return Config({"lifecycle": lc})


class Mbi_MixinHseApp(Mbi_MixinApp):
    """Master Boot Image App class for HSE application."""

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        super().mix_load_from_config(config)
        # For HSE application with or without boot header(IVT) is allowed on the input
        try:
            ivt = Ivt.parse(self.app, family=self.family)
            if len(self.app) <= ivt.app_offset:
                logger.warning("Invalid app_offset in IVT header: offset is larger than image size")
                return

            self.app = self.app[ivt.app_offset :]
            logger.warning(
                "The input image contains IVT header. The header will be removed and "
                "replaced by values from the configuration file."
            )
        except SPSDKVerificationError:
            logger.debug("No IVT header detected in input image, using raw application data")
            return
