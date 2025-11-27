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
    """Boot Configuration for HSE IVT.

    This class manages boot configuration settings for HSE (Hardware Security Engine)
    Initial Vector Table, providing bitfield manipulation for various boot parameters
    including CM7 core enable, boot sequence, and application software timer initialization.

    :cvar CM7_0_ENABLE_BIT: Bit position for CM7 core 0 enable flag.
    :cvar BOOT_SEQ_BIT: Bit position for boot sequence configuration.
    :cvar APP_SWT_INIT_BIT: Bit position for application software timer initialization.
    """

    # Bit positions for Boot Configuration
    CM7_0_ENABLE_BIT = 0
    BOOT_SEQ_BIT = 3
    APP_SWT_INIT_BIT = 5

    def __init__(self, value: int = 0) -> None:
        """Initialize Boot Configuration.

        :param value: Initial boot config value, defaults to 0.
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

        Calculates the boot configuration value by combining bit fields for CM7_0 enable,
        boot sequence, and application SWT initialization settings.

        :return: Boot config value as integer.
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

        This method updates the internal boot configuration value and automatically
        updates the corresponding bitfield properties (cm7_0_enable, boot_seq,
        app_swt_init) based on the bit positions defined in the class constants.

        :param value: Boot configuration value as integer bitmask.
        """
        self._value = value
        # Update bit fields from value
        self.cm7_0_enable = bool(value & (1 << self.CM7_0_ENABLE_BIT))
        self.boot_seq = bool(value & (1 << self.BOOT_SEQ_BIT))
        self.app_swt_init = bool(value & (1 << self.APP_SWT_INIT_BIT))

    def __str__(self) -> str:
        """Return string representation of Boot Config.

        Provides a formatted multi-line string showing the boot configuration value
        and its individual field interpretations including CM7_0 enable status,
        boot sequence type, and APP SWT initialization setting.

        :return: Multi-line string representation of the boot configuration.
        """
        result = [f"Boot Config: 0x{self.value:08X}"]
        result.append(f"  CM7_0 Enable: {self.cm7_0_enable}")
        result.append(f"  Boot Sequence: {'Secure Boot' if self.boot_seq else 'Non-Secure Boot'}")
        result.append(f"  APP SWT Init: {self.app_swt_init}")

        return "\n".join(result)

    def get_config(self) -> Config:
        """Get configuration of the boot config.

        This method creates a configuration dictionary containing the current boot configuration
        settings including CM7 core enable status, boot sequence, and application SWT initialization.

        :return: Configuration dictionary with boot settings.
        """
        return Config(
            {
                "cm7_0Enable": self.cm7_0_enable,
                "bootSeq": self.boot_seq,
                "appSwtInit": self.app_swt_init,
            }
        )


class Ivt:
    """HSE Image Vector Table representation for NXP MCU secure boot.

    This class manages the Image Vector Table (IVT) structure used in HSE (Hardware Security Engine)
    based secure boot process. It handles creation, parsing, and validation of IVT data including
    boot configuration, memory addresses, and authentication information.

    :cvar FORMAT: Binary format string for IVT structure packing/unpacking.
    :cvar SIZE: Size of the IVT structure in bytes.
    :cvar DEFAULT_IVT_MARKER: Default marker value identifying valid IVT structure.
    """

    FORMAT = "<IIIIIIIIIIIII204s"
    SIZE = struct.calcsize(FORMAT)
    DEFAULT_IVT_MARKER = 0x5AA55AA5

    def __init__(self, family: FamilyRevision) -> None:
        """Initialize HSE IVT.

        Initializes the HSE (Hardware Security Engine) Image Vector Table with default
        values and configuration structures for the specified family revision.

        :param family: The target MCU family revision for HSE configuration.
        """
        self.family = family
        self._ivt_marker = self.DEFAULT_IVT_MARKER
        self.boot_config = BootConfig()
        self.app_start_addr: Optional[int] = None
        self.lc_config_addr: Optional[int] = None
        self.hse_fw_addr: Optional[int] = None
        self.app_boot_header_addr: Optional[int] = None
        self.authentication_tag = bytes()

    def __len__(self) -> int:
        """Calculate the length of the IVT.

        :return: Length of the IVT in bytes.
        """
        return struct.calcsize(self.FORMAT)

    def __str__(self) -> str:
        """Return string representation of HSE IVT.

        Creates a formatted string containing all HSE Image Vector Table information including
        IVT marker, boot configuration, memory addresses, and authentication tag if present.

        :return: Multi-line string representation of the HSE IVT structure.
        """
        result = ["HSE Image Vector Table:"]
        result.append(f"  IVT Marker: 0x{self._ivt_marker:08X}")
        result.append(str(self.boot_config))
        result.append(f"  Start Address: 0x{(self.app_start_addr or 0x0):08X}")
        result.append(f"  LC Config Address: 0x{(self.lc_config_addr or 0x0):08X}")
        result.append(f"  HSE FW Address: 0x{(self.hse_fw_addr or 0x0):08X}")
        result.append(f"  App Boot Header Address: 0x{(self.app_boot_header_addr or 0x0):08X}")
        if self.authentication_tag:
            result.append(f"  Authentication Tag: {self.authentication_tag.hex()}")
        return "\n".join(result)

    def __repr__(self) -> str:
        """Return representation of HSE IVT.

        Creates a formatted string representation of the HSE Image Vector Table (IVT) containing
        all key configuration addresses and boot settings for debugging and logging purposes.

        :return: Formatted string with IVT marker, boot config, and memory addresses.
        """
        return (
            f"Ivt(marker=0x{self._ivt_marker:08X}, "
            f"boot_config={self.boot_config.value}, "
            f"cm7_0_app_start=0x{(self.app_start_addr or 0x0):08X}, "
            f"lc_config_addr=0x{(self.lc_config_addr or 0x0):08X}, "
            f"hse_fw_addr=0x{(self.hse_fw_addr or 0x0):08X}, "
            f"app_boot_header_addr=0x{(self.app_boot_header_addr or 0x0):08X})"
        )

    @property
    def is_signed(self) -> bool:
        """Check if the image is signed.

        The method determines whether the image has secure boot enabled by checking
        the boot sequence configuration.

        :return: True if the image is signed (secure boot), False otherwise.
        """
        return self.boot_config.boot_seq

    def verify(self) -> Verifier:
        """Verify HSE IVT (Image Vector Table) data integrity.

        The method validates the IVT marker against the expected default value and
        creates a verification report with detailed results including any errors
        found during validation.

        :return: Verifier object containing validation results and records.
        """
        ret = Verifier("HSE IVT verification")
        if self._ivt_marker != self.DEFAULT_IVT_MARKER:
            ret.add_record(
                name="IVT marker",
                result=VerifierResult.ERROR,
                value=f"Wrong IVT marker: {hex(self._ivt_marker)}, expected {hex(self.DEFAULT_IVT_MARKER)}",
            )
        ret.add_record_range(name="Application Start Address", value=self.app_start_addr)
        return ret

    def export(self) -> bytes:
        """Export IVT as bytes.

        Packs all IVT (Image Vector Table) fields into binary format using the predefined
        structure format. The method serializes boot configuration, addresses, and reserved
        fields into a byte sequence suitable for HSE firmware processing.

        :return: Binary representation of IVT structure.
        """
        # Pack all IVT fields in one go
        return struct.pack(
            self.FORMAT,
            self._ivt_marker,
            self.boot_config.value,
            0,  # reserved0
            self.app_start_addr or 0x0,
            0,  # reserved1
            0,  # reserved2
            0,  # reserved3
            0,  # reserved4
            0,  # reserved5
            self.lc_config_addr or 0x0,
            0,  # reserved6
            self.hse_fw_addr or 0x0,
            self.app_boot_header_addr or 0x0,
            bytes(204),  # reserved7
        )

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision = FamilyRevision("Unknown")) -> Self:
        """Parse binary data into HSE IVT object.

        The method unpacks binary data using the class format and validates the IVT marker
        to ensure data integrity before creating the HSE IVT object instance.

        :param data: Binary data to parse into HSE IVT structure.
        :param family: Family revision information for the target device.
        :return: Initialized HSE IVT object with parsed data.
        :raises SPSDKValueError: If IVT marker is invalid during validation.
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
        The method finds the highest memory block base address that is lower than
        the application start address.

        :return: The start address for the HSE image.
        :raises SPSDKError: If application start address is not set or no suitable start address found.
        """
        if self.app_start_addr is None:
            raise SPSDKError("Application start address is not set.")
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

        :raises SPSDKError: Application start address is not set.
        :return: Offset of the application in bytes.
        """
        if self.app_start_addr is None:
            raise SPSDKError("Application start address is not set.")
        return self.app_start_addr - self.start_address

    @property
    def app_boot_header_offset(self) -> Optional[int]:
        """Get the offset of the application boot header within the HSE image.

        This property calculates the relative offset of the application boot header from the start
        address. If the application boot header address is not set, returns None.

        :return: Offset of the application boot header in bytes, or None if not set.
        """
        if not self.app_boot_header_addr:
            return None
        return self.app_boot_header_addr - self.start_address

    @property
    def lc_config_offset(self) -> Optional[int]:
        """Get the offset of the lifecycle configuration within the HSE image.

        This property calculates the relative offset of the lifecycle configuration from the start
        address. If the lifecycle configuration address is not set, returns None.

        :return: Offset of the lifecycle configuration in bytes, or None if not set.
        """
        if not self.lc_config_addr:
            return None
        return self.lc_config_addr - self.start_address


class Mbi_MixinHseIvt(Mbi_Mixin):
    """Master Boot Image mixin for HSE Image Vector Table management.

    This mixin handles the creation, configuration, and processing of Image Vector
    Tables (IVT) specifically for HSE (Hardware Security Engine) enabled devices.
    It manages boot configuration, application start addresses, and HSE firmware
    addresses within the Master Boot Image structure.

    :cvar IVT_IMAGE_NAME: Human-readable name for the HSE IVT image type.
    :cvar VALIDATION_SCHEMAS: List of validation schemas used for configuration.
    :cvar NEEDED_MEMBERS: Required member variables for proper mixin operation.
    """

    IVT_IMAGE_NAME = "HSE Image Vector Table"
    VALIDATION_SCHEMAS: list[str] = ["hse_ivt"]
    NEEDED_MEMBERS: dict[str, Any] = {"ivt": None}

    ivt: Ivt

    def mix_len(self) -> int:
        """Compute length of individual mixin.

        The method returns the length of the IVT (Image Vector Table) which represents
        the size of this atomic mixin component.

        :return: Length of atomic mixin in bytes.
        """
        return len(self.ivt)

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration of HSE mixin from configuration object.

        The method initializes the IVT (Image Vector Table) with boot configuration,
        sets authentication type based on output image type, and configures various
        address fields including application start, LC config, and HSE firmware addresses.

        :param config: Configuration object containing HSE-specific fields and addresses.
        """
        boot_cfg = BootConfig()
        is_signed = config.get_str("outputImageAuthenticationType").lower() == "signed"
        boot_cfg.boot_seq = is_signed
        self.ivt = Ivt(family=FamilyRevision.load_from_config(config))
        self.ivt.boot_config = boot_cfg
        if "appStartAddress" in config:
            self.ivt.app_start_addr = config.get_int("appStartAddress")
        if "lcConfigAddr" in config:
            self.ivt.lc_config_addr = config.get_int("lcConfigAddr")
        if "hseFwAddr" in config:
            self.ivt.hse_fw_addr = config.get_int("hseFwAddr")
        # boot header address is set automatically as it is is located right in front of application
        if self.ivt.is_signed and self.ivt.app_start_addr is not None:
            self.ivt.app_boot_header_addr = self.ivt.app_start_addr - AppBootHeader.ALIGNMENT

    def mix_validate(self) -> None:
        """Validate the setting of image.

        This method performs validation of the image settings by verifying and validating
        the Image Vector Table (IVT) component.

        :raises SPSDKError: If the IVT validation fails.
        """
        self.ivt.verify().validate()

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary data to extract individual fields.

        This method parses the provided binary data and extracts the IVT (Image Vector Table)
        structure specific to the device family.

        :param data: Binary data representing the final image to be parsed.
        :raises SPSDKParsingError: If the binary data cannot be parsed or is invalid.
        """
        self.ivt = Ivt.parse(data, self.family)

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        Extracts configuration parameters from the IVT (Image Vector Table) including
        application start address, lifecycle configuration address, and HSE firmware address.

        :param output_folder: Output folder to store files.
        :return: Dictionary containing the mixin configuration with hex-formatted addresses.
        """
        cfg = Config({})
        if self.ivt.app_start_addr is not None:
            cfg["appStartAddress"] = hex(self.ivt.app_start_addr)
        if self.ivt.lc_config_addr:
            cfg["lcConfigAddr"] = hex(self.ivt.lc_config_addr)
        if self.ivt.hse_fw_addr:
            cfg["hseFwAddr"] = hex(self.ivt.hse_fw_addr)
        return cfg

    def export(self) -> bytes:
        """Export IVT as bytes.

        :return: Binary representation of IVT.
        """
        return self.ivt.export()

    @classmethod
    def get_image_type(cls, data: bytes) -> int:
        """Get image type from raw data.

        Determines the image type by parsing the IVT (Image Vector Table) and checking
        the boot sequence configuration.

        :param data: Raw binary data containing the image.
        :return: Image type identifier (4 if boot sequence is enabled, 0 otherwise).
        """
        if Ivt.parse(data).boot_config.boot_seq:
            return 4
        return 0


class AppBootHeader:
    """HSE Application Boot Header for NXP MCU secure boot process.

    This class represents the Application Boot Header used in HSE (Hardware Security Engine)
    enabled devices. It manages the boot header structure that contains essential information
    for application loading including start address, size, and core identification.

    :cvar FORMAT: Struct format string for binary packing/unpacking operations.
    :cvar TAG: Header identification tag (0xD5).
    :cvar VERSION: Supported header version (0x60).
    :cvar SIZE: Total size of the header structure in bytes.
    :cvar ALIGNMENT: Required memory alignment for the header.
    """

    class CoreId(SpsdkEnum):
        """Core ID enumeration for HSE operations.

        This enumeration defines the available processor cores that can be targeted
        for HSE (Hardware Security Engine) operations in NXP MCUs.
        """

        CORE_CM7_0 = (0x00, "cm7_0", "CM7 0 core")

    # Format string for struct packing/unpacking
    FORMAT = "<BBBBIIII11I"
    TAG = 0xD5
    VERSION = 0x60
    SIZE = struct.calcsize(FORMAT)
    ALIGNMENT = 0x40

    def __init__(self, family: FamilyRevision) -> None:
        """Initialize HSE Application Boot Header.

        Creates a new HSE Application Boot Header instance with default values
        for start address, application size, and core ID configuration.

        :param family: Family and revision specification for the target device.
        """
        self.family = family
        self._tag = self.TAG
        self._version = self.VERSION
        self.start_address: int = 0
        self.app_size: int = 0
        self.core_id = self.CoreId.CORE_CM7_0

    def verify(self) -> Verifier:
        """Verify HSE IVT header integrity.

        Validates the header tag and version fields against expected values and creates
        a verification report with any found issues.

        :return: Verifier object containing validation results for header fields.
        """
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

        The method packs the header data using the defined format structure and extends
        it to proper alignment boundary.

        :return: Binary representation of AppBL Header with proper alignment.
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

        :return: Size of the Application Boot Header in bytes.
        """
        return len(self.export())

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision = FamilyRevision("Unknown")) -> Self:
        """Parse binary data into HSE Application Boot Header object.

        This method deserializes binary data according to the HSE Application Boot Header format,
        extracting fields like tag, version, start address, application size, and core ID.

        :param data: Binary data to parse into HSE Application Boot Header format.
        :param family: Family revision information for the target MCU family.
        :return: Initialized HSE Application Boot Header object with parsed data.
        :raises SPSDKValueError: If tag or version is invalid during parsing or validation.
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
    """Master Boot Image HSE Application Boot Header mixin.

    This mixin handles HSE (Hardware Security Engine) application boot header
    functionality for Master Boot Images, including configuration loading,
    validation, and binary parsing of signed image authentication.

    :cvar APP_BOOT_HEADER_IMAGE_NAME: Display name for boot header image.
    :cvar VALIDATION_SCHEMAS: List of validation schemas for HSE app boot header.
    :cvar NEEDED_MEMBERS: Required member dictionary for HSE app boot header.
    """

    APP_BOOT_HEADER_IMAGE_NAME = "Boot Header"
    VALIDATION_SCHEMAS: list[str] = ["hse_app_boot_header"]
    NEEDED_MEMBERS: dict[str, Any] = {"hse_app_boot_header": None}

    ivt: Ivt
    hse_app_boot_header: AppBootHeader
    app: Optional[bytes]

    def mix_len(self) -> int:
        """Compute length of individual HSE mixin.

        The method calculates the size of the HSE application boot header if it exists,
        otherwise returns 0 for cases where no HSE boot header is configured.

        :return: Length of HSE atomic mixin in bytes, or 0 if no HSE boot header exists.
        """
        return self.hse_app_boot_header.size if self.hse_app_boot_header else 0

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration of HSE mixin from configuration object.

        This method processes the configuration to set up HSE (Hardware Security Engine)
        application boot header when the output image authentication type is set to "signed".
        It calculates the application size from the input binary image and sets the start
        address from the configuration.

        :param config: Configuration object containing HSE-specific fields including
                       outputImageAuthenticationType, inputImageFile, and appStartAddress.
        """
        if not config.get_str("outputImageAuthenticationType").lower() == "signed":
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
        """Validate the HSE application boot header settings.

        Performs validation of the HSE (Hardware Security Engine) application boot header
        if it exists. The validation includes both verification and validation steps to ensure
        the header configuration is correct and complete.

        :raises SPSDKError: If HSE application boot header validation fails.
        """
        if self.hse_app_boot_header:
            self.hse_app_boot_header.verify().validate()

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary data to extract HSE application boot header fields.

        The method extracts the HSE application boot header from the provided binary data
        if the IVT contains a valid app_boot_header_offset. If no offset is present,
        the method returns without performing any parsing operations.

        :param data: Binary image data containing the HSE application boot header.
        """
        if not self.ivt.app_boot_header_offset:
            return
        self.hse_app_boot_header = AppBootHeader.parse(
            data[self.ivt.app_boot_header_offset :], self.family
        )

    def export(self) -> bytes:
        """Export AppBL Header as bytes.

        The method exports the HSE application boot header if it exists, otherwise returns empty bytes.

        :return: Binary representation of AppBL Header, or empty bytes if header doesn't exist.
        """
        if not self.hse_app_boot_header:
            return b""
        return self.hse_app_boot_header.export()


class Mbi_ExportMixinHseSignature(Mbi_Mixin):
    """Master Boot Image HSE Signature Mixin class.

    This mixin provides HSE (Hardware Security Engine) signature functionality for Master Boot
    Images, handling ADKP (Application Debug Key Provisioning) keys, initialization vectors,
    and GMAC-based authentication for secure boot operations.

    :cvar VALIDATION_SCHEMAS: Configuration validation schemas for HSE signature.
    :cvar GMAC_SIZE: Size of GMAC authentication tag in bytes.
    :cvar IV_SIZE: Size of initialization vector in bytes.
    :cvar SIGNATURE_SIZE: Total signature size combining IV and GMAC.
    """

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

        This method loads HSE-specific configuration including ADKP key and initial vector.
        The initial vector is either loaded from config or generated randomly if not provided.

        :param config: Configuration object containing HSE-specific fields.
        :raises SPSDKValueError: Invalid key size or missing required configuration.
        """
        self.adkp = config.load_symmetric_key("adkp", expected_size=self.GMAC_SIZE)
        self.initial_vector = (
            config.load_symmetric_key("initialVector", expected_size=self.IV_SIZE)
            if "initialVector" in config
            else random_bytes(self.IV_SIZE)
        )

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary data to extract HSE-specific fields.

        Extracts the initial vector from the binary data at the calculated offset
        based on the application size. Only processes signed images.

        :param data: Complete binary image data to parse.
        """
        if not self.ivt.is_signed:
            return
        offset = self.ivt.app_offset + self.hse_app_boot_header.app_size
        self.adkp = None
        self.initial_vector = data[offset : offset + self.IV_SIZE]

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        Returns a dictionary containing the HSE mixin configuration including ADKP
        and initial vector values in hexadecimal format.

        :param output_folder: Output folder to store files.
        :return: Dictionary with mixin configuration containing 'adkp' and 'initialVector' keys.
        """
        return {
            "adkp": self.adkp.hex() if self.adkp else "Unknown",
            "initialVector": self.initial_vector.hex() if self.initial_vector else "Unknown",
        }


class Mbi_ExportMixinHseApp(Mbi_ExportMixin):
    """HSE Application Export Mixin for Master Boot Image.

    This mixin handles the collection and organization of HSE application data
    including IVT (Image Vector Table), application boot header, application
    binary, and lifecycle configuration for Master Boot Image export operations.

    :cvar APP_BLOCK_NAME: Name identifier for the application block container.
    :cvar APP_IMAGE_NAME: Name identifier for the application binary image.
    """

    APP_BLOCK_NAME = "Application Block"
    APP_IMAGE_NAME = "Application"

    app: Optional[bytes]
    ivt: Ivt
    hse_app_boot_header: AppBootHeader
    lifecycle: Optional["Mbi_MixinHseLifecycle.LifecycleState"]

    def collect_data(self) -> BinaryImage:
        """Collect application data into a binary image structure.

        This method assembles all application components including IVT, optional HSE app boot header,
        application binary, and lifecycle configuration into a structured binary image. It handles
        automatic calculation of lifecycle configuration address when not explicitly provided.

        :raises SPSDKError: Application data is missing.
        :return: Binary image containing all application components with proper offsets.
        """
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
            if self.ivt.lc_config_offset:
                lc_offset = self.ivt.lc_config_offset
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

        This method extracts the application part from the input image based on the IVT
        (Image Vector Table) configuration. It determines the end offset either from the
        HSE application boot header or the LC configuration offset.

        :param image: Binary image data to be disassembled.
        """
        end_offset = None
        if hasattr(self, "hse_app_boot_header"):
            end_offset = self.ivt.app_offset + self.hse_app_boot_header.app_size
        # if LC configuration word is part of the image, we take its offset as end of application
        elif self.ivt.lc_config_offset and self.ivt.lc_config_offset < len(image):
            end_offset = self.ivt.lc_config_offset
        self.app = image[self.ivt.app_offset : end_offset]


class Mbi_ExportMixinHseAppSigned(Mbi_ExportMixinHseApp):
    """Export Mixin for HSE application data with cryptographic signing capabilities.

    This mixin extends HSE application functionality by adding support for signed
    application data using AES-GCM encryption with authentication tags. It manages
    the cryptographic signing process including ADKP (Application Debug/Key Password)
    handling and initial vector management for secure boot operations.
    """

    adkp: Optional[bytes]
    initial_vector: Optional[bytes]

    def sign(self, image: BinaryImage, revert: bool = False) -> BinaryImage:
        """Calculate signature and return updated image with authentication tag.

        The method performs AES-GCM encryption to generate an authentication tag using the
        Application Debug/Key Password (ADKP) hash as the key. The authentication tag is
        appended to the image along with the initial vector.

        :param image: Input raw binary image to be signed.
        :param revert: If True, returns the original image without signing.
        :return: Binary image with authentication tag appended at the end.
        :raises SPSDKError: If ADKP, initial vector, or application data is missing.
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
    """Master Boot Image HSE Lifecycle Mixin.

    This mixin handles HSE (Hardware Security Engine) lifecycle state management
    for Master Boot Images, providing functionality to configure and parse
    lifecycle transitions such as OEM Production and In Field states.

    :cvar APP_BOOT_HEADER_IMAGE_NAME: Image name identifier for lifecycle header.
    :cvar VALIDATION_SCHEMAS: Configuration validation schemas for HSE lifecycle.
    :cvar NEEDED_MEMBERS: Required configuration members for lifecycle management.
    :cvar LC_VALUE_LENGTH: Length of lifecycle value in bytes.
    """

    class LifecycleState(SpsdkEnum):
        """HSE lifecycle state enumeration.

        Defines the available lifecycle states for HSE (Hardware Security Engine)
        operations, including state transitions and lifecycle advancement options.
        """

        NONE = (0xFFFF_FFFF, "none", "Do not advance Lifecycle")
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

        The method returns the length constant if lifecycle is enabled, otherwise returns 0.

        :return: Length of atomic Mixin in bytes.
        """
        return self.LC_VALUE_LENGTH if self.lifecycle else 0

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration of mixin from dictionary.

        The method processes lifecycle configuration if present in the config dictionary.
        If lifecycle configuration address is set but no lifecycle state is provided,
        a warning is logged.

        :param config: Dictionary with configuration fields.
        :raises SPSDKError: Invalid lifecycle state provided in configuration.
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
        """Parse the binary data to extract HSE lifecycle configuration.

        Extracts lifecycle state from the binary data using the lifecycle configuration
        address from IVT. If the lifecycle configuration address is not set, the method
        returns early without processing.

        :param data: Complete binary image data containing HSE configuration.
        :raises SPSDKValueError: When lifecycle value is not recognized.
        """
        if not self.ivt.lc_config_addr:
            return
        lc_offset = self.ivt.lc_config_addr - self.ivt.start_address
        lc_value = int.from_bytes(
            data[lc_offset : lc_offset + self.LC_VALUE_LENGTH], byteorder="little"
        )
        if lc_value not in self.LifecycleState.tags():
            logger.info(f"Unknown lifecycle state: {lc_value}")
            self.lifecycle = self.LifecycleState.NONE
        self.lifecycle = self.LifecycleState.from_tag(lc_value)

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        :return: Configuration dictionary containing lifecycle state information.
        """
        lc = self.lifecycle.label if self.lifecycle else self.LifecycleState.NONE.label
        return Config({"lifecycle": lc})


class Mbi_MixinHseApp(Mbi_MixinApp):
    """Master Boot Image App class for HSE application.

    This class handles HSE (Hardware Security Engine) application images within
    the Master Boot Image framework. It manages IVT (Image Vector Table) parsing
    and extraction from input images, automatically detecting and processing
    existing IVT headers while preserving critical configuration addresses.
    """

    ivt: Ivt

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary and process HSE application data.

        The method loads configuration using the parent class method, then attempts to parse
        an IVT (Image Vector Table) header from the application data. If found, it extracts
        the application data from the specified offset and updates IVT addresses that are
        not already configured. If no IVT header is detected, the raw application data is used.

        :param config: Dictionary with configuration fields.
        :raises SPSDKVerificationError: When IVT header parsing fails (handled internally).
        """
        super().mix_load_from_config(config)
        # For HSE application with or without boot header(IVT) is allowed on the input
        try:
            ivt = Ivt.parse(self.app, family=self.family)
            if len(self.app) <= ivt.app_offset:
                logger.warning("Invalid app_offset in IVT header: offset is larger than image size")
                return

            self.app = self.app[ivt.app_offset :]
            if ivt.app_start_addr and not self.ivt.app_start_addr:
                logger.info("Updating application start address from IVT found in input image file")
                self.ivt.app_start_addr = ivt.app_start_addr
            if ivt.lc_config_addr and not self.ivt.lc_config_addr:
                logger.info("Updating LC config address from IVT found in input image file")
                self.ivt.lc_config_addr = ivt.lc_config_addr
            if ivt.hse_fw_addr and not self.ivt.hse_fw_addr:
                logger.info("Updating HSE FW address from IVT found in input image file")
                self.ivt.hse_fw_addr = ivt.hse_fw_addr
            if ivt.app_boot_header_addr and not self.ivt.app_boot_header_addr:
                logger.info("Updating HSE boot header address from IVT found in input image file")
                self.ivt.app_boot_header_addr = ivt.app_boot_header_addr
        except SPSDKVerificationError:
            logger.debug("No IVT header detected in input image, using raw application data")
            return
