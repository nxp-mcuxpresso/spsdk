#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK HSE Attribute Handlers Module.

This module provides attribute handler classes for managing Hardware Security Engine (HSE)
attributes in NXP EdgeLock Enclave operations. It implements a comprehensive framework for
reading, writing, parsing, and serializing various HSE configuration attributes.
"""

from abc import abstractmethod
from struct import calcsize, pack, unpack
from typing import Any, Optional, Type

from typing_extensions import Self

from spsdk.ele.ele_message import LITTLE_ENDIAN, UINT8, UINT16, UINT32, UINT64
from spsdk.exceptions import SPSDKValueError
from spsdk.utils.abstract import BaseClass
from spsdk.utils.spsdk_enum import SpsdkEnum


class HseAttributeId(SpsdkEnum):
    """HSE attribute identifier enumeration.

    Defines the available attribute IDs that can be used with HSE (Hardware
    Security Engine) attribute get/set operations for secure provisioning.
    """

    FW_VERSION = (1, "FW_VERSION")
    CAPABILITIES = (2, "CAPABILITIES")
    APP_DEBUG_KEY = (11, "APP_DEBUG_KEY")
    SECURE_LIFECYCLE = (12, "SECURE_LIFECYCLE")
    ENABLE_PUBLISH_KEYSTORE_RAM_TO_FLASH = (602, "ENABLE_PUBLISH_KEYSTORE_RAM_TO_FLASH")


class HseAttributeType(SpsdkEnum):
    """HSE attribute type enumeration.

    Defines the available attribute types that determine access permissions
    and behavior for HSE (Hardware Security Engine) attributes in NXP MCU
    security operations.
    """

    READ_ONLY = (0, "RO-ATTR", "Read-Only attribute")
    ONE_TIME_PROGRAMMABLE = (
        1,
        "OTP-ATTR",
        "One Time Programmable; can be written only once (set FUSE/UTEST area)",
    )
    OTP_ADVANCE = (
        2,
        "OTP-ADVANCE-ATTR",
        "One Time Programmable attribute that can only be advanced (e.g. LifeCycle)",
    )
    NVM_READ_WRITE = (3, "NVM-RW-ATTR", "System NVM attributes; can be read or written")
    SET_ONCE = (
        4,
        "SET-ONCE-ATTR",
        "Once the attribute is set, it can not be changed until next reset",
    )


class HseAttributeHandler(BaseClass):
    """Base class for HSE attribute handlers.

    Provides common functionality for handling HSE attributes including data validation,
    size calculation, and abstract methods for decoding and string representation.
    This class serves as the foundation for all specific HSE attribute implementations.

    :cvar FORMAT: Struct format string for binary data packing/unpacking.
    :cvar ATTR_ID: HSE attribute identifier.
    :cvar ATTR_TYPE: HSE attribute type defining read/write permissions.
    """

    FORMAT: str
    ATTR_ID: HseAttributeId
    ATTR_TYPE: HseAttributeType

    @classmethod
    def is_readable(cls) -> bool:
        """Check if the HSE attribute is readable.

        :return: True if the attribute can be read, False otherwise.
        """
        return cls.ATTR_TYPE in [
            HseAttributeType.READ_ONLY,
            HseAttributeType.NVM_READ_WRITE,
            HseAttributeType.OTP_ADVANCE,
        ]

    @classmethod
    def is_writeable(cls) -> bool:
        """Check if the HSE attribute is writeable.

        Determines whether the attribute type allows write operations based on the
        attribute's type classification.

        :return: True if the attribute can be set, False otherwise.
        """
        return cls.ATTR_TYPE in [
            HseAttributeType.ONE_TIME_PROGRAMMABLE,
            HseAttributeType.OTP_ADVANCE,
            HseAttributeType.NVM_READ_WRITE,
            HseAttributeType.SET_ONCE,
        ]

    @property
    def size(self) -> int:
        """Get the default size for this attribute type.

        :return: Size in bytes.
        """
        return self.get_size()

    @classmethod
    def get_size(cls) -> int:
        """Get the default size for this attribute type.

        :return: Size in bytes calculated from the FORMAT string.
        """
        return calcsize(cls.FORMAT)

    @abstractmethod
    def to_dict(self) -> dict[str, Any]:
        """Convert attribute to a dictionary representation.

        :return: Dictionary containing attribute fields and values
        """

    @classmethod
    def get_attr_handler_cls(cls, attr_id: HseAttributeId) -> Type["HseAttributeHandler"]:
        """Get attribute handler class for specified attribute ID.

        Searches through all HseAttributeHandler subclasses to find the one that handles
        the specified attribute ID.

        :param attr_id: HSE attribute identifier to find handler for.
        :raises SPSDKValueError: When no handler is found for the specified attribute ID.
        :return: Handler class that can process the specified attribute ID.
        """
        for handler_cls in HseAttributeHandler.__subclasses__():
            assert issubclass(handler_cls, HseAttributeHandler)
            if hasattr(handler_cls, "ATTR_ID") and handler_cls.ATTR_ID == attr_id:
                return handler_cls
        raise SPSDKValueError(f"Unsupported attribute ID: {attr_id}")


class FwMemoryConfig(SpsdkEnum):
    """HSE firmware memory configuration enumeration.

    Defines the available memory configuration modes for HSE (Hardware Security Engine)
    firmware operations. These configurations determine how the firmware manages memory
    layout and swap operations for different operational scenarios.
    """

    FULL_MEMORY = (0, "FULL_MEMORY", "Full memory")
    AB_SWAP = (1, "AB_SWAP", "AB swap")


class FwVersionAttributeHandler(HseAttributeHandler):
    """HSE firmware version attribute handler.

    This class manages HSE firmware version information including SoC type,
    firmware type, and semantic version components (major, minor, patch).
    It provides functionality to parse raw firmware version data and export
    it back to binary format.

    :cvar FORMAT: Binary format string for packing/unpacking version data.
    :cvar ATTR_ID: HSE attribute identifier for firmware version.
    :cvar ATTR_TYPE: Read-only attribute type designation.
    """

    FORMAT = LITTLE_ENDIAN + UINT8 + UINT8 + UINT16 + UINT8 + UINT8 + UINT16
    ATTR_ID = HseAttributeId.FW_VERSION
    ATTR_TYPE = HseAttributeType.READ_ONLY

    def __init__(
        self,
        soc_type: int,
        fw_type: int,
        major: int,
        minor: int,
        patch: int,
        fw_memory_config: FwMemoryConfig,
    ) -> None:
        """Initialize the firmware version attribute handler.

        Creates a new instance with specified firmware version components including
        SoC type, firmware type, and semantic version numbers.

        :param soc_type: Type identifier of the System on Chip.
        :param fw_type: Type identifier of the firmware.
        :param major: Major version number of the firmware.
        :param minor: Minor version number of the firmware.
        :param patch: Patch version number of the firmware.
        :param fw_memory_config: FW memory configuration.
        """
        super().__init__()
        self.soc_type = soc_type
        self.fw_type = fw_type
        self.major = major
        self.minor = minor
        self.patch = patch
        self.fw_memory_config = fw_memory_config

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse firmware version data into structured fields.

        Extracts SoC type, firmware type, and version components from the raw data.

        :param data: Raw firmware version data bytes to be parsed.
        :return: Parsed firmware version object with extracted components.
        """
        mem_cfg, soc_type, fw_type, major, minor, patch = unpack(cls.FORMAT, data)
        return cls(soc_type, fw_type, major, minor, patch, FwMemoryConfig.from_tag(mem_cfg))

    def export(self) -> bytes:
        """Export firmware version data into raw bytes.

        The method packs firmware version information including SOC type, firmware type,
        and version numbers (major, minor, patch) into a binary format according to the
        predefined FORMAT structure.

        :return: Packed binary data containing firmware version information.
        """
        return pack(
            self.FORMAT,
            self.fw_memory_config.tag,
            self.soc_type,
            self.fw_type,
            self.major,
            self.minor,
            self.patch,
        )

    def __str__(self) -> str:
        """Return string representation of firmware version information.

        Provides a formatted string containing SoC type, firmware type, and version details
        in a human-readable format.

        :return: Formatted string with firmware version details.
        """
        ret = "Firmware Version:\n"
        ret += f"SoC Type: {self.soc_type}\n"
        ret += f"FW Type: {self.fw_type}\n"
        ret += f"Version: {self.major}.{self.minor}.{self.patch}\n"
        ret += f"FW Memory Config: {self.fw_memory_config.label}\n"
        return ret

    def __repr__(self) -> str:
        """Return a string representation of the firmware version.

        :return: String representation in the format 'FwVersion(soc_type=X, fw_type=Y, version=A.B.C)'.
        """
        return (
            f"FwVersion(soc_type={self.soc_type}, fw_type={self.fw_type},"
            f"version={self.major}.{self.minor}.{self.patch})"
            f"fw_memory_config={self.fw_memory_config.label})"
        )

    def to_dict(self) -> dict:
        """Convert HSE firmware version information to dictionary format.

        Serializes the HSE firmware version attributes and settings into a structured
        dictionary representation suitable for configuration files or data exchange.

        :return: Dictionary containing attribute ID label and firmware version settings
                 including SoC type, firmware type, and version numbers (major, minor, patch).
        """
        cfg: dict = {
            "attr_id": self.ATTR_ID.label,
            "settings": {
                "soc_type": self.soc_type,
                "fw_type": self.fw_type,
                "major": self.major,
                "minor": self.minor,
                "patch": self.patch,
                "fw_memory_config": self.fw_memory_config.label,
            },
        }
        return cfg


class CapabilityIndex(SpsdkEnum):
    """HSE capability indices enumeration.

    This enumeration defines the capability indices used to identify specific cryptographic
    algorithms and security features supported by the Hardware Security Engine (HSE).
    Each capability index maps to a particular cryptographic operation such as encryption,
    hashing, digital signatures, or key derivation functions.
    """

    RANDOM = (0, "RANDOM", "Random number generation")
    SHE = (1, "SHE", "SHE functionality")
    AES = (2, "AES", "AES encryption/decryption")
    XTS_AES = (3, "XTS_AES", "XTS-AES mode")
    AEAD_GCM = (4, "AEAD_GCM", "AEAD GCM mode")
    AEAD_CCM = (5, "AEAD_CCM", "AEAD CCM mode")
    RESERVED1 = (6, "RESERVED1", "Reserved (MD5 obsolete)")
    SHA1 = (7, "SHA1", "SHA-1 hash algorithm")
    SHA2 = (8, "SHA2", "SHA-2 hash algorithm family")
    SHA3 = (9, "SHA3", "SHA-3 hash algorithm family")
    MP = (10, "MP", "Message Part functionality")
    CMAC = (11, "CMAC", "CMAC algorithm")
    HMAC = (12, "HMAC", "HMAC algorithm")
    GMAC = (13, "GMAC", "GMAC algorithm")
    XCBC_MAC = (14, "XCBC_MAC", "XCBC-MAC algorithm")
    RSAES_NO_PADDING = (15, "RSAES_NO_PADDING", "RSA encryption scheme with no padding")
    RSAES_OAEP = (16, "RSAES_OAEP", "RSA encryption scheme with OAEP padding")
    RSAES_PKCS1_V15 = (17, "RSAES_PKCS1_V15", "RSA encryption scheme with PKCS#1 v1.5 padding")
    RSASSA_PSS = (18, "RSASSA_PSS", "RSA signature scheme with PSS padding")
    RSASSA_PKCS1_V15 = (19, "RSASSA_PKCS1_V15", "RSA signature scheme with PKCS#1 v1.5 padding")
    ECDH = (20, "ECDH", "Elliptic Curve Diffie-Hellman")
    ECDSA = (21, "ECDSA", "Elliptic Curve Digital Signature Algorithm")
    EDDSA = (22, "EDDSA", "Edwards-curve Digital Signature Algorithm")
    MONTDH = (23, "MONTDH", "Montgomery curve Diffie-Hellman")
    CLASSIC_DH = (24, "CLASSIC_DH", "Classic Diffie-Hellman")
    KDF_SP800_56C = (25, "KDF_SP800_56C", "Key Derivation Function SP800-56C")
    KDF_SP800_108 = (26, "KDF_SP800_108", "Key Derivation Function SP800-108")
    KDF_ANS_X963 = (27, "KDF_ANS_X963", "Key Derivation Function ANS X9.63")
    KDF_ISO18033_KDF1 = (28, "KDF_ISO18033_KDF1", "Key Derivation Function ISO18033 KDF1")
    KDF_ISO18033_KDF2 = (29, "KDF_ISO18033_KDF2", "Key Derivation Function ISO18033 KDF2")
    PBKDF2 = (30, "PBKDF2", "Password-Based Key Derivation Function 2")
    KDF_TLS12_PRF = (31, "KDF_TLS12_PRF", "Key Derivation Function TLS 1.2 PRF")
    HKDF = (32, "HKDF", "HMAC-based Key Derivation Function")
    KDF_IKEV2 = (33, "KDF_IKEV2", "Key Derivation Function IKEv2")


class CapabilitiesAttributeHandler(HseAttributeHandler):
    """HSE capabilities attribute handler.

    Manages HSE (Hardware Security Engine) capability information by handling
    the parsing, serialization, and representation of supported capabilities
    as a bitmap. This handler processes capability data to determine which
    security algorithms and features are available in the HSE firmware.

    :cvar FORMAT: Binary format specification for UINT64 little-endian encoding.
    :cvar ATTR_ID: HSE attribute identifier for capabilities.
    :cvar ATTR_TYPE: Read-only attribute type designation.
    """

    FORMAT = LITTLE_ENDIAN + UINT64
    ATTR_ID = HseAttributeId.CAPABILITIES
    ATTR_TYPE = HseAttributeType.READ_ONLY

    def __init__(self, capabilities: list[CapabilityIndex]) -> None:
        """Initialize the capabilities attribute handler.

        :param capabilities: List of capability indices to be handled by this instance.
        """
        super().__init__()
        self.capabilities: list[CapabilityIndex] = capabilities

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse capabilities data into a bitmap and list of supported algorithms.

        Extracts the capabilities bitmap from raw bytes and determines which specific
        algorithms are supported based on the capability flags.

        :param data: Raw capabilities data as bytes in little-endian format.
        :return: New instance with parsed capabilities list.
        """
        # Convert the bytes to an integer (little-endian)
        capabilities_int = int.from_bytes(data, byteorder="little")

        # Determine which algorithms are supported
        capabilities = []
        for cap in CapabilityIndex:
            if bool(capabilities_int & (1 << cap.tag)):
                capabilities.append(cap)
        return cls(capabilities)

    def export(self) -> bytes:
        """Export capabilities as UINT64 bitmap.

        Converts the list of supported capabilities into a bitmap where each bit represents a
        capability, and then serializes it as a UINT64 value in little-endian format.

        :return: Serialized capabilities bitmap as bytes.
        """
        # Initialize capabilities bitmap
        capabilities_int = 0

        # Set bits for each supported capability
        for cap in self.capabilities:
            capabilities_int |= 1 << cap.tag

        # Serialize as UINT64 in little-endian format
        return capabilities_int.to_bytes(8, byteorder="little")

    def __str__(self) -> str:
        """Format the capabilities for display.

        Creates a formatted string representation of HSE capabilities with proper indentation
        and sorting by capability tag for consistent output.

        :return: Formatted string representation of the capabilities.
        """
        ret = "Supported HSE Capabilities:\n"

        if not self.capabilities:
            ret += "  None\n"
        else:
            for cap in sorted(self.capabilities, key=lambda x: x.tag):
                ret += f"  - {cap.label}: {cap.description}\n"

        return ret

    def __repr__(self) -> str:
        """Return a string representation of the HSE capabilities.

        Provides a formatted string showing all supported HSE capabilities in a sorted order
        for consistent output. Empty capabilities are represented as an empty list.

        :return: String representation listing the supported capabilities in format
                 'Capabilities([capability1, capability2, ...])' or 'Capabilities([])' if empty.
        """
        if not self.capabilities:
            return "Capabilities([])"

        # Sort capabilities by tag for consistent output
        sorted_caps = sorted(self.capabilities, key=lambda x: x.tag)

        # Format each capability as its label
        cap_labels = [cap.label for cap in sorted_caps]

        # Join with commas and wrap in Capabilities([...])
        return f"Capabilities([{', '.join(cap_labels)}])"

    def to_dict(self) -> dict:
        """Convert the HSE attribute to dictionary representation.

        The method creates a dictionary containing the attribute ID label and
        capabilities settings for serialization purposes.

        :return: Dictionary with attribute ID and capabilities settings.
        """
        return {
            "attr_id": self.ATTR_ID.label,
            "settings": {"capabilities": [cap.label for cap in self.capabilities]},
        }


class EnablePublishKeyStoreRamToFlashAttributeHandler(HseAttributeHandler):
    """HSE attribute handler for controlling NVM keystore update behavior.

    This handler manages the HSE_ENABLE_PUBLISH_KEY_STORE_RAM_TO_FLASH_ATTR_ID attribute
    which controls whether HSE updates NVM keys only in RAM or also in flash memory.
    When enabled (HSE_CFG_YES), HSE updates NVM keys only in RAM, and the application
    must call HSE_SRV_ID_PUBLISH_NVM_KEYSTORE_RAM_TO_FLASH to write to flash.
    When disabled (HSE_CFG_NO, default), HSE updates both RAM and flash during key operations.
    Note: This attribute is available only in Cust-Del and Oem-Prod lifecycle states.
    """

    FORMAT = LITTLE_ENDIAN + UINT32
    ATTR_ID = HseAttributeId.ENABLE_PUBLISH_KEYSTORE_RAM_TO_FLASH
    ATTR_TYPE = HseAttributeType.NVM_READ_WRITE

    class ConfigValue(SpsdkEnum):
        """Configuration values for HSE publish key store attribute.

        Enumeration defining configuration options that control how the HSE (Hardware Security
        Engine) updates the key store during publish operations, specifying whether updates
        affect both RAM and flash memory or only RAM.
        """

        CFG_NO = (0, "CFG_NO", "Update both RAM and flash (default)")
        CFG_YES = (0xB7A5C365, "CFG_YES", "Update only RAM, manual flash update required")

    def __init__(
        self,
        config_value: "EnablePublishKeyStoreRamToFlashAttributeHandler.ConfigValue",
    ) -> None:
        """Initialize the publish key store RAM to flash attribute handler.

        :param config_value: Configuration value for the attribute handler.
        :type config_value: EnablePublishKeyStoreRamToFlashAttributeHandler.ConfigValue
        """
        super().__init__()
        self.config_value = config_value

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse attribute data from raw bytes.

        Extracts the configuration value from the raw data and creates a new instance
        of the class with the decoded configuration value.

        :param data: Raw byte data containing the attribute configuration value.
        :return: New instance of the class with parsed configuration value.
        """
        value = data[0]
        return cls(cls.ConfigValue.from_tag(value))

    def export(self) -> bytes:
        """Export the attribute value as bytes.

        Serializes the configuration value to a byte array according to the defined format.

        :return: Serialized attribute value as bytes.
        """
        return pack(self.FORMAT, self.config_value.tag)

    def __str__(self) -> str:
        """Format the attribute value for display.

        Creates a formatted string representation of the Publish Key Store RAM to Flash
        configuration, including the setting label and description.

        :return: Formatted string representation of the configuration.
        """
        ret = "Publish Key Store RAM to Flash:\n"
        ret += f"  Setting: {self.config_value.label} - {self.config_value.description}\n"

        return ret

    def __repr__(self) -> str:
        """Return a string representation of the publish key store RAM to flash attribute.

        :return: String representation indicating the configuration value.
        """
        return f"PublishKeyStoreRamToFlash({self.config_value.label})"

    def to_dict(self) -> dict[str, Any]:
        """Get configuration dictionary for this attribute.

        Creates a dictionary with the current attribute configuration that can be used
        for serialization or UI representation.

        :return: Dictionary with attribute configuration containing attr_id and settings.
        """
        return {
            "attr_id": self.ATTR_ID.label,
            "settings": {"config_value": self.config_value.label},
        }


class SecureLifecycle(SpsdkEnum):
    """HSE secure lifecycle enumeration.

    Represents HSE secure lifecycle states. The lifecycle can be advanced only in forward
    direction. A reset is recommended after each lifecycle write-advance operation as the
    lifecycle is read/scanned by hardware during the reset phase.

    Warning: The lifecycle can be advanced to OEM_PROD/IN_FIELD only if the ADKP was set before.
    """

    CUST_DEL = (0x04, "CUST_DEL", "Customer Delivery lifecycle")
    OEM_PROD = (0x08, "OEM_PROD", "OEM Production lifecycle")
    IN_FIELD = (0x10, "IN_FIELD", "In Field lifecycle")
    PRE_FA = (0x14, "PRE_FA", "Pre-Failure Analysis lifecycle")
    SIMULATED_OEM_PROD = (0xA6, "SIMULATED_OEM_PROD", "Simulated OEM Production lifecycle")
    SIMULATED_IN_FIELD = (0xA7, "SIMULATED_IN_FIELD", "Simulated In Field lifecycle")


class SecureLifecycleAttributeHandler(HseAttributeHandler):
    """HSE secure lifecycle attribute handler.

    Manages the HSE secure lifecycle state which controls the security configuration
    and available features. The lifecycle can only be advanced in forward direction
    and requires a hardware reset after each advancement operation.

    Important notes:
    - Lifecycle is read by hardware during reset phase
    - Reset is recommended after each lifecycle write-advance operation
    - Advancement to OEM_PROD/IN_FIELD requires ADKP to be set first

    :cvar FORMAT: Binary format specification for UINT8 encoding.
    :cvar ATTR_ID: HSE attribute identifier for secure lifecycle.
    :cvar ATTR_TYPE: OTP-ADVANCE attribute type - can only be advanced, not reversed.
    """

    FORMAT = LITTLE_ENDIAN + UINT8
    ATTR_ID = HseAttributeId.SECURE_LIFECYCLE
    ATTR_TYPE = HseAttributeType.OTP_ADVANCE

    def __init__(self, lifecycle: SecureLifecycle) -> None:
        """Initialize the secure lifecycle attribute handler.

        :param lifecycle: The secure lifecycle state to set or represent.
        """
        super().__init__()
        self.lifecycle = lifecycle

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse secure lifecycle data from raw bytes.

        Extracts the lifecycle state value from the raw data and creates a new instance
        with the corresponding lifecycle enumeration value.

        :param data: Raw byte data containing the lifecycle state value.
        :return: New instance of the class with parsed lifecycle state.
        :raises SPSDKValueError: If the lifecycle value is not recognized.
        """
        lifecycle_value = data[0]
        return cls(SecureLifecycle.from_tag(lifecycle_value))

    def export(self) -> bytes:
        """Export the secure lifecycle value as bytes.

        Serializes the lifecycle state to a byte array according to the defined format.

        :return: Serialized lifecycle value as bytes.
        """
        return pack(self.FORMAT, self.lifecycle.tag)

    def __str__(self) -> str:
        """Format the secure lifecycle for display.

        Creates a formatted string representation of the HSE secure lifecycle state
        including the lifecycle label and description.

        :return: Formatted string representation of the lifecycle state.
        """
        ret = "HSE Secure Lifecycle:\n"
        ret += f"  State: {self.lifecycle.label} (0x{self.lifecycle.tag:02X})\n"
        ret += f"  Description: {self.lifecycle.description}\n"
        ret += "\nWarnings:\n"
        ret += "  - Lifecycle can only be advanced in forward direction\n"
        ret += "  - Reset is recommended after each lifecycle write-advance operation\n"
        ret += "  - Advancement to OEM_PROD/IN_FIELD requires ADKP to be set\n"
        return ret

    def __repr__(self) -> str:
        """Return a string representation of the secure lifecycle attribute.

        :return: String representation indicating the lifecycle state.
        """
        return f"SecureLifecycle({self.lifecycle.label})"

    def to_dict(self) -> dict[str, Any]:
        """Convert the secure lifecycle attribute to dictionary representation.

        Creates a dictionary containing the attribute ID label and lifecycle settings
        for serialization purposes.

        :return: Dictionary with attribute ID and lifecycle settings.
        """
        return {
            "attr_id": self.ATTR_ID.label,
            "settings": {
                "lifecycle": self.lifecycle.label,
            },
        }


class AppDebugKeyAttributeHandler(HseAttributeHandler):
    """HSE Application Debug Key/Password attribute handler.

    Manages the 128-bit Application Debug Key/Password (ADKP) that must be set by the host
    in CUST_DEL lifecycle. This key is used for debug authentication and lifecycle advancement.

    Important notes:
    - Write: Accepts full 128-bit (16 bytes) debug key, can only be written once in CUST_DEL lifecycle
    - Read: Returns first 16 bytes of SHA2_224(ADKP), not the actual key
    - Keys with all 0x00 or all 0xFF bytes are rejected by HSE firmware
    - Required to be set before advancing to OEM_PROD/IN_FIELD lifecycle

    :cvar FORMAT: Binary format specification for 128-bit key (16 bytes).
    :cvar ATTR_ID: HSE attribute identifier for application debug key.
    :cvar ATTR_TYPE: One-time programmable attribute type.
    """

    FORMAT = LITTLE_ENDIAN + "16" + UINT8  # 16 bytes for 128-bit key
    ATTR_ID = HseAttributeId.APP_DEBUG_KEY
    ATTR_TYPE = HseAttributeType.NVM_READ_WRITE

    def __init__(self, data: bytes, is_hash: bool = True) -> None:
        """Initialize the application debug key attribute handler.

        :param data: Either the actual 128-bit debug key or its SHA2_224 hash (first 16 bytes).
        :param is_hash: True if data is the hash (from read), False if actual key (for write).
        :raises SPSDKValueError: If data is not exactly 16 bytes.
        """
        super().__init__()
        if len(data) != 16:
            raise SPSDKValueError(f"Data must be exactly 16 bytes, got {len(data)}")

        self.data = data
        self.is_hash = is_hash

        # Validate actual key if this is for writing
        if not is_hash:
            self._validate_debug_key(data)

    def _validate_debug_key(self, debug_key: bytes) -> None:
        """Validate the debug key for writing.

        :param debug_key: The 128-bit debug key to validate.
        :raises SPSDKValueError: If debug key is invalid (all zeros or all 0xFF).
        """
        # Check for rejected patterns (all 0x00 or all 0xFF)
        if debug_key == b"\x00" * 16:
            raise SPSDKValueError("Debug key cannot be all 0x00 bytes")
        if debug_key == b"\xff" * 16:
            raise SPSDKValueError("Debug key cannot be all 0xFF bytes")

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse application debug key hash data from read response.

        When reading APP_DEBUG_KEY attribute, HSE returns the first 16 bytes of SHA2_224(ADKP).
        This method parses that hash data.

        :param data: Raw byte data containing the key hash (16 bytes).
        :return: New instance with parsed key hash.
        :raises SPSDKValueError: If data is not exactly 16 bytes.
        """
        if len(data) < 16:
            raise SPSDKValueError(
                f"Invalid data length for APP_DEBUG_KEY: {len(data)}, expected 16 bytes"
            )

        key_hash = data[:16]
        return cls(key_hash, is_hash=True)

    def export(self) -> bytes:
        """Export the data as bytes.

        For read operations: Returns the SHA2_224 hash (first 16 bytes).
        For write operations: Returns the actual 128-bit debug key.

        :return: Serialized data as 16 bytes.
        """
        return pack(self.FORMAT, self.data)

    @property
    def debug_key(self) -> Optional[bytes]:
        """Get the actual debug key if available.

        :return: The actual debug key if this instance was created for writing, None if from read.
        """
        return self.data if not self.is_hash else None

    @property
    def key_hash(self) -> Optional[bytes]:
        """Get the key hash if available.

        :return: The SHA2_224 hash if this instance was created from read, None if for writing.
        """
        return self.data if self.is_hash else None

    def __str__(self) -> str:
        """Format the application debug key information for display.

        Shows different information based on whether this contains the actual key or its hash.

        :return: Formatted string representation of the debug key information.
        """
        ret = "Application Debug Key/Password:\n"

        if self.is_hash:
            ret += f"  Key Hash (SHA2_224 first 16 bytes): {self.data.hex().upper()}\n"
            ret += "  Note: This is the hash returned by read operation, not the actual key\n"
        else:
            ret += f"  Debug Key: {self.data.hex().upper()}\n"
            ret += "  Note: This is the actual key for write operation\n"

        ret += "\nAttribute Properties:\n"
        ret += "  - Can only be written once in CUST_DEL lifecycle\n"
        ret += "  - Required before advancing to OEM_PROD/IN_FIELD lifecycle\n"
        ret += "  - Keys with all 0x00 or all 0xFF bytes are rejected\n"
        ret += "  - Read returns SHA2_224 hash, write accepts actual key\n"
        return ret

    def __repr__(self) -> str:
        """Return a string representation of the application debug key attribute.

        :return: String representation showing the data type and hex value.
        """
        data_type = "hash" if self.is_hash else "key"
        return f"AppDebugKey({data_type}={self.data.hex().upper()})"

    def to_dict(self) -> dict[str, Any]:
        """Convert the application debug key attribute to dictionary representation.

        Creates a dictionary containing the attribute ID label and key data
        for serialization purposes.

        :return: Dictionary with attribute ID and key settings.
        """
        if self.is_hash:
            settings = {
                "key_hash": self.data.hex().upper(),
                "note": "This is SHA2_224 hash from read operation",
            }
        else:
            settings = {
                "debug_key": self.data.hex().upper(),
                "note": "This is actual key for write operation",
            }

        return {
            "attr_id": self.ATTR_ID.label,
            "settings": settings,
        }
