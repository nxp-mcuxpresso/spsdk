#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK database management and device information utilities.

This module provides comprehensive functionality for managing SPSDK databases
containing device-specific information, features, revisions, and configurations.
It handles database loading, caching, validation, and provides unified access
to device data across the NXP MCU portfolio.
"""

import logging
import os
import pickle
import re
import shutil
import textwrap
from copy import deepcopy
from typing import Any, Iterator, Optional, Union

import prettytable
from filelock import FileLock
from typing_extensions import Self

import spsdk
from spsdk import (
    SPSDK_ADDONS_DATA_FOLDER,
    SPSDK_CACHE_DISABLED,
    SPSDK_CACHE_FOLDER,
    SPSDK_DATA_FOLDER,
    SPSDK_DEBUG_DB,
    SPSDK_PLATFORM_DIRS,
    SPSDK_RESTRICTED_DATA_FOLDER,
    version,
)
from spsdk.apps.utils import spsdk_logger
from spsdk.crypto.hash import EnumHashAlgorithm, Hash, get_hash
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.utils.misc import (
    deep_update,
    find_first,
    load_configuration,
    size_fmt,
    value_to_bool,
    value_to_int,
)
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)


def get_spsdk_cache_dirname() -> str:
    """Get database cache folder name.

    Returns the path specified by SPSDK_CACHE_FOLDER if set and valid.
    Otherwise, returns the default user cache directory for SPSDK.

    :raises SPSDKValueError: If SPSDK_CACHE_FOLDER is set but not a valid absolute path.
    :return: The path to the SPSDK cache directory.
    """
    if SPSDK_CACHE_FOLDER:
        if not os.path.isabs(SPSDK_CACHE_FOLDER):
            raise SPSDKValueError(f"Invalid SPSDK_CACHE_FOLDER path: {SPSDK_CACHE_FOLDER}")
        return SPSDK_CACHE_FOLDER

    return SPSDK_PLATFORM_DIRS.user_cache_dir


class SPSDKErrorMissingDevice(SPSDKError):
    """SPSDK exception for missing device in database operations.

    This exception is raised when attempting to access or reference a device
    that is not found in the SPSDK device database, providing specific error
    context about the missing device.
    """

    def __init__(
        self, desc: Optional[str] = None, missing_device_name: Optional[str] = None
    ) -> None:
        """Initialize the SPSDKErrorMissingDevice exception.

        :param desc: Description of the error.
        :param missing_device_name: Name of the missing device.
        """
        super().__init__()
        self.description = desc
        self.dev_name = missing_device_name


class Features:
    """Device revision feature container for SPSDK database operations.

    This class encapsulates feature data for a specific device revision, providing
    methods to query and retrieve feature values with type safety and validation.
    It serves as the primary interface for accessing device-specific capabilities
    and configuration options within the SPSDK database system.
    """

    def __init__(
        self, name: str, is_latest: bool, device: "Device", features: dict[str, dict[str, Any]]
    ) -> None:
        """Initialize a Features instance.

        :param name: Revision name.
        :param is_latest: Flag indicating if this revision is the latest.
        :param device: Reference to its device.
        :param features: Dictionary of features.
        """
        self.name = name
        self.is_latest = is_latest
        self.device = device
        self.features = features

    def __str__(self) -> str:
        """Return a human-readable string representation of the Features object.

        :return: String containing the name, is_latest flag, and device information.
        """
        return f"Features(name='{self.name}', is_latest={self.is_latest}, device={self.device})"

    def __repr__(self) -> str:
        """Return a string representation of the Features object.

        :return: String representation in format 'Features(device_name[feature_name])'.
        """
        return f"Features({self.device.name}[{self.name}])"

    def check_key(self, feature: str, key: Union[list[str], str]) -> bool:
        """Check if the key exists in the database.

        :param feature: Feature name.
        :param key: Item key or key path as a list (e.g., ['grp1', 'grp2', 'key']).
        :raises SPSDKValueError: If the feature is unsupported.
        :return: True if the key exists, False otherwise.
        """
        if feature not in self.features:
            raise SPSDKValueError(f"Unsupported feature: '{feature}'")
        db_dict = self.features[feature]

        if isinstance(key, list):
            while len(key) > 1:
                act_key = key.pop(0)
                if act_key not in db_dict or not isinstance(db_dict[act_key], dict):
                    return False
                db_dict = db_dict[act_key]
            key = key[0]

        assert isinstance(key, str)
        return key in db_dict

    def get_value(self, feature: str, key: Union[list[str], str], default: Any = None) -> Any:
        """Get a value from the feature dictionary.

        The method supports both simple keys and nested key paths for accessing hierarchical data
        structures within feature dictionaries.

        :param feature: Feature name to access in the database.
        :param key: Item key or key path as a list (e.g., ['grp1', 'grp2', 'key']).
        :param default: Default value if the key is missing.
        :raises SPSDKValueError: If the feature is unsupported or the item is unavailable.
        :return: Value from the feature dictionary.
        """
        if feature not in self.features:
            raise SPSDKValueError(f"Unsupported feature: '{feature}'")
        db_dict = self.features[feature]

        if isinstance(key, list):
            while len(key) > 1:
                act_key = key.pop(0)
                if act_key not in db_dict or not isinstance(db_dict[act_key], dict):
                    if default is not None:
                        return default
                    raise SPSDKValueError(f"Non-existing nested group: '{act_key}'")
                db_dict = db_dict[act_key]
            key = key[0]

        assert isinstance(key, str)
        val = db_dict.get(key, default)

        if val is None:
            raise SPSDKValueError(f"Unavailable item '{key}' in feature '{feature}'")
        return val

    def get_bool(
        self, feature: str, key: Union[list[str], str], default: Optional[bool] = None
    ) -> bool:
        """Get a boolean value from the feature dictionary.

        :param feature: Feature name.
        :param key: Item key or key path as a list (e.g., ['grp1', 'grp2', 'key']).
        :param default: Default value if the key is missing.
        :return: Boolean value from the feature dictionary.
        """
        val = self.get_value(feature, key, default)
        return value_to_bool(val)

    def get_int(
        self, feature: str, key: Union[list[str], str], default: Optional[int] = None
    ) -> int:
        """Get an integer value from the feature dictionary.

        :param feature: Feature name.
        :param key: Item key or key path as a list (e.g., ['grp1', 'grp2', 'key']).
        :param default: Default value if the key is missing.
        :return: Integer value from the feature dictionary.
        """
        val = self.get_value(feature, key, default)
        return value_to_int(val)

    def get_str(
        self, feature: str, key: Union[list[str], str], default: Optional[str] = None
    ) -> str:
        """Get a string value from the feature dictionary.

        Retrieves a string value from the specified feature using the provided key or key path.
        The method ensures type safety by asserting the returned value is a string.

        :param feature: Feature name to search in.
        :param key: Item key or key path as a list (e.g., ['grp1', 'grp2', 'key']).
        :param default: Default value if the key is missing.
        :return: String value from the feature dictionary.
        """
        val = self.get_value(feature, key, default)
        assert isinstance(val, str)
        return val

    def get_list(
        self, feature: str, key: Union[list[str], str], default: Optional[list] = None
    ) -> list[Any]:
        """Get a list value from the feature dictionary.

        This method retrieves a value from the specified feature and ensures it is a list type.
        If the retrieved value is not a list, an assertion error will be raised.

        :param feature: Feature name to look up in the database.
        :param key: Item key or key path as a list (e.g., ['grp1', 'grp2', 'key']).
        :param default: Default value if the key is missing.
        :return: List value from the feature dictionary.
        """
        val = self.get_value(feature, key, default)
        assert isinstance(val, list)
        return val

    def get_dict(
        self, feature: str, key: Union[list[str], str], default: Optional[dict] = None
    ) -> dict:
        """Get a dictionary value from the feature dictionary.

        Retrieves a dictionary value from the specified feature using the provided key or key path.
        The method ensures the returned value is a dictionary type through assertion.

        :param feature: Feature name to search in.
        :param key: Item key or key path as a list (e.g., ['grp1', 'grp2', 'key']).
        :param default: Default value if the key is missing.
        :raises AssertionError: If the retrieved value is not a dictionary.
        :return: Dictionary value from the feature dictionary.
        """
        val = self.get_value(feature, key, default)
        assert isinstance(val, dict)
        return val

    def get_file_path(
        self,
        feature: str,
        key: Union[list[str], str],
        default: Optional[str] = None,
        just_standard_lib: bool = False,
    ) -> str:
        """Get a file path value from the feature dictionary.

        The method retrieves a string value from the feature dictionary and converts it to an
        absolute file path using the device's file path creation method.

        :param feature: Feature name to look up in the database.
        :param key: Item key or key path as a list (e.g., ['grp1', 'grp2', 'key']).
        :param default: Default value if the key is missing.
        :param just_standard_lib: Use only standard library files (no restricted data or addons).
        :return: Absolute file path for the device.
        """
        file_name = self.get_str(feature, key, default)
        return self.device.create_file_path(file_name, just_standard_lib)


class Revisions(list[Features]):
    """Device revision collection for SPSDK operations.

    This class extends the built-in list to store and manage Features objects
    representing different device revisions, providing convenient access methods
    for retrieving revisions by name or getting the latest available revision.
    """

    def revision_names(self, append_latest: bool = False) -> list[str]:
        """Get a list of revision names.

        :param append_latest: If True, append "latest" to the list of revision names.
        :return: List of all supported device revision names.
        """
        ret = [rev.name for rev in self]
        if append_latest:
            ret.append("latest")
        return ret

    def get(self, name: Optional[str] = None) -> Features:
        """Get the revision by its name.

        If name is not specified, or equal to 'latest', then the latest revision is returned.

        :param name: The revision name to retrieve.
        :return: The Features object for the specified revision.
        :raises SPSDKValueError: If the requested revision is not supported.
        """
        if name is None or name == "latest":
            revision = find_first(self, lambda rev: rev.is_latest)
        else:
            revision = find_first(self, lambda rev: rev.name == name)
        if not revision:
            raise SPSDKValueError(f"Requested revision {name} is not supported.")
        return revision


class UsbId:
    """USB identifier for device communication.

    This class represents a USB device identifier consisting of Vendor ID (VID)
    and Product ID (PID) values. It provides functionality for creating, updating,
    validating, and comparing USB identifiers used in device communication and
    configuration management.
    """

    def __init__(self, vid: Optional[int] = None, pid: Optional[int] = None) -> None:
        """Initialize a USB ID instance.

        :param vid: USB Vendor ID (optional).
        :param pid: USB Product ID (optional).
        """
        self.vid = vid
        self.pid = pid

    def __str__(self) -> str:
        """Return a string representation of the USB ID.

        :return: String in the format '[0xPID:0xVID]'.
        """
        return f"[0x{self.pid:04X}:0x{self.vid:04X}]"

    def __eq__(self, obj: Any) -> bool:
        """Check equality with another object.

        :param obj: Object to compare with.
        :return: True if obj is a UsbId instance with matching vid and pid, False otherwise.
        """
        return isinstance(obj, self.__class__) and self.vid == obj.vid and self.pid == obj.pid

    def update(self, usb_config: dict) -> None:
        """Update the USB ID from a configuration dictionary.

        :param usb_config: Dictionary containing 'vid' and/or 'pid' keys with USB vendor and product IDs.
        """
        self.vid = usb_config.get("vid", self.vid)
        self.pid = usb_config.get("pid", self.pid)

    @classmethod
    def load(cls, usb_config: dict) -> Self:
        """Create a UsbId instance from a configuration dictionary.

        The method extracts vendor ID and product ID from the provided configuration
        dictionary and creates a new UsbId instance with these values.

        :param usb_config: Dictionary containing 'vid' and/or 'pid' keys with USB identifiers.
        :return: New UsbId instance with configured vendor and product IDs.
        """
        return cls(vid=usb_config.get("vid", None), pid=usb_config.get("pid", None))

    def is_valid(self) -> bool:
        """Check if the USB ID is valid.

        The method validates that both vendor ID and product ID are properly set
        and not None values.

        :return: True if both vid and pid are set, False otherwise.
        """
        return self.vid is not None and self.pid is not None


class Bootloader:
    """SPSDK Bootloader representation.

    This class encapsulates bootloader configuration including protocol type,
    supported interfaces, USB identification, and protocol-specific parameters.
    It provides functionality for loading bootloader configurations from
    dictionaries and managing bootloader connection details across NXP MCU devices.
    """

    def __init__(
        self,
        protocol: Optional[str],
        interfaces: list,
        usb_id: UsbId,
        protocol_params: dict,
    ) -> None:
        """Initialize a Bootloader instance.

        :param protocol: Name of the bootloader protocol (e.g., 'mboot', 'sdp', 'sdps', 'lpc')
        :param interfaces: List of supported interfaces
        :param usb_id: USB identifier for the bootloader
        :param protocol_params: Dictionary of protocol-specific parameters
        :raises SPSDKValueError: If an invalid protocol value is provided
        """
        if protocol and protocol not in ["mboot", "sdp", "sdps", "lpc"]:
            raise SPSDKValueError(f"Invalid protocol value: {protocol}")
        self.protocol = protocol
        self.interfaces = interfaces
        self.usb_id = usb_id
        self.protocol_params = protocol_params

    def __str__(self) -> str:
        """Return a string representation of the Bootloader.

        Creates a formatted multi-line string containing bootloader protocol information,
        supported interfaces, and USB identification details when available.

        :return: Formatted string with bootloader details including protocol, interfaces, and USB ID.
        """
        ret = ""
        ret += f"Protocol:     {self.protocol or 'Not specified'}\n"
        ret += f"Interfaces:   {self.interfaces}"
        if self.usb_id.vid:
            ret += f"\nUSB ID:       {str(self.usb_id)}"
        return ret

    @classmethod
    def load(cls, config: dict) -> Self:
        """Create a Bootloader instance from a configuration dictionary.

        :param config: Dictionary containing bootloader configuration with keys like 'protocol',
            'interfaces', 'usb', and 'protocol_params'.
        :return: New Bootloader instance configured with the provided parameters.
        """
        return cls(
            protocol=config.get("protocol", None),
            interfaces=config.get("interfaces", []),
            usb_id=UsbId.load(config.get("usb", {})),
            protocol_params=config.get("protocol_params", {}),
        )

    def update(self, config: dict) -> None:
        """Update the Bootloader instance from a configuration dictionary.

        This method updates the bootloader's protocol, interfaces, protocol parameters,
        and USB ID configuration based on the provided configuration dictionary.

        :param config: Dictionary containing updated bootloader configuration with optional
            keys: 'protocol', 'interfaces', 'protocol_params', and 'usb'.
        """
        self.protocol = config.get("protocol", self.protocol)
        self.interfaces = config.get("interfaces", self.interfaces)
        self.protocol_params = config.get("protocol_params", self.protocol_params)
        self.usb_id.update(config.get("usb", {}))


class MemBlock:
    """Memory block representation from device memory map.

    This class represents a single memory block within a device's memory map,
    providing access to memory block properties such as base address, size,
    and external memory classification. It supports parsing of memory block
    names including core, block type, and instance identification.

    :cvar BLOCK_NAMES: List of supported memory block type names.
    :cvar CORES: List of supported processor core identifiers.
    :cvar SECURITY: List of supported security domain identifiers.
    """

    # List of known and accepted cores
    BLOCK_NAMES = [
        "dtcm",
        "itcm",
        "system-tcm",
        "code-tcm",
        "ram",
        "dram",
        "sdram",
        "sram",
        "sramx",
        "sram-l",
        "sram-u",
        "ocram",
        "ocram-ecc",
        "usb-ram",
        "flash-logical-window",
        "flexspi",
        "xspi",
        "internal-flash",
        "ifr-bank",
    ]
    CORES = ["a55", "cm7", "cm4", "cm33", "cm0", "cm0p"]
    SECURITY = ["s", "ns"]

    def __init__(self, name: str, desc: dict[str, Any]) -> None:
        """Initialize a MemBlock instance.

        :param name: Name of the memory block.
        :param desc: Dictionary containing the memory block description with configuration data.
        """
        self.name = name
        self.description = desc

    def __str__(self) -> str:
        """Return a string representation of the MemBlock.

        The string includes the memory block name, base address in hexadecimal format,
        size in human-readable format, and external flag status.

        :return: Formatted string with memory block details including name, base address, size, and external flag.
        """
        ret = self.name + ":\n"
        ret += f"  Base:     0x{self.base_address:08X}\n"
        ret += f"  Size:     {size_fmt(self.size,use_kibibyte=True)}\n"
        ret += f"  External: {self.external}"
        return ret

    def __repr__(self) -> str:
        """Return a string representation of the MemBlock object.

        :return: String representation including name, base address, and size.
        """
        return f"MemBlock(name='{self.name}', base=0x{self.base_address:08X}, size={self.size})"

    @property
    def base_address(self) -> int:
        """Get the base address of the memory block.

        :return: Base address as an integer.
        """
        return value_to_int(self.description["start_int"])

    @property
    def size(self) -> int:
        """Get the size of the memory block.

        :return: Size in bytes as an integer.
        """
        return value_to_int(self.description["size_int"])

    @property
    def external(self) -> bool:
        """Check if this is an external memory block.

        The method checks the 'external' field in the description dictionary to determine
        if the memory block is configured as external memory.

        :return: True if external, False otherwise.
        """
        return value_to_bool(self.description.get("external", False))

    @classmethod
    def parse_name(cls, name: str) -> tuple[Optional[str], str, Optional[int], Optional[bool]]:
        """Parse name to base elements.

        Parses a memory block name string into its constituent components including
        core name, memory name, instance index, and security access flag.

        :param name: Name of the memory block to parse.
        :raises SPSDKError: Invalid memory block name format or unknown security flag.
        :return: Tuple of:
            - Optional Core name
            - Name of memory
            - Optional index of memory
            - Optional boolean if secure access
        """
        el_cnt = name.count("_")
        core = None
        raw_name = ""
        raw_security = None
        if el_cnt == 0:
            raw_name = name
        elif el_cnt == 1:
            ix = name.find("_")
            if name[ix + 1 :] in cls.SECURITY:
                raw_name = name[:ix]
                raw_security = name[ix + 1 :]
            else:
                raw_name = name[ix + 1 :]
                core = name[:ix]
        elif el_cnt == 2:
            ix = name.find("_")
            core = name[:ix]
            ix_2nd = name.find("_", ix + 1)
            raw_name = name[ix + 1 : ix_2nd]
            raw_security = name[ix_2nd + 1 :]
            if raw_security not in cls.SECURITY:
                raise SPSDKError(f"Invalid security flag in memory block name: {raw_security}")
        else:
            raise SPSDKError(f"Database memory block parse name failed on: {name}")
        regex = re.compile(r"(?P<value>[a-zA-Z\-]+)(?P<instance>\d+)?")
        res = regex.match(raw_name)
        if res is None:
            raise SPSDKError(f"Database memory block parse name failed on: {name}")
        name = res.group("value")
        if name not in cls.BLOCK_NAMES:
            raise SPSDKError(f"Database memory block parse name failed on: {name}")
        raw_instance = res.group("instance")
        instance = int(raw_instance) if raw_instance else None
        security = bool(raw_security == "s") if raw_security else None

        return (core, name, instance, security)

    @property
    def core(self) -> Optional[str]:
        """Get core name if specified.

        Extracts the core name from the parsed device name using the parse_name method.

        :return: Core name if present in the device name, None otherwise.
        """
        core, _, _, _ = self.parse_name(self.name)
        return core

    @property
    def block_name(self) -> str:
        """Get block name from the parsed name.

        Extracts and returns the block name component by parsing the instance name
        using the parse_name method.

        :return: The block name component extracted from the parsed name.
        """
        _, block_name, _, _ = self.parse_name(self.name)
        return block_name

    @property
    def instance(self) -> Optional[int]:
        """Get instance if specified.

        :return: Instance number if present in the name, None otherwise.
        """
        _, _, instance, _ = self.parse_name(self.name)
        return instance

    @property
    def security_access(self) -> Optional[bool]:
        """Get security access if specified.

        The method parses the name attribute to extract security access information
        and returns whether security access is enabled or not.

        :return: True if security access is enabled, False if disabled, None if not specified.
        """
        _, _, _, sec_acc = self.parse_name(self.name)
        return sec_acc

    @classmethod
    def create_name(
        cls,
        block_name: str,
        core: Optional[str] = None,
        instance: Optional[int] = None,
        secure_access: Optional[bool] = None,
    ) -> str:
        """Create full name of memory block.

        The method constructs a memory block name by combining core name, block name, instance number,
        and secure access specification into a standardized format.

        :param block_name: Name of memory block
        :param core: Optional core name, defaults to None
        :param instance: Optional instance number, defaults to None
        :param secure_access: Optional specification if block has secure or non secure access,
            defaults to None
        :raises SPSDKError: Unknown core name provided
        :return: Full block name with optional core prefix, instance suffix, and security suffix
        """
        ret = ""
        if core:
            if core not in cls.CORES:
                raise SPSDKError(
                    f"Cannot create full memory block name cause unknown core name: {core}"
                )
            ret = core + "_"
        ret += block_name
        if instance is not None:
            ret += str(instance)
        if secure_access is not None:
            ret += "_s" if secure_access else "_ns"
        return ret


class MemMap:
    """Device memory map configuration manager.

    This class manages memory block configurations for NXP MCU devices, providing
    functionality to load, organize, and query memory layout information. It handles
    memory block definitions including base addresses, sizes, and access properties.
    """

    def __init__(self, mem_map: dict[str, MemBlock]) -> None:
        """Initialize device memory map configuration.

        :param mem_map: Dictionary mapping memory region names to MemBlock objects.
        """
        self._mem_map = mem_map

    def __str__(self) -> str:
        """Get string representation of the memory map.

        The method iterates through all memory blocks in the memory map and
        concatenates their string representations with newlines.

        :return: String representation of all memory blocks in the memory map.
        """
        ret = ""
        for block in self._mem_map.values():
            ret += str(block) + "\n"
        return ret

    def get_table(self) -> str:
        """Get string table with memory map description.

        Creates a formatted table showing memory blocks with their index, name, base address,
        size, and external flag. The table uses double border style for better readability.

        :return: Formatted string table containing memory map information.
        """
        table_p = prettytable.PrettyTable(["#", "Block", "Base", "Size", "External"])
        table_p.set_style(prettytable.TableStyle.DOUBLE_BORDER)
        for i, block in enumerate(self._mem_map.values()):
            table_p.add_row(
                [
                    str(i),
                    block.name,
                    f"0x{block.base_address:08X}",
                    size_fmt(block.size, use_kibibyte=True),
                    block.external,
                ]
            )
        return str(table_p)

    @classmethod
    def load(cls, mem_map: dict[str, dict[str, Any]]) -> Self:
        """Load the Memory map from configuration.

        Creates a new instance by converting dictionary configuration into MemBlock objects.

        :param mem_map: Dictionary with all blocks where keys are block names and values are block configurations.
        :return: New instance with loaded memory blocks.
        """
        ret = {}
        for k, v in mem_map.items():
            ret[k] = MemBlock(name=k, desc=v)
        return cls(ret)

    def get_memory(
        self,
        block_name: str,
        core: Optional[str] = None,
        instance: Optional[int] = None,
        secure: Optional[bool] = None,
    ) -> MemBlock:
        """Get the memory block by specified parameters.

        The method searches for a memory block using the provided parameters. If the exact
        match is not found and secure parameter is None, it attempts to find the block
        with secure_access set to False as a fallback.

        :param block_name: Core block name to search for.
        :param core: Optional core name, defaults to None.
        :param instance: Optional instance number, defaults to None.
        :param secure: Optional selection of secure/non-secure memory access, defaults to None.
        :return: Memory block matching the specified parameters.
        :raises SPSDKError: Block has not been found with given parameters.
        """
        # First try:
        name = MemBlock.create_name(
            block_name=block_name, core=core, instance=instance, secure_access=secure
        )
        if name in self._mem_map:
            return self._mem_map[name]

        # Second Try - MAybe we have stored memory as none secure
        if secure is None:
            name = MemBlock.create_name(
                block_name=block_name, core=core, instance=instance, secure_access=False
            )
            if name in self._mem_map:
                return self._mem_map[name]
        raise SPSDKError("Block has not been found")

    def find_memory_blocks(
        self,
        block_name: Optional[str] = None,
        core: Optional[str] = None,
        instance: Optional[int] = None,
        secure_access: Optional[bool] = None,
        external: Optional[bool] = None,
        name_regex: Optional[str] = None,
        base_address_range: Optional[tuple[int, int]] = None,
    ) -> list[MemBlock]:
        """Find memory blocks matching the specified criteria.

        All criteria are optional and combined with logical AND. If a criterion is None, it's not used
        for filtering.

        :param block_name: Exact block name to match.
        :param core: Core name to match.
        :param instance: Instance number to match.
        :param secure_access: Security access flag to match.
        :param external: External memory flag to match.
        :param name_regex: Regular expression pattern to match against the full block name.
        :param base_address_range: Tuple of (min_address, max_address) to match blocks within address
            range.
        :return: List of memory blocks matching all specified criteria.
        """
        result = []

        for block in self._mem_map.values():
            # Skip if block name doesn't match
            if block_name is not None and block.block_name != block_name:
                continue

            # Skip if core doesn't match
            if core is not None and block.core != core:
                continue

            # Skip if instance doesn't match
            if instance is not None and block.instance != instance:
                continue

            # Skip if security access doesn't match
            if secure_access is not None and block.security_access != secure_access:
                continue

            # Skip if external flag doesn't match
            if external is not None and block.external != external:
                continue

            # Skip if name doesn't match regex pattern
            if name_regex is not None and not re.search(name_regex, block.name):
                continue
            # Skip if base address is outside specified range
            if base_address_range is not None:
                min_addr, max_addr = base_address_range
                if not min_addr <= block.base_address <= max_addr:
                    continue

            # If we got here, the block matches all criteria
            result.append(block)

        return result


class IspCfg:
    """ISP Configuration Manager for NXP MCU bootloaders.

    This class manages In-System Programming (ISP) configuration data for both ROM
    and flashloader bootloaders, providing unified access to protocol support,
    USB identification, and configuration management across the SPSDK framework.
    """

    def __init__(self, rom: Bootloader, flashloader: Bootloader) -> None:
        """Initialize ISP configuration with ROM and flashloader instances.

        :param rom: ROM bootloader instance for initial communication.
        :param flashloader: Flashloader bootloader instance for memory operations.
        """
        self.rom = rom
        self.flashloader = flashloader

    def __str__(self) -> str:
        """Return string representation of the database entry.

        Provides a formatted string containing ROM and FlashLoader information
        with proper indentation for readability.

        :return: Formatted string representation of the database entry.
        """
        ret = ""
        if self.rom:
            ret += f"ROM:\n{textwrap.indent(str(self.rom), '  ')}\n"
        if self.flashloader.protocol:
            ret += f"FlashLoader:\n{textwrap.indent(str(self.flashloader), '  ')}\n"

        return ret

    @classmethod
    def load(cls, config: dict) -> Self:
        """Load database configuration from dictionary.

        Creates a new instance by loading ROM and flashloader bootloader configurations
        from the provided configuration dictionary.

        :param config: Configuration dictionary containing 'rom' and 'flashloader' keys.
        :return: New instance loaded from the configuration.
        """
        return cls(
            rom=Bootloader.load(config.get("rom", {})),
            flashloader=Bootloader.load(config.get("flashloader", {})),
        )

    def update(self, config: dict) -> None:
        """Update the object from configuration.

        This method updates both ROM and flashloader configurations from the provided
        configuration dictionary.

        :param config: Configuration dictionary containing 'rom' and/or 'flashloader' keys.
        """
        self.rom.update(config.get("rom", {}))
        self.flashloader.update(config.get("flashloader", {}))

    def is_protocol_supported(self, protocol: str) -> bool:
        """Check if any interface supports the given protocol.

        The method verifies whether either the ROM or flashloader interface
        supports the specified communication protocol.

        :param protocol: Protocol name to check for support.
        :return: True if either ROM or flashloader supports the protocol, False otherwise.
        """
        return self.rom.protocol == protocol or self.flashloader.protocol == protocol

    def get_usb_ids(self, protocol: str) -> list[UsbId]:
        """Get USB parameters for interfaces supporting given protocol.

        The method searches through ROM and flashloader interfaces to find
        USB IDs that support the specified protocol.

        :param protocol: Protocol name to search for in interfaces.
        :return: List of USB IDs supporting the specified protocol.
        """
        usb_ids = []
        if self.rom.protocol == protocol and self.rom.usb_id.is_valid():
            usb_ids.append(self.rom.usb_id)
        if self.flashloader.protocol == protocol and self.flashloader.usb_id.is_valid():
            usb_ids.append(self.flashloader.usb_id)
        return usb_ids


class DeviceInfo:
    """Device information container for NXP MCU devices.

    This class encapsulates comprehensive device information including purpose,
    memory mapping, ISP configuration, and web resources. It provides functionality
    to load device configurations from dictionaries and supports dynamic updates
    of device parameters.
    """

    def __init__(
        self,
        use_in_doc: bool,
        purpose: str,
        spsdk_predecessor_name: Optional[str],
        web: str,
        memory_map: dict[str, dict[str, Any]],
        isp: IspCfg,
    ) -> None:
        """Initialize device information class.

        :param use_in_doc: Flag indicating if device should be used in documentation.
        :param purpose: String description of purpose of MCU (device group).
        :param spsdk_predecessor_name: Device sub series name (predecessor name in SPSDK).
        :param web: Web page with device information.
        :param memory_map: Basic memory map of device.
        :param isp: Information regarding ISP mode.
        """
        self.use_in_doc = use_in_doc
        self.purpose = purpose
        self.spsdk_predecessor_name = spsdk_predecessor_name
        self.web = web
        self.memory_map = MemMap.load(memory_map)
        self.isp = isp

    def __repr__(self) -> str:
        """Return string representation of DeviceInfo object.

        :return: String representation in format 'DeviceInfo(purpose)'.
        """
        return f"DeviceInfo({self.purpose})"

    @classmethod
    def load(cls, config: dict[str, Any], defaults: dict[str, Any]) -> Self:
        """Load device configuration from provided config and defaults.

        The method merges configuration data with defaults using deep update strategy
        and creates a new device instance with the combined configuration.

        :param config: Device configuration dictionary to override defaults.
        :param defaults: Default device configuration values.
        :return: New Device instance with merged configuration.
        """
        data = deepcopy(defaults)
        deep_update(data, config)
        return cls(
            use_in_doc=bool(data.get("use_in_doc", True)),
            purpose=data["purpose"],
            spsdk_predecessor_name=data.get("spsdk_predecessor_name"),
            web=data["web"],
            memory_map=data["memory_map"],
            isp=IspCfg.load(data["isp"]),
        )

    def update(self, config: dict[str, Any]) -> None:
        """Update device information with new configuration data.

        This method updates the current device instance with values from the provided
        configuration dictionary. Only specified fields in the config will be updated,
        while unspecified fields retain their current values.

        :param config: Dictionary containing device configuration parameters to update.
        :raises SPSDKError: If memory map configuration is invalid or cannot be loaded.
        """
        self.use_in_doc = bool(config.get("use_in_doc", self.use_in_doc))
        self.purpose = config.get("purpose", self.purpose)
        self.spsdk_predecessor_name = config.get(
            "spsdk_predecessor_name", self.spsdk_predecessor_name
        )
        self.web = config.get("web", self.web)
        if "memory_map" in config:
            self.memory_map = MemMap.load(config["memory_map"])
        self.isp.update(config.get("isp", {}))


class Device:
    """SPSDK Device representation for hardware configuration management.

    This class represents a single device in the SPSDK database, managing device-specific
    information including revisions, features, and configuration data. It provides
    functionality for device identification, feature retrieval, and configuration
    file path resolution across different device revisions.
    """

    def __init__(
        self,
        name: str,
        db: "Database",
        latest_rev: str,
        info: DeviceInfo,
        device_alias: Optional["Device"] = None,
        revisions: Revisions = Revisions(),
    ) -> None:
        """Initialize SPSDK Device instance.

        Creates a new Device object with specified configuration including name, database reference,
        revision information, and optional device alias.

        :param name: Device name that will be converted to lowercase.
        :param db: Parent Database object containing this device.
        :param latest_rev: Name of the latest available revision.
        :param info: Device information object containing device details.
        :param device_alias: Optional alias device reference, defaults to None.
        :param revisions: Device revisions collection, defaults to empty Revisions().
        """
        self.name = name.lower()
        self.db = db
        self.latest_rev = latest_rev
        self.device_alias = device_alias
        self.revisions = revisions
        self.info = info

    def get_copy(self, new_name: Optional[str] = None) -> "Device":
        """Create a deep copy of the Device instance.

        This method creates a complete copy of the device including all its revisions,
        features, and metadata. The copy is independent of the original instance.

        :param new_name: Optional new name for the copied device, defaults to original name.
        :return: Deep copy of the Device instance with optionally updated name.
        """
        name = new_name or self.name
        name = name.lower()
        ret = Device(
            name=name,
            db=self.db,
            latest_rev=self.latest_rev,
            info=deepcopy(self.info),
            device_alias=self.device_alias,
        )
        # copy all revisions
        revisions = Revisions()
        for features in self.revisions:
            revisions.append(
                Features(
                    name=features.name,
                    is_latest=features.is_latest,
                    device=ret,
                    features=deepcopy(features.features),
                )
            )
        ret.revisions = revisions
        return ret

    def __repr__(self) -> str:
        """Return string representation of the Device object.

        :return: String in format "Device(<device_name>)".
        """
        return f"Device({self.name})"

    def __lt__(self, other: "Device") -> bool:
        """Less than comparison based on name.

        :param other: Another Device instance to compare with.
        :return: True if this device's name is lexicographically less than the other device's name.
        """
        return self.name < other.name

    def get_features(self, revision: Optional[str] = None) -> list[str]:
        """Get the list of device features.

        :param revision: Device revision to get features for. If None, uses default revision.
        :return: List of feature names available for the specified device revision.
        """
        return [str(k) for k in self.revisions.get(revision).features.keys()]

    @staticmethod
    def _load_alias(name: str, db: "Database", dev_cfg: dict[str, Any]) -> "Device":
        """Load device alias from configuration and create a copy with customizations.

        Creates a device instance based on an existing device (alias) with potential
        modifications to features, revisions, and device information. Handles both
        updates to existing revisions and creation of new revisions with aliases.

        :param name: The name of the new device alias.
        :param db: Database parent object containing device definitions.
        :param dev_cfg: Device configuration dictionary with alias and customizations.
        :raises SPSDKError: When alias key is missing for new revision definition.
        :return: Device object configured as alias with applied customizations.
        """
        name = name.lower()
        dev_alias_name = dev_cfg["alias"]
        # Let get() function raise exception in case that device not exists in database
        ret = db.devices.get(dev_alias_name).get_copy(name)
        ret.device_alias = db.devices.get(dev_alias_name)
        dev_features: dict[str, dict] = dev_cfg.get("features", {})
        dev_revisions: dict[str, dict] = dev_cfg.get("revisions", {})
        assert isinstance(dev_features, dict)
        assert isinstance(dev_revisions, dict)
        ret.latest_rev = dev_cfg.get("latest", ret.latest_rev)
        # First of all update general changes in features
        if dev_features:
            for rev in ret.revisions:
                deep_update(rev.features, dev_features)

        for rev_name, rev_updates in dev_revisions.items():
            try:
                dev_rev = ret.revisions.get(rev_name)
            except SPSDKValueError as exc:
                # In case of newly defined revision, there must be defined alias
                alias_rev = rev_updates.get("alias")
                if not alias_rev:
                    raise SPSDKError(
                        f"There is missing alias key in new revision ({rev_name}) of aliased device {ret.name}"
                    ) from exc
                dev_rev = deepcopy(ret.revisions.get(alias_rev))
                dev_rev.name = rev_name
                dev_rev.is_latest = bool(ret.latest_rev == rev_name)
                ret.revisions.append(dev_rev)

            # Update just same rev
            rev_specific_features = rev_updates.get("features")
            if rev_specific_features:
                deep_update(dev_rev.features, rev_specific_features)

        # remove redundant spsdk_predecessor_name
        ret.info.spsdk_predecessor_name = None

        if "info" in dev_cfg:
            ret.info.update(dev_cfg["info"])

        return ret

    @staticmethod
    def load(name: str, db: "Database") -> "Device":
        """Load device configuration from database folder.

        Loads device configuration from the database folder structure, including
        base configuration and any addon data. Handles device aliases and builds
        complete device object with all revisions and features.

        :param name: The name of device to load (case insensitive).
        :param db: Base database object containing device data.
        :raises SPSDKErrorMissingDevice: Device doesn't exist in database.
        :raises SPSDKError: Latest revision not found in supported revisions.
        :return: The Device object with loaded configuration and revisions.
        """
        name = name.lower()
        try:
            dev_cfg = load_configuration(
                db.get_data_file_path(os.path.join("devices", name, "database.yaml"))
            )
        except SPSDKError as exc:
            raise SPSDKErrorMissingDevice(
                f"Cannot load the device '{name}' - Doesn't exists in database."
            ) from exc

        # Update database by addons data
        if db._data.addons_data_path:
            addons_db_path = os.path.join(
                db._data.addons_data_path, "devices", name, "database.yaml"
            )
            if os.path.exists(addons_db_path):
                dev_cfg.update(load_configuration(addons_db_path))

        dev_alias_name = dev_cfg.get("alias")
        if dev_alias_name:
            return Device._load_alias(name=name, db=db, dev_cfg=dev_cfg)

        dev_features: dict[str, dict] = dev_cfg["features"]
        features_defaults: dict[str, dict] = deepcopy(db._data.defaults["features"])

        dev_info = DeviceInfo.load(dev_cfg["info"], db._data.defaults["info"])

        # Get defaults and update them by device specific data set
        for feature_name in dev_features:
            deep_update(features_defaults[feature_name], dev_features[feature_name])
            dev_features[feature_name] = features_defaults[feature_name]

        revisions = Revisions()
        dev_revisions: dict[str, dict] = dev_cfg["revisions"]
        latest: str = dev_cfg["latest"]
        if latest not in dev_revisions:
            raise SPSDKError(
                f"The latest revision defined in database for {name} is not in supported revisions"
            )

        ret = Device(name=name, db=db, info=dev_info, latest_rev=latest, device_alias=None)

        for rev, rev_updates in dev_revisions.items():
            features = deepcopy(dev_features)
            rev_specific_features = rev_updates.get("features")
            if rev_specific_features:
                deep_update(features, rev_specific_features)
            revisions.append(
                Features(name=rev, is_latest=bool(rev == latest), features=features, device=ret)
            )

        ret.revisions = revisions

        return ret

    def create_file_path(self, file_name: str, just_standard_lib: bool = False) -> str:
        """Create file path for the specified device.

        The method searches for the file in the device-specific directory within the database.
        If the file is not found and a device alias exists, it attempts to find the file
        using the alias device path as fallback.

        :param file_name: File name to be enriched by device path.
        :param just_standard_lib: Use just standard library files (no restricted data,
            neither addons), defaults to False.
        :raises SPSDKValueError: Non existing file in database.
        :return: File path value for the device.
        """
        path = self.db.get_data_file_path(
            os.path.join("devices", self.name, file_name),
            exc_enabled=False,
            just_standard_lib=just_standard_lib,
        )
        if not os.path.exists(path) and self.device_alias:
            path = self.device_alias.create_file_path(file_name)

        if not os.path.exists(path):
            raise SPSDKValueError(f"Non existing file ({file_name}) in database")
        return path


class Devices:
    """SPSDK device collection manager.

    This class manages a collection of devices from the SPSDK database, providing
    functionality to load, store, and retrieve device configurations. It serves as
    a container for Device objects and handles device name resolution including
    legacy SPSDK device names.
    """

    def __init__(self, db: "Database") -> None:
        """Initialize managed devices container for database operations.

        Creates a new instance to manage device collections within the database context.

        :param db: Database instance containing device configurations and metadata.
        """
        self.devices: list[Device] = []
        self.db = db

    def get(self, name: str) -> Device:
        """Get device configuration from database.

        Retrieves the device structure for the specified device name. The method
        handles device name normalization and lazy loading of device configurations.

        :param name: Device name or family identifier.
        :raises SPSDKErrorMissingDevice: If the device name is not specified or not found in database.
        :return: Device configuration structure.
        """
        # Check device name (it could be used predecessor SPSDK name)
        if not name:
            raise SPSDKErrorMissingDevice("The device name (family) is not specified.")
        name = name.lower()
        if DatabaseManager()._quick_info:
            name = DatabaseManager().quick_info.devices.get_correct_name(name)
        if name not in self._devices_names:
            self._load_and_append_device(name)
        dev = find_first(self.devices, lambda dev: dev.name == name)
        if not dev:
            raise SPSDKErrorMissingDevice(
                desc=f"The device with name {name} is not in the database.",
                missing_device_name=name,
            )
        return dev

    @property
    def _devices_names(self) -> list[str]:
        """Get the list of device names.

        :return: List of device names from the database.
        """
        return [dev.name for dev in self.devices]

    def feature_items(self, feature: str, key: str) -> Iterator[tuple[str, str, Any]]:
        """Iterate through the database to find feature items across all devices and revisions.

        The method searches through all devices and their revisions for a specific feature,
        then extracts the specified key value from that feature's configuration.

        :param feature: Name of the feature to search for in device configurations.
        :param key: Specific key within the feature to extract the value from.
        :raises SPSDKValueError: When the specified key is missing in the feature configuration.
        :return: Iterator yielding tuples of (device name, revision name, feature value).
        """
        for device in self.devices:
            for rev in device.revisions:
                if feature not in device.get_features(rev.name):
                    continue
                value = rev.features[feature].get(key)
                if value is None:
                    raise SPSDKValueError(f"Missing item '{key}' in feature '{feature}'!")
                yield (device.name, rev.name, value)

    def _load_and_append_device(self, dev_name: str) -> None:
        """Load and append device to the devices.

        The method handles device loading with duplicate prevention and recursive dependency
        resolution. If a device is already loaded, it skips the operation. When a missing
        device dependency is encountered, it recursively loads the required device first.

        :param dev_name: Name of the device to load and append to the devices list.
        :raises SPSDKErrorMissingDevice: When device cannot be found and no fallback available.
        """
        # Omit already loaded devices (used for multiple calls of this method (restricted data))
        dev_name = dev_name.lower()
        if dev_name in self._devices_names:
            logger.debug(f"The device '{dev_name}' is already in database.")
            return
        try:
            self.devices.append(Device.load(name=dev_name, db=self.db))
        except SPSDKErrorMissingDevice as exc:
            if exc.dev_name:
                self._load_and_append_device(dev_name=exc.dev_name)
                self.devices.append(Device.load(name=dev_name, db=self.db))
            else:
                raise exc

    def load_devices_from_path(self, devices_path: str) -> None:
        """Load devices from SPSDK database path.

        Scans the specified directory for device folders and attempts to load each device
        into the database. If loading a device fails, an error is logged but the process
        continues with remaining devices.

        :param devices_path: Path to directory containing device folders to load.
        :raises SPSDKError: When device loading fails (logged but not propagated).
        """
        for dev in os.scandir(devices_path):
            if dev.is_dir():
                try:
                    self._load_and_append_device(dev.name)
                except SPSDKError as exc:
                    logger.error(
                        f"Failed loading device '{dev.name}' into SPSDK database. Details:\n{str(exc)}"
                    )


class DeviceQuickInfo:
    """Device quick information container for SPSDK operations.

    This class provides a convenient interface for accessing device features, revisions,
    and capabilities. It manages feature availability across different device revisions
    and enables quick lookups for supported functionality during provisioning operations.
    """

    def __init__(self, features: Revisions, info: DeviceInfo, latest_rev: str) -> None:
        """Initialize Device quick information.

        Creates a new Device instance with features organized by revision for easy access.

        :param features: Device features collection containing revision-specific feature data.
        :param info: Device information object with basic device details.
        :param latest_rev: Latest chip revision identifier string.
        """
        self.revision_features: dict[str, dict[str, Optional[list]]] = {}
        self.info = info
        self.latest_rev = latest_rev.lower()
        for rev in features:
            self.revision_features[rev.name] = {}
            for k, v in rev.features.items():
                self.revision_features[rev.name][k] = v.get("sub_features")

    @property
    def revisions(self) -> list[str]:
        """Get list of available revisions.

        :return: List of revision names that are available in the database.
        """
        return list(self.revision_features.keys())

    def get_features(self, revision: Optional[str] = None) -> list[str]:
        """Get list of all supported features of device.

        Retrieves all available features for the specified device revision or the latest
        revision if none is provided.

        :param revision: Device revision to get features for, defaults to latest revision.
        :return: List of supported feature names for the specified revision.
        """
        revision = revision or self.latest_rev
        return list(self.revision_features[revision].keys())

    def is_feature_supported(
        self, feature: str, sub_feature: Optional[str] = None, revision: Optional[str] = None
    ) -> bool:
        """Check if a feature is supported by the device.

        The method verifies feature availability for a specific device revision,
        with optional sub-feature granularity checking.

        :param feature: Feature name to check for support.
        :param sub_feature: Sub feature name for more granular checking, defaults to None.
        :param revision: Specific device revision to check, defaults to latest revision.
        :return: True if the feature is supported by the device, False otherwise.
        """
        features = self.revision_features[revision or self.latest_rev]
        if feature in features:
            if sub_feature:
                if features[feature] is None:
                    return False
                sub_features: list = features[feature] or []
                return sub_feature in sub_features
            return True
        return False


class DevicesQuickInfo:
    """SPSDK device quick information manager.

    This class provides fast access to device information and features across
    the NXP MCU portfolio. It maintains a lookup table of devices with their
    capabilities and supports feature-based device discovery and predecessor
    device mapping.
    """

    def __init__(self) -> None:
        """Initialize devices database for quick device information lookup.

        Creates empty dictionaries for storing device information and predecessor
        relationships used for device compatibility and feature queries.
        """
        self.devices: dict[str, DeviceQuickInfo] = {}
        self.predecessor_lookup: dict[str, str] = {}

    @staticmethod
    def create(devices: Devices) -> "DevicesQuickInfo":
        """Create quick info about devices.

        Creates a DevicesQuickInfo object containing essential device information and predecessor
        lookup mapping from the full devices description.

        :param devices: Full devices description containing all device details.
        :return: DevicesQuickInfo object with device quick info and predecessor lookup.
        """
        dqi = {}
        pl = {}
        for dev in devices.devices:
            info = DeviceQuickInfo(dev.revisions, dev.info, dev.latest_rev)
            p_name = info.info.spsdk_predecessor_name
            if p_name:
                if p_name not in pl:
                    pl[p_name] = dev.name

            dqi[dev.name] = info

        ret = DevicesQuickInfo()

        ret.devices = dqi
        ret.predecessor_lookup = pl

        return ret

    def get_feature_list(self, family: str, revision: Optional[str] = None) -> list[str]:
        """Get features list for specified device family.

        If device database is empty, returns an empty list. Otherwise returns
        the list of supported features for the given family and optional revision.

        :param family: Device family name to get features for.
        :param revision: Optional device revision to filter features.
        :return: List of supported feature names for the device.
        """
        if self.devices == {}:
            return []
        return self.devices[family.lower()].get_features(revision)

    def get_devices_with_feature(
        self, feature: str, sub_feature: Optional[str] = None
    ) -> dict[str, list]:
        """Get devices that support the requested feature.

        Returns a dictionary mapping device names to lists of revisions that support
        the specified feature and optional sub-feature.

        :param feature: Name of feature to search for.
        :param sub_feature: Optional sub feature to better specify the device selection.
        :return: Dictionary with device names as keys and lists of supporting revisions as values.
        """
        devices: dict[str, list] = {}
        for name, info in self.devices.items():
            for revision in info.revision_features.keys():
                if info.is_feature_supported(feature, sub_feature, revision):
                    if name not in devices:
                        devices[name] = []
                    devices[name].append(revision)
        return dict(sorted(devices.items()))

    def get_family_names(self) -> list[str]:
        """Get the list of all families supported by SPSDK.

        Returns a sorted list of all device family names that are currently supported
        by the SPSDK library.

        :return: Sorted list of supported device family names.
        """
        devices = list(self.devices.keys())
        devices.sort()
        return devices

    def get_predecessors(self, families: list[str]) -> dict[str, str]:
        """Get the list of devices predecessors in previous SPSDK versions.

        :param families: List of current family names to find predecessors for.
        :return: Dictionary mapping predecessor family names to current names.
        """
        pr_names: dict[str, str] = {}
        for family in families:
            pr_name = self.devices[family.lower()].info.spsdk_predecessor_name
            if pr_name is not None and pr_name not in pr_names:
                assert isinstance(pr_name, str)
                pr_names[pr_name] = family

        return pr_names

    def is_predecessor_name(self, family: str) -> bool:
        """Check if device name is predecessor SPSDK device name.

        This method verifies whether the provided family name exists in the predecessor
        lookup table, indicating it's a legacy device name format.

        :param family: The MCU/MPU family name to check.
        :return: True if the family name is found in predecessor lookup, False otherwise.
        """
        return bool(family.lower() in self.predecessor_lookup)

    def get_correct_name(self, family: str) -> str:
        """Get correct(latest) device name.

        The method normalizes device family names by converting predecessor names to their
        current equivalents using the predecessor lookup table.

        :param family: The MCU/MPU family name to normalize.
        :return: Current database device name as string.
        """
        if self.is_predecessor_name(family.lower()):
            family = self.predecessor_lookup[family.lower()]
        return family


class FeaturesQuickData:
    """SPSDK Features Quick Data Manager.

    This class manages aggregated feature data across multiple devices in the SPSDK
    database, providing fast access to consolidated feature information without
    device-specific dependencies. It extracts and consolidates features like
    memory types from all devices to enable quick lookups and feature validation.
    """

    def __init__(self) -> None:
        """Initialize the database object.

        Sets up an empty features dictionary to store device and feature configurations.
        The features dictionary uses a nested structure where the outer key represents
        the device/family name and the inner dictionary contains feature definitions.
        """
        self.features: dict[str, dict[str, Any]] = {}

    @classmethod
    def create(cls, devices: Devices) -> Self:
        """Create Quick data from the Database.

        Extracts features from all devices in the database and consolidates them into a
        Quick features object. For each device, uses the latest revision and merges
        memory types while removing duplicates.

        :param devices: Database devices object to pick data from.
        :return: Quick features object with consolidated device features.
        """
        ret = cls()
        for dev in devices.devices:
            # get latest revision
            dev_features = dev.revisions.get()
            for name, content in dev_features.features.items():
                if name not in ret.features:
                    ret.features[name] = {}
                # Solve 'mem_types'
                mem_types: Optional[dict[str, Any]] = content.get("mem_types")
                if mem_types:
                    if "mem_types" in ret.features[name]:
                        # remove redundancies
                        ret.features[name]["mem_types"] = list(
                            set(ret.features[name]["mem_types"] + list(mem_types.keys()))
                        )
                    else:
                        ret.features[name]["mem_types"] = list(mem_types.keys())

        return ret

    @property
    def get_all_features(self) -> list[str]:
        """Get all supported features from the database.

        :return: List of all feature names available in the database.
        """
        return list(self.features.keys())

    def get_mem_types(self, feature: str) -> list[str]:
        """Get supported memory types for a specific feature across all devices.

        The method retrieves the list of memory types that are supported by the specified
        feature. If the feature doesn't exist or has no memory types defined, an empty
        list is returned.

        :param feature: Name of the feature to query for supported memory types.
        :return: List of supported memory type names, empty list if feature not found.
        """
        if feature not in self.features:
            return []
        if "mem_types" not in self.features[feature]:
            return []
        return self.features[feature]["mem_types"]


class QuickDatabase:
    """SPSDK Quick Database for lightweight device information access.

    This class provides a lightweight database loaded at SPSDK startup to supply
    basic device information for CLI operations such as help texts and enumeration
    choices without requiring the full heavyweight database to be loaded.
    """

    def __init__(self) -> None:
        """Initialize the database with empty device and feature collections.

        Sets up internal data structures for storing device information and feature data,
        along with an empty database hash for integrity checking.
        """
        self.devices = DevicesQuickInfo()
        self.features_data = FeaturesQuickData()
        self.db_hash = b""

    @classmethod
    def create(cls, database: "Database") -> Self:
        """Create Quick data from the Database.

        :param database: Database object to pick data from.
        :return: Quick database object.
        """
        ret = cls()
        ret.devices = DevicesQuickInfo.create(database.devices)
        ret.features_data = FeaturesQuickData.create(database.devices)
        return ret

    def split_devices_to_groups(self, devices: list[str]) -> dict[str, list[str]]:
        """Sort given devices to groups by their purposes.

        The method organizes devices into groups based on their purpose attribute from the
        device database. Each group contains devices with the same purpose, sorted alphabetically.

        :param devices: List of device names to be grouped.
        :return: Dictionary where the key is group name and value is list of devices.
        """
        ret: dict[str, list[str]] = {}
        for device in devices:
            dev_purpose = self.devices.devices[device.lower()].info.purpose
            if dev_purpose not in ret:
                ret[dev_purpose] = []
            ret[dev_purpose].append(device.lower())

        for grp in ret.values():
            grp.sort()
        return ret


class Database:
    """SPSDK database manager for device configuration and data files.

    This class provides centralized access to device databases, configuration files,
    and related data across the NXP MCU portfolio. It handles database caching,
    loading device-specific configurations, and managing restricted or addon data
    paths for efficient SPSDK operations.
    """

    class DatabaseData:
        """SPSDK Database Data Manager.

        This class manages database configuration data with intelligent caching capabilities
        to improve performance across SPSDK operations. It handles loading, validation,
        and caching of database configurations from multiple data sources including
        main database path, restricted data, and addon configurations.
        """

        def __init__(
            self,
            path: str,
            restricted_data_path: Optional[str] = None,
            addons_data_path: Optional[str] = None,
            complete_load: bool = False,
        ) -> None:
            """Initialize Database data object with configuration paths and caching options.

            The constructor sets up the database with primary data path and optional restricted
            and addon data paths. It handles cache loading/validation and loads default
            configurations from YAML files.

            :param path: Primary path to database data folder.
            :param restricted_data_path: Optional path to restricted data folder.
            :param addons_data_path: Optional path to addons data folder.
            :param complete_load: If True, forces complete database reload bypassing cache.
            :raises SPSDKError: Invalid cache file type or cache loading failure.
            """
            self.path = path
            self.restricted_data_path = restricted_data_path
            self.addons_data_path = addons_data_path

            self.db_hash = b""
            loaded_db_data = None
            if not SPSDK_CACHE_DISABLED or not complete_load:
                db_cache_file_name = self.get_cache_filename(path)
                if os.path.exists(db_cache_file_name):
                    try:
                        with FileLock(db_cache_file_name + ".lock", timeout=10):
                            with open(db_cache_file_name, mode="rb") as f:
                                loaded_db_data = pickle.load(f, encoding="utf-8")
                        if not isinstance(loaded_db_data, type(self)):
                            raise SPSDKError("Invalid cache file type.")
                        db_hash = self.hash_db_data(
                            cached_configs=list(loaded_db_data.cfg_cache.keys()),
                            path=path,
                            restricted_data_path=restricted_data_path,
                            addons_data_path=addons_data_path,
                        )
                        logger.debug(f"Current database finger print hash: {db_hash.hex()}")

                        if db_hash != loaded_db_data.db_hash:
                            loaded_db_data = None
                            logger.warning(
                                f"Existing cached DB ({db_cache_file_name}) has invalid hash. It will be erased."
                            )
                            os.remove(db_cache_file_name)
                        else:
                            logger.debug(f"Loaded database from cache: {db_cache_file_name}")
                            self.db_hash = db_hash
                    except (
                        SPSDKError,
                        UnicodeDecodeError,
                        FileNotFoundError,
                        pickle.PickleError,
                        MemoryError,
                    ) as exc:
                        logger.error(f"Fail during load of database cache: {str(exc)}")
                        if os.path.exists(db_cache_file_name):
                            os.remove(db_cache_file_name)

            defaults_path = os.path.join(path, "common", "database_defaults.yaml")
            if restricted_data_path:
                r_defaults_path = os.path.join(
                    restricted_data_path, "common", "database_defaults.yaml"
                )
                if os.path.exists(r_defaults_path):
                    defaults_path = r_defaults_path

            self.cfg_cache: dict[str, Any] = loaded_db_data.cfg_cache if loaded_db_data else {}
            self.defaults = (
                loaded_db_data.defaults if loaded_db_data else load_configuration(defaults_path)
            )

        def make_cache(self) -> None:
            """Create cache file of database data.

            The method creates a pickled cache file to improve performance by storing
            processed database configurations. It handles concurrent access using file
            locks and merges data from parallel processes when needed. The cache is
            only created if the database hash has changed.

            :raises Exception: Any exception during cache file creation or access.
            """
            db_hash = self.hash_db_data(
                cached_configs=list(self.cfg_cache.keys()),
                path=self.path,
                restricted_data_path=self.restricted_data_path,
                addons_data_path=self.addons_data_path,
            )
            if db_hash != self.db_hash:
                try:
                    db_cache_file_name = self.get_cache_filename(self.path)
                    cache_dir = os.path.dirname(db_cache_file_name)
                    if not os.path.exists(cache_dir):
                        os.makedirs(cache_dir, exist_ok=True)
                    self.db_hash = db_hash
                    with FileLock(db_cache_file_name + ".lock", timeout=10):
                        # 1. try to load the already existing cache file
                        if os.path.exists(db_cache_file_name):
                            with open(db_cache_file_name, mode="rb") as f:
                                cached_data = pickle.load(f, encoding="utf-8")
                            assert isinstance(cached_data, Database.DatabaseData)
                            # In case that the current database data has been updated by other parallel process
                            # Load it and merge together
                            if cached_data.db_hash != self.db_hash:
                                for rec in cached_data.cfg_cache.keys():
                                    if rec not in self.cfg_cache:
                                        self.cfg_cache[rec] = cached_data.cfg_cache[rec]
                            self.db_hash = self.hash_db_data(
                                cached_configs=list(self.cfg_cache.keys()),
                                path=self.path,
                                restricted_data_path=self.restricted_data_path,
                                addons_data_path=self.addons_data_path,
                            )
                        with open(db_cache_file_name, mode="wb") as f:
                            pickle.dump(self, f, pickle.DEFAULT_PROTOCOL)
                    logger.debug(f"Created database data cache: {db_cache_file_name}")
                except Exception as exc:
                    self.db_hash = b""
                    logger.debug(f"Cannot store database data cache: {str(exc)}")
            else:
                logger.debug("Not needed to create a new database data cache.")

        @staticmethod
        def get_cache_filename(path: str) -> str:
            """Get database cache filename based on path and version.

            The method generates a unique cache filename using the provided path,
            SPSDK version, and a SHA1 hash for uniqueness. The cache file is stored
            in the SPSDK cache directory.

            :param path: Path to generate cache filename for.
            :return: Full path to the database cache file.
            """
            data_folder = path.lower()
            cache_name = (
                "db_data_"
                + get_hash(data_folder.encode(), algorithm=EnumHashAlgorithm.SHA1)[:6].hex()
                + "_"
                + str(spsdk.version)
                + ".cache"
            )
            cache_path = get_spsdk_cache_dirname()
            return os.path.join(cache_path, cache_name)

        @staticmethod
        def hash_db_data(
            cached_configs: list[str],
            path: str,
            restricted_data_path: Optional[str] = None,
            addons_data_path: Optional[str] = None,
        ) -> bytes:
            """Generate SHA1 hash of database configuration files and paths.

            The method creates a hash based on file modification times, sizes, and paths
            to detect changes in database configuration data including cached configs,
            database path, restricted data, addons data, and default configuration.

            :param cached_configs: List of configuration file paths to be hashed.
            :param path: Base path to the database directory.
            :param restricted_data_path: Optional path to restricted data directory.
            :param addons_data_path: Optional path to addons data directory.
            :return: SHA1 hash bytes of all input data and file metadata.
            """

            def hash_file(file: str) -> None:
                """Update file hash with file metadata.

                Updates the hash object with the file's modification time (in nanoseconds) and size
                to create a unique fingerprint based on file metadata.

                :param file: Path to the file to hash.
                :raises OSError: If the file cannot be accessed or does not exist.
                """
                stat = os.stat(file)
                hash_obj.update_int(stat.st_mtime_ns)
                hash_obj.update_int(stat.st_size)

            hash_obj = Hash(EnumHashAlgorithm.SHA1)
            for cfg_file in cached_configs:
                hash_obj.update(cfg_file.encode())
                hash_file(cfg_file)

            hash_obj.update(path.encode())
            if restricted_data_path:
                hash_obj.update(restricted_data_path.encode())
            if addons_data_path:
                hash_obj.update(addons_data_path.encode())
            defaults_path = os.path.join(path, "common", "database_defaults.yaml")
            hash_obj.update(defaults_path.encode())

            return hash_obj.finalize()

    def __init__(
        self,
        path: str,
        restricted_data_path: Optional[str] = None,
        addons_data_path: Optional[str] = None,
        complete_load: bool = False,
    ) -> None:
        """Initialize database configuration.

        Creates a new database instance with base, restricted, and addon data sources.
        Optionally loads all device configurations immediately instead of using lazy loading.

        :param path: Path to the base database directory.
        :param restricted_data_path: Path to the restricted data database directory.
        :param addons_data_path: Path to the addons data database directory.
        :param complete_load: Load all database content immediately without caching.
        """
        self._data = self.DatabaseData(
            path=path,
            restricted_data_path=restricted_data_path,
            addons_data_path=addons_data_path,
            complete_load=complete_load,
        )

        self._devices = Devices(db=self)
        if complete_load:
            self._devices.load_devices_from_path(os.path.join(path, "devices"))
            if restricted_data_path:
                self._devices.load_devices_from_path(os.path.join(restricted_data_path, "devices"))

        # optional Database hash that could be used for identification of consistency
        self.db_hash = bytes()

    @property
    def devices(self) -> Devices:
        """Get the list of devices stored in the database.

        :return: Collection of devices available in the database.
        """
        return self._devices

    def get_defaults(self, feature: str) -> dict[str, Any]:
        """Get feature defaults from the database.

        The method retrieves default configuration values for a specified feature
        from the database's defaults section and returns a deep copy to prevent
        accidental modifications.

        :param feature: Name of the feature to get defaults for.
        :raises SPSDKValueError: Invalid or non-existing feature name.
        :return: Dictionary containing the feature's default configuration values.
        """
        features = self._data.defaults["features"]
        if feature not in features:
            raise SPSDKValueError(f"Invalid feature requested: {feature}")

        return deepcopy(features[feature])

    def get_device_features(self, family: str, revision: str = "latest") -> Features:
        """Get device features database for specified family and revision.

        Retrieves the feature configuration data for a specific device family and revision
        from the internal database. If revision is not specified, returns the latest available.

        :param family: The device family name to look up.
        :param revision: The device revision name, defaults to "latest".
        :raises SPSDKValueError: Unsupported family or revision.
        :return: The feature configuration data for the specified device.
        """
        dev = self.devices.get(family.lower())
        return dev.revisions.get(revision.lower())

    def get_data_file_path(
        self, path: str, exc_enabled: bool = True, just_standard_lib: bool = False
    ) -> str:
        """Get data file path.

        The method counts also with restricted data source and any other addons.

        :param path: Relative path in data folder.
        :param exc_enabled: Exception enabled in case of non existing file, defaults to True.
        :param just_standard_lib: Use just standard library files (no restricted data, neither
            addons), defaults to False.
        :raises SPSDKValueError: Non existing file path.
        :return: Final absolute path to data file.
        """
        # 1. Prepare normal data file
        normal_path = os.path.join(self._data.path, path)

        # 2. Try to get restricted data file
        if self._data.restricted_data_path and not just_standard_lib:
            restr_path = os.path.join(self._data.restricted_data_path, path)
            if os.path.exists(restr_path):
                return os.path.abspath(restr_path)

        if not os.path.exists(normal_path):
            # 3. If Normal nor Restricted file exists give chance of addons
            if self._data.addons_data_path and not just_standard_lib:
                addons_path = os.path.join(self._data.addons_data_path, path)
                if os.path.exists(addons_path):
                    return os.path.abspath(addons_path)

            # 4. In case that the file doesn't exist and exception is allowed, raise exception
            if exc_enabled:
                raise SPSDKValueError(f"The requested data file doesn't exists: {path}")

        # 5. Return normal path if exist or not
        return os.path.abspath(normal_path)

    def get_schema_file(self, feature: str) -> dict[str, Any]:
        """Get JSON Schema file for the requested feature.

        The method loads and returns the JSON Schema configuration file for a specific
        feature from the database's jsonschemas directory.

        :param feature: Name of the feature to get the schema for.
        :raises SPSDKError: If the schema file cannot be found or loaded.
        :return: Loaded dictionary containing the JSON Schema configuration.
        """
        path = self.get_data_file_path(os.path.join("jsonschemas", f"sch_{feature}.yaml"))
        return DatabaseManager().db.load_db_cfg_file(path)

    def get_common_data_file_path(self, path: str) -> str:
        """Get common data file path.

        The method counts also with restricted data source and any other addons.

        :param path: Relative path in common data folder.
        :raises SPSDKValueError: Non existing file path.
        :return: Final absolute path to data file.
        """
        return self.get_data_file_path(os.path.join("common", path))

    def load_db_cfg_file(self, filename: str) -> dict[str, Any]:
        """Load database configuration file with caching support.

        Loads JSON or YAML configuration files and caches them using singleton behavior
        to avoid repeated file operations for the same file path.

        :param filename: Path to the configuration file to load.
        :raises SPSDKError: Invalid or corrupted configuration file.
        :return: Loaded configuration data as dictionary.
        """
        abs_path = os.path.abspath(filename)
        if abs_path not in self._data.cfg_cache:
            try:
                cfg = load_configuration(abs_path)
            except SPSDKError as exc:
                raise SPSDKError(f"Invalid configuration file. {str(exc)}") from exc
            self._data.cfg_cache[abs_path] = cfg
            self._data.make_cache()

        return deepcopy(self._data.cfg_cache[abs_path])

    def __hash__(self) -> int:
        """Calculate hash value for the database instance.

        The hash is computed using SHA1 algorithm based on the length of the configuration cache,
        providing a unique identifier for the current state of the database.

        :return: Integer hash value representing the database state.
        """
        hash_obj = Hash(EnumHashAlgorithm.SHA1)
        hash_obj.update_int(len(self._data.cfg_cache))
        return value_to_int(hash_obj.finalize())


class FeaturesEnum(SpsdkEnum):
    """Enumeration of all SPSDK database features.

    This enumeration defines all supported features across the NXP MCU portfolio
    that can be managed through SPSDK. Each feature represents a specific
    functionality or component such as boot containers, security protocols,
    memory configurations, and programming interfaces. The enumeration provides
    a standardized way to identify and reference SPSDK capabilities in the
    database system.
    """

    FUSES = (0, "fuses", "One-Time Programmable fuses")
    BLHOST = (1, "blhost", "BLHOST application / mBoot In-System Programming protocol")
    COMM_BUFFER = (2, "comm_buffer", "Communication buffer in RAM memory")
    CERT_BLOCK = (3, "cert_block", "Certification Block")
    DAT = (4, "dat", "Debug Authentication Protocol")
    MBI = (5, "mbi", "Boot container - Master Boot Image")
    HAB = (6, "hab", "Boot container - High Assurance Boot")
    AHAB = (7, "ahab", "Boot container - Advanced High Assurance Boot")
    SIGNED_MSG = (8, "signed_msg", "Signed Message")
    PFR = (9, "pfr", "Protected Flash Region")
    BOOTABLE_IMAGE = (11, "bootable_image", "Bootable Image")
    FCB = (12, "fcb", "Flash Configuration Block")
    XMCD = (13, "xmcd", "External Memory Configuration Data")
    BEE = (14, "bee", "Bus Encryption Engine")
    IEE = (15, "iee", "Inline Encryption Engine")
    OTFAD = (16, "otfad", "On-The-Fly AES Decryption")
    SB21 = (17, "sb21", "Secure Binary v2.1")
    SB31 = (18, "sb31", "Secure Binary v3.1")
    SBX = (19, "sbx", "Secure Binary X")
    SHADOW_REGS = (20, "shadow_regs", "Shadow registers")
    DEVHSM = (21, "devhsm", "Device HSM")
    TP = (22, "tp", "Trust Provisioning")
    TZ = (23, "tz", "ARM TrustZone")
    ELE = (24, "ele", "EdgeLock Enclave")
    MEMCFG = (25, "memcfg", "Memory Configuration")
    WPC = (26, "wpc", "Wireless Power Consortium")
    SIGNING = (27, "signing", "Signing additional information")
    EL2GO_TP = (28, "el2go_tp", "EdgeLock 2 Go Trust Provisioning")
    LPCPROG = (29, "lpcprog", "LPC devices programming")
    DICE = (30, "dice", "Device Identifier Composition Engine")
    FASTBOOT = (31, "fastboot", "Fastboot protocol")
    NXPUUU = (32, "nxpuuu", "NXP UUU")
    BCA = (33, "bca", "Bootloader Configuration Area")
    FCF = (34, "fcf", "Flash Configuration Field")
    SB40 = (35, "sb40", "Secure Binary v4.0")
    SBC = (36, "sbc", "sbc")
    SHE_SCEC = (37, "she_scec", "Secure Hardware Extension")
    TLV_BLOB = (38, "tlv_blob", "Type-Length-Value blobs")


class DatabaseManager:
    """SPSDK database manager implementing singleton pattern for unified data access.

    This class provides centralized access to SPSDK database resources including
    device configurations, register definitions, and restricted data. It manages
    database initialization, caching, and ensures single instance access across
    the application lifecycle.

    :cvar FUSES: Database category for fuse-related data.
    :cvar BLHOST: Database category for bootloader host data.
    :cvar COMM_BUFFER: Database category for communication buffer data.
    :cvar CERT_BLOCK: Database category for certificate block data.
    :cvar DAT: Database category for debug authentication data.
    :cvar MBI: Database category for master boot image data.
    :cvar HAB: Database category for high assurance boot data.
    """

    _instance = None
    _db: Optional[Database] = None
    _quick_info: Optional[QuickDatabase] = None

    @staticmethod
    def clear_cache() -> None:
        """Clear SPSDK cache directory.

        Removes the entire SPSDK cache directory and all its contents. If the cache
        directory does not exist, logs an error message. If removal fails due to
        permission or other OS-related issues, logs an error with details.

        :raises PermissionError: When insufficient permissions to remove cache directory.
        :raises OSError: When OS-level error occurs during directory removal.
        """
        path = get_spsdk_cache_dirname()
        if not os.path.exists(path):
            logger.error(f"Cache directory '{path}' does not exist, nothing to clear.")
            return
        try:
            shutil.rmtree(path)
        except (PermissionError, OSError) as exc:
            logger.error(f"Cannot clear cache directory '{path}': {str(exc)}")

    @staticmethod
    def get_restricted_data() -> Optional[str]:
        """Get restricted data folder path, if applicable.

        Validates the restricted data folder by checking metadata version compatibility
        with current SPSDK version and verifying the data folder exists.

        :return: Path to restricted data folder if valid and compatible, None otherwise.
        """
        if SPSDK_RESTRICTED_DATA_FOLDER is None:
            return None

        try:
            rd_version: str = load_configuration(
                os.path.join(SPSDK_RESTRICTED_DATA_FOLDER, "metadata.yaml")
            )["version"]
        except SPSDKError:
            logger.error("The Restricted data has invalid folder or METADATA")
            return None
        major, minor = rd_version.split(".", maxsplit=2)
        if int(major) != version.major or int(minor) != version.minor:
            logger.error(
                f"The restricted data version does not match SPSDK current version: {rd_version} != {str(version)}"
            )
            return None
        database_path = os.path.join(SPSDK_RESTRICTED_DATA_FOLDER, "data")
        if not os.path.exists(database_path):
            logger.error(f"The restricted data doesn't contain data folder: {database_path}")
            return None
        return database_path

    @classmethod
    def _get_quick_info_db_path(cls) -> str:
        """Get quick info database filename.

        The method constructs a path to the cache file that stores quick database information,
        incorporating the current SPSDK version in the filename for version-specific caching.

        :return: Absolute path to the database cache file.
        """
        cache_folder = get_spsdk_cache_dirname()
        return os.path.join(cache_folder, f"db_quick_info_{spsdk.version}.cache")

    @classmethod
    def _get_quick_info_db(cls) -> QuickDatabase:
        """Get database and handle caching.

        This method retrieves a QuickDatabase instance with intelligent caching to improve
        performance. It checks if caching is disabled, validates cached data using hash
        fingerprints, and creates new cache files when necessary. The method handles
        various error conditions gracefully and falls back to creating a fresh database
        when cache operations fail.

        :return: QuickDatabase instance with current database data.
        """
        restricted_data = DatabaseManager.get_restricted_data()

        if SPSDK_CACHE_DISABLED:
            DatabaseManager.clear_cache()
            return QuickDatabase.create(cls.get_db())

        db_hash = DatabaseManager.get_quick_info_hash(
            [SPSDK_DATA_FOLDER, restricted_data, SPSDK_ADDONS_DATA_FOLDER]
        )

        logger.debug(f"Current database fingerprint hash: {db_hash.hex()}")
        cache_folder = get_spsdk_cache_dirname()
        db_cache_file_name = cls._get_quick_info_db_path()
        if os.path.exists(db_cache_file_name):
            try:
                with FileLock(db_cache_file_name + ".lock", timeout=10):
                    with open(db_cache_file_name, mode="rb") as f:
                        loaded_db = pickle.load(f, encoding="utf-8")
                assert isinstance(loaded_db, QuickDatabase)
                if db_hash == loaded_db.db_hash:
                    logger.debug(f"Loaded database from cache: {db_cache_file_name}")
                    return loaded_db
                # if the hash is not same clear cache and make a new one
                logger.warning(
                    f"Existing cached quick DB ({db_cache_file_name}) has invalid hash. It will be erased."
                )
            except (
                SPSDKError,
                UnicodeDecodeError,
                FileNotFoundError,
                pickle.PickleError,
                MemoryError,
            ) as exc:
                logger.error(f"Cannot load database cache: {str(exc)}")

        quick_info = QuickDatabase.create(cls.get_db(complete_load=True))
        quick_info.db_hash = db_hash
        try:
            os.makedirs(cache_folder, exist_ok=True)
            with FileLock(db_cache_file_name + ".lock", timeout=10):
                with open(db_cache_file_name, mode="wb") as f:
                    pickle.dump(quick_info, f, pickle.DEFAULT_PROTOCOL)
            logger.debug(f"Created quick database cache: {db_cache_file_name}")
        except Exception as exc:
            logger.debug(f"Cannot store database cache: {str(exc)}")
        return quick_info

    def __new__(cls) -> Self:
        """Create singleton instance of SPSDK Database manager.

        This method implements the singleton pattern to ensure only one instance of the
        DatabaseManager exists. It also configures logging based on the SPSDK_DEBUG_DB
        environment variable.

        :return: DatabaseManager singleton instance.
        """
        if cls._instance:
            return cls._instance
        spsdk_logger.install(
            level=logging.DEBUG if SPSDK_DEBUG_DB else logging.WARNING,
            logger=logger,
            create_debug_logger=False,
        )
        cls._instance = super(DatabaseManager, cls).__new__(cls)
        cls._quick_info = cls._get_quick_info_db()
        return cls._instance

    @staticmethod
    def get_quick_info_hash(paths: list[Optional[str]]) -> bytes:
        """Calculate hash for quick database validation.

        This method generates a SHA1 hash based on modification times and sizes of database files
        to quickly detect changes in the database structure without full content comparison.
        The hash includes common defaults and all device-specific database files.

        :param paths: List of paths to database folders, None values are ignored.
        :return: SHA1 hash of database files as bytes.
        """

        def hash_file(file: str) -> None:
            """Hash file metadata for integrity verification.

            Updates the hash object with file's modification time and size to create
            a unique fingerprint for file change detection.

            :param file: Path to the file to be hashed.
            :raises OSError: If the file cannot be accessed or does not exist.
            """
            stat = os.stat(file)
            hash_obj.update_int(stat.st_mtime_ns + stat.st_size)

        hash_obj = Hash(EnumHashAlgorithm.SHA1)
        # Hash this file
        if SPSDK_DEBUG_DB and os.path.exists(__file__):
            hash_obj.update_int(
                os.stat(__file__).st_size
            )  # Add to hash also this source file itself if exists

        for path in paths:
            if path is None:
                continue
            # Hash common defaults
            common_defaults = os.path.join(path, "common", "database_defaults.yaml")
            if os.path.exists(common_defaults):
                hash_file(common_defaults)
            # Hash devices database files
            devices = os.listdir(os.path.join(path, "devices"))
            devices.sort()
            for device in devices:
                hash_obj.update(device.encode())
                device_file = os.path.join(path, "devices", device, "database.yaml")
                if os.path.exists(device_file):
                    hash_file(device_file)

        return hash_obj.finalize()

    @classmethod
    def get_db(cls, complete_load: bool = False) -> Database:
        """Get database instance with lazy initialization.

        Creates and initializes the database on first access using SPSDK data folders
        and restricted data configuration.

        :param complete_load: If True, the database will be completely loaded during
            initialization, otherwise loaded on demand.
        :return: Database instance.
        """
        if cls._db is None:
            cls._db = Database(
                SPSDK_DATA_FOLDER,
                DatabaseManager.get_restricted_data(),
                SPSDK_ADDONS_DATA_FOLDER,
                complete_load=complete_load,
            )
        return cls._db

    @property
    def db(self) -> Database:
        """Get Database instance.

        Retrieves and validates the database instance from the internal storage.

        :raises AssertionError: If the retrieved object is not a Database instance.
        :return: The Database instance.
        """
        db = self.get_db()
        assert isinstance(db, Database)
        return db

    @property
    def quick_info(self) -> QuickDatabase:
        """Get quick info Database instance.

        :return: Quick database instance containing essential device information.
        """
        quick_info = type(self)._quick_info
        assert isinstance(quick_info, QuickDatabase)
        return quick_info

    # """List all SPSDK supported features"""
    FUSES = FeaturesEnum.FUSES.label
    BLHOST = FeaturesEnum.BLHOST.label
    COMM_BUFFER = FeaturesEnum.COMM_BUFFER.label
    CERT_BLOCK = FeaturesEnum.CERT_BLOCK.label
    DAT = FeaturesEnum.DAT.label
    MBI = FeaturesEnum.MBI.label
    HAB = FeaturesEnum.HAB.label
    AHAB = FeaturesEnum.AHAB.label
    SIGNED_MSG = FeaturesEnum.SIGNED_MSG.label
    PFR = FeaturesEnum.PFR.label
    BOOTABLE_IMAGE = FeaturesEnum.BOOTABLE_IMAGE.label
    FCB = FeaturesEnum.FCB.label
    XMCD = FeaturesEnum.XMCD.label
    BEE = FeaturesEnum.BEE.label
    IEE = FeaturesEnum.IEE.label
    OTFAD = FeaturesEnum.OTFAD.label
    SB21 = FeaturesEnum.SB21.label
    SB31 = FeaturesEnum.SB31.label
    SB40 = FeaturesEnum.SB40.label
    SBX = FeaturesEnum.SBX.label
    SHADOW_REGS = FeaturesEnum.SHADOW_REGS.label
    DEVHSM = FeaturesEnum.DEVHSM.label
    TP = FeaturesEnum.TP.label
    TZ = FeaturesEnum.TZ.label
    ELE = FeaturesEnum.ELE.label
    MEMCFG = FeaturesEnum.MEMCFG.label
    WPC = FeaturesEnum.WPC.label
    SIGNING = FeaturesEnum.SIGNING.label
    EL2GO_TP = FeaturesEnum.EL2GO_TP.label
    LPCPROG = FeaturesEnum.LPCPROG.label
    DICE = FeaturesEnum.DICE.label
    FASTBOOT = FeaturesEnum.FASTBOOT.label
    NXPUUU = FeaturesEnum.NXPUUU.label
    BCA = FeaturesEnum.BCA.label
    FCF = FeaturesEnum.FCF.label
    SBC = FeaturesEnum.SBC.label
    SHE_SCEC = FeaturesEnum.SHE_SCEC.label
    TLV_BLOB = FeaturesEnum.TLV_BLOB.label


def get_schema_file(feature: str) -> dict[str, Any]:
    """Get JSON Schema file for the requested feature.

    :param feature: Name of the feature to get schema for.
    :return: Loaded dictionary containing the JSON Schema file content.
    """
    return DatabaseManager().db.get_schema_file(feature)


def get_common_data_file_path(path: str) -> str:
    """Get common data file path.

    The method counts also with restricted data source and any other addons.

    :param path: Relative path in common data folder.
    :raises SPSDKValueError: Non existing file path.
    :return: Final absolute path to data file.
    """
    return DatabaseManager().db.get_common_data_file_path(path)


def get_whole_db() -> Database:
    """Get loaded main Database.

    :return: The loaded main Database object.
    """
    return DatabaseManager().db
