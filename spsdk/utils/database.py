#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module to manage and interact with databases used in SPSDK.

This module provides utilities and classes for handling various databases
used throughout the Secure Provisioning SDK (SPSDK). It includes functionality
for loading, caching, and accessing device-specific data, features, and revisions.
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

    Raises:
        SPSDKValueError: If SPSDK_CACHE_FOLDER is set but not a valid absolute path.

    Returns:
        str: The path to the SPSDK cache directory.
    """
    if SPSDK_CACHE_FOLDER:
        if not os.path.isabs(SPSDK_CACHE_FOLDER):
            raise SPSDKValueError(f"Invalid SPSDK_CACHE_FOLDER path: {SPSDK_CACHE_FOLDER}")
        return SPSDK_CACHE_FOLDER

    return SPSDK_PLATFORM_DIRS.user_cache_dir


class SPSDKErrorMissingDevice(SPSDKError):
    """Exception raised when a device is missing from the database."""

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
    """Represents a single device revision with its features."""

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

        :param feature: Feature name.
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

        :param feature: Feature name.
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

        :param feature: Feature name.
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

        :param feature: Feature name.
        :param key: Item key or key path as a list (e.g., ['grp1', 'grp2', 'key']).
        :param default: Default value if the key is missing.
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

        :param feature: Feature name.
        :param key: Item key or key path as a list (e.g., ['grp1', 'grp2', 'key']).
        :param default: Default value if the key is missing.
        :param just_standard_lib: Use only standard library files (no restricted data or addons).
        :return: File path value for the device.
        """
        file_name = self.get_str(feature, key, default)
        return self.device.create_file_path(file_name, just_standard_lib)


class Revisions(list[Features]):
    """List of device revisions.

    This class extends the built-in list to store and manage device revision Features.
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
    """USB identifier for a given device."""

    def __init__(self, vid: Optional[int] = None, pid: Optional[int] = None) -> None:
        """Initialize a USB ID instance.

        :param vid: USB Vendor ID
        :param pid: USB Product ID
        """
        self.vid = vid
        self.pid = pid

    def __str__(self) -> str:
        """Return a string representation of the USB ID.

        :return: String in the format '[0xPID:0xVID]'
        """
        return f"[0x{self.pid:04X}:0x{self.vid:04X}]"

    def __eq__(self, obj: Any) -> bool:
        """Check equality with another object.

        :param obj: Object to compare with
        :return: True if obj is a UsbId instance with matching vid and pid, False otherwise
        """
        return isinstance(obj, self.__class__) and self.vid == obj.vid and self.pid == obj.pid

    def update(self, usb_config: dict) -> None:
        """Update the USB ID from a configuration dictionary.

        :param usb_config: Dictionary containing 'vid' and/or 'pid' keys
        """
        self.vid = usb_config.get("vid", self.vid)
        self.pid = usb_config.get("pid", self.pid)

    @classmethod
    def load(cls, usb_config: dict) -> Self:
        """Create a UsbId instance from a configuration dictionary.

        :param usb_config: Dictionary containing 'vid' and/or 'pid' keys
        :return: New UsbId instance
        """
        return cls(vid=usb_config.get("vid", None), pid=usb_config.get("pid", None))

    def is_valid(self) -> bool:
        """Check if the USB ID is valid.

        :return: True if both vid and pid are set, False otherwise
        """
        return self.vid is not None and self.pid is not None


class Bootloader:
    """Represents a bootloader with its protocol and interface details."""

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

        :return: Formatted string with bootloader details
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

        :param config: Dictionary containing bootloader configuration
        :return: New Bootloader instance
        """
        return cls(
            protocol=config.get("protocol", None),
            interfaces=config.get("interfaces", []),
            usb_id=UsbId.load(config.get("usb", {})),
            protocol_params=config.get("protocol_params", {}),
        )

    def update(self, config: dict) -> None:
        """Update the Bootloader instance from a configuration dictionary.

        :param config: Dictionary containing updated bootloader configuration
        """
        self.protocol = config.get("protocol", self.protocol)
        self.interfaces = config.get("interfaces", self.interfaces)
        self.protocol_params = config.get("protocol_params", self.protocol_params)
        self.usb_id.update(config.get("usb", {}))


class MemBlock:
    """One memory block from memory map."""

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

        :param name: Name of the memory block
        :param desc: Dictionary containing the memory block description
        """
        self.name = name
        self.description = desc

    def __str__(self) -> str:
        """Return a string representation of the MemBlock.

        :return: Formatted string with memory block details
        """
        ret = self.name + ":\n"
        ret += f"  Base:     0x{self.base_address:08X}\n"
        ret += f"  Size:     {size_fmt(self.size,use_kibibyte=True)}\n"
        ret += f"  External: {self.external}"
        return ret

    @property
    def base_address(self) -> int:
        """Get the base address of the memory block.

        :return: Base address as an integer
        """
        return value_to_int(self.description["start_int"])

    @property
    def size(self) -> int:
        """Get the size of the memory block.

        :return: Size in bytes as an integer
        """
        return value_to_int(self.description["size_int"])

    @property
    def external(self) -> bool:
        """Check if this is an external memory block.

        :return: True if external, False otherwise
        """
        return value_to_bool(self.description.get("external", False))

    @classmethod
    def parse_name(cls, name: str) -> tuple[Optional[str], str, Optional[int], Optional[bool]]:
        """Parse name to base elements.

        :param name: Name of the memory block.
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
        """Get core name if specified."""
        core, _, _, _ = self.parse_name(self.name)
        return core

    @property
    def block_name(self) -> str:
        """Get block name."""
        _, block_name, _, _ = self.parse_name(self.name)
        return block_name

    @property
    def instance(self) -> Optional[int]:
        """Get instance if specified."""
        _, _, instance, _ = self.parse_name(self.name)
        return instance

    @property
    def security_access(self) -> Optional[bool]:
        """Get security access if specified."""
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

        :param block_name: Name of memory block
        :param core: Optional core name, defaults to None
        :param instance: Optional instance, defaults to None
        :param secure_access: Optional specification if block has secure or non secure access, defaults to None
        :return: Full block name.
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
    """Device memory map configuration."""

    def __init__(self, mem_map: dict[str, MemBlock]) -> None:
        """Device memory map configuration.

        :param mem_map_raw: Raw data of memory map loaded from database.
        """
        self._mem_map = mem_map

    def __str__(self) -> str:
        ret = ""
        for block in self._mem_map.values():
            ret += str(block) + "\n"
        return ret

    def get_table(self) -> str:
        """Get string table with memory map description."""
        table_p = prettytable.PrettyTable(["#", "Block", "Base", "Size", "External"])
        table_p.set_style(prettytable.DOUBLE_BORDER)
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
        """Loads the Memory map from configuration.

        :param mem_map: Dictionary with all blocks.
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
        """Get the one memory block by parameters.

        :param block_name: Core block name
        :param core: Optional core name, defaults to None
        :param instance: Optional instance, defaults to None
        :param secure: optional selection of secure non secure memory access, defaults to False
        :return: Memory block if available
        :raises: SPSDKError in case that block is not found.
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


class IspCfg:
    """ISP configuration."""

    def __init__(self, rom: Bootloader, flashloader: Bootloader) -> None:
        """Constructor of ISP config class.

        :param rom: ROM object
        :param flashloader: Flashloader object
        """
        self.rom = rom
        self.flashloader = flashloader

    def __str__(self) -> str:
        ret = ""
        if self.rom:
            ret += f"ROM:\n{textwrap.indent(str(self.rom), '  ')}\n"
        if self.flashloader.protocol:
            ret += f"FlashLoader:\n{textwrap.indent(str(self.flashloader), '  ')}\n"

        return ret

    @classmethod
    def load(cls, config: dict) -> Self:
        """Load from configuration."""
        return cls(
            rom=Bootloader.load(config.get("rom", {})),
            flashloader=Bootloader.load(config.get("flashloader", {})),
        )

    def update(self, config: dict) -> None:
        """Update the object from configuration."""
        self.rom.update(config.get("rom", {}))
        self.flashloader.update(config.get("flashloader", {}))

    def is_protocol_supported(self, protocol: str) -> bool:
        """Returns true is any of interfaces supports given protocol."""
        return self.rom.protocol == protocol or self.flashloader.protocol == protocol

    def get_usb_ids(self, protocol: str) -> list[UsbId]:
        """Get the usb params for interfaces supporting given protocol."""
        usb_ids = []
        if self.rom.protocol == protocol and self.rom.usb_id.is_valid():
            usb_ids.append(self.rom.usb_id)
        if self.flashloader.protocol == protocol and self.flashloader.usb_id.is_valid():
            usb_ids.append(self.flashloader.usb_id)
        return usb_ids


class DeviceInfo:
    """Device information dataclass."""

    def __init__(
        self,
        use_in_doc: bool,
        purpose: str,
        spsdk_predecessor_name: Optional[str],
        web: str,
        memory_map: dict[str, dict[str, Any]],
        isp: IspCfg,
    ) -> None:
        """Constructor of device information class.

        :param purpose: String description of purpose of MCU (in fact the device group)
        :param spsdk_predecessor_name: Device sub series name (usually predecessor name in SPSDK)
        :param web: Web page with device info
        :param memory_map: Basic memory map of device
        :param isp: Information regarding ISP mode
        """
        self.use_in_doc = use_in_doc
        self.purpose = purpose
        self.spsdk_predecessor_name = spsdk_predecessor_name
        self.web = web
        self.memory_map = MemMap.load(memory_map)
        self.isp = isp

    def __repr__(self) -> str:
        return f"DeviceInfo({self.purpose})"

    @classmethod
    def load(cls, config: dict[str, Any], defaults: dict[str, Any]) -> Self:
        """Loads the device from folder.

        :param config: The name of device.
        :param defaults: Device data defaults.
        :return: The Device object.
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
        """Updates Device info by new configuration.

        :param config: The new Device Info configuration
        """
        self.use_in_doc = bool(config.get("use_in_doc", self.use_in_doc))
        self.purpose = config.get("purpose", self.purpose)
        self.spsdk_predecessor_name = config.get(
            "spsdk_predecessor_name", self.spsdk_predecessor_name
        )
        self.web = config.get("web", self.web)
        self.memory_map = MemMap.load(config.get("memory_map", self.memory_map._mem_map))
        self.isp.update(config.get("isp", {}))


class Device:
    """Device dataclass represents a single device."""

    def __init__(
        self,
        name: str,
        db: "Database",
        latest_rev: str,
        info: DeviceInfo,
        device_alias: Optional["Device"] = None,
        revisions: Revisions = Revisions(),
    ) -> None:
        """Constructor of SPSDK Device.

        :param name: Device name
        :param db: Database parent object
        :param latest_rev: latest revision name
        :param device_alias: Device alias, defaults to None
        :param revisions: Device revisions, defaults to Revisions()
        """
        self.name = name
        self.db = db
        self.latest_rev = latest_rev
        self.device_alias = device_alias
        self.revisions = revisions
        self.info = info

    def get_copy(self, new_name: Optional[str] = None) -> "Device":
        """Get copy of self.

        :param new_name: Optionally the copy could has a new name.
        :returns: Copy of self.
        """
        name = new_name or self.name
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
        return f"Device({self.name})"

    def __lt__(self, other: "Device") -> bool:
        """Less than comparison based on name."""
        return self.name < other.name

    @property
    def features_list(self) -> list[str]:
        """Get the list of device features."""
        return [str(k) for k in self.revisions.get().features.keys()]

    @staticmethod
    def _load_alias(name: str, db: "Database", dev_cfg: dict[str, Any]) -> "Device":
        """Loads the device from folder.

        :param name: The name of device.
        :param db: Database parent object.
        :param dev_cfg: Already loaded configuration.
        :return: The Device object.
        """
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
        """Loads the device from folder.

        :param name: The name of device.
        :param db: Base database object.
        :return: The Device object.
        """
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
        """Create File path value for this device.

        :param file_name: File name to be enriched by device path
        :param just_standard_lib: Use just standard library files (no restricted data, neither addons), defaults False.
        :return: File path value for the device
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
    """List of devices."""

    def __init__(self, db: "Database") -> None:
        """Constructor of managed devices in database.

        :param db: Whole database object.
        """
        self.devices: list[Device] = []
        self.db = db

    def get(self, name: str) -> Device:
        """Return database device structure.

        :param name: String Key with device name.
        :raises SPSDKErrorMissingDevice: In case the device with given name does not exist
        :return: Dictionary device configuration structure or None:
        """
        # Check device name (it could be used predecessor SPSDK name)
        if not name:
            raise SPSDKErrorMissingDevice("The device name (family) is not specified.")
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
        """Get the list of devices names."""
        return [dev.name for dev in self.devices]

    def feature_items(self, feature: str, key: str) -> Iterator[tuple[str, str, Any]]:
        """Iter the whole database for the feature items.

        :return: Tuple of Device name, revision name and items value.
        """
        for device in self.devices:
            if feature not in device.features_list:
                continue
            for rev in device.revisions:
                value = rev.features[feature].get(key)
                if value is None:
                    raise SPSDKValueError(f"Missing item '{key}' in feature '{feature}'!")
                yield (device.name, rev.name, value)

    def _load_and_append_device(self, dev_name: str) -> None:
        """Load and append device to the devices."""
        # Omit already loaded devices (used for multiple calls of this method (restricted data))
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
        """Loads the devices from SPSDK database path.

        :param devices_path: The devices path.
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
    """Device quick and short info."""

    def __init__(self, features: Features, info: DeviceInfo) -> None:
        """Constructor of Device quick information.

        :param features: Device features to get information from
        """
        self.features: dict[str, Optional[list]] = {}
        self.info = info
        for k, v in features.features.items():
            self.features[k] = v.get("sub_features")

    @property
    def features_list(self) -> list[str]:
        """List of all supported features of device."""
        return list(self.features.keys())

    def is_feature_supported(self, feature: str, sub_feature: Optional[str] = None) -> bool:
        """Return True if the feature is supported by devices.

        :param feature: Feature name
        :param sub_feature: Sub feature name to better granularity, defaults to None
        :return: True if the feature is supported by devices, False otherwise.
        """
        if feature in self.features:
            if sub_feature:
                if self.features[feature] is None:
                    return False
                sub_features: list = self.features[feature] or []
                return sub_feature in sub_features
            return True
        return False


class DevicesQuickInfo:
    """List of all devices with their quick information."""

    def __init__(self) -> None:
        """Constructor of devices quick information."""
        self.devices: dict[str, DeviceQuickInfo] = {}
        self.predecessor_lookup: dict[str, str] = {}

    @staticmethod
    def create(devices: Devices) -> "DevicesQuickInfo":
        """Create quick info about devices.

        :param devices: Full devices description.
        """
        dqi = {}
        pl = {}
        for dev in devices.devices:
            info = DeviceQuickInfo(dev.revisions.get(), dev.info)
            p_name = info.info.spsdk_predecessor_name
            if p_name:
                if p_name not in pl:
                    pl[p_name] = dev.name

            dqi[dev.name] = info

        ret = DevicesQuickInfo()

        ret.devices = dqi
        ret.predecessor_lookup = pl

        return ret

    def get_feature_list(self, dev_name: str) -> list[str]:
        """Get features list.

        If device is not used, the whole list of SPSDK features is returned

        :param dev_name: Device name, defaults to None
        :returns: List of features.
        """
        if self.devices == {}:
            return []
        return self.devices[dev_name].features_list

    def get_devices_with_feature(
        self, feature: str, sub_feature: Optional[str] = None
    ) -> list[str]:
        """Get the list of all device names that supports requested feature.

        :param feature: Name of feature
        :param sub_feature: Optional sub feature to better specify the families selection
        :returns: List of devices that supports requested feature.
        """
        devices: list[str] = []
        for name, info in self.devices.items():
            if info.is_feature_supported(feature, sub_feature):
                devices.append(name)

        devices.sort()
        return devices

    def get_predecessors(self, devices: list[str]) -> dict[str, str]:
        """Get the list of devices predecessors in previous SPSDK versions.

        :param devices: List of current devices names.
        :returns: Dictionary of predecessors SPSDK devices names.
        """
        pr_names: dict[str, str] = {}
        for dev in devices:
            d = dev.casefold()
            pr_name = self.devices[d].info.spsdk_predecessor_name
            if pr_name is not None and pr_name not in pr_names:
                assert isinstance(pr_name, str)
                pr_names[pr_name] = d

        return pr_names

    def is_predecessor_name(self, device: str) -> bool:
        """Check if device name is predecessor SPSDK device name.

        :param device: Any device name.
        :return: True if it's SPSDK predecessor name.
        """
        return bool(device.casefold() in self.predecessor_lookup)

    def get_correct_name(self, device: str) -> str:
        """Get correct(latest) device name.

        :param device: Any device name.
        :return: Current database device name.
        """
        if self.is_predecessor_name(device):
            return self.predecessor_lookup[device.casefold()]
        return device


class FeaturesQuickData:
    """General quick data for features not depends on devices."""

    def __init__(self) -> None:
        """Constructor, just to keep members."""
        self.features: dict[str, dict[str, Any]] = {}

    @classmethod
    def create(cls, devices: Devices) -> Self:
        """Create Quick data from the Database.

        :param devices: Database devices object to pick data from
        :return: Quick features object.
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
        """Return list of all supported features."""
        return list(self.features.keys())

    def get_mem_types(self, feature: str) -> list[str]:
        """Get supported memory types in individual features per all devices.

        :param feature: Feature name
        """
        if feature not in self.features:
            return []
        if "mem_types" not in self.features[feature]:
            return []
        return self.features[feature]["mem_types"]


class QuickDatabase:
    """Base quick database class.

    This class is intend to be loaded after startup of SPSDK to
    provides basic information to satisfy whole CLI information (like helps texts and
    enums for choices) without loading heavy database with all data.
    """

    def __init__(self) -> None:
        """Just constructor to held the internal members."""
        self.devices = DevicesQuickInfo()
        self.features_data = FeaturesQuickData()
        self.db_hash = b""

    @classmethod
    def create(cls, database: "Database") -> Self:
        """Create Quick data from the Database.

        :param database: Database object to pick data from
        :return: Quick database object.
        """
        ret = cls()
        ret.devices = DevicesQuickInfo.create(database.devices)
        ret.features_data = FeaturesQuickData.create(database.devices)
        return ret

    def sort_devices_to_groups(self, devices: list[str]) -> dict[str, list[str]]:
        """Sort given devices to groups by their purposes.

        :param devices: Input list of devices.
        :return: Dictionary where the key is name od group and value is list of devices.
        """
        ret: dict[str, list[str]] = {}
        for device in devices:
            dev_purpose = self.devices.devices[device].info.purpose
            if dev_purpose not in ret:
                ret[dev_purpose] = []
            ret[dev_purpose].append(device)

        for grp in ret.values():
            grp.sort()
        return ret


class Database:
    """Class that helps manage used databases in SPSDK."""

    class DatabaseData:
        """Database data intended to be cached if possible."""

        def __init__(
            self,
            path: str,
            restricted_data_path: Optional[str] = None,
            addons_data_path: Optional[str] = None,
            complete_load: bool = False,
        ) -> None:
            """Constructor of Database data object."""
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
            """Create cache file of itself."""
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
            """Get database cache folder and file name.

            :return: Database cache file name.
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
            """Get hash of real files/data.

            :param cached_configs: List of file names to be hashed
            :param path: Path to database
            :param restricted_data_path: Optional path to restricted data, defaults to None
            :param addons_data_path: Optional path to addons data, defaults to None
            :return: Hash of all inputs including defaults content
            """

            def hash_file(file: str) -> None:
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
        """Register Configuration class constructor.

        :param path: The path to the base database.
        :param restricted_data_path: The path to the restricted data database.
        :param addons_data_path: The path to the addons data database.
        :param complete_load: The database is fully loaded from database path without using cache.
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
        """Get the list of devices stored in the database."""
        return self._devices

    def get_defaults(self, feature: str) -> dict[str, Any]:
        """Gets feature defaults.

        :param feature: Feature name
        :return: Dictionary with feature defaults.
        """
        features = self._data.defaults["features"]
        if feature not in features:
            raise SPSDKValueError(f"Invalid feature requested: {feature}")

        return deepcopy(features[feature])

    def get_device_features(
        self,
        device: str,
        revision: str = "latest",
    ) -> Features:
        """Get device features database.

        :param device: The device name.
        :param revision: The revision of the silicon.
        :raises SPSDKValueError: Unsupported feature
        :return: The feature data.
        """
        dev = self.devices.get(device)
        return dev.revisions.get(revision)

    def get_data_file_path(
        self, path: str, exc_enabled: bool = True, just_standard_lib: bool = False
    ) -> str:
        """Get data file path.

        The method counts also with restricted data source and any other addons.

        :param path: Relative path in data folder
        :param exc_enabled: Exception enabled in case of non existing file.
        :param just_standard_lib: Use just standard library files (no restricted data, neither addons), defaults False.
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
        """Get JSON Schema file name for the requested feature.

        :param feature: Requested feature.
        :return: Loaded dictionary of JSON Schema file.
        """
        path = self.get_data_file_path(os.path.join("jsonschemas", f"sch_{feature}.yaml"))
        return DatabaseManager().db.load_db_cfg_file(path)

    def get_common_data_file_path(self, path: str) -> str:
        """Get common data file path.

        The method counts also with restricted data source and any other addons.

        :param path: Relative path in common data folder
        :raises SPSDKValueError: Non existing file path.
        :return: Final absolute path to data file.
        """
        return self.get_data_file_path(os.path.join("common", path))

    def load_db_cfg_file(self, filename: str) -> dict[str, Any]:
        """Return load database config file (JSON/YAML). Use SingleTon behavior.

        :param filename: Path to config file.
        :raises SPSDKError: Invalid config file.
        :return: Loaded file in dictionary.
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
        """Hash function of the database."""
        hash_obj = Hash(EnumHashAlgorithm.SHA1)
        hash_obj.update_int(len(self._data.cfg_cache))
        return value_to_int(hash_obj.finalize())


class FeaturesEnum(SpsdkEnum):
    """Enumeration of all SPSDK database features."""

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
    IFR = (10, "ifr", "Information Registers")
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


class DatabaseManager:
    """Main SPSDK database manager implementing singleton pattern."""

    _instance = None
    _db: Optional[Database] = None
    _quick_info: Optional[QuickDatabase] = None

    @staticmethod
    def clear_cache() -> None:
        """Clear SPSDK cache directory."""
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

        :return: Optional restricted data folder path.
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

        :return: Database cache file name.
        """
        cache_folder = get_spsdk_cache_dirname()
        return os.path.join(cache_folder, f"db_quick_info_{spsdk.version}.cache")

    @classmethod
    def _get_quick_info_db(cls) -> QuickDatabase:
        """Get database and handle caching.

        :return: QuickDatabase instance.
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
        """Manage SPSDK Database as a singleton class.

        :return: SPSDK_Database object
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
        """Calculate the hash of the real databases.

        :param paths: List of paths to database folders.
        :return: Calculated hash as bytes.
        """

        def hash_file(file: str) -> None:
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
            for device in os.listdir(os.path.join(path, "devices")):
                hash_obj.update(device.encode())
                device_file = os.path.join(path, "devices", device, "database.yaml")
                if os.path.exists(device_file):
                    hash_file(device_file)

        return hash_obj.finalize()

    @classmethod
    def get_db(cls, complete_load: bool = False) -> Database:
        """Get database, and handle the first time use.

        :param complete_load: If True, the database will be completely loaded.
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
        """Get Database instance."""
        db = self.get_db()
        assert isinstance(db, Database)
        return db

    @property
    def quick_info(self) -> QuickDatabase:
        """Get quick info Database instance."""
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
    IFR = FeaturesEnum.IFR.label
    BOOTABLE_IMAGE = FeaturesEnum.BOOTABLE_IMAGE.label
    FCB = FeaturesEnum.FCB.label
    XMCD = FeaturesEnum.XMCD.label
    BEE = FeaturesEnum.BEE.label
    IEE = FeaturesEnum.IEE.label
    OTFAD = FeaturesEnum.OTFAD.label
    SB21 = FeaturesEnum.SB21.label
    SB31 = FeaturesEnum.SB31.label
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


def get_db(
    device: str,
    revision: str = "latest",
) -> Features:
    """Get device feature database.

    :param device: The device name.
    :param revision: The revision of the silicon.
    :return: The feature data.
    """
    return DatabaseManager().db.get_device_features(device, revision)


def get_device(device: str) -> Device:
    """Get device database object.

    :param device: The device name.
    :return: The device data.
    """
    return DatabaseManager().db.devices.get(device)


def get_families(feature: str, sub_feature: Optional[str] = None) -> list[str]:
    """Get the list of all family names that supports requested feature.

    :param feature: Name of feature.
    :param sub_feature: Optional sub feature name to specify the more precise selection.
    :return: List of devices that supports requested feature.
    """
    return DatabaseManager().quick_info.devices.get_devices_with_feature(feature, sub_feature)


def get_schema_file(feature: str) -> dict[str, Any]:
    """Get JSON Schema file name for the requested feature.

    :param feature: Requested feature.
    :return: Loaded dictionary of JSON Schema file.
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
