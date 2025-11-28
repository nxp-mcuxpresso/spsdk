#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK MBoot device configuration management for testing.

This module provides functionality for managing and validating device
configuration settings used in MBoot test operations. It handles configuration
schemas and device-specific parameters for secure provisioning test workflows.
"""

import typing

import yaml
from voluptuous import ALLOW_EXTRA, All, Any, Optional, Required, Schema

from spsdk.mboot.memories import ExtMemId
from spsdk.mboot.properties import (
    CommandTag,
    PeripheryTag,
    PropertyTag,
    Version,
    get_properties,
    get_property_index,
)

########################################################################################################################
# Validator schema for configuration file
########################################################################################################################
SCHEMA = {
    Required("Properties"): {
        Required("CurrentVersion"): Any(int, All(str, lambda v: Version(v).to_int())),
        Required("AvailablePeripherals"): All(
            list, [Any(*[item.label for item in PeripheryTag])], lambda v: tuple(set(v))
        ),
        Optional("FlashStartAddress"): Any(int, All(str, lambda v: int(v, 0))),
        Optional("FlashSize"): Any(int, All(str, lambda v: int(v, 0))),
        Optional("FlashSectorSize"): Any(int, All(str, lambda v: int(v, 0))),
        Optional("FlashBlockCount"): Any(int, All(str, lambda v: int(v, 0))),
        Required("AvailableCommands"): All(
            list, [Any(*[item.label for item in CommandTag])], lambda v: tuple(set(v))
        ),
        Optional("CrcCheckStatus"): Any(int, All(str, lambda v: int(v, 0))),
        Optional("VerifyWrites"): All(
            str, Any("YES", "ON", "NO", "OFF"), lambda v: 1 if v in ("YES", "ON") else 0
        ),
        Optional("MaxPacketSize"): Any(int, All(str, lambda v: int(v, 0))),
        Optional("ReservedRegions"): All(
            list,
            [
                {
                    Required("Address"): Any(int, All(str, lambda v: int(v, 0))),
                    Required("Size"): Any(int, All(str, lambda v: int(v, 0))),
                }
            ],
        ),
        Optional("ValidateRegions"): All(
            str, Any("YES", "ON", "NO", "OFF"), lambda v: 1 if v in ("YES", "ON") else 0
        ),
        Optional("RamStartAddress"): Any(int, All(str, lambda v: int(v, 0))),
        Optional("RamSize"): Any(int, All(str, lambda v: int(v, 0))),
        Optional("SystemDeviceIdent"): Any(int, All(str, lambda v: int(v, 16))),
        Optional("FlashSecurityState"): All(str, Any("LOCKED", "UNLOCKED")),
        Optional("UniqueDeviceIdent"): Any(int, All(str, lambda v: int(v, 16))),
        Optional("FlashFacSupport"): All(
            str, Any("YES", "ON", "NO", "OFF"), lambda v: 1 if v in ("YES", "ON") else 0
        ),
        Optional("FlashAccessSegmentSize"): Any(int, All(str, lambda v: int(v, 0))),
        Optional("FlashAccessSegmentCount"): Any(int, All(str, lambda v: int(v, 0))),
        Optional("FlashReadMargin"): Any(int, All(str, lambda v: int(v, 0))),
        Optional("QspiInitStatus"): Any(int, All(str, lambda v: int(v, 0))),
        Optional("TargetVersion"): Any(int, All(str, lambda v: Version(v).to_int())),
        Optional("ExternalMemoryAttributes"): All(
            list,
            [
                {
                    Required("MemoryType"): All(
                        list, Any(*[item.label for item in ExtMemId]), lambda v: tuple(set(v))
                    ),
                    Required("StartAddress"): Any(int, All(str, lambda v: int(v, 0))),
                    Required("Size"): Any(int, All(str, lambda v: int(v, 0))),
                    Optional("PageSize"): Any(int, All(str, lambda v: int(v, 0))),
                    Optional("SectorSize"): Any(int, All(str, lambda v: int(v, 0))),
                    Optional("BlockSize"): Any(int, All(str, lambda v: int(v, 0))),
                }
            ],
        ),
        Optional("ReliableUpdateStatus"): Any(int, All(str, lambda v: int(v, 0))),
        Optional("FlashPageSize"): Any(int, All(str, lambda v: int(v, 0))),
        Optional("IrqNotifierPin"): Any(int, All(str, lambda v: int(v, 0))),
        Optional("PfrKeystoreUpdateOpt"): Any(int, All(str, lambda v: int(v, 0))),
    },
    Optional("Others"): {},
}


########################################################################################################################
# Device configuration class
########################################################################################################################
class DevConfig:
    """SPSDK Device Configuration Manager.

    This class provides access to device configuration properties and capabilities
    for MBoot operations. It manages device-specific information such as flash
    memory parameters, available peripherals, supported commands, and operational
    settings retrieved from the target device.
    """

    @property
    def current_version(self) -> int:
        """Get the current version from device properties.

        Retrieves the CurrentVersion value from the internal properties dictionary.

        :raises AssertionError: When CurrentVersion key is not present in properties.
        :return: The current version number as an integer.
        """
        assert "CurrentVersion" in self._props
        return self._props["CurrentVersion"]

    @property
    def available_peripherals(self) -> int:
        """Get available peripherals as a bitmask value.

        This method retrieves the list of available peripherals from the device properties
        and converts them into a single integer bitmask where each bit represents a specific
        peripheral type.

        :raises AssertionError: When 'AvailablePeripherals' key is not present in properties.
        :return: Bitmask representing all available peripherals combined using OR operation.
        """
        assert "AvailablePeripherals" in self._props
        value = 0
        for name in self._props["AvailablePeripherals"]:
            value |= PeripheryTag.get_tag(name)
        return value

    @property
    def flash_start_address(self) -> int:
        """Get the flash start address from device properties.

        Retrieves the flash memory start address that was previously obtained
        from the device configuration properties.

        :raises AssertionError: When FlashStartAddress property is not available in device properties.
        :return: Flash memory start address as integer value.
        """
        assert "FlashStartAddress" in self._props
        return self._props["FlashStartAddress"]

    @property
    def flash_size(self) -> int:
        """Get the flash size of the device.

        Retrieves the flash size property from the device properties dictionary.

        :raises AssertionError: If FlashSize property is not available in device properties.
        :return: Flash size in bytes.
        """
        assert "FlashSize" in self._props
        return self._props["FlashSize"]

    @property
    def flash_sector_size(self) -> int:
        """Get flash sector size from device properties.

        Retrieves the flash sector size value from the internal device properties
        dictionary. This property must be available in the device configuration.

        :raises AssertionError: When FlashSectorSize property is not available in device properties.
        :return: Flash sector size in bytes.
        """
        assert "FlashSectorSize" in self._props
        return self._props["FlashSectorSize"]

    @property
    def flash_block_count(self) -> int:
        """Get the flash block count from device properties.

        :raises AssertionError: When FlashBlockCount property is not available in device properties.
        :return: Number of flash blocks on the device.
        """
        assert "FlashBlockCount" in self._props
        return self._props["FlashBlockCount"]

    @property
    def available_commands(self) -> int:
        """Get available commands as a bitmask value.

        Converts the list of available command names from properties into a bitmask
        where each bit represents a specific command based on its CommandTag value.

        :raises AssertionError: When 'AvailableCommands' key is not present in properties.
        :return: Bitmask representing available commands where each bit corresponds to a command tag.
        """
        assert "AvailableCommands" in self._props
        value = 0
        for cmd_name in self._props["AvailableCommands"]:
            value |= 1 << CommandTag.get_tag(cmd_name)
        return value

    @property
    def crc_check_status(self) -> int:
        """Get CRC check status from device properties.

        Retrieves the CRC check status value from the internal properties dictionary.
        This status indicates the current state of CRC verification on the device.

        :raises AssertionError: If CrcCheckStatus property is not available in device properties.
        :return: CRC check status value as integer.
        """
        assert "CrcCheckStatus" in self._props
        return self._props["CrcCheckStatus"]

    @property
    def verify_writes(self) -> int:
        """Get the verify writes property value.

        Retrieves the VerifyWrites configuration property from the device properties.

        :raises AssertionError: When VerifyWrites property is not present in device properties.
        :return: The verify writes configuration value.
        """
        assert "VerifyWrites" in self._props
        return self._props["VerifyWrites"]

    @property
    def max_packet_size(self) -> int:
        """Get the maximum packet size for the device.

        Retrieves the maximum packet size from the device properties that was
        previously obtained during device initialization.

        :raises AssertionError: If MaxPacketSize property is not available in device properties.
        :return: Maximum packet size in bytes.
        """
        assert "MaxPacketSize" in self._props
        return self._props["MaxPacketSize"]

    @property
    def reserved_regions(self) -> typing.Any:
        """Get reserved memory regions from device properties.

        This method retrieves the reserved memory regions configuration from the device
        properties. Currently not implemented and will raise NotImplementedError.

        :raises AssertionError: When 'ReservedRegions' key is not present in device properties.
        :raises NotImplementedError: Method is not yet implemented.
        """
        assert "ReservedRegions" in self._props
        raise NotImplementedError()

    @property
    def validate_regions(self) -> int:
        """Get the validate regions property value.

        Retrieves the ValidateRegions configuration value from the device properties.

        :raises AssertionError: When ValidateRegions property is not available in device properties.
        :return: The validate regions configuration value.
        """
        assert "ValidateRegions" in self._props
        return self._props["ValidateRegions"]

    @property
    def ram_start_address(self) -> int:
        """Get the RAM start address from device properties.

        This method retrieves the RAM start address value from the device's
        internal properties dictionary.

        :raises AssertionError: When RamStartAddress property is not available in device properties.
        :return: The RAM start address as an integer value.
        """
        assert "RamStartAddress" in self._props
        return self._props["RamStartAddress"]

    @property
    def ram_size(self) -> int:
        """Get the RAM size of the device.

        Retrieves the RAM size property from the device configuration properties.

        :raises AssertionError: If RamSize property is not available in device properties.
        :return: RAM size in bytes.
        """
        assert "RamSize" in self._props
        return self._props["RamSize"]

    @property
    def system_device_ident(self) -> int:
        """Get system device identification value.

        Retrieves the SystemDeviceIdent property from the internal properties dictionary.
        This value represents the unique device identifier for the system.

        :raises AssertionError: When SystemDeviceIdent property is not available in properties.
        :return: System device identification number.
        """
        assert "SystemDeviceIdent" in self._props
        return self._props["SystemDeviceIdent"]

    @property
    def flash_security_state(self) -> str:
        """Get the flash security state from device properties.

        Retrieves the current flash security state value from the cached device
        properties dictionary.

        :raises AssertionError: When FlashSecurityState property is not available in device properties.
        :return: Flash security state as a string value.
        """
        assert "FlashSecurityState" in self._props
        return self._props["FlashSecurityState"]

    @property
    def unique_device_ident(self) -> int:
        """Get unique device identifier from device properties.

        Retrieves the unique device identifier value from the internal properties
        dictionary. This identifier is typically used to uniquely identify the
        specific device instance.

        :raises AssertionError: When UniqueDeviceIdent property is not available in device properties.
        :return: The unique device identifier as an integer value.
        """
        assert "UniqueDeviceIdent" in self._props
        return self._props["UniqueDeviceIdent"]

    @property
    def flash_fac_support(self) -> int:
        """Get flash factory support property value.

        Retrieves the FlashFacSupport property from the device properties,
        indicating whether the device supports flash factory operations.

        :raises AssertionError: When FlashFacSupport property is not available in device properties.
        :return: Flash factory support value as integer.
        """
        assert "FlashFacSupport" in self._props
        return self._props["FlashFacSupport"]

    @property
    def flash_access_segment_size(self) -> int:
        """Get the flash access segment size from device properties.

        This property defines the maximum size of data that can be accessed
        in a single flash operation on the target device.

        :raises AssertionError: When FlashAccessSegmentSize property is not available in device properties.
        :return: Flash access segment size in bytes.
        """
        assert "FlashAccessSegmentSize" in self._props
        return self._props["FlashAccessSegmentSize"]

    @property
    def flash_access_segment_count(self) -> int:
        """Get the flash access segment count from device properties.

        This method retrieves the number of flash access segments supported by the device
        from the internal properties dictionary.

        :raises AssertionError: If FlashAccessSegmentCount property is not available in device properties.
        :return: Number of flash access segments supported by the device.
        """
        assert "FlashAccessSegmentCount" in self._props
        return self._props["FlashAccessSegmentCount"]

    @property
    def flash_read_margin(self) -> int:
        """Get flash read margin property value.

        Retrieves the FlashReadMargin property from the device configuration properties.

        :raises AssertionError: When FlashReadMargin property is not available in device properties.
        :return: Flash read margin value as integer.
        """
        assert "FlashReadMargin" in self._props
        return self._props["FlashReadMargin"]

    @property
    def qspi_init_status(self) -> int:
        """Get QSPI initialization status from device properties.

        Retrieves the QSPI (Quad Serial Peripheral Interface) initialization status
        from the device configuration properties.

        :raises AssertionError: If QspiInitStatus property is not available in device properties.
        :return: QSPI initialization status value as integer.
        """
        assert "QspiInitStatus" in self._props
        return self._props["QspiInitStatus"]

    @property
    def target_version(self) -> int:
        """Get the target version from device properties.

        Retrieves the target version value from the internal properties dictionary.
        This version indicates the firmware or bootloader version of the target device.

        :raises AssertionError: When TargetVersion key is not present in properties.
        :return: Target version as integer value.
        """
        assert "TargetVersion" in self._props
        return self._props["TargetVersion"]

    @property
    def external_memory_attributes(self) -> typing.Any:
        """Get external memory attributes from device properties.

        Retrieves the ExternalMemoryAttributes property from the device configuration
        properties dictionary.

        :raises AssertionError: When ExternalMemoryAttributes key is not present in properties.
        :return: External memory attributes data from device properties.
        """
        assert "ExternalMemoryAttributes" in self._props
        return self._props["ExternalMemoryAttributes"]

    @property
    def reliable_update_status(self) -> int:
        """Get the reliable update status from device properties.

        Retrieves the ReliableUpdateStatus property value from the internal
        properties dictionary. This status indicates the current state of
        the reliable update process on the device.

        :raises AssertionError: When ReliableUpdateStatus property is not available in device properties.
        :return: The reliable update status value as an integer.
        """
        assert "ReliableUpdateStatus" in self._props
        return self._props["ReliableUpdateStatus"]

    @property
    def flash_page_size(self) -> int:
        """Get the flash page size from device properties.

        Retrieves the FlashPageSize property from the internal device properties
        dictionary. This value represents the size of a single flash page in bytes
        for the target device.

        :raises AssertionError: When FlashPageSize property is not available in device properties.
        :return: Flash page size in bytes.
        """
        assert "FlashPageSize" in self._props
        return self._props["FlashPageSize"]

    @property
    def irq_notifier_pin(self) -> int:
        """Get the IRQ notifier pin value.

        Retrieves the interrupt notifier pin configuration from the device properties.

        :raises AssertionError: When IrqNotifierPin property is not available in device properties.
        :return: The IRQ notifier pin number.
        """
        assert "IrqNotifierPin" in self._props
        return self._props["IrqNotifierPin"]

    @property
    def pfr_keystore_update_opt(self) -> int:
        """Get PFR keystore update option value.

        Retrieves the PfrKeystoreUpdateOpt property value from the device configuration.

        :raises AssertionError: When PfrKeystoreUpdateOpt property is not available in device properties.
        :return: The PFR keystore update option as an integer value.
        """
        assert "PfrKeystoreUpdateOpt" in self._props
        return self._props["PfrKeystoreUpdateOpt"]

    def __init__(self, config_file: str) -> None:
        """Initialize device configuration from YAML file.

        Loads and validates device configuration from a YAML file using predefined schema.
        The configuration is parsed into properties and other optional settings.

        :param config_file: Path to the YAML configuration file to load.
        :raises FileNotFoundError: If the configuration file does not exist.
        :raises yaml.YAMLError: If the YAML file is malformed or cannot be parsed.
        :raises SchemaError: If the configuration does not match the expected schema.
        """
        with open(config_file, "r", encoding="utf-8") as f:
            dev_cfg = yaml.safe_load(f)
        validator = Schema(SCHEMA, extra=ALLOW_EXTRA)
        dev_cfg = validator(dev_cfg)
        self._props = dev_cfg["Properties"]
        self._other = dev_cfg.get("Others", {})

    def valid_cmd(self, tag: int) -> bool:
        """Check if a command tag is valid for this device.

        Validates whether the specified command tag is supported by checking if it exists
        in the device's available commands list.

        :param tag: Command tag value to validate
        :raises AssertionError: If tag is not in valid CommandTag values
        :return: True if command is available for this device, False otherwise
        """
        assert tag in CommandTag.tags()
        return CommandTag.get_label(tag) in self._props["AvailableCommands"]

    def get_properties_count(self) -> int:
        """Get the count of properties.

        Returns the total number of properties currently stored in the internal
        properties collection.

        :return: Number of properties in the collection.
        """
        return len(self._props)

    def get_property_values(self, tag: int) -> list[int]:
        """Get property values for a given property tag.

        Retrieves and processes property values based on the property tag. For certain properties
        like available commands and peripherals, the values are converted to bit masks. For unique
        device identifier, the 64-bit value is split into two 32-bit values.

        :param tag: Property tag index to retrieve values for.
        :raises AssertionError: If the tag is not found in available properties.
        :return: List of integer values for the property, or None if property not configured.
        """
        assert tag in list(get_properties().keys())
        pname = PropertyTag.from_index(tag).label
        if pname not in self._props:
            return None  # type: ignore
        if tag == get_property_index(PropertyTag.AVAILABLE_COMMANDS):
            value = 0
            for cmd_name in self._props["AvailableCommands"]:
                value |= 1 << CommandTag.get_tag(cmd_name)
            return [value]
        if tag == get_property_index(PropertyTag.AVAILABLE_PERIPHERALS):
            value = 0
            for name in self._props["AvailablePeripherals"]:
                value |= PeripheryTag.get_tag(name)
            return [value]
        if tag == get_property_index(PropertyTag.UNIQUE_DEVICE_IDENT):
            return [
                self._props["UniqueDeviceIdent"] >> 32,
                self._props["UniqueDeviceIdent"] & 0xFFFFFFFF,
            ]

        return [self._props[pname]]
