#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2016-2018 Martin Olejar
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK MBoot device properties management and interpretation utilities.

This module provides comprehensive functionality for handling and interpreting
target device properties in the MBoot context. It includes property definitions,
value parsing, formatting utilities, and human-readable representations of
device characteristics such as available peripherals, memory attributes,
and security features.
"""

import ctypes
import logging
from copy import deepcopy
from enum import Enum
from typing import Callable, Optional, Type, Union

from typing_extensions import Self

from spsdk.exceptions import SPSDKError, SPSDKKeyError, SPSDKValueError
from spsdk.mboot.commands import CommandTag
from spsdk.mboot.error_codes import StatusCode
from spsdk.mboot.exceptions import McuBootError
from spsdk.mboot.memories import ExtMemPropTags, MemoryRegion
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision, get_db
from spsdk.utils.misc import Endianness
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)


########################################################################################################################
# McuBoot helper functions
########################################################################################################################
def size_fmt(value: Union[int, float], kibibyte: bool = True) -> str:
    """Convert size value into human-readable string format.

    Converts a numeric size value (in bytes) into a formatted string with appropriate
    unit suffix (B, kB/kiB, MB/MiB, etc.) for better readability.

    :param value: The raw size value in bytes to be converted.
    :param kibibyte: True for binary units (1024 bytes = 1 kiB), False for decimal
        units (1000 bytes = 1 kB).
    :return: Human-readable size string with value and unit suffix.
    """
    base, suffix = [(1000.0, "B"), (1024.0, "iB")][kibibyte]
    x = "B"
    for x in ["B"] + [prefix + suffix for prefix in list("kMGTP")]:
        if -base < value < base:
            break
        value /= base

    return f"{value} {x}" if x == "B" else f"{value:3.1f} {x}"


def int_fmt(value: int, format_str: str) -> str:
    """Format integer value to string representation based on specified format.

    Converts an integer value to its string representation using various formatting
    options including size formatting, hexadecimal, decimal, signed 32-bit integer,
    or custom format strings.

    :param value: Integer value to be formatted.
    :param format_str: Format specification - 'size', 'hex', 'dec', 'int32', or custom format.
    :return: Formatted string representation of the integer value.
    """
    if format_str == "size":
        str_value = size_fmt(value)
    elif format_str == "hex":
        str_value = f"0x{value:08X}"
    elif format_str == "dec":
        str_value = str(value)
    elif format_str == "int32":
        str_value = str(ctypes.c_int32(value).value)
    else:
        str_value = format_str.format(value)
    return str_value


########################################################################################################################
# McuBoot helper classes
########################################################################################################################


class Version:
    """McuBoot version representation and management.

    This class provides version handling for McuBoot operations, supporting version
    parsing from string and integer formats, version comparison operations, and
    conversion between different version representations. The version consists of
    mark, major, minor, and fixation components.
    """

    def __init__(self, *args: Union[str, int], **kwargs: int):
        """Initialize the Version object.

        Creates a Version object from either an integer or string representation,
        or from individual version components passed as keyword arguments.

        :param args: Version data as integer or string representation
        :param kwargs: Individual version components (mark, major, minor, fixation)
        :raises McuBootError: When argument is neither string nor integer type
        """
        self.mark = kwargs.get("mark", "K")
        self.major = kwargs.get("major", 0)
        self.minor = kwargs.get("minor", 0)
        self.fixation = kwargs.get("fixation", 0)
        if args:
            if isinstance(args[0], int):
                self.from_int(args[0])
            elif isinstance(args[0], str):
                self.from_str(args[0])
            else:
                raise McuBootError("Value must be 'str' or 'int' type !")

    def __eq__(self, obj: object) -> bool:
        """Check equality between two Version objects.

        Compares this Version instance with another object by checking if the other object
        is also a Version instance and has identical attributes.

        :param obj: Object to compare with this Version instance.
        :return: True if objects are equal Version instances with same attributes, False otherwise.
        """
        return isinstance(obj, Version) and vars(obj) == vars(self)

    def __ne__(self, obj: object) -> bool:
        """Check if this object is not equal to another object.

        This method implements the inequality comparison by negating the equality comparison.

        :param obj: Object to compare with this instance.
        :return: True if objects are not equal, False if they are equal.
        """
        return not self.__eq__(obj)

    def __lt__(self, obj: "Version") -> bool:
        """Compare this version with another version object.

        This method implements the less-than comparison operator for Version objects by converting
        both versions to integer representation and comparing them.

        :param obj: Version object to compare against.
        :return: True if this version is less than the compared version, False otherwise.
        """
        return self.to_int(True) < obj.to_int(True)

    def __le__(self, obj: "Version") -> bool:
        """Check if this version is less than or equal to another version.

        Compares two Version objects using their integer representation to determine
        if this version is less than or equal to the other version.

        :param obj: Version object to compare against.
        :return: True if this version is less than or equal to the other version, False otherwise.
        """
        return self.to_int(True) <= obj.to_int(True)

    def __gt__(self, obj: "Version") -> bool:
        """Compare if this version is greater than another version.

        :param obj: Version object to compare against.
        :return: True if this version is greater than the compared version, False otherwise.
        """
        return self.to_int(True) > obj.to_int(True)

    def __ge__(self, obj: "Version") -> bool:
        """Check if this version is greater than or equal to another version.

        Compares two Version objects using their integer representation to determine
        if this version is greater than or equal to the provided version object.

        :param obj: Version object to compare against.
        :return: True if this version is greater than or equal to obj, False otherwise.
        """
        return self.to_int(True) >= obj.to_int(True)

    def __repr__(self) -> str:
        """Return string representation of Version object.

        Provides a detailed string representation showing all version components
        including mark, major, minor, and fixation values.

        :return: String representation in format '<Version(mark=X, major=Y, minor=Z, fixation=W)>'.
        """
        return f"<Version(mark={self.mark}, major={self.major}, minor={self.minor}, fixation={self.fixation})>"

    def __str__(self) -> str:
        """Return string representation of the object.

        :return: String representation of the object.
        """
        return self.to_str()

    def from_int(self, value: int) -> None:
        """Parse version data from raw integer value.

        Extracts version components (mark, major, minor, fixation) from a 32-bit integer
        where each component occupies 8 bits. The mark is converted to ASCII character
        if it represents a valid uppercase letter (A-Z).

        :param value: Raw 32-bit integer containing packed version information
        """
        mark = (value >> 24) & 0xFF
        self.mark = chr(mark) if 64 < mark < 91 else None  # type: ignore
        self.major = (value >> 16) & 0xFF
        self.minor = (value >> 8) & 0xFF
        self.fixation = value & 0xFF

    def from_str(self, value: str) -> None:
        """Parse version data from string value.

        The method parses a version string in format "X.Y.Z" or "MX.Y.Z" where M is a mark character,
        X is major version, Y is minor version, and Z is fixation version.

        :param value: String representation of version in format "X.Y.Z" or "MX.Y.Z"
        :raises ValueError: Invalid version string format or non-numeric version components
        """
        mark_major, minor, fixation = value.split(".")
        if len(mark_major) > 1 and mark_major[0] not in "0123456789":
            self.mark = mark_major[0]
            self.major = int(mark_major[1:])
        else:
            self.major = int(mark_major)
        self.minor = int(minor)
        self.fixation = int(fixation)

    def to_int(self, no_mark: bool = False) -> int:
        """Get version value in raw integer format.

        The method combines major, minor, and fixation version components into a single
        integer value. Optionally includes a character mark in the most significant byte.

        :param no_mark: If True, return value without mark component.
        :return: Integer representation of the version with optional mark.
        """
        value = self.major << 16 | self.minor << 8 | self.fixation
        mark = 0 if no_mark or self.mark is None else ord(self.mark) << 24  # type: ignore
        return value | mark

    def to_str(self, no_mark: bool = False) -> str:
        """Get version value in readable string format.

        :param no_mark: If True, return value without mark.
        :return: String representation of the version.
        """
        value = f"{self.major}.{self.minor}.{self.fixation}"
        mark = "" if no_mark or self.mark is None else self.mark
        return f"{mark}{value}"


########################################################################################################################
# McuBoot Properties
########################################################################################################################

# fmt: off
class PropertyTag(Enum):
    """McuBoot property tag enumeration.
    
    This enumeration defines all available property tags that can be queried from McuBoot-enabled
    devices. Each property represents a specific device characteristic such as flash memory
    attributes, RAM configuration, security state, or bootloader capabilities. The enumeration
    provides multiple representations for each property including internal labels, CLI-friendly
    names, and human-readable descriptions.
    """
    LIST_PROPERTIES            = ('ListProperties', 'list-properties', 'List Properties')
    CURRENT_VERSION            = ('CurrentVersion', 'current-version', 'Current Version')
    AVAILABLE_PERIPHERALS      = ('AvailablePeripherals', 'available-peripherals', 'Available Peripherals')
    FLASH_START_ADDRESS        = ('FlashStartAddress', 'flash-start-address', 'Flash Start Address')
    FLASH_SIZE                 = ('FlashSize', 'flash-size-in-bytes', 'Flash Size')
    FLASH_SECTOR_SIZE          = ('FlashSectorSize', 'flash-sector-size', 'Flash Sector Size')
    FLASH_BLOCK_COUNT          = ('FlashBlockCount', 'flash-block-count', 'Flash Block Count')
    AVAILABLE_COMMANDS         = ('AvailableCommands', 'available-commands', 'Available Commands')
    CRC_CHECK_STATUS           = ('CrcCheckStatus', 'check-status', 'CRC Check Status')
    LAST_ERROR                 = ('LastError', 'reserved', 'Last Error Value')
    VERIFY_WRITES              = ('VerifyWrites', 'verify-writes', 'Verify Writes')
    VERIFY_ERASE               = ('VerifyErase', 'verify-erase', 'Verify Erase')
    MAX_PACKET_SIZE            = ('MaxPacketSize', 'max-packet-size', 'Max Packet Size')
    RESERVED_REGIONS           = ('ReservedRegions', 'reserved-regions', 'Reserved Regions')
    VALIDATE_REGIONS           = ('ValidateRegions', 'reserved_1', 'Validate Regions')
    RAM_START_ADDRESS          = ('RamStartAddress', 'ram-start-address', 'RAM Start Address')
    RAM_SIZE                   = ('RamSize', 'ram-size-in-bytes', 'RAM Size')
    SYSTEM_DEVICE_IDENT        = ('SystemDeviceIdent', 'system-device-id', 'System Device Identification')
    FLASH_SECURITY_STATE       = ('FlashSecurityState', 'security-state', 'Security State')
    LIFE_CYCLE_STATE           = ('LifeCycleState', 'life-cycle', 'Life Cycle State')
    UNIQUE_DEVICE_IDENT        = ('UniqueDeviceIdent', 'unique-device-id', 'Unique Device Identification')
    FLASH_FAC_SUPPORT          = ('FlashFacSupport', 'flash-fac-support', 'Flash Fac. Support')
    FLASH_ACCESS_SEGMENT_SIZE  = ('FlashAccessSegmentSize', 'flash-access-segment-size', 'Flash Access Segment Size')
    FLASH_ACCESS_SEGMENT_COUNT = ('FlashAccessSegmentCount', 'flash-access-segment-count', 'Flash Access Segment Count')
    FLASH_READ_MARGIN          = ('FlashReadMargin', 'flash-read-margin', 'Flash Read Margin')
    QSPI_INIT_STATUS           = ('QspiInitStatus', 'qspi/otfad-init-status', 'QuadSPI Initialization Status')
    TARGET_VERSION             = ('TargetVersion', 'target-version', 'Target Version')
    EXTERNAL_MEMORY_ATTRIBUTES = ('ExternalMemoryAttributes', 'external-memory-attributes', 'External Memory Attributes') # pylint: disable=line-too-long
    RELIABLE_UPDATE_STATUS     = ('ReliableUpdateStatus', 'reliable-update-status', 'Reliable Update Status')
    FLASH_PAGE_SIZE            = ('FlashPageSize', 'flash-page-size', 'Flash Page Size')
    IRQ_NOTIFIER_PIN           = ('IrqNotifierPin', 'irq-notify-pin', 'Irq Notifier Pin')
    PFR_KEYSTORE_UPDATE_OPT    = ('PfrKeystoreUpdateOpt', 'pfr-keystore-update-opt', 'PFR Keystore Update Opt')
    BYTE_WRITE_TIMEOUT_MS      = ('ByteWriteTimeoutMs', 'byte-write-timeout-ms', 'Byte Write Timeout in ms')
    FUSE_LOCKED_STATUS         = ('FuseLockedStatus', 'fuse-locked-status', 'Fuse Locked Status')
    BOOT_STATUS_REGISTER       = ('BootStatusRegister', 'boot-status', 'Boot Status Register')
    FIRMWARE_VERSION           = ('FirmwareVersion', 'loadable-fw-version', 'Firmware Version')
    FUSE_PROGRAM_VOLTAGE       = ('FuseProgramVoltage', 'fuse-program-voltage', 'Fuse Program Voltage')
    SHE_FLASH_PARTITION        = ('SheFlashPartition', 'she-flash-partition', 'Secure Hardware Extension: Flash Partition') # pylint: disable=line-too-long
    SHE_BOOT_MODE              = ('SheBootMode', 'she-boot-mode', 'Secure Hardware Extension: Boot Mode')
    UNKNOWN                    = ('Unknown', 'unknown', 'Unknown property')

    @property
    def label(self) -> str:
        """Get the internal name of the property tag.
        
        :return: Internal name of the property tag.
        """
        return self.value[0]

    @property
    def friendly_name(self) -> str:
        """Get the friendly name of the property tag.
        
        :return: The human-readable name associated with this property tag.
        """
        return self.value[1]

    @property
    def description(self) -> str:
        """Get the description of the property tag.
        
        :return: Description string of the property tag.
        """
        return self.value[2]

    @classmethod
    def from_name(cls, name: str) -> Self:
        """Convert a name to its corresponding PropertyTag.
        
        Searches through all PropertyTag members to find a match based on either
        the label or friendly_name attribute.
        
        :param name: The name to convert (label or friendly_name).
        :return: The matching PropertyTag instance.
        :raises SPSDKValueError: If no matching PropertyTag is found.
        """
        for item in cls.__members__.values():
            if item.label == name or item.friendly_name == name:
                return item
        raise SPSDKValueError(f"There is no {cls.__name__} item with name {name} defined")

    @classmethod
    def from_index(cls, index: int, family: Optional[FamilyRevision] = None) -> "PropertyTag":
        """Convert property index to its corresponding PropertyTag.
        
        The method searches through available properties for the given family
        and returns the PropertyTag that matches the specified index.
        
        :param index: Property index to search for.
        :param family: Device family to get properties from, defaults to None.
        :return: The matching PropertyTag instance.
        :raises SPSDKError: If no matching PropertyTag is found for the given index.
        """
        properties = get_properties(family)
        for idx, prop in properties.items():
            if idx == index:
                return prop
        raise SPSDKError(f"No such a property with index {index} found")
COMMON_PROPERTY_INDEXES = {
    0x00: PropertyTag.LIST_PROPERTIES,
    0x01: PropertyTag.CURRENT_VERSION,
    0x02: PropertyTag.AVAILABLE_PERIPHERALS,
    0x03: PropertyTag.FLASH_START_ADDRESS,
    0x04: PropertyTag.FLASH_SIZE,
    0x05: PropertyTag.FLASH_SECTOR_SIZE,
    0x06: PropertyTag.FLASH_BLOCK_COUNT,
    0x07: PropertyTag.AVAILABLE_COMMANDS,
    0x08: PropertyTag.CRC_CHECK_STATUS,
    0x09: PropertyTag.LAST_ERROR,
    0x0A: PropertyTag.VERIFY_WRITES,
    0x0B: PropertyTag.MAX_PACKET_SIZE,
    0x0C: PropertyTag.RESERVED_REGIONS,
    0x0D: PropertyTag.VALIDATE_REGIONS,
    0x0E: PropertyTag.RAM_START_ADDRESS,
    0x0F: PropertyTag.RAM_SIZE,
    0x10: PropertyTag.SYSTEM_DEVICE_IDENT,
    0x11: PropertyTag.FLASH_SECURITY_STATE,
    0x12: PropertyTag.UNIQUE_DEVICE_IDENT,
    0x13: PropertyTag.FLASH_FAC_SUPPORT,
    0x14: PropertyTag.FLASH_ACCESS_SEGMENT_SIZE,
    0x15: PropertyTag.FLASH_ACCESS_SEGMENT_COUNT,
    0x16: PropertyTag.FLASH_READ_MARGIN,
    0x17: PropertyTag.QSPI_INIT_STATUS,
    0x18: PropertyTag.TARGET_VERSION,
    0x19: PropertyTag.EXTERNAL_MEMORY_ATTRIBUTES,
    0x1A: PropertyTag.RELIABLE_UPDATE_STATUS,
    0x1B: PropertyTag.FLASH_PAGE_SIZE,
    0x1C: PropertyTag.IRQ_NOTIFIER_PIN,
    0x1D: PropertyTag.PFR_KEYSTORE_UPDATE_OPT,
    0x1E: PropertyTag.BYTE_WRITE_TIMEOUT_MS,
    0x1F: PropertyTag.FUSE_LOCKED_STATUS,
    0x20: PropertyTag.BOOT_STATUS_REGISTER,
    0x21: PropertyTag.FIRMWARE_VERSION,
    0x22: PropertyTag.FUSE_PROGRAM_VOLTAGE,
    0x24: PropertyTag.SHE_FLASH_PARTITION,
    0x25: PropertyTag.SHE_BOOT_MODE,
    0xFF: PropertyTag.UNKNOWN,
}

def get_property_index(prop:Union[PropertyTag, int], family:Optional[FamilyRevision] = None) -> int:
    """Get index of given property.
    
    Retrieves the numeric index for a property, either by returning the integer directly
    or by looking up the PropertyTag in the family-specific properties dictionary.
    
    :param prop: Property tag or integer index to look up.
    :param family: Optional family revision to get properties for specific MCU family.
    :raises SPSDKError: When the property tag is not found in the properties dictionary.
    :return: Numeric index of the property.
    """
    if isinstance(prop, int):
        return prop
    properties = get_properties(family)
    for idx, prop_obj in properties.items():
        if prop == prop_obj:
            return idx
    raise SPSDKError(f"Unknown property: {prop.name}")

def get_properties(family: Optional[FamilyRevision] = None)-> dict[int, PropertyTag]:
    """Get all properties including family specific properties if family defined.
    
    This method retrieves common property indexes and optionally merges them with
    family-specific overridden properties from the database if a family is specified.
    
    :param family: Optional family revision to get specific properties for.
    :raises SPSDKValueError: When family has no blhost support defined in database.
    :return: Dictionary mapping property indexes to PropertyTag objects.
    """
    property_indexes = deepcopy(COMMON_PROPERTY_INDEXES)
    if family:
        try:
            overridden_properties = get_db(family).get_dict(DatabaseManager().BLHOST, "overridden_properties", {})
            for index, name in overridden_properties.items():
                property_indexes[index] = PropertyTag.from_name(name)
        except SPSDKValueError:
            logger.warning(f"Family '{family}' has no blhost support defined in the database."
                           "Please verify the family name is correct.")
    return property_indexes

class PeripheryTag(SpsdkEnum):
    """Enumeration of peripheral interface tags for bootloader communication.
    
    This class defines standardized tags that identify different peripheral
    interfaces supported by the bootloader for communication with the host.
    Each tag contains a numeric identifier, short name, and descriptive label
    for the corresponding peripheral interface type.
    """

    UART      = (0x01, "UART", "UART Interface")
    I2C_SLAVE = (0x02, "I2C-Slave", "I2C Slave Interface")
    SPI_SLAVE = (0x04, "SPI-Slave", "SPI Slave Interface")
    CAN       = (0x08, "CAN", "CAN Interface")
    USB_HID   = (0x10, "USB-HID", "USB HID-Class Interface")
    USB_CDC   = (0x20, "USB-CDC", "USB CDC-Class Interface")
    USB_DFU   = (0x40, "USB-DFU", "USB DFU-Class Interface")
    LIN       = (0x80, "LIN", "LIN Interface")


class FlashReadMargin(SpsdkEnum):
    """Flash read margin enumeration for memory operations.
    
    This enumeration defines the different margin levels used when reading
    flash memory to verify data integrity under various conditions.
    
    :cvar NORMAL: Standard read margin for normal operation.
    :cvar USER: User-defined read margin level.
    :cvar FACTORY: Factory-set read margin for production testing.
    """

    NORMAL  = (0, "NORMAL")
    USER    = (1, "USER")
    FACTORY = (2, "FACTORY")


class PfrKeystoreUpdateOpt(SpsdkEnum):
    """PFR keystore update operation options enumeration.
    
    This enumeration defines the available options for updating PFR (Protected Flash Region)
    keystore operations, specifying different methods for provisioning and memory operations.
    """

    KEY_PROVISIONING = (0, "KEY_PROVISIONING", "KeyProvisioning")
    WRITE_MEMORY     = (1, "WRITE_MEMORY", "WriteMemory")
# fmt: on

########################################################################################################################
# McuBoot Properties Values
########################################################################################################################


class PropertyValueBase:
    """Base class for property value representation in SPSDK.

    This class provides a foundation for handling property values with associated
    metadata including property tags, names, and descriptions. Derived classes
    must implement the to_str() method to provide specific string representations
    of their property values.
    """

    __slots__ = ("prop", "name", "desc")

    def __init__(
        self, prop: PropertyTag, name: Optional[str] = None, desc: Optional[str] = None
    ) -> None:
        """Initialize the base of property.

        :param prop: Property tag, see: `PropertyTag`
        :param name: Optional name for the property
        :param desc: Optional description for the property
        """
        self.prop = prop
        self.name = name or prop.label
        self.desc = desc or prop.description

    @property
    def tag(self) -> int:
        """Get the property tag index.

        :return: Integer index representing the property tag.
        """
        return get_property_index(self.prop)

    def __str__(self) -> str:
        """Return string representation of the property.

        Provides a formatted string showing the property description and its value.

        :return: Formatted string in format "description = value".
        """
        return f"{self.desc} = {self.to_str()}"

    def to_str(self) -> str:
        """Convert property value to string representation.

        This is an abstract method that must be implemented by derived classes
        to provide a human-readable string format of the property value.

        :return: String representation of the property value.
        :raises NotImplementedError: Derived class has to implement this method.
        """
        raise NotImplementedError("Derived class has to implement this method.")


class IntValue(PropertyValueBase):
    """Integer-based property value representation.

    This class handles integer property values from MCU boot properties,
    providing formatted string representation and raw integer access with
    support for decimal, hexadecimal, and size formatting options.
    """

    __slots__ = (
        "value",
        "_fmt",
    )

    def __init__(self, prop: PropertyTag, raw_values: list[int], str_format: str = "dec") -> None:
        """Initialize the integer-based property object.

        :param prop: Property tag, see: `PropertyTag`
        :param raw_values: List of integers representing the property
        :param str_format: Format to display the value ('dec', 'hex', 'size')
        """
        super().__init__(prop)
        self._fmt = str_format
        self.value = raw_values[0]

    def to_int(self) -> int:
        """Get the raw integer property representation.

        :return: Integer value of the property.
        """
        return self.value

    def to_str(self) -> str:
        """Get stringified property representation.

        Converts the property value to a formatted string representation using
        the internal format specification.

        :return: Formatted string representation of the property value.
        """
        return int_fmt(self.value, self._fmt)


class IntListValue(PropertyValueBase):
    """Property value container for lists of integers.

    This class represents a property value that contains a list of integer values,
    providing formatted string representation with configurable display format
    and delimiter options for the integer list elements.
    """

    __slots__ = ("value", "_fmt", "delimiter")

    def __init__(
        self,
        prop: PropertyTag,
        raw_values: list[int],
        str_format: str = "hex",
        delimiter: str = ", ",
    ) -> None:
        """Initialize the integer-list-based property object.

        :param prop: Property tag, see: `PropertyTag`
        :param raw_values: List of integers representing the property
        :param str_format: Format to display the value ('dec', 'hex', 'size')
        :param delimiter: Delimiter for values in a list
        """
        super().__init__(prop)
        self._fmt = str_format
        self.value = raw_values
        self.delimiter = delimiter

    def to_str(self) -> str:
        """Get stringified property representation.

        Converts the property values to a formatted string representation using the
        configured format and delimiter.

        :return: String representation of property values in format "[value1,value2,...]".
        """
        values = [int_fmt(v, self._fmt) for v in self.value]
        return f"[{self.delimiter.join(values)}]"


class BoolValue(PropertyValueBase):
    """Boolean property value representation for SPSDK device properties.

    This class handles boolean-based property values with customizable true/false
    representations, allowing flexible interpretation of raw integer values as
    boolean states with configurable string representations.
    """

    __slots__ = (
        "value",
        "_true_values",
        "_false_values",
        "_true_string",
        "_false_string",
    )

    def __init__(
        self,
        prop: PropertyTag,
        raw_values: list[int],
        true_values: tuple[int] = (1,),
        true_string: str = "YES",
        false_values: tuple[int] = (0,),
        false_string: str = "NO",
    ) -> None:
        """Initialize the Boolean-based property object.

        :param prop: Property tag, see: `PropertyTag`
        :param raw_values: List of integers representing the property
        :param true_values: Values representing 'True', defaults to (1,)
        :param true_string: String representing 'True', defaults to 'YES'
        :param false_values: Values representing 'False', defaults to (0,)
        :param false_string: String representing 'False', defaults to 'NO'
        """
        super().__init__(prop)
        self._true_values = true_values
        self._true_string = true_string
        self._false_values = false_values
        self._false_string = false_string
        self.value = raw_values[0]

    def __bool__(self) -> bool:
        """Check if the property value represents a boolean true.

        Evaluates whether the current property value is considered true by checking
        if it exists in the predefined set of true values.

        :return: True if the property value represents a boolean true, False otherwise.
        """
        return self.value in self._true_values

    def to_int(self) -> int:
        """Get the raw integer portion of the property.

        :return: The integer value of the property.
        """
        return self.value

    def to_str(self) -> str:
        """Get stringified property representation.

        Converts the boolean property value to its string representation based on
        the configured true/false string values.

        :return: String representation of the property value.
        """
        return self._true_string if self.value in self._true_values else self._false_string


class EnumValue(PropertyValueBase):
    """Property value wrapper for enumeration-based data.

    This class represents a property value that maps raw integer data to
    enumeration labels, providing both numeric and string representations
    of the property value with fallback handling for unknown values.
    """

    __slots__ = ("value", "enum", "_na_msg")

    def __init__(
        self,
        prop: PropertyTag,
        raw_values: list[int],
        enum: Type[SpsdkEnum],
        na_msg: str = "Unknown Item",
    ) -> None:
        """Initialize the enumeration-based property object.

        :param prop: Property tag, see PropertyTag enum.
        :param raw_values: List of integers representing the property values.
        :param enum: Enumeration class to pick property values from.
        :param na_msg: Message to display if an item is not found in the enum.
        """
        super().__init__(prop)
        self._na_msg = na_msg
        self.enum = enum
        self.value = raw_values[0]

    def to_int(self) -> int:
        """Get the raw integer portion of the property.

        :return: The integer value of the property.
        """
        return self.value

    def to_str(self) -> str:
        """Get stringified property representation.

        Converts the property value to its string representation using the associated enum label.
        If the enum label is not found, returns a formatted string with the raw value.

        :return: String representation of the property value or formatted error message.
        :raises SPSDKKeyError: When enum label cannot be found for the property value.
        """
        try:
            return self.enum.get_label(self.value)
        except SPSDKKeyError:
            return f"{self._na_msg}: {self.value}"


class VersionValue(PropertyValueBase):
    """SPSDK property value container for version information.

    This class represents a property value that contains version data, providing
    methods to access and format version information as both integer and string
    representations.
    """

    __slots__ = ("value",)

    def __init__(self, prop: PropertyTag, raw_values: list[int]) -> None:
        """Initialize the Version-based property object.

        :param prop: Property tag, see: `PropertyTag`
        :param raw_values: List of integers representing the property
        """
        super().__init__(prop)
        self.value = Version(raw_values[0])

    def to_int(self) -> int:
        """Get the raw integer portion of the property.

        :return: The integer value of the property.
        """
        return self.value.to_int()

    def to_str(self) -> str:
        """Get stringified property representation.

        :return: String representation of the property value.
        """
        return self.value.to_str()


class DeviceUidValue(PropertyValueBase):
    """Device UID value property representation.

    This class handles device unique identifier values from MCU properties,
    providing conversion methods to different formats including integer and
    hexadecimal string representations.
    """

    __slots__ = ("value",)

    def __init__(self, prop: PropertyTag, raw_values: list[int]) -> None:
        """Initialize the Version-based property object.

        :param prop: Property tag, see: `PropertyTag`
        :param raw_values: List of integers representing the property
        """
        super().__init__(prop)
        self.value = b"".join(
            [int.to_bytes(val, length=4, byteorder=Endianness.LITTLE.value) for val in raw_values]
        )

    def to_int(self) -> int:
        """Get the raw integer portion of the property.

        Converts the property value bytes to an integer using big-endian byte order.

        :return: Integer representation of the property value.
        """
        return int.from_bytes(self.value, byteorder=Endianness.BIG.value)

    def to_str(self) -> str:
        """Get stringified property representation.

        Converts the property value to a hexadecimal string representation where each byte
        is formatted as a two-digit lowercase hexadecimal value.

        :return: Hexadecimal string representation of the property value.
        """
        return "".join(f"{item:02x}" for item in self.value)


class ReservedRegionsValue(PropertyValueBase):
    """Reserved Regions property value container.

    This class represents and manages reserved memory regions property data,
    parsing raw integer values into structured memory region objects for
    easier access and manipulation.
    """

    __slots__ = ("regions",)

    def __init__(self, prop: PropertyTag, raw_values: list[int]) -> None:
        """Initialize the ReserverRegion-based property object.

        Creates memory regions from raw integer values, filtering out regions with zero size.

        :param prop: Property tag, see: `PropertyTag`
        :param raw_values: List of integers representing the property in pairs (address, size)
        """
        super().__init__(prop)
        self.regions: list[MemoryRegion] = []
        for i in range(0, len(raw_values), 2):
            if raw_values[i + 1] == 0:
                continue
            self.regions.append(MemoryRegion(raw_values[i], raw_values[i + 1]))

    def __str__(self) -> str:
        """Return string representation of the property.

        Provides a formatted string showing the property description followed by
        its detailed string representation.

        :return: Formatted string with property description and detailed content.
        """
        return f"{self.desc} =\n{self.to_str()}"

    def to_str(self) -> str:
        """Get stringified property representation.

        Converts the regions collection into a formatted multi-line string where each region
        is numbered and displayed on a separate line with proper indentation.

        :return: Multi-line string representation of all regions with numbering and indentation.
        """
        return "\n".join([f"    Region {i}: {region}" for i, region in enumerate(self.regions)])


class AvailablePeripheralsValue(PropertyValueBase):
    """Available Peripherals property value container.

    This class represents and manages the available peripherals property value,
    providing methods to convert the raw peripheral data into integer and
    human-readable string formats with peripheral names.
    """

    __slots__ = ("value",)

    def __init__(self, prop: PropertyTag, raw_values: list[int]) -> None:
        """Initialize the AvailablePeripherals-based property object.

        :param prop: Property tag, see: `PropertyTag`
        :param raw_values: List of integers representing the property
        """
        super().__init__(prop)
        self.value = raw_values[0]

    def to_int(self) -> int:
        """Get the raw integer portion of the property.

        :return: The integer value of the property.
        """
        return self.value

    def to_str(self) -> str:
        """Get stringified property representation.

        Converts the property value to a human-readable string by extracting and joining
        the labels of all peripheral tags that match the property's bit flags.

        :return: Comma-separated string of peripheral tag labels that are set in the property value.
        """
        return ", ".join(
            [
                peripheral_tag.label
                for peripheral_tag in PeripheryTag
                if peripheral_tag.tag & self.value
            ]
        )


class AvailableCommandsValue(PropertyValueBase):
    """Available commands property value container.

    This class represents and manages the available commands property from MCU bootloader,
    providing methods to check command availability and convert the bitmask value into
    human-readable command lists.
    """

    __slots__ = ("value",)

    @property
    def tags(self) -> list[int]:
        """Get list of command tags for available commands.

        Returns a list of integer tags representing commands that are available
        based on the current property value. Each bit in the property value
        corresponds to a specific command tag.

        :return: List of integer command tags for available commands.
        """
        return [
            cmd_tag.tag
            for cmd_tag in CommandTag
            if cmd_tag.tag > 0 and (1 << cmd_tag.tag - 1) & self.value
        ]

    def __init__(self, prop: PropertyTag, raw_values: list[int]) -> None:
        """Initialize the AvailableCommands-based property object.

        :param prop: Property tag, see: `PropertyTag`
        :param raw_values: List of integers representing the property
        """
        super().__init__(prop)
        self.value = raw_values[0]

    def __contains__(self, item: int) -> bool:
        """Check if a specific bit position is set in the property value.

        This method implements the 'in' operator for checking if a bit at the given
        position is set (equals 1) in the property's value.

        :param item: Bit position to check (1-based indexing).
        :return: True if the bit at the specified position is set, False otherwise.
        """
        return isinstance(item, int) and bool((1 << item - 1) & self.value)

    def to_str(self) -> str:
        """Get stringified property representation.

        Converts the property value to a list of command tag labels that correspond
        to the bits set in the property value.

        :return: List of command tag labels for bits set in the property value.
        """
        return [
            cmd_tag.label  # type: ignore
            for cmd_tag in CommandTag
            if cmd_tag.tag > 0 and (1 << cmd_tag.tag - 1) & self.value
        ]


class IrqNotifierPinValue(PropertyValueBase):
    """IRQ notifier pin property value container.

    This class represents and manages IRQ (Interrupt Request) notifier pin configuration
    data, providing access to pin number, port number, and enablement status from raw
    property values.
    """

    __slots__ = ("value",)

    @property
    def pin(self) -> int:
        """Get the pin number used for reporting IRQ.

        Extracts the pin number from the lower 8 bits of the value.

        :return: Pin number (0-255) used for IRQ reporting.
        """
        return self.value & 0xFF

    @property
    def port(self) -> int:
        """Get the port number used for reporting IRQ.

        Extracts the port number from bits 8-15 of the property value using bitwise
        operations to isolate the relevant byte.

        :return: Port number as an integer value (0-255).
        """
        return (self.value >> 8) & 0xFF

    @property
    def enabled(self) -> bool:
        """Indicates whether IRQ reporting is enabled.

        :return: True if IRQ reporting is enabled, False otherwise.
        """
        return bool(self.value & (1 << 31))

    def __init__(self, prop: PropertyTag, raw_values: list[int]) -> None:
        """Initialize the IrqNotifierPin-based property object.

        :param prop: Property tag, see: `PropertyTag`
        :param raw_values: List of integers representing the property
        """
        super().__init__(prop)
        self.value = raw_values[0]

    def __bool__(self) -> bool:
        """Return the boolean representation of the property status.

        :return: True if the property is enabled, False otherwise.
        """
        return self.enabled

    def to_str(self) -> str:
        """Get stringified property representation.

        :return: String representation of the IRQ port property including port, pin, and enabled status.
        """
        return (
            f"IRQ Port[{self.port}], Pin[{self.pin}] is {'enabled' if self.enabled else 'disabled'}"
        )


class ExternalMemoryAttributesValue(PropertyValueBase):
    """External memory attributes property value container.

    This class represents and manages attribute information for external memories
    in SPSDK bootloader operations, including memory geometry parameters such as
    start address, total size, page size, sector size, and block size.
    """

    __slots__ = (
        "value",
        "mem_id",
        "start_address",
        "total_size",
        "page_size",
        "sector_size",
        "block_size",
    )

    def __init__(self, prop: PropertyTag, raw_values: list[int], mem_id: int = 0) -> None:
        """Initialize the ExternalMemoryAttributes-based property object.

        :param prop: Property tag, see: `PropertyTag`
        :param raw_values: List of integers representing the property
        :param mem_id: ID of the external memory
        """
        super().__init__(prop)
        self.mem_id = mem_id
        self.start_address = (
            raw_values[1] if raw_values[0] & ExtMemPropTags.START_ADDRESS.tag else None
        )
        self.total_size = (
            raw_values[2] * 1024 if raw_values[0] & ExtMemPropTags.SIZE_IN_KBYTES.tag else None
        )
        self.page_size = raw_values[3] if raw_values[0] & ExtMemPropTags.PAGE_SIZE.tag else None
        self.sector_size = raw_values[4] if raw_values[0] & ExtMemPropTags.SECTOR_SIZE.tag else None
        self.block_size = raw_values[5] if raw_values[0] & ExtMemPropTags.BLOCK_SIZE.tag else None
        self.value = raw_values[0]

    def to_str(self) -> str:
        """Get stringified property representation.

        Formats the property object into a human-readable string containing available
        property information such as start address, total size, page size, sector size,
        and block size.

        :return: Comma-separated string of formatted property values.
        """
        str_values = []
        if self.start_address is not None:
            str_values.append(f"Start Address: 0x{self.start_address:08X}")
        if self.total_size is not None:
            str_values.append(f"Total Size:    {size_fmt(self.total_size)}")
        if self.page_size is not None:
            str_values.append(f"Page Size:     {size_fmt(self.page_size)}")
        if self.sector_size is not None:
            str_values.append(f"Sector Size:   {size_fmt(self.sector_size)}")
        if self.block_size is not None:
            str_values.append(f"Block Size:    {size_fmt(self.block_size)}")
        return ", ".join(str_values)


class FuseLock:
    """Fuse Lock representation for MCU OTP (One-Time Programmable) memory.

    This class represents the lock status of individual fuses in the MCU's OTP memory,
    providing information about whether a specific fuse index is locked or unlocked.
    """

    def __init__(self, index: int, locked: bool) -> None:
        """Initialize object representing information about fuse lock.

        :param index: Value of OTP index.
        :param locked: Status of the lock, true if locked.
        """
        self.index = index
        self.locked = locked

    def __str__(self) -> str:
        """Return string representation of the fuse status.

        Formats the fuse information including its index and lock status in a
        human-readable format.

        :return: Formatted string showing fuse index and lock status.
        """
        status = "LOCKED" if self.locked else "UNLOCKED"
        return f"  FUSE{(self.index):03d}: {status}\r\n"


class FuseLockRegister:
    """OTP Controller Fuse Lock Register representation.

    This class represents a fuse lock register from the OTP (One-Time Programmable)
    controller, providing access to individual fuse lock status bits and their
    formatted representation.
    """

    def __init__(self, value: int, index: int, start: int = 0) -> None:
        """Initialize object representing the OTP Controller Program Locked Status.

        Creates bitfields for each fuse position from the start index to bit 31,
        indicating whether each fuse is locked based on the register value.

        :param value: Value of the register containing lock status bits.
        :param index: Base index of the fuse register.
        :param start: Bit position to start processing from (default is 0).
        """
        self.value = value
        self.index = index
        self.msg = ""
        self.bitfields: list[FuseLock] = []

        shift = 0
        for _ in range(start, 32):
            locked = (value >> shift) & 1
            self.bitfields.append(FuseLock(index + shift, bool(locked)))
            shift += 1

    def __str__(self) -> str:
        """Get stringified property representation.

        Converts the property to its string representation, including any associated
        bitfields if present.

        :return: Formatted string representation of the property with bitfields.
        """
        if self.bitfields:
            for bitfield in self.bitfields:
                self.msg += str(bitfield)
        return f"\r\n{self.msg}"


class FuseLockedStatus(PropertyValueBase):
    """SPSDK Fuse Locked Status Property.

    This class represents and manages the locked status of OTP (One-Time Programmable)
    fuses in NXP MCU devices. It processes raw register values and provides structured
    access to individual fuse lock states through register and bitfield representations.
    """

    __slots__ = ("fuses",)

    def __init__(self, prop: PropertyTag, raw_values: list[int]) -> None:
        """Initialize the FuseLockedStatus property object.

        :param prop: Property tag, see: `PropertyTag`
        :param raw_values: List of integers representing the property
        """
        super().__init__(prop)
        self.fuses: list[FuseLockRegister] = []
        idx = 0
        for count, val in enumerate(raw_values):
            start = 0
            if count == 0:
                start = 16
            self.fuses.append(FuseLockRegister(val, idx, start))
            idx += 32
            if count == 0:
                idx -= 16

    def to_str(self) -> str:
        """Get stringified property representation.

        Converts the OTP Controller Program Locked Status registers to a formatted
        string representation showing each register's status with its index.

        :return: Formatted string containing all OTP Controller Program Locked Status
            registers with their respective indices.
        """
        msg = "\r\n"
        for count, register in enumerate(self.fuses):
            msg += f"OTP Controller Program Locked Status {count} Register: {register}"
        return msg

    def get_fuses(self) -> list[FuseLock]:
        """Get list of fuses bitfield objects.

        The method iterates through all fuse registers and extracts their bitfield objects
        into a single flat list.

        :return: List of FuseLockBitfield objects from all fuse registers.
        """
        fuses = []
        for registers in self.fuses:
            fuses.extend(registers.bitfields)
        return fuses


class SHEFlashPartition(PropertyValueBase):
    """SHE Flash Partition property representation for SPSDK mboot operations.

    This class handles the parsing and formatting of SHE (Secure Hardware Extension)
    flash partition properties, including maximum key capacity and flash size
    configuration for CSEc (Cryptographic Services Engine compact) operations.
    """

    __slots__ = ("max_keys", "flash_size")

    def __init__(self, prop: PropertyTag, raw_values: list[int]) -> None:
        """Initialize the SHE Flash Partition property object.

        :param prop: Property tag, see: `PropertyTag`
        :param raw_values: List of integers representing the property
        """
        super().__init__(prop)
        self.max_keys = raw_values[0] & 0x03
        self.flash_size = (raw_values[0] >> 8) & 0x03

    def to_str(self) -> str:
        """Get stringified property representation.

        Converts the property values into a human-readable string format that displays
        EEPROM flash size and maximum keys configuration.

        :return: Formatted string containing flash size and maximum keys information.
        """
        max_keys_mapping = {
            0: "0 Keys, CSEc disabled",
            1: "max 5 Key",
            2: "max 10 Keys",
            3: "max 20 Keys",
        }
        flash_size_mapping = {
            0: "64kB",
            1: "48kB",
            2: "32kB",
            3: "0kB",
        }
        return (
            f"{flash_size_mapping[self.flash_size]} EEPROM "
            f"with {max_keys_mapping[self.max_keys]}"
        )


class SHEBootMode(PropertyValueBase):
    """SHE Boot Mode property representation for SPSDK mboot operations.

    This class handles the parsing and formatting of SHE (Secure Hardware Extension) boot mode
    properties, extracting boot mode type and boot size information from raw property values.
    The class provides human-readable formatting of boot mode configurations including strict,
    serial, parallel, and undefined boot modes.
    """

    __slots__ = ("size", "mode")

    def __init__(self, prop: PropertyTag, raw_values: list[int]) -> None:
        """Initialize the SHE Boot Mode property object.

        :param prop: Property tag, see: `PropertyTag`
        :param raw_values: List of integers representing the property
        """
        super().__init__(prop)
        self.size = raw_values[0] & 0x3FFF_FFFF
        self.mode = (raw_values[0] >> 30) & 0x03

    def to_str(self) -> str:
        """Get stringified property representation.

        Converts the SHE (Secure Hardware Extension) boot property into a human-readable
        string format showing boot mode and size information.

        :return: Formatted string containing SHE boot mode and size details.
        """
        mode_mapping = {0: "Strict Boot", 1: "Serial Boot", 2: "Parallel Boot", 3: "Undefined"}
        return (
            f"SHE Boot Mode: {mode_mapping.get(self.mode, 'Unknown')} ({self.mode})\n"
            f"SHE Boot Size: {size_fmt(self.size // 8)} (0x{self.size:_x})"
        )

    def __str__(self) -> str:
        """Return string representation of the object.

        :return: String representation obtained from to_str() method.
        """
        return self.to_str()


########################################################################################################################
# McuBoot property response parser
########################################################################################################################

PROPERTY_RESPONSE: dict[PropertyTag, dict] = {
    PropertyTag.CURRENT_VERSION: {"class": VersionValue, "kwargs": {}},
    PropertyTag.AVAILABLE_PERIPHERALS: {
        "class": AvailablePeripheralsValue,
        "kwargs": {},
    },
    PropertyTag.FLASH_START_ADDRESS: {
        "class": IntValue,
        "kwargs": {"str_format": "hex"},
    },
    PropertyTag.FLASH_SIZE: {"class": IntValue, "kwargs": {"str_format": "size"}},
    PropertyTag.FLASH_SECTOR_SIZE: {
        "class": IntValue,
        "kwargs": {"str_format": "size"},
    },
    PropertyTag.FLASH_BLOCK_COUNT: {"class": IntValue, "kwargs": {"str_format": "dec"}},
    PropertyTag.AVAILABLE_COMMANDS: {"class": AvailableCommandsValue, "kwargs": {}},
    PropertyTag.CRC_CHECK_STATUS: {
        "class": EnumValue,
        "kwargs": {"enum": StatusCode, "na_msg": "Unknown CRC Status code"},
    },
    PropertyTag.VERIFY_WRITES: {
        "class": BoolValue,
        "kwargs": {"true_string": "ON", "false_string": "OFF"},
    },
    PropertyTag.LAST_ERROR: {
        "class": EnumValue,
        "kwargs": {"enum": StatusCode, "na_msg": "Unknown Error"},
    },
    PropertyTag.MAX_PACKET_SIZE: {"class": IntValue, "kwargs": {"str_format": "size"}},
    PropertyTag.RESERVED_REGIONS: {"class": ReservedRegionsValue, "kwargs": {}},
    PropertyTag.VALIDATE_REGIONS: {
        "class": BoolValue,
        "kwargs": {"true_string": "ON", "false_string": "OFF"},
    },
    PropertyTag.RAM_START_ADDRESS: {"class": IntValue, "kwargs": {"str_format": "hex"}},
    PropertyTag.RAM_SIZE: {"class": IntValue, "kwargs": {"str_format": "size"}},
    PropertyTag.SYSTEM_DEVICE_IDENT: {
        "class": IntValue,
        "kwargs": {"str_format": "hex"},
    },
    PropertyTag.FLASH_SECURITY_STATE: {
        "class": BoolValue,
        "kwargs": {
            "true_values": (0x00000000, 0x5AA55AA5),
            "true_string": "UNSECURE",
            "false_values": (0x00000001, 0xC33CC33C),
            "false_string": "SECURE",
        },
    },
    PropertyTag.UNIQUE_DEVICE_IDENT: {"class": DeviceUidValue, "kwargs": {}},
    PropertyTag.FLASH_FAC_SUPPORT: {
        "class": BoolValue,
        "kwargs": {"true_string": "ON", "false_string": "OFF"},
    },
    PropertyTag.FLASH_ACCESS_SEGMENT_SIZE: {
        "class": IntValue,
        "kwargs": {"str_format": "size"},
    },
    PropertyTag.FLASH_ACCESS_SEGMENT_COUNT: {
        "class": IntValue,
        "kwargs": {"str_format": "int32"},
    },
    PropertyTag.FLASH_READ_MARGIN: {
        "class": EnumValue,
        "kwargs": {"enum": FlashReadMargin, "na_msg": "Unknown Margin"},
    },
    PropertyTag.QSPI_INIT_STATUS: {
        "class": EnumValue,
        "kwargs": {"enum": StatusCode, "na_msg": "Unknown Error"},
    },
    PropertyTag.TARGET_VERSION: {"class": VersionValue, "kwargs": {}},
    PropertyTag.EXTERNAL_MEMORY_ATTRIBUTES: {
        "class": ExternalMemoryAttributesValue,
        "kwargs": {"mem_id": None},
    },
    PropertyTag.RELIABLE_UPDATE_STATUS: {
        "class": EnumValue,
        "kwargs": {"enum": StatusCode, "na_msg": "Unknown Error"},
    },
    PropertyTag.FLASH_PAGE_SIZE: {"class": IntValue, "kwargs": {"str_format": "size"}},
    PropertyTag.IRQ_NOTIFIER_PIN: {"class": IrqNotifierPinValue, "kwargs": {}},
    PropertyTag.PFR_KEYSTORE_UPDATE_OPT: {
        "class": EnumValue,
        "kwargs": {"enum": PfrKeystoreUpdateOpt, "na_msg": "Unknown"},
    },
    PropertyTag.BYTE_WRITE_TIMEOUT_MS: {
        "class": IntValue,
        "kwargs": {"str_format": "dec"},
    },
    PropertyTag.FUSE_LOCKED_STATUS: {
        "class": FuseLockedStatus,
        "kwargs": {},
    },
    PropertyTag.BOOT_STATUS_REGISTER: {
        "class": IntValue,
        "kwargs": {"str_format": "int32"},
    },
    PropertyTag.FIRMWARE_VERSION: {
        "class": IntValue,
        "kwargs": {"str_format": "int32"},
    },
    PropertyTag.FUSE_PROGRAM_VOLTAGE: {
        "class": BoolValue,
        "kwargs": {
            "true_string": "Over Drive Voltage (2.5 V)",
            "false_string": "Normal Voltage (1.8 V)",
        },
    },
    PropertyTag.SHE_FLASH_PARTITION: {"class": SHEFlashPartition, "kwargs": {}},
    PropertyTag.SHE_BOOT_MODE: {"class": SHEBootMode, "kwargs": {}},
    PropertyTag.VERIFY_ERASE: {
        "class": BoolValue,
        "kwargs": {"true_string": "ENABLE", "false_string": "DISABLE"},
    },
    PropertyTag.LIFE_CYCLE_STATE: {
        "class": BoolValue,
        "kwargs": {
            "true_values": (0x00000000, 0x5AA55AA5),
            "true_string": "development life cycle",
            "false_values": (0x00000001, 0xC33CC33C),
            "false_string": "deployment life cycle",
        },
    },
    PropertyTag.UNKNOWN: {
        "class": IntListValue,
        "kwargs": {"str_format": "hex"},
    },
}


def parse_property_value(
    property_tag: Union[int, PropertyTag],
    raw_values: list[int],
    ext_mem_id: Optional[int] = None,
    family: Optional[FamilyRevision] = None,
) -> Optional[PropertyValueBase]:
    """Parse the property value received from the device.

    The method converts raw property data from device into a structured property object.
    It handles property tag conversion and applies family-specific configurations.

    :param property_tag: Tag representing the property, either as integer or PropertyTag enum.
    :param raw_values: List of integer values received from the device.
    :param ext_mem_id: ID of the external memory used to read the property, defaults to None.
    :param family: Supported family revision for property parsing, defaults to None.
    :return: Object representing the parsed property or None if parsing fails.
    """
    assert isinstance(raw_values, list)
    properties_dict = get_properties(family)
    if isinstance(property_tag, int):
        if property_tag in list(properties_dict.keys()):
            property_tag = next(
                prop for idx, prop in properties_dict.items() if idx == property_tag
            )
        else:
            property_tag = PropertyTag.UNKNOWN

    property_response = PROPERTY_RESPONSE[property_tag]
    cls: Callable = property_response["class"]
    kwargs: dict = property_response["kwargs"]
    if "mem_id" in kwargs:
        kwargs["mem_id"] = ext_mem_id
    obj = cls(property_tag, raw_values, **kwargs)
    return obj


def get_property_tag_label(
    mboot_property: Union[PropertyTag, int], family: Optional[FamilyRevision] = None
) -> tuple[int, str]:
    """Get property tag and label from property identifier.

    Converts property identifier (either PropertyTag enum or integer) to a tuple
    containing the property index and its human-readable label. For unknown
    integer properties, returns "Unknown" as the label.

    :param mboot_property: Property identifier as PropertyTag enum or integer value.
    :param family: Optional family revision for property lookup context.
    :return: Tuple containing property index (int) and property label (str).
    """
    if isinstance(mboot_property, int):
        try:
            prop = PropertyTag.from_index(mboot_property, family)
            return mboot_property, prop.label
        except SPSDKKeyError:
            logger.warning(f"Unknown property id: {mboot_property} ({hex(mboot_property)})")
            return mboot_property, "Unknown"

    return get_property_index(mboot_property, family), mboot_property.label
