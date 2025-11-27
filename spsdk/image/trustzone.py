#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK TrustZone configuration management utilities.

This module provides functionality for handling TrustZone security configuration
data in SPSDK image processing. It supports both legacy and version 2 TrustZone
record formats for configuring memory regions and security policies.
"""

import logging
from dataclasses import dataclass
from struct import pack, unpack
from typing import Any, Optional, Type, Union

from typing_extensions import Self

from spsdk.exceptions import SPSDKValueError
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, get_db, get_families, update_validation_schema_family
from spsdk.utils.misc import Endianness
from spsdk.utils.registers import Registers, RegistersPreValidationHook
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)


class TrustZoneType(SpsdkEnum):
    """TrustZone configuration type enumeration.

    Defines the available TrustZone configuration modes for secure and non-secure
    world partitioning in ARM Cortex-M processors.
    """

    ENABLED = (0x0, "ENABLED", "TrustZone enabled with default settings")
    CUSTOM = (0x1, "CUSTOM", "TrustZone enabled with custom settings")
    DISABLED = (0x2, "DISABLED", "Disabled")


class TrustZone(FeatureBaseClass):
    """TrustZone configuration manager for ARM Cortex-M33 processors.

    This class provides functionality to create and manage binary data for configuring
    the TrustZone security engine in ARM Cortex-M33 based NXP MCUs. It handles TrustZone
    preset configurations, validation schemas, and binary export operations.

    :cvar FEATURE: Database manager feature identifier for TrustZone operations.
    :cvar PRE_VALIDATION_CFG_HOOK: Pre-validation hook for trustZonePreset register keys.
    """

    FEATURE = DatabaseManager.TZ
    PRE_VALIDATION_CFG_HOOK = RegistersPreValidationHook(register_keys=["trustZonePreset"])

    def __init__(self, family: FamilyRevision) -> None:
        """Initialize the TrustZone configuration for specified family.

        Creates a new TrustZone instance with registers configuration for the given
        MCU family. Validates that the family supports TrustZone functionality.

        :param family: MCU family and revision specification for TrustZone configuration.
        :raises SPSDKValueError: If the specified family doesn't support TrustZone.
        """
        self.family = family
        if family.name not in [x.name for x in get_families(DatabaseManager.TZ)]:
            raise SPSDKValueError(f"The {family} family doesn't support TrustZone")
        self.regs = Registers(family, DatabaseManager.TZ, base_endianness=Endianness.LITTLE)

    @classmethod
    def get_validation_schemas_from_cfg(cls, config: Config) -> list[dict[str, Any]]:
        """Get validation schemas based on configuration.

        Retrieves the appropriate validation schemas for TrustZone configuration by first validating
        the provided configuration against basic schemas, then loading the family revision and
        returning the family-specific validation schemas. This method can be overridden in
        subclasses for custom behavior.

        :param config: Valid configuration object containing TrustZone settings
        :return: List of validation schema dictionaries for the specified family
        :raises SPSDKError: Invalid configuration or unsupported family
        """
        config.check(cls.get_validation_schemas_basic())
        family = FamilyRevision.load_from_config(config)
        return get_tz_class(family).get_validation_schemas(family)

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get validation schemas for TrustZone configuration.

        Creates validation schemas for both family configuration and TrustZone preset
        settings, updating the family schema with supported families and integrating
        the TrustZone register validation schema.

        :param family: Family description containing chip family and revision information.
        :raises SPSDKError: Family or revision is not supported.
        :return: List containing family validation schema and TrustZone configuration schema.
        """
        sch_cfg = get_schema_file(DatabaseManager.TZ)["tz"]
        sch_family = get_schema_file("general")["family"]
        update_validation_schema_family(
            sch_family["properties"], cls.get_supported_families(), family
        )

        sch_cfg["properties"]["trustZonePreset"] = cls(family).regs.get_validation_schema()
        return [sch_family, sch_cfg]

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Create TrustZone instance from configuration data.

        This alternate constructor initializes a TrustZone object using the provided
        configuration, loading family information and trust zone preset settings.

        :param config: Configuration object containing family and trustZonePreset data.
        :raises SPSDKError: Invalid configuration file.
        :return: TrustZone class instance.
        """
        family = FamilyRevision.load_from_config(config)
        ret = cls(family)
        ret.regs.load_from_config(config.get_config("trustZonePreset"))
        return ret

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the TrustZone.

        The method generates a configuration dictionary containing family information, revision,
        output file path, and TrustZone preset settings.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary with TrustZone settings.
        """
        ret = Config()

        ret["family"] = self.family.name
        ret["revision"] = self.family.revision
        ret["tzpOutputFile"] = data_path + f"{self.family.name}_tz.yaml"
        ret["trustZonePreset"] = dict(self.regs.get_config())

        return ret

    @property
    def is_customized(self) -> bool:
        """Check if the TrustZone configuration has customized values.

        This method determines whether the TrustZone registers contain custom values
        or are still at their reset/default state.

        :return: True if the TrustZone is customized, False otherwise.
        """
        return not self.regs.has_reset_value

    def __len__(self) -> int:
        """Get the total size of TrustZone registers in bytes.

        Calculates the size by multiplying the number of registers by 4 bytes
        (32-bit register size).

        :return: Total size in bytes of all TrustZone registers.
        """
        return len(self.regs) * 4

    def __repr__(self) -> str:
        """Return string representation of the object.

        This method delegates to __str__() to provide a string representation
        suitable for debugging and development purposes.

        :return: String representation of the object.
        """
        return self.__str__()

    def __str__(self) -> str:
        """Get string representation of TrustZone configuration.

        Returns a human-readable description indicating whether the TrustZone uses
        customized values or default values with just enabled state.

        :return: String description of TrustZone configuration status.
        """
        if self.is_customized:
            return "TrustZone with customized values."
        return "TrustZone with default values(Just enabled)."

    def export(self) -> bytes:
        """Export TrustZone configuration data as binary representation.

        The method serializes the current TrustZone register configuration into a binary format
        that can be used for device programming or storage.

        :return: Binary representation of TrustZone configuration data.
        """
        return self.regs.export()

    @classmethod
    def parse(cls, data: bytes, family: Optional[FamilyRevision] = None) -> Self:
        """Parse TrustZone configuration from bytes array.

        :param data: Bytes array containing TrustZone configuration data.
        :param family: Family revision required for proper parsing of the configuration.
        :raises SPSDKValueError: If family parameter is not provided.
        :return: Parsed TrustZone instance with loaded configuration.
        """
        if family is None:
            raise SPSDKValueError("The family parameter must be defined")
        ret = cls(family=family)
        ret.regs.parse(data)
        return ret


@dataclass
class TrustZoneV2Record:
    """TrustZone v2.0 configuration record for secure register operations.

    This class represents a single configuration record used in TrustZone v2.0
    implementations for managing secure register access patterns. It encapsulates
    register address, value, mask, and operation flags to control read/write
    behavior during secure provisioning operations.
    Operation modes based on skip_write, skip_readback, and mask values:
    | Mode               | skip_write | skip_readback | mask     | Operations with register |
    |--------------------|------------|---------------|----------|--------------------------|
    | read-modify-write  | False      | False         | non-zero | read+write+read+read     |
    |  + readback        |            |               |          |                          |
    | write + readback   | False      | False         | 0x0      | write+read+read          |
    | read-modify-write  | False      | True          | non-zero | read+write               |
    | write              | False      | True          | 0x0      | write                    |

    :cvar RECORD_SIZE: Size of the record in bytes when exported.
    """

    RECORD_SIZE = 12

    address: int  # Register address (lowest 2 bits will be zeroed)
    value: int  #  Value to write to the register
    mask: int = 0  #  Optional mask to apply to the value during write/read operation
    skip_write: bool = False  # Whether to skip writing to this record (Does just read operation)
    skip_readback: bool = False  # Whether to skip readback for this record

    def export(self) -> bytes:
        """Export the TrustZone V2 record as bytes.

        The method serializes the TrustZone record into a binary format with address flags,
        mask, and value. The address is aligned by masking the lowest 2 bits, and control
        flags are encoded in the least significant bits.

        :return: Binary representation of the TrustZone record (12 bytes total).
        """
        # Mask out lowest 2 bits of address to ensure alignment
        address_flags = self.address & 0xFFFFFFFC

        # Add flags to address
        if self.skip_readback:
            address_flags |= 0x01
        if self.skip_write:
            address_flags |= 0x02

        # Pack record: address + flags (4 bytes), mask (4 bytes), value (4 bytes)
        return pack("<LLL", address_flags, self.mask, self.value)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse a TrustZone V2 record from bytes.

        Extracts address, mask, value and control flags from the binary data format.
        The address field contains embedded flags in the lower 2 bits.

        :param data: Binary data containing the TrustZone V2 record (minimum 12 bytes).
        :raises SPSDKValueError: Invalid data length (less than 12 bytes required).
        :return: New TrustZone V2 record instance with parsed values.
        """
        if len(data) < 12:
            raise SPSDKValueError("Invalid TrustZone V2 record length")
        address_flags, mask, value = unpack("<LLL", data[:12])
        # Extract flags from address
        address = address_flags & 0xFFFFFFFC
        skip_readback = bool(address_flags & 0x01)
        skip_write = bool(address_flags & 0x02)
        return cls(
            address=address,
            value=value,
            mask=mask,
            skip_write=skip_write,
            skip_readback=skip_readback,
        )

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load TrustZone V2 configuration from a configuration dictionary.

        Creates a new TrustZone V2 instance with parameters extracted from the provided
        configuration object.

        :param config: Configuration object containing TrustZone V2 settings.
        :return: New TrustZone V2 instance configured with the specified parameters.
        """
        address = config.get_int("address")
        skip_write = config.get_bool("skip_write", False)
        skip_readback = config.get_bool("skip_readback", False)
        mask = config.get_int("mask", 0)
        value = config.get_int("value")
        return cls(
            address=address,
            value=value,
            mask=mask,
            skip_write=skip_write,
            skip_readback=skip_readback,
        )

    def get_config(self) -> Config:
        """Generate configuration dictionary for TrustZone V2.

        Creates a configuration dictionary containing the TrustZone settings including
        address, value, and optional mask and control flags.

        :return: Configuration dictionary with TrustZone settings.
        """
        cfg = Config(
            {
                "address": hex(self.address),
                "value": hex(self.value),
            }
        )
        if self.mask != 0:
            cfg["mask"] = hex(self.mask)
        if self.skip_readback:
            cfg["skip_readback"] = True
        if self.skip_write:
            cfg["skip_write"] = True
        return cfg


class TrustZoneV2(FeatureBaseClass):
    """TrustZone V2 configuration manager for ARM Cortex-M33 processors.

    This class manages TrustZone security configuration data for ARM Cortex-M33 version 2.0,
    providing functionality to create, validate, and export binary configuration data that
    sets up the TrustZone security engine.

    :cvar MAGIC_CONST_START: Magic word (0x534D5A54) marking start of TrustZone configuration.
    :cvar MAGIC_CONST_END: Magic word (0x454D5A54) marking end of TrustZone configuration.
    """

    FEATURE = DatabaseManager.TZ
    MAGIC_CONST_START = 0x534D5A54  # "TZMS" Magic word to mark start of TrustZone configuration
    MAGIC_CONST_END = 0x454D5A54  # "TZME" Magic word to mark end of TrustZone configuration

    def __init__(
        self, family: FamilyRevision, records: Optional[list[TrustZoneV2Record]] = None
    ) -> None:
        """Initialize the TrustZone configuration.

        :param family: Family revision for the TrustZone configuration.
        :param records: Optional list of TrustZone V2 records to initialize with.
        """
        self.family = family
        self.records: list[TrustZoneV2Record] = records or []

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get validation schemas for TrustZone configuration.

        The method retrieves and combines validation schemas for family configuration
        and TrustZone v2 settings, updating the family schema with supported families.

        :param family: Family description containing family and revision information.
        :raises SPSDKError: Family or revision is not supported.
        :return: List of validation schemas containing family and TrustZone configuration schemas.
        """
        sch_cfg = get_schema_file(DatabaseManager.TZ)["tz_v2"]
        sch_family = get_schema_file("general")["family"]
        update_validation_schema_family(
            sch_family["properties"], cls.get_supported_families(), family
        )
        return [sch_family, sch_cfg]

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Create TrustZone instance from configuration data.

        This alternate constructor parses configuration data to extract family information
        and trust zone records, then creates a new TrustZone instance.

        :param config: Configuration object containing trust zone settings.
        :raises SPSDKError: Invalid configuration file.
        :return: TrustZone class instance.
        """
        family = FamilyRevision.load_from_config(config)
        records_cfg = config.get_list_of_configs("trustZoneRecords")
        records = []
        for record in records_cfg:
            records.append(TrustZoneV2Record.load_from_config(record))
        return cls(family=family, records=records)

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the TrustZone.

        The method generates a configuration dictionary containing family information, revision,
        output file path, and trust zone records for the TrustZone component.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary with TrustZone settings.
        """
        ret = Config()

        ret["family"] = self.family.name
        ret["revision"] = self.family.revision
        ret["tzpOutputFile"] = data_path + f"{self.family.name}_tz.yaml"
        ret["trustZoneRecords"] = [record.get_config() for record in self.records]

        return ret

    @property
    def is_customized(self) -> bool:
        """Check if the TrustZone configuration has customized values.

        A TrustZone is considered customized when it contains one or more configuration records
        that modify the default security settings.

        :return: True if the TrustZone has custom configuration records, False otherwise.
        """
        return bool(len(self.records) > 0)

    def __len__(self) -> int:
        """Get the total length of the TrustZone data structure in bytes.

        Calculates the size including magic start marker, records count field,
        all records data, and magic end marker.

        :return: Total size in bytes of the TrustZone structure.
        """
        return (
            4 + 4 + 12 * len(self.records) + 4
        )  # Magic start + Records count + Records + Magic end

    def __repr__(self) -> str:
        """Return string representation of TrustZone object.

        Provides a human-readable string representation showing the TrustZone version
        and the target MCU family name.

        :return: String representation in format "TrustZone v2. for {family_name}".
        """
        return f"TrustZone v2. for {self.family.name}"

    def __str__(self) -> str:
        """Return string representation of TrustZone object.

        Provides a formatted string containing the TrustZone version, target family name,
        and the number of records currently stored in the object.

        :return: String representation in format "TrustZone v2. for {family} (Records: {count})".
        """
        return f"TrustZone v2. for {self.family.name} (Records: {len(self.records)})"

    def export(self) -> bytes:
        """Export TrustZone configuration data to binary format.

        The method serializes the TrustZone configuration including magic constants,
        record count, and all individual records into a binary representation suitable
        for firmware integration.

        :return: Binary representation of TrustZone configuration data.
        """
        data = self.MAGIC_CONST_START.to_bytes(length=4, byteorder="little")
        data += len(self.records).to_bytes(length=4, byteorder="little")
        for record in self.records:
            data += record.export()
        data += self.MAGIC_CONST_END.to_bytes(length=4, byteorder="little")
        return data

    @classmethod
    def parse(cls, data: bytes, family: Optional[FamilyRevision] = None) -> Self:
        """Parse TrustZone configuration from bytes array.

        The method validates magic constants at the start and end of the data,
        extracts the number of records, and parses each TrustZone record sequentially.

        :param data: Bytes array containing TrustZone configuration data.
        :param family: Family revision required for parsing the configuration.
        :raises SPSDKValueError: If family is not provided or data format is invalid.
        :return: Parsed TrustZone instance with loaded configuration records.
        """
        if family is None:
            raise SPSDKValueError("The family parameter must be defined")
        ret = cls(family=family)
        # Validate magic constant at the start
        if int.from_bytes(data[:4], byteorder="little") != cls.MAGIC_CONST_START:
            raise SPSDKValueError("Invalid TrustZone configuration: Incorrect start magic constant")
        records_count = int.from_bytes(data[4:8], byteorder="little")
        current_offset = 8
        for _ in range(records_count):
            ret.records.append(TrustZoneV2Record.parse(data[current_offset:]))
            current_offset += TrustZoneV2Record.RECORD_SIZE
        # Validate magic constant at the end
        if (
            int.from_bytes(data[current_offset : current_offset + 4], byteorder="little")
            != cls.MAGIC_CONST_END
        ):
            raise SPSDKValueError("Invalid TrustZone configuration: Incorrect end magic constant")

        return ret

    @staticmethod
    def find_trustzone_block_offset(data: bytes) -> Optional[int]:
        """Find the offset of the TrustZone block in the data.

        This method searches for a valid TrustZone configuration block by looking for the
        magic start constant (TZMS) followed by a valid record count and the magic end
        constant (TZME) at the expected position.

        :param data: Binary image data to search in.
        :return: Offset of the TrustZone block if found, None otherwise.
        """
        magic_start = TrustZoneV2.MAGIC_CONST_START.to_bytes(4, "little")
        magic_end = TrustZoneV2.MAGIC_CONST_END.to_bytes(4, "little")
        for offset in range(0, len(data), 4):
            if data[offset : offset + 4] == magic_start:
                records_cnt = int.from_bytes(data[offset + 4 : offset + 8], "little")
                if (
                    data[
                        offset
                        + 8
                        + records_cnt * TrustZoneV2Record.RECORD_SIZE : offset
                        + 12
                        + records_cnt * TrustZoneV2Record.RECORD_SIZE
                    ]
                    == magic_end
                ):
                    return offset

        return None


def get_tz_class(family: FamilyRevision) -> Union[Type[TrustZone], Type[TrustZoneV2]]:
    """Get the appropriate TrustZone class based on family revision.

    The method determines which TrustZone implementation to use by querying the database
    for the TrustZone version associated with the given family revision.

    :param family: Family revision to determine TrustZone class.
    :return: Appropriate TrustZone class implementation (TrustZone or TrustZoneV2).
    """
    classes: dict[str, Union[Type[TrustZone], Type[TrustZoneV2]]] = {
        "v1": TrustZone,
        "v2": TrustZoneV2,
    }
    db = get_db(family)
    tz_version = db.get_str(DatabaseManager.TZ, "version")

    return classes.get(tz_version, TrustZone)
