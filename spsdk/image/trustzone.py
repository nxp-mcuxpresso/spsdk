#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module provides support for TrustZone configuration data."""
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
from spsdk.utils.registers import Registers
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)


class TrustZoneType(SpsdkEnum):
    """Enum defining various types of TrustZone types."""

    ENABLED = (0x0, "ENABLED", "TrustZone enabled with default settings")
    CUSTOM = (0x1, "CUSTOM", "TrustZone enabled with custom settings")
    DISABLED = (0x2, "DISABLED", "Disabled")


class TrustZone(FeatureBaseClass):
    """Provide creation of binary data to set up the TrustZone engine in CM-33."""

    FEATURE = DatabaseManager.TZ

    def __init__(self, family: FamilyRevision) -> None:
        """Initialize the trustzone."""
        self.family = family
        if family.name not in [x.name for x in get_families(DatabaseManager.TZ)]:
            raise SPSDKValueError(f"The {family} family doesn't support TrustZone")
        self.regs = Registers(family, DatabaseManager.TZ, base_endianness=Endianness.LITTLE)

    @classmethod
    def get_validation_schemas_from_cfg(cls, config: Config) -> list[dict[str, Any]]:
        """Get validation schema based on configuration.

        If the class doesn't behave generally, just override this implementation.

        :param config: Valid configuration
        :return: Validation schemas
        """
        config.check(cls.get_validation_schemas_basic())
        family = FamilyRevision.load_from_config(config)
        return get_tz_class(family).get_validation_schemas(family)

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Create the validation schema.

        :param family: Family description.
        :raises SPSDKError: Family or revision is not supported.
        :return: List of validation schemas.
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
        """Alternate constructor using configuration data.

        :raises SPSDKError: Invalid configuration file.
        :return: TrustZone class instance.
        """
        family = FamilyRevision.load_from_config(config)
        ret = cls(family)
        ret.regs.load_from_config(config.get_config("trustZonePreset"))
        return ret

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the TrustZOne.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        ret = Config()

        ret["family"] = self.family.name
        ret["revision"] = self.family.revision
        ret["tzpOutputFile"] = data_path + f"{self.family.name}_tz.yaml"
        ret["trustZonePreset"] = dict(self.regs.get_config())

        return ret

    @property
    def is_customized(self) -> bool:
        """The trustzone has customized values.

        :return: True if the TrustZone is customized, False otherwise.
        """
        return not self.regs.has_reset_value

    def __len__(self) -> int:
        return len(self.regs) * 4

    def __repr__(self) -> str:
        return self.__str__()

    def __str__(self) -> str:
        if self.is_customized:
            return "TrustZone with customized values."
        return "TrustZone with default values(Just enabled)."

    def export(self) -> bytes:
        """Return the TrustZone data as bytes."""
        return self.regs.export()

    @classmethod
    def parse(cls, data: bytes, family: Optional[FamilyRevision] = None) -> Self:
        """Parse object from bytes array.

        :param data: Bytes array containing TrustZone configuration
        :param family: Optional family revision for parsing
        :raises SPSDKValueError: If family is not provided
        :return: Parsed TrustZone instance
        """
        if family is None:
            raise SPSDKValueError("The family parameter must be defined")
        ret = cls(family=family)
        ret.regs.parse(data)
        return ret


@dataclass
class TrustZoneV2Record:
    """Dataclass representing a TrustZone v2.0 configuration record.

    Operation modes based on skip_write, skip_readback, and mask values:

    | Mode               | skip_write | skip_readback | mask     | Operations with register |
    |--------------------|------------|---------------|----------|--------------------------|
    | read-modify-write  | False      | False         | non-zero | read+write+read+read     |
    |  + readback        |            |               |          |                          |
    | write + readback   | False      | False         | 0x0      | write+read+read          |
    | read-modify-write  | False      | True          | non-zero | read+write               |
    | write              | False      | True          | 0x0      | write                    |
    """

    RECORD_SIZE = 12

    address: int  # Register address (lowest 2 bits will be zeroed)
    value: int  #  Value to write to the register
    mask: int = 0  #  Optional mask to apply to the value during write/read operation
    skip_write: bool = False  # Whether to skip writing to this record (Does just read operation)
    skip_readback: bool = False  # Whether to skip readback for this record

    def export(self) -> bytes:
        """Export the TrustZone V2 record as bytes."""
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
        """Parse a TrustZone V2 record from bytes."""
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
        """Load TrustZone V2 configuration from a configuration dictionary."""
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

        :return: Configuration dictionary
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
    """Provide creation of binary data to set up the TrustZone engine in CM-33 version 2.0."""

    FEATURE = DatabaseManager.TZ
    MAGIC_CONST_START = 0x534D5A54  # "TZMS" Magic word to mark start of TrustZone configuration
    MAGIC_CONST_END = 0x454D5A54  # "TZME" Magic word to mark end of TrustZone configuration

    def __init__(
        self, family: FamilyRevision, records: Optional[list[TrustZoneV2Record]] = None
    ) -> None:
        """Initialize the trustzone.

        :param family: Family revision for the trustzone configuration
        :param records: Optional list of TrustZone V2 records
        """
        self.family = family
        self.records: list[TrustZoneV2Record] = records or []

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Create the validation schema.

        :param family: Family description.
        :raises SPSDKError: Family or revision is not supported.
        :return: List of validation schemas.
        """
        sch_cfg = get_schema_file(DatabaseManager.TZ)["tz_v2"]
        sch_family = get_schema_file("general")["family"]
        update_validation_schema_family(
            sch_family["properties"], cls.get_supported_families(), family
        )
        return [sch_family, sch_cfg]

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Alternate constructor using configuration data.

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
        """Create configuration of the TrustZOne.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        ret = Config()

        ret["family"] = self.family.name
        ret["revision"] = self.family.revision
        ret["tzpOutputFile"] = data_path + f"{self.family.name}_tz.yaml"
        ret["trustZoneRecords"] = [record.get_config() for record in self.records]

        return ret

    @property
    def is_customized(self) -> bool:
        """The trustzone has customized values.

        :return: True if the TrustZone is customized, False otherwise.
        """
        return bool(len(self.records) > 0)

    def __len__(self) -> int:
        return (
            4 + 4 + 12 * len(self.records) + 4
        )  # Magic start + Records count + Records + Magic end

    def __repr__(self) -> str:
        return f"TrustZone v2. for {self.family.name}"

    def __str__(self) -> str:
        return f"TrustZone v2. for {self.family.name} (Records: {len(self.records)})"

    def export(self) -> bytes:
        """Return the TrustZone data as bytes."""
        data = self.MAGIC_CONST_START.to_bytes(length=4, byteorder="little")
        data += len(self.records).to_bytes(length=4, byteorder="little")
        for record in self.records:
            data += record.export()
        data += self.MAGIC_CONST_END.to_bytes(length=4, byteorder="little")
        return data

    @classmethod
    def parse(cls, data: bytes, family: Optional[FamilyRevision] = None) -> Self:
        """Parse object from bytes array.

        :param data: Bytes array containing TrustZone configuration
        :param family: Optional family revision for parsing
        :raises SPSDKValueError: If family is not provided
        :return: Parsed TrustZone instance
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

        :param data: Binary image data to search in
        :return: Offset of the TrustZone block if found, None otherwise
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

    :param family: Family revision to determine TrustZone class
    :return: Appropriate TrustZone class implementation
    :raises SPSDKError: If no matching TrustZone class is found
    """
    classes: dict[str, Union[Type[TrustZone], Type[TrustZoneV2]]] = {
        "v1": TrustZone,
        "v2": TrustZoneV2,
    }
    db = get_db(family)
    tz_version = db.get_str(DatabaseManager.TZ, "version")

    return classes.get(tz_version, TrustZone)
