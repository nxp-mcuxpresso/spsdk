#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for HSE key catalog configuration.

This module provides classes for creating, parsing, and manipulating HSE key catalog
configurations, including key group entries for both NVM and RAM catalogs.
"""

from struct import calcsize, pack, unpack
from typing import Any

from typing_extensions import Self

from spsdk.ele.ele_message import LITTLE_ENDIAN, UINT8, UINT16
from spsdk.exceptions import SPSDKParsingError, SPSDKValueError
from spsdk.image.hse.common import HseKeyBits, KeyType
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, update_validation_schema_family
from spsdk.utils.spsdk_enum import SpsdkEnum


class MuMask(SpsdkEnum):
    """Enumeration of HSE MU (Message Unit) masks.

    Defines the possible MU instances that can access a key group.
    """

    NONE = (0, "NONE", "No MU access")
    MU0 = (1, "MU0", "Access for MU0")
    MU1 = (2, "MU1", "Access for MU1")
    ALL = (3, "ALL", "Access for all MUs")


class KeyGroupOwner(SpsdkEnum):
    """Enumeration of HSE key group owners.

    Defines the possible owners for key groups in HSE key catalogs.
    """

    ANY = (0, "ANY", "Any owner (CUST or OEM)")
    CUST = (1, "CUST", "Customer owner")
    OEM = (2, "OEM", "OEM owner")


class KeyGroupCfgEntry:
    """HSE Key Group Configuration Entry.

    Describes a key group in the HSE key catalog, including key type, size, count, and access rights.
    """

    FORMAT = LITTLE_ENDIAN + UINT8 + UINT8 + UINT8 + UINT8 + UINT16 + UINT8 + UINT8

    def __init__(
        self,
        mu_mask: MuMask,
        group_owner: KeyGroupOwner,
        key_type: KeyType,
        num_of_key_slots: int,
        max_key_bit_len: HseKeyBits,
    ) -> None:
        """Initialize the key group configuration entry.

        :param family: The family revision
        :param mu_mask: MU mask specifying which MUs can access this key group
        :param group_owner: Owner of the key group (ANY, CUST, OEM)
        :param key_type: Type of keys in this group
        :param num_of_key_slots: Number of key slots in this group
        :param max_key_bit_len: Maximum key bit length for keys in this group
        """
        self.mu_mask = mu_mask
        self.group_owner = group_owner
        self.key_type = key_type
        self.num_of_key_slots = num_of_key_slots
        self.max_key_bit_len = max_key_bit_len

    def export(self) -> bytes:
        """Pack the key group configuration entry into bytes.

        :return: Packed key group configuration entry bytes
        """
        return pack(
            LITTLE_ENDIAN + UINT8 + UINT8 + UINT8 + UINT8 + UINT16 + UINT8 + UINT8,
            self.mu_mask.tag,
            self.group_owner.tag,
            self.key_type.tag,
            self.num_of_key_slots,
            self.max_key_bit_len.value,
            0,  # reserved[0]
            0,  # reserved[1]
        )

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse the raw key group configuration data into structured fields.

        :param data: Raw key group configuration data as bytes
        :param family: Family revision
        :return: HseKeyGroupCfgEntry instance
        :raises SPSDKParsingError: If data is missing or has invalid length
        """
        if not data:
            raise SPSDKParsingError("No data set for key group configuration")
        if len(data) < cls.get_size():
            raise SPSDKParsingError(f"Invalid data length for key group configuration: {len(data)}")

        (
            mu_mask_tag,
            group_owner_tag,
            key_type_tag,
            num_of_key_slots,
            max_key_bit_len,
            _,  # reserved[0]
            _,  # reserved[1]
        ) = unpack(cls.FORMAT, data[: cls.get_size()])

        return cls(
            mu_mask=MuMask.from_tag(mu_mask_tag),
            group_owner=KeyGroupOwner.from_tag(group_owner_tag),
            key_type=KeyType.from_tag(key_type_tag),
            num_of_key_slots=num_of_key_slots,
            max_key_bit_len=HseKeyBits(max_key_bit_len),
        )

    @classmethod
    def get_size(cls) -> int:
        """Get the size of the key group configuration entry in bytes.

        :return: Size in bytes
        """
        return calcsize(LITTLE_ENDIAN + UINT8 + UINT8 + UINT8 + UINT8 + UINT16 + UINT8 + UINT8)

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load key group configuration from a configuration file.

        :param config: Configuration object
        :return: KeyGroupCfgEntry instance
        :raises SPSDKValueError: If the configuration is invalid
        """
        # Extract MU mask
        mu_mask_str = config.get_str("muMask", "ALL")
        mu_mask = MuMask.from_label(mu_mask_str)

        # Extract group owner
        group_owner_str = config.get_str("groupOwner", "ANY")
        group_owner = KeyGroupOwner.from_label(group_owner_str)

        # Extract key type
        key_type_str = config.get_str("keyType")
        key_type = KeyType.from_label(key_type_str)

        # Extract number of key slots
        num_of_key_slots = config.get_int("numOfKeySlots")

        # Extract max key bit length
        max_key_bit_len_value = config.get_int("maxKeyBitLen")
        # Check if it's a named constant or a direct value
        max_key_bit_len = HseKeyBits(max_key_bit_len_value)
        return cls(
            mu_mask=mu_mask,
            group_owner=group_owner,
            key_type=key_type,
            num_of_key_slots=num_of_key_slots,
            max_key_bit_len=max_key_bit_len,
        )

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the Feature.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        config = Config(
            {
                "muMask": self.mu_mask.label,
                "groupOwner": self.group_owner.label,
                "keyType": self.key_type.label,
                "numOfKeySlots": self.num_of_key_slots,
                "maxKeyBitLen": self.max_key_bit_len.value,
            }
        )
        return config

    def __str__(self) -> str:
        """Format the key group configuration for display.

        :return: Formatted string representation
        """
        ret = "Key Group Configuration:\n"
        ret += f"MU Mask: {self.mu_mask.label} (0x{self.mu_mask.tag:02X})\n"
        ret += f"Group Owner: {self.group_owner.label} (0x{self.group_owner.tag:02X})\n"
        ret += f"Key Type: {self.key_type.label} (0x{self.key_type.tag:02X})\n"
        ret += f"Number of Key Slots: {self.num_of_key_slots}\n"
        ret += f"Max Key Bit Length: {self.max_key_bit_len}\n"
        return ret

    def __repr__(self) -> str:
        """Return a simplified string representation of the HseKeyGroupCfgEntry object.

        :return: String representation
        """
        return (
            f"HseKeyGroupCfgEntry(type={self.key_type.label}, "
            f"owner={self.group_owner.label}, "
            f"slots={self.num_of_key_slots}, "
            f"bits={self.max_key_bit_len})"
        )


class KeyCatalogCfg(FeatureBaseClass):
    """HSE Key Catalog Configuration.

    Contains the configuration for both NVM and RAM key catalogs, including
    the key group entries for each catalog.
    """

    FEATURE = DatabaseManager.HSE
    SUB_FEATURE = "key_catalog"

    def __init__(
        self,
        family: FamilyRevision,
        nvm_key_groups: list[KeyGroupCfgEntry],
        ram_key_groups: list[KeyGroupCfgEntry],
    ) -> None:
        """Initialize the key catalog configuration.

        :param family: The family revision
        :param nvm_key_groups: List of key group entries for the NVM catalog
        :param ram_key_groups: List of key group entries for the RAM catalog
        :raises SPSDKValueError: If the key catalog configuration is invalid
        """
        self.family = family
        self.nvm_key_groups = nvm_key_groups
        self.ram_key_groups = ram_key_groups

        # Validate the key catalog configuration
        self._validate_key_catalogs()

    def _validate_key_catalogs(self) -> None:
        """Validate the key catalog configurations.

        Checks that the key catalogs meet the HSE requirements:
        - At least one group should be defined for each catalog
        - SHE key groups are properly configured
        - Key group owners are valid for their catalog type
        - Key types are valid for their catalog type

        :raises SPSDKValueError: If key catalog configuration is invalid
        """
        # Check that at least one group is defined for each catalog
        if not self.nvm_key_groups:
            raise SPSDKValueError("At least one group must be defined for NVM key catalog")
        if not self.ram_key_groups:
            raise SPSDKValueError("At least one group must be defined for RAM key catalog")

        # Check NVM catalog
        she_group_count = 0
        for i, group in enumerate(self.nvm_key_groups):
            # Check if this is a SHE key group (group 0-4)
            is_she_group = group.key_type == KeyType.SHE
            if is_she_group:
                if i > 4:
                    raise SPSDKValueError("SHE key groups can only be in groups 0-4")
                she_group_count += 1
                # SHE groups must have ANY owner
                if group.group_owner != KeyGroupOwner.ANY:
                    raise SPSDKValueError("SHE key groups must have ANY owner")
                # First SHE group must be at index 0
                if she_group_count == 1 and i != 0:
                    raise SPSDKValueError(
                        "First SHE key group must be mapped to group 0 in NVM catalog"
                    )
            # Check that SHARED_SECRET is not in NVM catalog
            if group.key_type == KeyType.SHARED_SECRET:
                raise SPSDKValueError(
                    "SHARED_SECRET key groups can only be used in RAM key catalog"
                )

        # Check RAM catalog
        for group in self.ram_key_groups:
            # RAM key owner must always be ANY
            if group.group_owner != KeyGroupOwner.ANY:
                raise SPSDKValueError("RAM key groups must have ANY owner")

            # Check that RSA_PAIR is not in RAM catalog
            if group.key_type == KeyType.RSA_PAIR:
                raise SPSDKValueError("RSA_PAIR key groups can only be used in NVM key catalog")

    @property
    def nvm_catalog_cfg_size(self) -> int:
        """Get the size of the NVM key catalog configuration in bytes.

        The size includes all key group entries plus the terminating zero entry.

        :return: Size in bytes
        """
        return (len(self.nvm_key_groups) + 1) * KeyGroupCfgEntry.get_size()

    @property
    def ram_catalog_cfg_size(self) -> int:
        """Get the size of the RAM key catalog configuration in bytes.

        The size includes all key group entries plus the terminating zero entry.

        :return: Size in bytes
        """
        return (len(self.ram_key_groups) + 1) * KeyGroupCfgEntry.get_size()

    def export_nvm_catalog(self) -> bytes:
        """Export the NVM key catalog to bytes.

        :return: Serialized NVM key catalog
        """
        result = b""
        # Add all NVM key group descriptors
        for group in self.nvm_key_groups:
            result += group.export()

        # Add terminating zero entry
        result += bytes(KeyGroupCfgEntry.get_size())

        return result

    def export_ram_catalog(self) -> bytes:
        """Export the RAM key catalog to bytes.

        :return: Serialized RAM key catalog
        """
        result = b""
        # Add all RAM key group descriptors
        for group in self.ram_key_groups:
            result += group.export()

        # Add terminating zero entry
        result += bytes(KeyGroupCfgEntry.get_size())

        return result

    def export(self) -> bytes:
        """Export the complete key catalog configuration to bytes.

        The exported data contains both NVM and RAM key catalogs, with each catalog
        consisting of key group entries followed by a terminating zero entry.

        Format:
        - NVM key group entries (variable number)
        - NVM terminating zero entry
        - RAM key group entries (variable number)
        - RAM terminating zero entry

        :return: Serialized key catalog configuration
        """
        # Export NVM catalog
        nvm_catalog = self.export_nvm_catalog()

        # Export RAM catalog
        ram_catalog = self.export_ram_catalog()

        # Combine both catalogs
        return nvm_catalog + ram_catalog

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision = FamilyRevision("unknown")) -> Self:
        """Parse the raw key catalog data into structured fields.

        The input data should contain both NVM and RAM catalogs concatenated together.
        Each catalog consists of key group entries followed by a terminating zero entry.

        :param data: Raw key catalog data containing both NVM and RAM catalogs
        :param family: Family revision
        :return: KeyCatalogCfg instance
        :raises SPSDKParsingError: If data is missing or has invalid format
        """
        if not data:
            raise SPSDKParsingError("Missing data for key catalog configuration")

        entry_size = KeyGroupCfgEntry.get_size()

        # First, find the end of the NVM catalog (marked by a zero entry)
        nvm_end = 0
        while nvm_end + entry_size <= len(data):
            entry_data = data[nvm_end : nvm_end + entry_size]
            if all(b == 0 for b in entry_data):
                # Found terminating zero entry
                nvm_end += entry_size
                break
            nvm_end += entry_size

        if nvm_end == 0 or nvm_end > len(data):
            raise SPSDKParsingError("Could not find NVM catalog terminator")

        # Split the data into NVM and RAM portions
        nvm_data = data[:nvm_end]
        ram_data = data[nvm_end:]

        if not ram_data:
            raise SPSDKParsingError("Missing RAM catalog data")

        # Parse NVM key groups
        nvm_key_groups = []
        offset = 0

        while offset + entry_size <= len(nvm_data):
            entry_data = nvm_data[offset : offset + entry_size]
            # Check if this is a terminating zero entry
            if all(b == 0 for b in entry_data):
                break

            entry = KeyGroupCfgEntry.parse(entry_data)
            nvm_key_groups.append(entry)
            offset += entry_size

        # Parse RAM key groups
        ram_key_groups = []
        offset = 0

        while offset + entry_size <= len(ram_data):
            entry_data = ram_data[offset : offset + entry_size]
            # Check if this is a terminating zero entry
            if all(b == 0 for b in entry_data):
                break

            entry = KeyGroupCfgEntry.parse(entry_data)
            ram_key_groups.append(entry)
            offset += entry_size

        return cls(
            family=family,
            nvm_key_groups=nvm_key_groups,
            ram_key_groups=ram_key_groups,
        )

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load key catalog configuration from a configuration file.

        :param config: Configuration object
        :return: KeyCatalogCfg instance
        :raises SPSDKValueError: If the configuration is invalid
        """
        # Get family information
        family = FamilyRevision.load_from_config(config)

        # Load NVM key groups
        nvm_key_groups = []
        nvm_configs = config.get_list("nvmKeyGroups", [])
        for group_config in nvm_configs:
            nvm_key_groups.append(KeyGroupCfgEntry.load_from_config(Config(group_config)))

        # Load RAM key groups
        ram_key_groups = []
        ram_configs = config.get_list("ramKeyGroups", [])
        for group_config in ram_configs:
            ram_key_groups.append(KeyGroupCfgEntry.load_from_config(Config(group_config)))

        return cls(
            family=family,
            nvm_key_groups=nvm_key_groups,
            ram_key_groups=ram_key_groups,
        )

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the Feature.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        # Create base config with family information
        config = Config(
            {
                "family": self.family.name,
                "revision": self.family.revision,
            }
        )

        # Add NVM key groups
        nvm_groups_config = []
        for group in self.nvm_key_groups:
            group_config = group.get_config(data_path)
            nvm_groups_config.append(group_config)
        config["nvmKeyGroups"] = nvm_groups_config

        # Add RAM key groups
        ram_groups_config = []
        for group in self.ram_key_groups:
            group_config = group.get_config(data_path)
            ram_groups_config.append(group_config)
        config["ramKeyGroups"] = ram_groups_config

        return config

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Create the list of validation schemas.

        :param family: The CPU/MPU
        :return: List of validation schemas.
        """
        schemas = get_schema_file(DatabaseManager.HSE)
        family_schema = get_schema_file("general")["family"]
        update_validation_schema_family(
            sch=family_schema["properties"], devices=cls.get_supported_families(), family=family
        )
        return [family_schema, schemas["key_catalog"]]

    @classmethod
    def get_config_template(
        cls,
        family: FamilyRevision,
    ) -> str:
        """Get feature configuration template.

        :param family: The MCU family name.
        :return: Template file string representation.
        """
        schemas = cls.get_validation_schemas(family)
        return cls._get_config_template(family, schemas)

    def __str__(self) -> str:
        """Format the key catalog configuration for display.

        :return: Formatted string representation
        """
        ret = "HSE Key Catalog Configuration:\n"

        ret += "\nNVM Key Catalog:\n"
        ret += f"Number of groups: {len(self.nvm_key_groups)}\n"
        for i, group in enumerate(self.nvm_key_groups):
            ret += f"\nGroup {i}:\n"
            group_str = str(group)
            # Indent the group string
            ret += "\n".join(f"  {line}" for line in group_str.split("\n"))

        ret += "\n\nRAM Key Catalog:\n"
        ret += f"Number of groups: {len(self.ram_key_groups)}\n"
        for i, group in enumerate(self.ram_key_groups):
            ret += f"\nGroup {i}:\n"
            group_str = str(group)
            # Indent the group string
            ret += "\n".join(f"  {line}" for line in group_str.split("\n"))

        return ret

    def __repr__(self) -> str:
        """Return a simplified string representation of the KeyCatalogCfg object.

        :return: String representation
        """
        return f"KeyCatalogCfg(family={self.family}, NVM groups={len(self.nvm_key_groups)}, RAM groups={len(self.ram_key_groups)})"
