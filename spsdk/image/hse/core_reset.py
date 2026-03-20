#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""HSE Core Reset entry data structures and utilities.

This module provides data structures and utilities for managing HSE (Hardware Security Engine)
Core Reset entries, which define the parameters for advanced secure boot configurations
for Application Cores.
"""

from struct import calcsize, pack, unpack
from typing import Any, Dict, List, Union

from typing_extensions import Self

from spsdk.exceptions import SPSDKKeyError, SPSDKValueError
from spsdk.image.hse.common import CoreId
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, update_validation_schema_family
from spsdk.utils.misc import LITTLE_ENDIAN, UINT8, UINT16, UINT32, value_to_int
from spsdk.utils.spsdk_enum import SpsdkEnum, SpsdkIntFlag
from spsdk.utils.verifier import Verifier


class HseCrSanction(SpsdkEnum):
    """HSE Core Reset sanction enumeration.

    Defines the sanctions that can be applied if SMR(s) linked to a Core Reset
    entry fail verification during the secure boot process.
    """

    KEEP_CORE_IN_RESET = (0x7455, "KEEP_CORE_IN_RESET", "Keep the core in reset state")
    DIS_INDIV_KEYS = (0x7433, "DIS_INDIV_KEYS", "Disable individual keys at runtime")
    RESET_SOC = (0x8B17, "RESET_SOC", "Reset the entire SoC")
    DIS_ALL_KEYS = (0x8B1E, "DIS_ALL_KEYS", "Reset the entire SoC")


class HseCrStartOption(SpsdkEnum):
    """HSE Core Reset start option enumeration.

    Specifies whether the Application Core is automatically released from reset
    or requires manual intervention after successful SMR verification.
    """

    AUTO_START = (0x35A5, "AUTO_START", "Automatically release core from reset")
    MANUAL_START = (0x5567, "MANUAL_START", "Manual core release required")


class HseSmrMap(SpsdkIntFlag):
    """HSE SMR Map enumeration using IntFlag for bit manipulation.

    Represents a 32-bit SMR map where each bit specifies a particular SMR entry index from 0-31.
    Multiple SMR entries can be combined using bitwise OR operations.
    """

    NONE = 0
    SMR_0 = 1 << 0
    SMR_1 = 1 << 1
    SMR_2 = 1 << 2
    SMR_3 = 1 << 3
    SMR_4 = 1 << 4
    SMR_5 = 1 << 5
    SMR_6 = 1 << 6
    SMR_7 = 1 << 7
    SMR_8 = 1 << 8
    SMR_9 = 1 << 9
    SMR_10 = 1 << 10
    SMR_11 = 1 << 11
    SMR_12 = 1 << 12
    SMR_13 = 1 << 13
    SMR_14 = 1 << 14
    SMR_15 = 1 << 15
    SMR_16 = 1 << 16
    SMR_17 = 1 << 17
    SMR_18 = 1 << 18
    SMR_19 = 1 << 19
    SMR_20 = 1 << 20
    SMR_21 = 1 << 21
    SMR_22 = 1 << 22
    SMR_23 = 1 << 23
    SMR_24 = 1 << 24
    SMR_25 = 1 << 25
    SMR_26 = 1 << 26
    SMR_27 = 1 << 27
    SMR_28 = 1 << 28
    SMR_29 = 1 << 29
    SMR_30 = 1 << 30
    SMR_31 = 1 << 31

    @classmethod
    def from_int(cls, value: int) -> "HseSmrMap":
        """Create SMR map from integer value.

        :param value: 32-bit integer value
        :return: SMR map
        :raises SPSDKValueError: If value is out of range
        """
        if not 0 <= value <= 0xFFFFFFFF:
            raise SPSDKValueError(f"SMR map value must be 0-0xFFFFFFFF, got {value}")
        return cls(value)


class CoreResetEntry(FeatureBaseClass):
    """HSE Core Reset Entry data structure.

    Defines the parameters of a Core Reset entry in the CR table. The CR table contains
    the configurations for each Application Core that HSE will use to perform advanced
    secure boot operations.

    Important notes:

    - SuperUser rights are needed to install/update a Core Reset entry
    - Updating an existing CR entry requires all preBoot and postBoot SMR(s) linked
      with the previous entry to be verified successfully (applicable only in
      OEM_PROD/IN_FIELD life cycles)
    - The core release strategy is defined by HSE_CORE_RESET_RELEASE_ATTR_ID attribute
      ("ALL-AT-ONCE" or "ONE-BY-ONE")
    - For devices with SD/eMMC support, SMR with source address in SD/eMMC can be used
      only under specific conditions related to core release strategy

    :cvar FORMAT: Binary format specification for the Core Reset entry structure.
    :cvar SIZE: Size of the Core Reset entry structure in bytes.
    """

    FEATURE = DatabaseManager.HSE
    SUB_FEATURE = "cr"
    FORMAT = (
        LITTLE_ENDIAN
        + UINT8  # coreId (hseAppCore_t)
        + UINT8  # reserved0[1]
        + UINT16  # crSanction (hseCrSanction_t)
        + UINT32  # preBootSmrMap
        + UINT32  # passResetAddr
        + UINT32  # altPreBootSmrMap
        + UINT32  # altResetAddr
        + UINT32  # postBootSmrMap
        + UINT16  # startOption (hseCrStartOption_t)
        + UINT8  # reserved1[0]
        + UINT8  # reserved1[1]
        + UINT8  # reserved1[2]
        + UINT8  # reserved1[3]
        + UINT8  # reserved1[4]
        + UINT8  # reserved1[5]
    )
    SIZE = calcsize(FORMAT)

    def __init__(
        self,
        family: FamilyRevision,
        core_id: CoreId = CoreId.CORE_M7_0,
        cr_sanction: HseCrSanction = HseCrSanction.KEEP_CORE_IN_RESET,
        pre_boot_smr_map: Union[HseSmrMap, int, List[Union[int, HseSmrMap]]] = HseSmrMap.NONE,
        pass_reset_addr: int = 0,
        alt_pre_boot_smr_map: Union[HseSmrMap, int, List[Union[int, HseSmrMap]]] = HseSmrMap.NONE,
        alt_reset_addr: int = 0,
        post_boot_smr_map: Union[HseSmrMap, int, List[Union[int, HseSmrMap]]] = HseSmrMap.NONE,
        start_option: HseCrStartOption = HseCrStartOption.AUTO_START,
    ) -> None:
        """Initialize Core Reset Entry.

        Creates a new Core Reset entry with the specified configuration parameters
        for managing application core secure boot behavior.

        :param family: Device family
        :param core_id: Identifies the core ID to be started
        :param cr_sanction: Sanction applied if SMR(s) linked to CR entry fail verification
        :param pre_boot_smr_map: PRE-BOOT SMR(s) verified before releasing core from passResetAddr
        :param pass_reset_addr: Primary address of first instruction after regular reset
        :param alt_pre_boot_smr_map: ALT-PRE-BOOT SMR(s) verified before releasing from altResetAddr
        :param alt_reset_addr: Alternative address of first instruction after regular reset
        :param post_boot_smr_map: POST-BOOT SMR(s) loaded after verifying preBootSmrMap SMR(s)
        :param start_option: Specifies if Application Core is automatically released from reset
        :raises SPSDKValueError: If SMR map configurations are invalid
        """
        self.family = family
        self.core_id = core_id
        self.cr_sanction = cr_sanction
        self.pre_boot_smr_map = self._convert_smr_map(pre_boot_smr_map)
        self.pass_reset_addr = pass_reset_addr
        self.alt_pre_boot_smr_map = self._convert_smr_map(alt_pre_boot_smr_map)
        self.alt_reset_addr = alt_reset_addr
        self.post_boot_smr_map = self._convert_smr_map(post_boot_smr_map)
        self.start_option = start_option

    @classmethod
    def _convert_smr_map(
        cls, smr_map: Union[HseSmrMap, int, List[Union[int, HseSmrMap]]]
    ) -> HseSmrMap:
        """Convert various SMR map formats to HseSmrMap.

        :param smr_map: SMR map in various formats
        :return: HseSmrMap instance
        """
        if isinstance(smr_map, HseSmrMap):
            return smr_map
        elif isinstance(smr_map, (int, str)):
            return HseSmrMap.from_int(value_to_int(smr_map))
        elif isinstance(smr_map, list):
            return HseSmrMap.from_list([f"SMR_{i}" for i in smr_map if isinstance(i, (int))])
        else:
            raise SPSDKValueError(f"Invalid SMR map type: {type(smr_map)}")

    def __str__(self) -> str:
        """Get string representation of Core Reset Entry.

        :return: Human-readable string describing the Core Reset entry configuration
        """
        return (
            f"Core Reset Entry:\n"
            f"  Family: {self.family}\n"
            f"  Core ID: {self.core_id.label}\n"
            f"  Sanction: {self.cr_sanction.label}\n"
            f"  Pre-Boot SMR Map: 0x{self.pre_boot_smr_map:08X}\n"
            f"  Pass Reset Address: 0x{self.pass_reset_addr:08X}\n"
            f"  Alt Pre-Boot SMR Map: 0x{self.alt_pre_boot_smr_map:08X}\n"
            f"  Alt Reset Address: 0x{self.alt_reset_addr:08X}\n"
            f"  Post-Boot SMR Map: 0x{self.post_boot_smr_map:08X}\n"
            f"  Start Option: {self.start_option.label}"
        )

    def __repr__(self) -> str:
        """Get detailed representation of Core Reset Entry.

        :return: Detailed string representation for debugging
        """
        return (
            f"CoreResetEntry( family: {self.family}\n"
            f"core_id={self.core_id!r}, "
            f"cr_sanction={self.cr_sanction!r}, "
            f"pre_boot_smr_map=0x{self.pre_boot_smr_map:08X}, "
            f"pass_reset_addr=0x{self.pass_reset_addr:08X}, "
            f"alt_pre_boot_smr_map=0x{self.alt_pre_boot_smr_map:08X}, "
            f"alt_reset_addr=0x{self.alt_reset_addr:08X}, "
            f"post_boot_smr_map=0x{self.post_boot_smr_map:08X}, "
            f"start_option={self.start_option!r})"
        )

    def verify(self) -> Verifier:
        """Verify Core Reset Entry data and return verification results.

        This method performs comprehensive verification of the Core Reset entry,
        including validation of SMR maps, reset addresses, alignment, and HSE constraints.

        :return: Verifier object containing detailed verification results and any warnings or errors.
        """
        ret = Verifier("Core Reset Entry")
        ret.add_record(
            name="Core ID",
            result=self.core_id in CoreId.get_available_core_ids(self.family),
            value=f"Core with id {self.core_id.label} is supported.",
        )

        ret.add_record(
            "SMR Map Configuration",
            not (self.pre_boot_smr_map == 0 and self.alt_pre_boot_smr_map != 0),
            "If preBootSmrMap is 0, altPreBootSmrMap must also be 0",
        )
        ret.add_record(
            "Pass Reset Configuration",
            not (
                self.pre_boot_smr_map == 0
                and self.post_boot_smr_map == 0
                and self.pass_reset_addr != 0
            ),
            "If preBootSmrMap is 0, passResetAddr must be within a SMR specified by postBootSmrMap",
        )
        ret.add_record_bit_range("Reset Address", self.pass_reset_addr)
        ret.add_record_bit_range("Alt Reset Address", self.alt_reset_addr)
        ret.add_record(
            "Pass Reset Requirement",
            not (self.pre_boot_smr_map != 0 and self.pass_reset_addr == 0),
            "passResetAddr must be specified when preBootSmrMap is non-zero",
        )
        ret.add_record(
            "Alt Reset Requirement",
            not (self.alt_pre_boot_smr_map != 0 and self.alt_reset_addr == 0),
            "altResetAddr must be specified when altPreBootSmrMap is non-zero",
        )
        ret.add_record(
            "Pass Reset Alignment",
            not (self.pass_reset_addr != 0 and self.pass_reset_addr % 4 != 0),
            "passResetAddr must be aligned to 4 bytes",
        )
        ret.add_record(
            "Alt Reset Alignment",
            not (self.alt_reset_addr != 0 and self.alt_reset_addr % 4 != 0),
            "altResetAddr must be aligned to 4 bytes",
        )
        return ret

    def export(self) -> bytes:
        """Export Core Reset Entry to binary format.

        Serializes the Core Reset entry structure into binary format suitable
        for HSE communication and storage.

        :return: Binary representation of the Core Reset entry structure
        """
        return pack(
            self.FORMAT,
            self.core_id.tag,  # coreId
            0,  # reserved0[1]
            self.cr_sanction.tag,  # crSanction
            int(self.pre_boot_smr_map),  # preBootSmrMap
            self.pass_reset_addr,  # passResetAddr
            int(self.alt_pre_boot_smr_map),  # altPreBootSmrMap
            self.alt_reset_addr,  # altResetAddr
            int(self.post_boot_smr_map),  # postBootSmrMap
            self.start_option.tag,  # startOption
            0,
            0,
            0,
            0,
            0,
            0,  # reserved1[6]
        )

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision = FamilyRevision("unknown")) -> Self:
        """Parse Core Reset Entry from binary data.

        Creates a Core Reset entry instance from binary data representation,
        typically received from HSE or loaded from configuration files.

        :param data: Binary data containing the Core Reset entry structure
        :param offset: Offset within the data where the structure begins
        :return: Parsed Core Reset entry instance
        :raises SPSDKValueError: If data is insufficient or contains invalid values
        """
        if len(data) < cls.SIZE:
            raise SPSDKValueError(
                f"Insufficient data for Core Reset entry. "
                f"Expected {cls.SIZE} bytes, got {len(data)}"
            )

        values = unpack(cls.FORMAT, data[: cls.SIZE])

        try:
            core_id = CoreId.from_tag(values[0])
            cr_sanction = HseCrSanction.from_tag(values[2])
            start_option = HseCrStartOption.from_tag(values[8])
        except SPSDKKeyError as e:
            raise SPSDKValueError(f"Invalid enum value in Core Reset entry: {e}") from e

        return cls(
            family=family,
            core_id=core_id,
            cr_sanction=cr_sanction,
            pre_boot_smr_map=HseSmrMap.from_int(values[3]),
            pass_reset_addr=values[4],
            alt_pre_boot_smr_map=HseSmrMap.from_int(values[5]),
            alt_reset_addr=values[6],
            post_boot_smr_map=HseSmrMap.from_int(values[7]),
            start_option=start_option,
        )

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
        schemas["cr"]["properties"]["coreId"]["enum"] = [
            core.label for core in CoreId.get_available_core_ids(family)
        ]
        return [family_schema, schemas["cr"]]

    def to_dict(self) -> Dict[str, Any]:
        """Convert Core Reset Entry to dictionary representation.

        :return: Dictionary containing all Core Reset entry fields
        """
        return {
            "core_id": self.core_id.label,
            "cr_sanction": self.cr_sanction.label,
            "pre_boot_smr_map": f"0x{self.pre_boot_smr_map:08X}",
            "pass_reset_addr": f"0x{self.pass_reset_addr:08X}",
            "alt_pre_boot_smr_map": f"0x{self.alt_pre_boot_smr_map:08X}",
            "alt_reset_addr": f"0x{self.alt_reset_addr:08X}",
            "post_boot_smr_map": f"0x{self.post_boot_smr_map:08X}",
            "start_option": self.start_option.label,
        }

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load Core Reset Entry from configuration.

        :param config: Configuration object containing Core Reset entry settings
        :return: CoreResetEntry instance
        :raises SPSDKValueError: If configuration is invalid
        """
        # Get family
        family = config.get_family()

        # Get basic required fields
        core_id_str = config.get_str("coreId")
        core_id = CoreId.from_label(core_id_str)

        cr_sanction_str = config.get_str("crSanction")
        cr_sanction = HseCrSanction.from_label(cr_sanction_str)

        start_option_str = config.get_str("startOption")
        start_option = HseCrStartOption.from_label(start_option_str)

        # Get SMR maps and addresses
        pre_boot_smr_map = cls._convert_smr_map(config.get("preBootSmrMap", []))
        pass_reset_addr = config.get_int("passResetAddr", default=0)
        alt_pre_boot_smr_map = cls._convert_smr_map(config.get("altPreBootSmrMap", []))
        alt_reset_addr = config.get_int("altResetAddr", default=0)
        post_boot_smr_map = cls._convert_smr_map(config.get("postBootSmrMap", []))

        return cls(
            family=family,
            core_id=core_id,
            cr_sanction=cr_sanction,
            pre_boot_smr_map=pre_boot_smr_map,
            pass_reset_addr=pass_reset_addr,
            alt_pre_boot_smr_map=alt_pre_boot_smr_map,
            alt_reset_addr=alt_reset_addr,
            post_boot_smr_map=post_boot_smr_map,
            start_option=start_option,
        )

    def get_config(self, data_path: str = "./") -> Config:
        """Get configuration dictionary from Core Reset entry.

        :param data_path: Path for data files (not used for Core Reset entries)
        :return: Configuration dictionary that can be used to recreate this Core Reset entry
        """
        config: Config = Config(
            {
                "family": self.family.name,
                "revision": self.family.revision,
                "coreId": self.core_id.label,
                "crSanction": self.cr_sanction.label,
                "preBootSmrMap": f"0x{int(self.pre_boot_smr_map):08X}",
                "passResetAddr": f"0x{int(self.pass_reset_addr):08X}",
                "altPreBootSmrMap": f"0x{int(self.alt_pre_boot_smr_map):08X}",
                "altResetAddr": f"0x{int(self.alt_reset_addr):08X}",
                "postBootSmrMap": f"0x{int(self.post_boot_smr_map):08X}",
                "startOption": self.start_option.label,
            }
        )

        return config
