#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Protected Flash Region (PFR) management utilities.

This module provides comprehensive support for handling Protected Flash Region areas
including CMPA (Customer Manufacturing Programming Area), CFPA (Customer Field
Programmable Area), and related configuration structures for NXP MCUs.
"""

import logging
import math
from dataclasses import dataclass
from typing import Any, Optional, Type

from typing_extensions import Self

from spsdk.apps.utils.utils import SPSDKAppError
from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.crypto.keys import PublicKey, PublicKeyEcc, PublicKeyRsa
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.image.cert_block.rkht import RKHT
from spsdk.pfr.exceptions import SPSDKPfrError, SPSDKPfrRotkhIsNotPresent
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.exceptions import SPSDKRegsErrorRegisterNotFound
from spsdk.utils.family import FamilyRevision, get_db, get_families, update_validation_schema_family
from spsdk.utils.misc import BinaryPattern, Endianness, load_binary, value_to_int
from spsdk.utils.registers import Register, Registers, RegistersPreValidationHook

logger = logging.getLogger(__name__)


@dataclass
class AdditionalDataCfg:
    """Configuration for additional customer data in PFR/IFR areas.

    This class defines the parameters for additional customer data storage in Protected Flash Region
    areas, including enablement status, placement offset, and size constraints for customer-specific
    data within the secure flash regions.
    """

    enabled: bool
    offset: int
    max_size: int


class BaseConfigArea(FeatureBaseClass):
    """Base class for Protected Flash Region (PFR) configuration areas.

    This class provides common functionality for CMPA (Customer Manufacturing
    Programming Area) and CFPA (Customer Field Programming Area) configuration
    management. It handles register loading, binary size calculations, and
    family-specific database operations for NXP MCU protected flash regions.

    :cvar FEATURE: Database feature identifier for PFR operations.
    :cvar SUB_FEATURE: Sub-feature identifier to be defined by subclasses.
    :cvar BINARY_SIZE: Default binary size in bytes for configuration area.
    :cvar ROTKH_SIZE: Size of Root of Trust Key Hash in bytes.
    :cvar ROTKH_REGISTER: Register name for Root of Trust Key Hash.
    :cvar MARK: Binary marker for sealed configuration areas.
    :cvar DESCRIPTION: Human-readable description of the configuration area.
    :cvar IMAGE_PREFILL_PATTERN: Default pattern for prefilling binary images.
    :cvar WRITE_METHOD: Memory interface method name for write operations.
    :cvar READ_METHOD: Memory interface method name for read operations.
    """

    FEATURE = DatabaseManager.PFR
    PRE_VALIDATION_CFG_HOOK = RegistersPreValidationHook(register_keys=["settings"])
    SUB_FEATURE = "SubClassDefineIt"
    BINARY_SIZE = 512
    ROTKH_SIZE = 32
    ROTKH_REGISTER = "ROTKH"
    MARK = b"SEAL"
    DESCRIPTION = "Base Config Area"
    IMAGE_PREFILL_PATTERN = "0x00"
    WRITE_METHOD = "write_memory"
    READ_METHOD = "read_memory"

    def __init__(self, family: FamilyRevision) -> None:
        """Initialize PFR instance for specified device family.

        Sets up the database connection, loads device-specific registers, and initializes
        internal data structures for Protected Flash Region operations.

        :param family: Device family to use, list of supported families is available via 'get_supported_families' method
        :raises SPSDKError: When no device is provided
        :raises SPSDKError: When device is not supported
        """
        self.db = get_db(family)
        self.family = family
        self.computed_fields: dict[str, dict[str, str]] = self.db.get_dict(
            self.FEATURE, [self.SUB_FEATURE, "computed_fields"], {}
        )
        self.registers = self._load_registers(family)
        self._additional_data = bytes()
        self.registers_size = self._get_registers_size()
        has_update_field = self.db.get_bool(self.FEATURE, "has_update_field", default=False)
        if has_update_field:
            update_field_id = self.db.get_str(self.FEATURE, "update_field_id")
            update_field_value = self.db.get_int(
                self.FEATURE, [self.SUB_FEATURE, "update_field_value"]
            )
            update_reg = self.registers.get_reg(update_field_id)
            update_reg.set_value(update_field_value)

    def _get_registers_size(self) -> int:
        """Get binary size from database configuration.

        The method retrieves the size value from the database for the current feature and sub-feature.
        If the size is not specified in the database, it falls back to the default BINARY_SIZE.

        :raises SPSDKValueError: When database access fails (handled internally with fallback).
        :return: Size of the binary in bytes from database or default value.
        """
        try:
            return self.db.get_int(self.FEATURE, [self.SUB_FEATURE, "size"])
        except SPSDKValueError:
            # Fallback to default size if not specified in database
            return self.BINARY_SIZE

    @property
    def binary_size(self) -> int:
        """Get the final binary size of the PFR data.

        The binary size includes both the registers size and any additional data
        that has been added to the PFR structure.

        :return: Total size in bytes of the binary representation.
        """
        return self.registers_size + len(self.additional_data)

    @classmethod
    def get_supported_families(cls, include_predecessors: bool = False) -> list[FamilyRevision]:
        """Get supported families for the feature.

        Retrieves a list of supported family revisions for the current feature class.
        The method handles sub-features and can optionally include predecessor families.

        :param include_predecessors: Whether to include predecessor families in the result.
        :return: List of supported family revisions for the feature.
        """
        sub_feature = None if cls.SUB_FEATURE == "SubClassDefineIt" else cls.SUB_FEATURE

        return get_families(
            feature=cls.FEATURE,
            sub_feature=sub_feature,
            include_predecessors=include_predecessors,
        )

    def __str__(self) -> str:
        """Get string representation of PFR/IFR class.

        Returns a human-readable string representation by delegating to the __repr__ method.

        :return: String representation of the PFR/IFR object.
        """
        return self.__repr__()

    def __repr__(self) -> str:
        """String representation of PFR/IFR class.

        :return: String containing feature, sub-feature, and family information.
        """
        return f"{self.FEATURE} {self.SUB_FEATURE} class for {self.family}."

    @property
    def additional_data(self) -> bytes:
        """Get the additional customer data stored in the configuration area.

        :return: The additional customer data as bytes.
        """
        return self._additional_data

    @additional_data.setter
    def additional_data(self, value: bytes) -> None:
        """Set the additional customer data for the configuration area.

        This method allows setting additional customer data based on the configuration defined in
        additional_data_cfg(). It validates the size and presence of additional customer data before
        setting.

        :param value: The customer data bytes to be set for the configuration area.
        :raises SPSDKPfrError: If additional customer data configuration is invalid or data is not
                              provided.
        """
        cfg = self.additional_data_cfg(self.family)
        if not cfg.enabled:
            raise SPSDKPfrError(
                f"Customer data is not allowed for family {self.family}, area: {self.SUB_FEATURE}"
            )
        if len(value) > cfg.max_size:
            raise SPSDKPfrError(
                f"Customer data size must be maximum {cfg.max_size} bytes, got {len(value)} bytes"
            )
        self._additional_data = value

    @classmethod
    def additional_data_cfg(cls, family: FamilyRevision) -> AdditionalDataCfg:
        """Get the additional customer data configuration for the specified family.

        This method retrieves the additional customer data configuration parameters from the database
        for the specified family and PFR/IFR area.

        :param family: The family revision to get the configuration for.
        :return: AdditionalDataCfg object containing the configuration parameters.
        """
        add_data = get_db(family).get_dict(cls.FEATURE, [cls.SUB_FEATURE, "additional_data"], {})
        return AdditionalDataCfg(
            enabled=add_data.get("enabled", False),
            offset=add_data.get("offset", -1),
            max_size=add_data.get("max_size", 0),
        )

    @classmethod
    def _load_registers(cls, family: FamilyRevision) -> Registers:
        """Load register class for PFR tool.

        This method initializes a Registers object with the specified family configuration,
        sets up computed fields as reserved bitfields based on database configuration,
        and returns the configured registers instance.

        :param family: Device family revision specification.
        :return: Configured Registers instance with computed fields marked as reserved.
        """
        registers = Registers(
            family=family,
            feature=cls.FEATURE,
            base_key=cls.SUB_FEATURE,
            base_endianness=Endianness.LITTLE,
        )
        computed_fields: dict[str, dict[str, str]] = get_db(family).get_dict(
            cls.FEATURE, [cls.SUB_FEATURE, "computed_fields"], {}
        )
        # Set the computed field handler
        for reg, fields in computed_fields.items():
            reg_obj = registers.get_reg(reg)
            for bitfield in fields.keys():
                reg_obj.get_bitfield(bitfield).reserved = True
                logger.debug(f"Hiding bitfield: {bitfield} in {reg}")
        return registers

    def compute_register(self, reg: Register, method: str) -> None:
        """Recalculate register value.

        The method dynamically calls a computation function based on the provided method name
        to update the register's value.

        :param reg: Register to be recalculated.
        :param method: Method name to be used for recalculation of register value.
        :raises SPSDKPfrError: When the computing routine is not found.
        """
        if hasattr(self, method):
            method_ref = getattr(self, method)
            reg.set_value(method_ref(reg.get_value(True)), True)
        else:
            raise SPSDKPfrError(f"The '{method}' compute function doesn't exists.")

    @staticmethod
    def pfr_reg_inverse_high_half(val: int) -> int:
        """Inverse low 16-bits of register value to high 16 bits.

        The function takes the lower 16 bits of the input value, inverts them bitwise,
        and places the result in the upper 16 bits while preserving the original lower
        16 bits.

        :param val: Input register value to process.
        :return: Complete register value with inverted lower bits in upper half.
        """
        ret = val & 0xFFFF
        ret |= (ret ^ 0xFFFF) << 16
        return ret

    @staticmethod
    def pfr_reg_inverse_lower_8_bits(val: int) -> int:
        """Inverse lower 8 bits of register value and place result in bits 8-15.

        This function takes the lower 8 bits of the input value, performs bitwise inversion,
        and places the inverted bits in positions 8-15 while preserving other bits.

        :param val: Input register value to process.
        :return: Complete register value with inverted lower 8 bits placed in bits 8-15.
        """
        ret = val & 0xFFFF_00FF
        inverse = (val & 0xFF) ^ 0xFF
        ret |= inverse << 8
        return ret

    @classmethod
    def get_validation_schemas_basic(cls) -> list[dict[str, Any]]:
        """Create the validation schema for supported families.

        The method generates validation schemas by combining family-specific schema
        with PFR base configuration schema, filtered for supported families only.

        :return: List containing family validation schema and PFR base schema.
        """
        sch_family = get_schema_file("general")["family"]
        update_validation_schema_family(sch_family["properties"], cls.get_supported_families())
        sch_cfg = get_schema_file(DatabaseManager.PFR)

        return [sch_family, sch_cfg["pfr_base"]]

    @classmethod
    def get_validation_schemas_from_cfg(cls, config: Config) -> list[dict[str, Any]]:
        """Get validation schemas based on configuration.

        If the class doesn't behave generally, just override this implementation.
        The method validates the configuration against basic schemas, extracts family
        and area information, and returns appropriate validation schemas for the
        specific IFR/PFR class.

        :param config: Valid configuration object containing family and type information.
        :return: List of validation schema dictionaries for the specified area and family.
        """
        config.check(cls.get_validation_schemas_basic())
        family = FamilyRevision.load_from_config(config)
        area = config.get_str("type")
        klass = get_ifr_pfr_class(area_name=area, family=family)

        return klass.get_validation_schemas(FamilyRevision.load_from_config(config))

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get validation schemas for PFR configuration.

        Creates validation schemas for the Protected Flash Region (PFR) configuration
        including family-specific settings, base configuration, and optional additional data.

        :param family: Family and revision specification for target MCU.
        :raises SPSDKError: Family or revision is not supported.
        :return: List of validation schemas for PFR configuration.
        """
        sch_cfg = get_schema_file(DatabaseManager.PFR)
        sch_family = get_schema_file("general")["family"]
        update_validation_schema_family(
            sch_family["properties"], cls.get_supported_families(), family
        )
        sch_family["main_title"] = (
            f"{cls.FEATURE.upper()} {cls.SUB_FEATURE.upper()} configuration template for {family}"
        )

        try:
            regs = cls._load_registers(family=family)
            sch_cfg["pfr_base"]["properties"]["type"]["template_value"] = cls.__name__.upper()
            sch_cfg["pfr_base"]["properties"]["type"]["enum"] = [
                cls.__name__.upper(),
                cls.__name__.lower(),
            ]
            sch_cfg["pfr_settings"]["properties"]["settings"] = regs.get_validation_schema()
            ret = [sch_family, sch_cfg["pfr_base"], sch_cfg["pfr_settings"]]
            if cls.additional_data_cfg(family).enabled:
                ret.append(sch_cfg["pfr_additional_data"])
            return ret
        except (KeyError, SPSDKError) as exc:
            raise SPSDKError(f"Family {family} is not supported") from exc

    def set_config(self, cfg: Config) -> None:
        """Set a new values configuration.

        The method loads configuration into registers and automatically computes any missing
        bitfield values using predefined computation methods. If a register is used in
        configuration but some computed bitfields are not specified, those bitfields will
        be automatically calculated and a warning will be logged.

        :param cfg: Registers configuration containing register and bitfield definitions.
        """
        self.registers.load_from_config(cfg)
        # Updates necessary register values
        for reg_uid, bitfields_rec in self.computed_fields.items():
            reg = self.registers.get_reg(uid=reg_uid)
            reg_name = reg.find_config_key(cfg)
            if reg_name:
                for bitfield_uid, method in bitfields_rec.items():
                    bitfield = reg.get_bitfield(bitfield_uid)
                    # the register is defined as a value(no bitfields), do not recompute it
                    if not isinstance(cfg[reg_name], dict):
                        continue
                    bitfields_cfg = (
                        cfg.get_config(f"{reg_name}/bitfields")
                        if "bitfields" in cfg[reg_name]
                        else cfg.get_config(reg_name)
                    )
                    # bitfield is defined in config, do not recompute it
                    if bitfield.find_config_key(bitfields_cfg):
                        continue
                    self.compute_register(reg, method)
                    logger.warning(
                        (
                            f"The {reg_name} register has been recomputed, because "
                            f"it has been used in configuration and the bitfield {bitfield.name} "
                            "has not been specified"
                        )
                    )

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load configuration area from PFR configuration.

        Creates a BaseConfigArea object based on the provided configuration, including
        family revision, settings, and optional additional data that can be loaded
        from file or provided as hex string.

        :param config: PFR configuration containing type, settings and optional additional data.
        :return: Configured BaseConfigArea object of the appropriate type.
        :raises SPSDKError: When additional_data cannot be loaded from file or parsed as hex.
        """
        family = FamilyRevision.load_from_config(config)
        klass = CONFIG_AREA_CLASSES[config.get_str("type").lower()]
        settings = config.get_config("settings")
        ret = klass(family)
        ret.set_config(settings)
        additional_data = config.get_str("additional_data", "")
        if additional_data:
            try:
                ret.additional_data = load_binary(config.get_input_file_name("additional_data"))
            except SPSDKError:
                ret.additional_data = bytes.fromhex(additional_data)
        return ret  # type: ignore

    def get_config(self, data_path: str = "./", diff: bool = False) -> Config:
        """Get configuration from loaded PFR.

        Extracts the current PFR configuration including family information, settings,
        and any additional data into a structured configuration object.

        :param data_path: Data path parameter (not used in PFR implementation).
        :param diff: If True, return only configuration values that differ from reset state.
        :return: PFR configuration object containing family, revision, type, settings and
                 optional additional data.
        """
        res_data = Config()
        res_data["family"] = self.family.name
        res_data["revision"] = self.family.revision
        res_data["type"] = self.__class__.__name__.upper()
        res_data["settings"] = dict(self.registers.get_config(diff=diff))
        if self.additional_data:
            res_data["additional_data"] = self.additional_data.hex()
        return res_data

    def _calc_rotkh(self, keys: list[PublicKey]) -> bytes:
        """Calculate ROTKH (Root Of Trust Key Hash).

        The method computes ROTKH using a data structure of 4*32B length where each 32B slot
        contains a hash of individual keys. If fewer than 4 keys are provided, remaining slots
        are filled with null bytes. The algorithm selection must correspond to eFuse settings.

        :param keys: List of public keys to compute ROTKH from.
        :return: ROTKH value padded to the correct width for the target device.
        :raises SPSDKPfrError: Algorithm width doesn't fit into ROTKH field.
        """
        # the data structure use for computing final ROTKH is 4*32B long
        # 32B is a hash of individual keys
        # 4 is the max number of keys, if a key is not provided the slot is filled with '\x00'
        # Some devices have two options to compute ROTKH, so it's needed to be
        # detected the right algorithm and mandatory warn user about this selection because
        # it's MUST correspond to settings in eFuses!
        reg_rotkh = self.registers.find_reg("ROTKH")
        rkht = RKHT.get_class(family=self.family).from_keys(keys=keys)

        if rkht.hash_algorithm_size > reg_rotkh.width:
            raise SPSDKPfrError("The ROTKH field is smaller than used algorithm width.")
        return rkht.rkth().ljust(reg_rotkh.width // 8, b"\x00")

    def _get_seal_start_address(self) -> int:
        """Get start address of seal fields for the family.

        Retrieves the starting address of seal fields by looking up the seal_start
        configuration in the database and returning the corresponding register offset.

        :return: Start address of seal fields as integer offset.
        :raises SPSDKError: When 'seal_start_address' cannot be found in database.
        """
        start = self.db.get_str(self.FEATURE, [self.SUB_FEATURE, "seal_start"])
        if not start:
            raise SPSDKError("Can't find 'seal_start_address' in database.")
        return self.registers.get_reg(start).offset

    def _get_seal_count(self) -> int:
        """Get seal count for the family.

        Retrieves the number of seal fields from the database configuration
        for the current MCU family.

        :raises SPSDKError: When 'seal_count' in database cannot be found.
        :return: Count of seal fields.
        """
        count = self.db.get_int(self.FEATURE, [self.SUB_FEATURE, "seal_count"])
        if not count:
            raise SPSDKError("Can't find 'seal_count' in database")
        return value_to_int(count)

    def export(
        self,
        add_seal: bool = False,
        keys: Optional[list[PublicKey]] = None,
        rotkh: Optional[bytes] = None,
        draw: bool = True,
    ) -> bytes:
        """Export PFR configuration as binary data.

        Generates binary output for PFR (Protected Flash Region) configuration with optional
        sealing and ROTKH (Root of Trust Key Hash) computation. The method can compute ROTKH
        from provided keys or use pre-computed ROTKH value.

        :param add_seal: Finish the export with seal in the PFR record.
        :param keys: List of public keys to compute ROTKH field.
        :param rotkh: Pre-computed ROTKH binary value.
        :param draw: Draw the configuration data in log output.
        :return: Binary block with PFR configuration (CMPA or CFPA).
        :raises SPSDKPfrRotkhIsNotPresent: This PFR block doesn't contain ROTKH field.
        :raises SPSDKError: Invalid data size or cannot determine ROTKH source.
        """
        if keys or rotkh:
            try:
                # ROTKH may or may not be present, derived class defines its presence
                rotkh_reg = self.registers.find_reg(self.ROTKH_REGISTER)
                if rotkh:
                    rotkh_data = rotkh
                elif keys:
                    rotkh_data = self._calc_rotkh(keys)
                else:
                    raise SPSDKError("Cannot determine source of RoTKH data.")
                rotkh_reg.set_value(rotkh_data, False)
            except SPSDKRegsErrorRegisterNotFound as exc:
                raise SPSDKPfrRotkhIsNotPresent(
                    "This device doesn't contain ROTKH register!"
                ) from exc

        image_info = self.registers.image_info(
            size=self.registers_size, pattern=BinaryPattern(self.IMAGE_PREFILL_PATTERN)
        )
        if draw:
            logger.info(image_info.draw())
        data = bytearray(image_info.export())

        if add_seal:
            try:
                seal_start = self._get_seal_start_address()
                seal_count = self._get_seal_count()
                data[seal_start : seal_start + seal_count * 4] = self.MARK * seal_count
            except SPSDKError:
                logger.warning("This device doesn't support sealing of PFR page.")

        if len(data) != self.registers_size:
            raise SPSDKError(
                f"The size of data is {len(data)}, is not equal to {self.registers_size}"
            )
        self._add_additional_data(data)
        return bytes(data)

    def _add_additional_data(self, data: bytearray) -> None:
        """Add additional customer data to the binary data.

        The method handles insertion of customer-defined data either at a specific offset
        or appended to the end of the binary data, based on the family configuration.

        :param data: Binary data to which additional customer data will be added.
        :raises SPSDKError: Invalid offset for additional customer data insertion.
        """
        if not self.additional_data:
            return

        offset = self.additional_data_cfg(self.family).offset
        size = len(self.additional_data)
        logger.info(f"Adding customer defined data of {size} bytes")

        if offset == -1:
            data.extend(self.additional_data)
            logger.info("Additional customer data appended to the end of the binary")
        elif offset >= 0 and offset + size <= len(data):
            data[offset : offset + size] = self.additional_data
            logger.info(f"Additional customer data inserted at offset {offset}")
        elif offset >= len(data):
            padding_size = offset - len(data)
            data.extend(b"\xff" * padding_size)
            data.extend(self.additional_data)
            logger.info(f"Additional customer data inserted with {padding_size} bytes of padding")
        else:
            raise SPSDKError(
                f"Invalid offset {offset} for additional customer data (binary size: {len(data)})"
            )

    @classmethod
    def parse(cls, data: bytes, family: Optional[FamilyRevision] = None) -> Self:
        """Parse input binary data to registers.

        The method parses binary data into PFR registers and handles additional data
        if present and enabled for the specified MCU family.

        :param data: Input binary data of PFR block.
        :param family: The MCU family name.
        :raises SPSDKPfrError: When family parameter is not provided.
        :return: The PFR initialized class.
        """
        if family is None:
            raise SPSDKPfrError("For PFR parse method the family parameter is mandatory")
        ret = cls(family)
        ret.registers.parse(data)
        add_data_enabled = ret.additional_data_cfg(ret.family).enabled
        add_data_offset = ret.additional_data_cfg(ret.family).offset
        if add_data_offset == -1:
            add_data_offset = ret.registers.size
        if add_data_enabled and len(data) > add_data_offset:
            ret.additional_data = data[add_data_offset:]
        return ret

    def __eq__(self, obj: Any) -> bool:
        """Compare if two PFR objects have the same settings.

        This method performs equality comparison by checking if the other object
        is of the same class and has identical family and registers attributes.

        :param obj: Object to compare with this instance.
        :return: True if objects have same settings, False otherwise.
        """
        return (
            isinstance(obj, self.__class__)
            and obj.family == self.family
            and obj.registers == self.registers
        )


class CMPA(BaseConfigArea):
    """Customer Manufacturing Configuration Area.

    This class represents the Customer Manufacturing Programmable Area (CMPA) which is a
    specific configuration area used for manufacturing-related settings and parameters
    in NXP MCU devices.

    :cvar SUB_FEATURE: Identifier for the CMPA sub-feature.
    :cvar DESCRIPTION: Human-readable description of the programmable area.
    """

    SUB_FEATURE = "cmpa"
    DESCRIPTION = "Customer Manufacturing Programmable Area"


class CFPA(BaseConfigArea):
    """Customer In-Field Programmable Area configuration manager.

    This class manages the Customer In-Field Programmable Area (CFPA) configuration
    data for NXP MCU devices, providing functionality to handle customer-specific
    programmable settings that can be modified in the field.

    :cvar SUB_FEATURE: Identifier for the CFPA sub-feature.
    :cvar DESCRIPTION: Human-readable description of the configuration area.
    """

    SUB_FEATURE = "cfpa"
    DESCRIPTION = "Customer In-field Programmable Area"


class ROMCFG(BaseConfigArea):
    """ROM Bootloader Configuration Area for PFR.

    This class manages the ROMCFG region within the Protected Flash Region (PFR),
    which contains configuration data for the ROM bootloader. It handles the
    creation, validation, and processing of ROM bootloader settings.

    :cvar BINARY_SIZE: Fixed size of the ROMCFG region (304 bytes).
    :cvar IMAGE_PREFILL_PATTERN: Default fill pattern for unused areas.
    :cvar DESCRIPTION: Human-readable description of the configuration area.
    """

    FEATURE = DatabaseManager.PFR
    SUB_FEATURE = "romcfg"
    BINARY_SIZE = 304
    IMAGE_PREFILL_PATTERN = "0xFF"
    DESCRIPTION = "ROM Bootloader configurations"


class CMACTABLE(BaseConfigArea):
    """CMAC Table configuration area for Protected Flash Region.

    This class manages the CMAC (Cipher-based Message Authentication Code) table
    which stores cryptographic hashes of multiple boot components for secure boot
    verification in NXP MCUs.

    :cvar BINARY_SIZE: Fixed size of 128 bytes for the CMAC table region.
    :cvar IMAGE_PREFILL_PATTERN: Default fill pattern of 0xFF for unused areas.
    """

    FEATURE = DatabaseManager.PFR
    SUB_FEATURE = "cmactable"
    BINARY_SIZE = 128
    IMAGE_PREFILL_PATTERN = "0xFF"
    DESCRIPTION = "CMAC table - Used to save hashes of multiple boot components"


class IFR(BaseConfigArea):
    """Information Flash Region configuration manager.

    This class manages the Information Flash Region (IFR) configuration area,
    providing functionality for reading and programming once-programmable flash
    memory regions in NXP MCUs.

    :cvar BINARY_SIZE: Size of the IFR binary data in bytes (256).
    :cvar IMAGE_PREFILL_PATTERN: Default fill pattern for uninitialized areas.
    :cvar READ_METHOD: Flash operation method used for reading IFR data.
    :cvar WRITE_METHOD: Flash operation method used for programming IFR data.
    """

    FEATURE = DatabaseManager.PFR
    SUB_FEATURE = "ifr"
    BINARY_SIZE = 256
    IMAGE_PREFILL_PATTERN = "0xFF"
    DESCRIPTION = "Information Flash Region configuration"
    READ_METHOD = "flash_read_resource"
    WRITE_METHOD = "flash_program_once"


class CFPA_CMPA(BaseConfigArea):
    """CFPA and CMPA combined configuration area.

    This class manages the combined Customer Field Programmable Area (CFPA) and
    Customer Manufacturing Programmable Area (CMPA) configuration data for NXP MCUs.
    It provides functionality to handle both configuration areas as a unified
    1024-byte binary structure.

    :cvar SUB_FEATURE: Identifier for the combined CFPA/CMPA feature.
    :cvar BINARY_SIZE: Size of the combined configuration area in bytes.
    :cvar DESCRIPTION: Human-readable description of the configuration area.
    """

    SUB_FEATURE = "cfpa_cmpa"
    BINARY_SIZE = 1024
    DESCRIPTION = "CFPA and CMPA combined configuration area"


CONFIG_AREA_CLASSES: dict[str, Type[BaseConfigArea]] = {
    "cmpa": CMPA,
    "cfpa": CFPA,
    "cfpa_cmpa": CFPA_CMPA,
    "romcfg": ROMCFG,
    "cmactable": CMACTABLE,
    "ifr": IFR,
}


def calc_pub_key_hash(
    public_key: PublicKey,
    sha_width: int = 256,
) -> bytes:
    """Calculate a hash from public key components.

    For RSA keys, uses exponent and modulus. For ECC keys, uses X and Y coordinates.
    The hash is computed by concatenating the key components and applying the specified
    hash algorithm.

    :param public_key: Public key to compute hash from (RSA or ECC).
    :param sha_width: Width of SHA algorithm in bits (default: 256).
    :raises SPSDKError: Unsupported public key type.
    :return: Computed hash as bytes.
    """
    if isinstance(public_key, PublicKeyRsa):
        n_1 = public_key.e
        n1_len = math.ceil(n_1.bit_length() / 8)
        n_2 = public_key.n
        n2_len = math.ceil(n_2.bit_length() / 8)
    elif isinstance(public_key, PublicKeyEcc):
        n_1 = public_key.y
        n1_len = sha_width // 8
        n_2 = public_key.x
        n2_len = sha_width // 8
    else:
        raise SPSDKError(f"Unsupported key type: {type(public_key)}")

    n1_bytes = n_1.to_bytes(n1_len, Endianness.BIG.value)
    n2_bytes = n_2.to_bytes(n2_len, Endianness.BIG.value)

    return get_hash(n2_bytes + n1_bytes, algorithm=EnumHashAlgorithm.from_label(f"sha{sha_width}"))


def get_ifr_pfr_class(area_name: str, family: FamilyRevision) -> Type[BaseConfigArea]:
    """Get IFR/PFR configuration area class based on area name and family.

    Retrieves the appropriate configuration area class for the specified area name
    and validates that it's supported by the given family revision.

    :param area_name: Name of the configuration area (IFR/PFR).
    :param family: Target family revision to validate support.
    :raises SPSDKAppError: When the area is not supported by the specified family.
    :return: Configuration area class type for the specified area and family.
    """
    _cls: Type[BaseConfigArea] = globals()[area_name.upper()]
    if family not in _cls.get_supported_families(True):
        raise SPSDKAppError(
            f"The {_cls.FEATURE.upper()} {area_name.upper()} area is not supported by {family.name} family"
        )
    return _cls
