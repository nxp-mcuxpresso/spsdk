#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Protected Flash Region (PFR) management utilities.

This module provides comprehensive support for handling Protected Flash Region areas
including CMPA (Customer Manufacturing Programming Area), CFPA (Customer Field
Programmable Area), and related configuration structures for NXP MCUs.
"""

import logging
import math
import os
from abc import abstractmethod
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Callable, Optional, Type, cast

from typing_extensions import Self

from spsdk.apps.utils.utils import SPSDKAppError
from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.crypto.keys import PublicKey, PublicKeyEcc, PublicKeyRsa
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.image.cert_block.rkht import RKHT
from spsdk.pfr.exceptions import SPSDKPfrError, SPSDKPfrRotkhIsNotPresent
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.binary_image import BinaryImage
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.exceptions import SPSDKRegsError, SPSDKRegsErrorRegisterNotFound
from spsdk.utils.family import FamilyRevision, get_db, get_families, update_validation_schema_family
from spsdk.utils.misc import (
    BinaryPattern,
    Endianness,
    extend_block,
    load_binary,
    value_to_int,
    write_file,
)
from spsdk.utils.registers import Register, Registers, RegistersPreValidationHook

logger = logging.getLogger(__name__)


@dataclass
class AdditionalDataCfg:
    """Configuration for additional customer data in PFR/IFR areas.

    This class defines the parameters for additional customer data storage in Protected Flash Region
    areas, including enablement status, placement offset, and size constraints for customer-specific
    data within the secure flash regions.
    """

    type: str  # Supported types:
    # - CFPA_CMPA_SPLIT: Splitted CFPA and CMPA additional data, split offset defined in CMPA register * 32
    # - CFPA_ONLY: Additional data only after CFPA
    offset: Optional[str]  # name of the register where the offset is stored in CMPA
    max_size: int  # Maximum size of the additional data area

    @classmethod
    def create_from_dict(cls, cfg: dict) -> Self:
        """Create AdditionalDataCfg instance from dictionary configuration.

        :param cfg: Dictionary containing configuration parameters with keys 'type', 'offset', and
            'max_size'.
        :return: New AdditionalDataCfg instance created from the provided configuration.
        """
        return cls(
            type=cfg.get("type", "NONE"),
            offset=cfg.get("offset", "reg/bitfield"),
            max_size=cfg.get("max_size", 0),
        )


class AbstractBaseConfigArea(FeatureBaseClass):
    """Abstract base class for Protected Flash Region (PFR) configuration areas.

    This abstract class defines the interface that all PFR configuration area
    implementations must follow. It provides the contract for CMPA, CFPA, and
    other configuration management classes in the SPSDK PFR module.
    Subclasses must implement all abstract methods and define the required
    class variables for proper PFR operations including binary size, memory
    addresses, and device-specific configuration parameters.

    :cvar FEATURE: Database feature identifier for PFR operations.
    :cvar SUB_FEATURE: Specific sub-feature identifier for the configuration area.
    :cvar BINARY_SIZE_DEFAULT: Size in bytes of the binary representation.
    :cvar ROTKH_SIZE: Size of Root of Trust Key Hash in bytes.
    :cvar ROTKH_REGISTER: Register name for Root of Trust Key Hash.
    :cvar MARK: Binary marker identifying the configuration area type.
    :cvar DESCRIPTION: Human-readable description of the configuration area.
    """

    # Class variables that must be defined by subclasses
    FEATURE = DatabaseManager.PFR
    SUB_FEATURE: str
    BINARY_SIZE_DEFAULT: int
    ROTKH_SIZE: int
    ROTKH_REGISTER: str
    MARK: bytes
    DESCRIPTION: str
    IMAGE_PREFILL_PATTERN: str
    WRITE_METHOD: str = "write_memory"
    READ_METHOD: str = "read_memory"
    REQUIRED_IN_SCHEMAS = True
    SKIP_IN_TEMPLATE = False

    def __init__(self, family: FamilyRevision) -> None:
        """Initialize PFR instance for specified device family.

        Sets up the PFR configuration including database access, additional data support,
        and device-specific settings based on the provided family revision.

        :param family: Device family revision to use for PFR operations.
        :raises SPSDKError: When device is not provided or not supported.
        """
        self.db = get_db(family)
        self.family = family
        self._additional_data = bytes()

        self.support_additional_data = self.db.get_bool(
            self.FEATURE, [self.SUB_FEATURE, "support_additional_data"], default=False
        )

        self.additional_data_config = AdditionalDataCfg.create_from_dict(
            self.db.get_dict(self.FEATURE, [self.SUB_FEATURE, "additional_data_config"], {})
        )
        self.additional_data_raw_offset = self.db.get_int(
            self.FEATURE, "additional_data_raw_offset", -1
        )

    @property
    @abstractmethod
    def binary_size(self) -> int:
        """Get the final binary size of the PFR data.

        :return: Total size in bytes of the binary representation.
        """

    @property
    @abstractmethod
    def read_address(self) -> int:
        """Get the read address for this configuration area.

        The read address is retrieved from the database configuration and indicates
        the memory location from which this PFR area should be read.

        :return: Read address in bytes (default: 0 if not specified in database).
        """

    @property
    @abstractmethod
    def write_address(self) -> int:
        """Get the write address for this configuration area.

        The write address is retrieved from the database configuration and indicates
        the memory location to which this PFR area should be written.

        :return: Write address in bytes (default: 0 if not specified in database).
        """

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
        if not self.support_additional_data:
            raise SPSDKPfrError(
                f"Additional data is not supported for {self.FEATURE} {self.SUB_FEATURE}."
            )
        self._additional_data = value

    def get_additional_data_size(self) -> int:
        """Get the actual size of additional customer data based on configuration.

        The method calculates the size based on the additional data configuration type:
        - NONE: Returns 0 bytes

        :return: Actual size of additional data in bytes.
        :raises SPSDKPfrError: If additional data configuration type is not supported.
        """
        if self.additional_data_config.type == "NONE":
            return 0

        raise SPSDKPfrError(
            f"Unsupported additional data configuration type: {self.additional_data_config.type}"
        )

    def get_additional_data_max_size(self) -> int:
        """Get maximum allowed size of additional customer data.

        Returns the maximum size limit for additional customer data as defined
        in the configuration. This value represents the upper bound for additional
        data that can be stored in this configuration area.

        :return: Maximum size of additional data in bytes.
        """
        return self.additional_data_config.max_size

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

    @abstractmethod
    def force_update(self) -> None:
        """Force update mandatory fields in register configuration.

        This method ensures that all mandatory fields in the register configuration
        are properly updated with their required values.
        """

    @abstractmethod
    def export(
        self,
        add_seal: bool = False,
        draw: bool = True,
    ) -> bytes:
        """Export PFR configuration as binary data.

        :param add_seal: Finish the export with seal in the PFR record.
        :param draw: Draw the configuration data in log output.
        :return: Binary block with PFR configuration.
        """

    @classmethod
    @abstractmethod
    def parse(cls, data: bytes, family: Optional[FamilyRevision] = None) -> Self:
        """Parse input binary data to registers.

        :param data: Input binary data of PFR block.
        :param family: The MCU family name.
        :raises SPSDKPfrError: When family parameter is not provided.
        :return: The PFR initialized class.
        """

    @abstractmethod
    def read_from_device(
        self,
        read_method: Callable[[int, int], bytes],
    ) -> None:
        """Read PFR configuration from device using provided read method.

        This method handles the complete read operation for the PFR configuration area,
        including any additional data, and updates the internal state of the object
        (registers and additional_data). The implementation varies based on the
        configuration type and additional data strategy.

        :param read_method: Callable that reads data from device memory.
            Signature: read_method(address: int, length: int) -> bytes
            Returns bytes read from the specified address.
        :raises SPSDKPfrError: If read operation fails or addresses cannot be determined.
        """

    @abstractmethod
    def write_to_device(
        self,
        write_method: Callable[[int, bytes], bool],
        read_method: Optional[Callable[[int, int], bytes]] = None,
        add_seal: bool = False,
    ) -> bool:
        """Write PFR configuration to device using provided write method.

        This method handles the complete write operation for the PFR configuration area,
        including any additional data and dependencies. The implementation varies based
        on the configuration type and additional data strategy.

        :param write_method: Callable that writes data to device memory.
            Signature: write_method(address: int, data: bytes) -> bool
            Returns True if write succeeded, False otherwise.
        :param read_method: Optional callable that reads data from device memory.
            Signature: read_method(address: int, length: int) -> bytes
            Required for configurations that need to read dependencies (e.g., CFPA with AD).
        :param add_seal: Flag to indicate if sealing should be added to the operation.
        :return: True if all write operations succeeded, False otherwise.
        :raises SPSDKPfrError: If write operation fails or required dependencies are missing.
        """

    def erase_scratch_if_needed(
        self,
        erase_method: Callable[[int, int], bool],
    ) -> None:
        """Erase scratch page if required by device configuration.

        This method checks if the device requires scratch page erasure before PFR write
        operations and performs the erase if needed. The scratch page configuration is
        retrieved from the device database.

        :param erase_method: Callable that erases flash region on device.
            Signature: erase_method(address: int, length: int) -> bool
            Returns True if erase succeeded, False otherwise.
        :raises SPSDKPfrError: If scratch erase is required but fails.
        """
        requires_scratch_erase = self.db.get_bool(
            self.FEATURE, "requires_scratch_erase", default=False
        )

        if not requires_scratch_erase:
            return

        scratch_page_address = self.db.get_int(self.FEATURE, "scratch_page_address")
        scratch_page_size = self.db.get_int(self.FEATURE, "scratch_page_size")

        logger.info(
            f"Erasing scratch area at {scratch_page_address:#x} "
            f"({scratch_page_size} bytes) before writing configuration."
        )

        success = erase_method(scratch_page_address, scratch_page_size)

        if not success:
            raise SPSDKPfrError(f"Failed to erase scratch page at {scratch_page_address:#x}")

        logger.info("Scratch page erased successfully")

    @abstractmethod
    def compute_rotkh(
        self,
        keys: Optional[list[PublicKey]] = None,
        rotkh: Optional[bytes] = None,
    ) -> None:
        """Compute and set ROTKH (Root of Trust Key Hash) in the register.

        This method calculates the ROTKH value from provided public keys or uses a pre-computed
        ROTKH value, then sets it in the appropriate register. The ROTKH is used for secure boot
        verification in NXP MCU devices.

        :param keys: List of public keys to compute ROTKH field from.
        :param rotkh: Pre-computed ROTKH binary value to use directly.
        :raises SPSDKPfrRotkhIsNotPresent: This PFR block doesn't contain ROTKH register.
        :raises SPSDKError: Cannot determine source of ROTKH data (neither keys nor rotkh provided).
        """

    @abstractmethod
    def __eq__(self, obj: Any) -> bool:
        """Compare if two PFR objects have the same settings.

        :param obj: Object to compare with this instance.
        :return: True if objects have same settings, False otherwise.
        """

    @abstractmethod
    def __str__(self) -> str:
        """Get string representation of PFR/IFR class.

        :return: String representation of the PFR/IFR object.
        """

    @abstractmethod
    def __repr__(self) -> str:
        """String representation of PFR/IFR class.

        :return: String containing feature, sub-feature, and family information.
        """

    @abstractmethod
    def _get_registers_size(self) -> int:
        """Get binary size from database configuration.

        :return: Size of the binary in bytes from database or default value.
        """


class BaseConfigArea(AbstractBaseConfigArea):
    """Base class for Protected Flash Region (PFR) configuration areas.

    This class provides common functionality for CMPA (Customer Manufacturing
    Programming Area) and CFPA (Customer Field Programming Area) configuration
    management. It handles register loading, binary size calculations, and
    family-specific database operations for NXP MCU protected flash regions.

    :cvar SUB_FEATURE: Sub-feature identifier to be defined by subclasses.
    :cvar BINARY_SIZE_DEFAULT: Default binary size in bytes for configuration area.
    :cvar ROTKH_SIZE: Size of Root of Trust Key Hash in bytes.
    :cvar ROTKH_REGISTER: Register name for Root of Trust Key Hash.
    :cvar MARK: Binary marker for sealed configuration areas.
    :cvar DESCRIPTION: Human-readable description of the configuration area.
    :cvar IMAGE_PREFILL_PATTERN: Default pattern for prefilling binary images.
    :cvar WRITE_METHOD: Memory interface method name for write operations.
    :cvar READ_METHOD: Memory interface method name for read operations.
    """

    PRE_VALIDATION_CFG_HOOK = RegistersPreValidationHook(register_keys=["settings"])
    SUB_FEATURE = "SubClassDefineIt"
    BINARY_SIZE_DEFAULT = 512
    ROTKH_SIZE = 32
    ROTKH_REGISTER = "ROTKH"
    MARK = b"SEAL"
    DESCRIPTION = "Base Config Area"
    IMAGE_PREFILL_PATTERN = "0x00"

    def __init__(self, family: FamilyRevision) -> None:
        """Initialize PFR instance for specified device family.

        Sets up the database connection, loads device-specific registers, and initializes
        internal data structures for Protected Flash Region operations.

        :param family: Device family to use, list of supported families is available via
            'get_supported_families' method
        :raises SPSDKError: When no device is provided
        :raises SPSDKError: When device is not supported
        """
        super().__init__(family)
        self.computed_fields: dict[str, dict[str, str]] = self.db.get_dict(
            self.FEATURE, [self.SUB_FEATURE, "computed_fields"], {}
        )
        self.registers = self._load_registers(family)
        self.registers_size = self._get_registers_size()

        self._read_address = self.db.get_int(
            self.FEATURE,
            [self.SUB_FEATURE, "read_address"],
            default=self.db.get_int(self.FEATURE, [self.SUB_FEATURE, "address"], default=-1),
        )
        assert self._read_address >= 0
        self._write_address = self.db.get_int(
            self.FEATURE,
            [self.SUB_FEATURE, "write_address"],
            default=self.db.get_int(self.FEATURE, [self.SUB_FEATURE, "address"], default=-1),
        )
        assert self._write_address >= 0

    def _get_registers_size(self) -> int:
        """Get registers size from database configuration.

        The method retrieves the size value from the database for the current feature and sub-feature.
        If the size is not specified in the database, it falls back to the default BINARY_SIZE_DEFAULT.

        :raises SPSDKValueError: When database access fails (handled internally with fallback).
        :return: Size of the registers in bytes from database or default value.
        """
        try:
            return self.db.get_int(self.FEATURE, [self.SUB_FEATURE, "size"])
        except SPSDKValueError:
            # Fallback to default size if not specified in database
            return self.BINARY_SIZE_DEFAULT

    @property
    def binary_size(self) -> int:
        """Get the final binary size of the PFR data.

        The binary size includes both the registers size and any additional data that has been added to
        the PFR structure.

        :return: Total size in bytes of the binary representation.
        """
        return self.registers_size

    @property
    def read_address(self) -> int:
        """Get the read address for this configuration area.

        The read address is retrieved from the database configuration and indicates
        the memory location from which this PFR area should be read.

        :return: Read address in bytes (default: 0 if not specified in database).
        """
        return self._read_address

    @property
    def write_address(self) -> int:
        """Get the write address for this configuration area.

        The write address is retrieved from the database configuration and indicates
        the memory location to which this PFR area should be written.

        :return: Write address in bytes (default: 0 if not specified in database).
        """
        return self._write_address

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

    def compute_rotkh(
        self,
        keys: Optional[list[PublicKey]] = None,
        rotkh: Optional[bytes] = None,
    ) -> None:
        """Compute and set ROTKH (Root of Trust Key Hash) in the register.

        This method calculates the ROTKH value from provided public keys or uses a pre-computed
        ROTKH value, then sets it in the appropriate register. The ROTKH is used for secure boot
        verification in NXP MCU devices.

        :param keys: List of public keys to compute ROTKH field from.
        :param rotkh: Pre-computed ROTKH binary value to use directly.
        :raises SPSDKPfrRotkhIsNotPresent: This PFR block doesn't contain ROTKH register.
        :raises SPSDKError: Cannot determine source of ROTKH data or no input data provided.
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
        else:
            raise SPSDKError("No keys or ROTKH value provided for ROTKH computation.")

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
            return ret
        except (KeyError, SPSDKError) as exc:
            raise SPSDKError(f"Family {family} is not supported") from exc

    def force_update(self) -> None:
        """Force update mandatory fields in register configuration.

        This method ensures that all mandatory fields are properly updated by setting
        a new default configuration.
        """
        self.set_config(Config())

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
        ret = cast(BaseConfigArea, klass(family))
        ret.set_config(settings)
        return ret  # type: ignore

    def get_config(self, data_path: str = "./", diff: bool = False) -> Config:
        """Get configuration from loaded PFR.

        Extracts the current PFR configuration including family information, settings,
        and any additional data into a structured configuration object. If additional
        data is supported and present, it will be written to a binary file in the
        specified data path.

        :param data_path: Directory path where additional data file will be written if present.
        :param diff: If True, return only configuration values that differ from reset state.
        :return: PFR configuration object containing family, revision, type, settings and
                 optional additional data file reference.
        """
        res_data = Config()
        res_data["family"] = self.family.name
        res_data["revision"] = self.family.revision
        res_data["type"] = self.__class__.__name__.upper()
        res_data["settings"] = dict(self.registers.get_config(diff=diff))
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
        draw: bool = True,
    ) -> bytes:
        """Export PFR configuration as binary data.

        Generates binary output for PFR (Protected Flash Region) configuration with optional
        sealing and logging capabilities.

        :param add_seal: Finish the export with seal in the PFR record.
        :param draw: Draw the configuration data in log output.
        :raises SPSDKError: When the exported data size doesn't match expected registers size.
        :return: Binary block with PFR configuration (CMPA or CFPA).
        """
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
                logger.warning(
                    f"This device doesn't support sealing of PFR {self.SUB_FEATURE} page."
                )

        if len(data) != self.registers_size:
            raise SPSDKError(
                f"The size of data is {len(data)}, is not equal to {self.registers_size}"
            )

        return bytes(data)

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
        # Handle additional data if present and enabled for the family

        return ret

    def write_to_device(
        self,
        write_method: Callable[[int, bytes], bool],
        read_method: Optional[Callable[[int, int], bytes]] = None,
        add_seal: bool = False,
    ) -> bool:
        """Write single region PFR configuration to device.

        For single regions (CMPA, CFPA), this method writes the region data
        including any additional data that follows contiguously.

        :param write_method: Callable that writes data to device memory.
        :param read_method: Optional callable for reading from device (not used for single regions).
        :param add_seal: Whether to add seal to the exported data.
        :return: True if write operation succeeded, False otherwise.
        :raises SPSDKPfrError: If write operation fails.
        """
        try:
            # Export region data with additional data if present
            data = self.export(add_seal=add_seal)

            # Write to device
            logger.info(
                f"Writing {self.SUB_FEATURE.upper()} region "
                f"({len(data)} bytes) to address {self.write_address:#x}"
            )

            success = write_method(self.write_address, data)

            if not success:
                logger.error(f"Failed to write {self.SUB_FEATURE.upper()} region")
                return False

            logger.info(f"{self.SUB_FEATURE.upper()} region written successfully")
            return True

        except Exception as exc:
            logger.error(f"Error writing {self.SUB_FEATURE.upper()} region: {exc}")
            raise SPSDKPfrError(
                f"Failed to write {self.SUB_FEATURE.upper()} region to device"
            ) from exc

    def read_from_device(
        self,
        read_method: Callable[[int, int], bytes],
    ) -> None:
        """Read single region PFR configuration from device.

        For single regions (CMPA, CFPA), this method reads the region data from the specified
        device memory address and updates the internal registers with the parsed data.

        :param read_method: Callable function that reads data from device memory, takes address
                           and size parameters and returns bytes data.
        :raises SPSDKPfrError: If read operation fails or data parsing fails.
        """
        try:
            # Determine read address
            read_addr = self.read_address

            if read_addr == -1:
                raise SPSDKPfrError(f"Unable to determine read address for {self.SUB_FEATURE}")

            # Read region data
            region_size = self.registers_size

            logger.info(
                f"Reading {self.SUB_FEATURE.upper()} region "
                f"({region_size} bytes) from address {read_addr:#x}"
            )

            # Read data from device
            data = read_method(read_addr, region_size)

            if not data:
                raise SPSDKPfrError(f"Failed to read {self.SUB_FEATURE.upper()} region from device")

            # Parse the data into registers
            self.registers.parse(data)

            logger.info(f"{self.SUB_FEATURE.upper()} region read and parsed successfully")

        except Exception as exc:
            logger.error(f"Error reading {self.SUB_FEATURE.upper()} region: {exc}")
            raise SPSDKPfrError(
                f"Failed to read {self.SUB_FEATURE.upper()} region from device"
            ) from exc

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

    :cvar BINARY_SIZE_DEFAULT: Fixed size of the ROMCFG region (304 bytes).
    :cvar IMAGE_PREFILL_PATTERN: Default fill pattern for unused areas.
    :cvar DESCRIPTION: Human-readable description of the configuration area.
    """

    FEATURE = DatabaseManager.PFR
    SUB_FEATURE = "romcfg"
    BINARY_SIZE_DEFAULT = 304
    IMAGE_PREFILL_PATTERN = "0xFF"
    DESCRIPTION = "ROM Bootloader configurations"


class CMACTABLE(BaseConfigArea):
    """CMAC Table configuration area for Protected Flash Region.

    This class manages the CMAC (Cipher-based Message Authentication Code) table
    which stores cryptographic hashes of multiple boot components for secure boot
    verification in NXP MCUs.

    :cvar BINARY_SIZE_DEFAULT: Fixed size of 128 bytes for the CMAC table region.
    :cvar IMAGE_PREFILL_PATTERN: Default fill pattern of 0xFF for unused areas.
    """

    FEATURE = DatabaseManager.PFR
    SUB_FEATURE = "cmactable"
    BINARY_SIZE_DEFAULT = 128
    IMAGE_PREFILL_PATTERN = "0xFF"
    DESCRIPTION = "CMAC table - Used to save hashes of multiple boot components"


class IFR(BaseConfigArea):
    """Information Flash Region configuration manager.

    This class manages the Information Flash Region (IFR) configuration area,
    providing functionality for reading and programming once-programmable flash
    memory regions in NXP MCUs.

    :cvar BINARY_SIZE_DEFAULT: Size of the IFR binary data in bytes (256).
    :cvar IMAGE_PREFILL_PATTERN: Default fill pattern for uninitialized areas.
    :cvar READ_METHOD: Flash operation method used for reading IFR data.
    :cvar WRITE_METHOD: Flash operation method used for programming IFR data.
    """

    FEATURE = DatabaseManager.PFR
    SUB_FEATURE = "ifr"
    BINARY_SIZE_DEFAULT = 256
    IMAGE_PREFILL_PATTERN = "0xFF"
    DESCRIPTION = "Information Flash Region configuration"
    READ_METHOD = "flash_read_resource"
    WRITE_METHOD = "flash_program_once"


class UPDATE(BaseConfigArea):
    """UPDATE configuration area manager for CFPA and CMPA regions.

    This class handles the update configuration area that manages Customer Field
    Programmable Area (CFPA) and Customer Manufacturing Programmable Area (CMPA)
    configuration regions in NXP MCUs.

    :cvar BINARY_SIZE_DEFAULT: Size of the update binary data in bytes (16).
    :cvar IMAGE_PREFILL_PATTERN: Default fill pattern for uninitialized areas.
    """

    FEATURE = DatabaseManager.PFR
    SUB_FEATURE = "update"
    BINARY_SIZE_DEFAULT = 16
    IMAGE_PREFILL_PATTERN = "0xFF"
    DESCRIPTION = "Update CFPA and CMPA configuration region"
    REQUIRED_IN_SCHEMAS = False
    SKIP_IN_TEMPLATE = True

    def __init__(self, family: FamilyRevision) -> None:
        """Initialize UPDATE configuration area.

        :param family: Device family name and revision information.
        :raises SPSDKError: When database configuration is invalid or register setup fails.
        """
        super().__init__(family)

        self.update_field_id = self.db.get_str(self.FEATURE, [self.SUB_FEATURE, "update_field_id"])

        update_field_value = self.db.get_int(self.FEATURE, [self.SUB_FEATURE, "update_field_value"])
        if self.update_field_id and update_field_value is not None:
            update_reg = self.registers.get_reg(self.update_field_id)
            update_reg.set_value(update_field_value)


class MultiRegionBaseConfigArea(AbstractBaseConfigArea):
    """Multi-region base configuration area for PFR operations.

    This class manages multiple PFR configuration regions as a unified area,
    providing consolidated access to read/write addresses, binary size calculation,
    and configuration management across all contained regions.

    :cvar REGIONS: List of region identifiers to be managed by this configuration area.
    """

    REGIONS: list[str] = []

    def __init__(self, family: FamilyRevision) -> None:
        """Initialize MultiRegionBaseConfigArea.

        Creates a new instance with regions based on the specified device family and loads
        additional data configuration from the device database.

        :param family: Device family identifier used to determine supported regions and
            configuration options.
        :raises SPSDKError: If the family is not supported or database access fails.
        """
        super().__init__(family)
        self.regions = [
            cast(BaseConfigArea, get_ifr_pfr_class(reg, family)(family)) for reg in self.REGIONS
        ]

    @property
    def binary_size(self) -> int:
        """Get the final binary size of the PFR data.

        The method calculates the total size by summing all region sizes and adding any additional
        data size.

        :return: Total size in bytes of the binary representation.
        """
        return sum(region.binary_size for region in self.regions) + self.get_additional_data_size()

    @property
    def read_address(self) -> int:
        """Get the read address for this configuration area.

        The read address is retrieved from the database configuration and indicates
        the memory location from which this PFR area should be read. Returns the
        minimum read address among all regions in this configuration area.

        :return: Read address in bytes.
        """
        return min(region.read_address for region in self.regions)

    @property
    def write_address(self) -> int:
        """Get the write address for this configuration area.

        The write address is retrieved from the database configuration and indicates
        the memory location to which this PFR area should be written. Returns the
        minimum write address among all regions in this configuration area.

        :return: Write address in bytes.
        """
        return min(region.write_address for region in self.regions)

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get validation schemas for PFR configuration.

        Creates validation schemas for the Protected Flash Region (PFR) configuration
        including family-specific settings, base configuration, and optional additional data.
        The method builds a complete set of schemas by combining general family validation,
        base PFR configuration, and region-specific settings for each supported area.

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
        sch_cfg["pfr_base"]["properties"]["type"]["template_value"] = cls.__name__.upper()
        sch_cfg["pfr_base"]["properties"]["type"]["enum"] = [
            cls.__name__.upper(),
            cls.__name__.lower(),
        ]
        ret = [sch_family, sch_cfg["pfr_base"]]
        for area in cls.REGIONS:
            region_klass = get_ifr_pfr_class(area, family)
            settings_name = f"settings_{area.lower()}"
            settings_schema = deepcopy(sch_cfg["pfr_settings_multiple"])
            if region_klass.REQUIRED_IN_SCHEMAS:
                settings_schema["required"] = [settings_name]
            settings_schema["properties"][settings_name] = settings_schema["properties"].pop(
                "settings_replace"
            )
            settings_schema["properties"][settings_name][
                "template_value"
            ] = f"pfr_{area.lower()}.yaml"
            settings_schema["properties"][settings_name][
                "skip_in_template"
            ] = region_klass.SKIP_IN_TEMPLATE
            ret.append(settings_schema)

            if get_db(family).get_bool(cls.FEATURE, [area, "support_additional_data"], False):
                ad_name = f"additional_data_{area.lower()}"
                ad_schema = deepcopy(sch_cfg["pfr_additional_data"])
                ad_schema["properties"][ad_name] = ad_schema["properties"].pop("additional_data")
                ad_schema["properties"][ad_name][
                    "template_value"
                ] = f"additional_data_{area.lower()}.bin"
                ret.append(ad_schema)
        return ret

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load configuration area from PFR configuration.

        Creates a BaseConfigArea object based on the provided configuration, including
        family revision and settings for each region. Settings can be loaded from binary
        files or configuration data. Additional data can be optionally loaded for regions
        that support it.

        :param config: PFR configuration containing type, settings and region data.
        :return: Configured BaseConfigArea object of the appropriate type.
        :raises SPSDKError: When region data cannot be loaded from file, parsed from config,
            or when binary/additional data size validation fails.
        """
        family = FamilyRevision.load_from_config(config)
        ret = cls(family)

        for region in ret.regions:
            region_name = region.SUB_FEATURE.lower()
            settings_name = f"settings_{region_name}"
            if settings_name in config:
                try:
                    # Try to load as loading from config
                    region_cfg = config.load_sub_config(settings_name)
                    region_cfg["family"] = family.name
                    region_cfg["revision"] = family.revision
                    region_cfg["type"] = region_name
                    parsed_region = type(region).load_from_config(region_cfg)

                except SPSDKRegsError as exc:
                    raise SPSDKError(
                        f"Failed to parse {settings_name} configuration: {str(exc)}"
                    ) from exc

                except (SPSDKError, TypeError) as exc:
                    # Fallback load as binary file first
                    region_binary = load_binary(config.get_input_file_name(settings_name))
                    # Validate binary size
                    expected_size = region.registers_size
                    actual_size = len(region_binary)

                    # Strict size check
                    if actual_size != expected_size:
                        raise SPSDKError(
                            f"Invalid binary size for {region_name}: {actual_size} bytes. "
                            f"Expected exactly {expected_size} bytes."
                        ) from exc
                    parsed_region = type(region).parse(region_binary, family=family)

                if (
                    parsed_region.support_additional_data
                    and f"additional_data_{region_name}" in config
                ):
                    # With additional data: size must be between region_size and region_size + max_additional_data
                    max_additional_size = parsed_region.db.get_int(
                        ret.FEATURE,
                        [ret.SUB_FEATURE, "additional_data_config", "max_size"],
                        0,
                    )
                    additional_data_raw = config.get_str(f"additional_data_{region_name}")

                    try:
                        additional_data_binary = BinaryImage.load_binary_image(
                            path=config.get_input_file_name(f"additional_data_{region_name}"),
                            name=f"additional_data_{region_name}",
                        ).export()
                    except SPSDKError:
                        additional_data_binary = bytes.fromhex(additional_data_raw)

                    if len(additional_data_binary) > max_additional_size:
                        raise SPSDKError(
                            f"Invalid additional data size for {region_name}: {len(additional_data_binary)} bytes. "
                            f"Maximum allowed size is {max_additional_size} bytes."
                        )
                    parsed_region.additional_data = additional_data_binary

                # Replace the region in the list
                ret.regions[ret.regions.index(region)] = parsed_region
        return ret

    def get_config(self, data_path: str = "./", diff: bool = False) -> Config:
        """Get configuration from loaded PFR.

        Extracts the current PFR configuration including family information, settings,
        and any additional data into a structured configuration object. The method
        generates YAML configuration files for each region and saves them to the
        specified data path.

        :param data_path: Directory path where configuration files will be saved.
        :param diff: If True, return only configuration values that differ from reset state.
        :return: PFR configuration object containing family, revision, type, and settings
                 file references.
        """
        res_data = Config()
        res_data["family"] = self.family.name
        res_data["revision"] = self.family.revision
        res_data["type"] = self.__class__.__name__.upper()
        for region in self.regions:
            region_name = region.SUB_FEATURE.lower()
            settings_name = f"settings_{region_name}"
            res_data[settings_name] = f"pfr_{region_name}.yaml"
            region_config = region.get_config_yaml(data_path=data_path, diff=diff)
            write_file(data=region_config, path=os.path.join(data_path, f"pfr_{region_name}.yaml"))

            # Save additional data if present for this region
            if region.support_additional_data and region.additional_data:
                additional_data_file_name = f"additional_data_{region_name}.bin"
                write_file(
                    data=region.additional_data,
                    path=os.path.join(data_path, additional_data_file_name),
                    mode="wb",
                )
                res_data[f"additional_data_{region_name}"] = additional_data_file_name

        return res_data

    @property
    def additional_data(self) -> bytes:
        """Get the additional customer data stored in the configuration area.

        This method concatenates additional data from all regions in the PFR configuration
        to provide a unified view of customer-specific data.

        :return: The additional customer data as bytes.
        """
        return self.export_additional_data().export()

    @additional_data.setter
    def additional_data(self, value: bytes) -> None:
        """Set the additional customer data for the configuration area.

        The method distributes the provided customer data bytes across all regions in the PFR
        configuration, setting each region's additional data based on the region's binary size.

        :param value: The customer data bytes to be distributed across regions.
        :raises SPSDKPfrError: If additional customer data configuration is invalid.
        """
        self.parse_additional_data(value)

    def force_update(self) -> None:
        """Force update mandatory fields in register configuration.

        This method iterates through all regions and ensures that their mandatory
        fields are properly updated by calling the force_update method on each region.
        """
        for region in self.regions:
            region.force_update()

    def get_region(self, name: str) -> BaseConfigArea:
        """Get region by name.

        Searches through all available regions and returns the one matching the specified name.
        The comparison is case-insensitive.

        :param name: Name of the region to find.
        :raises SPSDKError: If the specified region is not found.
        :return: The region configuration area matching the given name.
        """
        for region in self.regions:
            if region.SUB_FEATURE.upper() == name.upper():
                return region
        raise SPSDKError(f"Region '{name}' not found")

    def get_additional_data_size(self) -> int:
        """Get the actual size of additional customer data based on configuration.

        The method calculates the size based on the additional data configuration type:
        - NONE: Returns 0 bytes
        - CFPA_CMPA_SPLIT: Returns split offset from CMPA register plus CFPA additional data size
        - CFPA_ONLY: Returns actual CFPA additional data size

        :return: Actual size of additional data in bytes.
        :raises SPSDKPfrError: If additional data configuration type is not supported.
        :raises SPSDKError: If CMPA region cannot be found or split offset is invalid.
        """
        if self.additional_data_config.type == "CFPA_CMPA_SPLIT":
            # 1. Find CMPA region to get the split offset
            cmpa = self.get_region("CMPA")
            cfpa = self.get_region("CFPA")

            # 2. Get the proper split offset of CMPA/CFPA data
            split_offset = self._extract_split_offset_from_cmpa(cmpa)

            # Return split offset + CFPA additional data size
            return split_offset + len(cfpa.additional_data)

        if self.additional_data_config.type == "CFPA_ONLY":
            # Return actual CFPA additional data size
            cfpa = self.get_region("CFPA")
            return len(cfpa.additional_data)

        return super().get_additional_data_size()

    def export_additional_data(self) -> BinaryImage:
        """Export additional customer data from all regions.

        The method handles different types of additional data configurations:
        - NONE: Returns empty binary image
        - CFPA_CMPA_SPLIT: Combines CMPA and CFPA data at specified split offset
        - CFPA_ONLY: Returns only CFPA additional data

        :raises SPSDKError: When split offset calculation fails or offset is invalid.
        :raises SPSDKPfrError: When additional data type is not supported.
        :return: Binary image containing the combined additional data from regions.
        """
        if self.additional_data_config.type == "NONE":
            return BinaryImage("Additional data", binary=b"", size=0)

        if self.additional_data_config.type == "CFPA_CMPA_SPLIT":
            # 1. Find CMPA region and export its additional data
            cmpa = self.get_region("CMPA")
            cfpa = self.get_region("CFPA")
            cmpa_additional_data = cmpa.additional_data
            # 2. Get the proper split offset of CMPA/CFPA data
            split_offset = self._extract_split_offset_from_cmpa(cmpa)

            if len(cmpa_additional_data) > split_offset:
                raise SPSDKError(
                    f"Invalid split offset {split_offset} for CMPA additional data of size {len(cmpa_additional_data)}"
                )
            # 3. Find CFPA region and export its additional data
            cfpa_additional_data = cfpa.additional_data

            # 4. Combine CMPA and CFPA additional data at the split offset
            ret = BinaryImage(
                "Additional data CMPA/CFPA",
                pattern=BinaryPattern("ones"),
            )
            if cmpa_additional_data:
                ret.add_image(
                    BinaryImage(name="CMPA additional data", binary=cmpa_additional_data, offset=0)
                )
            if cfpa_additional_data:
                ret.add_image(
                    BinaryImage(
                        name="CFPA additional data",
                        binary=cfpa_additional_data,
                        offset=split_offset,
                    ),
                )
            return ret
        if self.additional_data_config.type == "CFPA_ONLY":
            # Find CFPA region and export its additional data
            cfpa = self.get_region("CFPA")
            return BinaryImage(
                "Additional data CFPA", binary=cfpa.additional_data, pattern=BinaryPattern("ones")
            )

        raise SPSDKPfrError(
            f"Not supported type of additional data {self.additional_data_config.type}"
        )

    def parse_additional_data(self, data: bytes) -> None:
        """Parse additional customer data and distribute to regions.

        The method processes binary data containing additional customer data and distributes it
        to appropriate regions (CFPA/CMPA) based on the configured additional data type. For
        CFPA_CMPA_SPLIT type, it uses a split offset from CMPA register to divide the data.

        :param data: Binary data containing additional customer data for all regions
        :raises SPSDKPfrError: If additional data configuration type is not supported
        :raises SPSDKError: If CMPA region cannot be found or split offset is invalid
        """
        if self.additional_data_config.type == "NONE":
            return
        if self.additional_data_config.type == "CFPA_CMPA_SPLIT":
            # 1. Find CMPA region to get the split offset
            cmpa = self.get_region("CMPA")
            cfpa = self.get_region("CFPA")

            # 2. Get the proper split offset of CMPA/CFPA data
            split_offset = self._extract_split_offset_from_cmpa(cmpa)

            # 3. Split the data at the offset
            cmpa_additional_data = data[:split_offset]
            cfpa_additional_data = data[split_offset : self.additional_data_config.max_size]

            # 4. Assign to respective regions
            cmpa.additional_data = cmpa_additional_data
            cfpa.additional_data = cfpa_additional_data

        elif self.additional_data_config.type == "CFPA_ONLY":
            # All additional data goes to CFPA region
            cfpa = self.get_region("CFPA")
            cfpa.additional_data = data[: self.additional_data_config.max_size]

        else:
            raise SPSDKPfrError(
                f"Not supported type of additional data {self.additional_data_config.type}"
            )

    def compute_rotkh(
        self,
        keys: Optional[list[PublicKey]] = None,
        rotkh: Optional[bytes] = None,
    ) -> None:
        """Compute and set ROTKH (Root of Trust Key Hash) in the register.

        This method calculates the ROTKH value from provided public keys or uses a pre-computed
        ROTKH value, then sets it in the appropriate register. The ROTKH is used for secure boot
        verification in NXP MCU devices.

        :param keys: List of public keys to compute ROTKH field from.
        :param rotkh: Pre-computed ROTKH binary value to use directly.
        :raises SPSDKPfrRotkhIsNotPresent: This PFR block doesn't contain ROTKH register.
        :raises SPSDKError: Cannot determine source of ROTKH data (neither keys nor rotkh provided).
        """
        for regions in self.regions:
            try:
                regions.compute_rotkh(keys=keys, rotkh=rotkh)
                return
            except SPSDKPfrRotkhIsNotPresent:
                logger.debug(f"ROTKH is not present in region {regions.SUB_FEATURE}")
        raise SPSDKPfrRotkhIsNotPresent("ROTKH is not present in any region")

    def export(
        self,
        add_seal: bool = False,
        draw: bool = True,
    ) -> bytes:
        """Export PFR configuration as binary data.

        Exports the complete PFR (Protected Flash Region) configuration by processing all regions
        and combining them into a single binary block.

        :param add_seal: Finish the export with seal in the PFR record.
        :param draw: Enable drawing/visualization during export process.
        :return: Binary block with PFR configuration.
        """
        data = bytes()

        # Export each region and concatenate
        for region in self.regions:
            region_data = region.export(
                add_seal=add_seal,
                draw=draw,
            )
            data += region_data

        # Add additional data if applicable
        data += self.export_additional_data().export()

        return data

    @classmethod
    def parse(cls, data: bytes, family: Optional[FamilyRevision] = None) -> Self:
        """Parse input binary data to create PFR instance with populated registers.

        The method sequentially parses each region from the binary data, creating
        appropriate region instances and handling any additional data beyond the
        standard regions.

        :param data: Input binary data of PFR block to be parsed.
        :param family: The MCU family revision for proper parsing context.
        :raises SPSDKPfrError: When family parameter is not provided.
        :return: The PFR initialized class instance with parsed data.
        """
        if family is None:
            raise SPSDKPfrError("For PFR parse method the family parameter is mandatory")

        ret = cls(family)
        offset = 0

        # Parse each region sequentially from the binary data
        for i, region in enumerate(ret.regions):
            region_class = type(region)
            # Get the expected size for this region
            region_size = region.registers_size

            # Extract the data for this region
            region_data = data[offset : offset + region_size]

            # Parse the region
            parsed_region = region_class.parse(region_data, family=family)

            # Replace the region in the list
            ret.regions[i] = parsed_region

            # Move offset forward
            offset += parsed_region.binary_size

        # Parse additional data if applicable
        ret.parse_additional_data(data[offset:])

        return ret

    def read_from_device(
        self,
        read_method: Callable[[int, int], bytes],
    ) -> None:
        """Read multi-region PFR configuration from device.

        This method reads all regions and additional data, updating the internal
        state of all region objects based on the additional_data_config.type strategy.

        :param read_method: Callable that reads data from device memory, takes address and size.
        :raises SPSDKPfrError: If read operation fails.
        """
        try:
            logger.info(f"Reading {self.SUB_FEATURE.upper()} configuration from device")

            # Read each region using its own read_from_device method
            for region in self.regions:
                logger.info(f"Reading {region.SUB_FEATURE.upper()} region")
                region.read_from_device(read_method)

            # Read and parse additional data if present
            additional_data_size = self.get_additional_data_max_size()
            if additional_data_size > 0 and self.additional_data_raw_offset >= 0:
                logger.info(
                    f"Reading additional data ({additional_data_size} bytes) "
                    f"from {self.additional_data_raw_offset:#x}"
                )

                additional_data_address = self.read_address + self.additional_data_raw_offset
                additional_data = read_method(additional_data_address, additional_data_size)

                # Parse and distribute additional data to regions
                self.parse_additional_data(additional_data)

            logger.info("All regions read and parsed successfully")

        except Exception as exc:
            logger.error(f"Error reading multi-region configuration: {exc}")
            raise SPSDKPfrError(
                f"Failed to read {self.SUB_FEATURE.upper()} configuration from device"
            ) from exc

    def write_to_device(
        self,
        write_method: Callable[[int, bytes], bool],
        read_method: Optional[Callable[[int, int], bytes]] = None,
        add_seal: bool = False,
    ) -> bool:
        """Write multi-region PFR configuration to device.

        This method implements the write strategy based on the additional_data_config.type:
        - NONE: Write all regions in order
        - CFPA_ONLY: Write CFPA, then its additional data, then other regions
        - CFPA_CMPA_SPLIT: Write CFPA, CMPA (with its AD), CFPA AD (using split offset), then UPDATE

        :param write_method: Callable that writes data to device memory.
        :param read_method: Optional callable for reading from device. Required for CFPA_ONLY strategy
            (needs to read CMPA for split offset).
        :param add_seal: Finish the export with seal in the PFR record.
        :return: True if all write operations succeeded, False otherwise.
        :raises SPSDKPfrError: If write operation fails or required dependencies are missing.
        """
        try:
            ad_type = self.additional_data_config.type

            if ad_type == "NONE":
                return self._write_simple(write_method, add_seal)

            if ad_type == "CFPA_ONLY":
                if read_method is None:
                    raise SPSDKPfrError(
                        "read_method is required for CFPA_ONLY additional data strategy"
                    )
                return self._write_cfpa_only(write_method, read_method)

            if ad_type == "CFPA_CMPA_SPLIT":
                return self._write_cfpa_cmpa_split(write_method, add_seal)

            raise SPSDKPfrError(f"Unsupported additional data type: {ad_type}")

        except Exception as exc:
            logger.error(f"Error writing multi-region configuration: {exc}")
            raise SPSDKPfrError(
                f"Failed to write {self.SUB_FEATURE.upper()} configuration to device"
            ) from exc

    def _write_simple(
        self, write_method: Callable[[int, bytes], bool], add_seal: bool = False
    ) -> bool:
        """Write all regions without additional data handling.

        The method writes configuration regions to device memory, ensuring that UPDATE region
        is always written last if present. This maintains proper sequencing for device
        configuration updates.

        :param write_method: Callable that writes data to device memory.
        :param add_seal: Finish the export with seal in the PFR record.
        :return: True if all writes succeeded, False otherwise.
        """
        logger.info(f"Writing {self.SUB_FEATURE.upper()} configuration (simple mode)")

        # Separate UPDATE region from other regions
        update_region: Optional[BaseConfigArea] = None
        other_regions: list[BaseConfigArea] = []

        for region in self.regions:
            if region.SUB_FEATURE.upper() == "UPDATE":
                update_region = region
            else:
                other_regions.append(region)

        # Write all non-UPDATE regions first
        for region in other_regions:
            data = region.export(add_seal=add_seal)

            logger.info(
                f"Writing {region.SUB_FEATURE.upper()} region "
                f"({len(data)} bytes) to {region.write_address:#x}"
            )

            if not write_method(region.write_address, data):
                logger.error(f"Failed to write {region.SUB_FEATURE.upper()} region")
                return False

        # Write UPDATE region last if present
        if update_region:
            data = update_region.export()

            logger.info(
                f"Writing UPDATE region " f"({len(data)} bytes) to {update_region.write_address:#x}"
            )

            if not write_method(update_region.write_address, data):
                logger.error("Failed to write UPDATE region")
                return False

        logger.info("All regions written successfully")
        return True

    def _write_cfpa_only(
        self,
        write_method: Callable[[int, bytes], bool],
        read_method: Callable[[int, int], bytes],
    ) -> bool:
        """Write CFPA configuration to device memory in CFPA-only mode.

        This method implements a strategy for writing CFPA configuration when additional
        data is present, requiring reading CMPA from the device to determine the split
        offset. The process includes writing the CFPA region, any additional data at
        the calculated offset, and optionally the UPDATE region.
        Strategy:
        1. Read CMPA from device to get split offset
        2. Write CFPA region
        3. Write CFPA additional data at (base + split_offset)
        4. Write UPDATE region (if present)

        :param write_method: Callable that writes data to device memory at specified address.
        :param read_method: Callable that reads data from device memory at specified address.
        :return: True if all writes succeeded, False otherwise.
        """
        logger.info(f"Writing {self.SUB_FEATURE.upper()} configuration (CFPA_ONLY mode)")

        cfpa = self.get_region("CFPA")

        # Write CFPA region (without additional data)
        cfpa_data = cfpa.export()
        logger.info(f"Writing CFPA region ({len(cfpa_data)} bytes) to {cfpa.write_address:#x}")

        if not write_method(cfpa.write_address, cfpa_data):
            logger.error("Failed to write CFPA region")
            return False

        # Handle CFPA additional data if present
        if cfpa.additional_data:
            # Read CMPA from device to get split offset
            cmpa_address = self.db.get_int(self.FEATURE, ["cmpa", "read_address"])
            cmpa_size = self.db.get_int(self.FEATURE, ["cmpa", "size"])

            logger.info(f"Reading CMPA from device at {cmpa_address:#x} to get split offset")
            cmpa_data = read_method(cmpa_address, cmpa_size)

            # Extract split offset
            split_offset = self._extract_split_offset_from_data(cmpa_data)

            assert self.additional_data_raw_offset >= 0

            # Write CFPA additional data
            ad_address = self.write_address + self.additional_data_raw_offset + split_offset
            logger.info(
                f"Writing CFPA additional data ({len(cfpa.additional_data)} bytes) "
                f"to {ad_address:#x}"
            )

            if not write_method(ad_address, cfpa.additional_data):
                logger.error("Failed to write CFPA additional data")
                return False

        # Write UPDATE region if present
        try:
            update = self.get_region("UPDATE")
            update_data = update.export()
            logger.info(
                f"Writing UPDATE region ({len(update_data)} bytes) to {update.write_address:#x}"
            )

            if not write_method(update.write_address, update_data):
                logger.error("Failed to write UPDATE region")
                return False
        except SPSDKError:
            # UPDATE region not present, skip
            pass

        logger.info("All regions written successfully")
        return True

    def _write_cfpa_cmpa_split(
        self,
        write_method: Callable[[int, bytes], bool],
        add_seal: bool = False,
    ) -> bool:
        """Write CFPA and CMPA regions with split additional data strategy.

        This method implements a specific write strategy for PFR configurations where additional
        data is split between CMPA and CFPA regions. The strategy ensures proper ordering and
        alignment of data blocks during the write process.
        Strategy:
        1. Write CFPA region
        2. Write CMPA region (without additional data)
        3. Build complete additional data block:
           - CMPA additional data at offset 0
           - Padding/alignment to split offset
           - CFPA additional data at split offset
        4. Write complete additional data block as one operation
        5. Write UPDATE region

        :param write_method: Callable that writes data to device memory at specified address.
        :param add_seal: Finish the export with seal in the PFR record.
        :return: True if all writes succeeded, False otherwise.
        """
        logger.info(f"Writing {self.SUB_FEATURE.upper()} configuration (CFPA_CMPA_SPLIT mode)")

        cfpa = self.get_region("CFPA")
        cmpa = self.get_region("CMPA")

        # Write CFPA region (without additional data)
        cfpa_data = cfpa.export()
        logger.info(f"Writing CFPA region ({len(cfpa_data)} bytes) to {cfpa.write_address:#x}")

        if not write_method(cfpa.write_address, cfpa_data):
            logger.error("Failed to write CFPA region")
            return False

        # Write CMPA region (without additional data)
        cmpa_data = cmpa.export(add_seal=add_seal)
        logger.info(f"Writing CMPA region ({len(cmpa_data)} bytes) to {cmpa.write_address:#x}")

        if not write_method(cmpa.write_address, cmpa_data):
            logger.error("Failed to write CMPA region")
            return False

        # Build and write complete additional data block if any AD present
        if cmpa.additional_data or cfpa.additional_data:
            # Extract split offset from CMPA
            split_offset = self._extract_split_offset_from_cmpa(cmpa)

            # Build complete additional data block
            ad_block = self._build_additional_data_block(
                cmpa_ad=cmpa.additional_data,
                cfpa_ad=cfpa.additional_data,
                split_offset=split_offset,
            )

            assert self.additional_data_raw_offset >= 0

            # Write complete additional data block as one operation
            ad_base_address = self.write_address + self.additional_data_raw_offset
            logger.info(
                f"Writing complete additional data block ({len(ad_block)} bytes) "
                f"to {ad_base_address:#x} "
                f"(CMPA AD: {len(cmpa.additional_data)} bytes, "
                f"split at: {split_offset}, "
                f"CFPA AD: {len(cfpa.additional_data)} bytes)"
            )

            if not write_method(ad_base_address, ad_block):
                logger.error("Failed to write additional data block")
                return False

        # Write UPDATE region
        try:
            update = self.get_region("UPDATE")
            update_data = update.export()
            logger.info(
                f"Writing UPDATE region ({len(update_data)} bytes) to {update.write_address:#x}"
            )

            if not write_method(update.write_address, update_data):
                logger.error("Failed to write UPDATE region")
                return False
        except SPSDKError:
            # UPDATE region not present, skip
            pass

        logger.info("All regions written successfully")
        return True

    def _build_additional_data_block(
        self, cmpa_ad: bytes, cfpa_ad: bytes, split_offset: int
    ) -> bytes:
        """Build complete additional data block with proper alignment.

        Creates a structured block containing CMPA and CFPA additional data with proper
        padding and alignment. The block uses 0xFF padding pattern suitable for flash
        memory operations.
        Block structure:
        - [0 ... len(cmpa_ad)]: CMPA additional data
        - [len(cmpa_ad) ... split_offset]: Padding (0xFF)
        - [split_offset ... split_offset + len(cfpa_ad)]: CFPA additional data

        :param cmpa_ad: CMPA additional data bytes.
        :param cfpa_ad: CFPA additional data bytes.
        :param split_offset: Offset where CFPA additional data starts.
        :return: Complete additional data block as bytes.
        :raises SPSDKError: If CMPA additional data exceeds split offset.
        """
        # Validate that CMPA AD fits before split offset
        if len(cmpa_ad) > split_offset:
            raise SPSDKError(
                f"CMPA additional data size ({len(cmpa_ad)} bytes) exceeds "
                f"split offset ({split_offset} bytes)"
            )

        # Build block with padding pattern (0xFF is common for flash)
        return extend_block(
            extend_block(data=cmpa_ad or bytes(), length=split_offset, padding=0xFF) + cfpa_ad
            or bytes(),
            length=self.additional_data_config.max_size,
            padding=0xFF,
        )

    def _extract_split_offset_from_cmpa(self, cmpa_region: BaseConfigArea) -> int:
        """Extract split offset value from CMPA region.

        The method extracts the split offset bitfield value from the specified CMPA region
        and converts it to bytes by multiplying by 32.

        :param cmpa_region: CMPA region containing the split offset bitfield.
        :return: Split offset in bytes (bitfield value * 32).
        :raises SPSDKError: If split offset cannot be extracted or path not configured.
        """
        if not self.additional_data_config.offset:
            raise SPSDKError("Split offset path not configured")

        try:
            reg_name, bitfield_name = self.additional_data_config.offset.split("/")
            register = cmpa_region.registers.find_reg(reg_name)
            bitfield = register.find_bitfield(bitfield_name)

            # Value is in units of 32 bytes
            return bitfield.get_value() * 32
        except Exception as exc:
            raise SPSDKError(f"Failed to extract split offset from CMPA: {exc}") from exc

    def _extract_split_offset_from_data(self, cmpa_data: bytes) -> int:
        """Extract split offset value from raw CMPA data.

        The method parses the raw CMPA binary data into a temporary region object
        and extracts the split offset value using the region-based extraction method.

        :param cmpa_data: Raw CMPA binary data to parse and extract split offset from.
        :return: Split offset in bytes (bitfield value multiplied by 32).
        :raises SPSDKError: If split offset cannot be extracted from the data.
        """
        # Parse CMPA data to temporary region
        cmpa_temp = CMPA.parse(cmpa_data, self.family)
        return self._extract_split_offset_from_cmpa(cmpa_temp)

    def __eq__(self, obj: Any) -> bool:
        """Compare if two PFR objects have the same settings.

        The comparison checks if both objects are of the same class, have the same family,
        and all regions are identical between the objects.

        :param obj: Object to compare with this instance.
        :return: True if objects have same settings, False otherwise.
        """
        if not isinstance(obj, self.__class__):
            return False
        if self.family != obj.family:
            return False

        return all(region == obj_region for region, obj_region in zip(self.regions, obj.regions))

    def __str__(self) -> str:
        """Get string representation of PFR/IFR class.

        :return: String representation of the PFR/IFR object with all regions listed line by line.
        """
        return "\n".join(str(region) for region in self.regions)

    def __repr__(self) -> str:
        """String representation of PFR/IFR class.

        :return: String containing family information in constructor format.
        """
        return f"{self.__class__.__name__}(family={self.family})"

    def _get_registers_size(self) -> int:
        """Get total size of all registers in bytes.

        Calculates the sum of binary sizes for all regions in the PFR configuration.

        :return: Total size of all registers in bytes.
        """
        return sum(region.binary_size for region in self.regions)


class UPDATE_CFPA(MultiRegionBaseConfigArea):
    """UPDATE and CFPA combined configuration area.

    This class manages the combined UPDATE and Customer Field Programmable Area (CFPA)
    configuration data for NXP MCUs. It provides functionality to handle both
    configuration regions as a unified 512-byte binary structure for secure
    provisioning operations.

    :cvar SUB_FEATURE: Identifier for the combined UPDATE/CFPA feature.
    :cvar BINARY_SIZE_DEFAULT: Size of the combined configuration area in bytes.
    :cvar DESCRIPTION: Human-readable description of the configuration area.
    :cvar REGIONS: List of configuration regions managed by this class.
    """

    SUB_FEATURE = "update_cfpa"
    BINARY_SIZE_DEFAULT = 512
    DESCRIPTION = "UPDATE and CFPA combined configuration area"
    REGIONS = ["update", "cfpa"]

    def __init__(self, family: FamilyRevision) -> None:
        """Initialize UPDATE CFPA regions.

        Sets up the UPDATE region with the configured update field value if the region
        has an update field ID defined and the update field value is available in the
        database configuration.

        :param family: Family and revision specification for the target device.
        :raises SPSDKError: If region initialization fails or database access errors occur.
        """
        super().__init__(family)
        region = self.get_region("UPDATE")
        update_field_value = self.db.get_int(self.FEATURE, [self.SUB_FEATURE, "update_field_value"])
        if (
            hasattr(region, "update_field_id")
            and region.update_field_id
            and update_field_value is not None
        ):
            update_reg = region.registers.get_reg(region.update_field_id)
            update_reg.set_value(update_field_value)


class UPDATE_CFPA_CMPA(MultiRegionBaseConfigArea):
    """UPDATE, CFPA and CMPA combined configuration area.

    This class manages the combined UPDATE, Customer Field Programmable Area (CFPA) and
    Customer Manufacturing Programmable Area (CMPA) configuration data for NXP MCUs.
    It provides functionality to handle all three configuration areas as a unified
    1024-byte binary structure.

    :cvar SUB_FEATURE: Identifier for the combined UPDATE/CFPA/CMPA feature.
    :cvar BINARY_SIZE_DEFAULT: Size of the combined configuration area in bytes.
    :cvar DESCRIPTION: Human-readable description of the configuration area.
    :cvar REGIONS: List of configuration regions included in this area.
    """

    SUB_FEATURE = "update_cfpa_cmpa"
    BINARY_SIZE_DEFAULT = 1024
    DESCRIPTION = "UPDATE, CFPA and CMPA combined configuration area"
    REGIONS = ["update", "cfpa", "cmpa"]

    def __init__(self, family: FamilyRevision) -> None:
        """Initialize UPDATE CFPA regions.

        Sets up the UPDATE region with the configured update field value if available.
        The method retrieves the UPDATE region configuration and applies the update_field_value
        from the database to the corresponding register when both the update_field_id and
        update_field_value are properly defined.

        :param family: Family and revision specification for the target device.
        """
        super().__init__(family)
        region = self.get_region("UPDATE")
        update_field_value = self.db.get_int(self.FEATURE, [self.SUB_FEATURE, "update_field_value"])
        if (
            hasattr(region, "update_field_id")
            and region.update_field_id
            and update_field_value is not None
        ):
            update_reg = region.registers.get_reg(region.update_field_id)
            update_reg.set_value(update_field_value)


CONFIG_AREA_CLASSES: dict[str, Type[AbstractBaseConfigArea]] = {
    "cmpa": CMPA,
    "cfpa": CFPA,
    "update": UPDATE,
    "update_cfpa": UPDATE_CFPA,
    "update_cfpa_cmpa": UPDATE_CFPA_CMPA,
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


def get_ifr_pfr_class(area_name: str, family: FamilyRevision) -> Type[AbstractBaseConfigArea]:
    """Get IFR/PFR configuration area class based on area name and family.

    Retrieves the appropriate configuration area class for the specified area name
    and validates that it's supported by the given family revision.

    :param area_name: Name of the configuration area (IFR/PFR).
    :param family: Target family revision to validate support.
    :raises SPSDKAppError: When the area is not supported by the specified family.
    :return: Configuration area class type for the specified area and family.
    """
    _cls: Type[AbstractBaseConfigArea] = globals()[area_name.upper()]
    if family not in _cls.get_supported_families(True):
        raise SPSDKAppError(
            f"The {_cls.FEATURE.upper()} {area_name.upper()} area is not supported by {family.name} family"
        )
    return _cls


def get_ifr_pfr_class_from_config(config: Config) -> Type[AbstractBaseConfigArea]:
    """Get IFR/PFR configuration area class from configuration object.

    Retrieves the appropriate configuration area class based on the configuration
    object's area name and family settings.

    :param config: Configuration object containing area name and family information.
    :raises SPSDKAppError: When the area is not supported by the specified family.
    :return: Configuration area class type for the specified area and family.
    """
    area_name = config.get_str("type")
    family = config.get_family()
    return get_ifr_pfr_class(area_name, family)
