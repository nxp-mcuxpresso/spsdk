#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module provides support for Protected Flash Region areas (CMPA, CFPA)."""

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
from spsdk.utils.registers import Register, Registers

logger = logging.getLogger(__name__)


@dataclass
class AdditionalDataCfg:
    """Configuration for additional customer data in PFR/IFR areas.

    This class defines the parameters for additional customer data storage in Protected Flash Region areas.

    :param enabled: Flag indicating if additional customer data is supported
    :param offset: Offset in bytes where additional customer data should be placed (-1 means append to the end)
    :param max_size: Maximum allowed size for additional customer data in bytes
    """

    enabled: bool
    offset: int
    max_size: int


class BaseConfigArea(FeatureBaseClass):
    """Base for CMPA and CFPA classes."""

    FEATURE = DatabaseManager.PFR
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
        """Initialize an instance.

        :param family: Family to use, list of supported families is available via 'get_supported_families' method
        :raises SPSDKError: When no device is provided
        :raises SPSDKError: When no device is not supported
        """
        self.db = get_db(family)
        self.family = family
        self.computed_fields: dict[str, dict[str, str]] = self.db.get_dict(
            self.FEATURE, [self.SUB_FEATURE, "computed_fields"], {}
        )
        self.registers = self._load_registers(family)
        self._additional_data = bytes()
        self.registers_size = self._get_registers_size()

    def _get_registers_size(self) -> int:
        """Get binary size from database configuration."""
        try:
            return self.db.get_int(self.FEATURE, [self.SUB_FEATURE, "size"])
        except SPSDKValueError:
            # Fallback to default size if not specified in database
            return self.BINARY_SIZE

    @property
    def binary_size(self) -> int:
        """Final binary size."""
        return self.registers_size + len(self.additional_data)

    @classmethod
    def get_supported_families(cls, include_predecessors: bool = False) -> list[FamilyRevision]:
        """Get supported families for the feature."""
        sub_feature = None if cls.SUB_FEATURE == "SubClassDefineIt" else cls.SUB_FEATURE

        return get_families(
            feature=cls.FEATURE,
            sub_feature=sub_feature,
            include_predecessors=include_predecessors,
        )

    def __str__(self) -> str:
        """String representation of PFR/IFR class."""
        return self.__repr__()

    def __repr__(self) -> str:
        """String representation of PFR/IFR class."""
        return f"{self.FEATURE} {self.SUB_FEATURE} class for {self.family}."

    @property
    def additional_data(self) -> bytes:
        """Get the additional customer data stored in the configuration area.

        :return: The additional customer data as bytes
        """
        return self._additional_data

    @additional_data.setter
    def additional_data(self, value: bytes) -> None:
        """Set the additional customer data for the configuration area.

        This method allows setting additional customer data based on the configuration defined in additional_data_cfg().
        It validates the size and presence of additional customer data before setting.

        :raises SPSDKPfrError: If additional customer data configuration is invalid or data is not provided
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

        :param family: The family revision to get the configuration for
        :return: CustomerDataCfg object containing the configuration parameters
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

        :param family: Device family name
        :return: Loaded register class
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

        :param reg: Register to be recalculated.
        :param method: Method name to be use to recalculation of register value.
        :raises SPSDKPfrError: Raises when the computing routine is not found.
        """
        if hasattr(self, method):
            method_ref = getattr(self, method)
            reg.set_value(method_ref(reg.get_value(True)), True)
        else:
            raise SPSDKPfrError(f"The '{method}' compute function doesn't exists.")

    @staticmethod
    def pfr_reg_inverse_high_half(val: int) -> int:
        """Function that inverse low 16-bits of register value to high 16 bits.

        :param val: Input current reg value.
        :return: Returns the complete register value with updated higher half field.
        """
        ret = val & 0xFFFF
        ret |= (ret ^ 0xFFFF) << 16
        return ret

    @staticmethod
    def pfr_reg_inverse_lower_8_bits(val: int) -> int:
        """Function that inverse lower 8-bits of register value to 8-16 bits.

        :param val: Input current reg value.
        :return: Returns the complete register value with updated 8-16 bit field.
        """
        ret = val & 0xFFFF_00FF
        inverse = (val & 0xFF) ^ 0xFF
        ret |= inverse << 8
        return ret

    @classmethod
    def get_validation_schemas_basic(cls) -> list[dict[str, Any]]:
        """Create the validation schema just for supported families.

        :return: List of validation schemas for Shadow registers supported families.
        """
        sch_family = get_schema_file("general")["family"]
        update_validation_schema_family(sch_family["properties"], cls.get_supported_families())
        sch_cfg = get_schema_file(DatabaseManager.PFR)

        return [sch_family, sch_cfg["pfr_base"]]

    @classmethod
    def get_validation_schemas_from_cfg(cls, config: Config) -> list[dict[str, Any]]:
        """Get validation schema based on configuration.

        If the class doesn't behave generally, just override this implementation.

        :param config: Valid configuration
        :return: Validation schemas
        """
        config.check(cls.get_validation_schemas_basic())
        family = FamilyRevision.load_from_config(config)
        area = config.get_str("type")
        klass = get_ifr_pfr_class(area_name=area, family=family)

        return klass.get_validation_schemas(FamilyRevision.load_from_config(config))

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Create the validation schema.

        :param family: Family description.
        :raises SPSDKError: Family or revision is not supported.
        :return: List of validation schemas.
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

        :param cfg: Registers configuration.
        """
        self.registers.load_from_config(cfg)
        # Updates necessary register values
        for reg_uid, bitfields_rec in self.computed_fields.items():
            reg_name = self.registers.get_reg(uid=reg_uid).name
            if reg_name in cfg:
                reg = self.registers.get_reg(reg_uid)
                for bitfield_uid, method in bitfields_rec.items():
                    bitfield_name = reg.get_bitfield(bitfield_uid).name
                    compute = isinstance(cfg[reg_name], dict) and bitfield_name not in cfg[reg_name]
                    if compute:
                        self.compute_register(reg, method)
                        logger.warning(
                            (
                                f"The {reg_name} register has been recomputed, because "
                                f"it has been used in configuration and the bitfield {bitfield_name} "
                                "has not been specified"
                            )
                        )

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Get Configuration class from configuration.

        :param config: PFR configuration.
        :returns: BaseConfigArea object
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
        """Return configuration from loaded PFR.

        :param data_path: Data path is not used in PFR
        :param diff: Get only configuration with difference value to reset state.
        :return: PFR configuration in dictionary.
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

        :param keys: List of Keys to compute ROTKH.
        :return: Value of ROTKH with right width.
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
        """Function returns start of seal fields for the family.

        :return: Start of seals fields.
        :raises SPSDKError: When 'seal_start_address' in database can not be found
        """
        start = self.db.get_str(self.FEATURE, [self.SUB_FEATURE, "seal_start"])
        if not start:
            raise SPSDKError("Can't find 'seal_start_address' in database.")
        return self.registers.get_reg(start).offset

    def _get_seal_count(self) -> int:
        """Function returns seal count for the family.

        :return: Count of seals fields.
        :raises SPSDKError: When 'seal_count' in database can not be found
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
        """Generate binary output.

        :param add_seal: The export is finished in the PFR record by seal.
        :param keys: List of Keys to compute ROTKH field.
        :param rotkh: ROTKH binary value.
        :param draw: Draw the configuration data in log
        :return: Binary block with PFR configuration(CMPA or CFPA).
        :raises SPSDKPfrRotkhIsNotPresent: This PFR block doesn't contain ROTKH field.
        :raises SPSDKError: The size of data is {len(data)}, is not equal to {self.binary_size}.
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

        :param data: Binary data to which additional customer data will be added
        """
        if not self.additional_data:
            return

        offset = self.additional_data_cfg(self.family).offset
        size = self.additional_data_cfg(self.family).max_size
        logger.info(f"Adding customer defined data of {size} bytes")

        if offset == -1:
            data.extend(self.additional_data)
            logger.info("Additional customer data appended to the end of the binary")
        elif offset >= 0 and offset + size <= len(data):
            data[offset : offset + size] = self.additional_data
            logger.info(f"Additional customer data inserted at offset {offset}")
        else:
            raise SPSDKError(
                f"Invalid offset {offset} for additional customer data (binary size: {len(data)})"
            )

    @classmethod
    def parse(cls, data: bytes, family: Optional[FamilyRevision] = None) -> Self:
        """Parse input binary data to registers.

        :param data: Input binary data of PFR block.
        :param family: The MCU family name.
        :return: The PFR initialized class.
        """
        if family is None:
            raise SPSDKPfrError("For PFR parse method the family parameter is mandatory")
        ret = cls(family)
        ret.registers.parse(data)
        if ret.additional_data_cfg(ret.family).enabled and len(data) > ret.registers.size:
            ret.additional_data = data[ret.registers.size :]
        return ret

    def __eq__(self, obj: Any) -> bool:
        """Compare if the objects has same settings."""
        return (
            isinstance(obj, self.__class__)
            and obj.family == self.family
            and obj.registers == self.registers
        )


class CMPA(BaseConfigArea):
    """Customer Manufacturing Configuration Area."""

    SUB_FEATURE = "cmpa"
    DESCRIPTION = "Customer Manufacturing Programmable Area"


class CFPA(BaseConfigArea):
    """Customer In-Field Configuration Area."""

    SUB_FEATURE = "cfpa"
    DESCRIPTION = "Customer In-field Programmable Area"


class ROMCFG(BaseConfigArea):
    """Information flash region - ROMCFG."""

    FEATURE = DatabaseManager.PFR
    SUB_FEATURE = "romcfg"
    BINARY_SIZE = 304
    IMAGE_PREFILL_PATTERN = "0xFF"
    DESCRIPTION = "ROM Bootloader configurations"


class CMACTABLE(BaseConfigArea):
    """Information flash region - CMAC Table."""

    FEATURE = DatabaseManager.PFR
    SUB_FEATURE = "cmactable"
    BINARY_SIZE = 128
    IMAGE_PREFILL_PATTERN = "0xFF"
    DESCRIPTION = "CMAC table - Used to save hashes of multiple boot components"


class IFR(BaseConfigArea):
    """Information flash region - Information Flash Region."""

    FEATURE = DatabaseManager.PFR
    SUB_FEATURE = "ifr"
    BINARY_SIZE = 256
    IMAGE_PREFILL_PATTERN = "0xFF"
    DESCRIPTION = "Information Flash Region configuration"
    READ_METHOD = "flash_read_resource"
    WRITE_METHOD = "flash_program_once"


class CFPA_CMPA(BaseConfigArea):
    """CFPA and CMPA combined configuration area."""

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
    """Calculate a hash out of public key's exponent and modulus in RSA case, X/Y in EC.

    :param public_key: List of public keys to compute hash from.
    :param sha_width: Used hash algorithm.
    :raises SPSDKError: Unsupported public key type
    :return: Computed hash.
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
    """Return IFR/PFR class based on the name."""
    _cls: Type[BaseConfigArea] = globals()[area_name.upper()]
    if family not in _cls.get_supported_families(True):
        raise SPSDKAppError(
            f"The {_cls.FEATURE.upper()} {area_name.upper()} area is not supported by {family.name} family"
        )
    return _cls
