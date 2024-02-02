#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module provides support for Protected Flash Region areas (CMPA, CFPA)."""
import copy
import logging
import math
from typing import Any, Dict, List, Optional, Type, Union

from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.crypto.keys import PublicKey, PublicKeyEcc, PublicKeyRsa
from spsdk.exceptions import SPSDKError
from spsdk.utils.crypto.rkht import RKHT, RKHTv1, RKHTv21
from spsdk.utils.database import DatabaseManager, get_db, get_families, get_schema_file
from spsdk.utils.exceptions import SPSDKRegsErrorRegisterNotFound
from spsdk.utils.misc import BinaryPattern, Endianness, value_to_int
from spsdk.utils.reg_config import RegConfig
from spsdk.utils.registers import Registers
from spsdk.utils.schema_validator import check_config

from .exceptions import SPSDKPfrError, SPSDKPfrRotkhIsNotPresent

logger = logging.getLogger(__name__)


class BaseConfigArea:
    """Base for CMPA and CFPA classes."""

    FEATURE_NAME = DatabaseManager.PFR
    DB_SUB_KEYS: List[str] = []
    BINARY_SIZE = 512
    ROTKH_SIZE = 32
    ROTKH_REGISTER = "ROTKH"
    MARK = b"SEAL"
    DESCRIPTION = "Base Config Area"
    IMAGE_PREFILL_PATTERN = "0x00"

    def __init__(
        self,
        family: str,
        revision: Optional[str] = None,
    ) -> None:
        """Initialize an instance.

        :param family: Family to use, list of supported families is available via 'get_supported_families' method
        :param revision: silicon revision, if not specified, the latest is being used
        :param user_config: User configuration to use with initialization
        :raises SPSDKError: When no device is provided
        :raises SPSDKError: When no device is not supported
        :raises SPSDKError: When there is invalid revision
        """
        self.family = family
        self.revision = revision or "latest"

        self.reg_config = RegConfig(
            family=self.family,
            feature=self.FEATURE_NAME,
            revision=self.revision,
            db_path=self.DB_SUB_KEYS,
        )
        self.revision = self.reg_config.revision

        self.registers = Registers(self.family, base_endianness=Endianness.LITTLE)
        self.registers.load_registers_from_xml(
            xml=self.reg_config.get_data_file(),
            grouped_regs=self.reg_config.get_grouped_registers(),
        )

        # Set the computed field handler
        for reg, fields in self.reg_config.get_computed_fields().items():
            reg_obj = self.registers.find_reg(reg)
            reg_obj.add_setvalue_hook(self.reg_computed_fields_handler, fields)

    def reg_computed_fields_handler(self, val: bytes, context: Any) -> bytes:
        """Recalculate all fields for given register value.

        :param val: Input register value.
        :param context: The method context (fields).
        :return: recomputed value.
        :raises SPSDKPfrError: Raises when the computing routine is not found.
        """
        fields: dict = context
        for method in fields.values():
            if hasattr(self, method):
                method_ref = getattr(self, method)
                val = method_ref(val)
            else:
                raise SPSDKPfrError(f"The '{method}' compute function doesn't exists.")

        return val

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
    def get_supported_families(cls) -> List[str]:
        """Classmethod to get list of supported families.

        :return: List of supported families.
        """
        return get_families(cls.FEATURE_NAME, cls.DB_SUB_KEYS)

    @classmethod
    def get_validation_schemas_family(cls) -> List[Dict[str, Any]]:
        """Create the validation schema just for supported families.

        :return: List of validation schemas for Shadow registers supported families.
        """
        sch_cfg = get_schema_file(DatabaseManager.PFR)
        sch_cfg["pfr_base"]["properties"]["family"]["enum"] = cls.get_supported_families()
        return [sch_cfg["pfr_base"]]

    @classmethod
    def get_validation_schemas(cls, family: str, revision: str = "latest") -> List[Dict[str, Any]]:
        """Create the validation schema.

        :param family: Family description.
        :param revision: Chip revision specification, as default, latest is used.
        :raises SPSDKError: Family or revision is not supported.
        :return: List of validation schemas.
        """
        sch_cfg = get_schema_file(DatabaseManager.PFR)
        try:
            db = get_db(family, revision)
            regs = Registers(family, Endianness.LITTLE)
            regs.load_registers_from_xml(
                db.get_file_path(cls.FEATURE_NAME, cls.DB_SUB_KEYS + ["data_file"]),
                grouped_regs=db.get_list(
                    cls.FEATURE_NAME, cls.DB_SUB_KEYS + ["grouped_registers"], []
                ),
            )
            sch_cfg["pfr_base"]["properties"]["family"]["enum"] = cls.get_supported_families()
            sch_cfg["pfr_base"]["properties"]["family"]["template_value"] = family
            sch_cfg["pfr_base"]["properties"]["revision"]["template_value"] = revision
            sch_cfg["pfr_base"]["properties"]["type"]["template_value"] = cls.__name__.upper()
            sch_cfg["pfr_settings"]["properties"]["settings"][
                "properties"
            ] = regs.get_validation_schema()["properties"]
            return [sch_cfg["pfr_base"], sch_cfg["pfr_settings"]]
        except (KeyError, SPSDKError) as exc:
            raise SPSDKError(f"Family {family} or revision {revision} is not supported") from exc

    @classmethod
    def validate_config(cls, cfg: Dict[str, Any]) -> None:
        """Validate input PFR configuration.

        :param cfg: PFR configuration
        """
        base_schemas = cls.get_validation_schemas_family()
        check_config(cfg, base_schemas)
        description: Optional[Dict[str, Any]] = cfg.get("description")
        family = (
            description["device"] if description else cfg.get("family", cfg.get("device", "N/A"))
        )
        revision = (
            description.get("revision", "latest") if description else cfg.get("revision", "latest")
        )
        schemas = cls.get_validation_schemas(family=family, revision=revision)
        check_config(cfg, schemas)

    def set_config(self, cfg: Dict[str, Any]) -> None:
        """Set a new values configuration.

        :param cfg: Registers configuration.
        """
        self.registers.load_yml_config(cfg)
        if self.reg_config.get_value("mandatory_computed_regs", False):
            # Updates also computed registers not used in configuration
            all_computed = list(self.reg_config.get_computed_registers().keys())
            all_computed.extend(list(self.reg_config.get_computed_fields().keys()))
            rest_regs_to_update = list(set(all_computed) - set(cfg.keys()))
            for r in rest_regs_to_update:
                reg = self.registers.find_reg(r)
                reg.set_value(reg.get_value(raw=True), raw=False)

    @staticmethod
    def load_from_config(config: Dict[str, Any]) -> "BaseConfigArea":
        """Get Configuration class from configuration.

        :param config: PFR configuration.
        :returns: BaseConfigArea obejct
        """
        description: Optional[Dict[str, str]] = config.get("description")
        if description:  # backward compatibility branch
            family = description["device"]
            revision = description.get("revision", "latest")
            cls = CONFIG_AREA_CLASSES[description["type"].lower()]
        else:
            family = config.get("family", config.get("device"))
            revision = config.get("revision", "latest")
            cls = CONFIG_AREA_CLASSES[config["type"].lower()]
        settings = config["settings"]
        ret = cls(family=family, revision=revision)
        ret.set_config(settings)
        return ret

    def get_config(self, diff: bool = False) -> Dict[str, Union[str, Dict[str, Any]]]:
        """Return configuration from loaded PFR.

        :param diff: Get only configuration with difference value to reset state.
        :return: PFR configuration in dictionary.
        """
        if self.reg_config.get_value("mandatory_computed_regs", False):
            # Updates also computed registers not used in configuration
            all_computed = list(self.reg_config.get_computed_registers().keys())
            all_computed.extend(list(self.reg_config.get_computed_fields().keys()))
            for r in all_computed:
                reg = self.registers.find_reg(r)
                reg.set_value(reg.get_value(raw=True), raw=False)

        data = self.registers.get_config(diff=diff)
        res_data: Dict[str, Union[str, Dict[str, Any]]] = {}
        res_data["family"] = self.family
        res_data["revision"] = self.revision
        res_data["type"] = self.__class__.__name__.upper()
        res_data["settings"] = data
        return res_data

    def generate_config(self) -> Dict:
        """Generate configuration structure for user configuration.

        :return: YAML commented map with PFR configuration  in reset state.
        """
        # Create own copy to keep self as is and get reset values by standard YML output
        copy_of_self = copy.deepcopy(self)
        copy_of_self.registers.reset_values()
        return copy_of_self.get_config()

    def _calc_rotkh(self, keys: List[PublicKey]) -> bytes:
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
        assert self.family is not None
        cls = self.get_cert_block_class(family=self.family)
        rkht = cls.from_keys(keys=keys)

        if rkht.hash_algorithm_size > reg_rotkh.width:
            raise SPSDKPfrError("The ROTKH field is smaller than used algorithm width.")
        return rkht.rkth().ljust(reg_rotkh.width // 8, b"\x00")

    @classmethod
    def get_cert_block_class(cls, family: str) -> Type[RKHT]:
        """Return the seal count.

        :param family: The device name, if not specified, the general value is used.
        :return: The seal count.
        :raises SPSDKError: When there is invalid seal count
        """
        cert_blocks = {
            "cert_block_1": RKHTv1,
            "cert_block_21": RKHTv21,
        }
        val = get_db(family).get_str(DatabaseManager.CERT_BLOCK, "rot_type")
        if val is None or val not in cert_blocks:
            raise SPSDKError(f"Invalid certificate block version: {val}")

        return cert_blocks[val]

    def _get_seal_start_address(self) -> int:
        """Function returns start of seal fields for the family.

        :return: Start of seals fields.
        :raises SPSDKError: When 'seal_start_address' in database can not be found
        """
        start = self.reg_config.get_seal_start_address()
        if not start:
            raise SPSDKError("Can't find 'seal_start_address' in database.")
        return self.registers.find_reg(start).offset

    def _get_seal_count(self) -> int:
        """Function returns seal count for the family.

        :return: Count of seals fields.
        :raises SPSDKError: When 'seal_count' in database can not be found
        """
        count = self.reg_config.get_seal_count()
        if not count:
            raise SPSDKError("Can't find 'seal_count' in database")
        return value_to_int(count)

    def export(
        self,
        add_seal: bool = False,
        keys: Optional[List[PublicKey]] = None,
        rotkh: Optional[bytes] = None,
    ) -> bytes:
        """Generate binary output.

        :param add_seal: The export is finished in the PFR record by seal.
        :param keys: List of Keys to compute ROTKH field.
        :param rotkh: ROTKH binary value.
        :return: Binary block with PFR configuration(CMPA or CFPA).
        :raises SPSDKPfrRotkhIsNotPresent: This PFR block doesn't contain ROTKH field.
        :raises SPSDKError: The size of data is {len(data)}, is not equal to {self.BINARY_SIZE}.
        """
        if keys or rotkh:
            try:
                # ROTKH may or may not be present, derived class defines its presence
                rotkh_reg = self.registers.find_reg(self.ROTKH_REGISTER)
                if rotkh:
                    rotkh_data = rotkh
                elif keys:
                    rotkh_data = self._calc_rotkh(keys)
                rotkh_reg.set_value(rotkh_data, True)
            except SPSDKRegsErrorRegisterNotFound as exc:
                raise SPSDKPfrRotkhIsNotPresent(
                    "This device doesn't contain ROTKH register!"
                ) from exc

        image_info = self.registers.image_info(
            size=self.BINARY_SIZE, pattern=BinaryPattern(self.IMAGE_PREFILL_PATTERN)
        )
        logger.info(image_info.draw())
        data = bytearray(image_info.export())

        if add_seal:
            seal_start = self._get_seal_start_address()
            seal_count = self._get_seal_count()
            data[seal_start : seal_start + seal_count * 4] = self.MARK * seal_count

        if len(data) != self.BINARY_SIZE:
            raise SPSDKError(f"The size of data is {len(data)}, is not equal to {self.BINARY_SIZE}")
        return bytes(data)

    def parse(self, data: bytes) -> None:
        """Parse input binary data to registers.

        :param data: Input binary data of PFR block.
        """
        self.registers.parse(data)

    def __eq__(self, obj: Any) -> bool:
        """Compare if the objects has same settings."""
        return (
            isinstance(obj, self.__class__)
            and obj.family == self.family
            and obj.revision == self.revision
            and obj.registers == self.registers
        )


class CMPA(BaseConfigArea):
    """Customer Manufacturing Configuration Area."""

    DB_SUB_KEYS = ["cmpa"]
    DESCRIPTION = "Customer Manufacturing Programmable Area"


class CFPA(BaseConfigArea):
    """Customer In-Field Configuration Area."""

    DB_SUB_KEYS = ["cfpa"]
    DESCRIPTION = "Customer In-field Programmable Area"


class ROMCFG(BaseConfigArea):
    """Information flash region - ROMCFG."""

    FEATURE_NAME = DatabaseManager.IFR
    BINARY_SIZE = 304
    IMAGE_PREFILL_PATTERN = "0xFF"


CONFIG_AREA_CLASSES: Dict[str, Type[BaseConfigArea]] = {
    "cmpa": CMPA,
    "cfpa": CFPA,
    "romcfg": ROMCFG,
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
