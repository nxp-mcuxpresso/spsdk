#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module provides support for Protected Flash Region areas (CMPA, CFPA)."""
import copy
import logging
import math
import os
from typing import Any, Dict, List, Optional, Union

from ruamel.yaml.comments import CommentedMap as CM

from spsdk import SPSDKError
from spsdk import __author__ as spsdk_author
from spsdk import __release__ as spsdk_release
from spsdk import __version__ as spsdk_version
from spsdk.crypto import PublicKey, ec, rsa
from spsdk.utils.crypto.abstract import BackendClass
from spsdk.utils.crypto.backend_openssl import openssl_backend
from spsdk.utils.crypto.rkht import RKHT
from spsdk.utils.exceptions import SPSDKRegsErrorRegisterNotFound
from spsdk.utils.misc import change_endianness, load_configuration, value_to_int
from spsdk.utils.reg_config import RegConfig
from spsdk.utils.registers import Registers, RegsRegister

from . import PFR_DATA_FOLDER
from .exceptions import (
    SPSDKPfrConfigError,
    SPSDKPfrConfigReadError,
    SPSDKPfrError,
    SPSDKPfrRotkhIsNotPresent,
)

logger = logging.getLogger(__name__)


class PfrConfiguration:
    """Class to open PFR configuration file a get basic configuration."""

    def __init__(
        self,
        config: Union[str, dict, "PfrConfiguration"] = None,
        device: str = None,
        revision: str = None,
        cfg_type: str = None,
    ) -> None:
        """Open config PFR file.

        :param config: Filename or dictionary with PFR settings, defaults to None
        :param device: If needed it could be used to override device from settings, defaults to ""
        :param revision: If needed it could be used to override revision from settings, defaults to ""
        :param cfg_type: If needed it could be used to override PFR type from settings, defaults to ""
        """
        self.device = device
        self.revision = revision
        self.type = cfg_type
        self.settings: Optional[Union[CM, dict]] = None

        if isinstance(config, (str, os.PathLike, dict)):
            self.set_config(config)

        if isinstance(config, PfrConfiguration):
            if not self.device:
                self.device = config.device
            if not self.revision:
                self.revision = config.revision
            if not self.type:
                self.type = config.type
            if config.settings:
                self.settings = config.settings.copy()

    @staticmethod
    def _detect_obsolete_style_of_settings(data: Union[CM, dict]) -> bool:
        """Detect obsolete style of configuration.

        :param data: As old JSON style as new YML style of settings data.
        :return: True if obsolete style is detected.
        """
        if len(data) == 0:
            return False

        for key in data.keys():
            if isinstance(data[key], (str, int)):
                return True
            if isinstance(data[key], dict):
                first_key = list(data[key].keys())[0]
                if first_key not in ("value", "bitfields", "name"):
                    return True

        return False

    def _get_yml_style_of_settings(self, data: Union[CM, dict]) -> Union[CM, dict]:
        """Get unified YML style of settings.

        :param data: As old JSON style as new YML style of settings data.
        :return: New YML style of data.
        """
        if not self._detect_obsolete_style_of_settings(data):
            return data

        yml_style: Dict[str, Union[str, int, dict]] = {}
        for key, val in data.items():
            if isinstance(val, (str, int)):
                yml_style[key] = {"value": val}
            if isinstance(val, dict):
                bitfields = {}
                for key_b, val_b in val.items():
                    bitfields[key_b] = val_b
                yml_style[key] = {"bitfields": bitfields}

        return yml_style

    def set_config_dict(
        self,
        data: Union[CM, dict],
        device: str = None,
        revision: str = None,
        cfg_type: str = None,
    ) -> None:
        """Apply configuration dictionary.

        The function accepts as dictionary as from commented map.

        :param data: Settings of PFR.
        :param device: If needed it could be used to override device from settings, defaults to ""
        :param revision: If needed it could be used to override revision from settings, defaults to ""
        :param cfg_type: If needed it could be used to override PFR type from settings, defaults to ""
        :raises SPSDKPfrConfigReadError: Invalid YML file.
        """
        if data is None or len(data) == 0:
            raise SPSDKPfrConfigReadError("Empty YAML configuration.")

        try:
            description = data.get("description", data)
            self.device = device or description.get("device", None)
            self.revision = revision or description.get("revision", None)
            self.type = cfg_type or description.get("type", None)
            self.settings = self._get_yml_style_of_settings(data["settings"])

        except KeyError as exc:
            raise SPSDKPfrConfigReadError("Missing fields in YAML configuration.") from exc

    def set_config(self, config: Union[str, CM, dict]) -> None:
        """Apply configuration from file.

        :param config: Name of configuration file or Commented map.
        :raises SPSDKPfrConfigReadError: The configuration file cannot be loaded.
        """
        if isinstance(config, (CM, dict)):
            self.set_config_dict(config)
        else:
            try:
                data = load_configuration(config)
            except SPSDKError as exc:
                raise SPSDKPfrConfigReadError(str(exc)) from exc
            self.set_config_dict(data)

    def get_yaml_config(self, data: CM, indent: int = 0) -> CM:
        """Return YAML configuration In PfrConfiguration format.

        :param data: The registers settings data.
        :param indent: YAML start indent.
        :return: YAML PFR configuration in commented map(ordered dict).
        :raises SPSDKError: When there is no device found
        :raises SPSDKError: When there is no type found
        """
        if not self.device:
            raise SPSDKError("Device not found")
        if not self.type:
            raise SPSDKError("Type not found")
        res_data = CM()

        res_data.yaml_set_start_comment(
            f"NXP {self.device} PFR {self.type} configuration", indent=indent
        )

        description = CM()
        description.insert(1, "device", self.device, comment="The NXP device name.")
        description.insert(2, "revision", self.revision, comment="The NXP device revision.")
        description.insert(3, "type", self.type.upper(), comment="The PFR type (CMPA, CFPA).")
        description.insert(4, "version", spsdk_version, comment="The SPSDK tool version.")
        description.insert(5, "author", spsdk_author, comment="The author of the configuration.")
        description.insert(6, "release", spsdk_release, comment="The SPSDK release.")

        res_data.insert(
            1,
            "description",
            description,
            comment=f"The PFR {self.type} configuration description.",
        )
        res_data.insert(
            2, "settings", data, comment=f"The PFR {self.type} registers configuration."
        )
        return res_data

    def is_invalid(self) -> Optional[str]:
        """Validate configuration.

        :return: None if configuration is valid, otherwise description string what is invalid.
        """
        if not self.device:
            return "The device is NOT specified!"
        if not self.type:
            return "The PFR type (CMPA/CFPA) is NOT specified!"

        return None

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PfrConfiguration):
            return False

        return vars(self) == vars(other)


class BaseConfigArea:
    """Base for CMPA and CFPA classes."""

    CONFIG_DIR = PFR_DATA_FOLDER
    CONFIG_FILE = "database.json"
    BINARY_SIZE = 512
    ROTKH_SIZE = 32
    ROTKH_REGISTER = "ROTKH"
    MARK = b"SEAL"
    DESCRIPTION = "Base Config Area"
    IMAGE_PREFILL_PATTERN = 0

    def __init__(
        self, device: str = None, revision: str = None, user_config: PfrConfiguration = None
    ) -> None:
        """Initialize an instance.

        :param device: device to use, list of supported devices is available via 'devices' method
        :param revision: silicon revision, if not specified, the latest is being used
        :param user_config: PfrConfiguration with user configuration to use with initialization
        :raises SPSDKError: When no device is provided
        :raises SPSDKError: When no device is not supported
        :raises SPSDKError: When there is invalid revision
        """
        if not (device or user_config):
            raise SPSDKError("No device provided")
        self.config = self._load_config()
        # either 'device' or 'user_config' IS defined! Mypy doesn't understand the check above
        self.device = device or user_config.device  # type: ignore

        if self.device not in self.config.get_devices():
            raise SPSDKError(f"Device '{self.device}' is not supported")
        self.revision = revision or (user_config.revision if user_config else "latest")
        if not self.revision or self.revision == "latest":
            self.revision = self.config.get_latest_revision(self.device)
            logger.warning(
                f"The silicon revision is not specified, the latest: '{self.revision}' has been used."
            )

        if self.revision not in self.config.get_revisions(self.device):
            raise SPSDKError(f"Invalid revision '{self.revision}' for '{self.device}'")
        self.registers = Registers(self.device)
        self.registers.load_registers_from_xml(
            xml=self.config.get_data_file(self.device, self.revision),
            filter_reg=self.config.get_ignored_registers(self.device),
            grouped_regs=self.config.get_grouped_registers(self.device),
        )

        # Set the computed field handler
        for reg, fields in self.config.get_computed_fields(self.device).items():
            reg_obj = self.registers.find_reg(reg)
            reg_obj.add_setvalue_hook(self.reg_computed_fields_handler, fields)

        self.user_config = PfrConfiguration(
            config=user_config,
            device=self.device,
            revision=self.revision,
            cfg_type=self.__class__.__name__,
        )

        if self.user_config.settings:
            self.set_config(self.user_config, raw=False)

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

    @classmethod
    def _load_config(cls) -> RegConfig:
        """Loads the PFR block configuration file.

        :return: PFR block configuration database.
        """
        return RegConfig(os.path.join(cls.CONFIG_DIR, cls.CONFIG_FILE))

    @classmethod
    def devices(cls) -> List[str]:
        """Classmethod to get list of supported devices.

        :return: List of supported devices.
        """
        config = cls._load_config()
        return config.get_devices()

    def _get_registers(self) -> List[RegsRegister]:
        """Get a list of all registers.

        :return: List of PFR configuration registers.
        """
        exclude = self.config.get_ignored_registers(self.device)
        return self.registers.get_registers(exclude)

    def set_config(self, config: PfrConfiguration, raw: bool = False) -> None:
        """Apply configuration from file.

        :param config: PFR configuration.
        :param raw: When set all (included computed fields) configuration will be applied.
        :raises SPSDKError: When device is not provided.
        :raises SPSDKError: When revision is not provided.
        :raises SPSDKPfrConfigError: Invalid config file.
        """
        if not self.device:
            raise SPSDKError("No device provided")
        if not self.revision:
            raise SPSDKError("No revision provided")

        if config.device != self.device:
            raise SPSDKPfrConfigError(
                f"Invalid device in configuration. {self.device} != {config.device}"
            )
        if not config.revision or config.revision in ("latest", ""):
            config.revision = self.config.get_latest_revision(self.device)
            logger.warning(
                f"The configuration file doesn't contains silicon revision, \
the latest: '{config.revision}' has been used."
            )
        if config.revision != self.revision:
            raise SPSDKPfrConfigError(
                f"Invalid revision in configuration. {self.revision} != {config.revision}"
            )
        if config.type and config.type.upper() != self.__class__.__name__:
            raise SPSDKPfrConfigError(
                f"Invalid configuration type. {self.__class__.__name__} != {config.type}"
            )

        if not config.settings:
            raise SPSDKPfrConfigError("Missing configuration of PFR fields!")

        computed_regs = []
        computed_regs.extend(self.config.get_ignored_registers(self.device))
        if not raw:
            computed_regs.extend(self.config.get_computed_registers(self.device))
        computed_fields = None if raw else self.config.get_computed_fields(self.device)

        self.registers.load_yml_config(config.settings, computed_regs, computed_fields)
        if not raw:
            # # Just update only configured registers
            exclude_hooks = []
            if not self.config.get_value("mandatory_computed_regs", self.device):
                exclude_hooks.extend(
                    list(set(self.registers.get_reg_names()) - set(config.settings.keys()))
                )
            self.registers.run_hooks(exclude_hooks)

    def get_yaml_config(
        self, exclude_computed: bool = True, diff: bool = False, indent: int = 0
    ) -> CM:
        """Return YAML configuration from loaded registers.

        :param exclude_computed: Omit computed registers and fields.
        :param diff: Get only configuration with difference value to reset state.
        :param indent: YAML start indent.
        :return: YAML PFR configuration in commented map(ordered dict).
        """
        computed_regs = (
            None if not exclude_computed else self.config.get_computed_registers(self.device)
        )
        computed_fields = (
            None if not exclude_computed else self.config.get_computed_fields(self.device)
        )
        ignored_fields = self.config.get_ignored_fields(self.device)

        data = self.registers.create_yml_config(
            computed_regs, computed_fields, ignored_fields, diff, indent + 2
        )
        return self.user_config.get_yaml_config(data, indent)

    def generate_config(self, exclude_computed: bool = True) -> CM:
        """Generate configuration structure for user configuration.

        :param exclude_computed: Exclude computed fields, defaults to True.
        :return: YAML commented map with PFR configuration  in reset state.
        """
        # Create own copy to keep self as is and get reset values by standard YML output
        copy_of_self = copy.deepcopy(self)
        copy_of_self.registers.reset_values()

        return copy_of_self.get_yaml_config(exclude_computed)

    def _calc_rotkh(self, keys: List[PublicKey]) -> bytes:
        """Calculate ROTKH (Root Of Trust Key Hash).

        :param keys: List of Keys to compute ROTKH.
        :return: Value of ROTKH with right width.
        :raises SPSDKPfrError: Algorithm width doesn't fit into ROTKH field.
        """
        # the data structure use for computing final ROTKH is 4*32B long
        # 32B is a hash of individual keys
        # 4 is the max number of keys, if a key is not provided the slot is filled with '\x00'
        # The LPC55S3x has two options to compute ROTKH, so it's needed to be
        # detected the right algorithm and mandatory warn user about this selection because
        # it's MUST correspond to settings in eFuses!
        reg_rotkh = self.registers.find_reg("ROTKH")
        rkht = RKHT(keys=keys, keys_cnt=4, min_keys_cnt=1)
        rkht.validate()

        if rkht.hash_algorithm_size > reg_rotkh.width:
            raise SPSDKPfrError("The ROTKH field is smaller than used algorithm width.")

        return rkht.rotkh().ljust(reg_rotkh.width // 8, b"\x00")

    def _get_seal_start_address(self) -> int:
        """Function returns start of seal fields for the device.

        :return: Start of seals fields.
        :raises SPSDKError: When 'seal_start_address' in database.json can not be found
        """
        start = self.config.get_seal_start_address(self.device)
        if not start:
            raise SPSDKError("Can't find 'seal_start_address' in database.json")
        return self.registers.find_reg(start).offset

    def _get_seal_count(self) -> int:
        """Function returns seal count for the device.

        :return: Count of seals fields.
        :raises SPSDKError: When 'seal_count' in database.json can not be found
        """
        count = self.config.get_seal_count(self.device)
        if not count:
            raise SPSDKError("Can't find 'seal_count' in database.json")
        return value_to_int(count)

    def export(self, add_seal: bool = False, keys: List[PublicKey] = None) -> bytes:
        """Generate binary output.

        :param add_seal: The export is finished in the PFR record by seal.
        :param keys: List of Keys to compute ROTKH field.
        :return: Binary block with PFR configuration(CMPA or CFPA).
        :raises SPSDKPfrRotkhIsNotPresent: This PFR block doesn't contains ROTKH field.
        :raises SPSDKError: The size of data is {len(data)}, is not equal to {self.BINARY_SIZE}.
        """
        if keys:
            try:
                # ROTKH may or may not be present, derived class defines its presence
                rotkh_reg = self.registers.find_reg(self.ROTKH_REGISTER)
                rotkh_data = self._calc_rotkh(keys)
                rotkh_reg.set_value(rotkh_data, True)
            except SPSDKRegsErrorRegisterNotFound as exc:
                raise SPSDKPfrRotkhIsNotPresent(
                    "This device doesn't contain ROTKH register!"
                ) from exc

        data = bytearray([self.IMAGE_PREFILL_PATTERN] * self.BINARY_SIZE)
        for reg in self._get_registers():
            data[reg.offset : reg.offset + reg.width // 8] = reg.get_bytes_value()

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
        for reg in self._get_registers():
            value = bytearray(data[reg.offset : reg.offset + reg.width // 8])
            # don't change endian if register is meant to be used in 'reverse' (array of bytes)
            reg.set_value(value if reg.reverse else change_endianness(value), raw=True)


class CMPA(BaseConfigArea):
    """Customer Manufacturing Configuration Area."""

    CONFIG_DIR = os.path.join(BaseConfigArea.CONFIG_DIR, "cmpa")
    DESCRIPTION = "Customer Manufacturing Programmable Area"


class CFPA(BaseConfigArea):
    """Customer In-Field Configuration Area."""

    CONFIG_DIR = os.path.join(BaseConfigArea.CONFIG_DIR, "cfpa")
    DESCRIPTION = "Customer In-field Programmable Area"


def calc_pub_key_hash(
    public_key: PublicKey,
    backend: BackendClass = openssl_backend,
    sha_width: int = 256,
) -> bytes:
    """Calculate a hash out of public key's exponent and modulus in RSA case, X/Y in EC.

    :param public_key: List of public keys to compute hash from.
    :param backend: Crypto subsystem backend.
    :param sha_width: Used hash algorithm.
    :raises SPSDKError: Unsupported public key type
    :return: Computed hash.
    """
    if isinstance(public_key, rsa.RSAPublicKey):
        n_1 = public_key.public_numbers().e  # type: ignore # MyPy is unable to pickup the class member
        n1_len = math.ceil(n_1.bit_length() / 8)
        n_2 = public_key.public_numbers().n  # type: ignore # MyPy is unable to pickup the class member
        n2_len = math.ceil(n_2.bit_length() / 8)
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        n_1 = public_key.public_numbers().y  # type: ignore # MyPy is unable to pickup the class member
        n1_len = sha_width // 8
        n_2 = public_key.public_numbers().x  # type: ignore # MyPy is unable to pickup the class member
        n2_len = sha_width // 8
    else:
        raise SPSDKError(f"Unsupported key type: {type(public_key)}")

    n1_bytes = n_1.to_bytes(n1_len, "big")
    n2_bytes = n_2.to_bytes(n2_len, "big")

    return backend.hash(n2_bytes + n1_bytes, algorithm=f"sha{sha_width}")
