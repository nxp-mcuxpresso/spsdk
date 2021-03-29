#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module provides support for Protected Flash Region areas (CMPA, CFPA)."""
import logging
import math
import os
import copy
from typing import List, Union, Any
import json
import yaml
from ruamel.yaml.comments import CommentedMap as CM

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from spsdk import __version__ as spsdk_version
from spsdk import __release__ as spsdk_release
from spsdk import __author__ as spsdk_author
from spsdk.utils.crypto.abstract import BackendClass
from spsdk.utils.crypto.backend_openssl import openssl_backend
from spsdk.utils.registers import Registers, RegsBitField, RegsRegister
from spsdk.utils.reg_config import RegConfig
from spsdk.utils.misc import change_endianism, reverse_bytes_in_longs, value_to_int, format_value
from spsdk.utils.exceptions import SPSDKRegsErrorRegisterNotFound

from . import PFR_DATA_FOLDER
from .exceptions import (
    SPSDKPfrError,
    SPSDKPfrConfigError,
    SPSDKPfrConfigReadError,
    SPSDKPfrRotkhIsNotPresent
)

logger = logging.getLogger(__name__)

class PfrConfiguration():
    """Class to open PFR configuration file a get basic configuration."""

    def __init__(self, file_name: str = None) -> None:
        """Open config PFR file.

        :param file_name: File name of PFR configuration.
        :raises SPSDKPfrConfigReadError: Invalid configuration file.
        """
        self.device = "Unknown"
        self.revision = "latest"
        self.type = "Unknown"
        self.file_type = "Unknown"
        self.settings = None

        if file_name:
            self.set_config(file_name)

    def set_config_dict(self, data: Union[CM, dict]) -> None:
        """Apply configuration dictionary.

        The function accepts as dictionary as from commented map.

        :param data: Commented map of YML configuration.
        :raises SPSDKPfrConfigReadError: Invalid YML file.
        """
        if data is None or len(data) == 0:
            raise SPSDKPfrConfigReadError(f"Empty YAML configuration.")

        try:
            description = data.get("description", data)
            self.device = description["device"].lower() or ""
            self.revision = description.get("revision", "latest").lower()
            self.type = description["type"]
            self.settings = data["settings"]
            self.file_type = "YAML" if isinstance(data, CM) else "JSON"
        except KeyError:
            raise SPSDKPfrConfigReadError(f"Missing fields in YAML configuration.")

    def set_config_json(self, file_name: str) -> None:
        """Apply JSON configuration from file.

        :param file_name: Name of JSON configuration file.
        :raises SPSDKPfrConfigReadError: Invalid JSON file.
        """
        try:
            with open(file_name, "r") as file_json:
                data = json.load(file_json)
        except (FileNotFoundError, TypeError, ValueError) as exc:
            raise SPSDKPfrConfigReadError(f"Cannot load JSON configuration file. ({file_name}) - {exc}")

        try:
            self.set_config_dict(data)
            self.file_type = "JSON"
        except SPSDKPfrConfigReadError as exc:
            raise SPSDKPfrConfigReadError(f"Decoding error({str(exc)}) with JSON configuration file. ({file_name})")

    def set_config_yml(self, file_name: str) -> None:
        """Apply YML configuration from file.

        :param file_name: Name of YML configuration file.
        :raises SPSDKPfrConfigReadError: Invalid YML commented map.
        """
        try:
            with open(file_name, "r") as file_yml:
                yml_raw = file_yml.read()
            data = yaml.safe_load(yml_raw)
        except (FileNotFoundError, TypeError, ValueError) as exc:
            raise SPSDKPfrConfigReadError(f"Cannot load YAML configuration file. ({file_name}) - {exc}")

        try:
            self.set_config_dict(data)
            self.file_type = "YAML"
        except SPSDKPfrConfigReadError as exc:
            raise SPSDKPfrConfigReadError(f"Decoding error({str(exc)}) with YAML configuration file. ({file_name})")

    def set_config(self, config: Union[str, CM, dict]) -> None:
        """Apply configuration from file.

        :param config: Name of configuration file or Commented map.
        """
        if isinstance(config, (CM, dict)):
            self.set_config_dict(config)
        else:
            extension = os.path.splitext(config)[1]
            # Try open configuration file by its extensions
            if extension == ".json":
                self.set_config_json(config)
            elif extension in (".yml", ".yaml"):
                self.set_config_yml(config)
            else:
                # Just try to open one by one to be lucky
                try:
                    self.set_config_json(config)
                except SPSDKPfrConfigReadError:
                    self.set_config_yml(config)

    def get_yaml_config(self, data: CM, indent: int = 0) -> CM:
        """Return YAML configuration In PfrConfiguration format.

        :param data: The registers settings data.
        :param indent: YAML start indent.
        :return: YAML PFR configuration in commented map(ordered dict).
        """
        res_data = CM()

        res_data.yaml_set_start_comment(f"NXP {self.device.upper()} PFR {self.type} configuration", indent=indent)

        description = CM()
        description.insert(1, "device", self.device, comment="The NXP device name.")
        description.insert(2, "revision", self.revision, comment="The NXP device revision.")
        description.insert(3, "type", self.type.upper(), comment="The PFR type (CMPA, CFPA).")
        description.insert(4, "version", spsdk_version, comment="The SPSDK tool version.")
        description.insert(5, "author", spsdk_author, comment="The author of the configuration.")
        description.insert(6, "release", spsdk_release, comment="The SPSDK release.")

        res_data.insert(1, "description", description, comment=f"The PFR {self.type} configuration description.")
        res_data.insert(2, "settings", data, comment=f"The PFR {self.type} registers configuration.")
        return res_data

    def get_json_config(self, data: dict) -> dict:
        """Return JSON configuration In PfrConfiguration format.

        :param data: The registers settings data.
        :return: JSON PFR configuration in dictionary.
        """
        res_data = {}

        description = {}
        description["device"] = self.device
        description["revision"] = self.revision
        description["type"] = self.type.upper()
        description["version"] = spsdk_version
        description["author"] = spsdk_author
        description["release"] = spsdk_release

        res_data["description"] = description
        res_data["settings"] = data
        return res_data

class BaseConfigArea:
    """Base for CMPA and CFPA classes."""
    CONFIG_DIR = PFR_DATA_FOLDER
    CONFIG_FILE = "database.json"
    BINARY_SIZE = 512
    ROTKH_SIZE = 32
    ROTKH_REGISTER = "ROTKH"
    MARK = b'SEAL'
    DESCRIPTION = "Base Config Area"
    def __init__(self, device: str,
                 revision: str = None, user_config: PfrConfiguration = None) -> None:
        """Initialize an instance.

        :param device: device to use, list of supported devices is available via 'devices' method
        :param revision: silicon revision, if not specified, the latest is being used
        :param user_config: PfrConfiguration with user configuration to use with initialization
        """
        self.config = self._load_config()
        assert device in self.config.get_devices(), f"Device '{device}' is not supported"
        self.device = device
        self.revision = revision or self.config.get_latest_revision(device)
        assert self.revision in self.config.get_revisions(device), f"Invalid revision '{revision}' for '{device}'"
        self.registers = Registers(device)
        self.registers.load_registers_from_xml(self.config.get_data_file(self.device, self.revision),
                                               grouped_regs=self.config.get_grouped_registers(self.device))

        # Set the computed field handler
        for reg, fields  in self.config.get_computed_fields(self.device).items():
            reg_obj = self.registers.find_reg(reg)
            reg_obj.add_setvalue_hook(self.reg_computed_fields_handler, fields)

        self.user_config = PfrConfiguration()
        self.user_config.device = self.device
        self.user_config.revision = self.revision
        self.user_config.type = self.__class__.__name__

        if user_config:
            self.user_config = user_config
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
                method_ref = getattr(self, method, None)
                val = method_ref(val)
            else:
                raise SPSDKPfrError(f"The '{method}' compute function doesn't exists.")

        return val

    @staticmethod
    def pfr_reg_inverse_high_half(val: bytes) -> bytes:
        """Function that inverse low 16-bits of register value to high 16 bits.

        :param val: Input current reg value.
        :return: Returns the complete register value with updated higher half field.
        """
        ret = bytearray(val)
        ret[0] = ret[2] ^ 0xff
        ret[1] = ret[3] ^ 0xff
        return bytes(ret)

    @classmethod
    def _load_config(cls) -> RegConfig:
        """Load config file."""
        return RegConfig(os.path.join(cls.CONFIG_DIR, cls.CONFIG_FILE))

    @classmethod
    def devices(cls) -> List[str]:
        """Classmethod to get list of supported devices."""
        config = cls._load_config()
        return config.get_devices()

    def _get_registers(self, exclude_computed: bool = True) -> List[RegsRegister]:
        """Get a list of all registers as ElementTree."""
        exclude = self.config.get_ignored_registers(self.device)
        if exclude_computed:
            exclude.extend(self.config.get_computed_registers(self.device))
        return self.registers.get_registers(exclude)

    def _get_bitfields(self, register: RegsRegister, exclude_computed: bool = True) -> List[RegsBitField]:
        """Get bitfields for register."""
        # In XML data there are mandatory FIELDS for registers without any fields
        exclude = []
        ignore_bitfields = self.config.get_ignored_fields(self.device)
        if ignore_bitfields:
            exclude.extend(ignore_bitfields)
        if exclude_computed:
            exclude_fields = self.config.get_computed_fields(self.device)
            if register.name in exclude_fields.keys():
                exclude.extend(exclude_fields[register.name].keys())

        return register.get_bitfields(exclude)

    def set_config_json(self, data: Any, raw: bool = False) -> None:
        """Apply JSON configuration from file.

        :param data: Data of JSON configuration.
        :param raw: When set all (included computed fields) configuration will be applied.
        :raises SPSDKPfrConfigReadError: Invalid JSON file.
        """
        for reg in self._get_registers(not raw):
            json_reg = data.get(reg.name, None)
            if isinstance(json_reg, dict):
                for bitfield in self._get_bitfields(reg, not raw):
                    json_bitfield = json_reg.get(bitfield.name, None)
                    if json_bitfield:
                        bitfield.set_value(json_bitfield, raw)
            elif isinstance(json_reg, str):
                reg.set_value(json_reg, raw)
            else:
                logger.warning(f"Invalid configuration value for {reg.name}.")

    def set_config_yaml(self, data: Any, raw: bool = False) -> None:
        """Apply YML configuration from file.

        :param data: Data of YML configuration.
        :param raw: When set all (included computed fields) configuration will be applied.
        :raises SPSDKPfrConfigReadError: Invalid YML file.
        """
        computed_regs = []
        computed_regs.extend(self.config.get_ignored_registers(self.device))
        if not raw:
            computed_regs.extend(self.config.get_computed_registers(self.device))
        computed_fields = None if raw else self.config.get_computed_fields(self.device)

        self.registers.load_yml_config(data, computed_regs, computed_fields)
        if not raw:
            # Just update only configured registers
            exclude_hooks = list(set(self.registers.get_reg_names())-set(data.keys()))
            self.registers.run_hooks(exclude_hooks)

    def set_config(self, config: PfrConfiguration, raw: bool = False) -> None:
        """Apply configuration from file.

        :param config: PFR configuration.
        :param raw: When set all (included computed fields) configuration will be applied.
        :raises SPSDKPfrConfigError: Invalid config file.
        """
        if config.device != self.device:
            raise SPSDKPfrConfigError(f"Invalid device in configuration. {self.device} != {config.device}")
        if config.revision == "latest":
            config.revision = self.config.get_latest_revision(self.device)
        if config.revision != self.revision:
            raise SPSDKPfrConfigError(f"Invalid revision in configuration. {self.revision} != {config.revision}")
        if config.type.upper() != self.__class__.__name__:
            raise SPSDKPfrConfigError(f"Invalid configuration type. {self.__class__.__name__} != {config.type}")
        if config.file_type == "JSON":
            self.set_config_json(config.settings, raw)
        elif config.file_type == "YAML":
            self.set_config_yaml(config.settings, raw)
        else:
            raise SPSDKPfrConfigError(f"Unsupported type of configuration: {config.file_type}")

    def get_json_config(self, exclude_computed: bool = True) -> dict:
        """Return JSON configuration from loaded registers.

        :param exclude_computed: Omit computed registers and fields.
        :return: JSON PFR configuration.
        """
        def _get_json_config_register(reg: RegsRegister) -> Union[str, dict]:
            """Parse individual register, returns wither one 32b value or dict of bitfields."""
            bitfields = self._get_bitfields(reg, exclude_computed=False)
            # exit early if we found a single 32b field
            if len(bitfields) == 0:
                return format_value(reg.get_int_value(), 32)

            register = {}
            for field in bitfields:
                register[field.name] = format_value(field.get_value(), field.width)
            return register

        data = {}
        for reg in self._get_registers(exclude_computed):
            data[reg.name] = _get_json_config_register(reg)

        return self.user_config.get_json_config(data)

    def get_yaml_config(self, exclude_computed: bool = True, diff: bool = False, indent: int = 0) -> CM:
        """Return YAML configuration from loaded registers.

        :param exclude_computed: Omit computed registers and fields.
        :param diff: Get only configuration with difference value to reset state.
        :param indent: YAML start indent.
        :return: YAML PFR configuration in commented map(ordered dict).
        """
        computed_regs = None if not exclude_computed else self.config.get_computed_registers(self.device)
        computed_fields = None if not exclude_computed else self.config.get_computed_fields(self.device)
        ignored_fields = self.config.get_ignored_fields(self.device)

        data = self.registers.create_yml_config(computed_regs, computed_fields, ignored_fields, diff, indent+2)
        return self.user_config.get_yaml_config(data, indent)

    def generate_config(self, exclude_computed: bool = True) -> CM:
        """Generate configuration structure for user configuration."""
        # Create own copy to keep self as is and get reset values by standard YML output
        copy_of_self = copy.deepcopy(self)
        copy_of_self.registers.reset_values()

        return copy_of_self.get_yaml_config(exclude_computed)

    def _calc_rotkh(self, keys: List[RSAPublicKey]) -> bytes:
        """Calculate ROTKH (Root Of Trust Key Hash)."""
        # the data structure use for computing final ROTKH is 4*32B long
        # 32B is a hash of individual keys
        # 4 is the max number of keys, if a key is not provided the slot is filled with '\x00'
        key_hashes = [calc_pub_key_hash(key, openssl_backend) for key in keys]
        data = [key_hashes[i] if i < len(key_hashes) else bytes(32) for i in range(4)]
        return openssl_backend.hash(bytearray().join(data))

    def _get_seal_start_address(self) -> int:
        start = self.config.get_seal_start_address(self.device)
        assert start, "Can't find 'seal_start_address' in database.json"
        return self.registers.find_reg(start).offset

    def _get_seal_count(self) -> int:
        count = self.config.get_seal_count(self.device)
        assert count, "Can't find 'seal_count' in database.json"
        return value_to_int(count)

    def export(self, add_seal: bool = False, keys: List[RSAPublicKey] = None) -> bytes:
        """Generate binary output."""
        if keys:
            try:
                # ROTKH may or may not be present, derived class defines its presense
                rotkh_reg = self.registers.find_reg(self.ROTKH_REGISTER)
                rotkh_data = self._calc_rotkh(keys)
                rotkh_reg.set_value(rotkh_data, True)
            except SPSDKRegsErrorRegisterNotFound:
                raise SPSDKPfrRotkhIsNotPresent("This device doesn't contain ROTKH register!")

        data = bytearray(self.BINARY_SIZE)
        for reg in self._get_registers(exclude_computed=False):
            # rewriting 4B at the time
            if reg.has_group_registers():
                for grp_reg in reg.sub_regs:
                    val = grp_reg.get_value() if grp_reg.reverse else change_endianism(bytearray(grp_reg.get_value()))
                    data[grp_reg.offset: grp_reg.offset + grp_reg.width//8] = val
            else:
                val = reg.get_value() if reg.reverse else change_endianism(bytearray(reg.get_value()))
                data[reg.offset: reg.offset + reg.width//8] = val

        if add_seal:
            seal_start = self._get_seal_start_address()
            seal_count = self._get_seal_count()
            data[seal_start: seal_start + seal_count * 4] = self.MARK * seal_count

        assert len(data) == self.BINARY_SIZE, f'The size of data is {len(data)}, is not equal to {self.BINARY_SIZE}'
        return bytes(data)

    def parse(self, data: bytes, exclude_computed: bool = True) -> None:
        """Parse input binary data to registers."""
        for reg in self._get_registers(exclude_computed=exclude_computed):
            value = bytearray(data[reg.offset: reg.offset + reg.width // 8])
            reg.set_value(change_endianism(value), raw=not exclude_computed)

class CMPA(BaseConfigArea):
    """Customer Manufacturing Configuration Area."""
    CONFIG_DIR = os.path.join(BaseConfigArea.CONFIG_DIR, "cmpa")
    DESCRIPTION = "Customer Manufacturing Programable Area"


class CFPA(BaseConfigArea):
    """Customer In-Field Configuration Area."""
    CONFIG_DIR = os.path.join(BaseConfigArea.CONFIG_DIR, "cfpa")
    DESCRIPTION = "Customer In-field Programmable Area"


def calc_pub_key_hash(public_key: RSAPublicKey, backend: BackendClass = openssl_backend) -> bytes:
    """Calculate a hash out of public key's exponent and modulus."""
    exponent = public_key.public_numbers().e  # type: ignore # MyPy is unable to pickup the class member
    exp_len = math.ceil(exponent.bit_length() / 8)
    exp_bytes = exponent.to_bytes(exp_len, "big")

    modulus = public_key.public_numbers().n  # type: ignore # MyPy is unable to pickup the class member
    mod_len = math.ceil(modulus.bit_length() / 8)
    mod_bytes = modulus.to_bytes(mod_len, "big")

    return backend.hash(mod_bytes + exp_bytes)
