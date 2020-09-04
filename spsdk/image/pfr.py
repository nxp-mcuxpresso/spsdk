#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module provides support for Protected Flash Region."""
import json
import math
import os
from typing import List, Union
from xml.etree import ElementTree as ET

from bitstring import BitArray  # type: ignore #Type info for bitstring is not available
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from spsdk import SPSDK_DATA_FOLDER
from spsdk.image.misc import format_value, parse_int
from spsdk.utils.crypto.abstract import BackendClass
from spsdk.utils.crypto.backend_openssl import openssl_backend


class BaseConfigArea:
    """Base for CMPA and CFPA classes."""
    CONFIG_DIR = SPSDK_DATA_FOLDER
    CONFIG_FILE = "database.json"
    BINARY_SIZE = 512
    HAS_ROTKH = True
    ROTKH_SIZE = 32
    ROTKH_START_REGISTER = "ROTKH0"
    SHA_SIZE = 32
    SHA_START_REGISTER = "SHA256_DIGEST0"

    def __init__(self, device: str, keys: List[RSAPublicKey] = None,
                 revision: str = None, user_config: dict = None,
                 rotkh: bytes = None) -> None:
        """Initialize an instance.

        :param device: device to use, list of supported devices is available via 'devices' method
        :param keys: list of RSA Public Keys to compute ROTKH
        :param revision: silicon revision, if not specified, the latest is being used
        :param user_config: dict with user configuration
        :param rotkh: pre-computed ROTKH
        """
        self.config = self._load_config()
        assert device in self.get_devices(), f"Device '{device}' is not supported"
        self.device = device
        self.revision = revision or self._get_latest_revision(device)
        assert self.revision in self.get_revisions(device), f"Invalid revision '{revision}' for '{device}'"
        self.data = self._load_data()
        self.user_config = user_config or dict()
        self.keys = keys
        self.rotkh = rotkh

    @classmethod
    def _load_config(cls) -> dict:
        """Load config file."""
        with open(os.path.join(cls.CONFIG_DIR, cls.CONFIG_FILE)) as config_file:
            return json.load(config_file)

    def _get_latest_revision(self, device: str) -> str:
        """Get latest revision for device."""
        return self.config["devices"][device]["latest"]

    @classmethod
    def devices(cls) -> List[str]:
        """Classmethod to get list of supppoted devices."""
        config = cls._load_config()
        return list(config['devices'].keys())

    def get_devices(self) -> List[str]:
        """Get list of supported devices."""
        return list(self.config["devices"].keys())

    def get_revisions(self, device: str) -> List[str]:
        """Get list of revisions for given device."""
        return list(self.config["devices"][device]["revisions"].keys())

    def get_address(self, remove_underscore: bool = False) -> str:
        """Get the area address in chip memory."""
        address = self.config["devices"][self.device]["address"]
        if remove_underscore:
            return address.replace("_", "")
        return address

    def _get_data_file(self) -> str:
        """Return the full path to data file (xml)."""
        file_name = self.config["devices"][self.device]["revisions"][self.revision]
        return os.path.join(self.CONFIG_DIR, file_name)

    def _load_data(self) -> ET.ElementTree:
        """Load the register data."""
        reg_file = self._get_data_file()
        return ET.parse(reg_file)

    # pylint: disable=no-self-use   #It's better to have this function visually close to callies
    def _filter_by_names(self, items: List[ET.Element], names: List[str]) -> List[ET.Element]:
        """Filter out all items in the "items" tree,whose name starts with one of the strings in "names" list."""
        filtered = [
            item for item in items if not item.attrib["name"].startswith(tuple(names))
        ]
        return filtered

    def _filter_computed_registers(self, items: List[ET.Element]) -> List[ET.Element]:
        """Filter computed registers."""
        regs = self.config["computed_registers"]
        return self._filter_by_names(items, regs)

    def _filter_computed_fields(self, items: List[ET.Element]) -> List[ET.Element]:
        """Filter computerd fields."""
        fields = self.config["computed_fields"]
        return self._filter_by_names(items, fields)

    def _filter_ignored_registers(self, items: List[ET.Element]) -> List[ET.Element]:
        """Filter registers that shall be ignored."""
        regs = self.config.get("ignored_registers", "")
        return self._filter_by_names(items, regs)

    def _get_registers(self, exclude_computed: bool = True) -> List[ET.Element]:
        """Get a list of all registers as ElementTree."""
        registers = self.data.findall("register")
        registers = self._filter_ignored_registers(registers)
        if exclude_computed:
            return self._filter_computed_registers(registers)
        return registers

    def _get_register(self, register_name: str) -> ET.Element:
        """Get single register tree by the register's name."""
        reg = self.data.find(f"register[@name='{register_name}']")
        assert reg, f"Register '{register_name}' wasn't found!"
        return reg

    def _get_register_names(self, exclude_computed: bool = True) -> List[str]:
        """Get a list of all register names."""
        registers = self._get_registers(exclude_computed)
        return [r.attrib["name"] for r in registers]

    def _get_bitfields(self, register_name: str, exclude_computed: bool = True) -> List[ET.Element]:
        """Get bitfields for register as ElementTree."""
        fields = self.data.findall(f"register[@name='{register_name}']/bit_field")
        if exclude_computed:
            return self._filter_computed_fields(fields)
        return fields

    def _get_bitfield_names(self, register_name: str, exclude_computed: bool = True) -> List[str]:
        """Get a list of bitfield names for given register."""
        bit_fiels = self._get_bitfields(register_name, exclude_computed)
        return [bf.attrib["name"] for bf in bit_fiels]

    def _get_bitfield_config(self, register_name: str, exclude: bool) -> dict:
        """Get bitfield configuration."""
        field_config = {}
        for field in self._get_bitfields(register_name, exclude):
            name = field.attrib["name"]
            value = format_value(int(field.attrib["reset_value"]), int(field.attrib["width"]))
            field_config[name] = value
        return field_config

    def generate_config(self, exclude_computed: bool = True) -> dict:
        """Generate configuration structure for user configuration."""
        config = {}
        for reg in self._get_register_names(exclude_computed):
            field_config = self._get_bitfield_config(reg, exclude_computed)
            if len(field_config) == 1 and field_config.get('FIELD'):
                config[reg] = field_config.popitem()[1]
            else:
                config[reg] = field_config
        return config

    def _export_register(self, register_name: str, compute_inverses: bool) -> bytes:
        """Generate binary output for single register."""
        register = BitArray(length=32)
        user_config = self.user_config.get(register_name, dict())
        inverse_present = False
        for field in self._get_bitfields(register_name, exclude_computed=False):
            name = field.attrib["name"]
            offset = parse_int(field.attrib["offset"])
            width = parse_int(field.attrib["width"])
            # chcek whether there's a need to calculate inverse values
            inverse_present |= name == "INVERSE_VALUE"

            # The configuration allows to configure the whole register with single value
            if isinstance(user_config, str):
                temp_value = user_config
            else:
                temp_value = user_config.get(name) or field.attrib["reset_value"]
            value = parse_int(temp_value)
            # due to endianess we fill the bits from the end, therefore there's '-' in position
            # pos = 0 means offset = 0, means end of the BitArray
            register.overwrite(bs=BitArray(f"uint:{width}={value}"), pos=-(offset + width))
        if compute_inverses and inverse_present:
            # NOTE: For now we'll assume the INVERSES are 16b long and inverts bits[15:0]
            # should this change in the future a data model change is necessary
            # NOTE: invert method changes bits in-place, thus we need to call it on separate object
            # calling invert() after slicing doesn't work for BitArray
            b_lower = register[16:]
            b_lower.invert()
            register.overwrite(b_lower, 0)
        # swapping bytes from big endian into little
        register.byteswap()
        return register.bytes

    def _calc_rotkh(self) -> bytes:
        """Calculate ROTKH (Root Of Trust Key Hash)."""
        # the data structure use for computing final ROTKH is 4*32B long
        # 32B is a hash of individual keys
        # 4 is the max number of keys, if a key is not provided the slot is filled with '\x00'
        assert self.keys, f"Key's were not set, can't compute ROTKH"
        key_hashes = [calc_pub_key_hash(key, openssl_backend) for key in self.keys]
        data = [key_hashes[i] if i < len(key_hashes) else bytes(32) for i in range(4)]
        return openssl_backend.hash(bytearray().join(data))

    def _get_rotkh_start_address(self) -> int:
        """Return the offset of the first ROTKHx register defined as ROTKH_START_REGISTER."""
        return parse_int(self._get_register(self.ROTKH_START_REGISTER).attrib["offset"])

    def _get_sha_start_address(self) -> int:
        """Return the offset of the first SHA_DIGEST register."""
        return parse_int(self._get_register(self.SHA_START_REGISTER).attrib["offset"])

    def export(self, add_hash: bool = False, compute_inverses: bool = False) -> bytes:
        """Generate binary output."""
        data = bytearray(self.BINARY_SIZE)
        for reg in self._get_registers(exclude_computed=False):
            name = reg.attrib["name"]
            width = parse_int(reg.attrib["width"])
            offset = parse_int(reg.attrib["offset"])
            assert width == 32, "Don't know how to handle non-32b registers"
            register = self._export_register(name, compute_inverses)
            # rewriting 4B at the time
            data[offset: offset + 4] = register

        # ROTKH may or may not be present, derived class defines its presense
        if self.HAS_ROTKH:
            rotkh_data = self.rotkh or self._calc_rotkh()
            rothk_start = self._get_rotkh_start_address()
            data[rothk_start: rothk_start + self.ROTKH_SIZE] = rotkh_data

        if add_hash:
            sha_start = self._get_sha_start_address()
            data[sha_start: sha_start + self.SHA_SIZE] = openssl_backend.hash(data[:sha_start])
        return bytes(data)

    def _parse_register(self, register_name: str, data: bytes) -> Union[str, dict]:
        """Parse individual register, returns wither one 32b value or dict of bitfields."""
        register = {}
        bits = BitArray(data)
        # data is stored in little endian, but processed in big endian
        bits.byteswap()
        for field in self._get_bitfields(register_name, exclude_computed=False):
            width = parse_int(field.attrib["width"])
            # exit early if we found a single 32b field
            if width == 32:
                return format_value(bits.uint, width)
            name = field.attrib["name"]
            offset = parse_int(field.attrib["offset"])
            # OK, what the hell is that slicing about?!
            # offset is marked from the end of the bitarray not the begging like in a list
            # e.g.: ba = BitArray('0b00001100'), we want to extract bitfields of width=2 and offset=2 ('11')
            # again offset=2 means 2 bits from the end
            # BitArray supports negative indexing like an regular python list does: last bit has index -1
            # that means we want to extract bits with indecies -4,-3 => [-4:-2]
            # HOWEVER: if we would want to extract 2 bits in the end (offset=0)
            # we would need to use [-offset:] slice or [-offset:None]
            slice_end = None if offset == 0 else -offset
            filed_bits = bits[-(offset + width): slice_end]
            register[name] = format_value(filed_bits.uint, width)
        return register

    def parse(self, data: bytes, exclude_computed: bool = True) -> dict:
        """Return a user config JSON object based on input data."""
        user_config = {}
        for reg in self._get_registers(exclude_computed=exclude_computed):
            name = reg.attrib["name"]
            width = parse_int(reg.attrib["width"])
            offset = parse_int(reg.attrib["offset"])
            assert width == 32, "Don't know how to handle non-32b registers"
            reg_config = self._parse_register(name, data[offset: offset + 4])
            user_config[name] = reg_config
        return user_config


class CMPA(BaseConfigArea):
    """Customer Manufacturing Configuration Area."""
    CONFIG_DIR = os.path.join(BaseConfigArea.CONFIG_DIR, "cmpa")


class CFPA(BaseConfigArea):
    """Customer In-Field Configuration Area."""
    CONFIG_DIR = os.path.join(BaseConfigArea.CONFIG_DIR, "cfpa")
    HAS_ROTKH = False


def calc_pub_key_hash(public_key: RSAPublicKey, backend: BackendClass = openssl_backend) -> bytes:
    """Calculate a hash out of public key's exponent and modulus."""
    exponent = public_key.public_numbers().e  # type: ignore # MyPy is unable to pickup the class member
    exp_len = math.ceil(exponent.bit_length() / 8)
    exp_bytes = exponent.to_bytes(exp_len, "big")

    modulus = public_key.public_numbers().n  # type: ignore # MyPy is unable to pickup the class member
    mod_len = math.ceil(modulus.bit_length() / 8)
    mod_bytes = modulus.to_bytes(mod_len, "big")

    return backend.hash(mod_bytes + exp_bytes)
