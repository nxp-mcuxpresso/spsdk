#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""HAB Set Command implementation module.

This module provides implementation of the HAB SET command used to set the value
of variable configuration items, such as preferred cryptographic engines.
"""

from struct import pack, unpack_from
from typing import Optional

from typing_extensions import Self

from spsdk.exceptions import SPSDKError
from spsdk.image.hab.commands.commands import CmdBase
from spsdk.image.hab.constants import CmdName, CmdTag, EngineEnum, EnumAlgorithm
from spsdk.image.hab.hab_header import CmdHeader
from spsdk.utils.config import Config
from spsdk.utils.spsdk_enum import SpsdkEnum


class SetItmEnum(SpsdkEnum):
    """HAB Set command item type enumeration.

    This enumeration defines the available item types that can be configured
    using the HAB Set command, including manufacturing ID fuse locations
    and preferred cryptographic engine settings.
    """

    MID = (0x01, "MID", "Manufacturing ID (MID) fuse locations")
    ENG = (0x03, "ENG", "Preferred engine for a given algorithm")


class CmdSet(CmdBase):
    """HAB Set command for configuring variable items.

    This command sets the value of variable configuration items in the HAB (High Assurance Boot)
    system, including hash algorithms, engines, and engine configurations. The command follows
    the HAB command structure with tag, length, item, and value fields.

    +-------------+--------------+--------------+
    |     tag     |      len     |     itm      |
    +-------------+--------------+--------------+
    |                   value                   |
    +-------------------------------------------+
    |                     .                     |
    +-------------------------------------------+

    :cvar CMD_IDENTIFIER: Command identifier for SET_ENGINE operations.
    :cvar CMD_TAG: Command tag for SET operations.
    """

    CMD_IDENTIFIER = CmdName.SET_ENGINE
    CMD_TAG = CmdTag.SET

    def __init__(
        self,
        itm: SetItmEnum = SetItmEnum.ENG,
        hash_alg: EnumAlgorithm = EnumAlgorithm.ANY,
        engine: EngineEnum = EngineEnum.ANY,
        engine_cfg: int = 0,
    ):
        """Initialize the Set command.

        Creates a new Set command instance with specified configuration parameters
        for HAB (High Assurance Boot) operations.

        :param itm: Item type to set, defaults to ENG (engine configuration)
        :param hash_alg: Hash algorithm to use, defaults to ANY
        :param engine: Cryptographic engine type, defaults to ANY
        :param engine_cfg: Engine configuration value, defaults to 0
        :raises SPSDKError: When itm parameter is not a valid SetItmEnum value
        """
        if itm not in SetItmEnum:
            raise SPSDKError("Incorrect engine configuration flag")
        super().__init__(itm.tag)
        self.hash_algorithm = hash_alg
        self.engine = engine
        self.engine_cfg = engine_cfg
        self._header.length = CmdHeader.SIZE + 4

    @property
    def itm(self) -> SetItmEnum:
        """Get the item type of the Set command.

        :return: The item enumeration value extracted from the command header parameter.
        """
        return SetItmEnum.from_tag(self._header.param)

    @itm.setter
    def itm(self, value: SetItmEnum) -> None:
        """Set the item type for the HAB set command.

        This method configures the specific item type that the HAB set command will operate on,
        using predefined enumeration values.

        :param value: The item type to set for the command.
        :raises SPSDKError: If the provided value is not a valid SetItmEnum member.
        """
        if value not in SetItmEnum:
            raise SPSDKError("Incorrect item of set command")
        self._header.param = value.tag

    @property
    def hash_algorithm(self) -> EnumAlgorithm:
        """Get the hash algorithm type.

        :return: The hash algorithm enumeration value.
        """
        return self._hash_alg

    @hash_algorithm.setter
    def hash_algorithm(self, value: EnumAlgorithm) -> None:
        """Set the hash algorithm for the command.

        :param value: Hash algorithm to be used for the command.
        :raises SPSDKError: If the provided algorithm is not a valid EnumAlgorithm value.
        """
        if value not in EnumAlgorithm:
            raise SPSDKError("Incorrect type of algorithm")
        self._hash_alg = value

    @property
    def engine(self) -> EngineEnum:
        """Get engine plugin tags.

        :return: Engine plugin enumeration value.
        """
        return self._engine

    @engine.setter
    def engine(self, value: EngineEnum) -> None:
        """Set the engine plugin type for the command.

        This method validates and assigns the engine plugin type that will be used
        for cryptographic operations in the HAB command.

        :param value: The engine plugin type to set.
        :raises SPSDKError: If the provided engine type is not a valid EngineEnum value.
        """
        if value not in EngineEnum:
            raise SPSDKError("Incorrect type of engine plugin")
        self._engine = value

    def __repr__(self) -> str:
        """Return string representation of the Set command object.

        The representation includes the class name, item type, hash algorithm,
        engine type, and engine configuration in hexadecimal format.

        :return: String representation of the Set command with key attributes.
        """
        return (
            f"{self.__class__.__name__} <{self.itm.label}, {self.hash_algorithm.label},"
            f" {self.engine.label}, eng_cfg=0x{self.engine_cfg:X}>"
        )

    def __str__(self) -> str:
        """Get string representation of the Set command.

        Returns a formatted string containing the command details including ITM label,
        hash algorithm, engine type, and engine configuration.

        :return: Formatted string description of the Set command.
        """
        msg = super().__str__()
        msg += f"Set Command ITM : {self.itm.label}\n"
        msg += f"HASH Algo      : {self.hash_algorithm} ({self.hash_algorithm.description})\n"
        msg += f"Engine         : {self.engine} ({self.engine.description})\n"
        msg += f"Engine Conf    : {hex(self.engine_cfg)})\n"
        return msg

    def export(self) -> bytes:
        """Export command to binary representation.

        Serializes the SET command including its hash algorithm, engine type,
        and engine configuration into binary format for HAB processing.

        :return: Binary representation of the SET command.
        """
        raw_data = super().export()
        raw_data += pack("4B", 0x00, self.hash_algorithm.tag, self.engine.tag, self.engine_cfg)
        return raw_data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse binary data into SET command object.

        Deserializes binary representation of a SET command back into a command object
        by extracting header information and command-specific parameters.

        :param data: Binary data to be parsed into SET command.
        :return: Parsed SET command object.
        """
        header = CmdHeader.parse(data, CmdTag.SET.tag)
        (_, alg, eng, cfg) = unpack_from("4B", data, CmdHeader.SIZE)
        return cls(
            SetItmEnum.from_tag(header.param),
            EnumAlgorithm.from_tag(alg),
            EngineEnum.from_tag(eng),
            cfg,
        )

    @classmethod
    def load_from_config(cls, config: Config, cmd_index: Optional[int] = None) -> Self:
        """Load configuration into the command.

        This method creates a new command instance and populates it with configuration data
        including hash algorithm, engine type, and engine configuration settings.

        :param config: HAB image configuration containing command settings.
        :param cmd_index: Optional index of the command in the configuration in case multiple
            same commands are present.
        :return: New command instance populated with configuration data.
        """
        cmd = cls()
        cmd_cfg = cls._get_cmd_config(config, cmd_index)
        hash_algorithm = cmd_cfg.get("SetEngine_HashAlgorithm")
        if hash_algorithm is not None:
            cmd.hash_algorithm = EnumAlgorithm.from_label(hash_algorithm)
        engine = cmd_cfg.get("SetEngine_Engine")
        if engine is not None:
            cmd.engine = EngineEnum.from_label(engine)
        engine_cfg = cmd_cfg.get("SetEngine_EngineConfiguration")
        if engine_cfg is not None:
            cmd.engine_cfg = int(engine_cfg)
        return cmd
