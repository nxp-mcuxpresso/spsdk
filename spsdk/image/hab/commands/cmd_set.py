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
    """Engine configuration flags of Set command."""

    MID = (0x01, "MID", "Manufacturing ID (MID) fuse locations")
    ENG = (0x03, "ENG", "Preferred engine for a given algorithm")


class CmdSet(CmdBase):
    """Set the value of variable configuration items.

    +-------------+--------------+--------------+
    |     tag     |      len     |     itm      |
    +-------------+--------------+--------------+
    |                   value                   |
    +-------------------------------------------+
    |                     .                     |
    +-------------------------------------------+
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
        """Initialize the set command."""
        if itm not in SetItmEnum:
            raise SPSDKError("Incorrect engine configuration flag")
        super().__init__(itm.tag)
        self.hash_algorithm = hash_alg
        self.engine = engine
        self.engine_cfg = engine_cfg
        self._header.length = CmdHeader.SIZE + 4

    @property
    def itm(self) -> SetItmEnum:
        """Item of Set command."""
        return SetItmEnum.from_tag(self._header.param)

    @itm.setter
    def itm(self, value: SetItmEnum) -> None:
        if value not in SetItmEnum:
            raise SPSDKError("Incorrect item of set command")
        self._header.param = value.tag

    @property
    def hash_algorithm(self) -> EnumAlgorithm:
        """Type of hash algorithm."""
        return self._hash_alg

    @hash_algorithm.setter
    def hash_algorithm(self, value: EnumAlgorithm) -> None:
        if value not in EnumAlgorithm:
            raise SPSDKError("Incorrect type of algorithm")
        self._hash_alg = value

    @property
    def engine(self) -> EngineEnum:
        """Engine plugin tags."""
        return self._engine

    @engine.setter
    def engine(self, value: EngineEnum) -> None:
        if value not in EngineEnum:
            raise SPSDKError("Incorrect type of engine plugin")
        self._engine = value

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__} <{self.itm.label}, {self.hash_algorithm.label},"
            f" {self.engine.label}, eng_cfg=0x{self.engine_cfg:X}>"
        )

    def __str__(self) -> str:
        """Text description of the command."""
        msg = super().__str__()
        msg += f"Set Command ITM : {self.itm.label}\n"
        msg += f"HASH Algo      : {self.hash_algorithm} ({self.hash_algorithm.description})\n"
        msg += f"Engine         : {self.engine} ({self.engine.description})\n"
        msg += f"Engine Conf    : {hex(self.engine_cfg)})\n"
        return msg

    def export(self) -> bytes:
        """Export to binary form (serialization).

        :return: binary representation of the command
        """
        raw_data = super().export()
        raw_data += pack("4B", 0x00, self.hash_algorithm.tag, self.engine.tag, self.engine_cfg)
        return raw_data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Convert binary representation into command (deserialization from binary data).

        :param data: being parsed
        :return: parse command
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

        :param config: HAB image configuration
        :param cmd_index: Optional index of the command in the configuration in case multiple same commands are present
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
