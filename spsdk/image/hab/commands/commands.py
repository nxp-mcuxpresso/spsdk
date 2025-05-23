#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This module contains code related to CSF commands."""

import logging
from dataclasses import dataclass
from typing import Any, Optional, Type, Union

from typing_extensions import Self

from spsdk.exceptions import SPSDKError, SPSDKKeyError
from spsdk.image.hab.constants import CmdName, CmdTag
from spsdk.image.hab.hab_certificate import HabCertificate
from spsdk.image.hab.hab_header import CmdHeader
from spsdk.image.hab.hab_mac import MAC
from spsdk.image.hab.hab_signature import Signature
from spsdk.image.hab.hab_srk import SrkTable
from spsdk.utils.abstract import BaseClass
from spsdk.utils.config import Config

logger = logging.getLogger(__name__)


class SPSDKCommandNotDefined(SPSDKError):
    """Command not defined in configuration."""


@dataclass
class ImageBlock:
    """Single image block."""

    base_address: int
    start: int
    size: int


CmdSecretRefType = Union[HabCertificate, Signature, MAC, SrkTable]


class CmdBase(BaseClass):
    """Base class for all commands."""

    CMD_IDENTIFIER: Optional[CmdName] = None
    CMD_TAG: CmdTag

    def __init__(self, param: int, length: Optional[int] = None):
        """Constructor.

        :param tag: command tag
        :param param: tag
        :param length: of the binary command representation, in bytes
        """
        self._header = CmdHeader(self.CMD_TAG, param, length)

    @property
    def size(self) -> int:
        """Size of command."""
        return self._header.length

    @property
    def tag(self) -> int:
        """Command tag."""
        return self._header.tag

    @property
    def needs_cmd_data_reference(self) -> bool:
        """Whether the command needs a reference to an additional data.

        If returns True, the following methods must be implemented:
        - cmd_data_offset
        - cmd_data_reference
        """
        return False  # default implementation

    @property
    def cmd_data_offset(self) -> int:
        """Offset of an additional data (such as certificate, signature, etc) in binary image."""
        return 0

    @cmd_data_offset.setter
    def cmd_data_offset(self, value: int) -> None:  # pylint: disable=no-self-use
        """Setter.

        :param value: offset to set
        :raises SPSDKError: If cmd-data not supported by the command
        """
        raise SPSDKError("cmd-data not supported by the command")

    @property
    def cmd_data_reference(self) -> Optional[CmdSecretRefType]:
        """Reference to a command data (such as certificate, signature, etc).

        None if no reference was assigned;
        Value type is command-specific
        """
        return None

    @cmd_data_reference.setter
    def cmd_data_reference(self, value: CmdSecretRefType) -> None:  # pylint: disable=no-self-use
        """Setter.

        By default, the command does not support cmd_data_reference
        Note: the method must be implemented in `self.has_cmd_data_reference` returns True

        :param value: to be set
        :raises SPSDKError: If reference not supported by the command
        """
        raise SPSDKError("Command data are not supported by the command")

    def parse_cmd_data(self, data: bytes) -> Any:  # pylint: disable=no-self-use
        """Parse additional command data from binary data.

        :param data: to be parsed
        :raises SPSDKError: If cmd_data is not supported by the command
        """
        raise SPSDKError("Command data are supported by the command")

    def __repr__(self) -> str:
        return f"Command: {CmdTag.get_description(self.tag)}"

    def __str__(self) -> str:
        """Text representation of the command."""
        return f'Command "{CmdTag.get_description(self.tag)}"   [Tag={str(self.tag)}, Length={str(self.size)}]\n'

    def export(self) -> bytes:
        """Export to binary form (serialization).

        :return: binary representation of the command
        """
        hdr_data = self._header.export()
        return hdr_data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Convert binary representation into command (deserialization from binary data).

        :param data: being parsed
        :return: parse command
        :raises NotImplementedError: Derived class has to implement this method
        """
        raise NotImplementedError("Derived class has to implement this method.")

    @classmethod
    def load_from_config(cls, config: Config, cmd_index: Optional[int] = None) -> Self:
        """Load command from HAB configuration.

        A full HAB configuration is needed as some commands require additional data, such as options.
        :param config: Configuration object for loading command
        :param cmd_index: The index of a command in configuration
        """
        raise NotImplementedError("Derived class has to implement this method.")

    @classmethod
    def _get_cmd_config(cls, config: Config, cmd_index: Optional[int] = None) -> Config:
        if not cls.CMD_IDENTIFIER:
            raise SPSDKError(f"Command identifier is not defined for {cls.__name__}")

        cmd_configs = config.get_list_of_configs("sections")
        cmd_configs = [
            cmd for cmd in cmd_configs if list(cmd.keys())[0] == cls.CMD_IDENTIFIER.label
        ]
        if not cmd_configs:
            raise SPSDKCommandNotDefined(
                f"Command {cls.CMD_IDENTIFIER} is not defined in configuration"
            )
        if not cmd_index:
            return cmd_configs[0].get_config(cls.CMD_IDENTIFIER.label)

        if cmd_index >= len(cmd_configs):
            raise SPSDKKeyError(
                f"Command index {cmd_index} is out of range for {cls.CMD_IDENTIFIER}"
            )
        return cmd_configs[cmd_index].get_config(cls.CMD_IDENTIFIER.label)

    @classmethod
    def get_all_command_types(cls) -> list[Type["CmdBase"]]:
        """Get all command types that inherit from CmdBase.

        This method recursively finds all subclasses of CmdBase.

        :return: List of all command types
        """

        def get_subclasses(base_class: Type) -> list[Type["CmdBase"]]:
            """Recursively find all subclasses."""
            subclasses = []
            for subclass in base_class.__subclasses__():
                subclasses.append(subclass)
                subclasses.extend(get_subclasses(subclass))
            return subclasses

        return get_subclasses(CmdBase)

    def post_export(self, output_path: str) -> list[str]:
        """Post-export processing for segment size calculation.

        :return: Total size of the segment after export
        """
        return []


def parse_command(data: bytes) -> CmdBase:
    """Parse CSF/DCD command.

    :param data: binary data to be parsed
    :return: instance of the command
    :raises SPSDKError: If the command is not valid
    """
    try:
        cmd_tag = CmdTag.from_tag(data[0])
    except SPSDKKeyError as exc:
        raise SPSDKError("Unknown command to parse") from exc
    cmd_class = next(
        (cmd for cmd in CmdBase.get_all_command_types() if cmd.CMD_TAG == cmd_tag),
        None,
    )
    if not cmd_class:
        raise SPSDKError("Unknown command to parse")
    return cmd_class.parse(data)
