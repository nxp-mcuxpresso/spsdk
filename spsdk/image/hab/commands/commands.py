#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK HAB CSF command definitions and parsing utilities.

This module provides the foundation for HAB (High Assurance Boot) CSF (Command Sequence File)
commands used in secure boot processes. It includes base classes for command implementation,
command parsing functionality, and image block handling for NXP MCU secure provisioning.
"""

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
    """SPSDK HAB command configuration error exception.

    This exception is raised when a required HAB command is not properly defined
    or missing from the configuration during image processing operations.
    """


@dataclass
class ImageBlock:
    """HAB image block representation for secure boot operations.

    This class represents a single memory block within a HAB (High Assurance Boot)
    image, containing the base address, start offset, and size information needed
    for image processing and validation.
    """

    base_address: int
    start: int
    size: int


CmdSecretRefType = Union[HabCertificate, Signature, MAC, SrkTable]


class CmdBase(BaseClass):
    """Base class for all HAB commands.

    This class provides the foundation for implementing High Assurance Boot (HAB) commands
    used in secure boot operations. It manages command headers, data references, and provides
    a common interface for command serialization and parsing.

    :cvar CMD_IDENTIFIER: Optional command name identifier for the command type.
    :cvar CMD_TAG: Command tag that identifies the specific command type.
    """

    CMD_IDENTIFIER: Optional[CmdName] = None
    CMD_TAG: CmdTag

    def __init__(self, param: int, length: Optional[int] = None):
        """Initialize HAB command with header parameters.

        :param param: Command-specific parameter value.
        :param length: Length of the binary command representation in bytes, defaults to None.
        """
        self._header = CmdHeader(self.CMD_TAG, param, length)

    @property
    def size(self) -> int:
        """Get the size of the command in bytes.

        :return: Size of the command including header and data.
        """
        return self._header.length

    @property
    def tag(self) -> int:
        """Get command tag value.

        :return: Command tag as integer value.
        """
        return self._header.tag

    @property
    def needs_cmd_data_reference(self) -> bool:
        """Check if the command needs a reference to additional data.

        If returns True, the following methods must be implemented:
        - cmd_data_offset
        - cmd_data_reference

        :return: True if command needs data reference, False otherwise.
        """
        return False  # default implementation

    @property
    def cmd_data_offset(self) -> int:
        """Get offset of additional data in binary image.

        Returns the offset where additional data such as certificates, signatures,
        or other supplementary information is located within the binary image.

        :return: Offset value in bytes, defaults to 0 for base implementation.
        """
        return 0

    @cmd_data_offset.setter
    def cmd_data_offset(self, value: int) -> None:  # pylint: disable=no-self-use
        """Set command data offset.

        This method is not supported by this command type and will always raise an exception.

        :param value: Offset value to set for command data.
        :raises SPSDKError: If cmd-data not supported by the command.
        """
        raise SPSDKError("cmd-data not supported by the command")

    @property
    def cmd_data_reference(self) -> Optional[CmdSecretRefType]:
        """Get reference to command data.

        Returns reference to command data such as certificate, signature, or other
        command-specific data. The value type depends on the specific command implementation.
        """
        return None

    @cmd_data_reference.setter
    def cmd_data_reference(self, value: CmdSecretRefType) -> None:  # pylint: disable=no-self-use
        """Set command data reference.

        By default, the command does not support cmd_data_reference functionality.
        Note: this method must be implemented if `self.has_cmd_data_reference` returns True.

        :param value: Command secret reference type to be set.
        :raises SPSDKError: If reference not supported by the command.
        """
        raise SPSDKError("Command data are not supported by the command")

    def parse_cmd_data(self, data: bytes) -> Any:  # pylint: disable=no-self-use
        """Parse additional command data from binary data.

        This method should be overridden by subclasses to implement command-specific
        data parsing logic.

        :param data: Binary data to be parsed.
        :raises SPSDKError: If command data parsing is not supported by the command.
        """
        raise SPSDKError("Command data are supported by the command")

    def __repr__(self) -> str:
        """Return string representation of the command.

        The method provides a human-readable string representation showing the command type
        based on its tag value.

        :return: String representation in format "Command: <tag_description>".
        """
        return f"Command: {CmdTag.get_description(self.tag)}"

    def __str__(self) -> str:
        """Get text representation of the command.

        Returns a formatted string containing the command description, tag, and size information.

        :return: Formatted string with command details including description, tag, and length.
        """
        return f'Command "{CmdTag.get_description(self.tag)}"   [Tag={str(self.tag)}, Length={str(self.size)}]\n'

    def export(self) -> bytes:
        """Export command to binary form.

        Serializes the command into its binary representation by exporting the header data.

        :return: Binary representation of the command.
        """
        hdr_data = self._header.export()
        return hdr_data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Convert binary representation into command (deserialization from binary data).

        :param data: Binary data to be parsed into command object.
        :raises NotImplementedError: Derived class has to implement this method.
        :return: Parsed command object.
        """
        raise NotImplementedError("Derived class has to implement this method.")

    @classmethod
    def load_from_config(cls, config: Config, cmd_index: Optional[int] = None) -> Self:
        """Load command from HAB configuration.

        A full HAB configuration is needed as some commands require additional data, such as options.

        :param config: Configuration object for loading command.
        :param cmd_index: The index of a command in configuration.
        :raises NotImplementedError: Derived class has to implement this method.
        :return: Command instance loaded from configuration.
        """
        raise NotImplementedError("Derived class has to implement this method.")

    @classmethod
    def _get_cmd_config(cls, config: Config, cmd_index: Optional[int] = None) -> Config:
        """Get command configuration from the main configuration object.

        Extracts the configuration for a specific command type identified by CMD_IDENTIFIER.
        If multiple instances of the same command exist, returns the one at the specified index.

        :param config: Main configuration object containing all command sections.
        :param cmd_index: Index of the command instance to retrieve (defaults to first instance).
        :raises SPSDKError: Command identifier is not defined for the class.
        :raises SPSDKCommandNotDefined: Command is not found in configuration.
        :raises SPSDKKeyError: Command index is out of range.
        :return: Configuration object for the specified command instance.
        """
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

        This method recursively finds all subclasses of CmdBase to provide a complete list of
        available command types in the HAB command hierarchy.

        :return: List of all command types that inherit from CmdBase.
        """

        def get_subclasses(base_class: Type) -> list[Type["CmdBase"]]:
            """Recursively find all subclasses of the given base class.

            This method performs a depth-first search through the class hierarchy to collect
            all direct and indirect subclasses of the specified base class.

            :param base_class: The base class to find subclasses for.
            :return: List of all subclasses found in the inheritance hierarchy.
            """
            subclasses = []
            for subclass in base_class.__subclasses__():
                subclasses.append(subclass)
                subclasses.extend(get_subclasses(subclass))
            return subclasses

        return get_subclasses(CmdBase)

    def post_export(self, output_path: str) -> list[str]:
        """Post-export processing for segment size calculation.

        :param output_path: Path where the segment data will be exported.
        :return: List of strings representing exported file paths or segment information.
        """
        return []


def parse_command(data: bytes) -> CmdBase:
    """Parse CSF/DCD command from binary data.

    The method extracts command tag from the first byte and creates appropriate
    command instance based on the tag type.

    :param data: Binary data containing the command to be parsed.
    :raises SPSDKError: If the command tag is unknown or invalid.
    :return: Instance of the parsed command.
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
