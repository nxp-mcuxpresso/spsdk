#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright (c) 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for functionality shared across all MBoot interfaces."""

from abc import ABC, abstractmethod
from typing import Union

from spsdk.mboot.commands import CmdPacket, CmdResponse


class MBootInterface(ABC):
    """Base class for all Mboot Interface classes."""

    @property
    def is_opened(self) -> bool:
        """Indicates whether interface is open."""
        return False

    @property
    def need_data_split(self) -> bool:
        """Indicates whether device need to split data into smaller chunks."""
        return True

    def __init__(self, reopen: bool = False) -> None:
        """Initialize the Interface object.

        :param reopen: Reopen the interface after reset, defaults to False
        """
        self.reopen = reopen
        self.allow_abort = False

    @abstractmethod
    def open(self) -> None:
        """Open the interface."""

    @abstractmethod
    def close(self) -> None:
        """Close the interface."""

    @abstractmethod
    def read(self) -> Union[CmdResponse, bytes]:
        """Read data from the device."""

    @abstractmethod
    def write(self, packet: Union[CmdPacket, bytes]) -> None:
        """Write a packet to the device."""

    @abstractmethod
    def info(self) -> str:
        """Return string containing information about the interface."""


# for backwards compatibility
Interface = MBootInterface
