#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright (c) 2019-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for functionality shared across all MBoot interfaces."""

from abc import ABC
from typing import Any, Union

from spsdk.mboot.commands import CmdResponse


class Interface(ABC):
    """Base class for all Mboot Interface classes."""

    @property
    def is_opened(self) -> bool:
        """Indicates whether interface is open."""

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

    def open(self) -> None:
        """Open the interface."""

    def close(self) -> None:
        """Close the interface."""

    def read(self) -> Union[CmdResponse, bytes]:
        """Read data from the device."""

    def write(self, packet: Any) -> None:
        """Write a packet to the device."""

    def info(self) -> str:
        """Return string containing information about the interface."""
