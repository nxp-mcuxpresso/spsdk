#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for functionality shared accross all interfaces."""

from abc import ABC
from typing import Any


class Interface(ABC):
    """Base class for all Interface classes."""

    expect_status = True

    @property
    def is_opened(self) -> bool:
        """Indicates whether interface is open."""

    def open(self) -> None:
        """Open the interface."""

    def close(self) -> None:
        """Close the interface."""

    def read(self, length: int = None) -> Any:
        """Read data from the device."""

    def write(self, packet: Any) -> None:
        """Write a packet to the device."""

    def conf(self, config: dict) -> None:
        """Configure device."""

    def info(self) -> str:
        """Return string containing information about the interface."""
