#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for functionality shared across all interfaces."""

from abc import ABC, abstractmethod
from typing import Any, Optional


class SDPInterface(ABC):
    """Base class for all Interface classes."""

    expect_status = True

    @property
    def is_opened(self) -> bool:
        """Indicates whether interface is open."""
        return False

    @abstractmethod
    def open(self) -> None:
        """Open the interface."""

    @abstractmethod
    def close(self) -> None:
        """Close the interface."""

    @abstractmethod
    def read(self, length: Optional[int] = None) -> Any:
        """Read data from the device."""

    @abstractmethod
    def write(self, packet: Any) -> None:
        """Write a packet to the device."""

    @abstractmethod
    def conf(self, config: dict) -> None:
        """Configure device."""

    @abstractmethod
    def info(self) -> str:
        """Return string containing information about the interface."""


# for backwards compatibility
Interface = SDPInterface
