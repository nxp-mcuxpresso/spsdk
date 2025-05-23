#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Generic commands implementation."""
from abc import ABC, abstractmethod


class CmdResponseBase(ABC):
    """Response base format class."""

    @abstractmethod
    def __str__(self) -> str:
        """Get object info."""

    @property
    @abstractmethod
    def value(self) -> int:
        """Return a integer representation of the response."""


class CmdPacketBase(ABC):
    """COmmand protocol base."""

    @abstractmethod
    def export(self, padding: bool = True) -> bytes:
        """Export CmdPacket into bytes.

        :param padding: If True, add padding to specific size
        :return: Exported object into bytes
        """
