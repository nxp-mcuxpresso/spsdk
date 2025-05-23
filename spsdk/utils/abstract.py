#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for base abstract classes."""

from abc import ABC, abstractmethod
from typing import Any

from typing_extensions import Self


########################################################################################################################
# Abstract Class for Data Classes
########################################################################################################################
class RawBaseClass(ABC):
    """SPSDK raw abstract class for general Classes."""

    def __eq__(self, obj: Any) -> bool:
        """Check object equality."""
        return isinstance(obj, self.__class__) and vars(obj) == vars(self)

    def __ne__(self, obj: Any) -> bool:
        return not self.__eq__(obj)

    @abstractmethod
    def __repr__(self) -> str:
        """Object representation in string format."""

    @abstractmethod
    def __str__(self) -> str:
        """Object description in string format."""


class BaseClass(RawBaseClass):
    """SPSDK abstract class for Data Classes."""

    @abstractmethod
    def export(self) -> bytes:
        """Export object into bytes array."""

    @classmethod
    @abstractmethod
    def parse(cls, data: bytes) -> Self:
        """Parse object from bytes array."""

    def post_export(self, output_path: str) -> list[str]:
        """Post export method.

        :param output_path: Path to store the data files of configuration.
        :return: List of created file paths.
        """
        return []
