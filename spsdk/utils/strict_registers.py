#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module to handle strict registers."""

from typing import Any, Union

from spsdk.utils.misc import value_to_int
from spsdk.utils.registers import (
    Register,
    Registers,
    RegsBitField,
    SPSDKRegsErrorEnumNotFound,
    SPSDKValueError,
)


class StrictRegister(Register):
    """Register class that strictly validates bitfield values against allowed values."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the StrictRegister class."""
        super().__init__(*args, **kwargs)

    def set_value(self, val: Any, raw: bool = False) -> None:
        """Set the new value of register with strict validation of bitfields.

        :param val: The new value to set.
        :param raw: Do not use any modification hooks.
        :raises SPSDKValueError: When invalid values is loaded into register or bitfield value is not in allowed values.
        """
        # First set the value using the parent method
        super().set_value(val, raw)

        # If not raw mode, validate all bitfields have allowed values
        if not raw and self._bitfields:
            for bitfield in self._bitfields:
                self._validate_bitfield_value(bitfield)

    def _validate_bitfield_value(self, bitfield: RegsBitField) -> None:
        """Validate that the bitfield value is in the allowed values.

        :param bitfield: The bitfield to validate.
        :raises SPSDKValueError: When bitfield value is not in allowed values.
        """
        # Skip validation if no enums are defined
        if not bitfield.has_enums():
            return

        current_value = bitfield.get_value()
        allowed_values = [enum.get_value_int() for enum in bitfield.get_enums()]

        # If the current value is not in allowed values, raise an error
        if current_value not in allowed_values:
            enum_names = [f"{enum.name} ({enum.get_value_int()})" for enum in bitfield.get_enums()]
            allowed_values_str = ", ".join(enum_names)
            raise SPSDKValueError(
                f"Invalid value {current_value} for bitfield '{bitfield.name}'. "
                f"Allowed values are: {allowed_values_str}"
            )


class StrictRegsBitField(RegsBitField):
    """Bitfield class that strictly validates values against allowed values."""

    def set_value(self, new_val: Any, raw: bool = False, no_preprocess: bool = False) -> None:
        """Updates the value of the bitfield with strict validation.

        :param new_val: New value of bitfield.
        :param raw: If set, no automatic modification of value is applied.
        :param no_preprocess: If set, no pre-processing of value is applied.
        :raises SPSDKValueError: The input value is out of range or not in allowed values.
        """
        # First set the value using the parent method
        super().set_value(new_val, raw, no_preprocess)

        # If not raw mode and has enums, validate the value is in allowed values
        if not raw and self.has_enums():
            current_value = self.get_value()
            allowed_values = [enum.get_value_int() for enum in self.get_enums()]

            if current_value not in allowed_values:
                enum_names = [f"{enum.name} ({enum.get_value_int()})" for enum in self.get_enums()]
                allowed_values_str = ", ".join(enum_names)
                raise SPSDKValueError(
                    f"Invalid value {current_value} for bitfield '{self.name}'. "
                    f"Allowed values are: {allowed_values_str}"
                )

    def set_enum_value(self, new_val: Union[str, int], raw: bool = False) -> None:
        """Updates the value of the bitfield by its enum value with strict validation.

        :param new_val: New enum value of bitfield.
        :param raw: If set, no automatic modification of value is applied.
        :raises SPSDKRegsErrorEnumNotFound: Input value cannot be decoded.
        :raises SPSDKValueError: The input value is not in allowed values.
        """
        # Handle the special RAW: prefix case
        no_preprocess = False
        if isinstance(new_val, str) and new_val.startswith("RAW:"):
            new_val = new_val[4:]
            no_preprocess = True
            raw = True

        # Try to get the enum constant or convert to int
        try:
            val_int = self.get_enum_constant(new_val)
        except SPSDKRegsErrorEnumNotFound:
            try:
                val_int = value_to_int(new_val)
            except TypeError as exc:
                raise SPSDKRegsErrorEnumNotFound from exc

        # If raw mode, set the value directly
        if raw:
            self.set_value(val_int, raw, no_preprocess)
            return

        # In strict mode, validate the value is in allowed values
        allowed_values = [enum.get_value_int() for enum in self.get_enums()]
        if val_int not in allowed_values:
            enum_names = [f"{enum.name} ({enum.get_value_int()})" for enum in self.get_enums()]
            allowed_values_str = ", ".join(enum_names)
            raise SPSDKValueError(
                f"Invalid value {val_int} for bitfield '{self.name}'. "
                f"Allowed values are: {allowed_values_str}"
            )

        # Set the validated value
        self.set_value(val_int, raw, no_preprocess)


class StrictRegisters(Registers):
    """SPSDK class for registers handling with strict validation."""

    register_class = StrictRegister

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the StrictRegisters class."""
        super().__init__(*args, **kwargs)

        # Replace all RegsBitField instances with StrictRegsBitField
        for register in self._registers:
            for i, bitfield in enumerate(register._bitfields):
                # Create a new StrictRegsBitField with the same properties
                strict_bitfield = StrictRegsBitField(
                    parent=register,
                    name=bitfield.name,
                    offset=bitfield.offset,
                    width=bitfield.width,
                    uid=bitfield.uid,
                    description=bitfield.description,
                    access=bitfield.access,
                    reserved=bitfield.reserved,
                    config_processor=bitfield.config_processor,
                    no_yaml_comments=bitfield.no_yaml_comments,
                )

                # Copy enums
                for enum in bitfield.get_enums():
                    strict_bitfield.add_enum(enum)

                # Replace the original bitfield
                register._bitfields[i] = strict_bitfield

    def parse(self, binary: bytes) -> None:
        """Parse the binary data values into loaded registers with validation.

        :param binary: Binary data to parse.
        :raises SPSDKValueError: When a bitfield value is not in allowed values.
        """
        # First parse using the parent method
        super().parse(binary)

        # Then validate all bitfields in all registers
        for register in self._registers:
            if register._bitfields:
                for bitfield in register._bitfields:
                    if bitfield.has_enums():
                        current_value = bitfield.get_value()
                        allowed_values = [enum.get_value_int() for enum in bitfield.get_enums()]

                        if current_value not in allowed_values:
                            enum_names = [
                                f"{enum.name} ({enum.get_value_int()})"
                                for enum in bitfield.get_enums()
                            ]
                            allowed_values_str = ", ".join(enum_names)
                            raise SPSDKValueError(
                                f"Invalid value {current_value} for bitfield '{bitfield.name}'"
                                f" in register '{register.name}'. "
                                f"Allowed values are: {allowed_values_str}"
                            )
