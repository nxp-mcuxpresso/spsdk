#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK strict register management utilities.

This module provides enhanced register handling with strict validation and
type checking. It extends the base register functionality with additional
safety measures and validation rules for secure provisioning operations.
"""

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
    """Register class with strict validation of bitfield values against allowed enumerations.

    This class extends the base Register functionality by adding strict validation
    to ensure that all bitfield values are set only to their predefined allowed
    values. When setting register values, it validates that each bitfield with
    defined enumerations contains only values that match the allowed enumeration
    values, providing enhanced data integrity and error detection.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the StrictRegister class.

        :param args: Variable length argument list passed to parent class.
        :param kwargs: Arbitrary keyword arguments passed to parent class.
        """
        super().__init__(*args, **kwargs)

    def set_value(self, val: Any, raw: bool = False) -> None:
        """Set the new value of register with strict validation of bitfields.

        This method sets a new value to the register and validates that all bitfields
        contain values that are within their allowed ranges when not in raw mode.

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

        This method checks if the current value of a bitfield matches one of the
        enumerated allowed values. If no enums are defined for the bitfield,
        validation is skipped.

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
    """Strict register bitfield with enhanced value validation.

    This class extends RegsBitField to provide strict validation of values against
    predefined allowed values. It ensures that only valid enum values can be set,
    preventing invalid configurations in register operations.
    """

    def set_value(self, new_val: Any, raw: bool = False, no_preprocess: bool = False) -> None:
        """Updates the value of the bitfield with strict validation.

        This method extends the parent set_value functionality by adding validation
        against enumerated values when available. In non-raw mode, it ensures the
        final value matches one of the defined enum values.

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
        """Set enum value for bitfield with strict validation.

        Updates the value of the bitfield by its enum value. In strict mode, validates that
        the value is in the list of allowed enum values. Supports RAW: prefix for bypassing
        validation.

        :param new_val: New enum value of bitfield (string name or integer value).
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
    """SPSDK Registers container with strict validation enforcement.

    This class extends the standard Registers functionality by enforcing strict
    validation of bitfield values against their defined enumeration values during
    parsing operations. It automatically converts all bitfields to strict variants
    that validate values against allowed enumerations.

    :cvar register_class: Class used for creating register instances.
    """

    register_class = StrictRegister

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the StrictRegisters class.

        This constructor creates a StrictRegisters instance by calling the parent constructor
        and then replacing all RegsBitField instances with StrictRegsBitField instances to
        enforce strict validation. All properties and enums from original bitfields are
        preserved during the conversion.

        :param args: Variable length argument list passed to parent constructor.
        :param kwargs: Arbitrary keyword arguments passed to parent constructor.
        """
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
        """Parse binary data into registers with strict validation.

        This method first parses the binary data using the parent class method,
        then validates all bitfield values against their allowed enumeration values.

        :param binary: Binary data to parse into registers.
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
