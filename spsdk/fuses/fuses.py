#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK fuse operations and management utilities.

This module provides comprehensive functionality for reading, writing, and managing
fuses across NXP MCU devices. It includes abstract base classes for fuse operations,
concrete implementations for different tools (blhost, nxpele), and utilities for
fuse scripting and configuration management.
"""

import functools
import logging
from abc import abstractmethod
from typing import Any, Callable, Iterator, Optional, Type

from typing_extensions import Self

from spsdk import version as spsdk_version
from spsdk.exceptions import (
    SPSDKAttributeError,
    SPSDKError,
    SPSDKKeyError,
    SPSDKTypeError,
    SPSDKValueError,
)
from spsdk.fuses.fuse_registers import FuseLock, FuseRegister, FuseRegisters, IndividualWriteLock
from spsdk.mboot.mcuboot import McuBoot
from spsdk.utils.abstract_features import FeatureBaseClassComm
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, get_db, update_validation_schema_family
from spsdk.utils.misc import Endianness, get_abs_path, value_to_int, write_file
from spsdk.utils.schema_validator import check_config

logger = logging.getLogger(__name__)


class SPSDKFuseOperationFailure(SPSDKError):
    """SPSDK Fuse operation failure exception.

    Exception raised when fuse-related operations fail during device provisioning
    or configuration processes. This includes failures in fuse reading, writing,
    verification, or other fuse management operations.
    """


class SPSDKFuseConfigurationError(SPSDKError):
    """SPSDK Fuse configuration error exception.

    This exception is raised when fuse configuration operations fail due to
    invalid parameters, unsupported configurations, or other fuse-related errors.
    """


class FuseOperator:
    """Fuse operator abstract base class for device fuse management operations.

    This abstract class defines the interface for reading, writing, and managing fuses
    across different NXP MCU devices. Concrete implementations provide device-specific
    fuse operation capabilities including script generation and command formatting.

    :cvar NAME: Operator name identifier for registration and lookup.
    """

    NAME: Optional[str] = None

    def __str__(self) -> str:
        """Return string representation of the object.

        This method delegates to __repr__() to provide a string representation
        of the fuse object.

        :return: String representation of the object.
        """
        return self.__repr__()

    def __repr__(self) -> str:
        """Return string representation of the Fuse Operator.

        :return: String containing the operator name with 'Fuse Operator' prefix.
        """
        return f"Fuse Operator {self.NAME}"

    @abstractmethod
    def read_fuse(self, index: int, length: int) -> int:
        """Read a single fuse value from the device.

        :param index: Index of the fuse to read.
        :param length: Length of the fuse in bits.
        :return: The fuse value as an integer.
        """

    @abstractmethod
    def write_fuse(self, index: int, value: int, length: int, lock: bool = False) -> None:
        """Write a single fuse.

        The method writes a value to the specified fuse index with given bit length
        and optionally locks the fuse to prevent further modifications.

        :param index: Index of the fuse to write.
        :param value: Fuse value to be written.
        :param length: Length of fuse in bits.
        :param lock: Lock fuse after write to prevent further modifications.
        """

    @classmethod
    @abstractmethod
    def get_fuse_script(cls, family: FamilyRevision, fuses: list[FuseRegister]) -> str:
        """Get fuse script for specified family and fuse registers.

        Generates a script containing fuse programming commands based on the provided
        family revision and list of fuse registers.

        :param family: Target MCU family and revision information.
        :param fuses: List of fuse registers to include in the script.
        :return: Generated fuse programming script as string.
        """

    @classmethod
    @abstractmethod
    def get_fuse_write_cmd(
        cls, index: int, value: int, lock: bool = False, verify: bool = False
    ) -> str:
        """Get write command for a single fuse.

        :param index: Index of the fuse to write.
        :param value: Value to write to the fuse.
        :param lock: Whether to lock the fuse after writing, defaults to False.
        :param verify: Whether to verify the fuse value after writing, defaults to False.
        :return: Command string for writing the specified fuse.
        """

    @classmethod
    def get_operator_type(cls, name: str) -> Type["FuseOperator"]:
        """Get operator type by its name.

        Searches through all FuseOperator subclasses to find the one matching the specified name.

        :param name: Name of the fuse operator to find.
        :raises SPSDKKeyError: When no fuse operator with the specified name exists.
        :return: The FuseOperator subclass type matching the given name.
        """
        for subclass in FuseOperator.__subclasses__():
            if subclass.NAME == name:
                return subclass
        raise SPSDKKeyError(f"No such a fuse operator with name {name}")


def mboot_operation_decorator(func: Callable) -> Callable:
    """Decorator to handle MCUboot operations with automatic connection management.

    This decorator ensures that the MCUboot interface is properly opened before executing
    the decorated method and closed afterwards, regardless of whether the operation
    succeeds or fails.

    :param func: Function to be decorated that performs MCUboot operations.
    :return: Wrapped function with automatic connection management.
    """

    @functools.wraps(func)
    def wrapper(self: "BlhostFuseOperator", *args: Any, **kwargs: Any) -> Any:
        """Wrapper function to ensure mboot connection is properly managed.

        This decorator-like wrapper ensures that the mboot connection is opened before
        executing the wrapped function and properly closed afterwards, regardless of
        whether the function succeeds or raises an exception.

        :param self: The BlhostFuseOperator or BlhostFuseOperatorLegacy instance.
        :param args: Variable length argument list to pass to the wrapped function.
        :param kwargs: Arbitrary keyword arguments to pass to the wrapped function.
        :return: The return value of the wrapped function.
        """
        assert isinstance(self, (BlhostFuseOperator, BlhostFuseOperatorLegacy))
        if not self.mboot.is_opened:
            self.mboot.open()
        try:
            return func(self, *args, **kwargs)
        finally:
            self.mboot.close()

    return wrapper


class BlhostFuseOperator(FuseOperator):
    """SPSDK Blhost fuse operator for MCU fuse operations.

    This class provides fuse read/write operations using the Blhost protocol
    through McuBoot interface. It handles individual fuse programming,
    reading, and script generation for batch operations.

    :cvar NAME: Operator identifier for blhost protocol.
    """

    NAME = "blhost"

    def __init__(self, mboot: McuBoot):
        """Initialize the Blhost fuse operator.

        Creates a new instance of the fuse operator that uses the provided McuBoot
        interface for communication with the target device.

        :param mboot: McuBoot interface instance for device communication.
        """
        self.mboot = mboot

    @mboot_operation_decorator
    def read_fuse(self, index: int, length: int) -> int:
        """Read a single fuse value from the device.

        This method reads the value of a fuse at the specified index using the mboot interface.
        The length parameter specifies the expected bit length of the fuse data.

        :param index: Index of the fuse to read
        :param length: Length of fuse data in bits
        :raises SPSDKFuseOperationFailure: When the fuse reading operation fails
        :return: The value read from the specified fuse
        """
        ret = self.mboot.efuse_read_once(index)
        if ret is None:
            raise SPSDKFuseOperationFailure("Reading of fuse failed.")
        return ret

    @mboot_operation_decorator
    def write_fuse(self, index: int, value: int, length: int, lock: bool = False) -> None:
        """Write a single fuse to the device.

        The method programs a fuse at the specified index with the given value and
        optionally locks it to prevent further modifications.

        :param index: Index of the fuse to be written.
        :param value: Fuse value to be programmed.
        :param length: Length of fuse in bits.
        :param lock: Lock fuse after write to prevent further modifications.
        :raises SPSDKFuseOperationFailure: Writing of fuse failed.
        """
        if lock:
            index = index | (1 << 24)
        ret = self.mboot.efuse_program_once(index, value)
        if not ret:
            raise SPSDKFuseOperationFailure("Writing of fuse failed.")

    @classmethod
    def get_fuse_script(cls, family: FamilyRevision, fuses: list[FuseRegister]) -> str:
        """Generate BLHOST fuses programming script for given family and fuses.

        Creates a complete script with header information including SPSDK version and chip family,
        followed by individual fuse programming commands with descriptive comments.

        :param family: Target chip family and revision information.
        :param fuses: List of fuse registers to be programmed.
        :raises SPSDKAttributeError: When OTP index is not defined for a fuse register.
        :return: Complete BLHOST script as formatted string with programming commands.
        """
        ret = (
            "# BLHOST fuses programming script\n"
            f"# Generated by SPSDK {spsdk_version}\n"
            f"# Chip: {family}\n\n\n"
        )
        for fuse in fuses:
            if fuse.otp_index is None:
                raise SPSDKAttributeError(f"OTP index is nto defined for fuse {fuse.name}")
            otp_value = f"0x{fuse.get_value(raw=True):08X}"
            ret += f"# Fuse {fuse.name}, index {fuse.otp_index} and value: {otp_value}.\n"
            ret += cls.get_fuse_write_cmd(fuse.otp_index, fuse.get_value(raw=True))
            ret += "\n\n"
        return ret

    @classmethod
    def get_fuse_write_cmd(
        cls, index: int, value: int, lock: bool = False, verify: bool = False
    ) -> str:
        """Get fuse write command for programming eFuses.

        Generates a command string for programming eFuse values with optional verification
        and locking capabilities.

        :param index: eFuse index to program.
        :param value: Value to write to the eFuse.
        :param lock: Lock the eFuse after programming, defaults to False.
        :param verify: Verify the programmed value, defaults to False.
        :return: Formatted eFuse programming command string.
        """
        ret = f"efuse-program-once {index} {f'0x{value:X}'}"
        ret = f"{ret} {'--verify' if verify else '--no-verify'}"
        if lock:
            ret = f"{ret} lock"
        return ret


class BlhostFuseOperatorLegacy(FuseOperator):
    """Legacy Blhost fuse operator for backward compatibility.

    This class provides fuse operations using legacy Blhost commands that differ
    from the standard implementation. It maintains compatibility with older
    systems while providing the same fuse read/write interface.

    :cvar NAME: Operator identifier for legacy Blhost operations.
    """

    NAME = "blhost_legacy"

    def __init__(self, mboot: McuBoot):
        """Initialize the Blhost fuse operator.

        :param mboot: McuBoot instance for communication with the target device.
        """
        self.mboot = mboot

    @mboot_operation_decorator
    def read_fuse(self, index: int, length: int) -> int:
        """Read a single fuse value from the device.

        This method reads a fuse at the specified index with the given bit length
        and returns the fuse value as an integer.

        :param index: Index of the fuse to read
        :param length: Length of fuse in bits
        :return: Fuse value as integer
        :raises SPSDKFuseOperationFailure: When reading of fuse fails
        """
        ret = self.mboot.fuse_read(index, length // 8)
        if ret is None:
            raise SPSDKFuseOperationFailure("Reading of fuse failed.")
        return value_to_int(ret)

    @mboot_operation_decorator
    def write_fuse(self, index: int, value: int, length: int, lock: bool = False) -> None:
        """Write a single fuse.

        This method programs a fuse at the specified index with the given value by setting
        the appropriate voltage, programming the fuse, and resetting the voltage.

        :param index: Index of the fuse to be written.
        :param value: Fuse value to be programmed.
        :param length: Length of fuse in bits (currently not used in implementation).
        :param lock: Lock fuse after write (currently not implemented).
        :raises SPSDKFuseOperationFailure: When the fuse programming operation fails.
        """
        ret = self.mboot.set_property(22, 1)  # Set voltage for fuse programming
        # convert value to bytes
        byte_value = value.to_bytes(4, "little")
        ret |= self.mboot.fuse_program(index, byte_value)
        ret |= self.mboot.set_property(22, 0)  # Reset voltage setting
        if not ret:
            raise SPSDKFuseOperationFailure("Writing of fuse failed.")

    @classmethod
    def get_fuse_script(cls, family: FamilyRevision, fuses: list[FuseRegister]) -> str:
        """Generate BLHOST fuses programming script for given family and fuses.

        Creates a complete BLHOST script that includes voltage setting, fuse programming
        commands, and proper reset sequence for safe fuse programming operations.

        :param family: Target MCU family and revision information.
        :param fuses: List of fuse registers to be programmed with their values.
        :raises SPSDKAttributeError: When OTP index is not defined for a fuse register.
        :return: Complete BLHOST script as string with programming commands.
        """
        ret = (
            "# BLHOST fuses programming script\n"
            f"# Generated by SPSDK {spsdk_version}\n"
            f"# Chip: {family}\n\n\n"
        )
        # Set voltage for programming
        ret += "set-property 22 1\n"

        for fuse in fuses:
            if fuse.otp_index is None:
                raise SPSDKAttributeError(f"OTP index is nto defined for fuse {fuse.name}")
            otp_value = "0x" + fuse.get_bytes_value(raw=True).hex()
            ret += f"# Fuse {fuse.name}, index {fuse.otp_index} and value: {otp_value}.\n"
            ret += cls.get_fuse_write_cmd(fuse.otp_index, fuse.get_value(raw=True))
            ret += "\n\n"

        ret += "# Reset voltage setting\n"
        ret += "set-property 22 0\n"

        return ret

    @classmethod
    def get_fuse_write_cmd(
        cls, index: int, value: int, lock: bool = False, verify: bool = False
    ) -> str:
        """Get fuse write command.

        Generates a command string for programming a fuse with the specified index and value.

        :param index: Fuse index to program.
        :param value: Value to write to the fuse.
        :param lock: Whether to lock the fuse after programming (currently not used in command).
        :param verify: Whether to verify the fuse after programming (currently not used in command).
        :return: Command string for fuse programming.
        """
        ret = f"fuse-program {index} {{{f'0x{value:X}'}}}"
        return ret


class NxpeleFuseOperator(FuseOperator):
    """NXP EdgeLock Enclave (ELE) fuse operator.

    This class provides fuse operations for NXP EdgeLock Enclave devices, enabling
    reading and writing of fuse values through ELE message communication. It handles
    the low-level ELE protocol for secure fuse management operations.

    :cvar NAME: Operator identifier for NXP ELE fuse operations.
    """

    NAME = "nxpele"

    def __init__(self, ele_handler: Any):
        """Initialize NXP ELE fuse operator.

        Creates a new instance of the ELE fuse operator with the provided ELE message handler
        for secure fuse operations.

        :param ele_handler: ELE message handler instance for communication with ELE.
        :raises AssertionError: If ele_handler is not an instance of EleMessageHandler.
        """
        from spsdk.ele.ele_comm import EleMessageHandler

        assert isinstance(ele_handler, EleMessageHandler)
        self.ele_handler = ele_handler

    def read_fuse(self, index: int, length: int) -> int:
        """Read a single fuse value from the device.

        This method uses ELE (EdgeLock Enclave) messaging to read a common fuse value
        from the specified index position.

        :param index: Index of the fuse to read
        :param length: Length of fuse in bits (currently not used in implementation)
        :return: The fuse value as an integer
        """
        from spsdk.ele import ele_message

        read_common_fuse_msg = ele_message.EleMessageReadCommonFuse(index)
        with self.ele_handler:
            self.ele_handler.send_message(read_common_fuse_msg)
        return read_common_fuse_msg.fuse_value

    def write_fuse(self, index: int, value: int, length: int, lock: bool = False) -> None:
        """Write a single fuse.

        This method writes a value to a specific fuse register using the ELE (EdgeLock Enclave)
        messaging system. The fuse can optionally be locked after writing to prevent further
        modifications.

        :param index: Index of the fuse register to write to.
        :param value: Fuse value to be written to the register.
        :param length: Length of fuse in bits (currently unused, fixed at 32 bits).
        :param lock: Lock fuse after write to prevent further modifications.
        """
        from spsdk.ele import ele_message

        bit_position = index * 32
        bit_length = 32

        ele_fw_write_fuse_msg = ele_message.EleMessageWriteFuse(
            bit_position, bit_length, lock, value
        )
        with self.ele_handler:
            self.ele_handler.send_message(ele_fw_write_fuse_msg)

    @classmethod
    def get_fuse_script(cls, family: FamilyRevision, fuses: list[FuseRegister]) -> str:
        """Generate fuse programming script for specified family and fuse registers.

        Creates a complete NXPELE fuses programming script with header information
        and individual fuse write commands for each provided fuse register.

        :param family: Target chip family and revision information.
        :param fuses: List of fuse registers to include in the programming script.
        :raises SPSDKAttributeError: When OTP index is not defined for any fuse register.
        :return: Complete fuse programming script as formatted string.
        """
        ret = (
            "# NXPELE fuses programming script\n"
            f"# Generated by SPSDK {spsdk_version}\n"
            f"# Chip: {family}\n\n\n"
        )
        for fuse in fuses:
            if fuse.otp_index is None:
                raise SPSDKAttributeError(f"OTP index is not defined for fuse {fuse.name}")
            otp_value = "0x" + fuse.get_bytes_value(raw=True).hex()
            ret += f"# Fuse {fuse.name}, index {fuse.otp_index} and value: {otp_value}.\n"
            ret += cls.get_fuse_write_cmd(fuse.otp_index, fuse.get_value(raw=True))
            ret += "\n\n"
        return ret

    @classmethod
    def get_fuse_write_cmd(
        cls, index: int, value: int, lock: bool = False, verify: bool = False
    ) -> str:
        """Get write command for a single fuse.

        Generates a command string for writing a value to a specific fuse index with optional
        locking. The verify parameter is not applicable for nxpele command.

        :param index: Index of the fuse to write to.
        :param value: Value to write to the fuse.
        :param lock: Whether to lock the fuse after writing, defaults to False.
        :param verify: Verification flag (not applicable for nxpele command), defaults to False.
        :return: Command string for writing the fuse.
        """
        ret = f"write-fuse --index {index} --data {f'0x{value:X}'}"
        if lock:
            ret = f"{ret} --lock"
        return ret


class Fuses(FeatureBaseClassComm):
    """SPSDK Fuses Manager.

    This class provides a comprehensive interface for managing and manipulating
    fuse operations across NXP MCU families. It handles fuse register initialization,
    configuration loading, and communication with physical fuse hardware through
    configurable operators.

    :cvar FEATURE: Database feature identifier for fuses functionality.
    """

    FEATURE = DatabaseManager.FUSES

    def __init__(
        self,
        family: FamilyRevision,
        fuse_operator: Optional[FuseOperator] = None,
    ):
        """Initialize Fuses class to control fuse operations.

        The Fuses class provides functionality to manage and manipulate fuse registers
        for NXP MCU devices, including reading, writing, and configuring fuse values.

        :param family: Target MCU family and revision information for fuse operations.
        :param fuse_operator: Optional operator for performing actual fuse operations,
            defaults to None.
        :raises SPSDKError: When the specified family has no fuses definition available.
        """
        self.family = family
        self.db = get_db(family)
        if DatabaseManager.FUSES not in self.db.features:
            raise SPSDKError(f"The {self.family} has no fuses definition")
        self._operator = fuse_operator
        self.fuse_regs = self.get_init_regs(family)
        # keep the context based on the latest operation: load_from_config/read_all etc.
        self.fuse_context: list[FuseRegister] = []

    def __repr__(self) -> str:
        """Get string representation of the Fuses class.

        :return: String representation containing the family name.
        """
        return f"Fuses class for {self.family}."

    def __str__(self) -> str:
        """Get string representation of the fuses class.

        The method provides a detailed string representation that includes both the
        basic object information and the string representation of the fuse registers.

        :return: String representation containing object info and fuse registers details.
        """
        ret = self.__repr__()
        ret += "\n" + str(self.fuse_regs)
        return ret

    def __iter__(self) -> Iterator[FuseRegister]:
        """Make the fuse registers iterable.

        Allows iteration over all fuse registers in the collection using standard
        Python iteration protocols.

        :return: Iterator over FuseRegister objects.
        """
        return iter(self.fuse_regs)

    @property
    def fuse_operator(self) -> FuseOperator:
        """Get fuse operator instance.

        Property to access the fuse operator for performing fuse operations on the device.

        :raises SPSDKError: Fuse operator is not defined.
        :return: The fuse operator instance.
        """
        if self._operator is None:
            raise SPSDKError("Fuse operator is not defined.")
        return self._operator

    @fuse_operator.setter
    def fuse_operator(self, value: FuseOperator) -> None:
        """Set the fuse operator for this fuse.

        Validates that the provided operator is of the correct type before assignment.

        :param value: The fuse operator to set.
        :raises SPSDKTypeError: If the operator type doesn't match the expected fuse operator type.
        """
        if not isinstance(value, self.fuse_operator_type):
            raise SPSDKTypeError(
                f"Invalid fuse operator type: {type(value).__name__}. expected: {self.fuse_operator_type.__name__}"
            )

        self._operator = value

    @property
    def fuse_operator_type(self) -> Type[FuseOperator]:
        """Get fuse operator type for the current family.

        Returns the appropriate FuseOperator class type that corresponds to the
        device family configured for this instance.

        :return: FuseOperator class type for the configured family.
        """
        return self.get_fuse_operator_type(self.family)

    @classmethod
    def get_fuse_operator_type(cls, family: FamilyRevision) -> Type[FuseOperator]:
        """Get operator type based on family.

        Retrieves the appropriate FuseOperator type for the specified MCU family
        by querying the database configuration.

        :param family: MCU family and revision specification.
        :return: FuseOperator class type for the specified family.
        :raises SPSDKError: If family is not supported or database query fails.
        """
        return FuseOperator.get_operator_type(get_db(family).get_str(DatabaseManager.FUSES, "tool"))

    @classmethod
    def get_init_regs(cls, family: FamilyRevision) -> FuseRegisters:
        """Get initialized fuse registers.

        Creates and returns a new FuseRegisters instance for the specified family revision.

        :param family: The family revision to initialize the fuse registers for.
        :return: Initialized fuse registers instance for the given family.
        """
        return FuseRegisters(family=family)

    def load_config(self, config: dict[str, Any]) -> None:
        """Load the fuses configuration from dictionary.

        The method validates the configuration against schema, loads register values,
        and sets up the fuse context with the configured registers.

        :param config: Dictionary containing fuses configuration with registers section.
        :raises SPSDKError: Invalid configuration format or validation failure.
        """
        sch_full = self.get_validation_schemas(self.family)
        check_config(config, sch_full)
        self.fuse_regs.load_from_config(config["registers"])
        # set the fuse context to currently loaded registers
        self.fuse_context = [
            self.fuse_regs.find_reg(reg_name, include_group_regs=True)
            for reg_name in config["registers"].keys()
        ]

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Create fuses object from given configuration.

        This class method instantiates a new fuses object using the provided configuration
        data, including family revision information and fuse-specific settings.

        :param config: The configuration object containing fuses settings and family revision data.
        :return: New fuses object configured according to the provided configuration.
        """
        fuses = cls(FamilyRevision.load_from_config(config))
        fuses.load_config(config)
        return fuses

    def read_all(self) -> None:
        """Read all fuses from connected device.

        Attempts to read every fuse register from the connected device and updates the fuse context
        with successfully read registers. Failed reads are logged as warnings but do not stop the
        operation.

        :raises SPSDKFuseOperationFailure: When individual fuse read operations fail (logged as
            warnings, does not interrupt the overall operation).
        """
        ctx = []
        for reg in self.fuse_regs:
            try:
                self.read_single(reg.uid)
                ctx.append(reg)
            except SPSDKFuseOperationFailure as e:
                logger.warning(f"Unable to read the fuse {reg.name}: {str(e)}")
        self.fuse_context = ctx

    def read_single(self, name: str, check_locks: bool = True) -> int:
        """Read single fuse from device.

        Reads the value of a specified fuse register from the device, with optional
        lock checking to ensure the fuse is readable before attempting the operation.

        :param name: Fuse name or uid to read from device.
        :param check_locks: Check value of lock fuse before reading to prevent
            locked fuse access.
        :raises SPSDKFuseOperationFailure: When fuse is not readable or read
            operation is locked.
        :raises SPSDKFuseConfigurationError: When OTP index is not defined for
            the fuse.
        :return: Value read from the fuse register.
        """
        reg = self.fuse_regs.find_reg(name, include_group_regs=True)
        if not reg.access.is_readable:
            raise SPSDKFuseOperationFailure(
                f"Unable to read fuse {name}. Fuse access: {reg.access.description}"
            )
        lock_fuse = self.fuse_regs.get_lock_fuse(reg)
        if lock_fuse and check_locks:
            logger.debug("Reading the value of lock register first.")
            # if the fuse locks itself, do not read it
            self.read_single(lock_fuse.uid, check_locks=lock_fuse != reg)
            if FuseLock.READ_LOCK in reg.get_active_locks():
                raise SPSDKFuseOperationFailure(
                    f"Fuse {reg.name} read operation is locked by lock fuse {lock_fuse.name}."
                )

        if reg.has_group_registers():
            for sub_reg in reg.sub_regs:
                self.read_single(sub_reg.uid)
            self.fuse_context = [reg]
            return reg.get_value()

        if reg.otp_index is None:
            raise SPSDKFuseConfigurationError("OTP index is not defined")
        value = self.fuse_operator.read_fuse(reg.otp_index, reg.width)
        reg.set_value(value)
        self.fuse_regs.update_locks()
        self.fuse_context = [reg]
        return value

    def write_multiple(self, names: list[str]) -> None:
        """Write multiple fuses to the device.

        This method iterates through the provided list of fuse names or UIDs,
        finds the corresponding registers, and writes each one individually to the device.

        :param names: List of fuse names or UIDs to be written to the device.
        :raises SPSDKError: If any fuse name/UID is not found or write operation fails.
        """
        for name in names:
            reg = self.fuse_regs.find_reg(name, include_group_regs=True)
            self.write_single(reg.uid)

    def write_single(self, name: str, lock: bool = False) -> None:
        """Write single fuse to the device.

        The method handles both individual fuses and group registers. It performs
        lock checks, validates write permissions, and manages individual write lock
        behavior according to fuse configuration.

        :param name: Fuse name or uid to write.
        :param lock: Set lock after write operation.
        :raises SPSDKError: OTP index for fuse is not set.
        :raises SPSDKFuseOperationFailure: Fuse is not writable, write-locked, or has
                                           non-reset value with write lock.
        """

        def write_single_reg(reg: FuseRegister, lock: bool = False) -> None:
            """Write a single fuse register to the device.

            This method writes the value of a fuse register to the OTP memory with comprehensive
            validation including access rights, lock status checks, and individual write lock
            handling. The method automatically manages lock states and validates write permissions
            before performing the operation.

            :param reg: The fuse register to write to the device.
            :param lock: Whether to lock the fuse after writing, defaults to False.
            :raises SPSDKError: If the OTP index for the fuse is not set.
            :raises SPSDKFuseOperationFailure: If the fuse is not writable, write-locked by another
                fuse, or has non-reset value with write-lock restrictions.
            """
            if reg.otp_index is None:
                raise SPSDKError(f"OTP index for fuse {reg.name} is not set.")
            if not reg.access.is_writable:
                raise SPSDKFuseOperationFailure(
                    f"Unable to write fuse {name}. Fuse access: {reg.access.description}"
                )
            lock_reg = self.fuse_regs.get_lock_fuse(reg)
            if lock_reg:
                logger.debug("Reading the value of lock register first.")
                # if the fuse locks itself, do not check locks when reading
                self.read_single(lock_reg.uid, check_locks=lock_reg != reg)
                if FuseLock.WRITE_LOCK in reg.get_active_locks():
                    raise SPSDKFuseOperationFailure(
                        f"Fuse {reg.name} write operation is locked by lock fuse {lock_reg.name}."
                    )
            if reg.individual_write_lock in [
                IndividualWriteLock.ALWAYS,
                IndividualWriteLock.IMPLICIT,
            ]:
                reset = reg.get_reset_value()
                if self.read_single(reg.uid) != reset:
                    raise SPSDKFuseOperationFailure(
                        f"Fuse {reg.name} has non reset value {reset} and is write-locked."
                    )

            if lock and reg.individual_write_lock == IndividualWriteLock.IMPLICIT:
                logger.warning(
                    "The user's lock is ignored as the fuse will be implicitly locked after write"
                )
                lock = False
            if not lock and reg.individual_write_lock == IndividualWriteLock.ALWAYS:
                logger.info(
                    "Enabling the lock flag as the fuse has individual write lock set to 'always'"
                )
                lock = True
            self.fuse_operator.write_fuse(reg.otp_index, reg.get_value(), reg.width, lock)
            # lock the local register so it matches the real state in chip
            if lock or reg.individual_write_lock == IndividualWriteLock.IMPLICIT:
                reg.lock(FuseLock.WRITE_LOCK)

        reg = self.fuse_regs.find_reg(name, include_group_regs=True)
        if reg.has_group_registers():
            for sub_reg in reg.sub_regs:
                write_single_reg(sub_reg, lock)
        else:
            write_single_reg(reg, lock)

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Create the validation schema for fuses configuration.

        The method builds validation schemas by combining basic family schemas with
        fuse-specific configuration schemas. It updates the family properties and
        integrates register validation schemas from initialization registers.

        :param family: Family description containing MCU family and revision information.
        :return: List of validation schemas for fuses configuration.
        """
        sch_family: list[dict] = cls.get_validation_schemas_basic()
        update_validation_schema_family(
            sch_family[0]["properties"], cls.get_supported_families(), family
        )
        sch_cfg = get_schema_file(DatabaseManager.FUSES)
        init_regs = cls.get_init_regs(family)
        sch_cfg["fuses"]["properties"]["registers"][
            "properties"
        ] = init_regs.get_validation_schema()["properties"]
        return sch_family + [sch_cfg["fuses"]]

    def create_fuse_script(self) -> str:
        """Generate fuse programming script for blhost or nxpele tools.

        This method processes all fuse registers in the context, handling both simple registers
        and group registers with sub-registers. For group registers, it processes sub-registers
        in the appropriate order based on the reverse_subregs_order flag.

        :return: Content of the fuse programming script file as a string.
        """
        fuse_regs = []
        for reg in self.fuse_context:
            if reg.has_group_registers():
                for sub_reg in reg.sub_regs[:: -1 if reg.reverse_subregs_order else 1]:
                    fuse_regs.append(sub_reg)
            else:
                fuse_regs.append(reg)
        return self.fuse_operator_type.get_fuse_script(family=self.family, fuses=fuse_regs)

    def get_config(self, data_path: str = "./", diff: bool = False) -> Config:
        """Create fuse configuration object.

        Generates a configuration object containing family information, revision details,
        and register settings that can be used for fuse programming or analysis.

        :param data_path: Path to store the data files of configuration.
        :param diff: If set, only changed registers will be placed in configuration.
        :return: Configuration object with family, revision and register data.
        """
        ret = Config()
        ret["family"] = self.family.name
        ret["revision"] = self.family.revision
        ret["registers"] = self.fuse_regs.get_config(diff=diff)
        logger.debug("The fuse configuration was created.")
        return ret


class FuseScript:
    """SPSDK Fuse Script Generator.

    This class generates programming scripts for writing fuses to NXP MCU devices.
    It manages fuse configuration data, validates settings against device databases,
    and produces executable scripts compatible with various programming tools like blhost.
    """

    def __init__(
        self,
        family: FamilyRevision,
        feature: str,
        index: Optional[int] = None,
        fuses_key: str = "fuses",
    ):
        """Initialize FuseScript object.

        Creates a new FuseScript instance for managing fuse operations on a specific device family
        and feature configuration.

        :param family: Device family and revision information.
        :param feature: Feature name to configure fuses for.
        :param index: Optional index to append to fuses key for multiple configurations.
        :param fuses_key: Base key name for fuses configuration in database.
        :raises SPSDKError: When the specified family has no fuses definition.
        """
        self.feature = feature
        self.family = family

        self.db = get_db(family)

        if DatabaseManager.FUSES not in self.db.features:
            raise SPSDKError(f"The {self.family} has no fuses definition")

        self.fuses = FuseRegisters(
            family=family,
            base_endianness=Endianness.LITTLE,
        )

        self.operator = FuseOperator.get_operator_type(
            self.db.get_str(DatabaseManager.FUSES, "tool", "blhost")
        )

        if index is not None:
            # if index is present append it to the fuses key,
            # like fuses_0, fuses_1, etc.
            fuses_key += f"_{index}"

        self.fuses_db = self.db.get_dict(feature, fuses_key)

        # No verify flag means that fuse won't be verified after write
        # It is needed for read protected OTP (blhost --no-verify)
        self.no_verify = self.fuses_db.get("_no_verify", False)
        self.name = self.fuses_db.get("_name", "Fuse Script")

    def generate_file_header(self) -> str:
        """Generate file header for fuses programming script.

        Creates a formatted header containing operator name, fuse name, SPSDK version,
        and target family information for use in generated programming scripts.

        :return: Formatted header string with script metadata.
        """
        return (
            f"# {self.operator.NAME} {self.name} fuses programming script\n"
            f"# Generated by SPSDK {spsdk_version}\n"
            f"# Family: {self.family}"
        )

    @staticmethod
    def get_object_value(value: str, attributes_object: object) -> Any:
        """Get object value from attributes object by attribute name.

        Retrieves the value of an attribute from the given object. The method handles
        attribute names that start with double underscores by removing the prefix
        before attempting to access the attribute.

        :param value: Name of the attribute to retrieve, may start with "__" prefix.
        :param attributes_object: Object from which to retrieve the attribute value.
        :raises SPSDKValueError: When the object does not contain the specified attribute.
        :return: Value of the requested attribute from the object.
        """
        if value.startswith("__"):
            value = value[2:]
            if hasattr(attributes_object, value):
                return getattr(attributes_object, value)
        raise SPSDKValueError(f"Fuses: Object does not contain {value}")

    def generate_script(self, attributes_object: object, info_only: bool = False) -> str:
        """Generate script for writing fuses.

        This method generates a script for writing fuses based on the provided attributes object.
        The script includes the file header and the commands for setting the fuse values.
        Special attributes:
        - __str_value: Value with double underscore represents attribute of the object.

        :param attributes_object: An object containing the attributes used to set the fuse values.
        :param info_only: If True, only the information about the fuses is generated, defaults
            to False.
        :raises SPSDKError: OTP index is not defined for register.
        :return: The generated script for writing fuses or info string if info_only is True.
        """
        script = self.generate_file_header() + "\n"
        info = ""

        for key, value in self.fuses_db.items():
            extra_info = ""
            if key.startswith("_"):  # Skip private attributes
                continue
            reg = self.fuses.get_reg(key)
            if isinstance(value, (int, bool)):  # RAW int value or boolean
                reg.set_value(value_to_int(value), raw=True)

            elif isinstance(value, dict):  # value contains bitfields
                for sub_key, sub_value in value.items():
                    bitfield = reg.get_bitfield(sub_key)
                    if isinstance(sub_value, (int, bool)):
                        bitfield.set_value(value_to_int(sub_value), raw=True)
                    elif isinstance(sub_value, str):
                        sub_value = self.get_object_value(sub_value, attributes_object)
                        if sub_value:
                            bitfield.set_value(sub_value)

                    extra_info += (
                        f"# Bitfield: {bitfield.name}"
                        + f", Description: {bitfield.description}"
                        + f", Value: {bitfield.get_hex_value()}\n"
                    )
            elif isinstance(value, str):  # Value from object
                value = self.get_object_value(value, attributes_object)
                if value:
                    reg.set_value(value)

            script += f"\n# Value: 0x{reg.get_value():08X}\n"
            script += f"# Description: {reg.description}\n"
            script += extra_info
            if extra_info:
                script += "# WARNING! Partially set register, check all bitfields before writing\n"
            if reg.sub_regs:
                script += f"# Grouped register name: {reg.name}\n\n"
                info += f"\n --== Grouped register name: {reg.name} ==-- \n"
                for reg in reg.sub_regs:
                    script += f"# OTP ID: {reg.name}, Value: 0x{reg.get_value():08X}\n"
                    if reg.otp_index is None:
                        raise SPSDKError(f"OTP index is not defined for {reg.name}")
                    script += (
                        self.operator.get_fuse_write_cmd(
                            reg.otp_index, reg.get_value(raw=True), verify=not self.no_verify
                        )
                        + "\n"
                    )
                    info += f"OTP ID: {reg.otp_index}, Value: 0x{reg.get_value(raw=True):08X}\n"
            else:
                script += f"# OTP ID: {reg.name}\n\n"
                if reg.otp_index is None:
                    raise SPSDKError(f"OTP index is not defined for {reg.name}")
                script += (
                    self.operator.get_fuse_write_cmd(
                        reg.otp_index, reg.get_value(raw=True), verify=not self.no_verify
                    )
                    + "\n"
                )
                info += f"OTP ID: {reg.otp_index}, Value: {reg.get_value(raw=True):08X}\n"

        if info_only:
            return info
        return script

    def write_script(
        self, filename: str, output_dir: str, attributes_object: Any, overwrite: bool = True
    ) -> str:
        """Write script to file.

        Generates a script using the provided attributes object and writes it to a file
        with the operator name appended to the filename.

        :param filename: Base name for the output script file (without extension).
        :param output_dir: Directory where the script file will be written.
        :param attributes_object: Object containing attributes used for script generation.
        :param overwrite: Whether to overwrite existing file if it exists.
        :return: The absolute path to the generated script file.
        """
        script_content = self.generate_script(attributes_object)
        output = get_abs_path(f"{filename}_{self.operator.NAME}.bcf", output_dir)
        write_file(script_content, output, overwrite=overwrite)
        return output
