#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2026 NXP
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
from typing import Any, Callable, Iterator, Optional, Type, Union

from typing_extensions import Self

from spsdk import version as spsdk_version
from spsdk.dat.debug_mailbox import DebugMailbox
from spsdk.dat.dm_commands import StartDebugSession
from spsdk.debuggers.debug_probe import DebugProbe, SPSDKDebugProbeError
from spsdk.exceptions import (
    SPSDKAttributeError,
    SPSDKError,
    SPSDKKeyError,
    SPSDKTypeError,
    SPSDKValueError,
    SPSDKVerificationError,
)
from spsdk.fuses.fuse_registers import FuseLock, FuseRegister, FuseRegisters, IndividualWriteLock
from spsdk.mboot.mcuboot import McuBoot
from spsdk.utils.abstract_features import FeatureBaseClassComm
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.exceptions import SPSDKRegsError
from spsdk.utils.family import FamilyRevision, get_db, update_validation_schema_family
from spsdk.utils.misc import Endianness, get_abs_path, value_to_int, write_file

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


class SPSDKRegsInvalidAttribute(SPSDKRegsError):
    """Invalid attribute error for register operations.

    Exception raised when attempting to access or use an invalid or undefined
    attribute on a register object, such as missing shadow register addresses,
    undefined OTP indices, or other required register properties.
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
    def write_fuse(
        self, index: int, value: int, length: int, lock: bool = False, verify: bool = True
    ) -> None:
        """Write a single fuse.

        The method writes a value to the specified fuse index with given bit length
        and optionally locks the fuse to prevent further modifications.

        :param index: Index of the fuse to write.
        :param value: Fuse value to be written.
        :param length: Length of fuse in bits.
        :param lock: Lock fuse after write to prevent further modifications.
        :param verify: Verify the fuse value after writing, defaults to True.
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
    def write_fuse(
        self, index: int, value: int, length: int, lock: bool = False, verify: bool = True
    ) -> None:
        """Write a single fuse to the device.

        The method programs a fuse at the specified index with the given value and
        optionally locks it to prevent further modifications.

        :param index: Index of the fuse to be written.
        :param value: Fuse value to be programmed.
        :param length: Length of fuse in bits.
        :param lock: Lock fuse after write to prevent further modifications.
        :param verify: Verify the fuse value after writing, defaults to True.
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
    def write_fuse(
        self, index: int, value: int, length: int, lock: bool = False, verify: bool = True
    ) -> None:
        """Write a single fuse.

        This method programs a fuse at the specified index with the given value by setting
        the appropriate voltage, programming the fuse, and resetting the voltage.

        :param index: Index of the fuse to be written.
        :param value: Fuse value to be programmed.
        :param length: Length of fuse in bits (currently not used in implementation).
        :param lock: Lock fuse after write (currently not implemented).
        :param verify: Verify the fuse value after writing, defaults to True.
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
                raise SPSDKAttributeError(f"OTP index is not defined for fuse {fuse.name}")
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

    def write_fuse(
        self, index: int, value: int, length: int, lock: bool = False, verify: bool = True
    ) -> None:
        """Write a single fuse.

        This method writes a value to a specific fuse register using the ELE (EdgeLock Enclave)
        messaging system. The fuse can optionally be locked after writing to prevent further
        modifications.

        :param index: Index of the fuse register to write to.
        :param value: Fuse value to be written to the register.
        :param length: Length of fuse in bits (currently unused, fixed at 32 bits).
        :param lock: Lock fuse after write to prevent further modifications.
        :param verify: Verify the fuse value after writing, defaults to True.
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


class ShadowregsOperator(FuseOperator):
    """Shadow registers fuse operator for direct memory-mapped register access.

    This class provides fuse operations through shadow registers, which are memory-mapped
    representations of OTP fuses. It enables reading and writing fuse values via debug
    probe access to shadow register addresses, supporting devices that expose fuses
    through memory-mapped registers rather than dedicated fuse programming commands.

    The operator handles debug interface enablement, scratch register updates for some
    devices, and verification of written values with configurable verification masks.

    :cvar NAME: Operator identifier for shadow registers operations.
    """

    NAME = "shadowregs"

    def __init__(self, family: FamilyRevision, probe: Optional[DebugProbe] = None):
        """Initialize shadow registers operator.

        Creates a new instance of the shadow registers operator for the specified family.
        If a debug probe is provided, it attempts to enable debug access on the device.

        :param family: Target MCU family and revision information.
        :param probe: Optional debug probe for device communication. If provided,
            debug interface will be enabled automatically.
        :raises SPSDKError: When debug interface cannot be enabled with provided probe.
        """
        self._probe = probe
        self.family = family
        self.regs = FuseRegisters(family=self.family)
        self._db = get_db(family)
        self.write_address_offset = self._db.get_int(
            DatabaseManager.SHADOW_REGS, "write_address_offset", 0
        )
        self.scratch_reg = self._db.get_dict(DatabaseManager.SHADOW_REGS, "scratch_reg", {})
        self.possible_verification = self._db.get_bool(
            DatabaseManager.SHADOW_REGS, "possible_verification", True
        )
        if probe:
            if not self.enable_debug():
                raise SPSDKError("Cannot enable debug interface")

    def enable_debug(self) -> bool:
        """Enable debug access ports on devices with debug mailbox.

        The method checks if AHB access is available and if not, attempts to unlock
        the device using debug mailbox system. It handles probe reconnection and
        validates the unlock operation.

        :return: True if debug port is enabled, False otherwise.
        :raises SPSDKError: Invalid input parameters or unlock method failed.
        """
        from spsdk.debuggers.utils import test_ahb_access

        debug_enabled = False
        try:
            logger.debug("Check if AHB is enabled")

            if not test_ahb_access(self.probe):
                logger.debug("Locked Device. Launching unlock sequence.")
                # Reopen the probe after failed attempt of AHB Access
                self.probe.close()
                self.probe.open()
                self.probe.connect_safe()
                # Start debug mailbox system
                StartDebugSession(dm=DebugMailbox(debug_probe=self.probe, family=self.family)).run()

                # Recheck the AHB access
                if test_ahb_access(self.probe):
                    logger.debug("Access granted")
                    debug_enabled = True
                else:
                    logger.debug("Enable debug operation failed!")
            else:
                logger.debug("Unlocked Device")
                debug_enabled = True

        except AttributeError as exc:
            raise SPSDKError(f"Invalid input parameters({str(exc)})") from exc

        except SPSDKDebugProbeError as exc:
            raise SPSDKError(f"Can't unlock device ({str(exc)})") from exc

        return debug_enabled

    def _update_scratch_reg(self) -> None:
        """Update scratch register for to enable shadow register functionality.

        This method writes a specific value to the scratch register address to activate
        the shadow register functionality on some devices.
        """
        if not self.scratch_reg:
            return
        address = self.scratch_reg.get("address")
        if not isinstance(address, int):
            raise SPSDKTypeError("Scratch register address must be an integer")
        value = self.scratch_reg.get("value")
        if not isinstance(value, int):
            raise SPSDKTypeError("Scratch register value must be an integer")
        if not address or not value:
            raise SPSDKError("Scratch register address and value must be defined")
        logger.debug("Flushing shadow registers data")
        self.probe.mem_reg_write(address, value)

    def _get_reg_by_index(self, index: int) -> FuseRegister:
        """Get register by index."""
        reg = self.regs.get_by_otp_index(index)
        if reg.shadow_register_addr is None:
            raise SPSDKRegsInvalidAttribute(
                f"Register at index {index} has no shadow register addr"
            )
        return reg

    @property
    def probe(self) -> DebugProbe:
        """Get debug probe instance.

        Property to access the debug probe for performing shadow register operations.

        :raises SPSDKDebugProbeError: When debug probe is not defined.
        :return: The debug probe instance.
        """
        if not self._probe:
            raise SPSDKDebugProbeError(
                "Shadow registers: Cannot use the communication function without defined debug probe."
            )
        return self._probe

    def read_fuse(self, index: int, length: int) -> int:
        """Read a single fuse value from shadow register.

        This method reads the fuse value from the memory-mapped shadow register
        address corresponding to the specified OTP index.

        :param index: OTP index of the fuse to read.
        :param length: Length of fuse in bits (not used for shadow registers).
        :return: The fuse value read from the shadow register.
        :raises SPSDKRegsInvalidAttribute: When register has no shadow register address.
        """
        reg = self._get_reg_by_index(index)
        if not reg.shadow_register_addr:
            raise SPSDKRegsInvalidAttribute(
                f"Register at index {index} has no shadow register address defined"
            )
        return self.probe.mem_reg_read(reg.shadow_register_addr)

    def write_fuse(
        self, index: int, value: int, length: int, lock: bool = False, verify: bool = True
    ) -> None:
        """Write a single fuse value to shadow register.

        This method writes a value to the memory-mapped shadow register address
        corresponding to the specified OTP index. It handles write address offsets,
        scratch register updates, and optional verification.

        :param index: OTP index of the fuse to write.
        :param value: Fuse value to be written.
        :param length: Length of fuse in bits (not used for shadow registers).
        :param lock: Lock fuse after write (not supported for shadow registers).
        :param verify: Verify the write operation after writing.
        :raises SPSDKError: When register width exceeds 32 bits.
        :raises SPSDKRegsInvalidAttribute: When register has no shadow register address.
        :raises SPSDKVerificationError: When verification fails.
        """
        reg = self._get_reg_by_index(index)
        if not reg.shadow_register_addr:
            raise SPSDKRegsInvalidAttribute(
                f"Register at index {index} has no shadow register address defined"
            )
        if reg.width > 32:
            raise SPSDKError(
                f"Invalid width ({reg.width}b) of shadow register ({reg.name}) to write to device."
            )
        logger.info(
            f"Writing shadow register address: {hex(reg.shadow_register_addr)}, data: {hex(value)}"
        )
        write_address = (
            self.write_address_offset + reg.shadow_register_addr
        )  # some device has different write address then read
        self.probe.mem_reg_write(write_address, value)
        if self.scratch_reg:
            self._update_scratch_reg()
        if lock:
            logger.info("Lock parameter is not supported for shadow registers")
        if verify:
            self._verify_register(index, value)

    def _verify_register(self, index: int, value: int) -> None:
        if not self.possible_verification:
            logger.info(f"Verification is not supported for family {self.family}")
            return

        def create_verify_mask(reg: FuseRegister) -> int:
            verify_mask = 0
            bitfields = reg.get_bitfields()
            if bitfields:
                for bitfield in bitfields:
                    verify_mask = verify_mask | (((1 << bitfield.width) - 1) << bitfield.offset)
            else:
                verify_mask = (1 << reg.width) - 1
            return verify_mask

        reg = self._get_reg_by_index(index)
        assert reg.otp_index is not None
        verify_mask = create_verify_mask(reg)
        if verify_mask and self.possible_verification:
            read_back = self.read_fuse(reg.otp_index, reg.width // 8)
            if (read_back & verify_mask) != (value & verify_mask):
                raise SPSDKVerificationError(
                    f"Written value: 0x{(value & verify_mask):08X}, read value: 0x{(read_back & verify_mask):08X}"
                )

    @classmethod
    def get_fuse_script(cls, family: FamilyRevision, fuses: list[FuseRegister]) -> str:
        """Get fuse script for programming Fuses."""
        ret = (
            "# BLHOST fuses programming script\n"
            f"# Generated by SPSDK {spsdk_version}\n"
            f"# Chip: {family}\n\n\n"
        )
        for fuse in fuses:
            if fuse.otp_index is None:
                raise SPSDKAttributeError(f"OTP index is not defined for fuse {fuse.name}")
            # recalculate the value in a "fuse mode"
            orig_value = fuse.get_value(raw=True)
            try:
                fuse.shadow_mode = False
                fuse.compute_register()
                new_value = fuse.get_value(raw=True)
            finally:
                fuse.shadow_mode = False
                fuse.set_value(orig_value, raw=True)
            otp_value = "0x" + fuse.get_bytes_value(raw=True).hex()
            ret += f"# Fuse {fuse.name}, index {fuse.otp_index} and value: {otp_value}.\n"
            ret += cls.get_fuse_write_cmd(fuse.otp_index, new_value)
            ret += "\n\n"
        return ret

    @classmethod
    def get_fuse_write_cmd(
        cls, index: int, value: int, lock: bool = False, verify: bool = False
    ) -> str:
        """Get fuse write command for shadow registers.

        Generates a BLHOST-compatible command string for programming shadow registers
        through efuse-program-once command with optional verification.

        :param index: OTP index of the fuse to write.
        :param value: Value to write to the fuse.
        :param lock: Lock the fuse after writing (appends 'lock' to command).
        :param verify: Verify the fuse value after writing.
        :return: Formatted fuse programming command string.
        """
        ret = f"efuse-program-once {hex(index)} {value}\n"
        ret = f"{ret} {'--verify' if verify else '--no-verify'}"
        if lock:
            ret = f"{ret} lock"
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
        cache: bool = True,
    ):
        """Initialize Fuses class to control fuse operations.

        The Fuses class provides functionality to manage and manipulate fuse registers
        for NXP MCU devices, including reading, writing, and configuring fuse values.

        :param family: Target MCU family and revision information for fuse operations.
        :param fuse_operator: Optional operator for performing actual fuse operations,
            defaults to None.
        :param cache: Enable caching of lock fuse values to prevent multiple reads,
            defaults to True.
        :raises SPSDKError: When the specified family has no fuses definition available.
        """
        self.family = family
        self.db = get_db(family)
        self._operator = fuse_operator
        self.registers = self.get_init_regs(family)
        self._cache_enabled = cache
        self._cache: set[str] = set()  # Store UIDs of cached lock fuse registers

    def __repr__(self) -> str:
        """Get string representation of the Fuses class.

        :return: String representation containing the family name.
        """
        return f"{self.__class__.__name__} class for {self.family}."

    def __str__(self) -> str:
        """Get string representation of the fuses class.

        The method provides a detailed string representation that includes both the
        basic object information and the string representation of the fuse registers.

        :return: String representation containing object info and fuse registers details.
        """
        ret = self.__repr__()
        ret += "\n" + str(self.registers)
        return ret

    def __iter__(self) -> Iterator[FuseRegister]:
        """Make the fuse registers iterable.

        Allows iteration over all fuse registers in the collection using standard
        Python iteration protocols.

        :return: Iterator over FuseRegister objects.
        """
        return iter(self.registers)

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
        return FuseOperator.get_operator_type(get_db(family).get_str(cls.FEATURE, "tool"))

    @classmethod
    def get_init_regs(cls, family: FamilyRevision) -> FuseRegisters:
        """Get initialized fuse registers.

        Creates and returns a new FuseRegisters instance for the specified family revision.

        :param family: The family revision to initialize the fuse registers for.
        :return: Initialized fuse registers instance for the given family.
        """
        return FuseRegisters(family=family)

    def clear_cache(self) -> None:
        """Clear the lock fuse read cache.

        Removes all cached lock fuse values, forcing subsequent reads to fetch fresh
        data from the device.
        """
        self._cache.clear()
        logger.debug("Lock fuse cache cleared")

    def is_cached(self, reg: FuseRegister) -> bool:
        """Check if a lock fuse register value is cached.

        Only lock fuses are cached to prevent multiple reads during lock checks.

        :param reg: Fuse register to check.
        :return: True if the register is a lock fuse and its value is cached, False otherwise.
        """
        return self._cache_enabled and self.registers.is_lock_fuse(reg) and reg.uid in self._cache

    def add_to_cache(self, reg: FuseRegister) -> None:
        """Add a lock fuse register to the cache.

        Only lock fuses are cached to optimize lock checking operations.

        :param reg: Fuse register to add to cache.
        """
        if self._cache_enabled and self.registers.is_lock_fuse(reg):
            self._cache.add(reg.uid)
            logger.debug(f"Added lock fuse {reg.name} to cache")

    @classmethod
    def load_from_config(cls, config: Config, fuse_operator: Optional[FuseOperator] = None) -> Self:
        """Create fuses object from given configuration.

        This class method instantiates a new fuses object using the provided configuration
        data, including family revision information and fuse-specific settings.

        :param config: The configuration object containing fuses settings and family revision data.
        :param fuse_operator: Optional operator for performing actual fuse operations,
            defaults to None.
        :return: New fuses object configured according to the provided configuration.
        """
        fuses = cls(FamilyRevision.load_from_config(config), fuse_operator=fuse_operator)
        fuses.registers.load_from_config(config.get_config("registers"))
        for reg_name in config["registers"].keys():
            reg = fuses.registers.find_reg(reg_name, include_group_regs=True)
            reg.loaded_from_config = True
        return fuses

    def read_all(
        self,
        check_locks: bool = True,
        force: bool = False,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> None:
        """Read all fuses from connected device.

        Attempts to read every fuse register from the connected device.
        Failed reads are logged as warnings but do not stop the operation.

        :raises SPSDKFuseOperationFailure: When individual fuse read operations fail (logged as
            warnings, does not interrupt the overall operation).
        :raises SPSDKError: When individual fuse read fails. It causes the exception after all registers are read
        """
        errors = 0
        processed = 0
        total_registers = len(self.registers)
        if progress_callback:
            progress_callback(0, total_registers)  # Initialize progress bar at 0%
        for reg in self.registers:
            try:
                self.read_single(reg.uid, check_locks, force)
            except SPSDKFuseOperationFailure as e:
                logger.debug(f"Register '{reg.name}' was not read as it is not readable: {e}")
            except SPSDKError as e:
                logger.error(f"Error when reading the register '{reg.name}' from the device: {e}")
                errors += 1
            finally:
                processed += 1
                if progress_callback:
                    progress_callback(processed, total_registers)
        if errors:
            raise SPSDKError(f"Reading the fuses failed with {errors} error(s)")

    def read_single(self, name: str, check_locks: bool = True, force: bool = False) -> int:
        """Read single fuse from device.

        Reads the value of a specified fuse register from the device, with optional
        lock checking to ensure the fuse is readable before attempting the operation.
        Lock fuses are cached to avoid redundant reads during lock checking operations.

        :param name: Fuse name or uid to read from device.
        :param check_locks: Check value of lock fuse before reading to prevent
            locked fuse access.
        :param force: Force read even when the fuse is marked as non-readable
        :raises SPSDKFuseOperationFailure: When fuse is not readable or read
            operation is locked.
        :raises SPSDKFuseConfigurationError: When OTP index is not defined for
            the fuse.
        :return: Value read from the fuse register.
        """
        reg = self.registers.find_reg(name, include_group_regs=True)

        # Check cache first (only for lock fuses)
        if self.is_cached(reg):
            logger.debug(f"Returning cached value for lock fuse {reg.name}")
            return reg.get_value()

        if not reg.access.is_readable and not force:
            raise SPSDKFuseOperationFailure(
                f"Unable to read fuse {name}. Fuse access: {reg.access.description}"
            )
        if reg.reserved and not force:
            raise SPSDKFuseOperationFailure(f"Unable to read fuse {name}. Fuse is reserved.")

        lock_fuse = self.registers.get_lock_fuse(reg)
        if lock_fuse and check_locks:
            logger.debug(f"Reading the value of lock register first. {lock_fuse.name}")
            # if the fuse locks itself, do not read it
            self.read_single(lock_fuse.uid, check_locks=lock_fuse != reg)
            if FuseLock.READ_LOCK in reg.get_active_locks():
                raise SPSDKFuseOperationFailure(
                    f"Fuse {reg.name} read operation is locked by lock fuse {lock_fuse.name}."
                )

        if reg.has_group_registers():
            for sub_reg in reg.sub_regs:
                self.read_single(sub_reg.uid, check_locks=check_locks, force=force)
            # Cache group register if it's a lock fuse
            self.add_to_cache(reg)
            return reg.get_value()

        if reg.otp_index is None:
            raise SPSDKFuseConfigurationError("OTP index is not defined")

        value = self.fuse_operator.read_fuse(reg.otp_index, reg.width)
        reg.set_value(value, raw=True)
        self.registers.update_locks()
        # Cache only if it's a lock fuse
        self.add_to_cache(reg)
        return value

    def write_single(self, name: str, lock: bool = False, verify: bool = True) -> None:
        """Write single fuse to the device.

        The method handles both individual fuses and group registers. It performs
        lock checks, validates write permissions, and manages individual write lock
        behavior according to fuse configuration. After writing a lock fuse, its cache
        entry is cleared to ensure fresh reads.

        :param name: Fuse name or uid to write.
        :param lock: Set lock after write operation.
        :param verify: Verify the fuse value after writing, defaults to True.
        :raises SPSDKError: OTP index for fuse is not set.
        :raises SPSDKFuseOperationFailure: Fuse is not writable, write-locked, or has
                                           non-reset value with write lock.
        """
        reg = self.registers.find_reg(name, include_group_regs=True)
        if reg.has_group_registers():
            for sub_reg in reg.sub_regs:
                self._write_register(sub_reg, lock, verify)
            # Remove group register from cache if it's a lock fuse
            if self.registers.is_lock_fuse(reg) and reg.uid in self._cache:
                self._cache.remove(reg.uid)
        else:
            self._write_register(reg, lock, verify)

    def write_multiple(self, names: list[str], verify: bool = True) -> None:
        """Write multiple fuses to the device.

        This method iterates through the provided list of fuse names or UIDs,
        finds the corresponding registers, and writes each one individually to the device.

        :param names: List of fuse names or UIDs to be written to the device.
        :param verify: Verify the fuse value after writing, defaults to True.
        :raises SPSDKError: If any fuse name/UID is not found or write operation fails.
        """
        regs = [self.registers.find_reg(name, include_group_regs=True) for name in names]
        # permission error not skipped as user-defined registers should be writable
        self._write_multiple(regs, verify=verify)

    def write_all(self, verify: bool = True) -> None:
        """Write all fuse registers to the device.

        This method writes all fuse registers in the collection to the device.
        It processes registers in a specific order, writing non-lock fuses first
        to prevent lock fuses from blocking subsequent write operations.

        :param verify: Verify write operation after writing each register, defaults to True.
        :raises SPSDKFuseOperationFailure: When one or more fuse write operations fail.
        :raises SPSDKError: When register write operation encounters an error.
        """
        # skip permission error as some registers may be read-only
        self._write_multiple(self.registers._registers, verify=verify, skip_permission_error=True)

    def write_loaded(self, verify: bool = True) -> None:
        """Update shadow registers in target using their local values.

        This method iterates through all loaded registers and writes their current local values
        to the target device using the set_register method.

        :param verify: Verify write operation after setting each register.
        :raises SPSDKError: If register write operation fails.
        """
        regs = {r for r in self if r.loaded_from_config}
        # add also antipole registers
        regs.update(r.antipole_register for r in list(regs) if r.antipole_register)
        self._write_multiple(list(regs), verify=verify)

    def _write_multiple(
        self,
        regs: list[FuseRegister],
        allow_order_change: bool = True,
        verify: bool = True,
        skip_permission_error: bool = False,
    ) -> None:
        """Write multiple registers to the device."""
        errors = 0

        def _write_single(reg: FuseRegister, verify: bool = True) -> int:
            try:
                self.write_single(reg.name, verify=verify)
                return 0
            except SPSDKFuseOperationFailure as exc:
                log_func = logger.debug if skip_permission_error else logger.error
                log_func(f"Fuse '{reg.name}' was not written as it is not writeable: {exc}")
                return 1 if not skip_permission_error else 0
            except SPSDKError as exc:
                logger.error(f"Error when writing the fuse '{reg.name}' to the device: {exc}")
                return 1

        # first we need to write non-lock fuses as lock fuses may lock other fuses to be written
        if allow_order_change:
            lock_regs, normal_regs = self._split_registers(regs)
        else:
            lock_regs, normal_regs = [], regs
        for reg in normal_regs:
            errors += _write_single(reg, verify)
        for reg in lock_regs:
            errors += _write_single(reg, verify)
        if errors:
            raise SPSDKFuseOperationFailure(f"Writing the fuses failed with {errors} error(s)")

    def set_value(
        self, name: str, value: Union[bytes, bytearray, int, str], raw: bool = False
    ) -> None:
        """Set the value of a fuse register without writing to device.

        This method updates the local value of a fuse register identified by name,
        UID, or OTP index. The value is stored locally and can be written to the
        device later using write methods.

        :param name: Fuse register name, UID, or OTP index to set.
        :param value: The value to set for the fuse register.
        :param raw: If True, set raw value without applying modification hooks;
            if False, apply computed value with modification hooks, defaults to False.
        """
        value = value_to_int(value)
        fuse = self.registers.find_reg(name, include_group_regs=True)
        fuse.set_value(value, raw=raw)

    def _split_registers(
        self, regs: list[FuseRegister]
    ) -> tuple[list[FuseRegister], list[FuseRegister]]:
        """Split a group register into lock and normal registers.

        :param reg: The group register to split.
        :return: List of sub-registers if group
        """
        lock_fuses: list[FuseRegister] = []
        non_lock_fuses: list[FuseRegister] = []
        for reg in regs:
            if reg in self.registers.get_lock_fuses():
                lock_fuses.append(reg)
            else:
                non_lock_fuses.append(reg)
        return lock_fuses, non_lock_fuses

    def _write_register(self, reg: FuseRegister, lock: bool = False, verify: bool = True) -> None:
        """Write a single fuse register to the device.

        This method writes the value of a fuse register to the OTP memory with comprehensive
        validation including access rights, lock status checks, and individual write lock
        handling. The method automatically manages lock states and validates write permissions
        before performing the operation. After writing a lock fuse, its cache entry is removed.

        :param reg: The fuse register to write to the device.
        :param lock: Whether to lock the fuse after writing, defaults to False.
        :param verify: Verify the fuse value after writing, defaults to True.
        :raises SPSDKError: If the OTP index for the fuse is not set.
        :raises SPSDKFuseOperationFailure: If the fuse is not writable, write-locked by another
            fuse, or has non-reset value with write-lock restrictions.
        """
        if reg.otp_index is None:
            raise SPSDKError(f"OTP index for fuse {reg.name} is not set.")
        if not reg.access.is_writable:
            raise SPSDKFuseOperationFailure(
                f"Unable to write fuse {reg.name}. Fuse access: {reg.access.description}"
            )
        lock_reg = self.registers.get_lock_fuse(reg)
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
            value = self.fuse_operator.read_fuse(reg.otp_index, reg.width)
            if value != reset:
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
        self.fuse_operator.write_fuse(reg.otp_index, reg.get_value(), reg.width, lock, verify)
        # lock the local register so it matches the real state in chip
        if lock or reg.individual_write_lock == IndividualWriteLock.IMPLICIT:
            reg.lock(FuseLock.WRITE_LOCK)
        # Remove from cache after write if it's a lock fuse
        if self.registers.is_lock_fuse(reg) and reg.uid in self._cache:
            self._cache.remove(reg.uid)
            logger.debug(f"Removed lock fuse {reg.name} from cache after write")

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
        sch_cfg = get_schema_file(cls.FEATURE)
        init_regs = cls.get_init_regs(family)
        sch_cfg[cls.FEATURE]["properties"]["registers"][
            "properties"
        ] = init_regs.get_validation_schema()["properties"]
        return sch_family + [sch_cfg[cls.FEATURE]]

    def create_fuse_script(
        self,
        reg_list: Optional[list[str]] = None,
        loaded_only: bool = False,
        non_default_only: bool = False,
    ) -> str:
        """Generate fuse programming script for blhost or nxpele tools.

        This method processes all fuse registers in the context, handling both simple registers
        and group registers with sub-registers. For group registers, it processes sub-registers
        in the appropriate order based on the reverse_subregs_order flag.

        :param reg_list: Limit to list of registers.
        :param loaded_only: Limit to registers loaded from config.
        :param non_default_only: Limit to registers with non-default value.
        :return: Content of the fuse programming script file as a string.
        """
        fuse_regs = []
        # Determine which registers to process
        if reg_list is not None:
            # Filter registers based on the provided list
            registers_to_process = [
                self.registers.find_reg(reg_name, include_group_regs=True) for reg_name in reg_list
            ]
        else:
            # Process all registers
            registers_to_process = self.registers._registers
        if loaded_only:
            registers_to_process = [r for r in self.registers._registers if r.loaded_from_config]
        if non_default_only:
            registers_to_process = [r for r in registers_to_process if not r.has_reset_value]
        for reg in registers_to_process:
            if reg.has_group_registers():
                for sub_reg in reg.sub_regs[:: -1 if reg.reverse_subregs_order else 1]:
                    fuse_regs.append(sub_reg)
            else:
                fuse_regs.append(reg)
            if reg.antipole_register:
                fuse_regs.append(reg.antipole_register)
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
        ret["registers"] = self.registers.get_config(diff=diff)
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
