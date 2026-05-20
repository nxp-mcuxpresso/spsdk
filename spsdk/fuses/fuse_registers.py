#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK fuse registers management and operations.

This module provides comprehensive functionality for handling fuse registers,
including individual write locks, fuse locks, and register operations within
the SPSDK framework for NXP MCU provisioning.
"""

import logging
from dataclasses import dataclass
from typing import Any, Callable, Optional, Union

from typing_extensions import Self

from spsdk.exceptions import SPSDKError, SPSDKKeyError, SPSDKValueError
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager
from spsdk.utils.exceptions import (
    SPSDKRegsErrorRegisterGroupMishmash,
    SPSDKRegsErrorRegisterNotFound,
)
from spsdk.utils.family import FamilyRevision, get_db
from spsdk.utils.misc import Endianness, value_to_int
from spsdk.utils.registers import Register, _RegistersBase
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)


class IndividualWriteLock(SpsdkEnum):
    """Individual write lock enumeration for fuse registers.

    This enumeration defines the different types of write lock mechanisms
    that can be applied to individual fuse registers, controlling when and
    how register values can be modified after being written.
    """

    NONE = (0, "none", "No individual lock for the register")
    USER = (1, "user", "User configurable lock")
    ALWAYS = (2, "always_lock", "Always generate lock after write")
    IMPLICIT = (3, "implicit", "Implicit lock")


class FuseLock(SpsdkEnum):
    """Fuse lock type enumeration for SPSDK fuse operations.

    This enumeration defines the different types of locks that can be applied
    to fuses, controlling access permissions for read, write, and operation
    activities on fuse registers.
    """

    WRITE_LOCK = (0, "write_lock", "Write lock")
    READ_LOCK = (1, "read_lock", "Read lock")
    OPERATION_LOCK = (2, "operation_lock", "Operation lock")


@dataclass
class FuseLockRegister:
    """Fuse lock register representation for NXP MCU fuse operations.

    This class represents a fuse lock register that controls access permissions
    for fuse operations including write, read, and operational locks through
    configurable bit masks.
    """

    register_id: str
    write_lock_mask: Optional[int]
    read_lock_mask: Optional[int]
    operation_lock_mask: Optional[int]

    def __eq__(self, obj: Any) -> bool:
        """Check equality of two fuse register objects.

        Compares register ID and all lock masks (write, read, operation) to determine
        if two fuse register instances are equivalent.

        :param obj: Object to compare with this fuse register instance.
        :return: True if objects are equal, False otherwise.
        """
        if not isinstance(obj, self.__class__):
            return False
        return (
            self.register_id == obj.register_id
            and self.write_lock_mask == obj.write_lock_mask
            and self.read_lock_mask == obj.read_lock_mask
            and self.operation_lock_mask == obj.operation_lock_mask
        )

    def __str__(self) -> str:
        """Get string representation of the lock register.

        Provides a formatted string containing the lock register ID and associated
        masks for write, read, and operation locks when they are defined.

        :return: Formatted string with lock register details.
        """
        output = ""
        output += f"Lock Register id:   {self.register_id}\n"
        if self.write_lock_mask is not None:
            output += f"Write mask:   {self.write_lock_mask}\n"
        if self.read_lock_mask is not None:
            output += f"Read mask:   {self.read_lock_mask}\n"
        if self.operation_lock_mask is not None:
            output += f"Operation mask:   {self.operation_lock_mask}\n"
        return output

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Create object from given configuration.

        :param config: The configuration of fuse lock register.
        :return: New instance of the class created from configuration.
        """
        register_id = config.get_str("register_id")
        write_lock = config.get("write_lock_int")
        read_lock = config.get("read_lock_int")
        operation_lock = config.get("operation_lock_int")
        lock = cls(
            register_id=register_id,
            write_lock_mask=(value_to_int(write_lock) if write_lock is not None else None),
            read_lock_mask=(value_to_int(read_lock) if read_lock is not None else None),
            operation_lock_mask=(
                value_to_int(operation_lock) if operation_lock is not None else None
            ),
        )
        return lock

    def create_config(self) -> dict[str, Any]:
        """Create configuration dictionary from fuse register object.

        Generates a configuration dictionary containing the register ID and any defined
        lock masks (write, read, operation) in hexadecimal format.

        :return: Configuration dictionary with register_id and optional lock masks.
        """
        cfg = {
            "register_id": self.register_id,
        }
        if self.write_lock_mask is not None:
            cfg["write_lock_int"] = hex(self.write_lock_mask)
        if self.read_lock_mask is not None:
            cfg["read_lock_int"] = hex(self.read_lock_mask)
        if self.operation_lock_mask is not None:
            cfg["operation_lock_int"] = hex(self.operation_lock_mask)
        return cfg


class FuseRegister(Register):
    """SPSDK fuse register representation with locking capabilities.

    This class extends the base Register class to provide specialized functionality
    for managing OTP (One-Time Programmable) fuse registers including shadow register
    mapping, individual write locks, and various lock states for secure provisioning
    operations.
    """

    def __init__(
        self,
        *args: Any,
        otp_index: Optional[Union[str, int]] = None,
        shadow_register_offset: Optional[int] = None,
        shadow_register_base_addr: Optional[int] = None,
        individual_write_lock: IndividualWriteLock = IndividualWriteLock.NONE,
        fuse_lock_register: Optional[FuseLockRegister] = None,
        antipole_register: Optional["FuseRegister"] = None,
        computed_hooks: Optional[list[str]] = None,
        shadow_mode: bool = False,
        **kwargs: Any,
    ):
        """Initialize fuse register with configuration parameters.

        Sets up a fuse register instance with OTP indexing, shadow register mapping,
        write lock configuration, and internal lock state tracking.

        :param otp_index: Index of OTP fuse, can be string or integer.
        :param shadow_register_offset: Optional shadow register offset from base address.
        :param shadow_register_base_addr: Base address for shadow register mapping.
        :param individual_write_lock: Individual write lock configuration type.
        :param fuse_lock_register: Optional fuse lock register configuration object.
        :param antipole_register: Optional reference to antipole register for inverted value storage.
        :param calculated_hook: Optional name of computation method for register value calculation.
        :param shadow_mode: Enable shadow mode for register calculated hooks operations, defaults to False.
        """
        super().__init__(*args, **kwargs)
        self.individual_write_lock = individual_write_lock
        self.fuse_lock_register = fuse_lock_register
        self.otp_index = value_to_int(otp_index) if otp_index is not None else None
        self.shadow_register_offset = shadow_register_offset
        self.shadow_register_base_addr = shadow_register_base_addr
        self.antipole_register = antipole_register
        self._locks: dict = {
            FuseLock.READ_LOCK: False,
            FuseLock.WRITE_LOCK: False,
            FuseLock.OPERATION_LOCK: False,
        }
        self.computed_hooks = computed_hooks or []
        self.loaded_from_config = False
        self.shadow_mode = shadow_mode

    @property
    def is_readable(self) -> bool:
        """Check if the fuse register is readable.

        A fuse register is considered readable when it has read access permissions
        and the READ_LOCK is not currently active.

        :return: True if the fuse register can be read, False otherwise.
        """
        return self.access.is_readable and FuseLock.READ_LOCK not in self.get_active_locks()

    @property
    def is_writable(self) -> bool:
        """Check if the fuse register is writable.

        A fuse register is considered writable when it has write access permissions
        and no write lock is currently active.

        :return: True if the register can be written to, False otherwise.
        """
        return self.access.is_writable and FuseLock.WRITE_LOCK not in self.get_active_locks()

    def get_active_locks(self) -> list[FuseLock]:
        """Get list of active locks.

        :return: List of fuse locks that are currently active.
        """
        return [lock for lock, active in self._locks.items() if active]

    def lock(self, lock_type: FuseLock) -> None:
        """Set the fuse lock.

        Sets the specified lock type for this fuse register. If the lock is already set,
        the operation is ignored and a debug message is logged.

        :param lock_type: Type of lock to set on the fuse register.
        """
        if self._locks[lock_type]:
            return
        self._locks[lock_type] = True

    def unlock(self, lock_type: FuseLock) -> None:
        """Unset the fuse lock.

        Removes the specified lock type from the fuse register. If the lock is already
        unset no changes are made.

        :param lock_type: Type of fuse lock to be removed.
        """
        if not self._locks[lock_type]:
            return
        self._locks[lock_type] = False

    @classmethod
    def create_from_spec(
        cls, spec: dict[str, Any], reg_mods: Optional[dict[str, Any]] = None
    ) -> Self:
        """Create fuse register instance from specification dictionary.

        The method extends the parent class creation by adding fuse-specific attributes
        like OTP index, shadow register offset, lock register, and individual write lock
        configurations.

        :param spec: Dictionary containing register specification data including required
            'index_int' and optional 'shadow_reg_offset_int', 'lock', and
            'individual_write_lock' fields.
        :param reg_mods: Optional dictionary with register modifications to apply.
        :raises SPSDKKeyError: When required 'index_int' attribute is missing from spec.
        :return: New fuse register instance configured according to specification.
        """
        # First call the parent method to create the basic register
        reg = super().create_from_spec(spec, reg_mods)

        if "index_int" not in spec:
            raise SPSDKKeyError(
                f"Invalid fuse config for fuse {reg.uid}. Missing index_int attribute"
            )
        reg.otp_index = value_to_int(spec["index_int"])
        reg.shadow_register_offset = (
            value_to_int(spec["shadow_reg_offset_int"])
            if spec.get("shadow_reg_offset_int") is not None
            else None
        )
        if "lock" in spec:
            reg.fuse_lock_register = FuseLockRegister.load_from_config(Config(spec["lock"]))
        if "individual_write_lock" in spec:
            reg.individual_write_lock = IndividualWriteLock.from_label(
                spec["individual_write_lock"]
            )
        return reg

    def create_spec(self) -> dict[str, Any]:
        """Creates the register specification structure.

        This method builds a dictionary containing the register specification by extending
        the parent class specification with fuse-specific attributes including OTP index,
        shadow register offset, lock register configuration, and individual write lock.

        :return: Dictionary containing the complete register specification with fuse-specific attributes.
        """
        spec = super().create_spec()
        if self.otp_index is not None:
            spec["index_int"] = hex(self.otp_index)
        if self.shadow_register_offset is not None:
            spec["shadow_reg_offset_int"] = hex(self.shadow_register_offset)
        if self.fuse_lock_register:
            spec["lock"] = self.fuse_lock_register.create_config()
        if self.individual_write_lock:
            spec["individual_write_lock"] = self.individual_write_lock.label
        return spec

    def _add_group_reg(self, reg: Self) -> None:
        """Add group element for this register.

        Adds a register as a member of this register group and handles shadow register
        offset configuration. For the first member, it inherits the shadow register offset.
        For subsequent members, it validates shadow register compatibility.

        :param reg: Register member to add to this register group.
        :raises SPSDKRegsErrorRegisterGroupMishmash: When register doesn't support shadow register
            feature as its group parent.
        """
        first_member = self.has_group_registers()
        super()._add_group_reg(reg)
        if first_member:
            if self.shadow_register_offset is None:
                self.shadow_register_offset = reg.shadow_register_offset
        else:
            if self.shadow_register_offset is not None and reg.shadow_register_offset is None:
                raise SPSDKRegsErrorRegisterGroupMishmash(
                    f"The register {reg.name} doesn't support shadow register feature as its group parent."
                )

    def __hash__(self) -> int:
        """Generate hash value for the fuse register instance.

        The hash is based on the unique identifier (uid) of the fuse register,
        allowing the object to be used in hash-based collections like sets and
        dictionaries.

        :return: Hash value of the fuse register's uid.
        """
        return hash(self.uid)

    def __eq__(self, obj: Any) -> bool:
        """Compare if two fuse register objects have the same settings.

        This method performs a deep comparison of two fuse register objects by checking
        if they are of the same class and comparing their shadow register address,
        OTP index, and fuse lock register properties along with parent class attributes.

        :param obj: Object to compare with this fuse register instance.
        :return: True if objects have identical settings, False otherwise.
        """
        if not isinstance(obj, self.__class__):
            return False
        return (
            super().__eq__(obj)
            and self.shadow_register_addr == obj.shadow_register_addr
            and self.otp_index == obj.otp_index
            and self.fuse_lock_register == obj.fuse_lock_register
        )

    def __str__(self) -> str:
        """Get string representation of the fuse register.

        Provides a detailed, human-readable description of the register including its
        properties, bitfields, and optional fuse lock register information.

        :return: Formatted string containing register name, offset, width, access type,
                 description, fuse lock register (if present), and all bitfields.
        """
        output = ""
        output += f"Name:   {self.name}\n"
        output += f"Offset: 0x{self.offset:04X}\n"
        output += f"Width:  {self.width} bits\n"
        output += f"Access:   {self.access.label}\n"
        output += f"Description: \n {self.description}\n"
        if self.fuse_lock_register:
            output += f"Fuse Lock Register: \n {self.fuse_lock_register}\n"
        i = 0
        for bitfield in self._bitfields:
            output += f"Bitfield #{i}: \n" + str(bitfield)
            i += 1
        return output

    @property
    def shadow_register_addr(self) -> Optional[int]:
        """Calculate the absolute address of shadow registers.

        Computes the real memory address by adding the shadow register base address
        and offset. Returns None if base address is not configured.

        :raises SPSDKValueError: Shadow registers offset is not set while base address is available.
        :return: Absolute address of shadow registers, or None if base address is not set.
        """
        if self.shadow_register_base_addr is None:
            return None
        if self.shadow_register_offset is None:
            raise SPSDKValueError("Shadow registers offset is not set.")
        return self.shadow_register_base_addr + self.shadow_register_offset

    def set_value(self, val: Any, raw: bool = False) -> None:
        """Set the new value of register.

        The method validates the input value fits within the register width and handles
        endianness conversion if reverse mode is enabled. For group registers, it also
        updates all sub-registers with appropriate bit portions of the value.

        :param val: The new value to set (integer or convertible to integer).
        :param raw: Do not use any modification hooks if True.
        :raises SPSDKError: When invalid value is loaded into register or value exceeds
            register width.
        """
        super().set_value(val, raw)
        if not raw and self.computed_hooks:
            self.compute_register()
        if self.antipole_register:
            antipole_val = self.get_antipole_value()
            if antipole_val != self.antipole_register.get_value(raw=True):
                self.antipole_register.set_value(antipole_val, raw=True)
                logger.debug(
                    f"The {self.antipole_register.name} register has been used to compute antipole value,"
                    f"and it has been used in {self.name}."
                )

    def get_antipole_value(self) -> int:
        """Antipolize given registers by applying bitwise XOR with 0xFFFFFFFF.

        This method takes the value from the source register and applies bitwise NOT operation
        (XOR with 0xFFFFFFFF) to create an antipole value, which is then set to the destination
        register.
        """
        return self.get_value(True) ^ 0xFFFFFFFF

    def compute_register(self) -> None:
        """Recalculate register value using specified computation method.

        The method dynamically calls the specified computation function to update the register's value.
        The computation method must exist as an attribute of the current object.

        :raises SPSDKError: When the specified computing routine is not found.
        """
        if not self.computed_hooks:
            return
        for hook in self.computed_hooks:
            if hasattr(self, hook):
                method_ref = getattr(self, hook)
                self.set_value(method_ref(self.get_value(True)), raw=True)
                logger.debug(
                    f"The {self.name} register has been recomputed to value: {self.get_value()}"
                )
            else:
                raise SPSDKError(f"The '{hook}' compute function doesn't exists.")

    @staticmethod
    def crc_update(data: bytes, crc: int = 0, is_final: bool = True) -> int:
        """Compute CRC8 ITU checksum from given bytes.

        The function implements CRC8 ITU algorithm with polynomial 0x07 and final XOR value 0x55.
        Supports incremental CRC calculation for large data processing.

        :param data: Input data bytes to compute CRC checksum.
        :param crc: Initial CRC seed value for incremental calculation.
        :param is_final: Flag indicating whether to apply final XOR transformation.
        :return: Computed CRC8 checksum value.
        """
        k = 0
        data_len = len(data)
        while data_len != 0:
            data_len -= 1
            carry = data[k]
            k += 1
            for i in range(8):
                bit = (crc & 0x80) != 0
                if (carry & (0x80 >> i)) != 0:
                    bit = not bit
                crc <<= 1
                if bit:
                    crc ^= 0x07
            crc &= 0xFF
        if is_final:
            return (crc & 0xFF) ^ 0x55
        return crc & 0xFF

    @staticmethod
    def comalg_dcfg_cc_socu_crc8(val: int) -> int:
        """Compute CRC8 for DCFG_CC_SOCU register value.

        This function extracts the upper 24 bits of the input value, computes a CRC8
        checksum over those bytes, and replaces the lower 8 bits with the computed CRC.

        :param val: Input DCFG_CC_SOCU register value (32-bit integer).
        :return: DCFG_CC_SOCU value with CRC8 field in the lower 8 bits.
        """
        in_val = bytearray(3)
        for i in range(3):
            in_val[i] = (val >> (8 + i * 8)) & 0xFF
        val &= ~0xFF
        val |= FuseRegister.crc_update(in_val)
        return val

    def comalg_dcfg_cc_socu_test_en(self, val: int) -> int:
        """Configure DCFG_CC_SOCU register with appropriate test mode setting.

        The method modifies the DEV_TEST_EN bit in DCFG_CC_SOCU register based on the current
        fuse mode to satisfy MCU operational requirements.

        :param val: Input DCFG_CC_SOCU register value to be modified.
        :return: Modified DCFG_CC_SOCU value with test mode bit configured appropriately.
        """
        if self.shadow_mode:
            return val | 0x80000000
        return val & ~0x80000000


class FuseRegisters(_RegistersBase[FuseRegister]):
    """SPSDK Fuse Registers Manager.

    This class manages fuse register configurations for NXP MCU devices, providing
    functionality to load, validate, and manipulate fuse register data including
    shadow register handling and lock management.

    :cvar register_class: Class type used for individual fuse registers.
    """

    register_class = FuseRegister
    FEATURE = DatabaseManager.FUSES

    def __init__(
        self,
        family: FamilyRevision,
        base_key: Optional[Union[list[str], str]] = None,
        base_endianness: Endianness = Endianness.BIG,
        just_standard_library_data: bool = False,
    ) -> None:
        """Initialize fuse registers for a specific MCU family.

        Sets up the fuse registers configuration by loading the appropriate database
        for the specified family and configuring the base parameters for register access.

        :param family: MCU family and revision specification for fuse configuration.
        :param base_key: Optional key or list of keys for database access, defaults to None.
        :param base_endianness: Byte order for register data interpretation, defaults to BIG.
        :param just_standard_library_data: Use only standard library data if True, defaults to False.
        """
        self.shadow_reg_base_addr: Optional[int] = None
        self.db = get_db(family)
        self.computed_fields: dict[str, dict[str, str]] = self.db.get_dict(
            self.FEATURE, "computed_fields", {}
        )
        self.antipole_regs: dict[str, str] = self.db.get_dict(self.FEATURE, "inverted_regs", {})
        super().__init__(
            family,
            self.FEATURE,
            base_key,
            base_endianness,
            just_standard_library_data,
        )

    def _load_from_spec(
        self,
        config: dict[str, Any],
        grouped_regs: Optional[list[dict]] = None,
        reg_spec_modifications: Optional[dict[str, dict]] = None,
        deprecated_regs: Optional[dict[str, dict[str, Any]]] = None,
    ) -> None:
        """Load registers from specification.

        The method loads register configuration and sets up shadow register base addresses
        if specified in the configuration. It also updates register locks after loading.

        :param config: Register configuration dictionary containing register specifications.
        :param grouped_regs: List of register groups for organizing registers.
        :param reg_spec_modifications: Dictionary with additional register specifications
            for modifying default register behavior.
        :param deprecated_regs: Dictionary containing deprecated register definitions
            with their replacement information.
        """
        super()._load_from_spec(config, grouped_regs, reg_spec_modifications, deprecated_regs)
        if "shadow_reg_base_addr_int" in config:
            self.shadow_reg_base_addr = value_to_int(config["shadow_reg_base_addr_int"])
            for reg in self._registers:
                reg.shadow_register_base_addr = self.shadow_reg_base_addr
                if reg.has_group_registers():
                    for sub_reg in reg.sub_regs:
                        sub_reg.shadow_register_base_addr = self.shadow_reg_base_addr
        # set antipole register handlers
        for src_uid, dst_uid in self.antipole_regs.items():
            src_reg = self.get_reg(src_uid)
            dst_reg = self.get_reg(dst_uid)
            src_reg.antipole_register = dst_reg
            dst_reg.reserved = True
        # set computed registers hooks
        for reg_uid, bitfields_rec in self.computed_fields.items():
            reg = self.get_reg(reg_uid)
            for bitfield_uid, method in bitfields_rec.items():
                reg.computed_hooks.append(method)
                reg.get_bitfield(bitfield_uid).reserved = True
        self.update_locks()

    def load_from_config(self, config: Config) -> None:
        """Load configuration from YML file.

        The method processes register values from configuration data, taking into account
        restricted data sources and different naming conventions compared to standard
        embedded database entries. After loading, it automatically updates register locks.

        :param config: Configuration data containing register values and settings.
        """
        for reg_uid, bitfields_rec in self.computed_fields.items():
            reg = self.get_reg(reg_uid)
            if reg.name in config:
                for bitfield_uid in bitfields_rec.keys():
                    bitfield = reg.get_bitfield(bitfield_uid)
                    if not isinstance(config[reg.name], dict) or bitfield.name in config[reg.name]:
                        hook_name = bitfields_rec[bitfield_uid]
                        if hook_name in reg.computed_hooks:
                            reg.computed_hooks.remove(hook_name)
                            logger.debug(
                                f"Calculated hook {hook_name} has been removed as the bitfield "
                                f"{bitfield_uid} value is defined explicitly"
                            )
        for src_uid, dst_uid in self.antipole_regs.items():
            src_reg = self.get_reg(src_uid)
            dst_reg = self.get_reg(dst_uid)
            if dst_reg.name in config:
                logger.debug(
                    f"The antipole register {dst_reg.name} was removed from {src_reg.name} as it was defined explicitly"
                )
                src_reg.antipole_register = None
        super().load_from_config(config)
        self.update_locks()

    def update_locks(self) -> None:
        """Update locks on all registers.

        Iterates through all fuse registers and updates their lock status based on the
        corresponding lock register values. For each register, checks read, write, and
        operation lock masks against the actual lock register values to determine if
        the register should be locked or unlocked.
        """
        for lock_type, lock_register_attr in {
            FuseLock.READ_LOCK: "read_lock_mask",
            FuseLock.WRITE_LOCK: "write_lock_mask",
            FuseLock.OPERATION_LOCK: "operation_lock_mask",
        }.items():
            for reg in self:
                lock_reg = self.get_lock_fuse(reg)
                if lock_reg:
                    lock_mask = getattr(reg.fuse_lock_register, lock_register_attr)
                    if lock_mask is not None:
                        locked = (
                            lock_reg.get_value()
                            & getattr(reg.fuse_lock_register, lock_register_attr)
                        ) != 0
                        lock_func = reg.lock if locked else reg.unlock
                        lock_func(lock_type)

    def get_lock_fuses(self) -> list[FuseRegister]:
        """Get list of lock fuses.

        Lock fuses are used to control the access to other fuses. This method iterates through all
        fuses and collects their corresponding lock fuses, removing duplicates from the result.

        :return: List of unique lock fuse registers that control access to other fuses.
        """
        lock_fuses = []
        for fuse in self:
            lock_fuse = self.get_lock_fuse(fuse)
            if lock_fuse:
                lock_fuses.append(lock_fuse)
        return list(set(lock_fuses))

    def is_lock_fuse(self, reg: FuseRegister) -> bool:
        """Check if a fuse register is a lock fuse.

        A lock fuse is a register that controls access (read/write/operation locks)
        to other fuse registers in the system.

        :param reg: Fuse register to check.
        :return: True if the register is a lock fuse, False otherwise.
        """
        lock_fuses = self.get_lock_fuses()
        return reg in lock_fuses

    def get_by_otp_index(self, otp_index: int) -> FuseRegister:
        """Get fuse register by OTP index.

        Searches through all fuse registers and their sub-registers to find the one
        matching the specified OTP index.

        :param otp_index: The OTP index to search for.
        :raises SPSDKRegsErrorRegisterNotFound: When no fuse register with the specified
            OTP index is found.
        :return: The fuse register with the matching OTP index.
        """
        for fuse in self:
            if fuse.otp_index == otp_index:
                return fuse
            if fuse.has_group_registers():
                for subreg in fuse.sub_regs:
                    if subreg.otp_index == otp_index:
                        return subreg
        raise SPSDKRegsErrorRegisterNotFound(
            f"The fuse with {otp_index} is not found in loaded registers for {self.family} device."
        )

    def get_lock_fuse(self, fuse: Union[str, FuseRegister]) -> Optional[FuseRegister]:
        """Get the lock fuse of a fuse with given name.

        :param fuse: Fuse name or the fuse register itself.
        :return: Lock fuse register if exists, None otherwise.
        """
        if isinstance(fuse, str):
            fuse = self.find_reg(fuse, include_group_regs=True)
        assert isinstance(fuse, FuseRegister)
        if not fuse.fuse_lock_register:
            return None
        return self.find_reg(fuse.fuse_lock_register.register_id, include_group_regs=True)


def print_register_info(
    fuse_register: FuseRegister, rich: bool = False, print_func: Callable[[str], None] = print
) -> None:
    """Print info about a fuse register.

    :param fuse_register: Fuse register to be printed
    :param rich: Print additional information
    :param print_func: Function for output messages, defaults to print.
    """
    print_func(f"Name:        {fuse_register.name}")
    if fuse_register.otp_index is not None:  # all non-grouped registers
        print_func(f"OTP index:   {hex(fuse_register.otp_index)}")
    value = fuse_register.get_hex_value()
    print_func(f"Value:       {fuse_register.get_hex_value()}")
    print_func(f"Access:      {fuse_register.access.description}")
    locks = fuse_register.get_active_locks()
    print_func(f"Locks:       {','.join([lock.label for lock in locks]) if locks else 'No locks'}")
    if value != fuse_register.get_hex_value(raw=True):
        print_func(f"Raw value:   {fuse_register.get_hex_value(raw=True)}")
    if rich:
        print_func(f"Description: {fuse_register.description}")
        print_func(f"Width:       {fuse_register.width} bits")
        if fuse_register.get_bitfields():
            print_func("Bitfields:")
            for bitfield in fuse_register.get_bitfields():
                bf_value = bitfield.get_value()
                print_func(f"  - {bitfield.name}:")
                print_func(f"      Offset: {bitfield.offset}")
                print_func(f"      Width:  {bitfield.width} bits")
                print_func(f"      Value:  {hex(bf_value)} ({bf_value})")
                if bitfield.description:
                    print_func(f"      Description: {bitfield.description}")
