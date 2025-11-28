#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK fuse registers management and operations.

This module provides comprehensive functionality for handling fuse registers,
including individual write locks, fuse locks, and register operations within
the SPSDK framework for NXP MCU provisioning.
"""

import logging
from dataclasses import dataclass
from typing import Any, Optional, Union

from typing_extensions import Self

from spsdk.exceptions import SPSDKKeyError, SPSDKValueError
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager
from spsdk.utils.exceptions import (
    SPSDKRegsErrorRegisterGroupMishmash,
    SPSDKRegsErrorRegisterNotFound,
)
from spsdk.utils.family import FamilyRevision
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
        """
        super().__init__(*args, **kwargs)
        self.individual_write_lock = individual_write_lock
        self.fuse_lock_register = fuse_lock_register
        self.otp_index = value_to_int(otp_index) if otp_index is not None else None
        self.shadow_register_offset = shadow_register_offset
        self.shadow_register_base_addr = shadow_register_base_addr
        self._locks: dict = {
            FuseLock.READ_LOCK: False,
            FuseLock.WRITE_LOCK: False,
            FuseLock.OPERATION_LOCK: False,
        }

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
            logger.debug(f"Fuse {self.name} has already lock set {lock_type.description}.")
            return
        self._locks[lock_type] = True

    def unlock(self, lock_type: FuseLock) -> None:
        """Unset the fuse lock.

        Removes the specified lock type from the fuse register. If the lock is already
        unset, the operation is logged and no changes are made.

        :param lock_type: Type of fuse lock to be removed.
        """
        if not self._locks[lock_type]:
            logger.debug(f"Fuse {self.name} has already lock unset {lock_type.description}.")
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


class FuseRegisters(_RegistersBase[FuseRegister]):
    """SPSDK Fuse Registers Manager.

    This class manages fuse register configurations for NXP MCU devices, providing
    functionality to load, validate, and manipulate fuse register data including
    shadow register handling and lock management.

    :cvar register_class: Class type used for individual fuse registers.
    """

    register_class = FuseRegister

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
        super().__init__(
            family,
            DatabaseManager.FUSES,
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
        self.update_locks()

    def load_from_config(self, config: Config) -> None:
        """Load configuration from YML file.

        The method processes register values from configuration data, taking into account
        restricted data sources and different naming conventions compared to standard
        embedded database entries. After loading, it automatically updates register locks.

        :param config: Configuration data containing register values and settings.
        """
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
