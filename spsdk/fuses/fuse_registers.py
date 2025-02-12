#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module handling the operations on fuse registers."""

import logging
from dataclasses import dataclass
from typing import Any, Optional, Union

from typing_extensions import Self

from spsdk.exceptions import SPSDKKeyError, SPSDKValueError
from spsdk.utils.database import DatabaseManager
from spsdk.utils.exceptions import (
    SPSDKRegsErrorRegisterGroupMishmash,
    SPSDKRegsErrorRegisterNotFound,
)
from spsdk.utils.misc import Endianness, value_to_int
from spsdk.utils.registers import Register, _RegistersBase
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)


class IndividualWriteLock(SpsdkEnum):
    """Individual write lock enum."""

    NONE = (0, "none", "No individual lock for the register")
    USER = (1, "user", "User configurable lock")
    ALWAYS = (2, "always_lock", "Always generate lock after write")
    IMPLICIT = (3, "implicit", "Implicit lock")


class FuseLock(SpsdkEnum):
    """Fuse lock type enum."""

    WRITE_LOCK = (0, "write_lock", "Write lock")
    READ_LOCK = (1, "read_lock", "Read lock")
    OPERATION_LOCK = (2, "operation_lock", "Operation lock")


@dataclass
class FuseLockRegister:
    """Fuse lock register dataclass. Reference to the lock register and its settings."""

    register_id: str
    write_lock_mask: Optional[int]
    read_lock_mask: Optional[int]
    operation_lock_mask: Optional[int]

    def __eq__(self, obj: Any) -> bool:
        if not isinstance(obj, self.__class__):
            return False
        return (
            self.register_id == obj.register_id
            and self.write_lock_mask == obj.write_lock_mask
            and self.read_lock_mask == obj.read_lock_mask
            and self.operation_lock_mask == obj.operation_lock_mask
        )

    def __str__(self) -> str:
        """Object description in string format."""
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
    def load_from_config(cls, config: dict[str, Any]) -> Self:
        """Create object from given configuration.

        :param config: The configuration of fuse lock register.
        """
        try:
            register_id = config["register_id"]
        except KeyError as e:
            raise SPSDKKeyError("The 'register_id' must be defined") from e
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
        """Create configuration from this object."""
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
    """Single fuse register."""

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
        """Fuse register initialization.

        :param otp_index: Index of OTP fuse.
        :param shadow_register_offset: The optional shadow register offset.
        :param shadow_register_base_addr: The Shadow register base address.
        :param individual_write_lock: Individual write lock.
        :param fuse_lock_register: Fuse lock register configuration.
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
        """Is fuse register readable."""
        return self.access.is_readable and FuseLock.READ_LOCK not in self.get_active_locks()

    @property
    def is_writable(self) -> bool:
        """Is fuse register writeable."""
        return self.access.is_writable and FuseLock.WRITE_LOCK not in self.get_active_locks()

    def get_active_locks(self) -> list[FuseLock]:
        """Get list of active locks."""
        return [lock for lock, active in self._locks.items() if active]

    def lock(self, lock_type: FuseLock) -> None:
        """Set the fuse lock."""
        if self._locks[lock_type]:
            logger.debug(f"Fuse {self.name} has already lock set {lock_type.description}.")
            return
        self._locks[lock_type] = True

    def unlock(self, lock_type: FuseLock) -> None:
        """Unset the fuse lock."""
        if not self._locks[lock_type]:
            logger.debug(f"Fuse {self.name} has already lock unset {lock_type.description}.")
            return
        self._locks[lock_type] = False

    @classmethod
    def create_from_spec(cls, spec: dict[str, Any]) -> Self:
        """Initialization register by specification.

        :param spec: Input specification with register data.
        :return: The instance of this class.
        """
        reg = super().create_from_spec(spec)
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
            reg.fuse_lock_register = FuseLockRegister.load_from_config(spec["lock"])
        if "individual_write_lock" in spec:
            reg.individual_write_lock = IndividualWriteLock.from_label(
                spec["individual_write_lock"]
            )
        return reg

    def create_spec(self) -> dict[str, Any]:
        """Creates the register specification structure.

        :returns: The register specification.
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

        :param reg: Register member of this register group.
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
        return hash(self.uid)

    def __eq__(self, obj: Any) -> bool:
        """Compare if the objects has same settings."""
        if not isinstance(obj, self.__class__):
            return False
        return (
            super().__eq__(obj)
            and self.shadow_register_addr == obj.shadow_register_addr
            and self.otp_index == obj.otp_index
            and self.fuse_lock_register == obj.fuse_lock_register
        )

    def __str__(self) -> str:
        """Object description in string format.

        :return: Friendly looking string that describes the register.
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
        """The real offset of shadow registers.

        :return: Real offset of shadow register.
        """
        if self.shadow_register_base_addr is None:
            return None
        if self.shadow_register_offset is None:
            raise SPSDKValueError("Shadow registers offset is not set.")
        return self.shadow_register_base_addr + self.shadow_register_offset


class FuseRegisters(_RegistersBase[FuseRegister]):
    """Implementation of fuse registers."""

    register_class = FuseRegister

    def __init__(
        self,
        family: str,
        base_key: Optional[Union[list[str], str]] = None,
        revision: str = "latest",
        base_endianness: Endianness = Endianness.BIG,
        just_standard_library_data: bool = False,
    ) -> None:
        """Fuse registers initialization."""
        self.shadow_reg_base_addr: Optional[int] = None
        super().__init__(
            family,
            DatabaseManager.FUSES,
            base_key,
            revision,
            base_endianness,
            just_standard_library_data,
        )

    def _load_from_spec(
        self, config: dict[str, Any], grouped_regs: Optional[list[dict]] = None
    ) -> None:
        super()._load_from_spec(config, grouped_regs)
        if "shadow_reg_base_addr_int" in config:
            self.shadow_reg_base_addr = value_to_int(config["shadow_reg_base_addr_int"])
            for reg in self._registers:
                reg.shadow_register_base_addr = self.shadow_reg_base_addr
                if reg.has_group_registers():
                    for sub_reg in reg.sub_regs:
                        sub_reg.shadow_register_base_addr = self.shadow_reg_base_addr
        self.update_locks()

    def load_yml_config(self, data: dict[str, Any]) -> None:
        """The function loads the configuration from YML file.

        Note: It takes in count the restricted data and different names to standard data
        in embedded database.

        :param data: The data with register values.
        """
        super().load_yml_config(data)
        self.update_locks()

    def update_locks(self) -> None:
        """Update locks on all registers."""
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
        """Get list of lock fuses. Lock fuses are used to control the access to other fuses."""
        lock_fuses = []
        for fuse in self:
            lock_fuse = self.get_lock_fuse(fuse)
            if lock_fuse:
                lock_fuses.append(lock_fuse)
        return list(set(lock_fuses))

    def get_by_otp_index(self, otp_index: int) -> FuseRegister:
        """Get fuse by OTP index."""
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
        """
        if isinstance(fuse, str):
            fuse = self.find_reg(fuse, include_group_regs=True)
        assert isinstance(fuse, FuseRegister)
        if not fuse.fuse_lock_register:
            return None
        return self.find_reg(fuse.fuse_lock_register.register_id, include_group_regs=True)
