#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""HAB Unlock command implementations for various hardware engines.

This module provides classes to create and manage unlock commands for different
hardware engines such as CAAM, SNVS, and OCOTP in the HAB (High Assurance Boot)
context. It includes feature enumerations and command classes for unlocking
specific hardware capabilities.
"""

from struct import pack, unpack_from
from typing import Iterator, Optional, Type, Union

from typing_extensions import Self

from spsdk.exceptions import SPSDKKeyError
from spsdk.image.hab.commands.commands import CmdBase
from spsdk.image.hab.constants import CmdName, CmdTag, EngineEnum
from spsdk.image.hab.hab_header import CmdHeader
from spsdk.utils.config import Config
from spsdk.utils.spsdk_enum import SpsdkEnum


class UnlockCAAMFeaturesEnum(SpsdkEnum):
    """SPSDK Enum for CAAM unlock features configuration.

    This enumeration defines the available features that can be unlocked
    in the Cryptographic Acceleration and Assurance Module (CAAM) during
    HAB unlock operations.
    """

    MID = (1, "MID", "Leaves Job Ring and DECO master ID registers unlocked")
    RNG = (2, "RNG", "Leave RNG uninitialized.")
    MFG = (4, "MFG", "Keep manufacturing protection private key in CAAM internal memory.")


class CmdUnlockBase(CmdBase):
    """HAB unlock engine command for secure peripheral access.

    Abstract base class for Hardware Abstraction Layer unlock commands that enable
    access to secured engine peripherals. The command structure varies based on the
    target engine type and includes optional features and unique identifiers.

    +-------------+--------------+--------------+
    |     tag     |      len     |     eng      |
    +-------------+--------------+--------------+
    |                   [val]                   |
    +-------------------------------------------+
    |                     .                     |
    +-------------------------------------------+

    :cvar CMD_TAG: Command tag identifier for unlock operations.
    """

    CMD_TAG = CmdTag.UNLK

    def __init__(self, engine: EngineEnum = EngineEnum.ANY, features: int = 0, uid: int = 0):
        """Initialize HAB Unlock command.

        Creates a new unlock command instance with specified engine, features, and unique identifier.
        The command length is automatically adjusted based on whether a UID is required.

        :param engine: Engine type to be unlocked, defaults to ANY engine
        :param features: Engine-specific feature flags to unlock
        :param uid: Unique identifier required by certain engine/feature combinations
        """
        super().__init__(engine.tag, length=8)
        self.features = features
        self.uid = uid
        if self._need_uid:
            self._header.length += 8

    @classmethod
    def get_unlock_class(cls, engine: EngineEnum) -> Type["CmdUnlockBase"]:
        """Get unlock class based on the engine type.

        Factory method that returns the appropriate unlock command class for the specified
        cryptographic engine type.

        :param engine: The engine type to get unlock class for.
        :raises SPSDKKeyError: Unknown or unsupported unlock engine type.
        :return: Unlock command class corresponding to the engine type.
        """
        unlock_classes: dict[EngineEnum, Type["CmdUnlockBase"]] = {
            EngineEnum.CAAM: CmdUnlockCAAM,
            EngineEnum.SNVS: CmdUnlockSNVS,
            EngineEnum.OCOTP: CmdUnlockOCOTP,
        }
        if engine not in unlock_classes:
            raise SPSDKKeyError(f"Unknown unlock engine: {engine}")
        return unlock_classes[engine]

    def __iter__(self) -> Iterator[int]:
        """Make iterator for the command.

        :return: Iterator over command bytes.
        """
        return self.__iter__()

    def __repr__(self) -> str:
        """Return string representation of the HAB Unlock command.

        The representation includes the class name, engine description, features, and UID
        for debugging and logging purposes.

        :return: String representation in format 'ClassName <engine_desc, features, uid>'.
        """
        return f"{self.__class__.__name__} <{self.engine.description}, {self.features}, {self.uid}>"

    @property
    def engine(self) -> EngineEnum:
        """Get the engine to be unlocked.

        The term `engine` denotes a peripheral involved in one or more of the following functions:
        - cryptographic computation
        - security state management
        - security alarm handling
        - access control

        :return: Engine enumeration value representing the engine to be unlocked.
        """
        return EngineEnum.from_tag(self._header.param)

    def __str__(self) -> str:
        """Get string representation of the unlock command.

        Provides a formatted text description including the command type and engine details.

        :return: Formatted string describing the unlock command and its engine.
        """
        msg = super().__str__()
        msg += f"Unlock Command ({self.__class__.__name__})\n"
        msg += f"Engine : {self.engine.description}\n"
        return msg

    @property
    def _need_uid(self) -> bool:
        """Return True if given Engine and Feature requires UID.

        This method checks whether the current engine and features combination
        requires a UID (Unique Identifier) for proper operation.

        :return: True if UID is required, False otherwise.
        """
        return self.need_uid(self.engine, self.features)

    @staticmethod
    def need_uid(engine: EngineEnum, features: int) -> bool:
        """Return True if given Engine and Feature requires UID.

        Determines whether a specific engine type and feature combination requires a UID (Unique Identifier)
        for proper operation. Currently supports OCOTP engine with specific feature flags.

        :param engine: The engine type to check for UID requirement.
        :param features: Feature flags as integer bitmask to evaluate.
        :return: True if the engine and features combination requires UID, False otherwise.
        """
        overall_condition = False
        ocotp_condition = engine == EngineEnum.OCOTP and bool(features & 0b1101)
        overall_condition |= ocotp_condition
        return overall_condition

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse binary data into an Unlock command object.

        Deserializes binary representation of HAB unlock command into appropriate
        command object based on the engine type specified in the header.

        :param data: Binary data to be parsed into unlock command.
        :return: Parsed unlock command object (CmdUnlockSNVS, CmdUnlockCAAM,
                 CmdUnlockOCOTP, or generic unlock command).
        """
        header = CmdHeader.parse(data, CmdTag.UNLK.tag)
        features = unpack_from(">L", data, header.size)[0]
        engine = EngineEnum.from_tag(header.param)
        uid = 0
        if cls.need_uid(engine, features):
            uid = unpack_from(">Q", data, header.size + 4)[0]
        if engine == EngineEnum.SNVS:
            return CmdUnlockSNVS(features)  # type: ignore
        if engine == EngineEnum.CAAM:
            return CmdUnlockCAAM(features)  # type: ignore
        if engine == EngineEnum.OCOTP:
            return CmdUnlockOCOTP(features, uid)  # type: ignore
        return cls(engine, features, uid)

    def export(self) -> bytes:
        """Export command to binary form for serialization.

        Converts the unlock command instance into its binary representation by packing
        the features field and optionally the UID field based on internal requirements.

        :return: Binary representation of the unlock command.
        """
        raw_data = super().export()
        data = pack(">L", self.features)
        raw_data += data
        if self._need_uid:
            raw_data += pack(">Q", self.uid)
        return raw_data


class UnlockOCOTPFeaturesEnum(SpsdkEnum):
    """SPSDK enumeration for HAB Unlock command OCOTP features.

    This enumeration defines the available features that can be unlocked
    in OCOTP (One-Time Programmable) memory through HAB unlock operations.
    Each feature represents a specific security or functional capability
    that can be selectively unlocked during device provisioning.
    """

    FIELD_RETURN = (1, "FIELD RETURN", "Leave Field Return activation unlocked.")
    SRK_REVOKE = (2, "SRK REVOKE", "Leave SRK revocation unlocked.")
    SCS = (4, "SCS", "Leave SCS register unlocked.")
    JTAG = (8, "JTAG", "Unlock JTAG using SCS HAB_JDE bit.")


class CmdUnlockOCOTP(CmdUnlockBase):
    """HAB Unlock command for On-Chip One-Time Programmable memory (fuses).

    This command manages unlock operations for OCOTP memory features including
    field return activation, SRK revocation, SCS register access, and JTAG
    functionality. It provides granular control over which OCOTP features
    remain unlocked after HAB authentication.
    """

    def __init__(self, features: Union[int, UnlockOCOTPFeaturesEnum] = 0, uid: int = 0):
        """Initialize OCOTP unlock command.

        Creates a new unlock command instance with specified features and unique identifier
        for OCOTP (One-Time Programmable) memory operations.

        :param features: Mask of FEATURE_UNLOCK_x constants or UnlockOCOTPFeaturesEnum value,
            defaults to 0
        :param uid: Unique ID required by some engine/feature combinations, defaults to 0
        """
        super().__init__(
            EngineEnum.OCOTP, features if isinstance(features, int) else features.tag, uid=uid
        )

    @property
    def _need_uid(self) -> bool:
        """Return True if given Engine and Feature requires UID.

        This method checks if any of the unlock fields (unlock_fld_rtn, unlock_csc,
        or unlock_jtag) are set, indicating that a UID is required for the unlock
        operation.

        :return: True if UID is required for unlock operation, False otherwise.
        """
        return self.unlock_fld_rtn or self.unlock_csc or self.unlock_jtag

    @property
    def unlock_fld_rtn(self) -> bool:
        """Check if Field Return activation should remain unlocked.

        This method examines the unlock features to determine whether the Field Return
        activation should be left in an unlocked state.

        :return: True if Field Return activation should remain unlocked, False otherwise.
        """
        return self.features & UnlockOCOTPFeaturesEnum.FIELD_RETURN.tag != 0

    @property
    def unlock_srk_rvk(self) -> bool:
        """Check if SRK revocation is left unlocked.

        This method verifies whether the SRK (Super Root Key) revocation feature
        is configured to remain unlocked by checking the corresponding bit in the
        features field.

        :return: True if SRK revocation is unlocked, False otherwise.
        """
        return self.features & UnlockOCOTPFeaturesEnum.SRK_REVOKE.tag != 0

    @property
    def unlock_csc(self) -> bool:
        """Check if SCS register should remain unlocked.

        This method determines whether the SCS (Secure Configuration State) register
        should be left in an unlocked state based on the configured features.

        :return: True if SCS register should remain unlocked, False otherwise.
        """
        return self.features & UnlockOCOTPFeaturesEnum.SCS.tag != 0

    @property
    def unlock_jtag(self) -> bool:
        """Check if JTAG unlock feature is enabled.

        Verifies whether the JTAG unlock functionality is available by checking
        the JTAG bit in the unlock features bitmask against SCS HAB_JDE bit.

        :return: True if JTAG unlock is supported, False otherwise.
        """
        return self.features & UnlockOCOTPFeaturesEnum.JTAG.tag != 0

    def __str__(self) -> str:
        """Get text description of the unlock command.

        Returns a formatted string containing the unlock command details including
        field return, SRK revocation, CSC, JTAG settings, and optionally the UID
        if present.

        :return: Formatted string representation of the unlock command.
        """
        msg = super().__str__()
        msg += f"FLD_RTN : {self.unlock_fld_rtn}\n"
        msg += f"SRK_RVK : {self.unlock_srk_rvk}\n"
        msg += f"CSC     : {self.unlock_csc}\n"
        msg += f"JTAG    : {self.unlock_jtag}\n"
        if self.uid:
            msg += f"UID : {hex(self.uid)}\n"
        return msg


class CmdUnlockCAAM(CmdUnlockBase):
    """HAB command for unlocking CAAM (Cryptographic Acceleration and Assurance Module) features.

    This command allows selective unlocking of specific CAAM hardware features including
    Job Ring and DECO master ID registers, RNG instantiation control, and Master Key
    write operations. The unlock configuration is controlled through feature flags
    that determine which CAAM components remain accessible after the unlock operation.
    """

    def __init__(self, features: Union[int, UnlockCAAMFeaturesEnum] = 0):
        """Initialize CAAM unlock command.

        Creates a new unlock command instance for CAAM engine with specified features.

        :param features: Mask of unlock features or UnlockCAAMFeaturesEnum value, defaults to 0
        """
        super().__init__(EngineEnum.CAAM, features if isinstance(features, int) else features.tag)

    @property
    def unlock_mid(self) -> bool:
        """Check if Job Ring and DECO master ID registers should remain unlocked.

        This method examines the unlock features to determine whether the Job Ring
        and DECO master ID registers are configured to stay unlocked.

        :return: True if master ID registers should remain unlocked, False otherwise.
        """
        return self.features & UnlockCAAMFeaturesEnum.MID.tag != 0

    @property
    def unlock_rng(self) -> bool:
        """Check if RNG (Random Number Generator) should be left un-instantiated.

        This method examines the unlock features to determine whether the RNG
        should remain un-instantiated in the CAAM (Cryptographic Acceleration
        and Assurance Module).

        :return: True if RNG should be left un-instantiated, False otherwise.
        """
        return self.features & UnlockCAAMFeaturesEnum.RNG.tag != 0

    @property
    def unlock_mfg(self) -> bool:
        """Check if Master Key write is unlocked in manufacturing mode.

        This method examines the MFG feature flag to determine whether the Master Key
        write operation remains unlocked, allowing manufacturing operations to proceed.

        :return: True if Master Key write is unlocked, False otherwise.
        """
        return self.features & UnlockCAAMFeaturesEnum.MFG.tag != 0

    def __str__(self) -> str:
        """Get string representation of the unlock command.

        This method provides a formatted text description of the unlock command,
        including the MID (Manufacturing ID), RNG (Random Number Generator), and
        MFG (Manufacturing) values.

        :return: Formatted string containing command details with MID, RNG, and MFG values.
        """
        msg = super().__str__()
        msg += f"MID : {self.unlock_mid}\n"
        msg += f"RNG : {self.unlock_rng}\n"
        msg += f"MFG : {self.unlock_mfg}\n"
        return msg


class UnlockSNVSFeaturesEnum(SpsdkEnum):
    """SNVS unlock features enumeration for HAB commands.

    This enumeration defines the available features that can be unlocked
    in the Secure Non-Volatile Storage (SNVS) through HAB unlock commands.
    """

    LP_SWR = (1, "LP SWR", "Leaves LP SW reset unlocked")
    ZMK_WRITE = (2, "ZMK WRITE", "Leaves Zero-able Master Key write unlocked.")


class CmdUnlockSNVS(CmdUnlockBase):
    """HAB command for unlocking Secure Non-Volatile Storage (SNVS) engine features.

    This command allows selective unlocking of SNVS engine functionality including
    LP software reset and Zero Master Key write operations. It extends the base
    unlock command functionality with SNVS-specific feature management.
    """

    def __init__(self, features: Union[int, UnlockSNVSFeaturesEnum] = 0) -> None:
        """Initialize SNVS unlock command.

        :param features: Mask of unlock features, either as integer or UnlockSNVSFeaturesEnum value.
        """
        super().__init__(EngineEnum.SNVS, features if isinstance(features, int) else features.tag)

    @property
    def unlock_lp_swr(self) -> bool:
        """Check if LP SW reset should remain unlocked.

        This method examines the unlock features to determine whether the Low Power
        Software Reset (LP SWR) should be left in an unlocked state.

        :return: True if LP SW reset should remain unlocked, False otherwise.
        """
        return self.features & UnlockSNVSFeaturesEnum.LP_SWR.tag != 0

    @property
    def unlock_zmk_write(self) -> bool:
        """Check if Zero Master Key write is unlocked.

        :return: True if ZMK write is unlocked, False otherwise.
        """
        return self.features & UnlockSNVSFeaturesEnum.ZMK_WRITE.tag != 0

    def __str__(self) -> str:
        """Get text description of the unlock command.

        Returns a formatted string representation of the unlock command including
        the status of LP SWR unlock and ZMK write unlock flags.

        :return: Formatted string description of the unlock command.
        """
        msg = super().__str__()
        msg += f"Unlock LP SWR    : {self.unlock_lp_swr}\n"
        msg += f"Unlock ZMK Write : {self.unlock_zmk_write}\n"
        return msg


class CmdUnlockAny(CmdUnlockBase):
    """HAB unlock command for generic engine operations.

    This class implements a generic unlock command that can be used with any
    HAB engine type, providing flexibility for unlocking operations with
    configurable features and unique identifiers.
    """

    def __init__(self, engine: EngineEnum = EngineEnum.ANY, features: int = 0, uid: int = 0):
        """Initialize HAB Unlock command.

        Creates a new unlock command instance with specified engine, features mask,
        and unique identifier for HAB (High Assurance Boot) operations.

        :param engine: Engine type to be unlocked, defaults to ANY engine.
        :param features: Bitmask defining which features the engine should use.
        :param uid: Unique identifier for the unlock operation, defaults to 0.
        """
        super().__init__(engine, features, uid=uid)

    def __str__(self) -> str:
        """Get text description of the unlock command.

        Returns a formatted string containing the command details including
        features and UID information.

        :return: Formatted string representation of the unlock command.
        """
        msg = super().__str__()
        msg += f"Features: {self.features}\n"
        msg += f"UID:      {self.uid}\n"
        return msg


class CmdUnlock(CmdUnlockBase):
    """HAB unlock engine command implementation.

    This class provides a concrete implementation of the HAB unlock command,
    supporting configuration-based initialization and feature/UID calculations
    for unlocking specific hardware engines in NXP MCUs.

    :cvar CMD_IDENTIFIER: Command identifier for unlock operations.
    """

    CMD_IDENTIFIER = CmdName.UNLOCK

    @classmethod
    def load_from_config(cls, config: Config, cmd_index: Optional[int] = None) -> Self:
        """Load configuration into the unlock command.

        Creates an unlock command instance from the provided HAB image configuration by parsing
        the unlock engine type, features, and UID values from the configuration data.

        :param config: HAB image configuration containing unlock command settings.
        :param cmd_index: Optional index of the command in the configuration in case multiple
            same commands are present.
        :return: Configured unlock command instance.
        """
        cmd_cfg = cls._get_cmd_config(config, cmd_index)
        unlock_engine = EngineEnum.from_label(cmd_cfg["Unlock_Engine"])
        klass = CmdUnlockBase.get_unlock_class(unlock_engine)
        kwargs = {}
        unlock_features = cmd_cfg.get("Unlock_Features")
        if unlock_features is not None:
            features_class = CMD_TO_FEATURE[klass]
            # can be a coma separated list or the actual list
            features_str: list = (
                unlock_features.split(",") if isinstance(unlock_features, str) else unlock_features
            )
            features = [features_class.from_label(feature).tag for feature in features_str]

            kwargs["features"] = cls.calc_features_value(features)
        unlock_uid: str = cmd_cfg.get("Unlock_UID")
        if unlock_uid:
            # can be a coma separated list or the actual list
            uids: list[int] = (
                [int(uid.strip(), 0) for uid in unlock_uid.split(",")]
                if isinstance(unlock_uid, str)
                else unlock_uid
            )
            kwargs["uid"] = cls.calc_uid(uids)
        cmd = klass(**kwargs)  # type: ignore
        return cmd  # type: ignore

    @classmethod
    def calc_features_value(cls, features: list[int]) -> int:
        """Calculate the unlock features value.

        This method performs a bitwise OR operation on all feature values in the provided
        list to combine them into a single unlock features value.

        :param features: List of integer feature values to be combined.
        :return: Combined features value as a single integer.
        """
        result = 0
        for feature in features:
            result |= feature
        return result

    @classmethod
    def calc_uid(cls, uid_values: list[int]) -> int:
        """Calculate the unlock UID value from a list of UID components.

        This method combines multiple UID values into a single integer by shifting each value
        8 bits to the left and performing a bitwise OR operation.

        :param uid_values: List of integer UID components to be combined.
        :return: Combined UID value as a single integer.
        """
        result = 0
        for uid in uid_values:
            result = (result << 8) | uid
        return result


CMD_TO_FEATURE = {
    CmdUnlockOCOTP: UnlockOCOTPFeaturesEnum,
    CmdUnlockSNVS: UnlockSNVSFeaturesEnum,
    CmdUnlockCAAM: UnlockCAAMFeaturesEnum,
}
