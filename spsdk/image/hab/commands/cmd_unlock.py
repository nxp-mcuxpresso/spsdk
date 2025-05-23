#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module containing HAB Unlock command implementations for various engines.

This module provides classes to create and manage unlock commands for different
hardware engines such as CAAM, SNVS, and OCOTP in the HAB (High Assurance Boot).
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
    """Enum definition for Unlock SNVS features."""

    MID = (1, "MID", "Leaves Job Ring and DECO master ID registers unlocked")
    RNG = (2, "RNG", "Leave RNG uninitialized.")
    MFG = (4, "MFG", "Keep manufacturing protection private key in CAAM internal memory.")


class CmdUnlockBase(CmdBase):
    """Abstract unlock engine command; the command depends on engine type.

    +-------------+--------------+--------------+
    |     tag     |      len     |     eng      |
    +-------------+--------------+--------------+
    |                   [val]                   |
    +-------------------------------------------+
    |                     .                     |
    +-------------------------------------------+
    """

    CMD_TAG = CmdTag.UNLK

    def __init__(self, engine: EngineEnum = EngineEnum.ANY, features: int = 0, uid: int = 0):
        """Constructor.

        :param engine: to be unlocked
        :param features: engine specific features
        :param uid: Unique ID required by some engine/feature combinations
        """
        super().__init__(engine.tag, length=8)
        self.features = features
        self.uid = uid
        if self._need_uid:
            self._header.length += 8

    @classmethod
    def get_unlock_class(cls, engine: EngineEnum) -> Type["CmdUnlockBase"]:
        """Get unlock class based on the engine type."""
        unlock_classes: dict[EngineEnum, Type["CmdUnlockBase"]] = {
            EngineEnum.CAAM: CmdUnlockCAAM,
            EngineEnum.SNVS: CmdUnlockSNVS,
            EngineEnum.OCOTP: CmdUnlockOCOTP,
        }
        if engine not in unlock_classes:
            raise SPSDKKeyError(f"Unknown unlock engine: {engine}")
        return unlock_classes[engine]

    def __iter__(self) -> Iterator[int]:
        return self.__iter__()

    def __repr__(self) -> str:
        return f"{self.__class__.__name__} <{self.engine.description}, {self.features}, {self.uid}>"

    @property
    def engine(self) -> EngineEnum:
        """Engine to be unlocked.

        The term `engine` denotes a peripheral involved in one or more of the following functions:
        - cryptographic computation
        - security state management
        - security alarm handling
        - access control
        """
        return EngineEnum.from_tag(self._header.param)

    def __str__(self) -> str:
        """Text description of the command."""
        msg = super().__str__()
        msg += f"Unlock Command ({self.__class__.__name__})\n"
        msg += f"Engine : {self.engine.description}\n"
        return msg

    @property
    def _need_uid(self) -> bool:
        """Return True if given Engine and Feature requires UID."""
        return self.need_uid(self.engine, self.features)

    @staticmethod
    def need_uid(engine: EngineEnum, features: int) -> bool:
        """Return True if given Engine and Feature requires UID."""
        overall_condition = False
        ocotp_condition = engine == EngineEnum.OCOTP and bool(features & 0b1101)
        overall_condition |= ocotp_condition
        return overall_condition

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Convert binary representation into command (deserialization from binary data).

        :param data: being parsed
        :return: Unlock command
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
        """Export to binary form (serialization).

        :return: binary representation of the command
        """
        raw_data = super().export()
        data = pack(">L", self.features)
        raw_data += data
        if self._need_uid:
            raw_data += pack(">Q", self.uid)
        return raw_data


class UnlockOCOTPFeaturesEnum(SpsdkEnum):
    """Enum definition for Unlock SNVS features."""

    FIELD_RETURN = (1, "FIELD RETURN", "Leave Field Return activation unlocked.")
    SRK_REVOKE = (2, "SRK REVOKE", "Leave SRK revocation unlocked.")
    SCS = (4, "SCS", "Leave SCS register unlocked.")
    JTAG = (8, "JTAG", "Unlock JTAG using SCS HAB_JDE bit.")


class CmdUnlockOCOTP(CmdUnlockBase):
    """Command Unlock for On-Chip One-time programmable memory (fuses)."""

    def __init__(self, features: Union[int, UnlockOCOTPFeaturesEnum] = 0, uid: int = 0):
        """Initialize.

        :param features: mask of FEATURE_UNLOCK_x constants, defaults to 0
        :param uid: Unique ID required by some engine/feature combinations
        """
        super().__init__(
            EngineEnum.OCOTP, features if isinstance(features, int) else features.tag, uid=uid
        )

    @property
    def _need_uid(self) -> bool:
        """Return True if given Engine and Feature requires UID."""
        return self.unlock_fld_rtn or self.unlock_csc or self.unlock_jtag

    @property
    def unlock_fld_rtn(self) -> bool:
        """Leave Field Return activation unlocked."""
        return self.features & UnlockOCOTPFeaturesEnum.FIELD_RETURN.tag != 0

    @property
    def unlock_srk_rvk(self) -> bool:
        """Leave SRK revocation unlocked."""
        return self.features & UnlockOCOTPFeaturesEnum.SRK_REVOKE.tag != 0

    @property
    def unlock_csc(self) -> bool:
        """Leave SCS register unlocked."""
        return self.features & UnlockOCOTPFeaturesEnum.SCS.tag != 0

    @property
    def unlock_jtag(self) -> bool:
        """Unlock JTAG using SCS HAB_JDE bit."""
        return self.features & UnlockOCOTPFeaturesEnum.JTAG.tag != 0

    def __str__(self) -> str:
        """Text description of the command."""
        msg = super().__str__()
        msg += f"FLD_RTN : {self.unlock_fld_rtn}\n"
        msg += f"SRK_RVK : {self.unlock_srk_rvk}\n"
        msg += f"CSC     : {self.unlock_csc}\n"
        msg += f"JTAG    : {self.unlock_jtag}\n"
        if self.uid:
            msg += f"UID : {hex(self.uid)}\n"
        return msg


class CmdUnlockCAAM(CmdUnlockBase):
    """Command Unlock for Cryptographic Acceleration and Assurance Module ."""

    def __init__(self, features: Union[int, UnlockCAAMFeaturesEnum] = 0):
        """Initialize.

        :param features: mask of FEATURE_UNLOCK_x constants, defaults to 0
        """
        super().__init__(EngineEnum.CAAM, features if isinstance(features, int) else features.tag)

    @property
    def unlock_mid(self) -> bool:
        """Leave Job Ring and DECO master ID registers unlocked."""
        return self.features & UnlockCAAMFeaturesEnum.MID.tag != 0

    @property
    def unlock_rng(self) -> bool:
        """Leave RNG un-instantiated."""
        return self.features & UnlockCAAMFeaturesEnum.RNG.tag != 0

    @property
    def unlock_mfg(self) -> bool:
        """Leave Zero is able Master Key write unlocked."""
        return self.features & UnlockCAAMFeaturesEnum.MFG.tag != 0

    def __str__(self) -> str:
        """Text description of the command."""
        msg = super().__str__()
        msg += f"MID : {self.unlock_mid}\n"
        msg += f"RNG : {self.unlock_rng}\n"
        msg += f"MFG : {self.unlock_mfg}\n"
        return msg


class UnlockSNVSFeaturesEnum(SpsdkEnum):
    """Enum definition for Unlock SNVS features."""

    LP_SWR = (1, "LP SWR", "Leaves LP SW reset unlocked")
    ZMK_WRITE = (2, "ZMK WRITE", "Leaves Zero-able Master Key write unlocked.")


class CmdUnlockSNVS(CmdUnlockBase):
    """Command Unlock Secure Non-Volatile Storage (SNVS) Engine."""

    def __init__(self, features: Union[int, UnlockSNVSFeaturesEnum] = 0) -> None:
        """Constructor.

        :param features: mask of FEATURE_UNLOCK_* constants
        """
        super().__init__(EngineEnum.SNVS, features if isinstance(features, int) else features.tag)

    @property
    def unlock_lp_swr(self) -> bool:
        """Leave LP SW reset unlocked."""
        return self.features & UnlockSNVSFeaturesEnum.LP_SWR.tag != 0

    @property
    def unlock_zmk_write(self) -> bool:
        """Leave Zero is able Master Key write unlocked."""
        return self.features & UnlockSNVSFeaturesEnum.ZMK_WRITE.tag != 0

    def __str__(self) -> str:
        """Text description of the command."""
        msg = super().__str__()
        msg += f"Unlock LP SWR    : {self.unlock_lp_swr}\n"
        msg += f"Unlock ZMK Write : {self.unlock_zmk_write}\n"
        return msg


class CmdUnlockAny(CmdUnlockBase):
    """Generic unlock engine command."""

    def __init__(self, engine: EngineEnum = EngineEnum.ANY, features: int = 0, uid: int = 0):
        """Constructor.

        :param engine: to be unlocked
        :param features: mask of features to use by the engine
        :param uid: Unique ID (if needed)
        """
        super().__init__(engine, features, uid=uid)

    def __str__(self) -> str:
        """Text description of the command."""
        msg = super().__str__()
        msg += f"Features: {self.features}\n"
        msg += f"UID:      {self.uid}\n"
        return msg


class CmdUnlock(CmdUnlockBase):
    """Unlock engine command."""

    CMD_IDENTIFIER = CmdName.UNLOCK

    @classmethod
    def load_from_config(cls, config: Config, cmd_index: Optional[int] = None) -> Self:
        """Load configuration into the command.

        :param config: HAB image configuration
        :param cmd_index: Optional index of the command in the configuration in case multiple same commands are present
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
        """Calculate the unlock features value."""
        result = 0
        for feature in features:
            result |= feature
        return result

    @classmethod
    def calc_uid(cls, uid_values: list[int]) -> int:
        """Calculate the unlock uid value."""
        result = 0
        for uid in uid_values:
            result = (result << 8) | uid
        return result


CMD_TO_FEATURE = {
    CmdUnlockOCOTP: UnlockOCOTPFeaturesEnum,
    CmdUnlockSNVS: UnlockSNVSFeaturesEnum,
    CmdUnlockCAAM: UnlockCAAMFeaturesEnum,
}
