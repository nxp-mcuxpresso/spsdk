#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Utilities used by adapters."""

import logging
from dataclasses import dataclass
from typing import List, Literal, Optional, Set, Union, overload

from spsdk.crypto.certificate_management import X509NameConfig
from spsdk.mboot.interfaces.usb import RawHid, scan_usb
from spsdk.utils.database import Database
from spsdk.utils.misc import Timeout, value_to_int

from .. import TP_DATABASE, SPSDKTpError
from .tptarget_blhost import TpTargetBlHost

logger = logging.getLogger(__name__)


def sanitize_common_name(name_config: X509NameConfig) -> None:
    """Adjust the COMMON_NAME for TrustProvisioning purposes.

    Base common name will be AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-BB
    AA will be eventually replaced by UUID
    BB will be the certificate index (0-3)
    If the common name already contains some string, it will be used as a prefix
    """
    if isinstance(name_config, dict):
        subject_cn = name_config.get("COMMON_NAME") or ""
        assert isinstance(subject_cn, str)
        name_config["COMMON_NAME"] = subject_cn + 16 * "AA" + "-" + "BB"

    if isinstance(name_config, list):

        def find_item_index(config: List, item_key: str) -> int:
            for i, item in enumerate(config):
                assert isinstance(item, dict)
                if item_key in item:
                    return i
            return -1

        subject_cn_idx = find_item_index(name_config, "COMMON_NAME")
        if subject_cn_idx == -1:
            subject_cn = ""
        else:
            subject_cn = name_config[subject_cn_idx].get("COMMON_NAME") or ""
        subject_cn = subject_cn + 16 * "AA" + "-" + "BB"
        if subject_cn_idx == -1:
            name_config.append({"COMMON_NAME": subject_cn})
        else:
            name_config[subject_cn_idx] = {"COMMON_NAME": subject_cn}


def get_current_usb_paths() -> Set[bytes]:
    """Get paths to all NXP USB devices."""
    return {device.path for device in scan_usb()}


def detect_new_usb_path(
    initial_set: Optional[Set[bytes]] = None, timeout: int = 1000
) -> Optional[bytes]:
    """Return USB path to newly found NXP USB device.

    :param initial_set: Initial set of USB device paths, defaults to None
    :param timeout: Timeout in milliseconds for the device detection
    :raises SPSDKTpError: Unable to determine single USB device change in time
    :raises SPSDKTpError: Multiple USB devices detected at once
    :return: USB path to newly detected device, None in case no changes were detected
    """
    loc_timeout = Timeout(timeout=timeout, units="ms")
    previous_set = initial_set or set()
    while not loc_timeout.overflow():
        new_set = get_current_usb_paths()
        addition = new_set.difference(previous_set)
        logger.info(f"Additions: {addition}")
        previous_set = new_set
        if len(addition) > 1:
            raise SPSDKTpError("Multiple new usb devices detected at once!")
        if len(addition) == 1:
            return addition.pop()

    # when timeout passes and the USB paths set stays the same
    # this happens mostly on Windows under higher CPU load
    if initial_set == previous_set:
        logger.info("No changes were detected")
        return None

    raise SPSDKTpError("USB device detection malfunctioned")


def update_usb_path(tptarget: TpTargetBlHost, new_usb_path: Optional[bytes]) -> None:
    """Update USB path in TP target's MBoot USB."""
    if not isinstance(tptarget.mboot._device, RawHid):
        return
    if new_usb_path is None:
        return
    tptarget.mboot._device.path = new_usb_path


@dataclass
class TPFlags:
    """TrustProvisioning flags.

    TP flags are contained in 1 byte.
    [6-7]: Version of DIE ID certificate
    [4-5]: Version of the Key flags
    [1-3]: Reserved for future use
    [0]  : Use ProvData (SB3 file)
    """

    die_id_cert_version: int
    key_flags_version: int
    use_prov_data: bool

    @staticmethod
    def for_family(family: str) -> "TPFlags":
        """Create TPFlags for given chip family."""
        database = Database(TP_DATABASE)
        key_flags_version = value_to_int(
            database.get_device_value("key_flags_version", device=family, default=0),
        )
        die_id_cert_version = value_to_int(
            database.get_device_value("die_id_cert_version", device=family, default=0),
        )
        use_prov_data: bool = database.get_device_value("use_prov_data", device=family)
        return TPFlags(
            die_id_cert_version=die_id_cert_version,
            key_flags_version=key_flags_version,
            use_prov_data=use_prov_data,
        )

    @overload
    def export(self, as_bytes: Literal[True] = ...) -> bytes:
        ...

    @overload
    def export(self, as_bytes: Literal[False]) -> int:
        ...

    def export(self, as_bytes: bool = True) -> Union[bytes, int]:
        """Export TPFlags into bytes (or optionally into integer)."""
        flags = 0
        flags |= (self.die_id_cert_version & 0x03) << 6
        flags |= (self.key_flags_version & 0x03) << 4
        flags |= self.use_prov_data
        if as_bytes:
            return flags.to_bytes(length=1, byteorder="big")
        return flags

    @staticmethod
    def parse(flags: int) -> "TPFlags":
        """De-serialize TPFlags."""
        die_id_cert_version = (flags & 0xC0) >> 6
        key_flags_version = (flags & 0x30) >> 4
        use_prov_data = bool(flags & 0x01)
        return TPFlags(
            die_id_cert_version=die_id_cert_version,
            key_flags_version=key_flags_version,
            use_prov_data=use_prov_data,
        )


@dataclass
class OEMKeyFlags:
    """Flags for generating OEM keys used for OEM certificates."""

    oem_key_count: int
    use_ca_key: bool
    use_rtf_key: bool
    version: int

    @staticmethod
    def from_config(config_data: dict) -> "OEMKeyFlags":
        """Create OEMKeyFlags from configuration data."""
        family = config_data["family"]
        oem_id_count = config_data.get("oem_id_count", 0)
        key_flags_version = value_to_int(
            Database(TP_DATABASE).get_device_value("key_flags_version", device=family)
        )
        oem_id_ca_cert = config_data.get("oem_id_ca_cert_address", 0)
        oem_id_rtf_cert = config_data.get("oem_id_rtf_cert_address", 0)

        return OEMKeyFlags(
            oem_key_count=oem_id_count,
            use_ca_key=bool(oem_id_ca_cert),
            use_rtf_key=bool(oem_id_rtf_cert),
            version=key_flags_version,
        )

    @property
    def use_oem_keys(self) -> bool:
        """Return True if OEM keys are being used."""
        return self.oem_key_count > 0 or self.use_ca_key or self.use_rtf_key

    @overload
    def export(self, as_bytes: Literal[True] = ...) -> bytes:
        ...

    @overload
    def export(self, as_bytes: Literal[False]) -> int:
        ...

    def export(self, as_bytes: bool = True) -> Union[bytes, int]:
        """Export OEMKeyFlags into bytes (or optionally into integer)."""
        if self.version not in range(0, 2):
            raise SPSDKTpError(f"Unknown key_flags_version: {self.version}")
        flags = self.oem_key_count
        if self.version == 0:
            flags <<= 2
        if self.version == 1:
            if self.use_ca_key:
                flags |= 0x10
            if self.use_rtf_key:
                flags |= 0x20
        if as_bytes:
            return flags.to_bytes(length=1, byteorder="big")
        return flags

    @staticmethod
    def parse(flags: int, family: str) -> "OEMKeyFlags":
        """Parse OEMKeyFlags for given chip family."""
        version = value_to_int(
            Database(TP_DATABASE).get_device_value("key_flags_version", device=family)
        )

        if version == 0:
            return OEMKeyFlags(
                oem_key_count=flags >> 2,
                use_ca_key=False,
                use_rtf_key=False,
                version=version,
            )
        if version == 1:
            return OEMKeyFlags(
                oem_key_count=flags & 0x0F,
                use_ca_key=bool(flags & 0x10),
                use_rtf_key=bool(flags & 0x20),
                version=version,
            )
        raise SPSDKTpError(f"Unknown key_flags_version: {version}")

    @staticmethod
    def get_key_name(key_id: int) -> str:
        """Get a name for a key if applicable."""
        if key_id == 0x10:
            return "ca"
        if key_id == 0x20:
            return "rtf"
        return str(key_id)


@dataclass
class OEMCertInfo:
    """Information regarding generated OEM certificates."""

    oem_cert_count: int
    oem_cert_addresses: List[int]
    ca_cert_address: Optional[int]
    rtf_cert_address: Optional[int]
    key_flags_version: int

    @staticmethod
    def from_config(config_data: dict) -> "OEMCertInfo":
        """Create OEMCertInfo from configuration data."""
        family = config_data["family"]
        key_flags_version = value_to_int(
            Database(TP_DATABASE).get_device_value("key_flags_version", device=family)
        )
        oem_cert_count = config_data.get("oem_id_count", 0)
        if oem_cert_count > 0:
            oem_cert_addresses = config_data["oem_id_addresses"][:oem_cert_count]
        else:
            oem_cert_addresses = []

        ca_cert_address = config_data.get("oem_id_ca_cert_address")
        rtf_cert_address = config_data.get("oem_id_rtf_cert_address")
        return OEMCertInfo(
            oem_cert_count=oem_cert_count,
            oem_cert_addresses=oem_cert_addresses,
            ca_cert_address=ca_cert_address,
            rtf_cert_address=rtf_cert_address,
            key_flags_version=key_flags_version,
        )

    @property
    def use_oem_certs(self) -> bool:
        """Return True if OEM certificates are being used."""
        return self.flags.use_oem_keys

    @property
    def flags(self) -> OEMKeyFlags:
        """Return OEMKeyFlags associated with current OEM cert settings."""
        return OEMKeyFlags(
            oem_key_count=self.oem_cert_count,
            use_ca_key=bool(self.ca_cert_address),
            use_rtf_key=bool(self.rtf_cert_address),
            version=self.key_flags_version,
        )
