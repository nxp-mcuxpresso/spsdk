#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import yaml
from voluptuous import ALLOW_EXTRA, All, Any, Optional, Required, Schema

from spsdk.mboot.memories import ExtMemId
from spsdk.mboot.properties import CommandTag, PeripheryTag, PropertyTag, Version

########################################################################################################################
# Validator schema for configuration file
########################################################################################################################
SCHEMA = {
    Required("Properties"): {
        Required("CurrentVersion"): Any(int, All(str, lambda v: Version(v).to_int())),
        Required("AvailablePeripherals"): All(
            list, [Any(*[item.label for item in PeripheryTag])], lambda v: tuple(set(v))
        ),
        Optional("FlashStartAddress"): Any(int, All(str, lambda v: int(v, 0))),
        Optional("FlashSize"): Any(int, All(str, lambda v: int(v, 0))),
        Optional("FlashSectorSize"): Any(int, All(str, lambda v: int(v, 0))),
        Optional("FlashBlockCount"): Any(int, All(str, lambda v: int(v, 0))),
        Required("AvailableCommands"): All(
            list, [Any(*[item.label for item in CommandTag])], lambda v: tuple(set(v))
        ),
        Optional("CrcCheckStatus"): Any(int, All(str, lambda v: int(v, 0))),
        Optional("VerifyWrites"): All(
            str, Any("YES", "ON", "NO", "OFF"), lambda v: 1 if v in ("YES", "ON") else 0
        ),
        Optional("MaxPacketSize"): Any(int, All(str, lambda v: int(v, 0))),
        Optional("ReservedRegions"): All(
            list,
            [
                {
                    Required("Address"): Any(int, All(str, lambda v: int(v, 0))),
                    Required("Size"): Any(int, All(str, lambda v: int(v, 0))),
                }
            ],
        ),
        Optional("ValidateRegions"): All(
            str, Any("YES", "ON", "NO", "OFF"), lambda v: 1 if v in ("YES", "ON") else 0
        ),
        Optional("RamStartAddress"): Any(int, All(str, lambda v: int(v, 0))),
        Optional("RamSize"): Any(int, All(str, lambda v: int(v, 0))),
        Optional("SystemDeviceIdent"): Any(int, All(str, lambda v: int(v, 16))),
        Optional("FlashSecurityState"): All(str, Any("LOCKED", "UNLOCKED")),
        Optional("UniqueDeviceIdent"): Any(int, All(str, lambda v: int(v, 16))),
        Optional("FlashFacSupport"): All(
            str, Any("YES", "ON", "NO", "OFF"), lambda v: 1 if v in ("YES", "ON") else 0
        ),
        Optional("FlashAccessSegmentSize"): Any(int, All(str, lambda v: int(v, 0))),
        Optional("FlashAccessSegmentCount"): Any(int, All(str, lambda v: int(v, 0))),
        Optional("FlashReadMargin"): Any(int, All(str, lambda v: int(v, 0))),
        Optional("QspiInitStatus"): Any(int, All(str, lambda v: int(v, 0))),
        Optional("TargetVersion"): Any(int, All(str, lambda v: Version(v).to_int())),
        Optional("ExternalMemoryAttributes"): All(
            list,
            [
                {
                    Required("MemoryType"): All(
                        list, Any(*[item.label for item in ExtMemId]), lambda v: tuple(set(v))
                    ),
                    Required("StartAddress"): Any(int, All(str, lambda v: int(v, 0))),
                    Required("Size"): Any(int, All(str, lambda v: int(v, 0))),
                    Optional("PageSize"): Any(int, All(str, lambda v: int(v, 0))),
                    Optional("SectorSize"): Any(int, All(str, lambda v: int(v, 0))),
                    Optional("BlockSize"): Any(int, All(str, lambda v: int(v, 0))),
                }
            ],
        ),
        Optional("ReliableUpdateStatus"): Any(int, All(str, lambda v: int(v, 0))),
        Optional("FlashPageSize"): Any(int, All(str, lambda v: int(v, 0))),
        Optional("IrqNotifierPin"): Any(int, All(str, lambda v: int(v, 0))),
        Optional("PfrKeystoreUpdateOpt"): Any(int, All(str, lambda v: int(v, 0))),
    },
    Optional("Others"): {},
}


########################################################################################################################
# Device configuration class
########################################################################################################################
class DevConfig:
    @property
    def current_version(self):
        assert "CurrentVersion" in self._props
        return self._props["CurrentVersion"]

    @property
    def available_peripherals(self):
        assert "AvailablePeripherals" in self._props
        value = 0
        for name in self._props["AvailablePeripherals"]:
            value |= PeripheryTag.get_tag(name)
        return value

    @property
    def flash_start_address(self):
        assert "FlashStartAddress" in self._props
        return self._props["FlashStartAddress"]

    @property
    def flash_size(self):
        assert "FlashSize" in self._props
        return self._props["FlashSize"]

    @property
    def flash_sector_size(self):
        assert "FlashSectorSize" in self._props
        return self._props["FlashSectorSize"]

    @property
    def flash_block_count(self):
        assert "FlashBlockCount" in self._props
        return self._props["FlashBlockCount"]

    @property
    def available_commands(self):
        assert "AvailableCommands" in self._props
        value = 0
        for cmd_name in self._props["AvailableCommands"]:
            value |= 1 << CommandTag.get_tag(cmd_name)
        return value

    @property
    def crc_check_status(self):
        assert "CrcCheckStatus" in self._props
        return self._props["CrcCheckStatus"]

    @property
    def verify_writes(self):
        assert "VerifyWrites" in self._props
        return self._props["VerifyWrites"]

    @property
    def max_packet_size(self):
        assert "MaxPacketSize" in self._props
        return self._props["MaxPacketSize"]

    @property
    def reserved_regions(self):
        assert "ReservedRegions" in self._props
        raise NotImplementedError()

    @property
    def validate_regions(self):
        assert "ValidateRegions" in self._props
        return self._props["ValidateRegions"]

    @property
    def ram_start_address(self):
        assert "RamStartAddress" in self._props
        return self._props["RamStartAddress"]

    @property
    def ram_size(self):
        assert "RamSize" in self._props
        return self._props["RamSize"]

    @property
    def system_device_ident(self):
        assert "SystemDeviceIdent" in self._props
        return self._props["SystemDeviceIdent"]

    @property
    def flash_security_state(self):
        assert "FlashSecurityState" in self._props
        return self._props["FlashSecurityState"]

    @property
    def unique_device_ident(self):
        assert "UniqueDeviceIdent" in self._props
        return self._props["UniqueDeviceIdent"]

    @property
    def flash_fac_support(self):
        assert "FlashFacSupport" in self._props
        return self._props["FlashFacSupport"]

    @property
    def flash_access_segment_size(self):
        assert "FlashAccessSegmentSize" in self._props
        return self._props["FlashAccessSegmentSize"]

    @property
    def flash_access_segment_count(self):
        assert "FlashAccessSegmentCount" in self._props
        return self._props["FlashAccessSegmentCount"]

    @property
    def flash_read_margin(self):
        assert "FlashReadMargin" in self._props
        return self._props["FlashReadMargin"]

    @property
    def qspi_init_status(self):
        assert "QspiInitStatus" in self._props
        return self._props["QspiInitStatus"]

    @property
    def target_version(self):
        assert "TargetVersion" in self._props
        return self._props["TargetVersion"]

    @property
    def external_memory_attributes(self):
        assert "ExternalMemoryAttributes" in self._props
        return self._props["ExternalMemoryAttributes"]

    @property
    def reliable_update_status(self):
        assert "ReliableUpdateStatus" in self._props
        return self._props["ReliableUpdateStatus"]

    @property
    def flash_page_size(self):
        assert "FlashPageSize" in self._props
        return self._props["FlashPageSize"]

    @property
    def irq_notifier_pin(self):
        assert "IrqNotifierPin" in self._props
        return self._props["IrqNotifierPin"]

    @property
    def pfr_keystore_update_opt(self):
        assert "PfrKeystoreUpdateOpt" in self._props
        return self._props["PfrKeystoreUpdateOpt"]

    def __init__(self, config_file):
        with open(config_file, "r") as f:
            dev_cfg = yaml.safe_load(f)
        validator = Schema(SCHEMA, extra=ALLOW_EXTRA)
        dev_cfg = validator(dev_cfg)
        self._props = dev_cfg["Properties"]
        self._other = dev_cfg.get("Others", {})

    def valid_cmd(self, tag):
        assert tag in CommandTag.tags()
        return CommandTag.get_label(tag) in self._props["AvailableCommands"]

    def get_properties_count(self):
        return len(self._props)

    def get_property_values(self, tag: int):
        assert tag in PropertyTag.tags()
        pname = PropertyTag.get_label(tag)
        if pname not in self._props:
            return None
        if tag == PropertyTag.AVAILABLE_COMMANDS:
            value = 0
            for cmd_name in self._props["AvailableCommands"]:
                value |= 1 << CommandTag.get_tag(cmd_name)
            return [value]
        elif tag == PropertyTag.AVAILABLE_PERIPHERALS:
            value = 0
            for name in self._props["AvailablePeripherals"]:
                value |= PeripheryTag.get_tag(name)
            return [value]
        elif tag == PropertyTag.UNIQUE_DEVICE_IDENT:
            return [
                self._props["UniqueDeviceIdent"] >> 32,
                self._props["UniqueDeviceIdent"] & 0xFFFFFFFF,
            ]
        else:
            return [self._props[pname]]
