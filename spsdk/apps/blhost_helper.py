#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Helper module for blhost application."""

PROPERTIES_NAMES = {
    'list-properties':          0,
    'current-version':          1,
    'available-peripherals':    2,
    'flash-start-address':      3,
    'flash-size-in-bytes':      4,
    'flash-sector-size':        5,
    'flash-block-count':        6,
    'available-commands':       7,
    'check-status':             8,
    'reserved':                 9,
    'verify-writes':            10,
    'max-packet-size':          11,
    'reserved-regions':         12,
    'reserved':                 13,
    'ram-start-address':        14,
    'ram-size-in-bytes':        15,
    'system-device-id':         16,
    'security-state':           17,
    'unique-device-id':         18,
    'flash-fac-support':        19,
    'flash-access-segment-size':    20,
    'flash-access-segment-count':   21,
    'flash-read-margin':            22,
    'qspi/otfad-init-status':       23,
    'target-version':               24,
    'external-memory-attributes':   25,
    'reliable-update-status':       26,
    'flash-page-size':              27,
    'irq-notify-pin':               28,
    'ffr-keystore_update-opt':      29,
}

def parse_property_tag(property_tag: str) -> int:
    """Convert the property as name or stringified number into integer.

    :param property_tag: Name or number of the property tag
    :return: Property integer tag
    """
    try:
        return int(property_tag, 0)
    except:
        pass
    try:
        return PROPERTIES_NAMES[property_tag]
    except:
        pass
    return 0xFF
