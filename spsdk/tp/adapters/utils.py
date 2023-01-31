#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Utilities used by adapters."""

import logging
from typing import List, Optional, Set

from spsdk.crypto.certificate_management import X509NameConfig
from spsdk.mboot.interfaces.usb import RawHid, scan_usb
from spsdk.utils.misc import Timeout

from .. import SPSDKTpError
from .tptarget_blhost import TpTargetBlHost

USB_DETECTION_TIMEOUT = 1

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
        subject_cn = name_config[subject_cn_idx].get("COMMON_NAME") or ""
        subject_cn = subject_cn + 16 * "AA" + "-" + "BB"
        if subject_cn_idx == -1:
            name_config.append({"COMMON_NAME": subject_cn})
        else:
            name_config[subject_cn_idx] = {"COMMON_NAME": subject_cn}


def get_current_usb_paths() -> Set[bytes]:
    """Get paths to all NXP USB devices."""
    return {device.path for device in scan_usb()}


def detect_new_usb_path(initial_set: Optional[Set[bytes]] = None) -> bytes:
    """Return USB path to newly found NXP USB device.

    :param initial_set: Initial set of USB device paths, defaults to None
    :raises SPSDKTpError: Unable to detect new device in time USB_DETECTION_TIMEOUT (default: 1sec)
    :raises SPSDKTpError: Multiple USB devices detected at once
    :return: USB path to newly detected device
    """
    timeout = Timeout(USB_DETECTION_TIMEOUT)
    previous_set = initial_set or set()
    while not timeout.overflow():
        new_set = get_current_usb_paths()
        addition = new_set.difference(previous_set)
        logger.info(f"Additions: {addition}")
        previous_set = new_set
        if len(addition) > 1:
            raise SPSDKTpError("Multiple new usb devices detected at once!")
        if len(addition) == 1:
            return addition.pop()
        # TODO: should we wait here for a bit?

    raise SPSDKTpError(f"No new USB device detected in time ({USB_DETECTION_TIMEOUT} sec)")


def update_usb_path(tptarget: TpTargetBlHost, new_usb_path: bytes) -> None:
    """Update USB path in TP target's MBoot USB."""
    if not isinstance(tptarget.mboot._device, RawHid):
        return
    tptarget.mboot._device.path = new_usb_path
