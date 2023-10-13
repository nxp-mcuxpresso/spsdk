#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Helper module used for scanning the existing devices."""

from typing import List, Optional

from spsdk.exceptions import SPSDKError
from spsdk.sdp.protocol.base import SDPProtocolBase
from spsdk.utils.interfaces.scanner_helper import InterfaceParams, parse_plugin_config


def get_sdp_interface(
    port: Optional[str] = None,
    usb: Optional[str] = None,
    plugin: Optional[str] = None,
    timeout: int = 5000,
) -> SDPProtocolBase:
    """Get SDP interface.

    'port', 'usb' parameters are mutually exclusive; one of them is required.

    :param port: name and speed of the serial port (format: name[,speed]), defaults to None
    :param usb: PID,VID of the USB interface, defaults to None
    :param plugin: Additional plugin to be used
    :param timeout: timeout in milliseconds
    :return: Selected interface instance
    :raises SPSDKError: Only one of appropriate interfaces must be specified
    :raises SPSDKError: Interface couldn't be opened
    """
    interface_params: List[InterfaceParams] = []
    plugin_params = parse_plugin_config(plugin) if plugin else ("Unknown", "")
    interface_params.extend(
        [
            InterfaceParams(identifier="usb", is_defined=bool(usb), params=usb),
            InterfaceParams(identifier="uart", is_defined=bool(port), params=port),
            InterfaceParams(
                identifier=plugin_params[0], is_defined=bool(plugin), params=plugin_params[1]
            ),
        ]
    )
    interface_params = [ifce for ifce in interface_params if ifce.is_defined]
    if len(interface_params) == 0:
        raise SPSDKError("One of '--port', '--usb' must be specified.")
    if len(interface_params) > 1:
        raise SPSDKError("Only one of '--port', '--usb' must be specified.")
    interface = SDPProtocolBase.get_interface(interface_params[0].identifier)
    assert interface_params[0].params
    devices = interface.scan_from_args(
        params=interface_params[0].params,
        extra_params=interface_params[0].extra_params,
        timeout=timeout,
    )
    if len(devices) == 0:
        raise SPSDKError(f"Selected '{interface_params[0].identifier}' device not found.")
    if len(devices) > 1:
        raise SPSDKError(
            f"Multiple '{interface_params[0].identifier}' devices found: {len(devices)}"
        )
    return devices[0]
