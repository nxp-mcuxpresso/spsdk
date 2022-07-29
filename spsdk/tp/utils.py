#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Trust Provisioning utilities."""
import os
from typing import List, Type

from ruamel.yaml import YAML

from . import TP_DATA_FOLDER, TpDevInterface, TpIntfDescription, TpTargetInterface
from .adapters import TP_DEVICES, TP_TARGETS


def single_tp_device_adapter() -> bool:
    """Return True if there's only one TP device adapter."""
    return len(TP_DEVICES) == 1


def single_tp_target_adapter() -> bool:
    """Return True if there's only one TP target adapter."""
    return len(TP_TARGETS) == 1


def get_supported_devices() -> List[str]:
    """Return list of supported devices for Trust Provisioning.

    :return: List of devices.
    """
    with open(os.path.join(TP_DATA_FOLDER, "database.yaml")) as f:
        data = YAML(typ="safe").load(f)
    return list(data["devices"].keys())


def get_tp_device_types() -> List[str]:
    """Return list of supported TP device types."""
    return list(TP_DEVICES.keys())


def scan_tp_devices(tpdev: str = None, settings: dict = None) -> List[TpIntfDescription]:
    """The function scans the TP devices on system.

    :param tpdev: Selection of one type of TP device, defaults to None (scan all supported).
    :param settings: Additional settings to setup interface, defaults to {}.
    :return: List of active TP device descriptors.
    :raises ValueError: Invalid value of parameter.
    """
    if tpdev and tpdev not in get_tp_device_types():
        raise ValueError(f"Unsupported TP device name - {tpdev}")

    dev_list = [tpdev] if tpdev else get_tp_device_types()

    active_devices = []
    for dev in dev_list:
        active_devices.extend(TP_DEVICES[dev].get_connected_devices(settings))

    return active_devices


def get_tp_devices(tpdev: str = None, settings: dict = None) -> List[TpDevInterface]:
    """Return a list of active TP Devices fulfilling criteria in 'settings'.

    This functions attempts to open/close the device, please mind possible side-effects.

    :param tpdev: Name of TP Device interface, defaults to None
    :param settings: Settings for TP Target, defaults to None
    :return: List of active TP Devices
    """
    device_descriptors = scan_tp_devices(tpdev=tpdev, settings=settings)
    devices = []
    for descriptor in device_descriptors:
        try:
            dev = descriptor.create_interface()
            assert isinstance(dev, TpDevInterface)
            dev.open()
            dev.close()
            devices.append(dev)
        except Exception:  # pylint: disable=broad-except   # the underlying error is unknown
            dev.close()
            continue
    return devices


def get_tp_target_types() -> List[str]:
    """Return list of supported TP targets."""
    return list(TP_TARGETS.keys())


def scan_tp_targets(tptarget: str = None, settings: dict = None) -> List[TpIntfDescription]:
    """The function scans the TP targets on system.

    :param tptarget: Selection of one type of TP target, defaults to None (scan all supported).
    :param settings: Additional settings to setup interface, defaults to {}.
    :return: List of active TP devices.
    :raises ValueError: Invalid value of parameter.
    """
    if tptarget and tptarget not in get_tp_target_types():
        raise ValueError(f"Unsupported TP device name - {tptarget}")

    target_list = [tptarget] if tptarget else get_tp_target_types()

    active_targets = []
    for target in target_list:
        active_targets.extend(TP_TARGETS[target].get_connected_targets(settings))

    return active_targets


def get_tp_targets(tptarget: str = None, settings: dict = None) -> List[TpTargetInterface]:
    """Return a list of active TP Targets fulfilling criteria in 'settings'.

    This functions attempts to open/close the device, please mind possible side-effects.

    :param tptarget: Name of TP Target interface, defaults to None
    :param settings: Settings for TP Target, defaults to None
    :return: List is active TP Targets
    """
    target_descriptors = scan_tp_devices(tpdev=tptarget, settings=settings)
    targets = []
    for descriptor in target_descriptors:
        try:
            target = descriptor.create_interface()
            assert isinstance(target, TpTargetInterface)
            target.open()
            target.close()
            targets.append(target)
        except Exception:  # pylint: disable=broad-except   # the underlying error is unknown
            target.close()
            continue
    return targets


def get_tp_device_class(name: str) -> Type[TpDevInterface]:
    """Return class of TP device interface by name.

    :param name: Name of the interface.
    :return: TP device interface.
    """
    return TP_DEVICES[name]


def get_tp_target_class(name: str) -> Type[TpTargetInterface]:
    """Return class of TP target interface by name.

    :param name: Name of the interface.
    :return: TP target interface.
    """
    return TP_TARGETS[name]
