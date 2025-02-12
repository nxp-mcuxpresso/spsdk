#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Protocol base."""
from abc import ABC, abstractmethod
from types import ModuleType, TracebackType
from typing import Any, Optional, Sequence, Type, Union

from typing_extensions import Self

from spsdk.exceptions import SPSDKAttributeError, SPSDKError
from spsdk.utils.interfaces.commands import CmdPacketBase, CmdResponseBase
from spsdk.utils.interfaces.device.base import DeviceBase
from spsdk.utils.plugins import PluginsManager, PluginType


class SpsdkNoDeviceFoundError(SPSDKError):
    """No device found error."""

    def __init__(self, interface: str, scan_params: str) -> None:
        """Initialize the SpsdkNoDeviceFoundError exception.

        :param interface: interface identifier
        :param interface_params: interface parameters used for scanning
        """
        super().__init__()
        self.interface = interface
        self.scan_params = scan_params

    def __str__(self) -> str:
        return (
            f"No devices for given interface '{self.interface}' "
            f"and parameters '{self.scan_params}' was found."
        )


class SpsdkMultipleDevicesFoundError(SPSDKError):
    """Multiple devices found error."""

    def __init__(
        self,
        interface: str,
        scan_params: str,
        interfaces: Optional[Sequence["ProtocolBase"]] = None,
    ) -> None:
        """Initialize the SpsdkNoDeviceFoundError exception.

        :param interface: interface identifier
        :param interface_params: interface parameters used for scanning
        :param devices: devices found
        """
        super().__init__()
        self.interface = interface
        self.scan_params = scan_params
        self.interfaces = interfaces or []

    def __str__(self) -> str:
        msg = (
            f"Multiple devices for given interface '{self.interface}' and "
            f"parameters '{self.scan_params}' were found."
        )
        devices = [interface.device for interface in self.interfaces]
        for idx, device in enumerate(devices):
            msg += f"\n Device #{idx}: {str(device)}"
        return msg


class ProtocolBase(ABC):
    """Protocol base class."""

    device: DeviceBase
    identifier: str

    def __init__(self, device: DeviceBase) -> None:
        """Initialize the MbootSerialProtocol object.

        :param device: The device instance
        """
        self.device = device

    def __str__(self) -> str:
        return f"identifier='{self.identifier}', device={self.device}"

    def __enter__(self) -> Self:
        self.open()
        return self

    def __exit__(
        self,
        exception_type: Optional[Type[Exception]] = None,
        exception_value: Optional[Exception] = None,
        traceback: Optional[TracebackType] = None,
    ) -> None:
        self.close()

    @abstractmethod
    def open(self) -> None:
        """Open the interface."""

    @abstractmethod
    def close(self) -> None:
        """Close the interface."""

    @property
    @abstractmethod
    def is_opened(self) -> bool:
        """Indicates whether interface is open."""

    @classmethod
    def scan_single(cls, *args: Any, **kwargs: Any) -> Self:
        """Scan the existing connected devices and return a single interface.

        :raises SPSDKAttributeError: If interface 'scan' method is not implemented
        :raises SpsdkNoDeviceFoundError: If no device is found
        :raises SpsdkMultipleDevicesFoundError: If multiple devices are found
        """
        try:
            scan = getattr(cls, "scan")
        except AttributeError as e:
            raise SPSDKAttributeError("The scan method for the interface isn't implemented.") from e
        interfaces = scan(*args, **kwargs)
        # build a string containing params for the scan method
        params_groups = []
        args_str = ", ".join(args)
        if args_str:
            params_groups.append(args_str)
        kwargs_str = ", ".join(f"{key}={value}" for key, value in kwargs.items())
        if kwargs_str:
            params_groups.append(kwargs_str)
        params_str = ", ".join(params_groups)
        if len(interfaces) == 0:
            raise SpsdkNoDeviceFoundError(cls.identifier, params_str)
        if len(interfaces) > 1:
            raise SpsdkMultipleDevicesFoundError(cls.identifier, params_str, interfaces)
        return interfaces[0]

    @abstractmethod
    def write_command(self, packet: CmdPacketBase) -> None:
        """Write command to the device.

        :param packet: Command packet to be sent
        """

    @abstractmethod
    def write_data(self, data: bytes) -> None:
        """Write data to the device.

        :param data: Data to be send
        """

    @abstractmethod
    def read(self, length: Optional[int] = None) -> Union[CmdResponseBase, bytes]:
        """Read data from device.

        :return: read data
        """

    @classmethod
    def _get_interface_classes(cls) -> list[Type[Self]]:
        """Get list of all available interfaces."""
        cls._load_plugins()
        return [
            sub_class
            for sub_class in cls._get_subclasses(cls)
            if getattr(sub_class, "identifier", None)
        ]

    @classmethod
    def get_interface_class(cls, identifier: str) -> Type[Self]:
        """Get list of all available interface classes."""
        interface = next(
            (iface for iface in cls._get_interface_classes() if iface.identifier == identifier),
            None,
        )
        if not interface:
            raise SPSDKError(f"Interface with identifier {identifier} does not exist.")
        return interface

    @staticmethod
    def _load_plugins() -> dict[str, ModuleType]:
        """Load all installed interface plugins."""
        plugins_manager = PluginsManager()
        plugins_manager.load_from_entrypoints(PluginType.DEVICE_INTERFACE.label)
        return plugins_manager.plugins

    @classmethod
    def _get_subclasses(
        cls,
        base_class: Type,
    ) -> list[Type[Self]]:
        """Recursively find all subclasses."""
        subclasses = []
        for subclass in base_class.__subclasses__():
            subclasses.append(subclass)
            subclasses.extend(cls._get_subclasses(subclass))
        return subclasses
