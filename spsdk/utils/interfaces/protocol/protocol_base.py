#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK protocol base interface for device communication.

This module provides the abstract base class and common exceptions for implementing
communication protocols with NXP devices. It defines the standard interface that
all protocol implementations must follow for consistent device interaction across
the SPSDK ecosystem.
"""

from abc import ABC, abstractmethod
from types import ModuleType, TracebackType
from typing import Any, Optional, Sequence, Type, Union

from typing_extensions import Self

from spsdk.exceptions import SPSDKAttributeError, SPSDKError
from spsdk.utils.interfaces.commands import CmdPacketBase, CmdResponseBase
from spsdk.utils.interfaces.device.base import DeviceBase
from spsdk.utils.plugins import PluginsManager, PluginType


class SpsdkNoDeviceFoundError(SPSDKError):
    """SPSDK exception for device discovery failures.

    This exception is raised when no devices are found during interface scanning
    operations, providing detailed information about the failed search parameters.
    """

    def __init__(self, interface: str, scan_params: str) -> None:
        """Initialize the SpsdkNoDeviceFoundError exception.

        :param interface: Interface identifier string.
        :param scan_params: Interface parameters used for scanning devices.
        """
        super().__init__()
        self.interface = interface
        self.scan_params = scan_params

    def __str__(self) -> str:
        """Return string representation of the exception.

        :return: Formatted error message indicating no devices were found for the given interface and parameters.
        """
        return (
            f"No devices for given interface '{self.interface}' "
            f"and parameters '{self.scan_params}' was found."
        )


class SpsdkMultipleDevicesFoundError(SPSDKError):
    """SPSDK exception raised when multiple devices are found during interface scanning.

    This exception is raised when a device scan operation discovers more than one
    device matching the specified interface and parameters, requiring user
    intervention to select the appropriate device.
    """

    def __init__(
        self,
        interface: str,
        scan_params: str,
        interfaces: Optional[Sequence["ProtocolBase"]] = None,
    ) -> None:
        """Initialize the SpsdkNoDeviceFoundError exception.

        :param interface: Interface identifier used for device scanning.
        :param scan_params: Interface parameters used for scanning devices.
        :param interfaces: Optional sequence of available protocol interfaces found during scan.
        """
        super().__init__()
        self.interface = interface
        self.scan_params = scan_params
        self.interfaces = interfaces or []

    def __str__(self) -> str:
        """Return string representation of the multiple devices error.

        Provides a formatted error message listing all detected devices when multiple
        devices are found for the given interface and scan parameters.

        :return: Formatted error message with enumerated list of detected devices.
        """
        msg = (
            f"Multiple devices for given interface '{self.interface}' and "
            f"parameters '{self.scan_params}' were found."
        )
        devices = [interface.device for interface in self.interfaces]
        for idx, device in enumerate(devices):
            msg += f"\n Device #{idx}: {str(device)}"
        return msg


class ProtocolBase(ABC):
    """Abstract base class for communication protocols in SPSDK.

    This class defines the common interface for all protocol implementations used to
    communicate with NXP devices. It provides standardized methods for opening,
    closing, and managing device connections with context manager support.
    """

    device: DeviceBase
    identifier: str

    def __init__(self, device: DeviceBase) -> None:
        """Initialize the MbootSerialProtocol object.

        :param device: The device instance to be used for communication.
        """
        self.device = device

    def __str__(self) -> str:
        """Get string representation of the protocol interface.

        Returns a formatted string containing the identifier and device information
        for debugging and logging purposes.

        :return: String representation in format "identifier='<id>', device=<device>".
        """
        return f"identifier='{self.identifier}', device={self.device}"

    def __enter__(self) -> Self:
        """Enter the runtime context of the protocol.

        Opens the protocol connection and returns self for use in context manager.

        :return: Self instance for context manager usage.
        """
        self.open()
        return self

    def __exit__(
        self,
        exception_type: Optional[Type[Exception]] = None,
        exception_value: Optional[Exception] = None,
        traceback: Optional[TracebackType] = None,
    ) -> None:
        """Close the protocol interface and clean up resources.

        This method is called automatically when exiting a context manager (with statement).
        It ensures proper cleanup of the protocol connection and any associated resources.

        :param exception_type: Type of exception that caused the context to exit, if any.
        :param exception_value: Exception instance that caused the context to exit, if any.
        :param traceback: Traceback object associated with the exception, if any.
        """
        self.close()

    @abstractmethod
    def open(self) -> None:
        """Open the interface.

        Establishes connection and initializes the communication interface for data transfer.

        :raises SPSDKError: If the interface cannot be opened or is already open.
        """

    @abstractmethod
    def close(self) -> None:
        """Close the interface.

        This method properly closes the communication interface and releases any
        associated resources. Should be called when the interface is no longer needed
        to ensure proper cleanup.
        """

    @property
    @abstractmethod
    def is_opened(self) -> bool:
        """Indicates whether interface is open.

        :return: True if interface is open, False otherwise.
        """

    @classmethod
    def scan_single(cls, *args: Any, **kwargs: Any) -> Self:
        """Scan the existing connected devices and return a single interface.

        This method wraps the class's scan method to ensure exactly one device is found.
        It validates that the scan method exists and handles cases where zero or multiple
        devices are discovered.

        :param args: Positional arguments passed to the scan method.
        :param kwargs: Keyword arguments passed to the scan method.
        :raises SPSDKAttributeError: If interface 'scan' method is not implemented.
        :raises SpsdkNoDeviceFoundError: If no device is found.
        :raises SpsdkMultipleDevicesFoundError: If multiple devices are found.
        :return: Single interface instance from the scan results.
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

        :param packet: Command packet to be sent.
        :raises SPSDKError: When command write operation fails.
        """

    @abstractmethod
    def write_data(self, data: bytes) -> None:
        """Write data to the device.

        :param data: Data to be sent to the device.
        """

    @abstractmethod
    def read(self, length: Optional[int] = None) -> Union[CmdResponseBase, bytes]:
        """Read data from device.

        :param length: Number of bytes to read. If None, reads all available data.
        :return: Command response object or raw bytes data from the device.
        """

    @classmethod
    def _get_interface_classes(cls) -> list[Type[Self]]:
        """Get list of all available interface classes.

        This method loads all plugins and returns a filtered list of subclasses that have
        a valid identifier attribute.

        :return: List of interface classes that have an identifier attribute.
        """
        cls._load_plugins()
        return [
            sub_class
            for sub_class in cls._get_subclasses(cls)
            if getattr(sub_class, "identifier", None)
        ]

    @classmethod
    def get_interface_class(cls, identifier: str) -> Type[Self]:
        """Get interface class by identifier.

        Retrieves a specific interface class from the available interface classes
        based on the provided identifier string.

        :param identifier: String identifier of the interface class to retrieve.
        :raises SPSDKError: Interface with the specified identifier does not exist.
        :return: Interface class matching the provided identifier.
        """
        interface = next(
            (iface for iface in cls._get_interface_classes() if iface.identifier == identifier),
            None,
        )
        if not interface:
            raise SPSDKError(f"Interface with identifier {identifier} does not exist.")
        return interface

    @staticmethod
    def _load_plugins() -> dict[str, ModuleType]:
        """Load all installed interface plugins.

        This method initializes a PluginsManager instance and loads all device interface
        plugins that are registered as entry points in the system.

        :return: Dictionary mapping plugin names to their corresponding module objects.
        """
        plugins_manager = PluginsManager()
        plugins_manager.load_from_entrypoints(PluginType.DEVICE_INTERFACE.label)
        return plugins_manager.plugins

    @classmethod
    def _get_subclasses(
        cls,
        base_class: Type,
    ) -> list[Type[Self]]:
        """Get all subclasses of a base class recursively.

        This method traverses the inheritance hierarchy to find all direct and indirect
        subclasses of the specified base class.

        :param base_class: The base class to find subclasses for.
        :return: List of all subclasses found in the inheritance hierarchy.
        """
        subclasses = []
        for subclass in base_class.__subclasses__():
            subclasses.append(subclass)
            subclasses.extend(cls._get_subclasses(subclass))
        return subclasses
