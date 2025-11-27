#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK interface configuration helper for communication protocols.

This module provides configuration classes and utilities for setting up
various communication interfaces used by SDP and Mboot protocols, including
USB, UART, SPI, I2C, CAN, and SDIO interfaces.
"""

from abc import abstractmethod
from typing import Any, Optional

from typing_extensions import Self

from spsdk.apps.utils.utils import SPSDKAppError
from spsdk.exceptions import SPSDKKeyError, SPSDKValueError


class InterfaceConfig:
    """SPSDK Interface Configuration Manager.

    This abstract base class defines the interface for managing communication
    parameters and configuration for different interface types used in SPSDK
    operations. It provides a unified way to handle interface-specific settings,
    timeouts, and scanning parameters across various communication protocols.

    :cvar IDENTIFIER: String identifier for the specific interface type.
    """

    IDENTIFIER: str = "Unknown"

    def __init__(
        self, params: str, timeout: Optional[int] = None, extra_params: Optional[str] = None
    ) -> None:
        """Interface config initialization."""
        self.params = params
        self.timeout = timeout
        self.extra_params = extra_params

    @classmethod
    @abstractmethod
    def load(cls, cli_params: dict) -> Optional[Self]:
        """Load from dictionary of CLI parameters."""

    @abstractmethod
    def get_scan_args(self) -> dict:
        """Get arguments for scan method."""

    @staticmethod
    def get_timeout(cli_params: dict) -> Optional[int]:
        """Get timeout value from command line parameters."""
        if "timeout" in cli_params:
            return int(cli_params["timeout"])
        return None


class UsbInterfaceConfig(InterfaceConfig):
    """USB Interface configuration handler for SPSDK applications.

    This class manages USB interface parameters and provides functionality to load
    configuration from CLI parameters and prepare arguments for USB device scanning.

    :cvar IDENTIFIER: Interface type identifier for USB connections.
    """

    IDENTIFIER = "usb"

    @classmethod
    def load(cls, cli_params: dict[str, str]) -> Optional[Self]:
        """Load from dictionary of CLI parameters."""
        if not cli_params.get("usb"):
            return None
        return cls(params=cli_params[cls.IDENTIFIER], timeout=cls.get_timeout(cli_params))

    def get_scan_args(self) -> dict:
        """Get arguments for scan method."""
        args: dict[str, Any] = {"device_id": self.params.replace(",", ":")}
        if self.timeout is not None:
            args["timeout"] = self.timeout
        return args


class UartInterfaceConfig(InterfaceConfig):
    """UART interface configuration for SPSDK communication.

    This class handles configuration parameters for UART-based communication interfaces,
    including port settings, baudrate configuration, and timeout management for SPSDK
    operations.

    :cvar IDENTIFIER: Interface type identifier for UART connections.
    """

    IDENTIFIER = "uart"

    @classmethod
    def load(cls, cli_params: dict[str, str]) -> Optional[Self]:
        """Load from dictionary of CLI parameters."""
        if not cli_params.get("port") or cli_params.get("buspal"):
            return None
        return cls(params=cli_params["port"], timeout=cls.get_timeout(cli_params))

    def get_scan_args(self) -> dict:
        """Get arguments for scan method."""
        parts = self.params.split(",")
        args: dict[str, Any] = {"port": parts.pop(0)}
        if parts:
            args["baudrate"] = int(parts.pop(), 0)
        if self.timeout:
            args["timeout"] = self.timeout
        return args


class BuspalSpiInterfaceConfig(InterfaceConfig):
    """Buspal SPI Interface configuration manager.

    This class handles configuration parameters for Buspal SPI communication
    interfaces, including parameter validation, loading from CLI arguments,
    and preparation of scan arguments for SPI device discovery.

    :cvar IDENTIFIER: Interface type identifier for Buspal SPI.
    """

    IDENTIFIER = "buspal_spi"

    @classmethod
    def load(cls, cli_params: dict[str, str]) -> Optional[Self]:
        """Load from dictionary of CLI parameters."""
        if (
            not cli_params.get("port")
            or not cli_params.get("buspal")
            or "spi" not in cli_params["buspal"]
        ):
            return None
        return cls(
            params=cli_params["port"],
            extra_params=cli_params["buspal"],
            timeout=cls.get_timeout(cli_params),
        )

    def get_scan_args(self) -> dict:
        """Get arguments for scan method."""
        props = []
        if self.extra_params:
            props = self.extra_params.split(",")
        target = props.pop(0)
        if target != "spi":
            raise SPSDKValueError(f"Invalid target: {target}. Expected 'spi'.")
        port_parts = self.params.split(",")
        args: dict[str, Any] = {"port": port_parts.pop(0), "props": props}
        if self.timeout:
            args["timeout"] = self.timeout
        return args


class BuspalI2cInterfaceConfig(InterfaceConfig):
    """Buspal I2C interface configuration manager.

    This class handles configuration parameters for Buspal I2C communication
    interfaces, including parameter validation, loading from CLI arguments,
    and preparation of scan arguments for device discovery operations.

    :cvar IDENTIFIER: Interface type identifier for Buspal I2C connections.
    """

    IDENTIFIER = "buspal_i2c"

    @classmethod
    def load(cls, cli_params: dict[str, str]) -> Optional[Self]:
        """Load from dictionary of CLI parameters."""
        if (
            not cli_params.get("port")
            or not cli_params.get("buspal")
            or "i2c" not in cli_params["buspal"]
        ):
            return None
        return cls(
            params=cli_params["port"],
            extra_params=cli_params["buspal"],
            timeout=cls.get_timeout(cli_params),
        )

    def get_scan_args(self) -> dict:
        """Get arguments for scan method."""
        props = []
        if self.extra_params:
            props = self.extra_params.split(",")
        target = props.pop(0)
        if target != "i2c":
            raise SPSDKValueError(f"Invalid target: {target}. Expected 'i2c'.")
        port_parts = self.params.split(",")
        args: dict[str, Any] = {"port": port_parts.pop(0), "props": props}
        if self.timeout:
            args["timeout"] = self.timeout
        return args


class UsbsioSpiInterfaceConfig(InterfaceConfig):
    """USBSIO SPI interface configuration manager.

    This class handles configuration parameters for USBSIO SPI communication
    interfaces, providing methods to load configuration from CLI parameters
    and prepare scan arguments for device discovery operations.

    :cvar IDENTIFIER: Interface type identifier for USBSIO SPI.
    """

    IDENTIFIER = "usbsio_spi"

    @classmethod
    def load(cls, cli_params: dict[str, str]) -> Optional[Self]:
        """Load from dictionary of CLI parameters."""
        if not cli_params.get("lpcusbsio") or "spi" not in cli_params["lpcusbsio"]:
            return None
        return cls(params=cli_params["lpcusbsio"], timeout=cls.get_timeout(cli_params))

    def get_scan_args(self) -> dict:
        """Get arguments for scan method."""
        args: dict[str, Any] = {"config": self.params}
        if self.timeout:
            args["timeout"] = self.timeout
        return args


class UsbsioI2cInterfaceConfig(InterfaceConfig):
    """USBSIO I2C interface configuration manager.

    This class handles configuration parameters for USBSIO I2C communication
    interfaces, providing methods to load configuration from CLI parameters
    and prepare arguments for device scanning operations.

    :cvar IDENTIFIER: Interface type identifier for USBSIO I2C connections.
    """

    IDENTIFIER = "usbsio_i2c"

    @classmethod
    def load(cls, cli_params: dict[str, str]) -> Optional[Self]:
        """Load from dictionary of CLI parameters."""
        if not cli_params.get("lpcusbsio") or "i2c" not in cli_params["lpcusbsio"]:
            return None
        return cls(params=cli_params["lpcusbsio"], timeout=cls.get_timeout(cli_params))

    def get_scan_args(self) -> dict:
        """Get arguments for scan method."""
        args: dict[str, Any] = {"config": self.params}
        if self.timeout:
            args["timeout"] = self.timeout
        return args


class UsbSdioInterfaceConfig(InterfaceConfig):
    """USB SDIO Interface Configuration Manager.

    This class manages configuration parameters for USB SDIO interface connections,
    handling parameter loading from CLI inputs and providing scan arguments for
    device discovery operations.

    :cvar IDENTIFIER: Interface type identifier for SDIO connections.
    """

    IDENTIFIER = "sdio"

    @classmethod
    def load(cls, cli_params: dict[str, str]) -> Optional[Self]:
        """Load from dictionary of CLI parameters."""
        if not cli_params.get("sdio"):
            return None
        return cls(params=cli_params["sdio"], timeout=cls.get_timeout(cli_params))

    def get_scan_args(self) -> dict:
        """Get arguments for scan method."""
        args: dict[str, Any] = {"device_path": self.params}
        if self.timeout:
            args["timeout"] = self.timeout
        return args


class CanInterfaceConfig(InterfaceConfig):
    """CAN interface configuration handler for SPSDK communication.

    This class manages CAN (Controller Area Network) interface parameters and
    provides methods to parse and validate CAN connection settings including
    interface type, channel, bitrate, and message IDs.

    :cvar IDENTIFIER: Interface type identifier for CAN connections.
    """

    IDENTIFIER = "can"

    @classmethod
    def load(cls, cli_params: dict[str, str]) -> Optional[Self]:
        """Load from dictionary of CLI parameters."""
        if not cli_params.get("can"):
            return None
        return cls(params=cli_params["can"], timeout=cls.get_timeout(cli_params))

    def get_scan_args(self) -> dict:
        """Get arguments for scan method."""
        can_parts = self.params.split(",")
        if len(can_parts) < 1:
            raise SPSDKValueError("Invalid number of parameters. Interface is mandatory.")
        args: dict[str, Any] = {"interface": can_parts.pop(0)}
        if can_parts:
            args["channel"] = can_parts.pop(0)
        if can_parts:
            args["bitrate"] = can_parts.pop(0)
        if can_parts:
            args["rxid"] = can_parts.pop(0)
        if can_parts:
            args["txid"] = can_parts.pop(0)
        if self.timeout:
            args["timeout"] = self.timeout
        return args


class PluginInterfaceConfig(InterfaceConfig):
    """Plugin interface configuration for SPSDK communication adapters.

    This class manages configuration parameters for plugin-based communication
    interfaces, handling parameter parsing, validation, and interface setup
    for dynamic plugin loading in SPSDK applications.

    :cvar IDENTIFIER: Default plugin interface identifier.
    """

    IDENTIFIER = "plugin"

    @classmethod
    def load(cls, cli_params: dict[str, str]) -> Optional[Self]:
        """Load from dictionary of CLI parameters."""
        if not cli_params.get("plugin"):
            return None
        identifier, params = cls.parse_plugin_config(cli_params["plugin"])
        plugin = cls(params=params, timeout=cls.get_timeout(cli_params))
        plugin.IDENTIFIER = identifier
        return plugin

    def get_scan_args(self) -> dict:
        """Get arguments for scan method."""
        args: dict = {}
        if self.params:
            args = dict([tuple(p.split("=")) for p in self.params.split(",")])  # type: ignore
        if self.timeout:
            args["timeout"] = self.timeout
        return args

    @staticmethod
    def parse_plugin_config(plugin_conf: str) -> tuple[str, str]:
        """Extract 'identifier' from plugin params and build the params back to original format.

        :param plugin_conf: Plugin configuration string as given on command line
        :return: Tuple with identifier and params
        """
        params_dict: dict[str, str] = {}
        if plugin_conf:
            params_dict = dict([tuple(p.split("=")) for p in plugin_conf.split(",")])  # type: ignore
        if "identifier" not in params_dict:
            raise SPSDKKeyError("Plugin parameter must contain 'identifier' key")
        identifier = params_dict.pop("identifier")
        params = ",".join([f"{key}={value}" for key, value in params_dict.items()])
        return identifier, params


def load_interface_config(cli_params: dict) -> InterfaceConfig:
    """Load interface scan config from dictionary of CLI parameters."""
    iface_configs: list = []
    for interface_cls in InterfaceConfig.__subclasses__():
        iface_config = interface_cls.load(cli_params)
        if iface_config is not None:
            iface_configs.append(iface_config)
    if len(iface_configs) != 1:
        base_params = [
            f"'--{param}'"
            for param in ["port", "usb", "sdio", "lpcusbsio", "plugin", "can"]
            if param in cli_params
        ]
        if len(iface_configs) == 0:
            raise SPSDKAppError(f"One of {','.join(base_params)} must be specified.")
        if len(iface_configs) > 1:
            raise SPSDKAppError(f"Only one of {','.join(base_params)} must be specified.")
    return iface_configs[0]
