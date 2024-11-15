#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Trust provisioning host adapters interfaces."""
from typing import Any, Optional, Type, Union

from spsdk.tp.data_container.audit_log import AuditLog
from spsdk.tp.exceptions import SPSDKTpError


class TpIntfDescription:
    """Description of TP interface."""

    def __init__(
        self,
        name: str,
        intf: Optional[Union[Type["TpDevInterface"], Type["TpTargetInterface"]]],
        description: str,
        settings: Optional[dict],
        version: str = "0.0.0",
    ) -> None:
        """Root Of Trust device description.

        :param name: Name of the device.
        :param description: Description of the device.
        :param settings: Dictionary of settings needed to properly setup the device.
        """
        self.name = name
        self.intf = intf
        self.description = description
        self.settings = settings
        self.version = version

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}: id={self.get_id()}, version={self.version}>"

    def as_dict(self) -> dict[str, Any]:
        """Returns whole record as dictionary.

        :return: All variables of class in dictionary.
        """
        dictionary = vars(self).copy()
        dictionary.pop("settings")  # The settings are not important in this case
        dictionary.pop("intf")  # The interface is not important in this case
        return dictionary

    def get_id(self) -> Union[str, int]:
        """Returns the ID of the interface."""
        raise NotImplementedError()

    def get_id_hash(self) -> str:
        """Return the ID hash of the interface."""
        raise NotImplementedError()

    def create_interface(
        self, *args: Union[int, str], **kwargs: Union[int, str]
    ) -> Union["TpDevInterface", "TpTargetInterface"]:
        """Return TP Device or Target associated with this descriptor."""
        if not self.intf:
            raise SPSDKTpError("Interface is not defined.")
        return self.intf(self, *args, **kwargs)


class TpInterface:
    """Generic TP Interface."""

    NAME = "Interface"

    @classmethod
    def get_connected_interfaces(cls, settings: Optional[dict] = None) -> list[TpIntfDescription]:
        """Get all connected TP devices of this adapter.

        :param settings: Possible settings to determine the way to find connected device, defaults to None.
        :return: List of all founded TP devices.
        """
        raise NotImplementedError()

    def __init__(self, descriptor: TpIntfDescription) -> None:
        """Initialization of TP device.

        :param descriptor: Device Interface descriptor.
        """
        self.descriptor = descriptor

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}: desc={repr(self.descriptor)}>"

    def open(self) -> None:
        """Open the TP interface adapter.

        raises NotImplementedError: The function is not implemented.
        """
        raise NotImplementedError()

    @property
    def is_open(self) -> bool:
        """Check if the TP interface is open."""
        return True

    def close(self) -> None:
        """Close the TP interface adapter.

        raises NotImplementedError: The function is not implemented.
        """
        raise NotImplementedError()

    @staticmethod
    def get_help() -> str:
        """Return help for this interface, including settings description.

        :return: String with help.
        """
        raise NotImplementedError()

    @classmethod
    def get_validation_schemas(cls) -> list[dict[str, Any]]:
        """Return all additional validation schemas for interface.

        return: List of all additional validation schemas.
        """
        raise NotImplementedError()


class TpDevInterface(TpInterface):
    """Trust provisioning - Trust provisioning device adapter interface."""

    get_connected_devices = TpInterface.get_connected_interfaces

    def __init__(self, descriptor: TpIntfDescription) -> None:
        """Initialization of TP device."""
        super().__init__(descriptor=descriptor)

    def get_challenge(self, timeout: Optional[int] = None) -> bytes:
        """Request challenge from the TP device.

        :param timeout: Timeout of operation in milliseconds.
        :return: Challenge record, to be used for TP communication.
        """
        raise NotImplementedError()

    def authenticate_response(self, tp_data: bytes, timeout: Optional[int] = None) -> bytes:
        """Request TP device for TP authentication of connected MCU.

        :param tp_data: TP response of connected MCU.
        :param timeout: Timeout of operation in milliseconds.
        :return: Wrapped data after TP response processing.
        raises NotImplementedError: The function is not implemented.
        """
        raise NotImplementedError()

    def upload(self, config_data: dict, config_dir: Optional[str] = None) -> None:
        """Upload the user data into the provisioning device."""
        raise NotImplementedError()

    def setup(self) -> None:
        """Setup the provisioning device."""
        # By default do nothing

    def seal(self) -> None:
        """Seal the provisioning device (advance its lifecycle)."""
        raise NotImplementedError()

    def get_prov_counter(self) -> int:
        """Get actual provisioning counter."""
        raise NotImplementedError()

    def get_prov_remainder(self) -> int:
        """Get the number of remaining provisioning attempts."""
        raise NotImplementedError()

    def check_log_owner(self, audit_log: str) -> None:
        """Check if this TP Device's ID is present in the audit log."""
        my_id = str(self.descriptor.get_id())
        audit_log_properties = AuditLog.properties(audit_log)
        if my_id != audit_log_properties.tp_device_id:
            raise SPSDKTpError(
                "Audit log ID doesn't match. "
                f"TP Device ID: {my_id}, Audit log ID: {audit_log_properties.tp_device_id}"
            )


class TpTargetInterface(TpInterface):
    """Trust provisioning - provisioned target adapter interface."""

    get_connected_targets = TpInterface.get_connected_interfaces

    def __init__(self, descriptor: TpIntfDescription) -> None:
        """Initialization of TP target.

        :param descriptor: Target Interface descriptor.
        """
        super().__init__(descriptor=descriptor)

    @property
    def uses_uart(self) -> bool:
        """Check if the adapter is using UART for communication."""
        return False

    @property
    def uses_usb(self) -> bool:
        """Check if the adapter is using USB for communication."""
        return False

    def reset_device(self) -> None:
        """Reset the connected provisioned device.

        raises NotImplementedError: The function is not implemented.
        """
        raise NotImplementedError()

    def load_sb_file(self, sb_file: bytes, timeout: Optional[int] = None) -> None:
        """Load SB file into provisioned device.

        :param sb_file: SB file data to be loaded into provisioned device.
        :param timeout: Timeout of operation in milliseconds.
        raises NotImplementedError: The function is not implemented.
        """
        raise NotImplementedError()

    def prove_genuinity_challenge(self, challenge: bytes, timeout: Optional[int] = None) -> bytes:
        """Prove genuinity and get back the TP response to continue process of TP.

        :param challenge: Challenge data to start TP process.
        :param timeout: Timeout of operation in milliseconds.
        :return: Trust provisioning response for TP process.
        raises NotImplementedError: The function is not implemented.
        """
        raise NotImplementedError()

    def set_wrapped_data(self, wrapped_data: bytes, timeout: Optional[int] = None) -> None:
        """Provide wrapped data to provisioned device.

        :param wrapped_data: Wrapped data to finish TP process.
        :param timeout: Timeout of operation in milliseconds.
        raises NotImplementedError: The function is not implemented.
        """
        raise NotImplementedError()

    def read_memory(self, address: int, length: int, memory_id: int = 0) -> bytes:
        """Read data from the target's memory.

        :param address: Start address
        :param length: Number of bytes to read
        :param memory_id: Memory ID, defaults to 0
        :raises NotImplementedError: This function is not implemented
        :return: Data read from the target
        """
        raise NotImplementedError()

    def write_memory(self, address: int, data: bytes, memory_id: int = 0) -> None:
        """Write data to the target's memory.

        :param address: Start address
        :param data: Data to write
        :param memory_id: Memory ID, defaults to 0
        :raises NotImplementedError: This function is not implemented
        """
        raise NotImplementedError()

    def erase_memory(self, address: int, length: int, memory_id: int = 0) -> None:
        """Erase target's memory.

        :param address: Start address
        :param length: Number of bytes to erase
        :param memory_id: Memory ID, defaults to 0
        :raises NotImplementedError: This function is not implemented
        """
        raise NotImplementedError()

    # pylint: disable=no-self-use    # inherited classes may use self
    def check_provisioning_firmware(self) -> bool:
        """Check whether the Provisioning Firmware booted properly."""
        return True
