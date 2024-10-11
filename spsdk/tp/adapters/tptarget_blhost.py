#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Trust provisioning - TP Target, ISP mode over BLHOST."""

from enum import Enum
from typing import Any, Optional, Union

from spsdk.mboot.exceptions import McuBootError, StatusCode
from spsdk.mboot.interfaces.uart import MbootUARTInterface
from spsdk.mboot.interfaces.usb import MbootUSBInterface
from spsdk.mboot.mcuboot import McuBoot
from spsdk.mboot.protocol.base import MbootProtocolBase
from spsdk.tp.exceptions import SPSDKTpTargetError
from spsdk.tp.tp_intf import TpIntfDescription, TpTargetInterface
from spsdk.utils.database import DatabaseManager, get_db, get_schema_file
from spsdk.utils.interfaces.device.serial_device import SerialDevice
from spsdk.utils.interfaces.device.usb_device import UsbDevice
from spsdk.utils.misc import value_to_int


class TpBlHostIntfDescription(TpIntfDescription):
    """TP BLHOST Interface description."""

    def __init__(
        self,
        name: str,
        description: str,
        settings: Optional[dict],
    ) -> None:
        """The BLHOST adapter for TPHOST interface description class.

        :param name: Name of the target
        :param description: Description of the target
        :param settings: Settings of target
        """
        super().__init__(name, TpTargetBlHost, description, settings)
        self.interface: Optional[MbootProtocolBase] = None

    def as_dict(self) -> dict[str, Any]:
        """Returns dictionary with important fields for selection table."""
        ret = {}
        ret["name"] = self.name
        ret["description"] = self.description
        # For USB device
        if isinstance(self.interface, MbootUSBInterface):
            assert isinstance(self.interface.device, UsbDevice)
            ret["path_hash"] = self.interface.device.path_hash
            ret["pid_vid"] = f"{self.interface.device.vid:#06x}:{self.interface.device.pid:#06x}"
        if isinstance(self.interface, MbootUARTInterface):
            assert isinstance(self.interface.device, SerialDevice)
            ret["port"] = self.interface.device._device.port
            ret["baudrate"] = self.interface.device._device.baudrate

        return ret

    def get_id(self) -> str:
        """Returns the ID of the interface (com port or VID:PID)."""
        if isinstance(self.interface, MbootUARTInterface):
            assert isinstance(self.interface.device, SerialDevice)
            return self.interface.device._device.port
        if isinstance(self.interface, MbootUSBInterface):
            assert isinstance(self.interface.device, UsbDevice)
            return f"{self.interface.device.vid:#06x}:{self.interface.device.pid:#06x}"
        raise SPSDKTpTargetError(f"Unknown target device type: {type(self.interface)}")

    def get_id_hash(self) -> str:
        """Return the ID hash of the interface. (COM port or hash of USB path)."""
        if isinstance(self.interface, MbootUARTInterface):
            assert isinstance(self.interface.device, SerialDevice)
            return self.interface.device._device.port
        if isinstance(self.interface, MbootUSBInterface):
            assert isinstance(self.interface.device, UsbDevice)
            return self.interface.device.path_hash
        raise SPSDKTpTargetError(f"Unknown target device type: {type(self.interface)}")


class TpTargetBlHost(TpTargetInterface):
    """Trust provisioning target adapter for ISP mode over BLHOST."""

    NAME = "blhost"

    class SettingsKey(str, Enum):
        """Keys used in `get_connected_devices` in `settings` dictionary."""

        PORT = "blhost_port"
        USB = "blhost_usb"
        TIMEOUT = "blhost_timeout"
        BAUDRATE = "blhost_baudrate"

    @staticmethod
    def _get_settings(settings: Optional[dict] = None) -> dict:
        """The function gets the important parameters for BLHOST from general settings.

        :param settings: General TPHOST target settings, defaults to None
        :return: Just BLHOST adapter important settings.
        """
        ret = {}
        ret["usb"] = settings.get("blhost_usb", None) if settings else None
        ret["port"] = settings.get("blhost_port", None) if settings else None
        ret["baudrate"] = value_to_int(settings.get("blhost_baudrate", 57600)) if settings else None
        ret["timeout"] = value_to_int(settings.get("blhost_timeout", 50)) if settings else 50
        return ret

    @classmethod
    def get_connected_targets(cls, settings: Optional[dict] = None) -> list[TpIntfDescription]:
        """Get all connected TP targets of this adapter.

        :param settings: Possible settings to determine the way to find connected device, defaults to None.
        :return: List of all founded TP targets.
        """
        ret: list[TpIntfDescription] = []
        desc = cls._get_settings(settings)

        handle_usb = not desc["port"]
        handle_uart = not desc["usb"]
        # special case, when someone defines both 'port' and 'usb'
        if desc["port"] and desc["usb"]:
            handle_uart, handle_usb = True, True

        if handle_usb:
            usb_targets = MbootUSBInterface.scan(desc["usb"])
            for usb_target in usb_targets:
                assert isinstance(usb_target.device, UsbDevice)
                usb_name = usb_target.name
                description = "BLHOST USB target " + str(usb_target.device.interface_number)
                usbt_desc = TpBlHostIntfDescription(usb_name, description, settings)
                usbt_desc.interface = usb_target
                usbt_desc.interface.device.timeout = desc["timeout"]
                ret.append(usbt_desc)

        if handle_uart:
            uart_targets = MbootUARTInterface.scan(desc["port"], desc["baudrate"], desc["timeout"])
            for uart_target in uart_targets:
                assert isinstance(uart_target.device, SerialDevice)
                uart_name = uart_target.device._device.port
                description = "BLHOST UART target"
                uart_desc = TpBlHostIntfDescription(uart_name, description, settings)
                uart_desc.interface = uart_target
                ret.append(uart_desc)

        return ret

    get_connected_interfaces = get_connected_targets

    def __init__(
        self,
        descriptor: TpBlHostIntfDescription,
        family: str,
        *args: Union[int, str],
        **kwargs: Union[int, str],
    ) -> None:
        """Initialization of provisioned device adapter.

        :param descriptor: BLHOST adapter interface description.
        :raises SPSDKTpTargetError: None existing device.
        """
        super().__init__(descriptor=descriptor)
        if not descriptor.interface:
            raise SPSDKTpTargetError("Device is not defined.")
        self.mboot = McuBoot(descriptor.interface)

        self.buffer_address = (
            value_to_int(self.descriptor.settings.get("buffer_address", 0))
            if self.descriptor.settings
            else 0
        )
        if not self.buffer_address:
            db = get_db(family, "latest")
            self.buffer_address = db.get_int(DatabaseManager.COMM_BUFFER, "address")

        self.buffer_size = (
            value_to_int(self.descriptor.settings.get("buffer_size", 0))
            if self.descriptor.settings
            else 0
        )
        if not self.buffer_size:
            db = get_db(family, "latest")
            self.buffer_size = db.get_int(DatabaseManager.COMM_BUFFER, "size", default=0x1000)

    @property
    def uses_uart(self) -> bool:
        """Check if the adapter is using UART for communication."""
        assert isinstance(self.descriptor, TpBlHostIntfDescription)
        return isinstance(self.descriptor.interface, MbootUARTInterface)

    @property
    def uses_usb(self) -> bool:
        """Check if the adapter is using USB for communication."""
        assert isinstance(self.descriptor, TpBlHostIntfDescription)
        return isinstance(self.descriptor.interface, MbootUSBInterface)

    def open(self) -> None:
        """Open the provisioned device adapter."""
        self.mboot.open()
        self.mboot.reopen = True

    @property
    def is_open(self) -> bool:
        """Check if provisioned device adapter is open."""
        return self.mboot._interface.is_opened

    def close(self) -> None:
        """Close the provisioned device adapter."""
        self.mboot.close()

    def reset_device(self) -> None:
        """Reset the connected provisioned device.

        Note: Connection to the target will be closed.
        :raises SPSDKTpTargetError: Cannot reset the target.
        """
        try:
            if not self.mboot.reset(reopen=False):
                raise SPSDKTpTargetError("Cannot reset connected target.")
        except (SPSDKTpTargetError, ValueError, McuBootError) as exc:
            raise SPSDKTpTargetError(
                f"Cannot reset connected target. Error code: {self.mboot.status_string}"
            ) from exc

    def load_sb_file(self, sb_file: bytes, timeout: Optional[int] = None) -> None:
        """Load SB file into provisioned device.

        :param sb_file: SB file data to be loaded into provisioned device.
        :param timeout: Timeout of operation in milliseconds.
        :raises SPSDKTpTargetError: Problem with loading SB image into target.
        """
        if not self.mboot.receive_sb_file(sb_file):
            raise SPSDKTpTargetError(
                f"The loading of SB file to target failed. Error code: {self.mboot.status_string}"
            )

    def prove_genuinity_challenge(self, challenge: bytes, timeout: Optional[int] = None) -> bytes:
        """Prove genuinity and get back the TP response to continue process of TP.

        :param challenge: Challenge data to start TP process.
        :param timeout: Timeout of operation in milliseconds.
        :return: Trust provisioning response for TP process.
        :raises SPSDKTpTargetError: Problem with genuinity challenge.
        """
        if not self.mboot.write_memory(self.buffer_address, challenge):
            raise SPSDKTpTargetError(
                f"Setting of challenge failed. Error code: {self.mboot.status_string}"
            )

        tp_response_length = self.mboot.tp_prove_genuinity(self.buffer_address, self.buffer_size)
        if tp_response_length is None:
            raise SPSDKTpTargetError(
                f"Executing Prove Genuinity failed. Error code: {self.mboot.status_string}"
            )

        ret = self.mboot.read_memory(self.buffer_address, tp_response_length)
        if not ret:
            raise SPSDKTpTargetError(
                f"Reading of Trusted provisioning failed. Error code: {self.mboot.status_string}"
            )

        return ret

    def set_wrapped_data(self, wrapped_data: bytes, timeout: Optional[int] = None) -> None:
        """Provide wrapped data to provisioned device.

        :param wrapped_data: Wrapped data to finish TP process.
        :param timeout: Timeout of operation in milliseconds.
        :raises SPSDKTpTargetError: Problem with memory writing.
        """
        if not self.mboot.write_memory(self.buffer_address, wrapped_data):
            raise SPSDKTpTargetError(
                f"Setting of wrapped data failed. Error code: {self.mboot.status_string}"
            )

        if not self.mboot.tp_set_wrapped_data(self.buffer_address):
            raise SPSDKTpTargetError(
                f"Executing the setting of OEM data failed. Error code: {self.mboot.status_string}"
            )

    @staticmethod
    def get_help() -> str:
        """Return help for this interface, including settings description."""
        return "\n".join(
            [
                "The BLHOST adapter settings allow better specified the BLHOST target, otherwise the",
                "default settings are used - This could lead to find a multiple BLHOST targets connected to system.",
                "The BLHOST target adapter settings:",
                "   - blhost_usb - BLHOST USB device (vid:pid).",
                "   - blhost_port - BLHOST UART device port.",
                "   - blhost_baudrate - BLHOST UART device port baudrate.",
                "   - blhost_timeout - BLHOST device atomic operations timeout.",
                "   - buffer_address - Address in memory used for communication (buffer exchange)",
                "   - buffer_size - Size of the communication buffer; 1kB by default)",
            ]
        )

    @classmethod
    def get_validation_schemas(cls) -> list[dict[str, Any]]:
        """Return all additional validation schemas for interface.

        return: List of all additional validation schemas.
        """
        sch_cfg_file = get_schema_file(DatabaseManager.TP)

        return [sch_cfg_file["target_blhost"]]

    def read_memory(self, address: int, length: int, memory_id: int = 0) -> bytes:
        """Read data from target's memory.

        :param address: Start address
        :param length: Number of bytes to read
        :param memory_id: Memory ID, defaults to 0
        :raises SPSDKTpTargetError: In case of a MBoot failure
        :return: Data read from the target
        """
        data = self.mboot.read_memory(address=address, length=length, mem_id=memory_id)
        if not data:
            raise SPSDKTpTargetError(
                f"Unable to read memory (address=0x{address:08x}, length={length}) "
                f"Error: {self.mboot.status_string}"
            )
        return data

    def write_memory(self, address: int, data: bytes, memory_id: int = 0) -> None:
        """Write data to target's memory.

        :param address: Start address
        :param data: Data to write
        :param memory_id: Memory ID, defaults to 0
        :raises SPSDKTpTargetError: In case of a MBoot failure
        """
        if not self.mboot.write_memory(address=address, data=data, mem_id=memory_id):
            raise SPSDKTpTargetError(
                f"Unable to write data (address=0x{address:08x}) Error: {self.mboot.status_string}"
            )

    def erase_memory(self, address: int, length: int, memory_id: int = 0) -> None:
        """Erase target's memory.

        :param address: Start address
        :param length: Number of bytes to erase
        :param memory_id: Memory ID, defaults to 0
        :raises SPSDKTpTargetError: In case of a MBoot failure
        """
        if not self.mboot.flash_erase_region(address=address, length=length, mem_id=memory_id):
            raise SPSDKTpTargetError(
                f"Unable to erase memory (address=0x{address:08x}, length=0x{length:08x}"
            )

    def check_provisioning_firmware(self) -> bool:
        """Check whether the Provisioning Firmware booted properly.

        :raises SPSDKTpTargetError: In case of a MBoot failure
        :return: True if ProvFW booted up
        """
        try:
            # we expect this command to fail
            # TP_CONTAINERINVALID or FAIL errors mean ProvFW is running
            # UNKNOWN_COMMAND indicates ROM in running
            # any other error code should be re-raised
            self.prove_genuinity_challenge(bytes(self.mboot.DEFAULT_MAX_PACKET_SIZE))
        except SPSDKTpTargetError:
            if self.mboot.status_code in [StatusCode.TP_CONTAINERINVALID, StatusCode.FAIL]:
                return True
            if self.mboot.status_code == StatusCode.UNKNOWN_COMMAND:
                return False
            raise
        # this should never happen
        raise SPSDKTpTargetError("Check for ProvFW boot-up malfunctioned!")
