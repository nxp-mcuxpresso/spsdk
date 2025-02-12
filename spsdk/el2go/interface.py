#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""El2Go Interfaces."""
import logging
from abc import abstractmethod
from types import TracebackType
from typing import Callable, Optional, Type, Union

import click

from spsdk.apps.utils.interface_helper import InterfaceConfig
from spsdk.exceptions import SPSDKError
from spsdk.mboot.mcuboot import McuBoot, StatusCode, stringify_status_code
from spsdk.mboot.properties import PropertyTag
from spsdk.mboot.protocol.base import MbootProtocolBase
from spsdk.uboot.uboot import UbootFastboot, UbootSerial
from spsdk.utils.database import DatabaseManager, get_db, get_families
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)


def extract_device_id(uuid_list: list) -> str:
    """Format UID to be accepted by EdgeLock 2GO API."""
    response_uuid = ""
    for x in uuid_list:
        response_uuid += f"{(x >> 0) & 0xFF:02x}{(x >> 8) & 0xFF:02x}{(x >> 16) & 0xFF:02x}{(x >> 24) & 0xFF:02x}"
    response_uuid = str(int(response_uuid, 16))
    return response_uuid


class El2GoInterface(SpsdkEnum):
    """Enum containing supported EL2Go interfaces."""

    MBOOT = (0, "mboot", "El2Go over mboot")
    UBOOT_SERIAL = (1, "uboot_serial", "EL2Go over U-Boot serial console")
    UBOOT_FASTBOOT = (2, "uboot_fastboot", "EL2Go over fastboot")


class EL2GOInterfaceHandler:
    """Base class for El2Go interface handling."""

    def __init__(
        self,
        device: Union[McuBoot, UbootSerial, UbootFastboot],
        family: Optional[str] = None,
        revision: str = "latest",
        print_func: Callable[[str], None] = click.echo,
    ) -> None:
        """Class object initialized.

        :param device: Communication interface.
        :param family: Target family name.
        :param revision: Target revision, default is use 'latest' revision.
        :param print_func: Custom function to print data, defaults to print
        """
        self.device = device
        self.family = family
        self.revision = revision
        self.print_func = print_func

    @classmethod
    def get_el2go_interface_handler(
        cls,
        interface_params: InterfaceConfig,
        family: Optional[str] = None,
        revision: Optional[str] = "latest",
        interface: Optional[str] = "mboot",
        fb_addr: Optional[int] = None,
        fb_size: Optional[int] = None,
        usb_path: Optional[str] = None,
        usb_serial: Optional[str] = None,
    ) -> "EL2GOInterfaceHandler":
        """Get EL2GO interface handler based on the config.

        :param interface_params: Interface params
        :param family: Family, defaults to None
        :param revision: Revision, defaults to "latest"
        :param interface: Interface, defaults to "mboot"
        :param fb_addr: Address of FB buffer for override, defaults to None
        :param fb_size: Size of FB buffer for override, defaults to None
        :param usb_path: USB path, defaults to None
        :param usb_serial: USB serial, defaults to None
        :raises SPSDKError: If family or port is not provided where required
        :return: Respective class
        """
        revision = revision or "latest"
        port = interface_params.get_scan_args().get("port")
        timeout = interface_params.get_scan_args().get("timeout", 1)

        default_interface = None
        if not interface and not family:
            # Default to Mboot for backward compatibility
            default_interface = El2GoInterface.MBOOT

        if isinstance(interface, str):
            # If the interface is provided as string
            default_interface = El2GoInterface.from_label(interface)
        elif isinstance(family, str):
            # Get the default interface from DB if family is provided
            default_interface = EL2GOInterfaceHandler.get_el2go_interface(family, revision)

        if default_interface is None:
            raise SPSDKError("Unable to determine default interface")

        if default_interface == El2GoInterface.UBOOT_FASTBOOT:
            if not isinstance(family, str):
                raise SPSDKError("Family must be provided for U-Boot Fastboot connection")
            db = get_db(device=family, revision=revision)
            fb_buff_addr = fb_addr or db.get_int(DatabaseManager.FASTBOOT, "address")
            fb_buff_size = fb_size or db.get_int(DatabaseManager.FASTBOOT, "size")

            uboot_device = UbootFastboot(
                timeout=timeout,
                buffer_address=fb_buff_addr,
                buffer_size=fb_buff_size,
                serial_port=port,
            )
            return El2GoInterfaceHandlerUboot(
                device=uboot_device,
                family=family,
                revision=revision,
            )

        if default_interface == El2GoInterface.UBOOT_SERIAL:
            if not isinstance(family, str):
                raise SPSDKError("Family must be provided for U-Boot Serial connection")
            if not port:
                raise SPSDKError("Port must be specified")
            uboot_serial = UbootSerial(port, timeout)
            return El2GoInterfaceHandlerUboot(uboot_serial, family, revision)

        interface_cls = MbootProtocolBase.get_interface_class(interface_params.IDENTIFIER)
        mboot_interface = interface_cls.scan_single(**interface_params.get_scan_args())
        mboot = McuBoot(mboot_interface, cmd_exception=True)

        return El2GoInterfaceHandlerMboot(
            device=mboot,
            family=family,
            revision=revision,
        )

    @staticmethod
    def get_supported_families() -> list[str]:
        """Get list of supported target families.

        :return: List of supported families.
        """
        return get_families(DatabaseManager.EL2GO_TP)

    @staticmethod
    def get_supported_el2go_interfaces() -> list[str]:
        """Get list of supported target families.

        :return: List of supported families.
        """
        return El2GoInterface.labels()

    @staticmethod
    def get_el2go_interface(family: str, revision: Optional[str] = "latest") -> El2GoInterface:
        """Get default ELE device from DB.

        :param family: family name.
        :param revision: Device revision, defaults to 'latest'.
        :return: EleDevice instance.
        """
        revision = revision or "latest"
        return El2GoInterface.from_label(
            get_db(family, revision).get_str(DatabaseManager.EL2GO_TP, "el2go_interface")
        )

    @abstractmethod
    def prepare(self, loader: Optional[str]) -> None:
        """Optional preparation step."""

    @abstractmethod
    def get_version(self) -> str:
        """Return EdgeLock 2GO NXP Provisioning Firmware's version."""

    @abstractmethod
    def get_uuid(self) -> str:
        """Get UUID from the target and store it in a database."""

    @abstractmethod
    def write_memory(self, address: int, data: bytes) -> None:
        """Write memory."""

    @abstractmethod
    def send_command(self, command: str, no_exit: bool = False) -> str:
        """Send command."""

    @abstractmethod
    def reset(self) -> None:
        """Reset target."""

    @abstractmethod
    def run_provisioning(
        self,
        tp_data_address: int,
        use_dispatch_fw: bool = True,
        prov_fw: Optional[bytes] = None,
        dry_run: bool = False,
    ) -> None:
        """Run provisioning.

        :param tp_data_address: TP data address for dispatch FW
        :param use_dispatch_fw: Use dispatch FW, defaults to True
        :param prov_fw: Path to provisioning firmware, only applicable if dispatch FW is not used.
        :param dry_run: Dry run, defaults to False
        """

    def __enter__(self) -> None:
        """Enter function of ELE handler.

        Opens the device if it's not already opened.
        """
        if not self.device.is_opened:
            self.device.open()

    def __exit__(
        self,
        exception_type: Optional[Type[BaseException]] = None,
        exception_value: Optional[BaseException] = None,
        traceback: Optional[TracebackType] = None,
    ) -> None:
        """Close function of El2Go handler.

        Closes the device if it's opened.

        :param exception_type: Type of the exception if one was raised.
        :param exception_value: Exception instance if one was raised.
        :param traceback: Traceback if an exception was raised.
        """
        if self.device.is_opened:
            self.device.close()


class El2GoInterfaceHandlerMboot(EL2GOInterfaceHandler):
    """El2Go Handler over MCUBoot."""

    def __init__(
        self,
        device: McuBoot,
        family: Optional[str] = None,
        revision: str = "latest",
    ) -> None:
        """Class object initialized.

        :param device: mBoot device.
        :param family: Target family name.
        :param revision: Target revision, default is use 'latest' revision.
        """
        super().__init__(
            device,
            family,
            revision,
        )
        if not isinstance(self.device, McuBoot):
            raise SPSDKError("Wrong instance of device, must be MCUBoot")

    def get_version(self) -> str:
        """Return EdgeLock 2GO NXP Provisioning Firmware's version."""
        if not isinstance(self.device, McuBoot):
            raise SPSDKError("Wrong instance of device, must be MCUBoot")
        with self.device as device:
            version_list = device.el2go_get_version()
            if not version_list:
                raise SPSDKError(f"Unable to get FW version. Error: {device.status_string}")

            if device.status_code == StatusCode.SUCCESS:
                version = "{}".format(", ".join(hex(x) for x in version_list))
                version = "v" + version[2] + "." + version[3:5] + "." + version[5:7]
                return version

            raise SPSDKError(f"Unable to get FW version. Error: {device.status_string}")

    def get_uuid(self) -> str:
        """Get UUID."""
        if not isinstance(self.device, McuBoot):
            raise SPSDKError("Wrong instance of device, must be MCUBoot")
        with self.device as device:
            uuid_list = device.get_property(PropertyTag.UNIQUE_DEVICE_IDENT)
            if not uuid_list:
                raise SPSDKError(f"Unable to get UUID. Error: {self.device.status_string}")
            uuid = extract_device_id(uuid_list=uuid_list)
            return uuid

    def write_memory(self, address: int, data: bytes) -> None:
        """Write memory."""
        if not isinstance(self.device, McuBoot):
            raise SPSDKError("Wrong instance of device, must be MCUBoot")
        with self.device as device:
            device.write_memory(address, data)

    def reset(self) -> None:
        """Reset target."""
        if not isinstance(self.device, McuBoot):
            raise SPSDKError("Wrong instance of device, must be MCUBoot")
        with self.device as device:
            device.reset(reopen=False)

    def send_command(self, command: str, no_exit: bool = False) -> str:
        """Send command."""
        logger.error(f"Send command {command} is not implemented for mboot")
        raise SPSDKError("Send command is not supported")

    def prepare(self, loader: Optional[str]) -> None:
        """Prepare device for provisioning."""
        logger.debug("Prepare method is not implemented")

    def run_provisioning(
        self,
        tp_data_address: int,
        use_dispatch_fw: bool = True,
        prov_fw: Optional[bytes] = None,
        dry_run: bool = False,
    ) -> None:
        """Run provisioning.

        :param tp_data_address: TP data address for dispatch FW
        :param use_dispatch_fw: Use dispatch FW, defaults to True
        :param prov_fw: Path to provisioning firmware, only applicable if dispatch FW is not used.
        :param dry_run: Dry run, defaults to False
        """
        if not isinstance(self.device, McuBoot):
            raise SPSDKError("Wrong instance of device, must be MCUBoot")
        with self.device as device:
            if use_dispatch_fw:
                self.print_func("Starting provisioning process")
                status = device.el2go_close_device(tp_data_address, dry_run=dry_run)
                if status is None:
                    raise SPSDKError("Provisioning failed. No response from the firmware.")
                if status != StatusCode.EL2GO_PROV_SUCCESS.tag:
                    raise SPSDKError(
                        f"Provisioning failed with status: {stringify_status_code(status)}"
                    )
            else:
                self.print_func("Uploading ProvFW (Starting provisioning process)")
                if not isinstance(prov_fw, bytes):
                    raise SPSDKError("Provisioning firmware is not provided!")
                device.receive_sb_file(prov_fw)

        self.print_func("Secure Objects provisioned successfully")


class El2GoInterfaceHandlerUboot(EL2GOInterfaceHandler):
    """El2Go Handler over UBoot."""

    UUID_FUSE_READ_COMMAND = "fuse read 6 0 4"
    UUID_FUSE_READ_RESPONSE_START = "Word 0x00000000: "

    def __init__(
        self,
        device: Union[UbootSerial, UbootFastboot],
        family: Optional[str] = None,
        revision: str = "latest",
    ) -> None:
        """Class object initialized.

        :param device: UBoot device.
        :param family: Target family name.
        :param revision: Target revision, default is use 'latest' revision.
        """
        super().__init__(
            device,
            family,
            revision,
        )
        if not isinstance(self.device, (UbootFastboot, UbootSerial)):
            raise SPSDKError("Wrong instance of device, must be Uboot")
        self.uboot_started = False

    def get_version(self) -> str:
        """Return EdgeLock 2GO NXP Provisioning Firmware's version."""
        logger.error("No version available for U-Boot interface")
        return "N/A"

    def prepare(self, loader: Optional[str]) -> None:
        """Prepare device from provisioning."""
        if not isinstance(self.device, (UbootFastboot, UbootSerial)):
            raise SPSDKError("Wrong instance of device, must be Uboot")
        if isinstance(self.device, UbootSerial):
            logger.error("Preparation steps are not supported for U-Boot serial")
            return
        if loader and not self.uboot_started:
            self.device.uuu.run_cmd(f"SDPS[-t 10000]: boot -f {loader}")
            self.device.open()
            self.uboot_started = True

    def get_uuid(self) -> str:
        """Get UUID."""
        if not isinstance(self.device, (UbootFastboot, UbootSerial)):
            raise SPSDKError("Wrong instance of device, must be Uboot")
        self.device.write(self.UUID_FUSE_READ_COMMAND)
        uuid_raw_output = self.device.read_output()
        for line in uuid_raw_output.splitlines():
            if line.startswith(self.UUID_FUSE_READ_RESPONSE_START):
                uuid = line.replace(self.UUID_FUSE_READ_RESPONSE_START, "")
                uuid_lst = [int(x, base=16) for x in uuid.strip().split(" ")]
                uuid = extract_device_id(uuid_lst)
                logger.info(f"Extracted UUID: {uuid}")
                return uuid
        raise SPSDKError("Cannot get UUID from the device")

    def write_memory(self, address: int, data: bytes) -> None:
        """Write memory."""
        if not isinstance(self.device, (UbootFastboot, UbootSerial)):
            raise SPSDKError("Wrong instance of device, must be Uboot")
        self.device.write_memory(address, data)

    def send_command(self, command: str, no_exit: bool = False) -> str:
        """Send command to the target."""
        if not isinstance(self.device, (UbootFastboot, UbootSerial)):
            raise SPSDKError("Wrong instance of device, must be Uboot")
        self.device.write(command, no_exit)
        return self.device.read_output()

    def run_provisioning(
        self,
        tp_data_address: int,
        use_dispatch_fw: bool = True,
        prov_fw: Optional[bytes] = None,
        dry_run: bool = False,
    ) -> None:
        """Run provisioning."""
        logger.debug("Provisioning not supported for U-Boot interface")

    def reset(self) -> None:
        """Reset the target."""
        logger.error("Reset is not supported")
