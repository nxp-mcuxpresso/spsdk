#!/usr/bin/env python
# -*- coding: utf-8 -*-
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
from hexdump import hexdump

from spsdk.apps.utils.interface_helper import InterfaceConfig
from spsdk.exceptions import SPSDKError
from spsdk.mboot.mcuboot import McuBoot, StatusCode, stringify_status_code
from spsdk.mboot.properties import PropertyTag
from spsdk.mboot.protocol.base import MbootProtocolBase
from spsdk.uboot.uboot import UbootFastboot, UbootSerial
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision, get_db, get_families
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
        family: Optional[FamilyRevision] = None,
        print_func: Callable[[str], None] = click.echo,
    ) -> None:
        """Class object initialized.

        :param device: Communication interface.
        :param family: Target family name.
        :param print_func: Custom function to print data, defaults to print
        """
        self.device = device
        self.family = family
        self.print_func = print_func
        self.db = get_db(family=self.family) if self.family else None

    @classmethod
    def get_el2go_interface_handler(
        cls,
        interface_params: InterfaceConfig,
        family: Optional[FamilyRevision] = None,
        interface: Optional[str] = "mboot",
        fb_addr: Optional[int] = None,
        fb_size: Optional[int] = None,
        usb_path: Optional[str] = None,
        usb_serial: Optional[str] = None,
    ) -> "EL2GOInterfaceHandler":
        """Get EL2GO interface handler based on the config.

        :param interface_params: Interface params
        :param family: Family, defaults to None
        :param interface: Interface, defaults to "mboot"
        :param fb_addr: Address of FB buffer for override, defaults to None
        :param fb_size: Size of FB buffer for override, defaults to None
        :param usb_path: USB path, defaults to None
        :param usb_serial: USB serial, defaults to None
        :raises SPSDKError: If family or port is not provided where required
        :return: Respective class
        """
        port = interface_params.get_scan_args().get("port")
        timeout = interface_params.get_scan_args().get("timeout", 1)

        default_interface = None
        if not interface and not family:
            # Default to Mboot for backward compatibility
            default_interface = El2GoInterface.MBOOT

        if isinstance(interface, str):
            # If the interface is provided as string
            default_interface = El2GoInterface.from_label(interface)
        elif isinstance(family, FamilyRevision):
            # Get the default interface from DB if family is provided
            default_interface = EL2GOInterfaceHandler.get_el2go_interface(family)

        if default_interface is None:
            raise SPSDKError("Unable to determine default interface")

        if default_interface == El2GoInterface.UBOOT_FASTBOOT:
            if not isinstance(family, FamilyRevision):
                raise SPSDKError("Family must be provided for U-Boot Fastboot connection")
            db = get_db(family=family)
            fb_buff_addr = fb_addr or db.get_int(DatabaseManager.FASTBOOT, "address")
            fb_buff_size = fb_size or db.get_int(DatabaseManager.FASTBOOT, "size")

            uboot_device = UbootFastboot(
                timeout=timeout,
                buffer_address=fb_buff_addr,
                buffer_size=fb_buff_size,
                serial_port=port,
                usb_path_filter=usb_path,
                usb_serial_no_filter=usb_serial,
            )
            return El2GoInterfaceHandlerUboot(device=uboot_device, family=family)

        if default_interface == El2GoInterface.UBOOT_SERIAL:
            if not isinstance(family, FamilyRevision):
                raise SPSDKError("Family must be provided for U-Boot Serial connection")
            if not port:
                raise SPSDKError("Port must be specified")
            uboot_serial = UbootSerial(port, timeout)
            return El2GoInterfaceHandlerUboot(uboot_serial, family)

        interface_cls = MbootProtocolBase.get_interface_class(interface_params.IDENTIFIER)
        mboot_interface = interface_cls.scan_single(**interface_params.get_scan_args())
        mboot = McuBoot(mboot_interface, cmd_exception=True, family=family)

        return El2GoInterfaceHandlerMboot(device=mboot, family=family)

    @staticmethod
    def get_supported_families() -> list[FamilyRevision]:
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
    def get_el2go_interface(family: FamilyRevision) -> El2GoInterface:
        """Get default ELE device from DB.

        :param family: family name.
        :return: EleDevice instance.
        """
        return El2GoInterface.from_label(
            get_db(family).get_str(DatabaseManager.EL2GO_TP, "el2go_interface")
        )

    @property
    def buffer_address(self) -> int:
        """Get the buffer address from the database.

        :return: Buffer address for the specific family
        :raises SPSDKError: If no database context is available
        """
        if not self.db:
            raise SPSDKError("No database context available")
        return self.db.get_int(DatabaseManager.COMM_BUFFER, "buffer_address")

    def write_to_buff(self, data: bytes, offset: int = 0) -> None:
        """Write data to a buffer with optional offset."""
        address = self.buffer_address + offset
        self.write_memory(address=address, data=data)

    @abstractmethod
    def prepare(self, loader: Optional[str]) -> None:
        """Optional preparation step."""

    @abstractmethod
    def prepare_dispatch(
        self,
        secure_objects: bytes,
        secure_objects_address: int,
        prov_fw: Optional[bytes] = None,
        prov_fw_address: Optional[int] = None,
    ) -> None:
        """Prepare device to run NXP Provisioning Firmware."""

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
    def reset(self, reopen: bool = False) -> None:
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

    @abstractmethod
    def run_batch_provisioning(
        self,
        tp_data_address: int,
        use_dispatch_fw: bool = True,
        prov_fw: Optional[bytes] = None,
        prov_report_address: Optional[int] = None,
        dry_run: bool = False,
    ) -> Optional[bytes]:
        """Run provisioning using Batch mode.

        :param tp_data_address: TP data address for dispatch FW
        :param use_dispatch_fw: Use dispatch FW, defaults to True, defaults to True
        :param prov_fw: Path to provisioning firmware, only applicable if dispatch FW is not used., defaults to None
        :param dry_run: Dry run, defaults to False
        :param prov_report_address: Address where to store Provisioning Report,
            defaults to None = don't store the report
        :returns: Provisioning report
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

    def __init__(self, device: McuBoot, family: Optional[FamilyRevision] = None) -> None:
        """Class object initialized.

        :param device: mBoot device.
        :param family: Target family name.
        """
        super().__init__(device, family)
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

    def reset(self, reopen: bool = False) -> None:
        """Reset target."""
        if not isinstance(self.device, McuBoot):
            raise SPSDKError("Wrong instance of device, must be MCUBoot")
        with self.device as device:
            device.reset(reopen=reopen)

    def send_command(self, command: str, no_exit: bool = False) -> str:
        """Send command."""
        logger.error(f"Send command {command} is not implemented for mboot")
        raise SPSDKError("Send command is not supported")

    def prepare(self, loader: Optional[str]) -> None:
        """Prepare device for provisioning."""
        logger.debug("Prepare method is not implemented")

    def prepare_dispatch(
        self,
        secure_objects: bytes,
        secure_objects_address: int,
        prov_fw: Optional[bytes] = None,
        prov_fw_address: Optional[int] = None,
    ) -> None:
        """Prepare device to run NXP Provisioning Firmware."""
        if not isinstance(self.device, McuBoot):
            raise SPSDKError("Wrong instance of device, must be MCUBoot")
        with self.device as device:
            result = device.flash_erase_region(secure_objects_address, len(secure_objects))
            if not result:
                raise SPSDKError(
                    f"Failed to erase secure objects region. Error: {device.status_string}"
                )
            result = device.write_memory(secure_objects_address, secure_objects)
            if not result:
                raise SPSDKError(f"Failed to write secure objects. Error: {device.status_string}")
            if prov_fw is not None and prov_fw_address is not None:
                result = device.flash_erase_region(prov_fw_address, len(prov_fw))
                if not result:
                    raise SPSDKError(
                        f"Failed to erase  provisioning firmware region. Error: {device.status_string}"
                    )
                result = device.write_memory(prov_fw_address, prov_fw)
                if not result:
                    raise SPSDKError(
                        f"Failed to write provisioning firmware. Error: {device.status_string}"
                    )
            device.reset(reopen=False)

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

    def run_batch_provisioning(
        self,
        tp_data_address: Optional[int] = True,
        use_dispatch_fw: bool = True,
        prov_fw: Optional[bytes] = None,
        prov_report_address: Optional[int] = None,
        dry_run: bool = False,
    ) -> Optional[bytes]:
        """Run provisioning in Batch mode.

        :param tp_data_address: TP data address for dispatch FW
        :param use_dispatch_fw: Use dispatch FW, defaults to True
        :param prov_fw: Path to provisioning firmware, only applicable if dispatch FW is not used.
        :param prov_report_address: Address where to store Provisioning Report,
            defaults to None = don't store the report
        :param dry_run: Dry run, defaults to False
        :returns: Provisioning report (in case the provisioning process was executed successfully)
        """
        if not isinstance(self.device, McuBoot):
            raise SPSDKError("Wrong instance of device, must be MCUBoot")
        with self.device as device:
            if use_dispatch_fw:
                self.print_func("Starting provisioning process in batch mode")
                status, report = device.el2go_batch_tp(
                    data_address=tp_data_address or self.buffer_address,
                    report_address=prov_report_address or 0xFFFF_FFFF,
                    dry_run=dry_run,
                )
                if status is None:
                    raise SPSDKError("Provisioning failed. No response from the firmware.")
                if status != StatusCode.EL2GO_PROV_SUCCESS.tag:
                    raise SPSDKError(
                        f"Provisioning failed with status: {stringify_status_code(status)}"
                    )

                if prov_report_address is not None and prov_report_address != 0xFFFF_FFFF:
                    self.print_func(
                        f"Provisioning report stored at address: {hex(prov_report_address)}"
                    )
                self.print_func("Secure Objects provisioned successfully")
                if report:
                    logger.debug("Provisioning report content")
                    logger.debug(hexdump(report))
                    return report
                logger.info("No report available")
                return None
            raise NotImplementedError("Batch mode without dispatch FW is not supported.")


class El2GoInterfaceHandlerUboot(EL2GOInterfaceHandler):
    """El2Go Handler over UBoot."""

    UUID_FUSE_READ_COMMAND = "fuse read"
    UUID_FUSE_READ_RESPONSE_START = "Word 0x00000000: "

    def __init__(
        self, device: Union[UbootSerial, UbootFastboot], family: Optional[FamilyRevision] = None
    ) -> None:
        """Class object initialized.

        :param device: UBoot device.
        :param family: Target family name.
        :param revision: Target revision, default is use 'latest' revision.
        """
        super().__init__(device, family)
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
        if not self.family:
            raise SPSDKError("Family must be specified to get UUID")
        db = get_db(self.family)
        fuse_index = db.get_str(DatabaseManager.EL2GO_TP, "uuid_fuse_index", default="6 0 4")
        self.device.write(f"{self.UUID_FUSE_READ_COMMAND} {fuse_index}")
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
        raise NotImplementedError("Provisioning not supported for U-Boot interface")

    def run_batch_provisioning(
        self,
        tp_data_address: int,
        use_dispatch_fw: bool = True,
        prov_fw: Optional[bytes] = None,
        prov_report_address: Optional[int] = None,
        dry_run: bool = False,
    ) -> Optional[bytes]:
        """Run provisioning in Batch mode."""
        raise NotImplementedError("Batch Mode Provisioning not supported for U-Boot interface")

    def reset(self, reopen: bool = False) -> None:
        """Reset the target."""
        logger.error("Reset is not supported")

    def prepare_dispatch(
        self,
        secure_objects: bytes,
        secure_objects_address: int,
        prov_fw: Optional[bytes] = None,
        prov_fw_address: Optional[int] = None,
    ) -> None:
        """Prepare device to run NXP Provisioning Firmware."""
        raise NotImplementedError("Provisioning not supported for U-Boot interface")
