#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK EL2GO interface management for secure device provisioning.

This module provides abstract and concrete interface implementations for communicating
with devices during the EL2GO (EdgeLock 2GO) provisioning process. It includes handlers
for different boot modes and connection protocols.
"""

import logging
import os
from abc import abstractmethod
from functools import wraps
from types import TracebackType
from typing import Any, Callable, Optional, Type, TypeVar, Union

import click
from hexdump import hexdump

from spsdk.apps.utils.interface_helper import InterfaceConfig
from spsdk.el2go.api_utils import EL2GOTPClient
from spsdk.el2go.client import CleanMethod
from spsdk.el2go.secure_objects import SecureObjects
from spsdk.exceptions import SPSDKError, SPSDKNotImplementedError, SPSDKUnsupportedOperation
from spsdk.mboot.mcuboot import McuBoot, StatusCode, stringify_status_code
from spsdk.mboot.properties import PropertyTag
from spsdk.mboot.protocol.base import MbootProtocolBase
from spsdk.uboot.uboot import UbootFastboot, UbootSerial
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision, get_db, get_families
from spsdk.utils.misc import write_file
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)


def extract_device_id(uuid_list: list) -> str:
    """Extract device ID from UUID list for EdgeLock 2GO API.

    Converts a list of UUID integers into a formatted string representation
    that is compatible with the EdgeLock 2GO API requirements. Each UUID
    integer is processed byte by byte and concatenated into a hexadecimal
    string, which is then converted to a decimal string.

    :param uuid_list: List of UUID integers to be processed.
    :return: Formatted device ID as decimal string for EdgeLock 2GO API.
    """
    response_uuid = ""
    for x in uuid_list:
        response_uuid += f"{(x >> 0) & 0xFF:02x}{(x >> 8) & 0xFF:02x}{(x >> 16) & 0xFF:02x}{(x >> 24) & 0xFF:02x}"
    response_uuid = str(int(response_uuid, 16))
    return response_uuid


F = TypeVar("F", bound=Callable[..., Any])


def verify_fastboot_connection(timeout: int = 2) -> Callable[[F], F]:
    """Decorator to verify device connection before method execution.

    Verifies both fastboot and serial connections with appropriate timeout handling.
    For fastboot connections, performs active connection verification with timeout.
    For serial connections, checks if the port is opened and available.

    :param timeout: Timeout in seconds for fastboot connection verification, defaults to 2
    :raises SPSDKError: When fastboot connection is not available or serial port is not open
    :return: Decorator function that wraps methods requiring verified device connection
    """

    def decorator(func: F) -> F:
        """Decorator to verify device connection before executing El2Go interface methods.

        This decorator checks the connection status of the underlying device (either Fastboot or Serial)
        and ensures it's available before allowing the decorated method to execute. For Fastboot devices,
        it verifies the connection with a timeout. For Serial devices, it checks if the port is open.

        :param func: The function to be decorated.
        :raises SPSDKError: If the device connection is not available or the serial port is not open.
        :return: The decorated function with connection verification.
        """

        @wraps(func)
        def wrapper(self: "El2GoInterfaceHandlerUboot", *args: Any, **kwargs: Any) -> Any:
            """Wrapper function to verify device connection before executing El2Go interface methods.

            Validates the connection state for both Fastboot and Serial device types before allowing
            method execution. For Fastboot devices, performs timeout-based connection verification.
            For Serial devices, checks if the connection is open and available.

            :param self: El2GoInterfaceHandlerUboot instance.
            :param args: Variable length argument list to pass to the wrapped function.
            :param kwargs: Arbitrary keyword arguments to pass to the wrapped function.
            :raises SPSDKError: When Fastboot connection verification fails or Serial connection
                is not open.
            :return: Result from the wrapped function execution.
            """
            if isinstance(self.device, UbootFastboot):
                if not self.device.verify_connection(timeout=timeout):
                    raise SPSDKError(
                        f"Fastboot connection is not available for {func.__name__}. "
                        "Please ensure the device is in fastboot mode."
                    )
            elif isinstance(self.device, UbootSerial):
                # For UART/serial connections, just check if the device is opened
                # No timeout verification as UART doesn't have the same timeout behavior
                if not self.device.is_opened:
                    raise SPSDKError(
                        f"Serial connection is not open for {func.__name__}. "
                        "Please ensure the device is connected and the serial port is available."
                    )
                logger.debug(f"Serial connection verified for {func.__name__}")
            return func(self, *args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator


class El2GoInterface(SpsdkEnum):
    """EL2Go Interface enumeration for SPSDK operations.

    This enumeration defines the supported communication interfaces for EL2Go
    (Edge Lock 2 Go) provisioning operations, including mboot, U-Boot serial
    console, and fastboot protocols.
    """

    MBOOT = (0, "mboot", "El2Go over mboot")
    UBOOT_SERIAL = (1, "uboot_serial", "EL2Go over U-Boot serial console")
    UBOOT_FASTBOOT = (2, "uboot_fastboot", "EL2Go over fastboot")


class EL2GOInterfaceHandler:
    """EL2GO Interface Handler for secure provisioning operations.

    This class provides a unified interface for communicating with NXP MCU devices
    during EL2GO (EdgeLock 2GO) secure provisioning workflows. It abstracts the
    underlying communication protocols (McuBoot, U-Boot Serial, U-Boot Fastboot)
    and manages device interactions for provisioning operations.
    The handler supports multiple interface types and provides methods for device
    preparation, buffer management, and version detection across the NXP MCU
    portfolio.
    """

    def __init__(
        self,
        device: Union[McuBoot, UbootSerial, UbootFastboot],
        family: Optional[FamilyRevision] = None,
        print_func: Callable[[str], None] = click.echo,
    ) -> None:
        """Initialize EL2GO interface with device communication and configuration.

        :param device: Communication interface for target device operations.
        :param family: Target MCU family revision for device-specific operations.
        :param print_func: Custom function to print data, defaults to click.echo.
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
        """Get EL2GO interface handler based on the configuration.

        Creates and returns an appropriate EL2GO interface handler instance based on the provided
        configuration parameters. Supports multiple interface types including MBoot, U-Boot Fastboot,
        and U-Boot Serial connections.

        :param interface_params: Interface configuration parameters containing connection details.
        :param family: Target MCU family revision for interface-specific operations.
        :param interface: Interface type identifier, defaults to "mboot".
        :param fb_addr: Custom address for Fastboot buffer, overrides database default.
        :param fb_size: Custom size for Fastboot buffer, overrides database default.
        :param usb_path: USB device path filter for device identification.
        :param usb_serial: USB serial number filter for device identification.
        :raises SPSDKError: If family or port is not provided when required by interface type.
        :raises SPSDKError: If unable to determine the default interface type.
        :return: Configured EL2GO interface handler instance for the specified interface type.
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

        :return: List of supported families with their revisions.
        """
        return get_families(DatabaseManager.EL2GO_TP)

    @staticmethod
    def get_supported_el2go_interfaces() -> list[str]:
        """Get list of supported EL2GO interfaces.

        :return: List of supported EL2GO interface labels.
        """
        return El2GoInterface.labels()

    @staticmethod
    def get_el2go_interface(family: FamilyRevision) -> El2GoInterface:
        """Get EL2GO interface for specified family.

        Retrieves the default EL2GO interface configuration from the database for the given
        family revision.

        :param family: Family revision to get EL2GO interface for.
        :return: EL2GO interface instance configured for the specified family.
        """
        return El2GoInterface.from_label(
            get_db(family).get_str(DatabaseManager.EL2GO_TP, "el2go_interface")
        )

    @property
    def buffer_address(self) -> int:
        """Get the buffer address from the database.

        Retrieves the communication buffer address for the specific MCU family from the database
        configuration.

        :return: Buffer address as integer value for the specific family.
        :raises SPSDKError: If no database context is available.
        """
        if not self.db:
            raise SPSDKError("No database context available")
        return self.db.get_int(DatabaseManager.COMM_BUFFER, "buffer_address")

    def write_to_buff(self, data: bytes, offset: int = 0) -> None:
        """Write data to a buffer with optional offset.

        :param data: Binary data to write to the buffer.
        :param offset: Byte offset from the buffer start address, defaults to 0.
        :raises SPSDKError: If memory write operation fails.
        """
        address = self.buffer_address + offset
        self.write_memory(address=address, data=data)

    @abstractmethod
    def prepare(self, loader: Optional[str]) -> None:
        """Optional preparation step for the EL2GO interface.

        This method allows for any necessary setup or initialization before
        the main operations are performed.

        :param loader: Optional loader specification for preparation setup.
        """

    @abstractmethod
    def prepare_dispatch(self, secure_objects: bytes, client: EL2GOTPClient) -> None:
        """Prepare device to run NXP Provisioning Firmware.

        This method configures the device with the provided secure objects and establishes
        communication with the EL2GO OTP client to prepare for provisioning operations.

        :param secure_objects: Binary data containing secure objects for device configuration.
        :param client: EL2GO OTP client instance for communication with the provisioning service.
        """

    @abstractmethod
    def get_version(self) -> str:
        """Get EdgeLock 2GO NXP Provisioning Firmware version.

        :return: Version string of the EdgeLock 2GO NXP Provisioning Firmware.
        """

    @abstractmethod
    def get_uuid(self) -> str:
        """Get UUID from the target and store it in a database.

        :return: UUID string retrieved from the target device.
        """

    @abstractmethod
    def write_memory(self, address: int, data: bytes) -> None:
        """Write memory to specified address.

        :param address: Memory address where data should be written.
        :param data: Binary data to write to memory.
        """

    @abstractmethod
    def send_command(self, command: str, no_exit: bool = False) -> str:
        """Send command to the EL2GO interface.

        This method executes a command string through the EL2GO interface and returns
        the response. The command execution behavior can be controlled through the
        no_exit parameter.

        :param command: Command string to be executed.
        :param no_exit: If True, prevents automatic exit on command failure.
        :return: Response string from the executed command.
        """

    @abstractmethod
    def reset(self, reopen: bool = False) -> None:
        """Reset target.

        :param reopen: Whether to reopen the connection after reset, defaults to False.
        """

    @abstractmethod
    def write_secure_objects(
        self,
        client: EL2GOTPClient,
        secure_objects: bytes,
        workspace: Optional[str] = None,
        clean: bool = False,
    ) -> None:
        """Write secure objects to the device memory.

        This method handles the provisioning of secure objects to the target device through
        the EL2GO OTP client interface.

        :param client: EL2GO OTP client instance for device communication.
        :param secure_objects: Binary data containing the secure objects to be written.
        :param workspace: Optional workspace identifier for the operation.
        :param clean: Flag to indicate whether to clean existing data before writing.
        """

    @abstractmethod
    def write_secure_objects_prod(
        self,
        client: EL2GOTPClient,
        secure_objects: bytes,
        workspace: Optional[str] = None,
        clean: bool = False,
    ) -> None:
        """Write secure objects to the device memory.

        This method handles the writing of secure objects to device memory using the EL2GO OTP client,
        with optional workspace specification and cleanup functionality.

        :param client: EL2GO OTP client instance for device communication.
        :param secure_objects: Binary data containing the secure objects to be written.
        :param workspace: Optional workspace identifier for the operation.
        :param clean: Whether to perform cleanup operations after writing.
        """

    @abstractmethod
    def run_provisioning(
        self,
        client: EL2GOTPClient,
        dry_run: bool = False,
    ) -> None:
        """Run provisioning process for the device.

        Executes the complete provisioning workflow using the provided EL2GO TP client.
        In dry run mode, the process is simulated without actual device modifications.

        :param client: EL2GO TP Client instance for communication with EL2GO service
        :param dry_run: If True, simulate provisioning without actual device changes,
            defaults to False
        """

    @abstractmethod
    def run_batch_provisioning(
        self,
        client: EL2GOTPClient,
        dry_run: bool = False,
    ) -> Optional[bytes]:
        """Run provisioning using Batch mode.

        This method executes the batch provisioning process using the provided EL2GO TP client.
        The dry run option allows testing the provisioning flow without actual execution.

        :param client: EL2GO TP Client instance used for provisioning operations.
        :param dry_run: If True, performs a test run without actual provisioning, defaults to False.
        :return: Provisioning data as bytes if successful, None if dry run or no data available.
        """

    def __enter__(self) -> None:
        """Enter the ELE handler context manager.

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
    """EdgeLock 2GO interface handler using MCUBoot communication protocol.

    This class provides EdgeLock 2GO provisioning functionality through MCUBoot
    interface, enabling secure provisioning operations including version retrieval,
    UUID extraction, memory operations, and secure object management on NXP MCUs.
    """

    def __init__(self, device: McuBoot, family: Optional[FamilyRevision] = None) -> None:
        """Initialize EL2GO interface with MCU boot device.

        :param device: MCU boot device instance for communication.
        :param family: Target MCU family revision, defaults to None for auto-detection.
        :raises SPSDKError: If device is not a valid McuBoot instance.
        """
        super().__init__(device, family)
        if not isinstance(self.device, McuBoot):
            raise SPSDKError("Wrong instance of device, must be MCUBoot")

    def get_version(self) -> str:
        """Get EdgeLock 2GO NXP Provisioning Firmware version.

        Retrieves the firmware version from the EdgeLock 2GO provisioning device and formats
        it as a human-readable version string.

        :raises SPSDKError: If device is not MCUBoot instance, unable to get version,
                           or communication fails.
        :return: Formatted version string in format "vX.XX.XX".
        """
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
        """Get device UUID from MCU.

        Retrieves the unique device identifier from the connected MCU device
        using the MCUBoot interface.

        :raises SPSDKError: If device is not MCUBoot instance or UUID retrieval fails.
        :return: Device UUID as string.
        """
        if not isinstance(self.device, McuBoot):
            raise SPSDKError("Wrong instance of device, must be MCUBoot")
        with self.device as device:
            uuid_list = device.get_property(PropertyTag.UNIQUE_DEVICE_IDENT)
            if not uuid_list:
                raise SPSDKError(f"Unable to get UUID. Error: {self.device.status_string}")
            uuid = extract_device_id(uuid_list=uuid_list)
            return uuid

    def write_memory(self, address: int, data: bytes) -> None:
        """Write memory data to specified address on the device.

        This method writes the provided data bytes to the specified memory address
        using the MCUBoot device interface.

        :param address: Memory address where data should be written.
        :param data: Data bytes to write to memory.
        :raises SPSDKError: If device is not an MCUBoot instance.
        """
        if not isinstance(self.device, McuBoot):
            raise SPSDKError("Wrong instance of device, must be MCUBoot")
        with self.device as device:
            device.write_memory(address, data)

    def receive_sb_file(self, data: bytes) -> None:
        """Receive SB file to the connected MCU device.

        This method sends a Secure Binary (SB) file to the MCU device using the MCUBoot
        protocol. The device must be an instance of McuBoot for this operation to succeed.

        :param data: The SB file content as bytes to be sent to the device.
        :raises SPSDKError: If the device is not an instance of McuBoot.
        """
        if not isinstance(self.device, McuBoot):
            raise SPSDKError("Wrong instance of device, must be MCUBoot")
        with self.device as device:
            device.receive_sb_file(data=data)

    def run_cleanup_method(self, client: EL2GOTPClient) -> None:
        """Run cleanup method based on client configuration.

        Executes the appropriate cleanup procedure for the device based on the client's
        clean_method setting. Supports NONE (no cleanup) and ERASE_CMPA (erase Customer
        Manufacturing Programming Area) methods.

        :param client: EL2GO TP client containing cleanup method configuration.
        :raises SPSDKUnsupportedOperation: When an unsupported cleanup method is specified.
        """
        if client.clean_method == CleanMethod.NONE:
            logger.info(f"Device {self.family} doesn't have a registered cleanup method")
            return
        if client.clean_method == CleanMethod.ERASE_CMPA:
            # don't use top-level import to save time in production, where this functionality is not required
            from spsdk.pfr.pfr import CMPA

            if not client.family or not client.db:
                logger.error("Family and DB must be provided for CMPA cleanup method")
                return
            cmpa = CMPA(family=client.family)
            cmpa.set_config(Config())
            cmpa_data = cmpa.export(draw=False)
            cmpa_address = client.db.get_int(DatabaseManager.PFR, ["cmpa", "address"])

            self.write_memory(address=cmpa_address, data=cmpa_data)
            return

        raise SPSDKUnsupportedOperation(f"Unsupported cleanup method {client.clean_method}")

    def write_secure_objects(
        self,
        client: EL2GOTPClient,
        secure_objects: bytes,
        workspace: Optional[str] = None,
        clean: bool = False,
    ) -> None:
        """Write secure objects to device memory using the specified EL2GO client configuration.

        This method handles different provisioning methods including dispatch firmware,
        user configuration, and data splitting approaches. It validates secure objects,
        optionally saves files to workspace, and writes data to appropriate memory addresses.

        :param client: EL2GO OTP client containing configuration and provisioning settings.
        :param secure_objects: Binary data containing the secure objects to be written.
        :param workspace: Optional directory path to save intermediate files during provisioning.
        :param clean: Whether to perform cleanup method before writing secure objects.
        :raises SPSDKNotImplementedError: When unsupported provisioning method is configured.
        """
        if workspace:
            write_file(secure_objects, os.path.join(workspace, "secure_objects.bin"), mode="wb")

        user_config, fw_read_address, user_data_address = client.create_user_config()
        if workspace and user_config:
            write_file(user_config, os.path.join(workspace, "user_config.bin"), mode="wb")

        so_list = SecureObjects.parse(secure_objects)
        so_list.validate(family=client.family)

        if clean:
            logger.info("Performing cleanup method")
            self.run_cleanup_method(client=client)
        if client.use_dispatch_fw:
            logger.info(f"Writing Secure Objects to: {hex(fw_read_address)}")
            self.write_memory(address=fw_read_address, data=secure_objects)
            if client.prov_fw:
                if client.use_dispatch_write:
                    logger.info("Uploading ProvFW using write-memory")
                    self.write_memory(address=client.fw_load_address, data=client.prov_fw)
                if client.use_dispatch_sb_file:
                    logger.info("Uploading ProvFW using receive-sb-file")
                    self.receive_sb_file(data=client.prov_fw)
            if client.use_dispatch_reset:
                logger.info("Resetting the device (Starting Provisioning FW)")
                self.reset()
        elif client.use_user_config:
            click.echo(f"Writing User config data to: {hex(fw_read_address)}")
            self.write_memory(address=fw_read_address, data=user_config)
            click.echo(f"Writing Secure Objects to: {hex(user_data_address)}")
            self.write_memory(address=user_data_address, data=secure_objects)
        elif client.use_data_split:
            internal, external = so_list.split_int_ext()
            if internal:
                if workspace:
                    write_file(internal, os.path.join(workspace, "internal_so.bin"), mode="wb")
                click.echo(f"Writing Internal Secure Objects to: {hex(fw_read_address)}")
                self.write_memory(address=fw_read_address, data=internal)
            if external:
                if workspace:
                    write_file(external, os.path.join(workspace, "external_so.bin"), mode="wb")
                click.echo(f"Writing External Secure Objects to: {hex(user_data_address)}")
                self.write_memory(address=user_data_address, data=external)
        else:
            raise SPSDKNotImplementedError("Unsupported provisioning method")

        logger.info("Secure Objects uploaded successfully")

    def write_secure_objects_prod(
        self,
        client: EL2GOTPClient,
        secure_objects: bytes,
        workspace: Optional[str] = None,
        clean: bool = False,
    ) -> None:
        """Write secure objects to the device memory for production environment.

        This method is a wrapper around write_secure_objects specifically designed for
        production deployment scenarios.

        :param client: EL2GO OTP client instance for communication.
        :param secure_objects: Binary data containing the secure objects to write.
        :param workspace: Optional workspace identifier for the operation.
        :param clean: Whether to clean the target memory before writing.
        """
        self.write_secure_objects(
            client=client, secure_objects=secure_objects, workspace=workspace, clean=clean
        )

    def reset(self, reopen: bool = False) -> None:
        """Reset target device.

        Performs a reset operation on the target MCU device through the MCUBoot interface.

        :param reopen: Whether to reopen the connection after reset, defaults to False
        :raises SPSDKError: If the device instance is not of type McuBoot
        """
        if not isinstance(self.device, McuBoot):
            raise SPSDKError("Wrong instance of device, must be MCUBoot")
        with self.device as device:
            device.reset(reopen=reopen)

    def send_command(self, command: str, no_exit: bool = False) -> str:
        """Send command to the interface.

        This method is not implemented for mboot interface and will always raise an exception.

        :param command: Command string to be sent to the interface.
        :param no_exit: Flag to control exit behavior on command failure.
        :raises SPSDKError: Always raised as send command is not supported for this interface.
        """
        logger.error(f"Send command {command} is not implemented for mboot")
        raise SPSDKError("Send command is not supported")

    def prepare(self, loader: Optional[str]) -> None:
        """Prepare device for provisioning.

        This method should be implemented by subclasses to perform device-specific
        preparation steps required before the provisioning process can begin.

        :param loader: Optional loader specification for device preparation.
        """
        logger.debug("Prepare method is not implemented")

    def prepare_dispatch(self, secure_objects: bytes, client: EL2GOTPClient) -> None:
        """Prepare device to run NXP Provisioning Firmware.

        This method erases and writes secure objects to the device memory, and optionally
        loads provisioning firmware if provided. The device is reset after the operation
        to prepare it for running the provisioning firmware.

        :param secure_objects: Binary data containing secure objects to be written to device.
        :param client: EL2GO OTP client containing configuration and optional firmware data.
        :raises SPSDKError: If device is not MCUBoot instance or memory operations fail.
        """
        if not isinstance(self.device, McuBoot):
            raise SPSDKError("Wrong instance of device, must be MCUBoot")
        with self.device as device:
            result = device.flash_erase_region(client.tp_data_address, len(secure_objects))
            if not result:
                raise SPSDKError(
                    f"Failed to erase secure objects region. Error: {device.status_string}"
                )
            result = device.write_memory(client.tp_data_address, secure_objects)
            if not result:
                raise SPSDKError(f"Failed to write secure objects. Error: {device.status_string}")
            if client.prov_fw is not None and client.fw_load_address is not None:
                result = device.flash_erase_region(client.fw_load_address, len(client.prov_fw))
                if not result:
                    raise SPSDKError(
                        f"Failed to erase  provisioning firmware region. Error: {device.status_string}"
                    )
                result = device.write_memory(client.fw_load_address, client.prov_fw)
                if not result:
                    raise SPSDKError(
                        f"Failed to write provisioning firmware. Error: {device.status_string}"
                    )
            device.reset(reopen=False)

    def run_provisioning(
        self,
        client: EL2GOTPClient,
        dry_run: bool = False,
    ) -> None:
        """Run provisioning process on the target device.

        Executes the EL2GO provisioning workflow either using dispatch firmware
        or by uploading provisioning firmware to the MCU device.

        :param client: EL2GO TP Client instance containing provisioning data
        :param dry_run: If True, performs validation without actual provisioning
        :raises SPSDKError: If device is not McuBoot instance, provisioning fails,
                           or provisioning firmware is not provided
        """
        if not isinstance(self.device, McuBoot):
            raise SPSDKError("Wrong instance of device, must be MCUBoot")
        with self.device as device:
            if client.use_dispatch_fw:
                self.print_func(
                    f"Starting provisioning process: SO address {hex(client.tp_data_address)}, dry_run={dry_run}"
                )
                status = device.el2go_close_device(client.tp_data_address, dry_run=dry_run)
                if status is None:
                    raise SPSDKError("Provisioning failed. No response from the firmware.")
                if status != StatusCode.EL2GO_PROV_SUCCESS.tag:
                    raise SPSDKError(
                        f"Provisioning failed with status: {stringify_status_code(status)}"
                    )
            else:
                self.print_func("Uploading ProvFW (Starting provisioning process)")
                if not isinstance(client.prov_fw, bytes):
                    raise SPSDKError("Provisioning firmware is not provided!")
                device.receive_sb_file(client.prov_fw)

        self.print_func("Secure Objects provisioned successfully")

    def run_batch_provisioning(
        self,
        client: EL2GOTPClient,
        dry_run: bool = False,
    ) -> Optional[bytes]:
        """Run provisioning using Batch mode.

        This method executes the EL2GO Trust Provisioning process in batch mode using the MCUBoot
        device interface. It requires a dispatch firmware to be loaded on the target device.

        :param client: EL2GO TP Client instance containing provisioning configuration
        :param dry_run: If True, performs validation without actual provisioning, defaults to False
        :raises SPSDKError: If device is not MCUBoot instance, provisioning fails, or no response
        :raises NotImplementedError: If batch mode is used without dispatch firmware
        :return: Provisioning report as bytes if available, None otherwise
        """
        if not isinstance(self.device, McuBoot):
            raise SPSDKError("Wrong instance of device, must be MCUBoot")
        with self.device as device:
            if client.use_dispatch_fw:
                data_address = client.tp_data_address or self.buffer_address
                self.print_func("Starting provisioning process in batch mode")
                logger.info(f"Data Address: {hex(data_address)}, Dry Run: {dry_run}")
                status, report = device.el2go_batch_tp(
                    data_address=data_address,
                    report_address=client.prov_report_address or 0xFFFF_FFFF,
                    dry_run=dry_run,
                )
                if status is None:
                    raise SPSDKError("Provisioning failed. No response from the firmware.")
                if status != StatusCode.EL2GO_PROV_SUCCESS.tag:
                    raise SPSDKError(
                        f"Provisioning failed with status: {stringify_status_code(status)}"
                    )

                if (
                    client.prov_report_address is not None
                    and client.prov_report_address != 0xFFFF_FFFF
                ):
                    self.print_func(
                        f"Provisioning report stored at address: {hex(client.prov_report_address)}"
                    )
                self.print_func("Secure Objects provisioned successfully")
                if report:
                    logger.info(f"Provisioning report content:\n{hexdump(report, result='return')}")
                    return report
                logger.info("No report available")
                return None
            raise NotImplementedError("Batch mode without dispatch FW is not supported.")


class El2GoInterfaceHandlerUboot(EL2GOInterfaceHandler):
    """EdgeLock 2GO interface handler for U-Boot communication.

    This class provides EdgeLock 2GO provisioning capabilities through U-Boot
    interfaces, supporting both serial and fastboot communication protocols.
    It handles device preparation, secure object provisioning, and UUID reading
    operations specific to U-Boot environments.

    :cvar UUID_FUSE_READ_COMMAND: U-Boot command for reading fuse values.
    :cvar UUID_FUSE_READ_RESPONSE_START: Expected start of fuse read response.
    """

    UUID_FUSE_READ_COMMAND = "fuse read"
    UUID_FUSE_READ_RESPONSE_START = "Word 0x00000000: "

    def __init__(
        self, device: Union[UbootSerial, UbootFastboot], family: Optional[FamilyRevision] = None
    ) -> None:
        """Initialize EL2GO interface with UBoot device.

        Sets up the interface for communicating with EL2GO service through UBoot device.
        The device must be either UbootSerial or UbootFastboot instance.

        :param device: UBoot device instance for communication.
        :param family: Target MCU family and revision information.
        :raises SPSDKError: If device is not a valid UBoot instance.
        """
        super().__init__(device, family)
        if not isinstance(self.device, (UbootFastboot, UbootSerial)):
            raise SPSDKError("Wrong instance of device, must be Uboot")
        self.uboot_started = False

    def get_version(self) -> str:
        """Get EdgeLock 2GO NXP Provisioning Firmware version.

        This method returns the version information for U-Boot interface, which is not available
        and logs an error message.

        :return: Version string, always "N/A" for U-Boot interface.
        """
        logger.error("No version available for U-Boot interface")
        return "N/A"

    def prepare(self, loader: Optional[str]) -> None:
        """Prepare device for provisioning by establishing connection and loading bootloader if needed.

        This method handles device preparation for EL2GO provisioning. For UbootFastboot devices,
        it attempts to establish a fastboot connection. If that fails and a loader is provided,
        it uses SDPS to boot the loader and then establishes the fastboot connection.
        UbootSerial devices are not supported for preparation steps.

        :param loader: Optional path to bootloader file for SDPS boot when fastboot is not available
        :raises SPSDKError: If device is not a Uboot instance, SDPS boot fails, or fastboot
                            connection cannot be established
        """
        if not isinstance(self.device, (UbootFastboot, UbootSerial)):
            raise SPSDKError("Wrong instance of device, must be Uboot")

        if isinstance(self.device, UbootSerial):
            logger.error("Preparation steps are not supported for U-Boot serial")
            return

        # Check if loader is specified
        if loader:
            # First, try to connect with minimum timeout to quickly detect if fastboot is available
            try:
                with self.device.uuu.with_temporary_timeouts(1, 1):  # 1 second minimum timeouts
                    logger.debug("Attempting fastboot connection with minimum timeout")
                    self.device.open()
                    logger.info("Fastboot connection established successfully")
                    self.uboot_started = True

            except Exception as e:
                logger.info(
                    f"Fastboot not available with quick timeout ({e}), attempting SDPS boot"
                )

                # Close any partial connection
                if self.device.is_opened:
                    self.device.close()

                try:
                    # Load bootloader using SDPS
                    logger.info(f"Loading bootloader via SDPS: {loader}")
                    self.device.uuu.run_cmd(f"SDPS[-t 10000]: boot -f {loader}")

                    # Now try to establish fastboot connection with normal timeout
                    logger.debug("Attempting fastboot connection after SDPS boot")
                    self.device.open()
                    logger.info("Fastboot connection established after loading bootloader")
                    self.uboot_started = True

                except Exception as sdps_error:
                    logger.error(f"SDPS boot failed: {sdps_error}")
                    raise SPSDKError(
                        f"Failed to load bootloader via SDPS and establish fastboot connection: {sdps_error}"
                    ) from sdps_error
        else:
            logger.debug("No loader specified, skipping bootloader preparation")

    def get_uuid(self) -> str:
        """Get device UUID from fuses.

        Reads the UUID from device fuses using U-boot commands. The method requires
        a U-boot device interface and a specified device family to determine the
        correct fuse index for UUID reading.

        :raises SPSDKError: If device is not a U-boot instance, family is not
            specified, or UUID cannot be extracted from device response.
        :return: Device UUID as a string.
        """
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

    @verify_fastboot_connection()
    def write_memory(self, address: int, data: bytes) -> None:
        """Write memory data to specified address.

        This method writes the provided data bytes to the specified memory address
        using the underlying U-boot device interface.

        :param address: Memory address where data should be written.
        :param data: Bytes data to be written to memory.
        :raises SPSDKError: When device is not a U-boot instance (UbootFastboot or UbootSerial).
        """
        if not isinstance(self.device, (UbootFastboot, UbootSerial)):
            raise SPSDKError("Wrong instance of device, must be Uboot")
        self.device.write_memory(address, data)

    @verify_fastboot_connection()
    def send_command(self, command: str, no_exit: bool = False) -> str:
        """Send command to the target device.

        This method sends a command to a U-boot device (either Fastboot or Serial) and returns
        the output response. For serial devices with no_exit=True, no output is returned.

        :param command: Command string to send to the target device.
        :param no_exit: If True, don't wait for command completion (serial only).
        :raises SPSDKError: If device is not a U-boot instance (Fastboot or Serial).
        :return: Command output from device, or empty string for serial with no_exit=True.
        """
        if not isinstance(self.device, (UbootFastboot, UbootSerial)):
            raise SPSDKError("Wrong instance of device, must be Uboot")
        self.device.write(command, no_exit)
        if no_exit and isinstance(self.device, UbootSerial):
            return ""
        return self.device.read_output()

    def write_secure_objects(
        self,
        client: EL2GOTPClient,
        secure_objects: bytes,
        workspace: Optional[str] = None,
        clean: bool = False,
    ) -> None:
        """Write secure objects to the target device.

        The method validates the secure objects before writing them using U-Boot interface.
        It parses and validates the objects against the specified MCU family.

        :param client: EL2GO OTP client instance for device communication.
        :param secure_objects: Binary data containing the secure objects to write.
        :param workspace: Optional workspace path for temporary files during operation.
        :param clean: Whether to clean up temporary files after operation.
        """
        self.write_secure_objects_uboot(
            client=client, secure_objects=secure_objects, workspace=workspace, clean=clean
        )

    def write_secure_objects_prod(
        self,
        client: EL2GOTPClient,
        secure_objects: bytes,
        workspace: Optional[str] = None,
        clean: bool = False,
    ) -> None:
        """Write secure objects to the device memory for production environment.

        This method delegates to write_secure_objects_uboot to handle the actual writing
        of secure objects to device memory in production scenarios.

        :param client: EL2GO OTP client instance for communication.
        :param secure_objects: Binary data containing the secure objects to write.
        :param workspace: Optional workspace identifier for the operation.
        :param clean: Whether to clean the workspace before writing, defaults to False.
        """
        self.write_secure_objects_uboot(
            client=client, secure_objects=secure_objects, workspace=workspace, clean=clean
        )

    def write_secure_objects_uboot(
        self,
        client: EL2GOTPClient,
        secure_objects: bytes,
        workspace: Optional[str] = None,
        clean: bool = False,
    ) -> None:
        """Write secure objects to the device memory using U-Boot interface.

        This method handles writing secure objects to device memory through U-Boot commands,
        optionally saving files to workspace and using FAT filesystem operations for OEM applications.

        :param client: EL2GO OTP client instance containing configuration and interface details.
        :param secure_objects: Binary data containing the secure objects to be written.
        :param workspace: Optional directory path where secure objects and user config files will be
            saved locally.
        :param clean: Flag indicating whether to perform cleanup operations (currently unused).
        """
        so_list = SecureObjects.parse(secure_objects)
        so_list.validate(family=client.family)

        if workspace:
            write_file(secure_objects, os.path.join(workspace, "secure_objects.bin"), mode="wb")

        user_config, _, user_data_address = client.create_user_config()
        if workspace and user_config:
            write_file(user_config, os.path.join(workspace, "user_config.bin"), mode="wb")

        if client.use_oem_app:
            logger.info(f"Writing Secure Objects to MMC/SD FAT: {hex(user_data_address)}")
            self.write_memory(address=user_data_address, data=secure_objects)
            output = self.send_command(
                f"fatwrite {client.fatwrite_interface} {client.fatwrite_device_partition}"
                + f" {user_data_address:x} {client.fatwrite_filename} {len(secure_objects):x}"
            )
            logger.info(f"Data written {output}")

    @verify_fastboot_connection()
    def save_config(self, client: EL2GOTPClient) -> None:
        """Save configuration to the target device.

        Writes OEM provisioning configuration data to the target device's memory and saves it
        to MMC/SD FAT filesystem if configuration filename is provided.

        :param client: EL2Go client containing provisioning configuration data and target
            device parameters.
        :type client: EL2GOTPClient
        """
        if client.oem_provisioning_config_filename:
            self.write_memory(
                address=client.tp_data_address, data=client.oem_provisioning_config_bin
            )
            # Write also OEM APP config if provided
            logger.info(
                f"Writing OEM Provisioning Config to MMC/SD FAT: {client.oem_provisioning_config_filename}"
            )

            output = self.send_command(
                f"fatwrite {client.fatwrite_interface} {client.fatwrite_device_partition}"
                + f" {client.tp_data_address:x} {client.oem_provisioning_config_filename} "
                + f"{len(client.oem_provisioning_config_bin):x}"
            )

            logger.info(f"Data written {output}")

    def boot_linux(self, client: EL2GOTPClient) -> None:
        """Boot Linux for provisioning.

        Executes the Linux boot sequence commands on the target device if boot_linux
        is enabled in the client configuration. The last command in the sequence is
        executed with no_exit flag to maintain connection.

        :param client: EL2GO TP Client instance containing boot configuration
        :type client: EL2GOTPClient
        """
        if client.boot_linux:
            logger.info("Booting Linux")

            for command in client.linux_boot_sequence:
                # in case of last command set no_exit to true
                if command == client.linux_boot_sequence[-1]:
                    output = self.send_command(command, no_exit=True)
                else:
                    output = self.send_command(command)
                logger.info(f"  Command: {command} -> {output}")

    def run_provisioning(
        self,
        client: EL2GOTPClient,
        dry_run: bool = False,
    ) -> None:
        """Run provisioning process for EL2GO device.

        This method executes the complete provisioning workflow including saving
        configuration and booting Linux. After completion, the OEM provisioning
        application handles the remaining steps.

        :param client: EL2GO TP Client instance for communication
        :param dry_run: If True, performs dry run without actual provisioning
        """
        # 1. Optionally save config for El2Go provisioning
        self.save_config(client)
        # 2. Boot Linux
        self.boot_linux(client)
        logger.info("SPSDK ends here, OEM provisioning app takes care of the rest")

    def run_batch_provisioning(
        self,
        client: EL2GOTPClient,
        dry_run: bool = False,
    ) -> Optional[bytes]:
        """Run provisioning using Batch mode.

        The method executes batch provisioning which is equivalent to regular provisioning
        for this interface implementation.

        :param client: EL2GO TP Client instance for provisioning operations
        :param dry_run: If True, performs dry run without actual provisioning, defaults to False
        """
        # Batch provisioning is same as regular provisioning for this interface
        self.run_provisioning(client, dry_run)
        return None

    def reset(self, reopen: bool = False) -> None:
        """Reset the target.

        This method attempts to reset the target device. Note that reset functionality
        is not supported by this interface implementation.

        :param reopen: Whether to reopen the connection after reset, defaults to False
        """
        logger.debug("Reset is not supported")

    def prepare_dispatch(self, secure_objects: bytes, client: EL2GOTPClient) -> None:
        """Prepare device to run OEM Provisioning App.

        This method is not supported for U-Boot interface and will only log a debug message.

        :param secure_objects: Secure objects data to be used in provisioning.
        :param client: EL2GO OTP client instance for communication.
        """
        logger.debug("Provisioning not supported for U-Boot interface")
