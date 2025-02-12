#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""EdgeLock Enclave (ELE) Message Handler.

This module provides functionality for handling communication with the EdgeLock Enclave (ELE),
a hardware security module present in certain NXP microcontrollers. It includes classes and
methods for constructing, sending, and receiving ELE messages, as well as managing the
communication interface with different types of devices.

The module supports various communication protocols, including MCUBoot, U-Boot serial console,
and U-Boot fastboot, allowing for flexible integration with different development and production
environments.

Key components:
- EleDevice: An enumeration of supported ELE-capable devices and communication interfaces.
- EleMessageHandler: A base class for handling ELE message construction and communication.

This module is part of the SPSDK (Secure Provisioning SDK) and is designed to facilitate
secure operations and provisioning tasks on NXP microcontrollers featuring the EdgeLock Enclave.
"""

import logging
import re
from abc import abstractmethod
from types import TracebackType
from typing import Optional, Type, Union

from spsdk.apps.utils.interface_helper import load_interface_config
from spsdk.ele.ele_constants import ResponseStatus
from spsdk.ele.ele_message import EleMessage
from spsdk.exceptions import SPSDKError, SPSDKLengthError
from spsdk.mboot.mcuboot import McuBoot
from spsdk.mboot.protocol.base import MbootProtocolBase
from spsdk.uboot.uboot import UbootFastboot, UbootSerial
from spsdk.utils.database import DatabaseManager, get_db, get_families
from spsdk.utils.misc import value_to_bytes
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)


class EleDevice(SpsdkEnum):
    """Enum containing supported ELE devices."""

    MBOOT = (0, "mboot", "ELE over mboot")
    UBOOT_SERIAL = (1, "uboot_serial", "ELE over U-Boot serial console")
    UBOOT_FASTBOOT = (2, "uboot_fastboot", "ELE over fastboot")


class EleMessageHandler:
    """Base class for ELE message handling."""

    def __init__(
        self,
        device: Union[McuBoot, UbootSerial, UbootFastboot],
        family: str,
        revision: str = "latest",
        buffer_address: Optional[int] = None,
        buffer_size: Optional[int] = None,
    ) -> None:
        """Class object initialized.

        :param device: Communication interface.
        :param family: Target family name.
        :param revision: Target revision, default is use 'latest' revision.
        :param buffer_address: Override default buffer address for ELE.
        :param buffer_size: Override default buffer size for ELE.
        """
        self.device = device
        self.database = get_db(device=family, revision=revision)
        self.family = family
        self.revision = revision
        self.comm_buff_addr = buffer_address or self.database.get_int(
            DatabaseManager.COMM_BUFFER, "address"
        )
        self.comm_buff_size = buffer_size or self.database.get_int(
            DatabaseManager.COMM_BUFFER, "size"
        )
        logger.info(
            f"ELE communicator is using {self.comm_buff_size} B size buffer at "
            f"{self.comm_buff_addr:08X} address in {family} target."
        )

    @staticmethod
    def get_supported_families() -> list[str]:
        """Get list of supported target families.

        :return: List of supported families.
        """
        return get_families(DatabaseManager.ELE)

    @staticmethod
    def get_supported_ele_devices() -> list[str]:
        """Get list of supported target families.

        :return: List of supported families.
        """
        return EleDevice.labels()

    @staticmethod
    def get_ele_device(device: str, revision: str = "latest") -> EleDevice:
        """Get default ELE device from DB.

        :param device: Device name.
        :param revision: Device revision, defaults to 'latest'.
        :return: EleDevice instance.
        """
        return EleDevice.from_label(
            get_db(device, revision).get_str(DatabaseManager.ELE, "ele_device")
        )

    @abstractmethod
    def send_message(self, msg: EleMessage) -> None:
        """Send message and receive response.

        :param msg: EdgeLock Enclave message.
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
        """Close function of ELE handler.

        Closes the device if it's opened.

        :param exception_type: Type of the exception if one was raised.
        :param exception_value: Exception instance if one was raised.
        :param traceback: Traceback if an exception was raised.
        """
        if self.device.is_opened:
            self.device.close()

    @classmethod
    def get_message_handler(
        cls,
        family: str,
        revision: str = "latest",
        device: Optional[str] = None,
        fb_addr: Optional[int] = None,
        fb_size: Optional[int] = None,
        buffer_addr: Optional[int] = None,
        buffer_size: Optional[int] = None,
        port: Optional[str] = None,
        usb: Optional[str] = None,
        buspal: Optional[str] = None,
        lpcusbsio: Optional[str] = None,
        timeout: int = 5000,
    ) -> "EleMessageHandler":
        """Get Ele message handler."""
        default_device = device or EleMessageHandler.get_ele_device(family, revision)
        if default_device == EleDevice.UBOOT_FASTBOOT:
            db = get_db(device=family, revision=revision)
            fb_buff_addr = fb_addr or db.get_int(DatabaseManager.FASTBOOT, "address")
            fb_buff_size = fb_size or db.get_int(DatabaseManager.FASTBOOT, "size")

            uboot_device = UbootFastboot(
                timeout=timeout,
                buffer_address=fb_buff_addr,
                buffer_size=fb_buff_size,
                serial_port=port,
            )
            return EleMessageHandlerUBoot(
                device=uboot_device,
                family=family,
                revision=revision,
                comm_buffer_address_override=buffer_addr,
                comm_buffer_size_override=buffer_size,
            )

        if default_device == EleDevice.UBOOT_SERIAL:
            if not port:
                raise SPSDKError("Port must be specified")
            uboot_serial = UbootSerial(port, timeout)
            return EleMessageHandlerUBoot(uboot_serial, family, revision)
        iface_params = load_interface_config(
            {"port": port, "usb": usb, "buspal": buspal, "lpcusbsio": lpcusbsio}
        )
        interface_cls = MbootProtocolBase.get_interface_class(iface_params.IDENTIFIER)
        interface = interface_cls.scan_single(**iface_params.get_scan_args())
        mboot = McuBoot(interface, cmd_exception=True)
        return EleMessageHandlerMBoot(
            device=mboot,
            family=family,
            revision=revision,
            comm_buffer_address_override=buffer_addr,
            comm_buffer_size_override=buffer_size,
        )


class EleMessageHandlerMBoot(EleMessageHandler):
    """EdgeLock Enclave Message Handler over MCUBoot.

    This class can send the ELE message into target over mBoot and decode the response.
    """

    def __init__(
        self,
        device: McuBoot,
        family: str,
        revision: str = "latest",
        comm_buffer_address_override: Optional[int] = None,
        comm_buffer_size_override: Optional[int] = None,
    ) -> None:
        """Class object initialized.

        :param device: mBoot device.
        :param family: Target family name.
        :param revision: Target revision, default is use 'latest' revision.
        :param comm_buffer_address_override: Override default buffer address for ELE.
        :param comm_buffer_size_override: Override default buffer size for ELE.
        """
        if not isinstance(device, McuBoot):
            raise SPSDKError("Wrong instance of device, must be MCUBoot")
        super().__init__(
            device,
            family,
            revision,
            buffer_address=comm_buffer_address_override,
            buffer_size=comm_buffer_size_override,
        )

    def send_message(self, msg: EleMessage) -> None:
        """Send message and receive response.

        This method sends an EdgeLock Enclave message to the target device, executes it, and processes the response.
        It handles the entire communication process, including writing the command to target memory,
        executing the ELE message, reading back the response, and decoding it. If required, it also
        handles command data and response data.

        :param msg: EdgeLock Enclave message to be sent
        :raises SPSDKError: If the device is not an instance of McuBoot, or if ELE communication fails,
            or if the ELE message fails
        :raises SPSDKLengthError: If invalid read back length is detected for response or response data
        """
        if not isinstance(self.device, McuBoot):
            raise SPSDKError("Wrong instance of device, must be MCUBoot")
        msg.set_buffer_params(self.comm_buff_addr, self.comm_buff_size)
        try:
            # 1. Prepare command in target memory
            self.device.write_memory(msg.command_address, msg.export())

            # 1.1. Prepare command data in target memory if required
            if msg.has_command_data:
                self.device.write_memory(msg.command_data_address, msg.command_data)

            # 2. Execute ELE message on target
            self.device.ele_message(
                msg.command_address,
                msg.command_words_count,
                msg.response_address,
                msg.response_words_count,
            )
            if msg.response_words_count == 0:
                return
            # 3. Read back the response
            response = self.device.read_memory(msg.response_address, 4 * msg.response_words_count)
        except SPSDKError as exc:
            raise SPSDKError(f"ELE Communication failed with mBoot: {str(exc)}") from exc

        if not response or len(response) < 4 * msg.RESPONSE_HEADER_WORDS_COUNT:
            raise SPSDKLengthError("ELE Message - Invalid response read-back operation.")
        # 4. Decode the response
        msg.decode_response(response)

        # 4.1 Check the response status
        if msg.status != ResponseStatus.ELE_SUCCESS_IND:
            raise SPSDKError(f"ELE Message failed. \n{msg.info()}")

        # 4.2 Read back the response data from target memory if required
        if msg.has_response_data:
            try:
                response_data = self.device.read_memory(
                    msg.response_data_address, msg.response_data_size
                )
            except SPSDKError as exc:
                raise SPSDKError(f"ELE Communication failed with mBoot: {str(exc)}") from exc

            if not response_data or len(response_data) != msg.response_data_size:
                raise SPSDKLengthError("ELE Message - Invalid response data read-back operation.")

            msg.decode_response_data(response_data)

        logger.info(f"Sent message information:\n{msg.info()}")


class EleMessageHandlerUBoot(EleMessageHandler):
    """EdgeLock Enclave Message Handler over uBoot.

    This class implements functionality to send ELE messages to the target device over UBoot
    and decode the responses. It provides an interface for communication with the EdgeLock
    Enclave using the UBoot protocol.
    """

    def __init__(
        self,
        device: Union[UbootSerial, UbootFastboot],
        family: str,
        revision: str = "latest",
        comm_buffer_address_override: Optional[int] = None,
        comm_buffer_size_override: Optional[int] = None,
    ) -> None:
        """This method initializes the EleMessageHandlerUBoot class.

        :param device: UBoot device.
        :param family: Target family name.
        :param revision: Target revision, default is use 'latest' revision.
        :param comm_buffer_address_override: Override default buffer address for ELE.
        :param comm_buffer_size_override: Override default buffer size for ELE.

        :raises SPSDKError: If the device is not an instance of UbootSerial or UbootFastboot.
        """
        if not isinstance(device, UbootSerial) and not isinstance(device, UbootFastboot):
            raise SPSDKError("Wrong instance of device, must be UBoot")
        super().__init__(
            device,
            family,
            revision,
            buffer_address=comm_buffer_address_override,
            buffer_size=comm_buffer_size_override,
        )

    def extract_error_values(self, error_message: str) -> tuple[int, int, int]:
        """Extract error values from error_message.

        This method parses the error message to extract abort_code, status, and indication values.
        It uses regular expressions to find and extract the relevant information.

        :param error_message: Error message containing ret and response
        :return: A tuple containing (abort_code, status, indication)
        :raises: No exceptions are raised, but errors are logged if parsing fails
        """
        # Define regular expressions to extract values
        ret_pattern = re.compile(r"ret (0x[0-9a-fA-F]+),")
        response_pattern = re.compile(r"response (0x[0-9a-fA-F]+)")

        # Find matches in the error message
        ret_match = ret_pattern.search(error_message)
        response_match = response_pattern.search(error_message)

        if not ret_match or not response_match:
            logger.error(f"Cannot decode error message from ELE!\n{error_message}")
            abort_code = 0
            status = 0
            indication = 0
        else:
            ret_code = int(ret_match.group(1), 16)
            logger.debug(f"Return code of uBoot ELE MSG command {ret_code}")
            status_all = int(response_match.group(1), 16)
            abort_code = (status_all >> 16) & 0xFFFF
            indication = (status_all >> 8) & 0xFF
            status = status_all & 0xFF
        return abort_code, status, indication

    def send_message(self, msg: EleMessage) -> None:
        """Send message to EdgeLock Enclave and receive response.

        This method performs the following steps:
        1. Prepares command data in target memory if required.
        2. Executes the ELE message on the target.
        3. Reads back the response.
        4. Decodes the response.
        5. Checks the response status.
        6. Reads back the response data from target memory if required.

        :param msg: EdgeLock Enclave message to be sent
        :raises SPSDKError: If an invalid response status is detected or if communication fails
        :raises SPSDKLengthError: If an invalid read back length is detected
        """
        if not isinstance(self.device, UbootSerial) and not isinstance(self.device, UbootFastboot):
            raise SPSDKError("Wrong instance of device, must be UBoot")
        msg.set_buffer_params(self.comm_buff_addr, self.comm_buff_size)
        response = b""
        try:
            logger.debug(f"ELE msg {hex(msg.buff_addr)} {hex(msg.buff_size)} {msg.export().hex()}")

            # 0. Prepare command data in target memory if required
            if msg.has_command_data:
                self.device.write_memory(msg.command_data_address, msg.command_data)

            # 1. Execute ELE message on target
            self.device.write(
                f"ele_message {hex(msg.buff_addr)} {hex(msg.buff_size)} {msg.export().hex()}",
                no_exit=(msg.response_words_count == 0),
            )

            if msg.response_words_count == 0:
                return

            output = self.device.read_output()
            logger.debug(f"Raw ELE message output:\n{output}")

            if "Error" in output:
                msg.abort_code, msg.status, msg.indication = self.extract_error_values(output)
            else:
                # 2. Read back the response
                output = re.sub(r"(u-boot)?=> ", "", output.splitlines()[-1])
                output = output[: msg.response_words_count * 8]
                logger.debug(f"Stripped output {output}")
                response = value_to_bytes("0x" + output)
        except (SPSDKError, IndexError) as exc:
            raise SPSDKError(f"ELE Communication failed with UBoot: {str(exc)}") from exc

        if "Error" not in output:
            if not response or len(response) < 4 * msg.RESPONSE_HEADER_WORDS_COUNT:
                raise SPSDKLengthError("ELE Message - Invalid response read-back operation.")
            # 3. Decode the response
            msg.decode_response(response)

        # 3.1 Check the response status
        if msg.status != ResponseStatus.ELE_SUCCESS_IND:
            raise SPSDKError(f"ELE Message failed. \n{msg.info()}")

        # 3.2 Read back the response data from target memory if required
        if msg.has_response_data:
            try:
                response_data = self.device.read_memory(
                    msg.response_data_address, msg.response_data_size
                )
            except SPSDKError as exc:
                raise SPSDKError(f"ELE Communication failed with mBoot: {str(exc)}") from exc

            if not response_data or len(response_data) != msg.response_data_size:
                raise SPSDKLengthError("ELE Message - Invalid response data read-back operation.")

            msg.decode_response_data(response_data)

        logger.info(f"Sent message information:\n{msg.info()}")
