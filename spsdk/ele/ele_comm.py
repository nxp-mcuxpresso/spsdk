#!/usr/bin/env python
#
# Copyright 2023-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""EdgeLock Enclave (ELE) communication interface.

This module provides functionality for handling communication with the EdgeLock Enclave (ELE),
a hardware security module present in certain NXP microcontrollers. It includes classes and
methods for constructing, sending, and receiving ELE messages through various communication
protocols including MCUBoot, U-Boot serial console, and U-Boot fastboot.
The module supports flexible integration with different development and production environments
by providing abstract message handling capabilities and device-specific implementations for
ELE-capable NXP microcontrollers.
"""

import logging
import re
from abc import abstractmethod
from types import TracebackType

from spsdk.apps.utils.interface_helper import load_interface_config
from spsdk.ele.ele_constants import ResponseStatus
from spsdk.ele.ele_message import EleMessage
from spsdk.exceptions import SPSDKError, SPSDKLengthError
from spsdk.mboot.mcuboot import McuBoot
from spsdk.mboot.protocol.base import MbootProtocolBase
from spsdk.uboot.uboot import UbootFastboot, UbootSerial
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision, get_db, get_families
from spsdk.utils.misc import value_to_bytes
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)


class _ChipResetDetected(Exception):
    """Internal sentinel raised when a chip reset is detected for COULD_RESET_CHIP commands."""


class EleDevice(SpsdkEnum):
    """ELE device communication interface enumeration.

    This enumeration defines the supported communication interfaces for EdgeLock Enclave (ELE)
    devices, including different boot modes and communication protocols.
    """

    MBOOT = (0, "mboot", "ELE over mboot")
    UBOOT_SERIAL = (1, "uboot_serial", "ELE over U-Boot serial console")
    UBOOT_FASTBOOT = (2, "uboot_fastboot", "ELE over fastboot")


class EleMessageHandler:
    """ELE Message Handler for NXP MCU communication.

    This class provides a unified interface for handling EdgeLock Enclave (ELE)
    message communication across supported NXP MCU families. It manages the
    communication buffer configuration, device interaction, and message processing
    for secure provisioning operations.
    The handler supports multiple communication interfaces including McuBoot,
    U-Boot Serial, and U-Boot Fastboot protocols, providing a consistent API
    for ELE operations regardless of the underlying transport mechanism.
    """

    def __init__(
        self,
        device: McuBoot | UbootSerial | UbootFastboot,
        family: FamilyRevision,
        buffer_address: int | None = None,
        buffer_size: int | None = None,
    ) -> None:
        """Initialize ELE communication interface.

        Sets up communication with EdgeLock Enclave (ELE) using the specified device
        and configures buffer parameters for data exchange.

        :param device: Communication interface for device interaction.
        :param family: Target MCU family and revision information.
        :param buffer_address: Override default buffer address for ELE communication.
        :param buffer_size: Override default buffer size for ELE communication.
        """
        self.device = device
        self.database = get_db(family=family)
        self.family = family

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
    def get_supported_families() -> list[FamilyRevision]:
        """Get list of supported target families for ELE.

        The method retrieves all families supported by the ELE (EdgeLock Enclave) database
        manager from the SPSDK database.

        :return: List of supported families with their revisions.
        """
        return get_families(DatabaseManager.ELE)

    @staticmethod
    def get_supported_ele_devices() -> list[str]:
        """Get list of supported ELE device families.

        :return: List of supported ELE device family names.
        """
        return EleDevice.labels()

    @staticmethod
    def get_ele_device(family: FamilyRevision) -> EleDevice:
        """Get default ELE device from database.

        Retrieves the default EdgeLock Enclave (ELE) device configuration for the specified
        device family from the database.

        :param family: Device family and revision information.
        :return: EleDevice instance with default configuration for the specified family.
        """
        return EleDevice.from_label(get_db(family).get_str(DatabaseManager.ELE, "ele_device"))

    @abstractmethod
    def send_message(self, msg: EleMessage) -> None:
        """Send message and receive response.

        :param msg: EdgeLock Enclave message to be sent.
        :raises SPSDKError: If message sending or response receiving fails.
        """

    def __enter__(self) -> None:
        """Enter the ELE handler context manager.

        Opens the device if it's not already opened.
        """
        if not self.device.is_opened:
            self.device.open()

    def __exit__(
        self,
        exception_type: type[BaseException] | None = None,
        exception_value: BaseException | None = None,
        traceback: TracebackType | None = None,
    ) -> None:
        """Close function of ELE handler.

        Closes the device if it's opened. This method is called automatically when
        exiting the context manager.

        :param exception_type: Type of the exception if one was raised.
        :param exception_value: Exception instance if one was raised.
        :param traceback: Traceback if an exception was raised.
        """
        if self.device.is_opened:
            self.device.close()

    @classmethod
    def get_message_handler(
        cls,
        family: FamilyRevision,
        device: str | None = None,
        fb_addr: int | None = None,
        fb_size: int | None = None,
        buffer_addr: int | None = None,
        buffer_size: int | None = None,
        port: str | None = None,
        usb: str | None = None,
        buspal: str | None = None,
        lpcusbsio: str | None = None,
        timeout: int = 5000,
        uboot_prompt: str | None = None,
    ) -> "EleMessageHandler":
        """Get ELE message handler for specified device and family.

        Creates and configures an appropriate ELE message handler based on the device type
        and family. Supports U-Boot (FastBoot and Serial) and MBoot interfaces with
        configurable communication parameters.

        :param family: Target MCU family and revision information.
        :param device: Device type to use, defaults to family-specific device if None.
        :param fb_addr: FastBoot buffer address, uses database default if None.
        :param fb_size: FastBoot buffer size, uses database default if None.
        :param buffer_addr: Communication buffer address override.
        :param buffer_size: Communication buffer size override.
        :param port: Serial port identifier for serial communication.
        :param usb: USB device identifier for USB communication.
        :param buspal: BusPal interface configuration.
        :param lpcusbsio: LPCUSBSIO interface configuration.
        :param timeout: Communication timeout in milliseconds.
        :param uboot_prompt: Custom U-Boot prompt for serial communication.
        :raises SPSDKError: When port is not specified for U-Boot serial device.
        :return: Configured ELE message handler instance.
        """
        if isinstance(uboot_prompt, str):
            UbootSerial.set_prompt(uboot_prompt)
        default_device = device or EleMessageHandler.get_ele_device(family)
        if default_device == EleDevice.UBOOT_FASTBOOT:
            db = get_db(family)
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
                comm_buffer_address_override=buffer_addr,
                comm_buffer_size_override=buffer_size,
            )

        if default_device == EleDevice.UBOOT_SERIAL:
            if not port:
                raise SPSDKError("Port must be specified")
            uboot_serial = UbootSerial(port, timeout)
            return EleMessageHandlerUBoot(uboot_serial, family)
        iface_params = load_interface_config(
            {"port": port, "usb": usb, "buspal": buspal, "lpcusbsio": lpcusbsio}
        )
        interface_cls = MbootProtocolBase.get_interface_class(iface_params.IDENTIFIER)
        interface = interface_cls.scan_single(**iface_params.get_scan_args())
        mboot = McuBoot(interface, cmd_exception=True, family=family)
        return EleMessageHandlerMBoot(
            device=mboot,
            family=family,
            comm_buffer_address_override=buffer_addr,
            comm_buffer_size_override=buffer_size,
        )


class EleMessageHandlerMBoot(EleMessageHandler):
    """EdgeLock Enclave Message Handler over MCUBoot.

    This class provides communication interface for sending EdgeLock Enclave messages to target
    devices through MCUBoot protocol. It handles the complete message lifecycle including
    command preparation, execution, response processing, and data transfer operations.
    """

    def __init__(
        self,
        device: McuBoot,
        family: FamilyRevision,
        comm_buffer_address_override: int | None = None,
        comm_buffer_size_override: int | None = None,
    ) -> None:
        """Initialize ELE communication interface.

        :param device: McuBoot device instance for communication.
        :param family: Target family revision specification.
        :param comm_buffer_address_override: Override default communication buffer address for ELE.
        :param comm_buffer_size_override: Override default communication buffer size for ELE.
        :raises SPSDKError: Invalid device instance provided, must be McuBoot.
        """
        if not isinstance(device, McuBoot):
            raise SPSDKError("Wrong instance of device, must be MCUBoot")
        super().__init__(
            device,
            family,
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

        if not response or len(response) < 4 * msg.response_header_words_count:
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
    """EdgeLock Enclave Message Handler for U-Boot communication.

    This class implements functionality to send ELE messages to target devices over U-Boot
    and decode the responses. It provides an interface for communication with the EdgeLock
    Enclave using the U-Boot protocol, supporting both serial and fastboot communication
    methods.
    """

    def __init__(
        self,
        device: UbootSerial | UbootFastboot,
        family: FamilyRevision,
        comm_buffer_address_override: int | None = None,
        comm_buffer_size_override: int | None = None,
    ) -> None:
        """Initialize ELE message handler for U-Boot communication.

        Creates an ELE message handler instance that communicates with EdgeLock Enclave
        through U-Boot interface using either serial or fastboot protocol.

        :param device: U-Boot communication device instance.
        :param family: Target chip family and revision information.
        :param comm_buffer_address_override: Custom communication buffer address for ELE.
        :param comm_buffer_size_override: Custom communication buffer size for ELE.
        :raises SPSDKError: If device is not UbootSerial or UbootFastboot instance.
        """
        if not isinstance(device, UbootSerial) and not isinstance(device, UbootFastboot):
            raise SPSDKError("Wrong instance of device, must be UBoot")
        super().__init__(
            device,
            family,
            buffer_address=comm_buffer_address_override,
            buffer_size=comm_buffer_size_override,
        )

    def extract_error_values(self, error_message: str) -> tuple[int, int, int]:
        """Extract error values from error message.

        This method parses the error message to extract abort_code, status, and indication values
        using regular expressions to find hexadecimal values in the message format.

        :param error_message: Error message containing ret and response hexadecimal values.
        :return: A tuple containing (abort_code, status, indication) as integers.
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

    def _execute_ele_command(self, msg: EleMessage) -> tuple[str, bool]:
        """Execute ELE command over U-Boot and return raw output and error flag.

        :param msg: ELE message to execute.
        :return: Tuple of (output string, ele_error flag).
        :raises SPSDKError: If communication fails and the command cannot tolerate a chip reset.
        """
        assert isinstance(self.device, (UbootSerial, UbootFastboot))
        ele_error = False
        output = ""
        try:
            if msg.has_command_data:
                self.device.write_memory(msg.command_data_address, msg.command_data)

            self.device.write(
                f"ele_message {hex(msg.buff_addr)} {hex(msg.buff_size)} {msg.export().hex()}",
                no_exit=False,
            )
            output = self.device.read_output()
            logger.debug(f"Raw ELE message output:\n{output}")

            if "Error" in output:
                msg.abort_code, msg.status, msg.indication = self.extract_error_values(output)
                ele_error = True
        except (SPSDKError, IndexError) as exc:
            exc_str = str(exc)
            if "Error" in exc_str and not ele_error:
                try:
                    msg.abort_code, msg.status, msg.indication = self.extract_error_values(exc_str)
                    ele_error = True
                except Exception:  # noqa: BLE001
                    pass
            if msg.COULD_RESET_CHIP and not ele_error:
                logger.info(
                    f"Chip reset detected during ELE command - expected behavior"
                    f" for {type(msg).__name__}."
                )
                raise _ChipResetDetected() from exc
            raise SPSDKError(f"ELE Communication failed with UBoot: {str(exc)}") from exc

        return output, ele_error

    def _parse_response_from_output(self, msg: EleMessage, output: str) -> bytes:
        """Parse response hex words from U-Boot command output.

        :param msg: ELE message with expected response word count.
        :param output: Raw U-Boot output string.
        :return: Response bytes.
        :raises SPSDKError: If no valid response line found.
        """
        lines = output.splitlines()
        response_lines = [line for line in lines if line.startswith("06") or line.startswith("07")]
        if not response_lines:
            raise SPSDKError("No valid response line found in output")
        stripped_line = re.sub(r"(u-boot)?=> ", "", response_lines[0])
        hex_str = stripped_line[: msg.response_words_count * 8]
        hex_str = re.sub(r"Detect.*", "", hex_str)
        logger.debug(f"Stripped output: {hex_str}")
        return value_to_bytes("0x" + hex_str)

    def _read_response_data(self, msg: EleMessage) -> None:
        """Read and decode optional response data from target memory.

        :param msg: ELE message with response data address and size.
        :raises SPSDKError: If reading response data fails.
        :raises SPSDKLengthError: If response data length is invalid.
        """
        if not msg.has_response_data:
            return
        try:
            response_data = self.device.read_memory(
                msg.response_data_address, msg.response_data_size
            )
        except SPSDKError as exc:
            raise SPSDKError(f"ELE Communication failed with mBoot: {str(exc)}") from exc

        if not response_data or len(response_data) != msg.response_data_size:
            raise SPSDKLengthError("ELE Message - Invalid response data read-back operation.")
        msg.decode_response_data(response_data)

    def send_message(self, msg: EleMessage) -> None:
        """Send message to EdgeLock Enclave and receive response.

        This method performs the following steps:
        1. Prepares command data in target memory if required.
        2. Executes the ELE message on the target.
        3. Reads back the response.
        4. Decodes the response.
        5. Checks the response status.
        6. Reads back the response data from target memory if required.

        :param msg: EdgeLock Enclave message to be sent.
        :raises SPSDKError: If an invalid response status is detected or if communication fails.
        :raises SPSDKLengthError: If an invalid read back length is detected.
        """
        if not isinstance(self.device, UbootSerial) and not isinstance(self.device, UbootFastboot):
            raise SPSDKError("Wrong instance of device, must be UBoot")
        msg.set_buffer_params(self.comm_buff_addr, self.comm_buff_size)

        logger.debug(f"ELE msg {hex(msg.buff_addr)} {hex(msg.buff_size)} {msg.export().hex()}")

        try:
            output, ele_error = self._execute_ele_command(msg)
        except _ChipResetDetected:
            return

        if ele_error:
            raise SPSDKError(f"ELE Message failed. \n{msg.info()}")

        if msg.response_words_count == 0:
            return

        response = self._parse_response_from_output(msg, output)
        if not response or len(response) < 4 * msg.response_header_words_count:
            raise SPSDKLengthError("ELE Message - Invalid response read-back operation.")

        msg.decode_response(response)

        if msg.status != ResponseStatus.ELE_SUCCESS_IND:
            raise SPSDKError(f"ELE Message failed. \n{msg.info()}")

        self._read_response_data(msg)
        logger.info(f"Sent message information:\n{msg.info()}")
