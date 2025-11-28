#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK U-Boot UUU library wrapper.

This module provides a Python interface to the libuuu library for U-Boot
USB recovery operations. It enables communication with NXP devices in
Serial Download Protocol (SDP) mode for flashing and recovery purposes.
"""

import logging
import re
from ctypes import CFUNCTYPE, POINTER, c_char_p, c_int, c_uint16, c_void_p
from functools import wraps
from types import TracebackType
from typing import Any, Callable, Optional, no_type_check

import click
from libuuu import LibUUU, UUUNotifyCallback, UUUState
from libuuu.libuuu import UUUNotifyStruct, UUUNotifyType, _default_notify_callback

from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.utils.database import DatabaseManager, UsbId
from spsdk.utils.family import FamilyRevision, get_db, get_families
from spsdk.utils.misc import load_text
from spsdk.utils.threading import CancellableWait

logger = logging.getLogger(__name__)

UUULsUsbDevices = CFUNCTYPE(
    c_int,  # Return type
    c_char_p,  # const char *path
    c_char_p,  # const char *chip
    c_char_p,  # const char *pro
    c_uint16,  # uint16_t vid
    c_uint16,  # uint16_t pid
    c_uint16,  # uint16_t bcd
    c_char_p,  # const char *serial_no
    c_void_p,  # void *p
)


@UUUNotifyCallback
def _spsdk_notify_callback(struct: UUUNotifyStruct, data) -> int:  # type: ignore
    """Default callback function that stores UUU response in class variable.

    This callback processes UUU notifications and updates the internal state. For command info
    notifications, it accumulates the response data in the LibUUU response buffer.

    :param struct: UUU notification structure containing response data and type information
    :param data: Pointer to additional data (unused in this implementation)
    :return: 1 if no error occurred, 0 if there was an error in the state
    """
    # pylint: disable=unused-argument
    SPSDKUUU._state.update(struct)
    if struct.type == UUUNotifyType.NOTIFY_CMD_INFO:
        LibUUU._response.value += bytes(struct.response.str)
    return 1 if SPSDKUUU._state.error else 0


class SPSDKUUUState(UUUState):
    """SPSDK UUU State Manager.

    This class extends UUUState to provide enhanced state management for UUU operations
    with integrated progress tracking and visual feedback capabilities for SPSDK workflows.

    :cvar progress_bars: Dictionary storing active progress bar instances for concurrent tasks.
    """

    progress_bars: dict[str, Any] = {}

    def __init__(self, progress_bar: bool = True) -> None:
        """Initialize SPSDK UUU state manager.

        Creates a new instance of the SPSDK UUU state manager with configurable progress bar display
        and initializes the status tracking.

        :param progress_bar: Enable progress bar display during operations, defaults to True
        """
        self.progress_bar = progress_bar
        self.status = 0
        super().__init__()

    def update_progress_bar(self, task_name: str, total_steps: int, step: int) -> None:
        """Update the progress bar for a task.

        Creates a new progress bar if it doesn't exist for the given task, updates the current
        progress, and cleans up when the task is completed.

        :param task_name: The name of the task to display in progress bar.
        :param total_steps: The total number of steps for the task.
        :param step: The current step number of the task.
        """
        # Check if the progress bar for the task already exists
        if task_name not in self.progress_bars:
            # Create a new progress bar and store it in the dictionary
            self.progress_bars[task_name] = click.progressbar(
                length=total_steps, label=task_name, bar_template="%(info)s [%(bar)s] %(label)s"
            )

        # Update the existing progress bar
        bar = self.progress_bars[task_name]
        bar.update(step - bar.pos)

        # If the current step is the last step print new line
        if step == total_steps:
            del self.progress_bars[task_name]
            click.echo("\r")
            # Enable cursor again
            click.echo("\033[?25h", nl=False)

    def update(self, struct: UUUNotifyStruct) -> None:
        """Update the state with a notification from uuu.

        This method processes different types of notifications from the uuu tool and updates
        the internal state accordingly, including command progress, device attachment status,
        transfer progress, and error conditions.

        :param struct: A UUUNotifyStruct object containing notification data and type.
        :raises SPSDKError: If the command fails.
        """
        self.waiting = struct.type == UUUNotifyType.NOTIFY_WAIT_FOR
        self.done = struct.type == UUUNotifyType.NOTIFY_DONE

        if struct.type == UUUNotifyType.NOTIFY_CMD_TOTAL:
            self.cmd_total = struct.response.total
        elif struct.type == UUUNotifyType.NOTIFY_CMD_START:
            self.cmd = struct.response.str.decode("utf-8")
            self.cmd_pos = 0
            self.cmd_start = struct.timestamp
        elif struct.type == UUUNotifyType.NOTIFY_CMD_END:
            self.status = struct.response.status
            self.done = True
            self.error = self.status != 0
            self.cmd_end = struct.timestamp
        elif struct.type == UUUNotifyType.NOTIFY_DEV_ATTACH:
            self.dev = struct.response.str
            self.done = False
            self.error = False
        elif struct.type == UUUNotifyType.NOTIFY_TRANS_SIZE:
            self.trans_size = struct.response.total
        elif struct.type == UUUNotifyType.NOTIFY_TRANS_POS:
            self.trans_pos = struct.response.total
            if self.progress_bar:
                self.update_progress_bar(self.cmd, self.trans_size, self.trans_pos)
            self.logger.debug(f"Transfer {self.trans_pos}/{self.trans_size}")

        self.logger.debug(f"{self.cmd=},{self.dev=},{self.waiting=},{self.error=}")


@no_type_check
# pylint: disable=no-self-argument,missing-type-doc
def check_uuu_error_state_after_command(f: Any):
    """Decorator to check UUU error state after command execution.

    This decorator wraps functions that call libuuu and automatically checks for error
    conditions after the function execution. If an error is detected (non-zero return
    code or error state), it raises an SPSDKError with detailed error information.

    :param f: Function to be wrapped that calls libuuu operations.
    :raises SPSDKError: When UUU command fails or error state is detected.
    :return: Decorated function that performs error checking.
    """

    @wraps(f)
    def inner(self: "SPSDKUUU", *args: Any, **kwargs: Any) -> int:
        """Inner wrapper function for UUU command execution with error handling.

        This method wraps the execution of UUU commands and provides comprehensive error
        handling. It checks the return code and internal state, then raises an SPSDKError
        with detailed error information if the command fails.

        :param self: SPSDKUUU instance.
        :param args: Variable length argument list passed to the wrapped function.
        :param kwargs: Arbitrary keyword arguments passed to the wrapped function.
        :raises SPSDKError: When UUU command execution fails or returns non-zero exit code.
        :return: Exit code from the executed UUU command.
        """
        ret = f(self, *args, **kwargs)
        if ret != 0 or self._state.error:
            message = (
                f"{f.__name__}: "
                + (
                    "Failed while executing UUU command " + self._state.cmd
                    if self._state.cmd
                    else ""
                )
                + f"(exit code: {ret}, status: {self._state.status})"
                + (f"\nError details: {self.last_error_str}" if self.last_error_str else "")
            )
            raise SPSDKError(message)
        return ret

    return inner


class SPSDKUUU:
    """SPSDK U-Boot UUU Interface.

    This class provides a Python wrapper around the libuuu library for U-Boot
    device programming and management. It offers a user-friendly interface for
    executing UUU scripts, managing USB device connections, and handling device
    communication with enhanced error handling and progress reporting.

    :cvar SCRIPT_ARG_REGEX: Regular expression pattern for parsing UUU script arguments.
    """

    SCRIPT_ARG_REGEX = r"# @(\S+)\s*(\[(\S+)\])?\s*\|\s*(.+)"
    _state = SPSDKUUUState()

    def __init__(
        self,
        wait_timeout: int = 5,
        wait_next_timeout: int = 5,
        poll_period: int = 200,
        progress_bar: bool = True,
        usb_path_filter: Optional[str] = None,
        usb_serial_no_filter: Optional[str] = None,
    ) -> None:
        """Initialize the SPSDKUUU object.

        Sets up the UUU library wrapper with specified timeouts, polling configuration,
        and USB device filters for secure provisioning operations.

        :param wait_timeout: Timeout for command execution in seconds, defaults to 5
        :param wait_next_timeout: Timeout for waiting for next device in seconds, defaults to 5
        :param poll_period: USB device polling period in milliseconds, defaults to 200
        :param progress_bar: Enable progress bar display to stdout, defaults to True
        :param usb_path_filter: USB path filter string for device selection
        :param usb_serial_no_filter: USB serial number filter for device selection
        :raises SPSDKValueError: Invalid USB path or serial number filter configuration
        """
        self.uuu = LibUUU()
        self.wait_timeout = wait_timeout
        self.wait_next_timeout = wait_next_timeout
        self.uuu.set_wait_timeout(wait_timeout)
        self.uuu.set_wait_next_timeout(wait_next_timeout)
        self.uuu.set_poll_period(poll_period)
        self.uuu.unregister_notify_callback(_default_notify_callback)
        self.uuu.register_notify_callback(_spsdk_notify_callback, POINTER(c_void_p)())
        rc = 0
        logger.debug(f"Adding USB path filter: {usb_path_filter}")
        rc = self.add_usbpath_filter(usb_path_filter) if usb_path_filter else 0
        if rc != 0:
            raise SPSDKValueError(f"Error adding USB path filter: {rc}")
        logger.debug(f"Adding USB serial number filter: {usb_serial_no_filter}")
        rc = self.add_usbserial_no_filter(usb_serial_no_filter) if usb_serial_no_filter else 0
        if rc != 0:
            raise SPSDKValueError(f"Error adding USB serial number filter: {rc}")
        self._state.progress_bar = progress_bar

    @property
    def response(self) -> str:
        """Get the response from the last command.

        :return: Decoded response string from the most recent UUU command execution.
        """
        return self.uuu.response.decode()

    @property
    def last_error_str(self) -> str:
        """Get the last error string from UUU library.

        :return: The last error message as a string.
        """
        return self.uuu.get_last_error_string()

    @property
    def last_error(self) -> int:
        """Get the last error code.

        Retrieves the most recent error code from the UUU library operation.

        :return: The last error code as an integer value.
        """
        return self.uuu.get_last_error()

    @staticmethod
    def get_supported_families() -> list[FamilyRevision]:
        """Get the list of supported families for U-Boot operations.

        This method retrieves all NXP MCU families that are supported by the SPSDK U-Boot
        functionality through the database manager.

        :return: List of FamilyRevision objects representing supported MCU families.
        """
        return get_families(DatabaseManager.NXPUUU)

    @staticmethod
    def get_supported_devices() -> list[str]:
        """Get supported devices for U-Boot UUU operations.

        Retrieves a list of all supported boot devices from the NXP UUU database
        for the first available family in the database manager.

        :return: List of supported device names for UUU operations.
        """
        return list(
            get_db(get_families(DatabaseManager.NXPUUU)[0])
            .get_dict(DatabaseManager.NXPUUU, "boot_devices")
            .keys()
        )

    @classmethod
    def get_usb_ids(cls) -> dict[str, list[UsbId]]:
        """Get list of all supported devices from the database.

        The method retrieves device information from the database and filters devices that have
        SDPS USB configurations available for UUU operations.

        :return: Dictionary mapping device names to their corresponding USB ID configurations.
        """
        devices = {}
        for device, quick_info in DatabaseManager().quick_info.devices.devices.items():
            usb_ids = quick_info.info.isp.get_usb_ids("sdps")
            if usb_ids:
                devices[device] = usb_ids
        return devices

    @staticmethod
    def replace_arguments(
        input_string: str, arguments_dict: dict[str, dict[str, Any]], arguments: list[str]
    ) -> str:
        """Replace arguments in input string with provided values.

        The method normalizes file paths, maps argument keys to replacement values,
        and handles special cases for compressed files (.ZST, .BZ2) by appending
        wildcard patterns. Uses regex for whole-word replacement to avoid partial matches.

        :param input_string: The input string containing argument placeholders to replace.
        :param arguments_dict: Dictionary with argument keys and their metadata including
                              optional_key field for fallback values.
        :param arguments: List of replacement values corresponding to arguments_dict keys.
        :return: Input string with argument placeholders replaced by actual values.
        """
        # Normalize arguments by replacing backslashes with forward slashes
        normalized_arguments = [arg.replace("\\", "/") for arg in arguments]

        # Create a mapping of argument keys to their replacements
        argument_mapping = {
            key: normalized_arguments[i]
            for i, key in enumerate(arguments_dict.keys())
            if i < len(normalized_arguments)
        }

        # Create a list of tuples (key, replacement) to avoid modifying the input_string while iterating
        replacements = []

        for key, val in arguments_dict.items():
            if key in input_string:
                if key in argument_mapping:
                    replacement = argument_mapping[key]
                    # Check for .ZST or .BZ2 extension and modify the replacement string
                    if replacement.upper().endswith(".ZST") or replacement.upper().endswith(".BZ2"):
                        if replacement.endswith('"'):
                            replacement = replacement[:-1] + '/*"'
                        else:
                            replacement += "/*"
                    replacements.append((key, replacement))
                elif val["optional_key"] and val["optional_key"] in argument_mapping:
                    replacements.append((key, argument_mapping[val["optional_key"]]))
                else:
                    replacements.append((key, val["optional_key"] if val["optional_key"] else ""))

        # Perform replacements in the input_string using regular expressions to match whole words
        for key, replacement in replacements:
            input_string = re.sub(r"\b" + re.escape(key) + r"\b", replacement, input_string)

        return input_string

    def get_uuu_script(
        self, boot_device: str, family: FamilyRevision, args: Optional[list[str]]
    ) -> str:
        """Get the uuu script for the given boot device.

        Loads and processes a UUU script template by replacing argument placeholders
        with provided values based on the boot device configuration.

        :param boot_device: Name of the boot device to get script for.
        :param family: Target MCU family and revision information.
        :param args: List of arguments to substitute in the script template.
        :raises SPSDKValueError: When no arguments provided, too many arguments passed,
            or invalid arguments that don't match expected format.
        :return: Processed UUU script with arguments substituted.
        """
        script_path = get_db(family).get_file_path(
            DatabaseManager.NXPUUU, ["boot_devices", boot_device, "script"]
        )

        argument_names = get_db(family).get_list(
            DatabaseManager.NXPUUU, ["boot_devices", boot_device, "arguments"]
        )

        if not args:
            raise SPSDKValueError("At least one argument must be passed")

        if len(args) > len(argument_names):
            raise SPSDKValueError(
                f"Count of passed arguments is higher than what is needed, need: {argument_names}"
            )

        script = load_text(script_path)
        pattern = re.compile(self.SCRIPT_ARG_REGEX)

        arguments_dict = {}
        matches = pattern.findall(script)
        for match in matches:
            key = match[0]
            optional_key = match[2] if match[2] else None
            description = match[3].strip()
            arguments_dict[key] = {"description": description, "optional_key": optional_key}

        try:
            script = SPSDKUUU.replace_arguments(script, arguments_dict, args)
        except ValueError as e:
            raise SPSDKValueError(
                f"Invalid arguments passed, you should pass {argument_names}"
            ) from e
        return script

    def run_uboot(self, command: str) -> bool:
        """Execute U-Boot command via UUU protocol.

        Sends the specified command to U-Boot through the libuuu interface and logs
        the execution result along with any response received.

        :param command: U-Boot command string to execute
        :return: True if command executed successfully, False otherwise
        """
        success = self.uuu.run_cmd(f"FB:UCMD {command}", 0) == 0
        logger.info(f"{command} {success=} response={self.response}")
        return success

    def run_uboot_acmd(self, command: str) -> bool:
        """Run uboot command ACMD.

        Executes a U-Boot command using the ACMD (Application Command) interface through UUU
        (Universal Update Utility). The command execution status is logged for debugging purposes.

        :param command: U-Boot command string to execute.
        :return: True if command executed successfully, False otherwise.
        """
        success = self.uuu.run_cmd(f"FB:ACMD {command}", 0) == 0
        logger.info(f"{command} {success=} response={self.response}")
        return success

    def enable_fastboot_output(self) -> bool:
        """Enable fastboot output for stdout and stderr of uboot commands.

        This method configures the U-Boot environment to redirect both standard output
        and standard error streams to serial and fastboot interfaces, enabling output
        capture during fastboot operations.

        :return: True if the command executed successfully, False otherwise.
        """
        return self.run_uboot("setenv stdout serial,fastboot")

    @check_uuu_error_state_after_command
    def run_cmd(self, cmd: str, dry: bool = False) -> int:
        """Run a uuu command.

        Execute the specified uuu command either in dry run mode or actual execution mode.

        :param cmd: The command to run.
        :param dry: If set to False command will be executed, otherwise it's a dry run.
        :return: 0 if success.
        """
        return self.uuu.run_cmd(cmd, dry)

    @check_uuu_error_state_after_command
    def run_script(self, script_path: str, dry: bool = False) -> int:
        """Run a uuu script.

        Execute a Universal Update Utility (UUU) script file for device programming and configuration.

        :param script_path: The path to the script file to execute.
        :param dry: If set to True, performs a dry run without executing commands, defaults to False.
        :return: The result code of the script execution.
        """
        self.uuu._response.value = b""
        return self.uuu.lib.uuu_run_cmd_script(c_char_p(str.encode(script_path)), c_int(int(dry)))

    def auto_detect_file(self, filename: str) -> int:
        """Auto detect file type and format.

        Automatically detects the type and format of the specified file using the UUU library's
        auto-detection capabilities. This method clears any previous response data before
        performing the detection.

        :param filename: Path to the file to be analyzed for type detection.
        :return: Detection result code from the UUU library (0 for success, non-zero for error).
        """
        self.uuu._response.value = b""
        return self.uuu.lib.uuu_auto_detect_file(c_char_p(str.encode(filename)))

    @check_uuu_error_state_after_command
    def wait_uuu_finish(
        self,
        daemon: bool = False,
        dry: bool = False,
    ) -> int:
        """Wait for the uuu execution to finish.

        The method waits for the Universal Update Utility (UUU) process to complete execution,
        with options for daemon mode and dry run operations.

        :param daemon: If True, run uuu as a daemon process, defaults to False.
        :param dry: If True, perform a dry run without executing the commands, defaults to False.
        :raises ValueError: When both daemon and dry parameters are True simultaneously.
        :return: The result code of the uuu execution.
        """
        if daemon and dry:
            raise ValueError("Cannot run as daemon and dry run simultaneously")

        if daemon:
            self.uuu.set_wait_timeout(-1)
            self.uuu.set_wait_next_timeout(-1)

        wait_helper = CancellableWait()
        return wait_helper.run_interruptible(
            self.uuu.lib.uuu_wait_uuu_finish, c_int(int(daemon)), c_int(int(dry))
        )

    def for_each_devices(self, callback: Callable) -> int:
        """Execute callback function for each connected USB device.

        Iterates through all available USB devices and executes the provided callback
        function for each device found in the system.

        :param callback: Callback function to execute for each detected USB device.
        :return: Result code from the underlying UUU library operation.
        """
        return self.uuu.lib.uuu_for_each_devices(UUULsUsbDevices(callback))

    def add_usbpath_filter(self, path: str) -> int:
        """Add a USB path filter to the UUU library.

        This method adds a USB device path filter that can be used to restrict
        communication to specific USB devices based on their system path.

        :param path: USB device path string to be added as filter.
        :return: Integer result code from the underlying UUU library operation.
        """
        return self.uuu.lib.uuu_add_usbpath_filter(c_char_p(str.encode(path)))

    def add_usbserial_no_filter(self, serial_no: str) -> int:
        """Add a USB serial number filter to the UUU library.

        This method adds a USB serial number filter that can be used to restrict
        operations to specific USB devices based on their serial numbers.

        :param serial_no: The USB serial number string to add as a filter.
        :return: Integer result code from the underlying UUU library operation.
        """
        return self.uuu.lib.uuu_add_usbserial_no_filter(c_char_p(str.encode(serial_no)))

    def set_timeouts(self, wait_timeout: int, wait_next_timeout: int) -> None:
        """Set both wait timeouts for UUU operations.

        This method configures the timeout values for waiting operations and applies
        them to the underlying UUU instance.

        :param wait_timeout: Timeout for waiting in seconds
        :param wait_next_timeout: Timeout for waiting for next device in seconds
        """
        self.wait_timeout = wait_timeout
        self.wait_next_timeout = wait_next_timeout
        self.uuu.set_wait_timeout(wait_timeout)
        self.uuu.set_wait_next_timeout(wait_next_timeout)

    def get_timeouts(self) -> tuple[int, int]:
        """Get current timeout values.

        :return: Tuple of (wait_timeout, wait_next_timeout) in seconds.
        """
        return self.wait_timeout, self.wait_next_timeout

    def with_temporary_timeouts(self, wait_timeout: int, wait_next_timeout: int) -> Any:
        """Create context manager for temporary UUU timeout modifications.

        This method provides a safe way to temporarily change UUU timeout values for specific
        operations and automatically restore the original values when exiting the context,
        ensuring proper cleanup even if exceptions occur.

        :param wait_timeout: Temporary wait timeout value in seconds.
        :param wait_next_timeout: Temporary wait next timeout value in seconds.
        :return: Context manager instance for timeout handling.
        """

        class TimeoutContext:
            """Context manager for temporarily modifying UUU timeout settings.

            This class provides a safe way to temporarily change timeout values for UUU
            operations and automatically restore the original values when exiting the
            context, ensuring proper cleanup even if exceptions occur.
            """

            def __init__(self, uuu_instance: "SPSDKUUU", temp_wait: int, temp_next: int) -> None:
                """Initialize UUU timeout context manager.

                Context manager to temporarily modify UUU timeout settings and restore them afterwards.

                :param uuu_instance: SPSDK UUU instance to modify timeout settings for.
                :param temp_wait: Temporary wait timeout value in seconds.
                :param temp_next: Temporary next timeout value in seconds.
                """
                self.uuu = uuu_instance
                self.temp_wait = temp_wait
                self.temp_next = temp_next
                self.original_wait: Optional[int] = None
                self.original_next: Optional[int] = None

            def __enter__(self) -> "TimeoutContext":
                """Enter the timeout context manager.

                Sets temporary timeout values for UUU operations and stores the original
                timeout values for restoration when exiting the context.

                :return: The TimeoutContext instance for use in with statement.
                """
                self.original_wait, self.original_next = self.uuu.get_timeouts()
                self.uuu.set_timeouts(self.temp_wait, self.temp_next)
                return self

            def __exit__(
                self,
                exc_type: Optional[type[BaseException]],
                exc_val: Optional[BaseException],
                exc_tb: Optional[TracebackType],
            ) -> None:
                """Exit the timeout context manager and restore original timeout values.

                Restores the UUU instance's original wait and next timeout values that were
                saved when entering the context manager, ensuring proper cleanup of timeout
                modifications.

                :param exc_type: Type of exception that caused the context to exit, if any.
                :param exc_val: Exception instance that caused the context to exit, if any.
                :param exc_tb: Traceback object associated with the exception, if any.
                """
                if self.original_wait is not None and self.original_next is not None:
                    self.uuu.set_timeouts(self.original_wait, self.original_next)

        return TimeoutContext(self, wait_timeout, wait_next_timeout)

    def verify_fastboot_connection(self, timeout: int = 1) -> bool:
        """Verify if fastboot connection is available with a short timeout.

        The method temporarily sets connection timeouts and attempts to execute
        a simple fastboot command to verify device connectivity.

        :param timeout: Timeout in seconds for verification, defaults to 1
        :return: True if fastboot is available, False otherwise
        """
        try:
            with self.with_temporary_timeouts(timeout, timeout):
                # Try a simple fastboot command to verify connection
                result = self.run_cmd("FB: getvar version", dry=False)
                return result == 0
        except Exception as e:
            logger.debug(f"Fastboot verification failed: {e}")
            return False
