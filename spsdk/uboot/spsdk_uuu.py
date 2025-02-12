#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""module that wraps libuuu library and provides a more user-friendly interface."""
import logging
import re
from ctypes import CFUNCTYPE, POINTER, c_char_p, c_int, c_uint16, c_void_p
from typing import Any, Callable, Optional

import click
from libuuu import LibUUU, UUUNotifyCallback, UUUState
from libuuu.libuuu import UUUNotifyStruct, UUUNotifyType, _default_notify_callback

from spsdk.exceptions import SPSDKValueError
from spsdk.utils.database import DatabaseManager, get_db, get_families
from spsdk.utils.misc import load_text

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
    """A default callback function that stores the response in a class variable.

    :param struct: A UUUNotifyStruct object
    :param data: A pointer to data, here it is not used
    """
    # pylint: disable=unused-argument
    SPSDKUUU._state.update(struct)
    if struct.type == UUUNotifyType.NOTIFY_CMD_INFO:
        LibUUU._response.value += bytes(struct.response.str)
    return 1 if SPSDKUUU._state.error else 0


class SPSDKUUUState(UUUState):
    """A class that represents the state of the UUU."""

    progress_bars: dict[str, Any] = {}

    def __init__(self, progress_bar: bool = True) -> None:
        """SPSDKUUU State constructor.

        :param progress_bar: show progress bar, defaults to True
        """
        self.progress_bar = progress_bar
        super().__init__()

    def update_progress_bar(self, task_name: str, total_steps: int, step: int) -> None:
        """Update the progress bar for a task.

        :param task_name: The name of the task.
        :param total_steps: The total number of steps for the task.
        :param step: The current step of the task.
        """
        # Check if the progress bar for the task already exists
        if task_name not in self.progress_bars:
            # Create a new progress bar and store it in the dictionary
            self.progress_bars[task_name] = click.progressbar(
                length=total_steps, label=task_name, bar_template="%(info)s [%(bar)s] %(label)s"
            )

        # Update the existing progress bar
        bar = self.progress_bars[task_name]
        bar.update(step)

        # If the current step is the last step print new line
        if step == total_steps:
            del self.progress_bars[task_name]
            click.echo("\r")

    def update(self, struct: UUUNotifyStruct) -> None:
        """Update the state with a notification from uuu.

        :param struct: A UUUNotifyStruct object
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
            status = struct.response.status
            self.done = True
            self.error = status != 0
            self.cmd_end = struct.timestamp
            if status != 0:
                self.logger.error(f"Command {self.cmd} failed with error code {status}")
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

        self.logger.debug(f"{self.cmd=},{self.dev=},{self.waiting=}")


class SPSDKUUU:
    """A class that wraps the libuuu library and provides a more user-friendly interface."""

    SCRIPT_ARG_REGEX = r"# @(\S+)\s*(\[(\S+)\])?\s*\|\s*(.+)"
    _state = SPSDKUUUState()

    def __init__(
        self,
        wait_timeout: int = 30,
        wait_next_timeout: int = 30,
        poll_period: int = 100,
        progress_bar: bool = True,
        usb_path_filter: Optional[str] = None,
        usb_serial_no_filter: Optional[str] = None,
    ) -> None:
        """Initialize the SPSDKUUU object.

        :param wait_timeout: The timeout value for command execution in seconds, defaults to 30
        :param wait_next_timeout: The timeout value for waiting for the next device in seconds, defaults to 30
        :param poll_period: The period in milliseconds for polling the USB device, defaults to 100
        :param progress_bar: True for showing the progress bar to stdout
        :param usb_path_filter: The USB path to filter
        :param usb_serial_no_filter: The USB serial number to filter
        """
        self.uuu = LibUUU()
        self.uuu.set_wait_timeout(wait_timeout)
        self.uuu.set_wait_next_timeout(wait_next_timeout)
        self.uuu.set_poll_period(poll_period)
        self.uuu.unregister_notify_callback(_default_notify_callback)
        self.uuu.register_notify_callback(_spsdk_notify_callback, POINTER(c_void_p)())
        rc = 0
        rc = self.add_usbpath_filter(usb_path_filter) if usb_path_filter else 0
        if rc != 0:
            raise SPSDKValueError(f"Error adding USB path filter: {rc}")
        rc = self.add_usbserial_no_filter(usb_serial_no_filter) if usb_serial_no_filter else 0
        if rc != 0:
            raise SPSDKValueError(f"Error adding USB serial number filter: {rc}")
        self._state.progress_bar = progress_bar

    @property
    def response(self) -> str:
        """Get the response from the last command."""
        return self.uuu.response.decode()

    @property
    def last_error_str(self) -> str:
        """Get the last error string."""
        return self.uuu.get_last_error_string()

    @property
    def last_error(self) -> int:
        """Get the last error code."""
        return self.uuu.get_last_error()

    @staticmethod
    def get_supported_families() -> list[str]:
        """Get the list of supported families.

        :return: List of family names that support memory configuration.
        """
        return get_families(DatabaseManager.NXPUUU)

    @staticmethod
    def get_supported_devices() -> list[str]:
        """Get supported devices for the given family."""
        return list(
            get_db(get_families(DatabaseManager.NXPUUU)[0])
            .get_dict(DatabaseManager.NXPUUU, "boot_devices")
            .keys()
        )

    @staticmethod
    def replace_arguments(
        input_string: str, arguments_dict: dict[str, dict[str, Any]], arguments: list[str]
    ) -> str:
        """Replace arguments in the input string.

        :param input_string: The input string to replace arguments in.
        :param arguments_dict: A dictionary containing the arguments and their descriptions.
        :param arguments: The list of arguments to replace in the input string.
        :return: The input string with the arguments replaced.
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
                    replacements.append((key, argument_mapping[key]))
                elif val["optional_key"] and val["optional_key"] in argument_mapping:
                    replacements.append((key, argument_mapping[val["optional_key"]]))
                else:
                    replacements.append((key, val["optional_key"] if val["optional_key"] else ""))

        # Perform replacements in the input_string using regular expressions to match whole words
        for key, replacement in replacements:
            input_string = re.sub(r"\b" + re.escape(key) + r"\b", replacement, input_string)

        return input_string

    def get_uuu_script(self, boot_device: str, family: str, args: Optional[list[str]]) -> str:
        """Get the uuu script for the given boot device."""
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
            script = self.replace_arguments(script, arguments_dict, args)
        except ValueError as e:
            raise SPSDKValueError(
                f"Invalid arguments passed, you should pass {argument_names}"
            ) from e
        return script

    def run_uboot(self, command: str) -> bool:
        """Run uboot command.

        :param command: string command
        :return: Return code from the libuuu
        """
        success = self.uuu.run_cmd(f"FB:UCMD {command}", 0) == 0
        logger.info(f"{command} {success=} response={self.response}")
        return success

    def run_uboot_acmd(self, command: str) -> bool:
        """Run uboot command ACMD.

        :param command: string command
        """
        success = self.uuu.run_cmd(f"FB:ACMD {command}", 0) == 0
        logger.info(f"{command} {success=} response={self.response}")
        return success

    def enable_fastboot_output(self) -> bool:
        """Enable fastboot output for stdout and stderr of uboot commands."""
        return self.run_uboot("setenv stdout serial,fastboot")

    def run_cmd(self, cmd: str, dry: bool = False) -> int:
        """Run a uuu command.

        :param cmd: The command to run
        :param dry: If set to False command will be executed, otherwise its a dry run
        :return: 0 if success
        """
        return self.uuu.run_cmd(cmd, dry)

    def run_script(self, script_path: str, dry: bool = False) -> int:
        """Run a uuu script.

        :param script_path: The path to the script file.
        :param dry: If set to True, it will be a dry run without executing the commands, defaults to False.
        :return: The result of the script execution.
        """
        self.uuu._response.value = b""
        return self.uuu.lib.uuu_run_cmd_script(c_char_p(str.encode(script_path)), c_int(int(dry)))

    def auto_detect_file(self, filename: str) -> int:
        """Auto detect file.

        :param filename: The name of the file to be auto detected.
        :return: The result of the auto detection.
        """
        self.uuu._response.value = b""
        return self.uuu.lib.uuu_auto_detect_file(c_char_p(str.encode(filename)))

    def wait_uuu_finish(
        self,
        daemon: bool = False,
        dry: bool = False,
    ) -> int:
        """Wait for the uuu execution to finish.

        :param daemon: If True, run uuu as a daemon process, defaults to False.
        :param dry: If True, perform a dry run without executing the commands, defaults to False.
        :return: The result of the uuu execution.
        """
        return self.uuu.lib.uuu_wait_uuu_finish(c_int(int(daemon)), c_int(int(dry)))

    def for_each_devices(self, callback: Callable) -> int:
        """For each device.

        :param callback: The callback function to be executed for each device.
        :return: The result of the execution.
        """
        return self.uuu.lib.uuu_for_each_devices(UUULsUsbDevices(callback))

    def add_usbpath_filter(self, path: str) -> int:
        """Add a USB path filter.

        :param path: The USB path to filter.
        :return: The result of adding the filter.
        """
        return self.uuu.lib.uuu_add_usbpath_filter(c_char_p(str.encode(path)))

    def add_usbserial_no_filter(self, serial_no: str) -> int:
        """Add a USB serial number filter.

        :param serial_no: The USB serial number to filter.
        :return: The result of adding the filter.
        """
        return self.uuu.lib.uuu_add_usbserial_no_filter(c_char_p(str.encode(serial_no)))
