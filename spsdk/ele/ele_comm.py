#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""EdgeLock Enclave Message handler."""

import logging
import os
from types import TracebackType
from typing import List, Optional, Type

from spsdk import SPSDK_DATA_FOLDER
from spsdk.ele.ele_constants import ResponseStatus
from spsdk.ele.ele_message import EleMessage
from spsdk.exceptions import SPSDKError, SPSDKLengthError, SPSDKValueError
from spsdk.mboot.mcuboot import McuBoot
from spsdk.utils.database import Database

ELE_DATA_FOLDER: str = os.path.join(SPSDK_DATA_FOLDER, "ele")
ELE_DATABASE_FILE: str = os.path.join(ELE_DATA_FOLDER, "database.yaml")

logger = logging.getLogger(__name__)


class EleMessageHandler:
    """EdgeLock Enclave Message Handler over MCUBoot.

    This class can send the ELE message into target over mBoot and decode the response.
    """

    def __init__(self, mboot: McuBoot, family: str, revision: str = "latest") -> None:
        """Class object initialized.

        :param mboot: mBoot device.
        :param family: Target family name.
        :param revision: Target revision, default is use 'latest' revision.
        """
        self.mboot = mboot
        self.database = Database(ELE_DATABASE_FILE)
        if family not in self.database.devices.device_names:
            raise SPSDKValueError(f"{family} is not supported by EdgeLock Enclave in SPSDK.")
        self.family = family
        self.revision = revision
        self.comm_buff_addr = self.database.get_device_value(
            "comm_buffer_address", device=self.family, revision=self.revision
        )
        self.comm_buff_size = self.database.get_device_value(
            "comm_buffer_size", device=self.family, revision=self.revision
        )
        logger.info(
            f"ELE communicator is using {self.comm_buff_size} B size buffer at "
            f"{self.comm_buff_addr:08X} address in {family} target."
        )

    @staticmethod
    def get_supported_families() -> List[str]:
        """Get list of supported target families.

        :return: List of supported families.
        """
        return Database(ELE_DATABASE_FILE).devices.device_names

    def send_message(self, msg: EleMessage) -> None:
        """Send message and receive response.

        :param msg: EdgeLock Enclave message
        :raises SPSDKError: Invalid response status detected.
        :raises SPSDKLengthError: Invalid read back length detected.
        """
        msg.set_buffer_params(self.comm_buff_addr, self.comm_buff_size)
        try:
            # 1. Prepare command in target memory
            self.mboot.write_memory(msg.command_address, msg.export())

            # 1.1. Prepare command data in target memory if required
            if msg.has_command_data:
                self.mboot.write_memory(msg.command_data_address, msg.command_data)

            # 2. Execute ELE message on target
            self.mboot.ele_message(
                msg.command_address,
                msg.command_words_count,
                msg.response_address,
                msg.response_words_count,
            )
            if msg.response_words_count == 0:
                return
            # 3. Read back the response
            response = self.mboot.read_memory(msg.response_address, 4 * msg.response_words_count)
        except SPSDKError as exc:
            raise SPSDKError(f"ELE Communication failed with mBoot: {str(exc)}") from exc

        if not response or len(response) != 4 * msg.response_words_count:
            raise SPSDKLengthError("ELE Message - Invalid response read-back operation.")
        # 4. Decode the response
        msg.decode_response(response)

        # 4.1 Check the response status
        if msg.status != ResponseStatus.ELE_SUCCESS_IND:
            raise SPSDKError(f"ELE Message failed. \n{msg.info()}")

        # 4.2 Read back the response data from target memory if required
        if msg.has_response_data:
            try:
                response_data = self.mboot.read_memory(
                    msg.response_data_address, msg.response_data_size
                )
            except SPSDKError as exc:
                raise SPSDKError(f"ELE Communication failed with mBoot: {str(exc)}") from exc

            if not response_data or len(response_data) != msg.response_data_size:
                raise SPSDKLengthError("ELE Message - Invalid response data read-back operation.")

            msg.decode_response_data(response_data)

        logger.info(f"Sent message information:\n{msg.info()}")

    def __enter__(self) -> None:
        """Enter function of ELE handler."""
        if not self.mboot.is_opened:
            self.mboot.open()

    def __exit__(
        self,
        exception_type: Optional[Type[BaseException]] = None,
        exception_value: Optional[BaseException] = None,
        traceback: Optional[TracebackType] = None,
    ) -> None:
        """Close function of ELE handler."""
        if self.mboot.is_opened:
            self.mboot.close()
