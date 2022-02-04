#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for DebugMailbox Pemicro Debug probes support."""

import logging
from typing import Dict, Optional

from pypemicro import PEMicroException, PEMicroInterfaces, PyPemicro

from spsdk import SPSDKError

from .debug_probe import (
    DebugProbe,
    SPSDKDebugProbeError,
    SPSDKDebugProbeNotOpenError,
    SPSDKDebugProbeTransferError,
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.CRITICAL)
PEMICRO_LOGGER = logger.getChild("PyPemicro")


class DebugProbePemicro(DebugProbe):
    """Class to define Pemicro package interface for NXP SPSDK."""

    @classmethod
    def get_pemicro_lib(cls) -> PyPemicro:
        """Get J-Link object.

        :return: The J-Link Object
        :raises SPSDKDebugProbeError: The J-Link object get function failed.
        """
        return PyPemicro(
            log_info=PEMICRO_LOGGER.info,
            log_debug=PEMICRO_LOGGER.debug,
            log_err=PEMICRO_LOGGER.error,
            log_war=PEMICRO_LOGGER.warn,
        )

    def __init__(self, hardware_id: str, user_params: Dict = None) -> None:
        """The Pemicro class initialization.

        The Pemicro initialization function for SPSDK library to support various DEBUG PROBES.
        """
        super().__init__(hardware_id, user_params)

        self.pemicro: Optional[PyPemicro] = None
        self.last_access_memory = False

        logger.debug("The SPSDK Pemicro Interface has been initialized")

    @classmethod
    def get_connected_probes(cls, hardware_id: str = None, user_params: Dict = None) -> list:
        """Get all connected probes over Pemicro.

        This functions returns the list of all connected probes in system by Pemicro package.

        :param hardware_id: None to list all probes, otherwise the the only probe with matching
            hardware id is listed.
        :param user_params: The user params dictionary
        :return: probe_description
        """
        # pylint: disable=import-outside-toplevel
        from .utils import DebugProbes, ProbeDescription

        pemicro = DebugProbePemicro.get_pemicro_lib()

        probes = DebugProbes()
        connected_probes = pemicro.list_ports()
        for probe in connected_probes:
            probes.append(
                ProbeDescription("PEMicro", probe["id"], probe["description"], DebugProbePemicro)
            )

        return probes

    def open(self) -> None:
        """Open Pemicro interface for NXP SPSDK.

        The Pemicro opening function for SPSDK library to support various DEBUG PROBES.
        The function is used to initialize the connection to target and enable using debug probe
        for DAT purposes.

        :raises SPSDKDebugProbeError: The Pemicro cannot establish communication with target
        """
        try:
            self.pemicro = DebugProbePemicro.get_pemicro_lib()
            if self.pemicro is None:
                raise SPSDKDebugProbeError("Getting of J-Link library failed.")
        except SPSDKDebugProbeError as exc:
            raise SPSDKDebugProbeError(f"Getting of J-Link library failed({str(exc)}).") from exc
        try:
            self.pemicro.open(debug_hardware_name_ip_or_serialnum=self.hardware_id)
            self.pemicro.connect(PEMicroInterfaces.SWD)  # type: ignore
            dbgmlbx_ap_ix = self._get_dmbox_ap()
        except PEMicroException as exc:
            raise SPSDKDebugProbeError(
                f"Pemicro cannot establish  communication with target({str(exc)})."
            ) from exc

        if self.dbgmlbx_ap_ix == -1:
            if dbgmlbx_ap_ix == -1:
                raise SPSDKDebugProbeError("The Debug mailbox access port is not available!")
            self.dbgmlbx_ap_ix = dbgmlbx_ap_ix
        else:
            if dbgmlbx_ap_ix != self.dbgmlbx_ap_ix:
                logger.info(
                    "The detected debug mailbox accessport index is different to specified."
                )

    def close(self) -> None:
        """Close Pemicro interface.

        The Pemicro closing function for SPSDK library to support various DEBUG PROBES.
        """
        if self.pemicro:
            self.pemicro.close()

    def mem_reg_read(self, addr: int = 0) -> int:
        """Read 32-bit register in memory space of MCU.

        This is read 32-bit register in memory space of MCU function for SPSDK library
        to support various DEBUG PROBES.

        :param addr: the register address
        :return: The read value of addressed register (4 bytes)
        :raises SPSDKDebugProbeNotOpenError: The Pemicro probe is NOT opened
        :raises SPSDKError: The Pemicro probe has failed during read operation
        """
        if self.pemicro is None:
            raise SPSDKDebugProbeNotOpenError("The Pemicro debug probe is not opened yet")

        self.last_access_memory = True
        reg = 0
        try:
            reg = self.pemicro.read_32bit(addr)
        except PEMicroException as exc:
            logger.error(f"Failed read memory({str(exc)}).")
            raise SPSDKError(str(exc)) from exc
        return reg

    def mem_reg_write(self, addr: int = 0, data: int = 0) -> None:
        """Write 32-bit register in memory space of MCU.

        This is write 32-bit register in memory space of MCU function for SPSDK library
        to support various DEBUG PROBES.

        :param addr: the register address
        :param data: the data to be written into register
        :raises SPSDKDebugProbeNotOpenError: The Pemicro probe is NOT opened
        :raises SPSDKError: The Pemicro probe has failed during write operation
        """
        if self.pemicro is None:
            raise SPSDKDebugProbeNotOpenError("The Pemicro debug probe is not opened yet")

        self.last_access_memory = True
        try:
            self.pemicro.write_32bit(address=addr, data=data)
        except PEMicroException as exc:
            logger.error(f"Failed write memory({str(exc)}).")
            raise SPSDKError(str(exc)) from exc

    def dbgmlbx_reg_read(self, addr: int = 0) -> int:
        """Read debug mailbox access port register.

        This is read debug mailbox register function for SPSDK library to support various DEBUG PROBES.

        :param addr: the register address
        :return: The read value of addressed register (4 bytes)
        :raises NotImplementedError: The dbgmlbx_reg_read is NOT implemented
        """
        return self.coresight_reg_read(addr=addr | (self.dbgmlbx_ap_ix << self.APSEL_SHIFT))

    def dbgmlbx_reg_write(self, addr: int = 0, data: int = 0) -> None:
        """Write debug mailbox access port register.

        This is write debug mailbox register function for SPSDK library to support various DEBUG PROBES.

        :param addr: the register address
        :param data: the data to be written into register
        :raises NotImplementedError: The dbgmlbx_reg_write is NOT implemented
        """
        self.coresight_reg_write(addr=addr | (self.dbgmlbx_ap_ix << self.APSEL_SHIFT), data=data)

    def coresight_reg_read(self, access_port: bool = True, addr: int = 0) -> int:
        """Read coresight register over Pemicro interface.

        The Pemicro read coresight register function for SPSDK library to support various DEBUG PROBES.

        :param access_port: if True, the Access Port (AP) register will be read(default), otherwise the Debug Port
        :param addr: the register address
        :return: The read value of addressed register (4 bytes)
        :raises SPSDKDebugProbeTransferError: The IO operation failed
        :raises SPSDKDebugProbeNotOpenError: The Pemicro probe is NOT opened
        """
        if self.pemicro is None:
            raise SPSDKDebugProbeNotOpenError("The Pemicro debug probe is not opened yet")

        try:
            if self.last_access_memory:
                self.last_access_memory = False

            if access_port:
                ap_ix = (addr & self.APSEL_APBANKSEL) >> self.APSEL_SHIFT
                ret = self.pemicro.read_ap_register(apselect=ap_ix, addr=addr)
            else:
                ret = self.pemicro.read_dp_register(addr=addr)
            return ret
        except PEMicroException as exc:
            raise SPSDKDebugProbeTransferError(
                f"The Coresight read operation failed({str(exc)})."
            ) from exc

    def coresight_reg_write(self, access_port: bool = True, addr: int = 0, data: int = 0) -> None:
        """Write coresight register over Pemicro interface.

        The Pemicro write coresight register function for SPSDK library to support various DEBUG PROBES.

        :param access_port: if True, the Access Port (AP) register will be write(default), otherwise the Debug Port
        :param addr: the register address
        :param data: the data to be written into register
        :raises SPSDKDebugProbeTransferError: The IO operation failed
        :raises SPSDKDebugProbeNotOpenError: The Pemicro probe is NOT opened
        """
        if self.pemicro is None:
            raise SPSDKDebugProbeNotOpenError("The Pemicro debug probe is not opened yet")

        try:
            if self.last_access_memory:
                self.last_access_memory = False

            if access_port:
                ap_ix = (addr & self.APSEL_APBANKSEL) >> self.APSEL_SHIFT
                self.pemicro.write_ap_register(apselect=ap_ix, addr=addr, value=data)
            else:
                self.pemicro.write_dp_register(addr=addr, value=data)

        except PEMicroException as exc:
            raise SPSDKDebugProbeTransferError(
                f"The Coresight write operation failed({str(exc)})."
            ) from exc

    def reset(self) -> None:
        """Reset a target.

        It resets a target.

        :raises SPSDKDebugProbeNotOpenError: The Pemicro debug probe is not opened yet
        """
        if self.pemicro is None:
            raise SPSDKDebugProbeNotOpenError("The Pemicro debug probe is not opened yet")

        try:
            self.pemicro.reset_target()
        except PEMicroException as exc:
            logger.warning("The reset sequence occurred some errors.")
            self.pemicro.control_reset_line(assert_reset=False)

    def _get_dmbox_ap(self) -> int:
        """Search for Debug Mailbox Access Point.

        This is helper function to find and return the debug mailbox access port index.

        :return: Debug MailBox Access Port Index if found, otherwise -1
        :raises SPSDKDebugProbeNotOpenError: The PEMicro probe is NOT opened
        """
        idr_expected = 0x002A0000
        idr_address = 0xFC

        if self.pemicro is None:
            raise SPSDKDebugProbeNotOpenError("The Pemicro debug probe is not opened yet")

        logger.debug("Looking for debug mailbox access port")

        for access_port_ix in range(256):
            try:
                address = idr_address | (
                    (access_port_ix << self.APSEL_SHIFT) & self.APSEL_APBANKSEL
                )
                ret = self.pemicro.read_ap_register(apselect=access_port_ix, addr=address)
                if ret == idr_expected:
                    logger.debug(f"Found debug mailbox ix:{access_port_ix}")
                    return access_port_ix
                if ret != 0:
                    logger.debug(f"Found general access port ix:{access_port_ix}, IDR:{ret}")
                else:
                    logger.debug(f"The AP({access_port_ix}) is not available")
            except PEMicroException:
                logger.debug(f"The AP({access_port_ix}) is not available")

        return -1
