#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for DebugMailbox PyLink Debug probes support."""

import logging
from time import sleep
from typing import List

import pylink
import pylink.protocols.swd as swd
from pylink.errors import JLinkException

from .debug_probe import (DebugProbe,
                          ProbeDescription,
                          DebugProbeTransferError,
                          DebugProbeNotOpenError,
                          DebugProbeError)

logger = logging.getLogger(__name__)
logger.setLevel(logging.CRITICAL)
JLINK_LOGGER = logger.getChild("PyLink")



class DebugProbePyLink(DebugProbe):
    """Class to define PyLink package interface for NXP SPSDK."""

    @classmethod
    def get_jlink_lib(cls) -> pylink.JLink:
        """Get J-Link object.

        :return: The J-Link Object
        :raises DebugProbeError: The J-Link object get function failed.
        """
        try:
            return pylink.JLink(log=JLINK_LOGGER.info, detailed_log=JLINK_LOGGER.debug,
                                error=JLINK_LOGGER.error, warn=JLINK_LOGGER.warn)
        except TypeError:
            raise DebugProbeError("Cannot open Jlink DLL")

    def __init__(self, hardware_id: str, ip_address: str = None) -> None:
        """The PyLink class initialization.

        The PyLink initialization function for SPSDK library to support various DEBUG PROBES.
        """
        super().__init__(hardware_id, ip_address)

        self.pylink = None

        # Use coresight_read/write API - True (default)
        # or the original swd interface- False (this did not work properly)
        self.use_coresight_rw = True

        logger.debug(f"The SPSDK PyLink Interface has been initialized")

    @classmethod
    def get_connected_probes(cls, hardware_id: str = None) -> List[ProbeDescription]:
        """Get all connected probes over PyLink.

        This functions returns the list of all connected probes in system by PyLink package.
        :param hardware_id: None to list all probes, otherwise the the only probe with matching
            hardware id is listed.
        :return: probe_description
        """
        #TODO fix problems with cyclic import
        from .utils import DebugProbes

        jlink = DebugProbePyLink.get_jlink_lib()

        probes = DebugProbes()
        connected_probes = jlink.connected_emulators()
        for probe in connected_probes:
            probes.append(ProbeDescription("Jlink",
                                           str(probe.SerialNumber),
                                           "Segger " + probe.acProduct.decode("utf-8") + ": " + str(probe.SerialNumber),
                                           DebugProbePyLink))

        return probes

    def open(self) -> None:
        """Open PyLink interface for NXP SPSDK.

        The PyLink opening function for SPSDK library to support various DEBUG PROBES.
        The function is used to initialize the connection to target and enable using debug probe
        for DAT purposes.
        :raises ProbeNotFoundError: The probe has not found
        :raises DebugMailBoxAPNotFoundError: The debug mailbox access port NOT found
        :raises DebugProbeError: The PyLink cannot establish communication with target
        """
        try:
            self.pylink = DebugProbePyLink.get_jlink_lib()
            if self.pylink is None:
                raise DebugProbeError(f"Getting of J-Link library failed.")
        except DebugProbeError as exc:
            raise DebugProbeError(f"Getting of J-Link library failed({str(exc)}).")

        try:
            self.pylink.open(serial_no=self.hardware_id, ip_addr=self.ip_address)
            self.pylink.set_tif(pylink.enums.JLinkInterfaces.SWD)
            self.pylink.coresight_configure()
            debugmb_ap_ix = self._get_dmbox_ap()

            # Select ISP - AP
            if self.dbgmlbx_ap_ix == -1:
                if debugmb_ap_ix == -1:
                    raise DebugProbeError(f"The Debug mailbox access port is not available!")
                self.dbgmlbx_ap_ix = debugmb_ap_ix
            else:
                if debugmb_ap_ix != self.dbgmlbx_ap_ix:
                    logger.info(f"The detected debug mailbox accessport index is different to specified.")

            self._select_ap(ap_ix=self.dbgmlbx_ap_ix)

        except JLinkException as exc:
            raise DebugProbeError(f"PyLink cannot establish communication with target({str(exc)}).")

    def close(self) -> None:
        """Close PyLink interface.

        The PyLink closing function for SPSDK library to support various DEBUG PROBES.
        """
        if self.pylink:
            self.pylink.close()

    def dbgmlbx_reg_read(self, addr: int = 0) -> int:
        """Read debug mailbox access port register.

        This is read debug mailbox register function for SPSDK library to support various DEBUG PROBES.
        :param addr: the register address
        :return: The read value of addressed register (4 bytes)
        :raises NotImplementedError: The dbgmlbx_reg_read is NOT implemented
        """
        return self._coresight_reg_read(addr=addr)

    def dbgmlbx_reg_write(self, addr: int = 0, data: int = 0) -> None:
        """Write debug mailbox access port register.

        This is write debug mailbox register function for SPSDK library to support various DEBUG PROBES.
        :param addr: the register address
        :param data: the data to be written into register
        :raises NotImplementedError: The dbgmlbx_reg_write is NOT implemented
        """
        self._coresight_reg_write(addr=addr, data=data)

    def _coresight_reg_read(self, access_port: bool = True, addr: int = 0) -> int:
        """Read coresight register over PyLink interface.

        The PyLink read coresight register function for SPSDK library to support various DEBUG PROBES.
        :param access_port: if True, the Access Port (AP) register will be read(defau1lt), otherwise the Debug Port
        :param addr: the register address
        :return: The read value of addressed register (4 bytes)
        :raises DebugProbeTransferError: The IO operation failed
        :raises DebugProbeNotOpenError: The PyLink probe is NOT opened

        """
        if self.pylink is None:
            raise DebugProbeNotOpenError("The PyLink debug probe is not opened yet")

        try:
            if not self.use_coresight_rw:
                request = swd.ReadRequest(addr // 4, ap=access_port)
                response = request.send(self.pylink)
                if access_port:
                    sleep(0.1)  #TODO Check if this delay is necessary
                    request2 = swd.ReadRequest(3, ap=False)
                    response2 = request2.send(self.pylink)
                    return response2.data

                return response.data
            return self.pylink.coresight_read(reg=addr // 4, ap=access_port)
        except JLinkException as exc:
            raise DebugProbeTransferError(f"The Coresight read operation failed({str(exc)}).")

    def _coresight_reg_write(self, access_port: bool = True, addr: int = 0, data: int = 0) -> None:
        """Write coresight register over PyLink interface.

        The PyLink write coresight register function for SPSDK library to support various DEBUG PROBES.
        :param access_port: if True, the Access Port (AP) register will be write(default), otherwise the Debug Port
        :param addr: the register address
        :param data: the data to be written into register
        :raises DebugProbeTransferError: The IO operation failed
        :raises DebugProbeNotOpenError: The PyLink probe is NOT opened
        """
        if self.pylink is None:
            raise DebugProbeNotOpenError("The PyLink debug probe is not opened yet")

        try:
            if not self.use_coresight_rw:
                request = swd.WriteRequest(addr // 4, data=data, ap=access_port)
                response = request.send(self.pylink)
                if not response.ack():
                    raise DebugProbeTransferError("No ack from JLink")
            else:
                self.pylink.coresight_write(reg=addr // 4, data=data, ap=access_port)

        except JLinkException as exc:
            raise DebugProbeTransferError(f"The Coresight write operation failed({str(exc)}).")

    def _select_ap(self, ap_ix: int, address: int = 0) -> None:
        """Helper function to selct the access port in DP.

        :param ap_ix: requested Access port  index.
        :param address: requested address.
        """
        self._coresight_reg_write(access_port=False, addr=0x08, data=(address | (ap_ix << 24)))

    def _get_dmbox_ap(self) -> int:
        """Search for Debug Mailbox Access Point.

        This is helper function to find and return the debug mailbox access port index.
        :return: Debug MailBox Access Port Index if found, otherwise -1
        :raises DebugProbeNotOpenError: The Segger JLink probe is NOT opened
        """
        idr_expected = 0x002A0000
        idr_address = 0xFC

        if self.pylink is None:
            raise DebugProbeNotOpenError("The Segger debug probe is not opened yet")

        logger.debug(f"Looking for debug mailbox access port")

        for access_port_ix in range(0, 255, 1):
            try:
                self._select_ap(ap_ix=access_port_ix, address=0x000000F0)
                ret = self._coresight_reg_read(addr=idr_address)

                if ret == idr_expected:
                    logger.debug(f"Found debug mailbox ix:{access_port_ix}")
                    return access_port_ix

                if ret != 0:
                    logger.debug(f"Found general access port ix:{access_port_ix}")
                else:
                    logger.debug(f"The AP({access_port_ix}) is not available")
            except JLinkException:
                logger.debug(f"The AP({access_port_ix}) is not available")
            except DebugProbeTransferError:
                logger.debug(f"The AP({access_port_ix}) is not available")
        return -1
