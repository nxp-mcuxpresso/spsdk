#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for DebugMailbox Pemicro Debug probes support."""

import logging
from typing import Dict, Optional

from pypemicro import PEMicroException, PEMicroInterfaces, PyPemicro

from spsdk.utils.misc import value_to_int

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

    @staticmethod
    def get_options_help() -> Dict[str, str]:
        """Get full list of options of debug probe.

        :return: Dictionary with individual options. Key is parameter name and value the help text.
        """
        return {
            "frequency": "Set the communication frequency in Hz, default is 100_000Hz",
        }

    @classmethod
    def get_pemicro_lib(cls) -> PyPemicro:
        """Get Pemicro object.

        :return: The Pemicro Object
        :raises SPSDKDebugProbeError: The Pemicro object get function failed.
        """
        try:
            return PyPemicro(
                log_info=PEMICRO_LOGGER.info,
                log_debug=PEMICRO_LOGGER.debug,
                log_err=PEMICRO_LOGGER.error,
                log_war=PEMICRO_LOGGER.warn,
            )
        except PEMicroException as exc:
            raise SPSDKDebugProbeError(f"Cannot get Pemicro library: ({str(exc)})") from exc

    def __init__(self, hardware_id: str, options: Optional[Dict] = None) -> None:
        """The Pemicro class initialization.

        The Pemicro initialization function for SPSDK library to support various DEBUG PROBES.
        """
        super().__init__(hardware_id, options)

        self.pemicro: Optional[PyPemicro] = None

        logger.debug("The SPSDK Pemicro Interface has been initialized")

    @classmethod
    def get_connected_probes(
        cls, hardware_id: Optional[str] = None, options: Optional[Dict] = None
    ) -> list:
        """Get all connected probes over Pemicro.

        This functions returns the list of all connected probes in system by Pemicro package.

        :param hardware_id: None to list all probes, otherwise the the only probe with matching
            hardware id is listed.
        :param options: The options dictionary
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
                raise SPSDKDebugProbeError("Getting of Pemicro library failed.")
        except SPSDKDebugProbeError as exc:
            raise SPSDKDebugProbeError(f"Getting of Pemicro library failed({str(exc)}).") from exc
        try:
            self.pemicro.open(debug_hardware_name_ip_or_serialnum=self.hardware_id)
            self.pemicro.connect(PEMicroInterfaces.SWD)
            self.pemicro.set_debug_frequency(value_to_int(self.options.get("frequency", 100000)))
            self.clear_sticky_errors()
            self.power_up_target()

        except PEMicroException as exc:
            raise SPSDKDebugProbeError(
                f"Pemicro cannot establish  communication with target({str(exc)})."
            ) from exc

    def close(self) -> None:
        """Close Pemicro interface.

        The Pemicro closing function for SPSDK library to support various DEBUG PROBES.
        """
        if self.pemicro:
            self.pemicro.close()

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
            if access_port:
                ap_ix = (addr & self.APSEL_APBANKSEL) >> self.APSEL_SHIFT
                ret = self.pemicro.read_ap_register(apselect=ap_ix, addr=addr)
            else:
                ret = self.pemicro.read_dp_register(addr=addr)
            return ret
        except PEMicroException as exc:
            self._reinit_target()
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
            if access_port:
                ap_ix = (addr & self.APSEL_APBANKSEL) >> self.APSEL_SHIFT
                self.pemicro.write_ap_register(apselect=ap_ix, addr=addr, value=data)
            else:
                self.pemicro.write_dp_register(addr=addr, value=data)

        except PEMicroException as exc:
            self._reinit_target()
            raise SPSDKDebugProbeTransferError(
                f"The Coresight write operation failed({str(exc)})."
            ) from exc

    def assert_reset_line(self, assert_reset: bool = False) -> None:
        """Control reset line at a target.

        :param assert_reset: If True, the reset line is asserted(pulled down), if False the reset line is not affected.
        :raises SPSDKDebugProbeNotOpenError: The Pemicro debug probe is not opened yet
        :raises SPSDKDebugProbeError: The PyPEMicro probe RESET function failed
        """
        if self.pemicro is None:
            raise SPSDKDebugProbeNotOpenError("The Pemicro debug probe is not opened yet")

        try:
            if assert_reset:
                self.pemicro.control_reset_line(True)
            else:
                self.pemicro.control_reset_line(False)
        except PEMicroException as exc:
            raise SPSDKDebugProbeError(f"Pemicro reset operation failed: {str(exc)}") from exc
