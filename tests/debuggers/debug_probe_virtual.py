#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for DebugMailbox Virtual Debug probes support used for product testing."""

from json.decoder import JSONDecodeError
import logging
import json
from typing import Dict, Any

from spsdk.debuggers.debug_probe import (
    DebugProbe,
    DebugProbeTransferError,
    DebugProbeNotOpenError,
    DebugProbeError,
    DebugProbeMemoryInterfaceNotEnabled,
)

logger = logging.getLogger(__name__)


def set_logger(level: int) -> None:
    """Sets the log level for this module.

    param level: Requested level.
    """
    logger.setLevel(level)


set_logger(logging.ERROR)


class DebugProbeVirtual(DebugProbe):
    """Class to define Virtual package interface for NXP SPSDK."""

    UNIQUE_SERIAL = "Virtual_DebugProbe_SPSDK"

    def __init__(self, hardware_id: str, user_params: Dict = None) -> None:
        """The Virtual class initialization.

        The Virtual initialization function for SPSDK library to support various DEBUG PROBES.
        """
        super().__init__(hardware_id, user_params)

        set_logger(logging.root.level)

        self.opened = False
        self.enabled_memory_interface = False
        self.virtual_memory: Dict[Any, Any] = {}
        self.virtual_memory_substituted: Dict[Any, Any] = {}
        self.coresight_ap: Dict[Any, Any] = {}
        self.coresight_ap_substituted: Dict[Any, Any] = {}
        self.coresight_dp: Dict[Any, Any] = {}
        self.coresight_dp_write_exception = False
        self.coresight_dp_substituted: Dict[Any, Any] = {}

        if user_params is not None:
            if "exc" in user_params.keys():
                raise DebugProbeError("Forced exception from constructor.")
            if "subs_ap" in user_params.keys():
                self.set_coresight_ap_substitute_data(
                    self._load_subs_from_param(user_params["subs_ap"])
                )
            if "subs_dp" in user_params.keys():
                self.set_coresight_dp_substitute_data(
                    self._load_subs_from_param(user_params["subs_dp"])
                )
            if "subs_mem" in user_params.keys():
                self.set_virtual_memory_substitute_data(
                    self._load_subs_from_param(user_params["subs_mem"])
                )

        logger.debug(f"The SPSDK Virtual Interface has been initialized")

    @classmethod
    def get_connected_probes(cls, hardware_id: str = None, user_params: Dict = None) -> list:
        """Get all connected probes over Virtual.

        This functions returns the list of all connected probes in system by Virtual package.
        :param hardware_id: None to list all probes, otherwise the the only probe with matching
            hardware id is listed.
        :param user_params: The user params dictionary
        :return: probe_description
        :raises DebugProbeError: In case of invoked test Exception.
        """
        # pylint: disable=import-outside-toplevel
        from spsdk.debuggers.utils import DebugProbes, ProbeDescription

        probes = DebugProbes()

        if user_params is not None and "exc" in user_params.keys():
            raise DebugProbeError("Forced exception from discovery function.")

        # Find this 'probe' just in case of direct request (user must know the hardware id :-) )
        if hardware_id == DebugProbeVirtual.UNIQUE_SERIAL:
            probes.append(
                ProbeDescription(
                    "Virtual",
                    DebugProbeVirtual.UNIQUE_SERIAL,
                    "Special virtual debug probe used for product testing",
                    DebugProbeVirtual,
                )
            )
        return probes

    def open(self) -> None:
        """Open Virtual interface for NXP SPSDK.

        The Virtual opening function for SPSDK library to support various DEBUG PROBES.
        The function is used to initialize the connection to target and enable using debug probe
        for DAT purposes.
        """
        self.dbgmlbx_ap_ix = 2
        self.opened = True

    def enable_memory_interface(self) -> None:
        """Debug probe enabling memory interface.

        General memory interface enabling method (it should be called after open method) for SPSDK library
        to support various DEBUG PROBES. The function is used to initialize the target memory interface
        and enable using memory access of target over debug probe.
        """
        self.enabled_memory_interface = True

    def close(self) -> None:
        """Close Virtual interface.

        The Virtual closing function for SPSDK library to support various DEBUG PROBES.
        """
        self.opened = False
        self.enabled_memory_interface = False

    def _get_requested_value(self, values: Dict, subs_values: Dict, addr: Any) -> int:
        """Method to return back the requested value.

        :param values: The dictionary with already loaded values.
        :param subs_values: The dictionary with substituted values.
        :param addr: Address of value.
        :return: Value by address.
        :raises DebugProbeError: General virtual probe error.
        """
        if subs_values and addr in subs_values.keys():
            if len(subs_values[addr]) > 0:
                svalue = subs_values[addr].pop()
                if isinstance(svalue, int):
                    return svalue
                if isinstance(svalue, str) and svalue == "Exception":
                    raise DebugProbeError("Simulated Debug probe exception")

        return int(values[addr]) if addr in values.keys() else 0

    def dbgmlbx_reg_read(self, addr: int = 0) -> int:
        """Read debug mailbox access port register.

        This is read debug mailbox register function for SPSDK library to support various DEBUG PROBES.
        :param addr: the register address
        :return: The read value of addressed register (4 bytes)
        :raises DebugProbeNotOpenError: The virtual probe is not open
        """
        if not self.opened:
            raise DebugProbeNotOpenError("The Virtual debug probe is not opened yet")

        # Add ap selection to 2 as a standard index of debug mailbox
        return self.coresight_reg_read(access_port=True, addr=addr | 2 << self.APSEL_SHIFT)

    def dbgmlbx_reg_write(self, addr: int = 0, data: int = 0) -> None:
        """Write debug mailbox access port register.

        This is write debug mailbox register function for SPSDK library to support various DEBUG PROBES.
        :param addr: the register address
        :param data: the data to be written into register
        :raises DebugProbeNotOpenError: The virtual probe is not open
        """
        if not self.opened:
            raise DebugProbeNotOpenError("The Virtual debug probe is not opened yet")

        # Add ap selection to 2 as a standard index of debug mailbox
        self.coresight_reg_write(access_port=True, addr=addr | 2 << self.APSEL_SHIFT, data=data)

    def mem_reg_read(self, addr: int = 0) -> int:
        """Read 32-bit register in memory space of MCU.

        This is read 32-bit register in memory space of MCU function for SPSDK library
        to support various DEBUG PROBES.
        :param addr: the register address
        :return: The read value of addressed register (4 bytes)
        :raises DebugProbeNotOpenError: The Virtual probe is NOT opened
        :raises DebugProbeMemoryInterfaceNotEnabled: The Virtual is using just CoreSight access.
        :raises DebugProbeError: General virtual probe error.
        """
        if not self.opened:
            raise DebugProbeNotOpenError("The Virtual debug probe is not opened yet")

        if not self.enabled_memory_interface:
            raise DebugProbeMemoryInterfaceNotEnabled(
                "Memory interface is not enabled over Virtual."
            )

        return self._get_requested_value(self.virtual_memory, self.virtual_memory_substituted, addr)

    def mem_reg_write(self, addr: int = 0, data: int = 0) -> None:
        """Write 32-bit register in memory space of MCU.

        This is write 32-bit register in memory space of MCU function for SPSDK library
        to support various DEBUG PROBES.
        :param addr: the register address
        :param data: the data to be written into register
        :raises DebugProbeNotOpenError: The Virtual probe is NOT opened
        :raises DebugProbeMemoryInterfaceNotEnabled: The Virtual is using just CoreSight access.
        """
        if not self.opened:
            raise DebugProbeNotOpenError("The Virtual debug probe is not opened yet")

        if not self.enabled_memory_interface:
            raise DebugProbeMemoryInterfaceNotEnabled(
                "Memory interface is not enabled over Virtual."
            )

        self.virtual_memory[addr] = data

    def coresight_reg_read(self, access_port: bool = True, addr: int = 0) -> int:
        """Read coresight register over Virtual interface.

        The Virtual read coresight register function for SPSDK library to support various DEBUG PROBES.
        :param access_port: if True, the Access Port (AP) register will be read(default), otherwise the Debug Port
        :param addr: the register address
        :return: The read value of addressed register (4 bytes)
        :raises DebugProbeTransferError: The IO operation failed
        :raises DebugProbeNotOpenError: The Virtual probe is NOT opened
        :raises DebugProbeError: General virtual probe error.
        """
        if not self.opened:
            raise DebugProbeNotOpenError("The Virtual debug probe is not opened yet")
        # As first try to solve AP requests
        if access_port:
            return self._get_requested_value(self.coresight_ap, self.coresight_ap_substituted, addr)

        # DP requests
        return self._get_requested_value(self.coresight_dp, self.coresight_dp_substituted, addr)

    def coresight_reg_write(self, access_port: bool = True, addr: int = 0, data: int = 0) -> None:
        """Write coresight register over Virtual interface.

        The Virtual write coresight register function for SPSDK library to support various DEBUG PROBES.
        :param access_port: if True, the Access Port (AP) register will be write(default), otherwise the Debug Port
        :param addr: the register address
        :param data: the data to be written into register
        :raises DebugProbeTransferError: The IO operation failed
        :raises DebugProbeNotOpenError: The Virtual probe is NOT opened
        """
        if not self.opened:
            raise DebugProbeNotOpenError("The Virtual debug probe is not opened yet")

        if access_port:
            self.coresight_ap[addr] = data
        else:
            if self.coresight_dp_write_exception:
                self.coresight_dp_write_exception = False
                raise DebugProbeTransferError(f"The Coresight write operation failed.")
            self.coresight_dp[addr] = data

    def reset(self) -> None:
        """Reset a target.

        It resets a target.
        :raises DebugProbeNotOpenError: The Virtual probe is NOT opened
        """
        if not self.opened:
            raise DebugProbeNotOpenError("The Virtual debug probe is not opened yet")

        logger.debug("The Virtual probe did reset of virtual target.")

    def clear(self, only_substitute: bool = False) -> None:
        """Clear the buffered values.

        :param only_substitute: When set, it clears just substitute data.
        """
        if not only_substitute:
            self.coresight_dp.clear()
            self.coresight_ap.clear()
            self.virtual_memory.clear()

        self.coresight_dp_substituted.clear()
        self.coresight_dp_write_exception = False
        self.coresight_ap_substituted.clear()
        self.virtual_memory_substituted.clear()

    def set_virtual_memory_substitute_data(self, substitute_data: Dict) -> None:
        """Set the virtual memory read substitute data.

        :param substitute_data: Dictionary of list of substitute data.
        """
        for key in substitute_data.keys():
            substitute_data[key].reverse()
        self.virtual_memory_substituted = substitute_data

    def set_coresight_dp_substitute_data(self, substitute_data: Dict) -> None:
        """Set the virtual memory read substitute data.

        :param substitute_data: Dictionary of list of substitute data.
        """
        for key in substitute_data.keys():
            substitute_data[key].reverse()
        self.coresight_dp_substituted = substitute_data

    def set_coresight_ap_substitute_data(self, substitute_data: Dict) -> None:
        """Set the coresight AP read substitute data.

        :param substitute_data: Dictionary of list of substitute data.
        """
        for key in substitute_data.keys():
            substitute_data[key].reverse()

        self.coresight_ap_substituted = substitute_data

    def dp_write_cause_exception(self) -> None:
        """Attempt to write to DP register cause exception."""
        self.coresight_dp_write_exception = True

    def _load_subs_from_param(self, arg: str) -> Dict:
        """Get the substituted values from input arguments.

        :param arg: Input string arguments with substitute values.
        :return: List of values for the substituted values.
        :raises DebugProbeError: The input string is not able do parse.
        """
        try:
            subs_data_raw = json.loads(arg)
            subs_data = {}
            for key in subs_data_raw.keys():
                subs_data[int(key)] = subs_data_raw[key]
            return subs_data
        except (TypeError, JSONDecodeError) as exc:
            raise DebugProbeError(f"Cannot parse substituted values: ({str(exc)})")
