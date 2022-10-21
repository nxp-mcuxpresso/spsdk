#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for DebugMailbox PyOCD Debug probes support."""

import logging
from typing import Any, Dict

import pylink
import pyocd
from pylink.errors import JLinkException
from pyocd.core.exceptions import Error as PyOCDError
from pyocd.core.helpers import ConnectHelper
from pyocd.coresight import dap
from pyocd.coresight.ap import MEM_AP
from pyocd.coresight.discovery import ADIv5Discovery, ADIv6Discovery, ADIVersion
from pyocd.probe.debug_probe import DebugProbe as PyOCDDebugProbe
from pyocd.probe.jlink_probe import JLinkProbe
from pyocd.utility.sequencer import CallSequence

from spsdk.exceptions import SPSDKError

from .debug_probe import (
    DebugProbe,
    SPSDKDebugMailBoxAPNotFoundError,
    SPSDKDebugProbeError,
    SPSDKDebugProbeMemoryInterfaceAPNotFoundError,
    SPSDKDebugProbeNotOpenError,
    SPSDKDebugProbeTransferError,
    SPSDKProbeNotFoundError,
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.CRITICAL)


def set_logger(level: int) -> None:
    """Sets the log level for this module.

    param level: Requested level.
    """
    logger.setLevel(level)

    logging.getLogger("pyocd.board.board").setLevel(logging.CRITICAL)
    logging.getLogger("pyocd.core.coresight_target").setLevel(level)
    logging.getLogger("pyocd.probe.common").setLevel(level)
    logging.getLogger("pyocd.utility").setLevel(level)
    logging.getLogger("pyocd.core").setLevel(level)
    logging.getLogger("pyocd.coresight").setLevel(level)


set_logger(logging.CRITICAL)


class DebugProbePyOCD(DebugProbe):
    """Class to define PyOCD package interface for NXP SPSDK."""

    def __init__(self, hardware_id: str, user_params: Dict = None) -> None:
        """The PyOCD class initialization.

        The PyOCD initialization function for SPSDK library to support various DEBUG PROBES.
        """
        super().__init__(hardware_id, user_params)

        set_logger(logging.root.level)

        self.pyocd_session = None
        self.dbgmlbx_ap_ix = -1
        self.mem_ap_ix = -1
        self.dbgmlbx_ap = None
        self.mem_ap = None

        logger.debug("The SPSDK PyOCD Interface has been initialized")

    @classmethod
    def get_connected_probes(cls, hardware_id: str = None, user_params: Dict = None) -> list:
        """Get all connected probes over PyOCD.

        This functions returns the list of all connected probes in system by PyOCD package.

        :param hardware_id: None to list all probes, otherwise the the only probe with matching
            hardware id is listed.
        :param user_params: The user params dictionary
        :return: probe_description
        """
        # pylint: disable=import-outside-toplevel
        from .utils import DebugProbes, ProbeDescription

        probes = DebugProbes()
        connected_probes = ConnectHelper.get_all_connected_probes(
            blocking=False, unique_id=hardware_id
        )
        for probe in connected_probes:
            probes.append(
                ProbeDescription("PyOCD", probe.unique_id, probe.description, DebugProbePyOCD)
            )

        return probes

    def open(self) -> None:
        """Open PyOCD interface for NXP SPSDK.

        The PyOCD opening function for SPSDK library to support various DEBUG PROBES.
        The function is used to initialize the connection to target and enable using debug probe
        for DAT purposes.

        :raises SPSDKProbeNotFoundError: The probe has not found
        :raises SPSDKDebugMailBoxAPNotFoundError: The debug mailbox access port NOT found
        :raises SPSDKDebugProbeError: The PyOCD cannot establish communication with target
        """
        try:
            self.pyocd_session = ConnectHelper.session_with_chosen_probe(
                blocking=False, unique_id=self.hardware_id
            )

            if self.pyocd_session is None:
                raise SPSDKProbeNotFoundError("No probe available!")
            self.pyocd_session.options.set("scan_all_aps", True)
            self.pyocd_session.delegate = self
            self.pyocd_session.open()
            logger.info(f"PyOCD connected via {self.pyocd_session.probe.product_name} probe.")
        except PyOCDError as exc:
            raise SPSDKDebugProbeError("PyOCD cannot establish communication with target.") from exc
        self.dbgmlbx_ap = self._get_dmbox_ap()
        self.mem_ap = self._get_mem_ap()
        if self.mem_ap is None:
            logger.warning("The memory interface not found - probably locked device or in ISP mode")
        if self.dbgmlbx_ap is None:
            raise SPSDKDebugMailBoxAPNotFoundError("No debug mail box access point available!")

    def close(self) -> None:
        """Close PyOCD interface.

        The PyOCD closing function for SPSDK library to support various DEBUG PROBES.
        """
        try:
            if self.pyocd_session:
                self.pyocd_session.close()
        except OSError:
            pass

    def mem_reg_read(self, addr: int = 0) -> int:
        """Read 32-bit register in memory space of MCU.

        This is read 32-bit register in memory space of MCU function for SPSDK library
        to support various DEBUG PROBES.

        :param addr: the register address
        :return: The read value of addressed register (4 bytes)
        :raises SPSDKDebugProbeMemoryInterfaceAPNotFoundError: The device doesn't content memory interface
        :raises SPSDKDebugProbeTransferError: Memory read operation failed.
        """
        if self.mem_ap is None:
            raise SPSDKDebugProbeMemoryInterfaceAPNotFoundError

        reg = 0
        try:
            reg = self.mem_ap.read32(addr=addr)
        except PyOCDError as exc:
            raise SPSDKDebugProbeTransferError(f"Failed read memory({str(exc)}).") from exc
        return reg

    def mem_reg_write(self, addr: int = 0, data: int = 0) -> None:
        """Write 32-bit register in memory space of MCU.

        This is write 32-bit register in memory space of MCU function for SPSDK library
        to support various DEBUG PROBES.

        :param addr: the register address
        :param data: the data to be written into register
        :raises SPSDKDebugProbeMemoryInterfaceAPNotFoundError: The device doesn't content memory interface
        :raises SPSDKDebugProbeTransferError: Memory write operation failed.
        """
        if self.mem_ap is None:
            raise SPSDKDebugProbeMemoryInterfaceAPNotFoundError

        try:
            self.mem_ap.write32(addr=addr, value=data)
        except PyOCDError as exc:
            raise SPSDKDebugProbeTransferError(f"Failed write memory({str(exc)}).") from exc

    def dbgmlbx_reg_read(self, addr: int = 0) -> int:
        """Read debug mailbox access port register.

        This is read debug mailbox register function for SPSDK library to support various DEBUG PROBES.

        :param addr: the register address
        :return: The read value of addressed register (4 bytes)
        :raises SPSDKDebugMailBoxAPNotFoundError: The dbgmlbx_reg_read is NOT implemented
        :raises SPSDKDebugProbeTransferError: The dbgmlbx_reg_read ends with data transfer error
        """
        if self.dbgmlbx_ap is None:
            raise SPSDKDebugMailBoxAPNotFoundError("No debug mail box access point available!")
        try:
            return self.dbgmlbx_ap.read_reg(self.APADDR & addr)
        except PyOCDError as exc:
            raise SPSDKDebugProbeTransferError("The Coresight read operation failed") from exc

    def dbgmlbx_reg_write(self, addr: int = 0, data: int = 0) -> None:
        """Write debug mailbox access port register.

        This is write debug mailbox register function for SPSDK library to support various DEBUG PROBES.

        :param addr: the register address
        :param data: the data to be written into register
        :raises SPSDKDebugMailBoxAPNotFoundError: The dbgmlbx_reg_write is NOT implemented
        :raises SPSDKDebugProbeTransferError: The dbgmlbx_reg_write ends with data transfer error
        """
        if self.dbgmlbx_ap is None:
            raise SPSDKDebugMailBoxAPNotFoundError("No debug mail box access point available!")
        try:
            self.dbgmlbx_ap.write_reg(addr=self.APADDR & addr, data=data)
        except PyOCDError as exc:
            raise SPSDKDebugProbeTransferError("The Coresight write operation failed") from exc

    def reset(self) -> None:
        """Reset a target.

        It resets a target.

        :raises SPSDKDebugProbeNotOpenError: The PyOCD debug probe is not opened yet
        """
        if self.pyocd_session is None:
            raise SPSDKDebugProbeNotOpenError("The PyOCD debug probe is not opened yet")
        self.pyocd_session.target.reset()

    def _get_ap_by_ix(self, index: int) -> Any:
        """Function returns the AP PyoCD object by index if exists.

        :param index: Index of requested access port class.
        :return: Access port class, by its IX
        :raises SPSDKDebugProbeNotOpenError: The PyOCD probe is NOT opened
        SPSDK:raises SPSDKDebugProbeError: There is not active access port for specified index.
        """
        if self.pyocd_session is None:
            raise SPSDKDebugProbeNotOpenError("The PyOCD debug probe is not opened yet")
        for access_port in self.pyocd_session.target.aps.values():
            if access_port.address.apsel == index:
                return access_port

        raise SPSDKDebugProbeError(f"The access port {index} is not present.")

    def _get_ap_by_addr(self, addr: int) -> Any:
        """Function returns the AP PyoCD object by address if exists.

        :param addr: The access port address.
        :return: The Access port object.
        :raises SPSDKDebugProbeNotOpenError: The PyOCD probe is NOT opened
        """
        if self.pyocd_session is None:
            raise SPSDKDebugProbeNotOpenError("The PyOCD debug probe is not opened yet")
        ap_sel = (addr & self.APSEL) >> self.APSEL_SHIFT

        return self._get_ap_by_ix(ap_sel)

    def coresight_reg_read(self, access_port: bool = True, addr: int = 0) -> int:
        """Read coresight register over PyOCD interface.

        The PyOCD read coresight register function for SPSDK library to support various DEBUG PROBES.

        :param access_port: if True, the Access Port (AP) register will be read(default), otherwise the Debug Port
        :param addr: the register address
        :return: The read value of addressed register (4 bytes)
        :raises SPSDKDebugProbeTransferError: The IO operation failed
        :raises SPSDKDebugProbeNotOpenError: The PyOCD probe is NOT opened
        """
        if self.pyocd_session is None:
            raise SPSDKDebugProbeNotOpenError("The PyOCD debug probe is not opened yet")
        try:
            if access_port:
                access_p = self._get_ap_by_addr(addr)
                return access_p.read_reg(self.APADDR & addr)

            return self.pyocd_session.target.dp.read_dp(addr)
        except PyOCDError as exc:
            raise SPSDKDebugProbeTransferError("The Coresight read operation failed") from exc

    def coresight_reg_write(self, access_port: bool = True, addr: int = 0, data: int = 0) -> None:
        """Write coresight register over PyOCD interface.

        The PyOCD write coresight register function for SPSDK library to support various DEBUG PROBES.

        :param access_port: if True, the Access Port (AP) register will be write(default), otherwise the Debug Port
        :param addr: the register address
        :param data: the data to be written into register
        :raises SPSDKDebugProbeTransferError: The IO operation failed
        :raises SPSDKDebugProbeNotOpenError: The PyOCD probe is NOT opened
        """
        if self.pyocd_session is None:
            raise SPSDKDebugProbeNotOpenError("The PyOCD debug probe is not opened yet")
        try:
            if access_port:
                access_p = self._get_ap_by_addr(addr)
                access_p.write_reg(self.APADDR & addr, data)
            else:
                self.pyocd_session.target.dp.write_dp(addr, data)
        except PyOCDError as exc:
            raise SPSDKDebugProbeTransferError("The Coresight write operation failed") from exc

    def _get_dmbox_ap(self) -> Any:
        """Search for Debug Mailbox Access Point.

        This is helper function to find and return the debug mailbox access port.

        :return: Debug MailBox Access Port
        :raises SPSDKDebugProbeNotOpenError: The PyOCD probe is NOT opened
        """
        idr_expected = 0x002A0000

        if self.pyocd_session is None:
            raise SPSDKDebugProbeNotOpenError("The PyOCD debug probe is not opened yet")

        for access_port in self.pyocd_session.target.aps.values():
            if self.dbgmlbx_ap_ix >= 0:
                if access_port.address.apsel == self.dbgmlbx_ap_ix:
                    return access_port
            else:
                if access_port.idr == idr_expected:
                    logger.debug(f"Found debug mailbox {access_port.short_description}")
                    self.dbgmlbx_ap_ix = access_port.address.apsel
                    return access_port

        return None

    def _get_mem_ap(self) -> Any:
        """Search for Memory Interface Access Point.

        This is helper function to find and return the memory interface access port.

        :return: Memory Interface Access Port
        :raises SPSDKDebugProbeNotOpenError: The PyOCD probe is NOT opened
        """
        if self.pyocd_session is None:
            raise SPSDKDebugProbeNotOpenError("The PyOCD debug probe is not opened yet")

        for access_port in self.pyocd_session.target.aps.values():
            if self.mem_ap_ix >= 0:
                if access_port.address.apsel == self.mem_ap_ix:
                    return access_port
            else:
                if isinstance(access_port, MEM_AP):
                    logger.debug(
                        f"Found Memory interface access port {access_port.short_description}"
                    )
                    self.mem_ap_ix = access_port.address.apsel
                    return access_port

        return None

    # pylint: disable=unused-argument
    def will_init_target(self, target: Any, init_sequence: "CallSequence") -> None:
        """Initialize target.

        Modification of initialization sequence to allow do debug authentication operations.
        """
        # modify the (coresight_target.py) mutable call sequence
        init_sequence.remove_task("load_svd")
        init_sequence.replace_task("dp_init", self.dp_init_sequence)
        init_sequence.replace_task("create_discoverer", self._create_discoverer)
        init_sequence.remove_task("check_for_cores")
        init_sequence.remove_task("create_flash")

    # pylint: disable=protected-access
    def _create_discoverer(self) -> None:
        """Init task to create the discovery object.

        Instantiates the appropriate @ref pyocd.coresight.discovery.CoreSightDiscovery
        CoreSightDiscovery subclass for the target's ADI version.
        """
        if self.pyocd_session:
            target = self.pyocd_session.target
            target._discoverer = self.DMBOX_ADI_DISCOVERY_CLASS_MAP[target.dp.adi_version](target)

    # pylint: disable=protected-access
    def dp_init_sequence(self) -> CallSequence:
        """Debug Port init sequence modification function.

        This function allows miss the Connect action for J-LINK probes, because the J-Link DLL
        do some additional unwanted actions that are not welcomed by DAT.

        :return: Debug Port initialization call sequence
        :raises SPSDKDebugProbeNotOpenError: The PyOCD probe is NOT opened
        """
        if self.pyocd_session is None:
            raise SPSDKDebugProbeNotOpenError("The PyOCD debug probe is not opened yet")

        debug_probe = self.pyocd_session.target.dp
        probe = debug_probe.probe

        if isinstance(probe, JLinkProbe):
            return CallSequence(
                ("get_probe_capabilities", debug_probe._get_probe_capabilities),
                ("connect", self._connect_jlink),
                ("clear_sticky_err", debug_probe.clear_sticky_err),
                ("power_up_debug", debug_probe.power_up_debug),
                ("check_version", debug_probe._check_version),
            )

        return CallSequence(
            ("get_probe_capabilities", debug_probe._get_probe_capabilities),
            ("connect", debug_probe._connect),
            ("clear_sticky_err", debug_probe.clear_sticky_err),
            ("power_up_debug", debug_probe.power_up_debug),
            ("check_version", debug_probe._check_version),
        )

    # pylint: disable=protected-access
    def _connect_jlink(self) -> None:
        """Custom J-Link connect function.

        :raises SPSDKError: Unsupported communication protocol.
        :raises SPSDKDebugProbeNotOpenError: The PyOCD probe is NOT opened
        :raises SPSDKDebugProbeError: General error with probe.
        """
        if self.pyocd_session is None:
            raise SPSDKDebugProbeNotOpenError("The PyOCD debug probe is not opened yet")

        # Attempt to connect.
        debug_probe = self.pyocd_session.target.dp
        probe = debug_probe.probe
        protocol = debug_probe._protocol

        # Connect to the target via JTAG or SWD.

        # Handle default protocol.
        if (protocol is None) or (protocol == pyocd.probe.debug_probe.DebugProbe.Protocol.DEFAULT):
            protocol = probe._default_protocol

        # Validate selected protocol.
        if protocol not in probe._supported_protocols:
            raise SPSDKError(f"unsupported wire protocol {protocol}")

        # Convert protocol to port enum.
        if protocol == PyOCDDebugProbe.Protocol.SWD:
            interface = pylink.enums.JLinkInterfaces.SWD
        elif protocol == PyOCDDebugProbe.Protocol.JTAG:
            interface = pylink.enums.JLinkInterfaces.JTAG

        try:
            probe._link.set_tif(interface)
            if probe.session.options.get("jlink.power"):
                probe._link.power_on()
            # device_name = probe.session.options.get('jlink.device') or "Cortex-M4"
            # probe._link.connect(device_name, speed=200)
            probe._link.coresight_configure()
            probe._protocol = protocol
        except JLinkException as exc:
            raise SPSDKDebugProbeError(probe._convert_exception(exc)) from exc

        def __read_idr(probe) -> int:
            """Read IDR register and get DP version."""
            dpidr = probe.read_dp(dap.DP_IDR, now=True)
            dp_partno = (dpidr & dap.DPIDR_PARTNO_MASK) >> dap.DPIDR_PARTNO_SHIFT
            dp_version = (dpidr & dap.DPIDR_VERSION_MASK) >> dap.DPIDR_VERSION_SHIFT
            dp_revision = (dpidr & dap.DPIDR_REVISION_MASK) >> dap.DPIDR_REVISION_SHIFT
            is_mindp = (dpidr & dap.DPIDR_MIN_MASK) != 0
            return dap.DPIDR(dpidr, dp_partno, dp_version, dp_revision, is_mindp)

        # Report on DP version.
        debug_probe.dpidr = probe.dpidr = __read_idr(probe)
        mindp = " MINDP" if probe.dpidr.mindp else ""
        logger.info(
            f"DP IDR = 0x{probe.dpidr.idr:08X} (v{probe.dpidr.version}{mindp} rev{probe.dpidr.revision})"
        )

    class DMBoxADIv5Discovery(ADIv5Discovery):
        """Custom discoverer class based of ADIv5Discovery."""

        def discover(self) -> CallSequence:
            """Setup list of calls to perform the components discovery."""
            return CallSequence(
                ("find_aps", self._find_aps),
                ("create_aps", self._create_aps),
                ("find_components", self._find_components),
                ("create_cores", self._create_cores),
            )

        def _find_components(self) -> None:
            return None

        def _create_cores(self) -> None:
            return None

    class DMBoxADIv6Discovery(ADIv6Discovery):
        """Custom discoverer class based of ADIv6Discovery."""

        # def __init__(self, target: Any) -> None:
        #     """! @brief Constructor."""
        #     super().__init__(target)

        def discover(self) -> CallSequence:
            """Setup list of calls to perform the components discovery."""
            return CallSequence(
                ("find_root_components", self._find_root_components),
            )

    ## Map from ADI version to the discovery class.
    DMBOX_ADI_DISCOVERY_CLASS_MAP = {
        ADIVersion.ADIv5: DMBoxADIv5Discovery,
        ADIVersion.ADIv6: DMBoxADIv6Discovery,
    }
