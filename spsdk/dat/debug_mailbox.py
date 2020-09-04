#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for DebugMailbox."""
import logging
import sys

from time import sleep
from typing import Any, Tuple

import prettytable
import colorama

from munch import munchify
from pyocd.core.helpers import ConnectHelper
from pyocd.utility.sequencer import CallSequence
from pyocd.coresight.discovery import ADIVersion, ADIv5Discovery, ADIv6Discovery

from spsdk.debuggers import JLinkWrapper, RedLinkWrapper
from spsdk.debuggers import pemicroProbeWrapper, pemicroUnitAcmp

# logging.basicConfig(level=logging.DEBUG)
logging.getLogger('pyocd.board.board').setLevel(logging.CRITICAL)
logging.getLogger('pyocd.core.coresight_target').setLevel(logging.CRITICAL)
logging.getLogger('pyocd.probe.common').setLevel(logging.CRITICAL)

logger = logging.getLogger(__name__)


class DebugMailboxError(RuntimeError):
    """Class for DebugMailboxError."""
    pass


class DebugProbes(list):
    """Helper class for debug probe selection."""

    def append_pyocd_probes(self, probes: list) -> None:
        """Add PyOCD-based probes."""
        if probes != None:
            for probe in probes:
                self.append({"Interface":"PyOCD", "Id":probe.unique_id, "Description":probe.description})

    def append_pemicro_probes(self, probes: list) -> None:
        """Add P&E Micro-based probes."""
        if probes != None:
            for probe in probes:
                self.append({"Interface":"PEMICRO", "Id":probe["id"], "Description":probe["description"]})

    def select_probe(self, probes_list: list) -> Tuple[str, str]:
        """Perform Probe selection."""
        colorama.init()

        # Print all PyOCD probes and then Pemicro with local index
        table = prettytable.PrettyTable(["#", "Interface", "Id", "Description"])
        table.align = 'l'
        table.header = True
        table.border = True
        table.hrules = prettytable.HEADER
        table.vrules = prettytable.NONE
        i = 0
        i_selected = i
        if probes_list != None:
            for probe in probes_list:
                table.add_row([
                    colorama.Fore.YELLOW + str(i),
                    colorama.Fore.WHITE + probe["Interface"],
                    colorama.Fore.CYAN + probe["Id"],
                    colorama.Fore.GREEN + probe["Description"],
                    ])
                i += 1

        if i == 0:
            print("There is no any debug probe connected in system!")
            raise IOError("There is no any debug probe connected in system!")

        print(table)
        print(colorama.Style.RESET_ALL, end='')

        if i == 1:
            # Automatically gets and use only one option\
            i_selected = 0
        else:
            print("Please choose the debug probe: ", end='')
            i_selected = int(input())
            if i_selected > i-1:
                print("The choosen probe index is out of range")
                raise IOError("The choosen probe index is out of range")

        row = table[i_selected]
        row.border = False
        row.header = False
        debug_interface = row.get_string(fields=["Interface"]).strip().replace(colorama.Fore.WHITE, "").lower()
        hardware_id = row.get_string(fields=["Id"]).strip().replace(colorama.Fore.CYAN, "").lower()

        return debug_interface, hardware_id


class DebugMailbox:
    """Class for DebugMailbox."""
    def __init__(self, debug_interface: str, apnumber: int = 2,
                 reset: bool = True, moredelay: float = 1.0,
                 serial_no: int = None, ip_addr: str = None,
                 tool: str = None, hardware_id: str = None) -> None:
        """Initialize DebugMailbox object."""
        # setup debug port / access point
        # self.args = args
        self.debug_interface = debug_interface
        self.tool = tool
        self.serial_no = serial_no
        self.ip_addr = ip_addr
        self.hardware_id = hardware_id
        self.reset = reset
        self.moredelay = moredelay
        # setup registers and register bitfields
        self.registers = REGISTERS

        debug_probes = DebugProbes()

        # if self.debug_interface == None:
        #     # There is no selected debug interface - gather all possible connected Debug interfaces
        #     try:
        #         pyocdProbes = ConnectHelper.get_all_connected_probes(blocking=False)
        #     except:
        #         pyocdProbes = None
        #     try:
        #         pemicroProbes = pemicroUnitAcmp().listPorts()
        #     except:
        #         pemicroProbes = None    #type: ignore

        #     debug_probes.append_pyocd_probes(pyocdProbes)
        #     debug_probes.append_pemicro_probes(pemicroProbes)

        #     try:
        #         self.debug_interface, self.hardware_id = debug_probes.select_probe(debug_probes)
        #     except IOError as e:
        #         print("Cannot select the debug probe. Error:{err}".format(err=str(e)))
        #         sys.exit(-1)

        if self.debug_interface == 'pyocd':
            # ---------------------------------------------------------------
            # pyocd 0.27.0
            # ---------------------------------------------------------------
            if self.hardware_id == None:
                try:
                    pyocdProbes = ConnectHelper.get_all_connected_probes(blocking=False)
                    debug_probes.append_pyocd_probes(pyocdProbes)
                    self.debug_interface, self.hardware_id = debug_probes.select_probe(debug_probes)
                except IOError as e:
                    print("Cannot select the debug probe. Error:{err}".format(err=str(e)))
                    sys.exit(-1)

            self.session = ConnectHelper.session_with_chosen_probe(
                # blocking=False, return_first=False, unique_id=None,
                blocking=False, return_first=False, unique_id=self.hardware_id,
                did_show_no_libusb_warning=True, allow_no_cores=True
            )
            if self.session is None:
                raise ValueError("No probe available!")
            self.session.delegate = self
            self.session.options.set("probe_all_aps", True)
            self.session.open()
            self.board = self.session.board
            self.target = self.session.target
            logger.info("PyOCD connected via {0} probe.".format(self.session.probe.product_name))
            self.di = self.get_dmbox_ap(self.target.aps)
            if self.di is None:
                raise ValueError("No debug mail box access point available!")

            self.target.dp.init()
            self.target.dp.power_up_debug()
        elif self.debug_interface == 'redlink':
            self.di = RedLinkWrapper(apnumber, self.tool)
        elif self.debug_interface == 'jlink':
            self.di = JLinkWrapper(apnumber, self.serial_no, self.ip_addr)
        elif self.debug_interface == 'pemicro':
            if self.hardware_id is None:
                try:
                    pemicroProbes = pemicroUnitAcmp().listPorts()
                    debug_probes.append_pemicro_probes(pemicroProbes)
                    self.debug_interface, self.hardware_id = debug_probes.select_probe(debug_probes)
                except IOError as e:
                    print("Cannot select the debug probe. Error:{err}".format(err=str(e)))
                    sys.exit(-1)

            self.di = pemicroProbeWrapper(apnumber, self.hardware_id)
            if not self.di.connectedToDebugHardware:
                print('Error ... Unable to connect to PEMicro HW.')
                print('Specify with --pemicroid ID or list with --pemicroid listids')
                sys.exit(1)
            else:
                print('Connecting to debug hardware ... ok.')
            if not self.di.connectedToTarget:
                print('Error ... Unable to establish communications with target via SWD.')
                print('Check target power/connections.')
                self.close()
                sys.exit(1)
            else:
                print('Establishing communications to target via SWD ... ok.')
        else:
            raise ValueError("Bad interface specified!")

        # From now on, we can use self.di.read_reg(ADDR)
        # or self.di.write_reg(ADDR, VALUE) to read and
        # write to registers



        # Now, proceed with initiation (Resynchronisation request)

        # The communication to the DM is initiated by the debugger.
        # It does so by writing the RESYNCH_REQ bit of the CSW (Control and Status Word)
        # register to 1. It then needs to reset the chip so that ROM code can observe
        # this request.
        # In order to reset the chip, the debugger can either pull the
        # reset line of the chip, or set the CHIP_RESET_REQ (This can be done at the
        # same time as setting the RESYNCH_REQ bit).

        logger.debug(f"No reset mode: {self.reset!r}")
        if self.reset:
            self.di.write_reg(
                self.registers.CSW.address,
                self.registers.CSW.bits.RESYNCH_REQ |
                self.registers.CSW.bits.CHIP_RESET_REQ
            )

        # Acknowledgement of initiation

        # After performing the initiation, the debugger must readback the CSW register.
        # The DM will stall the debugger until the ROM code has serviced the resynchronization request.
        # The ROM does this by performing a soft reset of the DM block, thus resetting
        # the request bit/s which were set by the debugger.
        # Therefore, the debugger must read back 0x0 in CSW to know that the initiation
        # request has been serviced.

        if self.moredelay > 0.001:
            sleep(self.moredelay)
        if self.debug_interface == 'pyocd':
            ret = None
            retries = 20
            while ret is None:
                try:
                    ret = self.di.read_reg(self.registers.CSW.address)
                except Exception as e:
                    retries -= 1
                    if retries == 0:
                        retries = 20
                        raise IOError("TransferTimeoutError limit exceeded!")
                    # if isinstance(e, TransferTimeoutError):
                    sleep(0.05)

        else:
            while self.di.read_reg(self.registers.CSW.address, requiresDelay=True) != 0:
                sleep(0.01)


    def get_dmbox_ap(self, aps: Any) -> Any:
        """Search for Debug Mailbox Access Point."""
        for ap in aps.values():
            if ap.idr == self.registers.IDR.expected:
                logger.debug("Found debug mailbox %s" % ap.short_description)
                return ap

        return None

    def will_init_target(self, target: Any, init_sequence: 'CallSequence') -> None:
        """Initialize target."""
        # modify the (coresight_target.py) mutable call sequence
        init_sequence.remove_task('load_svd')
        init_sequence.remove_task('create_flash')
        init_sequence.replace_task('create_discoverer', self._create_discoverer)
        init_sequence.remove_task('check_for_cores')

    def _create_discoverer(self) -> None:
        """Init task to create the discovery object.

        Instantiates the appropriate @ref pyocd.coresight.discovery.CoreSightDiscovery
        CoreSightDiscovery subclass for the target's ADI version.
        """
        target = self.session.target
        target._discoverer = DMBOX_ADI_DISCOVERY_CLASS_MAP[target.dp.adi_version](target)

    def _override_ap_list(self) -> None:
        """Override ap list."""
        self.session.target.dp.valid_aps = [2]

    def close(self) -> None:
        """Close session."""
        if self.debug_interface == 'pyocd':
            self.session.close()
        else:
            self.di.close()

    def spin_read(self, reg: int, now: bool = True) -> int:
        """Read."""
        ret = None
        while ret is None:
            try:
                ret = self.di.read_reg(reg, now)
            except Exception as e:
                logger.error(str(e))
                logger.error(f"read exception  {reg:#08X}")
                sleep(0.01)
        return ret

    def spin_write(self, reg: int, value: int) -> None:
        """Write."""
        while True:
            try:
                self.di.write_reg(reg, value)
                # wait for rom code to read the data
                while True:
                    ret = self.di.read_reg(self.registers.CSW.address)
                    if (ret & self.registers.CSW.bits.REQ_PENDING) == 0:
                        break

                return
            except Exception as e:
                logger.error(str(e))
                logger.error(f"write exception addr={reg:#08X}, val={value:#08X}")
                sleep(0.01)


class dmboxADIv5Discovery(ADIv5Discovery):
    """Custom discoverer class based of ADIv5Discovery."""
    def __init__(self, target: Any) -> None:
        """! @brief Constructor."""
        super(dmboxADIv5Discovery, self).__init__(target)

    def discover(self) -> CallSequence:
        """Setup list of calls to perform the components discovery."""
        #pylint: disable=bad-whitespace
        return CallSequence(
            ('find_aps',            self._find_aps),
            ('create_aps',          self._create_aps),
            ('find_components',     self._find_components),
            ('create_cores',     	self._create_cores)
        )

    def _find_components(self) -> None:
        return None

    def _create_cores(self) -> None:
        return None


class dmboxADIv6Discovery(ADIv6Discovery):
    """Custom discoverer class based of ADIv6Discovery."""

    def __init__(self, target: Any) -> None:
        """! @brief Constructor."""
        super(dmboxADIv6Discovery, self).__init__(target)

    def discover(self) -> CallSequence:
        """Setup list of calls to perform the components discovery."""
        return CallSequence(
            ('find_root_components', self._find_root_components),
        )


## Map from ADI version to the discovery class.
DMBOX_ADI_DISCOVERY_CLASS_MAP = {
    ADIVersion.ADIv5: dmboxADIv5Discovery,
    ADIVersion.ADIv6: dmboxADIv6Discovery,
}


REGISTERS = munchify({
    # Control and Status Word (CSW) is used to control
    # the Debug Mailbox communication
    'CSW': {
        'address': 0x00,
        'bits': {

            # Debugger will set this bit to 1 to request a resynchronrisation
            'RESYNCH_REQ': (1 << 0),

            # Request is pending from debugger (i.e unread value in REQUEST)
            'REQ_PENDING': (1 << 1),

            # Debugger overrun error
            # (previous REQUEST overwritten before being picked up by ROM)
            'DBG_OR_ERR': (1 << 2),

            # AHB overrun Error (Return value overwritten by ROM)
            'AHB_OR_ERR': (1 << 3),

            # Soft Reset for DM (write-only from AHB,
            # not readable and self-clearing).
            # A write to this bit will cause a soft reset for DM.
            'SOFT_RESET': (1 << 4),

            # Write only bit. Once written will cause the chip to reset
            # (note that the DM is not reset by this reset as it is
            #   only resettable by a SOFT reset or a POR/BOD event)
            'CHIP_RESET_REQ': (1 << 5),
        }
    },

    # Request register is used to send data from debugger to device
    'REQUEST': {
        'address': 0x04,
    },

    # Return register is used to send data from device to debugger
    # Note: Any read from debugger side will be stalled until new data is present.
    'RETURN': {
        'address': 0x08,
    },

    # IDR register is used to identify the access port
    'IDR': {
        'address': 0xFC,
        'expected': 0x002A0000,
    }
})
