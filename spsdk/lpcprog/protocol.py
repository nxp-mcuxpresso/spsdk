#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""ISP Communication protocol for LPC devices."""

import inspect
import logging
import time
from typing import Callable, Optional

from spsdk.crypto.crc import CrcAlg, from_crc_algorithm
from spsdk.exceptions import SPSDKAlignmentError, SPSDKError, SPSDKValueError
from spsdk.lpcprog.device import LPCDevice
from spsdk.lpcprog.error_codes import StatusCode
from spsdk.lpcprog.interface import LPCProgInterface
from spsdk.utils.database import DatabaseManager, get_db, get_families
from spsdk.utils.misc import align_block, value_to_int, write_file
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)


class LPCProgCRPLevels(SpsdkEnum):
    """LPC CRP Levels.

    Code Read Protection is a mechanism that allows the user to enable different levels of
    security in the system so that access to the on-chip flash and use of the ISP can be
    restricted. When needed, CRP is invoked by programming a specific pattern in the flash
    image at offset 0x0000 02FC. IAP commands are not affected by the code read
    protection.
    """

    NO_ISP = (
        0x536A_AC95,
        "NO_ISP",
        "Access to the chip via the SWD pins is enabled, ISP pins disabled",
    )
    NO_CRP = (0xFFFFFFFF, "NO_CRP", "All USART ISP commands are supported.")
    CRP1 = (
        0x5963_A69C,
        "CRP1",
        "SWD Disabled, ISP commands restricted. Cannot write sector 0 and read memory.",
    )
    CRP2 = (0x9635_69CA, "CRP2", "SWD Disabled, ISP only allows erase of all sectors")
    CRP3 = (0x6359_9CA6, "CRP3", "SWD Disabled, ISP disabled.")


class LPCProgProtocol:
    """LPCProg protocol."""

    UNLOCK_CODE = 23130
    SECTOR_SIZE = 1024
    PAGE_SIZE = 64
    CRP_OFFSET = 0x2FC
    CRP_LENGTH = 4
    CRC_VECT_TABLE_OFFSET = 0x1C
    VECT_TABLE_SIZE = 32

    ALLOWED_BAUD_RATES = [9600, 19200, 38400, 57600, 115200, 230400, 460800]
    # this is just for click - Click.choice must be str
    ALLOWED_BAUD_RATES_STR = [str(i) for i in ALLOWED_BAUD_RATES]

    def __init__(
        self,
        interface: LPCProgInterface,
        print_func: Callable[[str], None],
        device: Optional[LPCDevice] = None,
    ) -> None:
        """Initialize the LPCProgProtocol."""
        self.interface = interface
        self.print_func = print_func
        self.synced = False
        self.device = device

        # Open the interface
        self.interface.open()

        self.latest_status: Optional[StatusCode] = StatusCode.SUCCESS

    def __del__(self) -> None:
        """Destructor to ensure the interface is closed properly."""
        self.close()

    def close(self) -> None:
        """Close the interface."""
        if self.interface:
            self.interface.close()

    @staticmethod
    def get_supported_families() -> list[str]:
        """Get the list of supported families by LPCProg.

        :return: List of supported families.
        """
        return get_families(DatabaseManager.LPCPROG)

    def get_device(self) -> LPCDevice:
        """Get LPCDevice if defined or read it from part ID.

        :return: LPCDevice
        """
        # if device is defined return it
        if self.device:
            return self.device

        # otherwise decoded it from part ID
        self.decode_part_id(self.read_part_id())

        # if still not found raise and exception
        if not self.device:
            raise SPSDKError(
                "LPC Device cannot be decoded, you have to specify it using the --family"
            )

        return self.device

    def print_status(self, status: Optional[StatusCode]) -> None:
        """Print status from the status code.

        :param status: StatusCode
        """
        if status:
            if status.tag == 0:
                self.print_func(f"\nStatus: {status.label}")
            else:
                self.print_func(
                    f"\nStatus: {status.label}\nDescription: {StatusCode.get_description(status.tag)}"
                )

    def get_latest_status(self) -> str:
        """Get latest status."""
        if self.latest_status and self.latest_status.tag == 0:
            return f"\nStatus: {self.latest_status.label}"
        elif self.latest_status:
            return f"\nStatus: {self.latest_status.label}\nDescription: {StatusCode.get_description(self.latest_status.tag)}"
        return "No status"

    def return_status(self, status: Optional[StatusCode]) -> bool:
        """Return True if status is SUCCESS. Otherwise False."""
        if status:
            return status == StatusCode.SUCCESS
        return False

    def assert_rc(self, status: bool) -> None:
        """Assert status."""
        if not status:
            raise SPSDKError(f"Command failed with status: {self.latest_status}")

    def send_command(
        self, command: str, print_status: bool = False, expect_rc: bool = True
    ) -> Optional[StatusCode]:
        """Send command.

        :param command: command to send
        :param print_status: print status
        :param expect_rc: expect return code
        :return: status code
        """
        logger.debug(f"->SEND COMMAND: {command}")
        rc = self.interface.send_command(command, expect_rc)
        if rc is not None:
            status = StatusCode.from_tag(rc)
            self.latest_status = status
            logger.info((f"CMD: {inspect.stack()[1].function}, STATUS: {status.label}"))
            if print_status:
                self.print_status(status)
            return status
        self.latest_status = None
        return None

    def sync_connection(self, frequency: int, retries: int = 10) -> bool:
        """Synchronize connection.

        :param frequency: frequency of the crystal
        :param retries: number of retries
        :return: True if synchronized

        1. Send ? to get baud rate
        2. Receive "Synchronized" message
        3. Send "Synchronized" message
        4. Receive "OK" message
        """
        self.interface.sync_connection(frequency, retries)
        try:
            # Clear serial after synchronization
            time.sleep(0.5)
            # Wait for 500 ms to get all responses from sync
            self.interface.read_all()
            self.interface.clear_serial()
        except Exception:
            pass
        self.print_func("Synchronized")
        return True

    def unlock(self, print_status: bool = True) -> bool:
        """This command is used to unlock Flash Write, Erase, and Go commands.

        :param print_status: print status
        :return: True if unlocked
        """
        return self.return_status(self.send_command(f"U {self.UNLOCK_CODE}", print_status))

    def set_baud_rate(self, baud_rate: int, stop_bits: int = 1, print_status: bool = True) -> bool:
        """This command is used to change the baud rate.

        :param baud_rate: new baud rate
        :param stop_bits: number of stop bits
        :param print_status: print status

        The new baud rate is effective after the command
        handler sends the CMD_SUCCESS return code.
        """
        if baud_rate not in self.ALLOWED_BAUD_RATES:
            raise SPSDKValueError(f"Invalid baud rate: {baud_rate}")
        status = self.send_command(f"B {baud_rate} {stop_bits}", print_status)
        self.interface.device._device.baudrate = baud_rate
        return self.return_status(status)

    def set_echo(self, echo: bool, print_status: bool = True) -> bool:
        """The default setting for echo command is ON.

        :param echo: echo
        :param print_status: print status
        :return: True if echo is set

        When ON the ISP command handler sends the
        received serial data back to the host.
        """
        status = self.send_command(f"E {int(echo)}", print_status)
        self.interface.echo = echo
        return self.return_status(status)

    def write_ram(self, address: int, data: bytes) -> bool:
        """This command is used to download data to RAM.

        :param address: address in RAM
        :param data: data to write

        This command is blocked when code read protection levels 2 or 3 are enabled.
        Writing to addresses below 0x1000 0600 is disabled for CRP1.

        The host should send the plain binary code after receiving the CMD_SUCCESS return code.
        This ISP command handler responds with “OK<CR><LF>” when the transfer has finished.
        """
        if len(data) % 4 != 0:
            raise SPSDKAlignmentError("Data must be aligned to four bytes boundary")
        rc = self.send_command(f"W {address} {len(data)}")
        if rc == StatusCode.SUCCESS:
            self.interface.write(data)
            time.sleep(0.1)
            self.interface.read_all()
            self.interface.clear_serial()
        else:
            assert isinstance(rc, StatusCode), "Invalid status code"
            raise SPSDKError(f"Cannot write to RAM, error: {rc.label} ")
        return rc == StatusCode.SUCCESS

    def read_memory(
        self,
        address: int,
        length: int,
        binary: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> bytes:
        """This command is used to read data from RAM or flash memory.

        :param address: address in RAM or flash
        :param length: length of data to read
        :param binary: binary file to write the data
        :param progress_callback: progress callback
        :return: read data

        This command is blocked when code read protection is enabled.
        """
        read_data = b""
        total_length = length

        # check boundaries in case device is provided
        if self.device:
            if not self.device.is_valid_address(address, length):
                logger.error("Address is not valid for the provided LPC device!")

        while length > 0:
            chunk_length = min(length, self.SECTOR_SIZE)
            rc = self.send_command(f"R {address} {chunk_length}")
            if rc != StatusCode.SUCCESS:
                self.print_status(rc)
                return b""
            chunk_data = self.interface._read(chunk_length)
            read_data += chunk_data
            length -= chunk_length
            address += chunk_length
            if progress_callback:
                progress_callback(len(read_data), total_length)
        if binary:
            write_file(read_data, binary, mode="wb")
        return read_data

    def prepare_sectors_for_write(
        self, start_sector: int, end_sector: int, print_status: bool = True
    ) -> bool:
        """Prepare sectors for write.

        :param start_sector: start sector
        :param end_sector: end sector
        :param print_status: print status
        :return: True if prepared

        This command must be executed before executing
        "Copy RAM to flash" or "Erase Sector(s)", or “Erase Pages” command.

        Successful execution of the "Copy RAM to flash" or "Erase Sector(s)" or “Erase Pages”
        command causes relevant sectors to be protected again.
        To prepare a single sector use the same "Start" and "End" sector numbers.
        """
        return self.return_status(self.send_command(f"P {start_sector} {end_sector}", print_status))

    def copy_ram_to_flash(
        self, flash_address: int, ram_address: int, length: int, print_status: bool = True
    ) -> bool:
        """This command is used to program the flash memory.

        :param flash_address: address in flash
        :param ram_address: address in RAM
        :param length: length of data to copy
        :param print_status: print status
        :return: True if copied

        The "Prepare Sector(s) for Write Operation" command should precede this command.
        The affected sectors are automatically protected again once the copy
        command is successfully executed. This command is blocked when
        code read protection is enabled.
        """
        return self.return_status(
            self.send_command(f"C {flash_address} {ram_address} {length}", print_status)
        )

    def go(self, address: int, thumb_mode: bool = False) -> None:
        """This command is used to execute a program residing in RAM or flash memory.

        :param address: address in RAM or flash
        :param thumb_mode: thumb mode

        It may not be possible to return to the ISP
        command handler once this command is successfully executed.
        This command is blocked when code read protection is enabled.
        """
        mode = " T" if thumb_mode else ""
        self.send_command(f"G {address}{mode}")

    def erase_sector(self, start_sector: int, end_sector: int, print_status: bool = True) -> bool:
        """This command is used to erase one or more sector(s) of on-chip flash memory.

        :param start_sector: start sector
        :param end_sector: end sector
        :param print_status: print status
        :return: True if erased

        This command only allows
        erasure of all user sectors when the code read protection is enabled.
        """
        return self.return_status(self.send_command(f"E {start_sector} {end_sector}", print_status))

    def erase_page(self, start_page: int, end_page: int, print_status: bool = True) -> bool:
        """This command is used to erase one or more page(s) of on-chip flash memory.

        :param start_page: start page
        :param end_page: end page
        :param print_status: print status
        :return: True if erased
        """
        return self.return_status(self.send_command(f"X {start_page} {end_page}", print_status))

    def blank_check_sectors(
        self, start_sector: int, end_sector: int, print_status: bool = True
    ) -> bool:
        """This command is used to blank check one or more sectors of on-chip flash memory.

        :param start_sector: start sector
        :param end_sector: end sector
        :param print_status: print status
        :return: True if blank
        """
        rc = self.send_command(f"I {start_sector} {end_sector}", print_status)
        if rc == StatusCode.SUCCESS:
            self.print_func("Sectors are blank")
            return True
        elif rc == StatusCode.SECTOR_NOT_BLANK:
            self.print_func("Sectors are not blank")
            first_word = self.interface.read_line()
            self.print_func(f"Offset of the first non blank word {first_word}")
            content = self.interface.read_line()
            self.print_func(f"Content of the first non blank word {hex(int(content))}")

        return False

    def read_part_id(self) -> str:
        """This command is used to read the part identification number."""
        self.send_command("J")
        return self.interface.read_line()

    def read_boot_code_version(self) -> str:
        """Read boot code version."""
        self.send_command("K")
        minor = self.interface.read_line().strip()
        major = self.interface.read_line().strip()
        return f"{major}.{minor}"

    def compare(
        self, dst_address: int, src_address: int, length: int, print_status: bool = True
    ) -> bool:
        """This command is used to compare the memory contents at two locations.

        :param dst_address: destination address
        :param src_address: source address
        :param length: length of data to compare
        :param print_status: print status
        :return: True if content is same
        """
        if length % 4 != 0:
            raise SPSDKAlignmentError("Byte count must be multiple of 4")
        rc = self.send_command(f"M {dst_address} {src_address} {length}", print_status)
        if rc == StatusCode.SUCCESS:
            self.print_func("Content is same")
            return True
        elif rc == StatusCode.COMPARE_ERROR:
            self.print_func("Content differs")
            diff = self.interface.read_line()
            self.print_func(f"Offset of first difference {diff}")
        return False

    def read_uid(self) -> str:
        """This command is used to read the unique ID."""
        self.send_command("N")
        uuids = [self.interface.read_line() for _ in range(4)]
        return " ".join([f"0x{int(uid):08x}" for uid in uuids])

    def read_crc_checksum(self, address: int, length: int) -> Optional[int]:
        """This command is used to read the CRC checksum of a block of RAM or flash memory.

        :param address: address in RAM or flash
        :param length: length of data
        :return: CRC checksum

        This command is blocked when code read protection is enabled.
        """
        rc = self.send_command(f"S {address} {length}")
        if rc == StatusCode.SUCCESS:
            return int(self.interface.read_line())
        return None

    def read_flash_signature(
        self, start_address: int, end_address: int, wait_states: int = 2, mode: int = 0
    ) -> int:
        """This command is used to read the flash signature generated by the flash controller.

        :param start_address: start address
        :param end_address: end address
        :param wait_states: wait states
        :param mode: mode
        :return: flash signature
        """
        rc = self.send_command(f"Z {start_address} {end_address} {wait_states} {mode}")
        if rc == StatusCode.SUCCESS:
            return int(self.interface.read_line())
            # return [self.interface.read_line() for _ in range(4)]

        raise SPSDKError("Cannot read flash signature")

    def decode_part_id(self, part_id: str) -> Optional[str]:
        """Return decoded part ID from the database."""
        part_id = hex(value_to_int(part_id))[-4:].strip()
        devices = get_families(DatabaseManager.LPCPROG)
        for device in devices:
            part_ids = get_db(device).get_dict(DatabaseManager.LPCPROG, "part_ids")
            decoded_part_id = part_ids.get(part_id)
            if decoded_part_id:
                self.device = LPCDevice(device)
                return decoded_part_id
        logger.error(f"Cannot decode part ID: {part_id}")
        return None

    def get_crp_level(self) -> LPCProgCRPLevels:
        """Read CRP level from offset 0x2FC and decode it.

        :return: CRP level
        """
        try:
            crp = value_to_int(self.read_memory(self.CRP_OFFSET, self.CRP_LENGTH))
            return LPCProgCRPLevels.from_tag(crp)
        except (SPSDKError, KeyError):
            return LPCProgCRPLevels.CRP2

    def get_info(self) -> str:
        """Returns info about the device.

        1. Part ID
        2. UID
        3. Boot code version
        4. CRP level

        :return: string containing description
        """
        uid = self.read_uid()
        boot_code_version = self.read_boot_code_version()
        part_id = self.decode_part_id(self.read_part_id())
        crp_level = self.get_crp_level()

        msg = f"Part ID: {part_id}\nUID: {uid}\nBoot code version: {boot_code_version}"
        msg += f"\nCRP Level: {crp_level.label}\n{crp_level.description}"

        return msg

    @staticmethod
    def calc_crc(data: bytes) -> int:
        """Calculate CRC from the data.

        :param data: data to calculate CRC from
        :return: calculated CRC
        """
        crc_ob = from_crc_algorithm(CrcAlg.CRC32)
        return crc_ob.calculate(data)

    def program_flash_sector(
        self, data: bytes, sector: int, verify: bool = False, erase: bool = True
    ) -> bool:
        """This command is used for programming the flash sector.

        :param data: data to be written
        :param sector: sector to write
        :param verify: verify the written data
        :param erase: erase the sector before writing

        Approach for writing the sector
        1) Write data to RAM
        2) Prepare sector for writing
        3) Erase sector
        4) Again prepare sector
        5) Copy RAM to flash
        """
        ram_address = self.get_device().buffer_address
        flash_start = self.get_device().flash_address
        sector_size = self.get_device().sector_size
        page_size = self.get_device().page_size
        flash_address = flash_start + sector * sector_size

        if len(data) > sector_size:
            raise SPSDKAlignmentError("Data size is larger than sector size")

        logger.info(f"Writing flash sector: {sector} Address: {hex(flash_address)}")

        # Align data to page size, minimal size that could be copied from RAM to flash
        data = align_block(data, page_size)
        # Calculate CRC of data
        initial_crc = self.calc_crc(data)
        # Write data to RAM by page size
        self.assert_rc(self.write_ram(ram_address, data))
        # Optionally verify the written data
        if verify:
            read_data = self.read_memory(ram_address, len(data))
            if data != read_data:
                raise SPSDKError("Written data are not same")
        if erase:
            # Prepare sector for erase
            logger.info(f"Preparing sector {sector} for erase")
            self.assert_rc(self.prepare_sectors_for_write(sector, sector, print_status=False))
            # Erase sector
            logger.info(f"Erasing sector {sector}")
            self.assert_rc(self.erase_sector(sector, sector, print_status=False))
        # Prepare sector for write
        logger.info(f"Preparing sector {sector} for write")
        self.assert_rc(self.prepare_sectors_for_write(sector, sector, print_status=False))
        # Copy RAM to flash
        logger.info(
            f"Copying {len(data)}B RAM {hex(ram_address)} to flash address {hex(flash_address)}"
        )
        self.assert_rc(
            self.copy_ram_to_flash(flash_address, ram_address, len(data), print_status=False)
        )
        # Read CRC
        logger.info("Calculating checksum")
        final_crc = self.read_crc_checksum(flash_address, len(data))

        if initial_crc != final_crc:
            raise SPSDKError(f"CRC checksum does not match {initial_crc}!={final_crc}")

        return self.return_status(self.latest_status)

    def program_flash_page(
        self, data: bytes, page_index: int, verify: bool = False, erase: bool = True
    ) -> bool:
        """This command is used for programming a single flash page.

        :param data: data to be written
        :param page_index: index of the page to write
        :param verify: verify the written data
        :param erase: erase the page before writing

        Approach for writing a single page:
        1) Write data to RAM
        2) Prepare sector for writing
        3) Erase page (if required)
        4) Again prepare sector
        5) Copy RAM to flash
        """
        ram_address = self.get_device().buffer_address
        flash_start = self.get_device().flash_address
        sector_size = self.get_device().sector_size
        page_size = self.get_device().page_size
        flash_address = flash_start + page_index * page_size

        if len(data) > page_size:
            raise SPSDKAlignmentError("Data size is larger than page size")

        logger.info(f"Writing flash page: {page_index} Address: {hex(flash_address)}")

        # Align data to page size, minimal size that could be copied from RAM to flash
        data = align_block(data, page_size)
        # Calculate CRC of data
        initial_crc = self.calc_crc(data)
        # Write data to RAM by page size
        self.assert_rc(self.write_ram(ram_address, data))
        # Optionally verify the written data
        if verify:
            read_data = self.read_memory(ram_address, len(data))
            if data != read_data:
                raise SPSDKError("Written data are not same")
        if erase:
            sector = (flash_address - flash_start) // sector_size
            # Prepare sector for erase
            logger.info(f"Preparing sector {sector} for erase")
            self.assert_rc(self.prepare_sectors_for_write(sector, sector, print_status=False))
            # Erase page
            logger.info(f"Erasing page {page_index}")
            self.assert_rc(self.erase_page(page_index, page_index, print_status=False))
        # Prepare sector for write
        sector = (flash_address - flash_start) // sector_size
        logger.info(f"Preparing sector {sector} for write")
        self.assert_rc(self.prepare_sectors_for_write(sector, sector, print_status=False))
        # Copy RAM to flash
        logger.info(
            f"Copying {len(data)}B RAM {hex(ram_address)} to flash address {hex(flash_address)}"
        )
        self.assert_rc(
            self.copy_ram_to_flash(flash_address, ram_address, len(data), print_status=False)
        )
        # Read CRC
        logger.info("Calculating checksum")
        final_crc = self.read_crc_checksum(flash_address, len(data))

        if initial_crc != final_crc:
            raise SPSDKError(f"CRC checksum does not match {initial_crc}!={final_crc}")

        return self.return_status(self.latest_status)

    def calculate_sector_count(self, data: bytes) -> int:
        """Calculate number of sectors needed for writing the data."""
        return (len(data) + self.get_device().sector_size - 1) // self.get_device().sector_size

    def calculate_page_count(self, data: bytes) -> int:
        """Calculate number of pages needed for writing the data."""
        return (len(data) + self.get_device().page_size - 1) // self.get_device().page_size

    def program_flash(
        self,
        bin_data: bytes,
        start_sector: int = 0,
        start_page: Optional[int] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        print_status: bool = True,
        erase: bool = True,
        verify: bool = True,
    ) -> bool:
        """This command is used for programming the flash memory.

        :param bin_data: binary data to be written
        :param start_sector: start sector to write
        :param start_page: start page to write
        :param progress_callback: callback function for progress
        :param print_status: print status
        :param erase: erase the sector before writing
        :param verify: verify the written data

        1) Erase the first sector to make the image un-bootable and prevent bricking
        2) Optionally write the checksum to the image vector table
        3) Write the image in reverse order
        """
        sector_size = self.get_device().sector_size
        page_size = self.get_device().page_size
        sector_count = self.calculate_sector_count(bin_data)
        page_count = self.calculate_page_count(bin_data)

        if start_sector + sector_count > self.get_device().sector_count:
            raise SPSDKValueError("Sector count is larger than available sectors")

        if start_sector != 0 and start_page is not None:
            raise SPSDKValueError("Start sector and start page cannot be defined at the same time")

        # 1. Unlock the device for programming
        self.assert_rc(self.unlock(print_status=False))
        size_written = 0

        if start_sector == 0 and not start_page and erase:
            # Meaning we are writing the whole bootable image
            # Erase the first sector to make the image un-bootable and prevent bricking
            self.assert_rc(
                self.program_flash_sector(
                    bytes([0xFF] * sector_size), 0, verify=verify, erase=erase
                )
            )

        # If the start page is not defined, write the data by sectors
        if start_page is None:
            # 2. Write data to flash memory, in reverse order
            for sector in reversed(range(start_sector, start_sector + sector_count)):
                data = bin_data[
                    (sector - start_sector)
                    * sector_size : (sector - start_sector + 1)
                    * sector_size
                ]
                self.assert_rc(self.program_flash_sector(data, sector, verify=verify, erase=erase))
                size_written += len(data)
                if progress_callback:
                    progress_callback(size_written, len(bin_data))
        else:
            # 2. Write data to flash memory, in reverse order
            for page in reversed(range(start_page, start_page + page_count)):
                data = bin_data[
                    (page - start_page) * page_size : (page - start_page + 1) * page_size
                ]
                self.assert_rc(self.program_flash_page(data, page, verify=verify, erase=erase))
                size_written += len(data)
                if progress_callback:
                    progress_callback(size_written, len(bin_data))

        logger.info(f"Programming flash memory completed, written {size_written}B")

        if print_status:
            self.print_func(self.get_latest_status())

        return self.return_status(self.latest_status)
