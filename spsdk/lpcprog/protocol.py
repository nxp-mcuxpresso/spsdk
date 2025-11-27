#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""ISP Communication protocol for LPC devices.

This module implements the In-System Programming (ISP) communication protocol
for NXP LPC microcontrollers, providing low-level protocol handling and
device interaction capabilities for secure provisioning operations.
"""

import inspect
import logging
import time
from typing import Callable, Optional

from spsdk.crypto.crc import CrcAlg, from_crc_algorithm
from spsdk.exceptions import SPSDKAlignmentError, SPSDKError, SPSDKValueError
from spsdk.lpcprog.device import LPCDevice
from spsdk.lpcprog.error_codes import StatusCode
from spsdk.lpcprog.interface import LPCProgInterface
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision, get_db, get_families
from spsdk.utils.misc import align_block, value_to_int, write_file
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)


class LPCProgCRPLevels(SpsdkEnum):
    """LPC Code Read Protection (CRP) levels enumeration.

    This enumeration defines the available Code Read Protection levels for LPC microcontrollers.
    CRP is a security mechanism that restricts access to on-chip flash and ISP functionality
    by programming specific patterns at flash offset 0x0000 02FC. Each level provides different
    restrictions on SWD access and ISP command availability, while IAP commands remain unaffected.
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
    """LPCProg communication protocol handler.

    This class implements the LPCProg protocol for communicating with NXP LPC
    microcontrollers, providing low-level operations for device programming,
    synchronization, and status management.

    :cvar UNLOCK_CODE: Magic unlock code for device operations.
    :cvar SECTOR_SIZE: Standard sector size in bytes.
    :cvar PAGE_SIZE: Standard page size in bytes.
    :cvar ALLOWED_BAUD_RATES: List of supported communication baud rates.
    """

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
        """Initialize the LPCProgProtocol.

        Sets up the protocol handler with the specified interface and configuration options.
        Opens the interface and initializes internal state tracking.

        :param interface: Communication interface for LPC programming operations.
        :param print_func: Function to handle output messages during operations.
        :param device: Optional LPC device specification for targeted operations.
        """
        self.interface = interface
        self.print_func = print_func
        self.synced = False
        self.device = device

        # Open the interface
        self.interface.open()

        self.latest_status: Optional[StatusCode] = StatusCode.SUCCESS

    def __del__(self) -> None:
        """Destructor to ensure the interface is closed properly.

        This method is automatically called when the object is being destroyed
        to guarantee that any open interface connections are properly closed
        and resources are released.
        """
        self.close()

    def close(self) -> None:
        """Close the communication interface.

        Safely closes the active communication interface if one is currently open.
        The method performs cleanup operations to ensure proper resource management.
        """
        if self.interface:
            self.interface.close()

    @staticmethod
    def get_supported_families() -> list[FamilyRevision]:
        """Get the list of supported families by LPCProg.

        This method retrieves all MCU families that are supported by the LPCProg protocol
        from the database manager.

        :return: List of supported MCU families with their revision information.
        """
        return get_families(DatabaseManager.LPCPROG)

    def get_device(self) -> LPCDevice:
        """Get LPCDevice if defined or read it from part ID.

        This method first checks if a device is already defined. If not, it attempts to
        decode the device from the part ID by reading it from the target. If the device
        cannot be determined, an exception is raised.

        :raises SPSDKError: When LPC Device cannot be decoded from part ID and no family
            is specified.
        :return: LPCDevice instance.
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
        """Print status information from the provided status code.

        The method displays the status label and optionally includes a detailed
        description if the status code tag is non-zero.

        :param status: Status code object containing tag and label information, or None if no status
            to display.
        """
        if status:
            if status.tag == 0:
                self.print_func(f"\nStatus: {status.label}")
            else:
                self.print_func(
                    f"\nStatus: {status.label}\nDescription: {StatusCode.get_description(status.tag)}"
                )

    def get_latest_status(self) -> str:
        """Get latest status information from the protocol.

        Retrieves the most recent status information including status label and description
        if available. Returns formatted status string or indicates no status is available.

        :return: Formatted status string with label and description, or "No status" if unavailable.
        """
        if self.latest_status and self.latest_status.tag == 0:
            return f"\nStatus: {self.latest_status.label}"
        if self.latest_status:
            return (
                f"\nStatus: {self.latest_status.label}\n"
                "Description: {StatusCode.get_description(self.latest_status.tag)}"
            )
        return "No status"

    def return_status(self, status: Optional[StatusCode]) -> bool:
        """Check if the given status code indicates success.

        :param status: Status code to evaluate, can be None.
        :return: True if status equals SUCCESS, False otherwise.
        """
        if status:
            return status == StatusCode.SUCCESS
        return False

    def assert_rc(self, status: bool) -> None:
        """Assert command execution status and raise exception on failure.

        This method checks if the provided status indicates success and raises an
        SPSDKError with the latest status information if the command failed.

        :param status: Boolean indicating whether the command was successful.
        :raises SPSDKError: When status is False, indicating command failure.
        """
        if not status:
            raise SPSDKError(f"Command failed with status: {self.latest_status}")

    def send_command(
        self, command: str, print_status: bool = False, expect_rc: bool = True
    ) -> Optional[StatusCode]:
        """Send command to the interface and process the response.

        The method sends a command through the interface, processes any return code
        to create a status object, logs the operation, and optionally prints status.

        :param command: Command string to send to the interface.
        :param print_status: Whether to print the status after command execution.
        :param expect_rc: Whether to expect a return code from the command.
        :return: StatusCode object if return code received, None otherwise.
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
        """Synchronize connection with the target device.

        Establishes communication by performing a handshake sequence that includes
        sending synchronization commands and clearing the serial interface buffer.

        1. Send ? to get baud rate
        2. Receive "Synchronized" message
        3. Send "Synchronized" message
        4. Receive "OK" message

        :param frequency: Frequency of the crystal in Hz.
        :param retries: Number of synchronization attempts, defaults to 10.
        :return: True if synchronization is successful.
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
        """Unlock Flash Write, Erase, and Go commands.

        This command removes the protection from flash operations, allowing
        write, erase, and go commands to be executed on the target device.

        :param print_status: Whether to print command status information.
        :return: True if unlock operation was successful, False otherwise.
        """
        return self.return_status(self.send_command(f"U {self.UNLOCK_CODE}", print_status))

    def set_baud_rate(self, baud_rate: int, stop_bits: int = 1, print_status: bool = True) -> bool:
        """Change the baud rate for communication.

        The new baud rate is effective after the command handler sends the CMD_SUCCESS return code.

        :param baud_rate: New baud rate value to set.
        :param stop_bits: Number of stop bits to use, defaults to 1.
        :param print_status: Whether to print status information, defaults to True.
        :raises SPSDKValueError: Invalid baud rate provided.
        :return: True if baud rate change was successful, False otherwise.
        """
        if baud_rate not in self.ALLOWED_BAUD_RATES:
            raise SPSDKValueError(f"Invalid baud rate: {baud_rate}")
        status = self.send_command(f"B {baud_rate} {stop_bits}", print_status)
        self.interface.device._device.baudrate = baud_rate
        return self.return_status(status)

    def set_echo(self, echo: bool, print_status: bool = True) -> bool:
        """Set echo mode for ISP command handler.

        The default setting for echo command is ON. When ON the ISP command handler sends the
        received serial data back to the host.

        :param echo: Enable or disable echo mode.
        :param print_status: Whether to print command status information.
        :return: True if echo mode was successfully set, False otherwise.
        """
        status = self.send_command(f"E {int(echo)}", print_status)
        self.interface.echo = echo
        return self.return_status(status)

    def write_ram(self, address: int, data: bytes) -> bool:
        """Write data to RAM memory.

        This command is used to download data to RAM. The command is blocked when code read
        protection levels 2 or 3 are enabled. Writing to addresses below 0x1000 0600 is
        disabled for CRP1.
        The host should send the plain binary code after receiving the CMD_SUCCESS return code.
        This ISP command handler responds with "OK<CR><LF>" when the transfer has finished.

        :param address: Target address in RAM memory.
        :param data: Binary data to write (must be aligned to 4-byte boundary).
        :raises SPSDKAlignmentError: Data is not aligned to four bytes boundary.
        :raises SPSDKError: Cannot write to RAM due to communication or protection error.
        :return: True if write operation was successful, False otherwise.
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
        """Read data from RAM or flash memory.

        This command reads specified amount of data from device memory starting at given address.
        The data is read in chunks and can be optionally saved to a binary file. Command is blocked
        when code read protection is enabled.

        :param address: Starting address in RAM or flash memory to read from.
        :param length: Number of bytes to read from memory.
        :param binary: Optional path to binary file where read data will be saved.
        :param progress_callback: Optional callback function called with (current, total) progress.
        :return: Read data as bytes.
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
        """Prepare sectors for write operation.

        This command must be executed before executing "Copy RAM to flash", "Erase Sector(s)",
        or "Erase Pages" command. Successful execution of these commands causes relevant sectors
        to be protected again. To prepare a single sector use the same start and end sector numbers.

        :param start_sector: Starting sector number to prepare.
        :param end_sector: Ending sector number to prepare.
        :param print_status: Whether to print command status during execution.
        :return: True if sectors were successfully prepared, False otherwise.
        """
        return self.return_status(self.send_command(f"P {start_sector} {end_sector}", print_status))

    def copy_ram_to_flash(
        self, flash_address: int, ram_address: int, length: int, print_status: bool = True
    ) -> bool:
        """Copy data from RAM to flash memory.

        This command programs the flash memory by copying data from RAM. The "Prepare Sector(s)
        for Write Operation" command should precede this command. The affected sectors are
        automatically protected again once the copy command is successfully executed. This command
        is blocked when code read protection is enabled.

        :param flash_address: Starting address in flash memory where data will be written.
        :param ram_address: Starting address in RAM where data will be read from.
        :param length: Number of bytes to copy from RAM to flash.
        :param print_status: Whether to print command execution status.
        :return: True if data was successfully copied to flash, False otherwise.
        """
        return self.return_status(
            self.send_command(f"C {flash_address} {ram_address} {length}", print_status)
        )

    def go(self, address: int, thumb_mode: bool = False) -> None:
        """Execute a program residing in RAM or flash memory.

        This command starts execution at the specified address. It may not be possible
        to return to the ISP command handler once this command is successfully executed.
        This command is blocked when code read protection is enabled.

        :param address: Address in RAM or flash memory where program execution starts.
        :param thumb_mode: Enable Thumb mode execution if True, ARM mode if False.
        :raises SPSDKError: When the command execution fails or is blocked by code protection.
        """
        mode = " T" if thumb_mode else ""
        self.send_command(f"G {address}{mode}")

    def erase_sector(self, start_sector: int, end_sector: int, print_status: bool = True) -> bool:
        """Erase one or more sectors of on-chip flash memory.

        This command only allows erasure of all user sectors when the code read
        protection is enabled.

        :param start_sector: Starting sector number to erase.
        :param end_sector: Ending sector number to erase.
        :param print_status: Whether to print operation status messages.
        :return: True if sectors were successfully erased, False otherwise.
        """
        return self.return_status(self.send_command(f"E {start_sector} {end_sector}", print_status))

    def erase_page(self, start_page: int, end_page: int, print_status: bool = True) -> bool:
        """Erase one or more pages of on-chip flash memory.

        This command sends an erase command to the target device to clear the specified
        range of flash memory pages.

        :param start_page: Starting page number to erase.
        :param end_page: Ending page number to erase (inclusive).
        :param print_status: Whether to print command status information.
        :return: True if pages were successfully erased, False otherwise.
        """
        return self.return_status(self.send_command(f"X {start_page} {end_page}", print_status))

    def blank_check_sectors(
        self, start_sector: int, end_sector: int, print_status: bool = True
    ) -> bool:
        """Check if one or more sectors of on-chip flash memory are blank.

        This command verifies whether the specified range of flash memory sectors
        contains only erased (blank) data. If sectors are not blank, it provides
        details about the first non-blank word found.

        :param start_sector: Starting sector number for blank check.
        :param end_sector: Ending sector number for blank check.
        :param print_status: Whether to print status messages during operation.
        :return: True if all specified sectors are blank, False otherwise.
        """
        rc = self.send_command(f"I {start_sector} {end_sector}", print_status)
        if rc == StatusCode.SUCCESS:
            self.print_func("Sectors are blank")
            return True
        if rc == StatusCode.SECTOR_NOT_BLANK:
            self.print_func("Sectors are not blank")
            first_word = self.interface.read_line()
            self.print_func(f"Offset of the first non blank word {first_word}")
            content = self.interface.read_line()
            self.print_func(f"Content of the first non blank word {hex(int(content))}")

        return False

    def read_part_id(self) -> str:
        """Read the part identification number from the device.

        This command sends a 'J' command to the device and reads back the part ID.

        :return: Part identification number as a string.
        """
        self.send_command("J")
        return self.interface.read_line()

    def read_boot_code_version(self) -> str:
        """Read boot code version from the device.

        The method sends a 'K' command to the device and reads the version information
        in two parts: minor and major version numbers.

        :return: Boot code version in format "major.minor".
        """
        self.send_command("K")
        minor = self.interface.read_line().strip()
        major = self.interface.read_line().strip()
        return f"{major}.{minor}"

    def compare(
        self, dst_address: int, src_address: int, length: int, print_status: bool = True
    ) -> bool:
        """Compare memory contents at two locations.

        This command compares the memory contents between destination and source addresses
        for the specified length and reports whether they are identical.

        :param dst_address: Destination memory address to compare.
        :param src_address: Source memory address to compare.
        :param length: Number of bytes to compare (must be multiple of 4).
        :param print_status: Whether to print status messages during operation.
        :raises SPSDKAlignmentError: If length is not multiple of 4.
        :return: True if memory contents are identical, False otherwise.
        """
        if length % 4 != 0:
            raise SPSDKAlignmentError("Byte count must be multiple of 4")
        rc = self.send_command(f"M {dst_address} {src_address} {length}", print_status)
        if rc == StatusCode.SUCCESS:
            self.print_func("Content is same")
            return True
        if rc == StatusCode.COMPARE_ERROR:
            self.print_func("Content differs")
            diff = self.interface.read_line()
            self.print_func(f"Offset of first difference {diff}")
        return False

    def read_uid(self) -> str:
        """Read the unique ID from the device.

        This command sends a read UID request to the device and formats the response
        as a space-separated string of hexadecimal values.

        :return: Formatted unique ID as space-separated hexadecimal values
            (e.g., "0x12345678 0x9abcdef0 0x11223344 0x55667788").
        """
        self.send_command("N")
        uuids = [self.interface.read_line() for _ in range(4)]
        return " ".join([f"0x{int(uid):08x}" for uid in uuids])

    def read_crc_checksum(self, address: int, length: int) -> Optional[int]:
        """Read CRC checksum of a block of RAM or flash memory.

        This command is blocked when code read protection is enabled.

        :param address: Address in RAM or flash memory.
        :param length: Length of data block in bytes.
        :return: CRC checksum value if successful, None if operation failed.
        """
        rc = self.send_command(f"S {address} {length}")
        if rc == StatusCode.SUCCESS:
            return int(self.interface.read_line())
        return None

    def read_flash_signature(
        self, start_address: int, end_address: int, wait_states: int = 2, mode: int = 0
    ) -> int:
        """Read flash signature generated by the flash controller.

        This command uses the flash controller to generate a signature for the specified
        memory range with configurable wait states and mode parameters.

        :param start_address: Starting address of the flash memory range to sign.
        :param end_address: Ending address of the flash memory range to sign.
        :param wait_states: Number of wait states for flash access (default: 2).
        :param mode: Flash signature generation mode (default: 0).
        :raises SPSDKError: When flash signature reading fails.
        :return: Flash signature value as integer.
        """
        rc = self.send_command(f"Z {start_address} {end_address} {wait_states} {mode}")
        if rc == StatusCode.SUCCESS:
            return int(self.interface.read_line())
            # return [self.interface.read_line() for _ in range(4)]

        raise SPSDKError("Cannot read flash signature")

    def decode_part_id(self, part_id: str) -> Optional[str]:
        """Decode part ID from the database and identify the corresponding device.

        This method converts the input part ID to a standardized hex format and searches
        through all available device families in the LPCPROG database to find a matching
        part ID. When found, it sets the device attribute and returns the decoded name.

        :param part_id: Raw part ID value to decode (string or numeric format)
        :raises SPSDKValueError: When part_id cannot be converted to integer
        :return: Decoded part ID name if found, None if no match exists in database
        """
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

        The method reads the Code Read Protection (CRP) level from the device memory at a specific
        offset and decodes it into a corresponding CRP level enum value. If reading fails or the
        value cannot be decoded, it defaults to CRP2 level.

        :return: Decoded CRP level from device memory, defaults to CRP2 on error.
        """
        try:
            crp = value_to_int(self.read_memory(self.CRP_OFFSET, self.CRP_LENGTH))
            return LPCProgCRPLevels.from_tag(crp)
        except (SPSDKError, KeyError):
            return LPCProgCRPLevels.CRP2

    def get_info(self) -> str:
        """Get device information summary.

        Retrieves and formats comprehensive device information including Part ID,
        UID, Boot code version, and CRP (Code Read Protection) level with description.

        :return: Formatted string containing device information summary.
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

        The method uses CRC32 algorithm to compute checksum for the provided data bytes.

        :param data: Data bytes to calculate CRC from.
        :return: Calculated CRC32 checksum as integer.
        """
        crc_ob = from_crc_algorithm(CrcAlg.CRC32)
        return crc_ob.calculate(data)

    def program_flash_sector(
        self, data: bytes, sector: int, verify: bool = False, erase: bool = True
    ) -> bool:
        """Program flash sector with data verification.

        Writes data to the specified flash sector using a multi-step process that includes
        RAM buffering, sector preparation, optional erasing, and CRC verification to ensure
        data integrity.

        Approach for writing the sector
        1) Write data to RAM
        2) Prepare sector for writing
        3) Erase sector
        4) Again prepare sector
        5) Copy RAM to flash

        :param data: Data bytes to be written to the flash sector.
        :param sector: Target sector number for programming.
        :param verify: Enable verification of data written to RAM buffer.
        :param erase: Enable sector erase before writing new data.
        :raises SPSDKAlignmentError: Data size exceeds sector size limit.
        :raises SPSDKError: Data verification failed or CRC checksum mismatch.
        :return: Status of the programming operation.
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
        """Program a single flash page with data.

        This command writes data to a flash page using a multi-step approach:
        1) Write data to RAM buffer
        2) Prepare sector for writing operations
        3) Erase page (if erase flag is enabled)
        4) Prepare sector again after erase
        5) Copy data from RAM to flash memory
        6) Verify operation using CRC checksum

        :param data: Binary data to be written to flash page.
        :param page_index: Zero-based index of the flash page to program.
        :param verify: Whether to verify data written to RAM before flash operation.
        :param erase: Whether to erase the page before writing new data.
        :raises SPSDKAlignmentError: When data size exceeds page size.
        :raises SPSDKError: When data verification fails or CRC checksum mismatch occurs.
        :return: True if operation completed successfully, False otherwise.
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
        """Calculate number of sectors needed for writing the data.

        This method determines how many device sectors are required to accommodate
        the given data based on the device's sector size.

        :param data: Binary data to be written to the device.
        :return: Number of sectors required to store the data.
        """
        return (len(data) + self.get_device().sector_size - 1) // self.get_device().sector_size

    def calculate_page_count(self, data: bytes) -> int:
        """Calculate number of pages needed for writing the data.

        The method calculates how many device pages are required to store the given data
        by dividing the data length by the device page size and rounding up.

        :param data: Binary data to be written to the device.
        :return: Number of pages required to store the data.
        """
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
        """Program binary data to flash memory with optional erase and verify.

        The method programs flash memory in reverse order to prevent device bricking.
        When programming from sector 0, it first erases the first sector to make the
        image un-bootable during programming process.

        1) Erase the first sector to make the image un-bootable and prevent bricking
        2) Optionally write the checksum to the image vector table
        3) Write the image in reverse order

        :param bin_data: Binary data to be written to flash memory.
        :param start_sector: Starting sector number for programming.
        :param start_page: Starting page number for programming (mutually exclusive
            with start_sector).
        :param progress_callback: Optional callback function called with
            (bytes_written, total_bytes) for progress tracking.
        :param print_status: Whether to print programming status information.
        :param erase: Whether to erase sectors/pages before writing.
        :param verify: Whether to verify written data after programming.
        :raises SPSDKValueError: When sector count exceeds available sectors or when
            both start_sector and start_page are specified.
        :return: True if programming completed successfully, False otherwise.
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
