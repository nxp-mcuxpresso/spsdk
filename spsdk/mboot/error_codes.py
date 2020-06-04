#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2016-2018 Martin Olejar
# Copyright 2019-2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Status and error codes used by the MBoot protocol."""

from spsdk.utils.easy_enum import Enum


########################################################################################################################
# McuBoot Status Codes (Errors)
########################################################################################################################

class StatusCode(Enum):
    """McuBoot status codes."""

    SUCCESS = (0, 'Success', 'Success')
    FAIL = (1, 'Fail', 'Fail')
    READ_ONLY = (2, 'ReadOnly', 'Read Only Error')
    OUT_OF_RANGE = (3, 'OutOfRange', 'Out Of Range Error')
    INVALID_ARGUMENT = (4, 'InvalidArgument', 'Invalid Argument Error')
    TIMEOUT = (5, 'TimeoutError', 'Timeout Error')
    NO_TRANSFER_IN_PROGRESS = (6, 'NoTransferInProgress', 'No Transfer In Progress Error')

    # Flash driver errors.
    FLASH_SIZE_ERROR = (100, 'FlashSizeError', 'FLASH Driver: Size Error')
    FLASH_ALIGNMENT_ERROR = (101, 'FlashAlignmentError', 'FLASH Driver: Alignment Error')
    FLASH_ADDRESS_ERROR = (102, 'FlashAddressError', 'FLASH Driver: Address Error')
    FLASH_ACCESS_ERROR = (103, 'FlashAccessError', 'FLASH Driver: Access Error')
    FLASH_PROTECTION_VIOLATION = (104, 'FlashProtectionViolation', 'FLASH Driver: Protection Violation')
    FLASH_COMMAND_FAILURE = (105, 'FlashCommandFailure', 'FLASH Driver: Command Failure')
    FLASH_UNKNOWN_PROPERTY = (106, 'FlashUnknownProperty', 'FLASH Driver: Unknown Property')
    FLASH_REGION_EXECUTE_ONLY = (108, 'FlashRegionExecuteOnly', 'FLASH Driver: Region Execute Only')
    FLASH_EXEC_IN_RAM_NOT_READY = (109, 'FlashExecuteInRamFunctionNotReady',
                                   'FLASH Driver: Execute In RAM Function Not Ready')
    FLASH_COMMAND_NOT_SUPPORTED = (111, 'FlashCommandNotSupported', 'FLASH Driver: Command Not Supported')
    FLASH_OUT_OF_DATE_CFPA_PAGE = (132, 'FlashOutOfDateCfpaPage', 'FLASH Driver: Out Of Date CFPA Page')

    # I2C driver errors.
    I2C_SLAVE_TX_UNDERRUN = (200, 'I2cSlaveTxUnderrun', 'I2C Driver: Slave Tx Underrun')
    I2C_SLAVE_RX_OVERRUN = (201, 'I2cSlaveRxOverrun', 'I2C Driver: Slave Rx Overrun')
    I2C_ARBITRATION_LOST = (202, 'I2cArbitrationLost', 'I2C Driver: Arbitration Lost')

    # SPI driver errors.
    SPI_SLAVE_TX_UNDERRUN = (300, 'SpiSlaveTxUnderrun', 'SPI Driver: Slave Tx Underrun')
    SPI_SLAVE_RX_OVERRUN = (301, 'SpiSlaveRxOverrun', 'SPI Driver: Slave Rx Overrun')

    # QuadSPI driver errors.
    QSPI_FLASH_SIZE_ERROR = (400, 'QspiFlashSizeError', 'QSPI Driver: Flash Size Error')
    QSPI_FLASH_ALIGNMENT_ERROR = (401, 'QspiFlashAlignmentError', 'QSPI Driver: Flash Alignment Error')
    QSPI_FLASH_ADDRESS_ERROR = (402, 'QspiFlashAddressError', 'QSPI Driver: Flash Address Error')
    QSPI_FLASH_COMMAND_FAILURE = (403, 'QspiFlashCommandFailure', 'QSPI Driver: Flash Command Failure')
    QSPI_FLASH_UNKNOWN_PROPERTY = (404, 'QspiFlashUnknownProperty', 'QSPI Driver: Flash Unknown Property')
    QSPI_NOT_CONFIGURED = (405, 'QspiNotConfigured', 'QSPI Driver: Not Configured')
    QSPI_COMMAND_NOT_SUPPORTED = (406, 'QspiCommandNotSupported', 'QSPI Driver: Command Not Supported')
    QSPI_COMMAND_TIMEOUT = (407, 'QspiCommandTimeout', 'QSPI Driver: Command Timeout')
    QSPI_WRITE_FAILURE = (408, 'QspiWriteFailure', 'QSPI Driver: Write Failure')

    # OTFAD driver errors.
    OTFAD_SECURITY_VIOLATION = (500, 'OtfadSecurityViolation', 'OTFAD Driver: Security Violation')
    OTFAD_LOGICALLY_DISABLED = (501, 'OtfadLogicallyDisabled', 'OTFAD Driver: Logically Disabled')
    OTFAD_INVALID_KEY = (502, 'OtfadInvalidKey', 'OTFAD Driver: Invalid Key')
    OTFAD_INVALID_KEY_BLOB = (503, 'OtfadInvalidKeyBlob', 'OTFAD Driver: Invalid Key Blob')

    # SDMMC driver errors.

    # Bootloader errors.
    UNKNOWN_COMMAND = (10000, 'UnknownCommand', 'Unknown Command')
    SECURITY_VIOLATION = (10001, 'SecurityViolation', 'Security Violation')
    ABORT_DATA_PHASE = (10002, 'AbortDataPhase', 'Abort Data Phase')
    PING_ERROR = (10003, 'PingError', 'Ping Error')
    NO_RESPONSE = (10004, 'NoResponse', 'No Response')
    NO_RESPONSE_EXPECTED = (10005, 'NoResponseExpected', 'No Response Expected')
    UNSUPPORTED_COMMAND = (10006, 'UnsupportedCommand', 'Unsupported Command')

    # SB loader errors.
    ROMLDR_SECTION_OVERRUN = (10100, 'RomLdrSectionOverrun', 'ROM Loader: Section Overrun')
    ROMLDR_SIGNATURE = (10101, 'RomLdrSignature', 'ROM Loader: Signature Error')
    ROMLDR_SECTION_LENGTH = (10102, 'RomLdrSectionLength', 'ROM Loader: Section Length Error')
    ROMLDR_UNENCRYPTED_ONLY = (10103, 'RomLdrUnencryptedOnly', 'ROM Loader: Unencrypted Only')
    ROMLDR_EOF_REACHED = (10104, 'RomLdrEOFReached', 'ROM Loader: EOF Reached')
    ROMLDR_CHECKSUM = (10105, 'RomLdrChecksum', 'ROM Loader: Checksum Error')
    ROMLDR_CRC32_ERROR = (10106, 'RomLdrCrc32Error', 'ROM Loader: CRC32 Error')
    ROMLDR_UNKNOWN_COMMAND = (10107, 'RomLdrUnknownCommand', 'ROM Loader: Unknown Command')
    ROMLDR_ID_NOT_FOUND = (10108, 'RomLdrIdNotFound', 'ROM Loader: ID Not Found')
    ROMLDR_DATA_UNDERRUN = (10109, 'RomLdrDataUnderrun', 'ROM Loader: Data Underrun')
    ROMLDR_JUMP_RETURNED = (10110, 'RomLdrJumpReturned', 'ROM Loader: Jump Returned')
    ROMLDR_CALL_FAILED = (10111, 'RomLdrCallFailed', 'ROM Loader: Call Failed')
    ROMLDR_KEY_NOT_FOUND = (10112, 'RomLdrKeyNotFound', 'ROM Loader: Key Not Found')
    ROMLDR_SECURE_ONLY = (10113, 'RomLdrSecureOnly', 'ROM Loader: Secure Only')
    ROMLDR_RESET_RETURNED = (10114, 'RomLdrResetReturned', 'ROM Loader: Reset Returned')
    ROMLDR_ROLLBACK_BLOCKED = (10115, 'RomLdrRollbackBlocked', 'ROM Loader: Rollback Blocked')
    ROMLDR_INVALID_SECTION_MAC_COUNT = (10116, 'RomLdrInvalidSectionMacCount', 'ROM Loader: Invalid Section Mac Count')
    ROMLDR_UNEXPECTED_COMMAND = (10117, 'RomLdrUnexpectedCommand', 'ROM Loader: Unexpected Command')

    # Memory interface errors.
    MEMORY_RANGE_INVALID = (10200, 'MemoryRangeInvalid', 'Memory Range Invalid')
    MEMORY_READ_FAILED = (10201, 'MemoryReadFailed', 'Memory Read Failed')
    MEMORY_WRITE_FAILED = (10202, 'MemoryWriteFailed', 'Memory Write Failed')
    MEMORY_CUMULATIVE_WRITE = (10203, 'MemoryCumulativeWrite', 'Memory Cumulative Write')
    MEMORY_NOT_CONFIGURED = (10205, 'MemoryNotConfigured', 'Memory Not Configured')

    # Property store errors.
    UNKNOWN_PROPERTY = (10300, 'UnknownProperty', 'Unknown Property')
    READ_ONLY_PROPERTY = (10301, 'ReadOnlyProperty', 'Read Only Property')
    INVALID_PROPERTY_VALUE = (10302, 'InvalidPropertyValue', 'Invalid Property Value')

    # Property store errors.
    APP_CRC_CHECK_PASSED = (10400, 'AppCrcCheckPassed', 'Application CRC Check: Passed')
    APP_CRC_CHECK_FAILED = (10401, 'AppCrcCheckFailed', 'Application: CRC Check: Failed')
    APP_CRC_CHECK_INACTIVE = (10402, 'AppCrcCheckInactive', 'Application CRC Check: Inactive')
    APP_CRC_CHECK_INVALID = (10403, 'AppCrcCheckInvalid', 'Application CRC Check: Invalid')
    APP_CRC_CHECK_OUT_OF_RANGE = (10404, 'AppCrcCheckOutOfRange', 'Application CRC Check: Out Of Range')
