#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""EdgeLock Enclave Message constants."""

from spsdk.utils.easy_enum import Enum


class MessageIDs(Enum):
    """ELE Messages ID."""

    PING_REQ = (0x01, "Ping request.", "")
    ELE_FW_AUTH_REQ = (0x02, "ELE firmware authenticate request.", "")
    ELE_RELEASE_CONTAINER_REQ = (0x89, "Release Container.", "")
    WRITE_SEC_FUSE_REQ = (0x91, "Write secure fuse request.", "")
    READ_COMMON_FUSE = (0x97, "Read common fuse request.", "")
    GET_FW_VERSION_REQ = (0x9D, "Get firmware version request.", "")
    RETURN_LIFECYCLE_UPDATE_REQ = (0xA0, "Return lifecycle update request.", "")
    LOAD_KEY_BLOB_REQ = (0xA7, "Load KeyBlob request.", "")
    GENERATE_KEY_BLOB_REQ = (0xAF, "Generate KeyBlob request.", "")
    GET_FW_STATUS_REQ = (0xC5, "Get ELE FW status request.", "")
    GET_INFO_REQ = (0xDA, "Get ELE Information request.", "")
    START_RNG_REQ = (0xA3, "Start True Random Generator request.", "")
    GET_TRNG_STATE_REQ = (0xA3, "Get True Random Generator state request.", "")
    RESET_REQ = (0xC7, "System reset request.", "")
    WRITE_FUSE = (0xD6, "Write fuse", "")
    WRITE_SHADOW_FUSE = (0xF2, "Write shadow fuse", "")
    READ_SHADOW_FUSE = (0xF3, "Read shadow fuse request.", "")


class LifeCycle(Enum):
    """ELE life cycles."""

    LC_BLANK = (0x002, "BLANK", "Blank device")
    LC_FAB = (0x004, "FAB", "Fab mode")
    LC_NXP_PROV = (0x008, "NXP_PROV", "NXP Provisioned")
    LC_OEM_OPEN = (0x010, "OEM_OPEN", "OEM Open")
    LC_OEM_SWC = (0x020, "OEM_SWC", "OEM Secure World Closed")
    LC_OEM_CLSD = (0x040, "OEM_CLSD", "OEM Closed")
    LC_OEM_FR = (0x080, "OEM_FR", "Field Return OEM")
    LC_NXP_FR = (0x100, "NXP_FR", "Field Return NXP")
    LC_OEM_LCKD = (0x200, "OEM_LCKD", "OEM Locked")
    LC_BRICKED = (0x400, "BRICKED", "BRICKED")


class ResponseStatus(Enum):
    """ELE Message Response status."""

    ELE_SUCCESS_IND = (0xD6, "Success", "The request was successful")
    ELE_FAILURE_IND = (0x29, "Failure", "The request failed")


class ResponseIndication(Enum):
    """ELE Message Response indication."""

    ELE_ROM_PING_FAILURE_IND = (0x0A, "ROM ping failure")
    ELE_FW_PING_FAILURE_IND = (0x1A, "Firmware ping failure", "")
    ELE_BAD_SIGNATURE_FAILURE_IND = (0xF0, "Bad signature failure", "")
    ELE_BAD_HASH_FAILURE_IND = (0xF1, "Bad hash failure", "")
    ELE_INVALID_LIFECYCLE_IND = (0xF2, "Invalid lifecycle", "")
    ELE_PERMISSION_DENIED_FAILURE_IND = (0xF3, "Permission denied failure", "")
    ELE_INVALID_MESSAGE_FAILURE_IND = (0xF4, "Invalid message failure", "")
    ELE_BAD_VALUE_FAILURE_IND = (0xF5, "Bad value failure", "")
    ELE_BAD_FUSE_ID_FAILURE_IND = (0xF6, "Bad fuse ID failure", "")
    ELE_BAD_CONTAINER_FAILURE_IND = (0xF7, "Bad container failure", "")
    ELE_BAD_VERSION_FAILURE_IND = (0xF8, "Bad version failure", "")
    ELE_INVALID_KEY_FAILURE_IND = (0xF9, "Invalid key failure", "")
    ELE_BAD_KEY_HASH_FAILURE_IND = (0xFA, "Bad key hash failure", "")
    ELE_NO_VALID_CONTAINER_FAILURE_IND = (0xFB, "No valid container failure", "")
    ELE_BAD_CERTIFICATE_FAILURE_IND = (0xFC, "Bad certificate failure", "")
    ELE_BAD_UID_FAILURE_IND = (0xFD, "Bad UID failure", "")
    ELE_BAD_MONOTONIC_COUNTER_FAILURE_IND = (0xFE, "Bad monotonic counter failure", "")
    ELE_MUST_SIGNED_FAILURE_IND = (0xE0, "Must be signed failure", "")
    ELE_NO_AUTHENTICATION_FAILURE_IND = (0xEE, "No authentication failure", "")
    ELE_BAD_SRK_SET_FAILURE_IND = (0xEF, "Bad SRK set failure", "")
    ELE_UNALIGNED_PAYLOAD_FAILURE_IND = (0xA6, "Un-aligned payload failure", "")
    ELE_WRONG_SIZE_FAILURE_IND = (0xA7, "Wrong size failure", "")
    ELE_ENCRYPTION_FAILURE_IND = (0xA8, "Encryption failure", "")
    ELE_DECRYPTION_FAILURE_IND = (0xA9, "Decryption failure", "")
    ELE_OTP_PROGFAIL_FAILURE_IND = (0xAA, "OTP program fail failure", "")
    ELE_OTP_LOCKED_FAILURE_IND = (0xAB, "OTP locked failure", "")
    ELE_OTP_INVALID_IDX_FAILURE_IND = (0xAD, "OTP Invalid IDX failure", "")
    ELE_TIME_OUT_FAILURE_IND = (0xB0, "Timeout  failure", "")
    ELE_BAD_PAYLOAD_FAILURE_IND = (0xB1, "Bad payload failure", "")
    ELE_WRONG_ADDRESS_FAILURE_IND = (0xB4, "Wrong address failure", "")
    ELE_DMA_FAILURE_IND = (0xB5, "DMA failure", "")
    ELE_DISABLED_FEATURE_FAILURE_IND = (0xB6, "Disabled feature failure", "")
    ELE_MUST_ATTEST_FAILURE_IND = (0xB7, "Must attest failure", "")
    ELE_RNG_NOT_STARTED_FAILURE_IND = (0xB8, "Random number generator not started failure", "")
    ELE_CRC_ERROR_IND = (0xB9, "CRC error", "")
    ELE_AUTH_SKIPPED_OR_FAILED_FAILURE_IND = (0xBB, "Authentication skipped or failed failure", "")
    ELE_INCONSISTENT_PAR_FAILURE_IND = (0xBC, "Inconsistent parameter failure", "")
    ELE_RNG_INST_FAILURE_IND = (0xBD, "Random number generator instantiation failure", "")
    ELE_LOCKED_REG_FAILURE_IND = (0xBE, "Locked register failure", "")
    ELE_BAD_ID_FAILURE_IND = (0xBF, "Bad ID failure", "")
    ELE_INVALID_OPERATION_FAILURE_IND = (0xC0, "Invalid operation failure", "")
    ELE_NON_SECURE_STATE_FAILURE_IND = (0xC1, "Non secure state failure", "")
    ELE_MSG_TRUNCATED_IND = (0xC2, "Message truncated failure", "")
    ELE_BAD_IMAGE_NUM_FAILURE_IND = (0xC3, "Bad image number failure", "")
    ELE_BAD_IMAGE_ADDR_FAILURE_IND = (0xC4, "Bad image address failure", "")
    ELE_BAD_IMAGE_PARAM_FAILURE_IND = (0xC5, "Bad image parameters failure", "")
    ELE_BAD_IMAGE_TYPE_FAILURE_IND = (0xC6, "Bad image type failure", "")
    ELE_CORRUPTED_SRK_FAILURE_IND = (0xD0, "Corrupted SRK failure", "")
    ELE_OUT_OF_MEMORY_IND = (0xD1, "Out of memory failure", "")
    ELE_CSTM_FAILURE_IND = (0xCF, "CSTM failure", "")
    ELE_OLD_VERSION_FAILURE_IND = (0xCE, "Old version failure", "")
    ELE_WRONG_BOOT_MODE_FAILURE_IND = (0xCD, "Wrong boot mode failure", "")
    ELE_APC_ALREADY_ENABLED_FAILURE_IND = (0xCB, "APC already enabled failure", "")
    ELE_RTC_ALREADY_ENABLED_FAILURE_IND = (0xCC, "RTC already enabled failure", "")
    ELE_ABORT_IND = (0xFF, "Abort", "")


class EleFwStatus(Enum):
    """ELE Firmware status."""

    ELE_FW_STATUS_NOT_IN_PLACE = (0, "Not in place", "")
    ELE_FW_STATUS_IN_PLACE = (1, "Authenticated and operational", "")


class KeyBlobEncryptionAlgorithm(Enum):
    """ELE KeyBlob encryption algorithms."""

    AES_CBC = (0x03, "AES_CBC", "KeyBlob encryption algorithm AES CBC")
    AES_CTR = (0x04, "AES_CTR", "KeyBlob encryption algorithm AES CTR")
    AES_XTS = (0x37, "AES_XTS", "KeyBlob encryption algorithm AES XTS")
    SM4_CBC = (0x2B, "SM4_CBC", "KeyBlob encryption algorithm SM4 CBC")


class KeyBlobEncryptionIeeCtrModes(Enum):
    """IEE Keyblob mode attributes."""

    AesCTRWAddress = (0x02, "CTR_WITH_ADDRESS", " AES CTR w address binding mode")
    AesCTRWOAddress = (0x03, "CTR_WITHOUT_ADDRESS", " AES CTR w/o address binding mode")
    AesCTRkeystream = (0x04, "CTR_KEY_STREAM", "AES CTR keystream only")


class EleTrngState(Enum):
    """ELE TRNG state."""

    ELE_TRNG_PROGRAM = (0x1, "TRNG is in program mode", "")
    ELE_TRNG_GENERATING_ENTROPY = (0x1, "TRNG is still generating entropy", "")
    ELE_TRNG_READY = (0x3, "TRNG entropy is valid and ready to be read", "")
    ELE_TRNG_ERROR = (0x4, "TRNG encounter an error while generating entropy", "")


class EleCsalState(Enum):
    """ELE CSAL state."""

    ELE_CSAL_NOT_READY = (0x0, "Crypto Lib random context initialization is not done yet", "")
    ELE_CSAL_ON_GOING = (0x1, "Crypto Lib random context initialization is on-going", "")
    ELE_CSAL_READY = (0x2, "Crypto Lib random context initialization succeed", "")
    ELE_CSAL_ERROR = (0x3, "Crypto Lib random context initialization failed", "")
