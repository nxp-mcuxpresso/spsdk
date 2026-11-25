#!/usr/bin/env python
#
# Copyright 2023-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""EdgeLock Enclave constants and enumerations.

This module provides constant definitions and enumeration classes for EdgeLock Enclave (ELE)
operations, including message IDs, response codes, lifecycle states, and configuration options
used throughout the SPSDK ELE functionality.
"""

from spsdk.utils.spsdk_enum import SpsdkEnum, SpsdkSoftEnum


class MessageIDs(SpsdkSoftEnum):
    """ELE Message Identifiers enumeration.

    This enumeration defines all supported EdgeLock Enclave (ELE) message identifiers
    used for communication with the ELE firmware. Each message ID represents a specific
    command or request that can be sent to the ELE subsystem for various operations
    including authentication, key management, lifecycle updates, and system control.
    """

    PING_REQ = (0x01, "PING_REQ", "Ping request.")
    ELE_FW_AUTH_REQ = (0x02, "ELE_FW_AUTH_REQ", "ELE firmware authenticate request.")
    RESTART_RST_TIMER_REQ = (0x04, "RESTART_RST_TIMER_REQ", "Restart reset timer request.")
    SESSION_OPEN_REQ = (0x10, "SESSION_OPEN_REQ", "Session Open Request")
    SESSION_CLOSE_REQ = (0x11, "SESSION_CLOSE_REQ", "Session Close Request")
    SAB_INIT_REQ = (0x17, "SAB_INIT_REQ", "SAB Init Request")

    ELE_DUMP_DEBUG_BUFFER_REQ = (0x21, "ELE_DUMP_DEBUG_BUFFER_REQ", "Dump the ELE logs")

    KEY_STORE_OPEN_REQ = (0x30, "KEY_STORE_OPEN_REQ", "Key Store Open Request")
    KEY_STORE_CLOSE_REQ = (0x31, "KEY_STORE_CLOSE_REQ", "Key Store Close Request")

    PUBLIC_KEY_EXPORT_REQ = (0x32, "PUBLIC_KEY_EXPORT_REQ", "Public Key Export Request")

    ELE_OEM_CNTN_AUTH_REQ = (0x87, "ELE_OEM_CNTN_AUTH_REQ", "OEM Container authenticate")
    ELE_VERIFY_IMAGE_REQ = (0x88, "ELE_VERIFY_IMAGE_REQ", "Verify Image")
    ELE_RELEASE_CONTAINER_REQ = (0x89, "ELE_RELEASE_CONTAINER_REQ", "Release Container.")
    WRITE_SEC_FUSE_REQ = (0x91, "WRITE_SEC_FUSE_REQ", "Write secure fuse request.")
    ELE_FWD_BOOT_CRYPTO_REQ = (0x93, "ELE_FWD_BOOT_CRYPTO_REQ", "Forward boot crypto request.")
    ELE_FWD_LIFECYCLE_UP_REQ = (0x95, "ELE_FWD_LIFECYCLE_UP_REQ", "Forward Lifecycle update")
    READ_COMMON_FUSE = (0x97, "READ_COMMON_FUSE", "Read common fuse request.")
    GET_FW_VERSION_REQ = (0x9D, "GET_FW_VERSION_REQ", "Get firmware version request.")
    RETURN_LIFECYCLE_UPDATE_REQ = (
        0xA0,
        "RETURN_LIFECYCLE_UPDATE_REQ",
        "Return lifecycle update request.",
    )
    ELE_GET_EVENTS_REQ = (0xA2, "ELE_GET_EVENTS_REQ", "Get Events")
    LOAD_KEY_BLOB_REQ = (0xA7, "LOAD_KEY_BLOB_REQ", "Load KeyBlob request.")
    ELE_COMMIT_REQ = (0xA8, "ELE_COMMIT_REQ", "EdgeLock Enclave commit request.")
    ELE_DERIVE_KEY_REQ = (0xA9, "ELE_DERIVE_KEY_REQ", "Derive key")
    GENERATE_KEY_BLOB_REQ = (0xAF, "GENERATE_KEY_BLOB_REQ", "Generate KeyBlob request.")
    START_CLOCK_VOLTAGE_CHANGE_REQ = (
        0xC0,
        "START_CLOCK_VOLTAGE_CHANGE_REQ",
        "Start clock/voltage change request.",
    )
    STOP_CLOCK_VOLTAGE_CHANGE_REQ = (
        0xC1,
        "STOP_CLOCK_VOLTAGE_CHANGE_REQ",
        "Stop clock/voltage change request.",
    )
    ENABLE_PATCH_REQ = (0xC3, "ENABLE_PATCH_REQ", "Enable patch request.")
    RELEASE_RDC_REQ = (0xC4, "RELEASE_RDC_REQ", "Release RDC request.")
    GET_FW_STATUS_REQ = (0xC5, "GET_FW_STATUS_REQ", "Get ELE FW status request.")
    ENABLE_DECRYPT_REQ = (0xC6, "ENABLE_DECRYPT_REQ", "Enable decrypt request.")
    UPDATE_OTP_CLK_DIV_REQ = (0xD0, "UPDATE_OTP_CLK_DIV_REQ", "Update OTP clock divider request.")
    POWER_DONE_REQ = (0xD1, "POWER_DONE_REQ", "Power done request.")
    ELE_ENABLE_APC_REQ = (0xD2, "ELE_ENABLE_APC_REQ", "Enable APC (Application processor)")
    ELE_ENABLE_RTC_REQ = (0xD3, "ELE_ENABLE_RTC_REQ", "Enable RTC (Runtime processor)")
    DEEP_POWER_DOWN_REQ = (0xD4, "DEEP_POWER_DOWN_REQ", "Deep power down request.")
    STOP_RST_TIMER_REQ = (0xD5, "STOP_RST_TIMER_REQ", "Stop reset timer request.")
    RELEASE_CAAM_REQ = (0xD7, "RELEASE_CAAM_REQ", "Release CAAM request.")
    MOVE_TO_UNSECURE_REQ = (0xD9, "MOVE_TO_UNSECURE_REQ", "Move to unsecure request.")
    GET_INFO_REQ = (0xDA, "GET_INFO_REQ", "Get ELE Information request.")
    ELE_RESET_APC_CTX_REQ = (0xD8, "ELE_RESET_APC_CTX_REQ", "Reset APC Context")
    ATTEST_REQ = (0xDB, "ATTEST_REQ", "Attestation request.")
    RELEASE_PATCH_REQ = (0xDC, "RELEASE_PATCH_REQ", "Release patch request.")
    OTP_SEQ_SWITCH_REQ = (0xDD, "OTP_SEQ_SWITCH_REQ", "OTP sequence switch request.")
    FAST_BOOT_STATUS_REQ = (0xE0, "FAST_BOOT_STATUS_REQ", "Fast boot status request.")
    GENERIC_CONTAINER_AUTH_REQ = (
        0xE1,
        "GENERIC_CONTAINER_AUTH_REQ",
        "Generic container authenticate request.",
    )
    FAST_VERIFY_IMAGE_REQ = (0xE2, "FAST_VERIFY_IMAGE_REQ", "Fast verify image request.")
    START_RNG_REQ = (0xA3, "START_RNG_REQ", "Start True Random Generator request.")
    GET_TRNG_STATE_REQ = (0xA4, "GET_TRNG_STATE_REQ", "Get True Random Generator state request.")
    RESET_REQ = (0xC7, "RESET_REQ", "System reset request.")
    WRITE_FUSE = (0xD6, "WRITE_FUSE", "Write fuse")
    WRITE_SHADOW_FUSE = (0xF2, "WRITE_SHADOW_FUSE", "Write shadow fuse")
    READ_SHADOW_FUSE = (0xF3, "READ_SHADOW_FUSE", "Read shadow fuse request.")


class SocId(SpsdkSoftEnum):
    """SOC Identification enumeration for NXP microcontrollers.

    This enumeration provides standardized identifiers for supported System-on-Chip (SOC)
    devices in the SPSDK library, mapping numeric IDs to device names and marketing names.
    """

    MX8ULP = (0x084D, "MX8ULP", "i.MX8ULP")
    RT1180 = (0x1180, "RT1180", "i.MXRT1180")
    MX91 = (0x9100, "MX91", "i.MX91")
    MX93 = (0x9300, "MX93", "i.MX93")
    MX95 = (0x9500, "MX95", "i.MX95")
    MX95_1 = (0x9590, "MX95", "i.MX95")
    MX943 = (0x9430, "MX943", "i.MX943")
    MX952 = (0x9570, "MX952", "i.MX952")


class LifeCycle(SpsdkSoftEnum):
    """ELE device lifecycle state enumeration.

    This enumeration defines the various lifecycle states that an ELE (EdgeLock Enclave)
    device can be in, from initial blank state through provisioning, deployment, and
    end-of-life states. Each lifecycle state represents a specific security and
    operational mode of the device.
    """

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


class LifeCycleToSwitch(SpsdkSoftEnum):
    """ELE life cycle enumeration for switching operations.

    This enumeration defines the available life cycle states that can be used
    in ELE (EdgeLock Enclave) life cycle switching requests, providing
    standardized constants for OEM closed and locked states.
    """

    OEM_CLOSED = (0x08, "OEM_CLOSED", "OEM Closed")
    OEM_LOCKED = (0x80, "OEM_LOCKED", "OEM Locked")


class SecureBootCryptoMode(SpsdkSoftEnum):
    """Secure boot crypto mode enumeration for FORWARD BOOT CRYPTO requests.

    This enumeration defines the target secure boot crypto modes that the device's
    secure boot crypto policy (Classic, PQC, Hybrid) can be moved to using the
    FORWARD BOOT CRYPTO (0x93) baseline command, either directly or via a signed
    message. Classic is not listed as it is only ever a source state; the
    destination magic values below define which signatures secure boot will
    verify going forward.
    """

    HYBRID = (0x05FF, "HYBRID", "PQC and classic signature will be verified during secure boot.")
    PQC = (0x7A1F, "PQC", "Only PQC signature will be verified during secure boot.")
    RETURN_TO_CLASSIC = (
        0x7FE0,
        "RETURN_TO_CLASSIC",
        "When current policy is hybrid or PQC, go back to classic. "
        "Only classic will be verified during secure boot.",
    )


class MessageUnitId(SpsdkSoftEnum):
    """Message Unit ID enumeration for ELE communication.

    This enumeration defines the available message unit identifiers used
    for communication with the EdgeLock Enclave (ELE) subsystem.
    """

    RTD_MU = (0x01, "RTD_MU", "Real Time Device message unit")
    APD_MU = (0x02, "APD_MU", "Application Processor message unit")


class ResponseStatus(SpsdkEnum):
    """ELE Message Response status enumeration.

    This enumeration defines the possible response status codes returned by ELE
    (EdgeLock Enclave) message operations, indicating success or failure of requests.
    """

    ELE_SUCCESS_IND = (0xD6, "Success", "The request was successful")
    ELE_FAILURE_IND = (0x29, "Failure", "The request failed")


class ResponseIndication(SpsdkSoftEnum):
    """ELE Message Response indication enumeration.

    This enumeration defines response indication codes returned by the EdgeLock Enclave (ELE)
    to indicate various failure conditions and error states during message processing.
    An indication returned together with a successful status represents a warning
    (e.g. a not-authenticated container accepted in open lifecycle).
    """

    ELE_ROM_PING_FAILURE_IND = (0x0A, "ELE_ROM_PING_FAILURE_IND", "ROM ping failure")
    ELE_FW_PING_FAILURE_IND = (0x1A, "ELE_FW_PING_FAILURE_IND", "Firmware ping failure")
    ELE_BAD_COMMAND_FAILURE_IND = (
        0x56,
        "ELE_BAD_COMMAND_FAILURE_IND",
        "Bad command: invalid parameters",
    )
    ELE_FASTBOOT_DISABLE_FAILURE_IND = (
        0x90,
        "ELE_FASTBOOT_DISABLE_FAILURE_IND",
        "Fastboot disable failure",
    )
    ELE_FASTBOOT_ILLEGAL_STATE_FAILURE_IND = (
        0x91,
        "ELE_FASTBOOT_ILLEGAL_STATE_FAILURE_IND",
        "Fastboot illegal state failure",
    )
    ELE_FW_AUTH_FAILURE_IND = (
        0x92,
        "ELE_FW_AUTH_FAILURE_IND",
        "Generic firmware authentication failure",
    )
    ELE_OEM_AUTH_FAILURE_IND = (
        0x93,
        "ELE_OEM_AUTH_FAILURE_IND",
        "Generic OEM authentication failure",
    )
    ELE_FAST_VERIFY_FAILURE_IND = (
        0x94,
        "ELE_FAST_VERIFY_FAILURE_IND",
        "Fast image verification failure",
    )
    ELE_UNALIGNED_PAYLOAD_FAILURE_IND = (
        0xA6,
        "ELE_UNALIGNED_PAYLOAD_FAILURE_IND",
        "Un-aligned payload failure",
    )
    ELE_WRONG_SIZE_FAILURE_IND = (0xA7, "ELE_WRONG_SIZE_FAILURE_IND", "Wrong size failure")
    ELE_ENCRYPTION_FAILURE_IND = (0xA8, "ELE_ENCRYPTION_FAILURE_IND", "Encryption failure")
    ELE_DECRYPTION_FAILURE_IND = (0xA9, "ELE_DECRYPTION_FAILURE_IND", "Decryption failure")
    ELE_OTP_PROGFAIL_FAILURE_IND = (
        0xAA,
        "ELE_OTP_PROGFAIL_FAILURE_IND",
        "OTP program fail failure",
    )
    ELE_OTP_LOCKED_FAILURE_IND = (0xAB, "ELE_OTP_LOCKED_FAILURE_IND", "OTP locked failure")
    ELE_OTP_INVALID_IDX_FAILURE_IND = (
        0xAD,
        "ELE_OTP_INVALID_IDX_FAILURE_IND",
        "OTP Invalid IDX failure",
    )
    ELE_TIME_OUT_FAILURE_IND = (0xB0, "ELE_TIME_OUT_FAILURE_IND", "Timeout failure")
    ELE_BAD_PAYLOAD_FAILURE_IND = (0xB1, "ELE_BAD_PAYLOAD_FAILURE_IND", "Bad payload failure")
    ELE_WRONG_ADDRESS_FAILURE_IND = (
        0xB4,
        "ELE_WRONG_ADDRESS_FAILURE_IND",
        "Wrong address failure",
    )
    ELE_DMA_FAILURE_IND = (0xB5, "ELE_DMA_FAILURE_IND", "DMA failure")
    ELE_DISABLED_FEATURE_FAILURE_IND = (
        0xB6,
        "ELE_DISABLED_FEATURE_FAILURE_IND",
        "Disabled feature failure",
    )
    ELE_MUST_ATTEST_FAILURE_IND = (0xB7, "ELE_MUST_ATTEST_FAILURE_IND", "Must attest failure")
    ELE_RNG_NOT_STARTED_FAILURE_IND = (
        0xB8,
        "ELE_RNG_NOT_STARTED_FAILURE_IND",
        "Random number generator not started failure",
    )
    ELE_CRC_ERROR_IND = (0xB9, "ELE_CRC_ERROR_IND", "CRC error")
    ELE_SENSOR_FAILURE_IND = (0xBA, "ELE_SENSOR_FAILURE_IND", "Sensor general error")
    ELE_AUTH_SKIPPED_OR_FAILED_FAILURE_IND = (
        0xBB,
        "ELE_AUTH_SKIPPED_OR_FAILED_FAILURE_IND",
        "Authentication skipped or failed",
    )
    ELE_INCONSISTENT_PAR_FAILURE_IND = (
        0xBC,
        "ELE_INCONSISTENT_PAR_FAILURE_IND",
        "Inconsistent parameter failure",
    )
    ELE_RNG_INST_FAILURE_IND = (
        0xBD,
        "ELE_RNG_INST_FAILURE_IND",
        "Random number generator instantiation failure",
    )
    ELE_LOCKED_REG_FAILURE_IND = (0xBE, "ELE_LOCKED_REG_FAILURE_IND", "Locked register failure")
    ELE_BAD_ID_FAILURE_IND = (0xBF, "ELE_BAD_ID_FAILURE_IND", "Bad ID failure")
    ELE_INVALID_OPERATION_FAILURE_IND = (
        0xC0,
        "ELE_INVALID_OPERATION_FAILURE_IND",
        "Invalid operation failure",
    )
    ELE_NON_SECURE_STATE_FAILURE_IND = (
        0xC1,
        "ELE_NON_SECURE_STATE_FAILURE_IND",
        "Non secure state failure",
    )
    ELE_MSG_TRUNCATED_IND = (0xC2, "ELE_MSG_TRUNCATED_IND", "Message truncated failure")
    ELE_BAD_IMAGE_NUM_FAILURE_IND = (
        0xC3,
        "ELE_BAD_IMAGE_NUM_FAILURE_IND",
        "Bad image number failure",
    )
    ELE_BAD_IMAGE_ADDR_FAILURE_IND = (
        0xC4,
        "ELE_BAD_IMAGE_ADDR_FAILURE_IND",
        "Bad image address failure",
    )
    ELE_BAD_IMAGE_PARAM_FAILURE_IND = (
        0xC5,
        "ELE_BAD_IMAGE_PARAM_FAILURE_IND",
        "Bad image parameters failure",
    )
    ELE_BAD_IMAGE_TYPE_FAILURE_IND = (
        0xC6,
        "ELE_BAD_IMAGE_TYPE_FAILURE_IND",
        "Bad image type failure",
    )
    ELE_RDC_FAILURE_IND = (0xC7, "ELE_RDC_FAILURE_IND", "RDC failure")
    ELE_FW_MISSING_FAILURE_IND = (
        0xCA,
        "ELE_FW_MISSING_FAILURE_IND",
        "Firmware is mandatory and missing",
    )
    ELE_APC_ALREADY_ENABLED_FAILURE_IND = (
        0xCB,
        "ELE_APC_ALREADY_ENABLED_FAILURE_IND",
        "APC already enabled failure",
    )
    ELE_RTC_ALREADY_ENABLED_FAILURE_IND = (
        0xCC,
        "ELE_RTC_ALREADY_ENABLED_FAILURE_IND",
        "RTC already enabled failure",
    )
    ELE_WRONG_BOOT_MODE_FAILURE_IND = (
        0xCD,
        "ELE_WRONG_BOOT_MODE_FAILURE_IND",
        "Wrong boot mode failure",
    )
    ELE_OLD_VERSION_FAILURE_IND = (0xCE, "ELE_OLD_VERSION_FAILURE_IND", "Old version failure")
    ELE_CSTM_FAILURE_IND = (0xCF, "ELE_CSTM_FAILURE_IND", "CSTM failure")
    ELE_CORRUPTED_SRK_FAILURE_IND = (
        0xD0,
        "ELE_CORRUPTED_SRK_FAILURE_IND",
        "Corrupted SRK failure",
    )
    ELE_OUT_OF_MEMORY_IND = (0xD1, "ELE_OUT_OF_MEMORY_IND", "Internal out of memory failure")
    ELE_UNSUPPORTED_TIMER_FAILURE_IND = (
        0xD2,
        "ELE_UNSUPPORTED_TIMER_FAILURE_IND",
        "Unsupported timer failure",
    )

    ELE_MUST_SIGNED_FAILURE_IND = (
        0xE0,
        "ELE_MUST_SIGNED_FAILURE_IND",
        "Must be signed failure",
    )
    ELE_BAD_ALGORITHM_FAILURE_IND = (
        0xE1,
        "ELE_BAD_ALGORITHM_FAILURE_IND",
        "Bad algorithm failure",
    )
    ELE_NO_AUTHENTICATION_FAILURE_IND = (
        0xEE,
        "ELE_NO_AUTHENTICATION_FAILURE_IND",
        "No authentication - container not authenticated (accepted in open lifecycle only);"
        " container is considered as unsigned",
    )
    ELE_BAD_SRK_SET_FAILURE_IND = (0xEF, "ELE_BAD_SRK_SET_FAILURE_IND", "Bad SRK set failure")
    ELE_BAD_SIGNATURE_FAILURE_IND = (
        0xF0,
        "ELE_BAD_SIGNATURE_FAILURE_IND",
        "Bad signature failure",
    )
    ELE_BAD_HASH_FAILURE_IND = (0xF1, "ELE_BAD_HASH_FAILURE_IND", "Bad hash failure")
    ELE_INVALID_LIFECYCLE_IND = (0xF2, "ELE_INVALID_LIFECYCLE_IND", "Invalid lifecycle")
    ELE_PERMISSION_DENIED_FAILURE_IND = (
        0xF3,
        "ELE_PERMISSION_DENIED_FAILURE_IND",
        "Permission denied failure",
    )
    ELE_INVALID_MESSAGE_FAILURE_IND = (
        0xF4,
        "ELE_INVALID_MESSAGE_FAILURE_IND",
        "Invalid message: content not well filled, message not supported by the loaded"
        " firmware, or ELE is in abort state",
    )
    ELE_BAD_VALUE_FAILURE_IND = (0xF5, "ELE_BAD_VALUE_FAILURE_IND", "Bad value failure")
    ELE_BAD_FUSE_ID_FAILURE_IND = (0xF6, "ELE_BAD_FUSE_ID_FAILURE_IND", "Bad fuse ID failure")
    ELE_BAD_CONTAINER_FAILURE_IND = (
        0xF7,
        "ELE_BAD_CONTAINER_FAILURE_IND",
        "Bad container failure",
    )
    ELE_BAD_VERSION_FAILURE_IND = (0xF8, "ELE_BAD_VERSION_FAILURE_IND", "Bad version failure")
    ELE_INVALID_KEY_FAILURE_IND = (
        0xF9,
        "ELE_INVALID_KEY_FAILURE_IND",
        "The key in the container is invalid or the SRK is revoked",
    )
    ELE_BAD_KEY_HASH_FAILURE_IND = (
        0xFA,
        "ELE_BAD_KEY_HASH_FAILURE_IND",
        "The key hash verification does not match OTP",
    )
    ELE_NO_VALID_CONTAINER_FAILURE_IND = (
        0xFB,
        "ELE_NO_VALID_CONTAINER_FAILURE_IND",
        "No valid container failure",
    )
    ELE_BAD_CERTIFICATE_FAILURE_IND = (
        0xFC,
        "ELE_BAD_CERTIFICATE_FAILURE_IND",
        "Bad certificate failure",
    )
    ELE_BAD_UID_FAILURE_IND = (0xFD, "ELE_BAD_UID_FAILURE_IND", "Bad UID failure")
    ELE_BAD_MONOTONIC_COUNTER_FAILURE_IND = (
        0xFE,
        "ELE_BAD_MONOTONIC_COUNTER_FAILURE_IND",
        "Bad monotonic counter failure",
    )
    ELE_ABORT_IND = (0xFF, "ELE_ABORT_IND", "Abort")


class HsmResponseIndication(SpsdkSoftEnum):
    """ELE HSM (SAB) Message Response indication enumeration.

    HSM API messages (session, key store, key management) report failures using the SAB
    rating codes instead of the baseline ELE response indications.
    """

    SAB_INVALID_MESSAGE = (
        0x01,
        "SAB_INVALID_MESSAGE",
        "The received message is invalid or unknown",
    )
    SAB_INVALID_ADDRESS = (
        0x02,
        "SAB_INVALID_ADDRESS",
        "The provided address is invalid or doesn't respect the API requirements",
    )
    SAB_UNKNOWN_ID = (0x03, "SAB_UNKNOWN_ID", "The provided identifier is not known")
    SAB_INVALID_PARAM = (
        0x04,
        "SAB_INVALID_PARAM",
        "Message unit sanity check failed or invalid parameters",
    )
    SAB_NVM_ERROR = (0x05, "SAB_NVM_ERROR", "NVM generic issue")
    SAB_OUT_OF_MEMORY = (
        0x06,
        "SAB_OUT_OF_MEMORY",
        "There is not enough memory to handle the requested operation",
    )
    SAB_UNKNOWN_HANDLE = (0x07, "SAB_UNKNOWN_HANDLE", "Unknown session or service handle")
    SAB_UNKNOWN_KEY_STORE = (
        0x08,
        "SAB_UNKNOWN_KEY_STORE",
        "The key store identified by the provided key store ID doesn't exist and the create"
        " flag is not set",
    )
    SAB_KEY_STORE_AUTH = (0x09, "SAB_KEY_STORE_AUTH", "Key store authentication fails")
    SAB_KEY_STORAGE_ERROR = (
        0x0A,
        "SAB_KEY_STORAGE_ERROR",
        "An error occurred in the key storage internal processing",
    )
    SAB_ID_CONFLICT = (
        0x0B,
        "SAB_ID_CONFLICT",
        "An element (key store, key...) with the provided ID already exists",
    )
    SAB_RNG_NOT_STARTED = (0x0C, "SAB_RNG_NOT_STARTED", "The internal RNG is not started")
    SAB_CMD_NOT_SUPPORTED = (
        0x0D,
        "SAB_CMD_NOT_SUPPORTED",
        "The functionality is not supported for the current session, service or key store"
        " configuration",
    )
    SAB_INVALID_LIFECYCLE = (
        0x0E,
        "SAB_INVALID_LIFECYCLE",
        "Invalid lifecycle for requested operation",
    )
    SAB_KEY_STORE_CONFLICT = (
        0x0F,
        "SAB_KEY_STORE_CONFLICT",
        "A key store with the same attributes already exists",
    )
    SAB_KEY_STORE_COUNTER = (
        0x10,
        "SAB_KEY_STORE_COUNTER",
        "An issue occurred while updating the key store counter",
    )
    SAB_FEATURE_NOT_SUPPORTED = (
        0x11,
        "SAB_FEATURE_NOT_SUPPORTED",
        "The HSM feature is not supported",
    )
    SAB_SELF_TEST_FAILURE = (
        0x12,
        "SAB_SELF_TEST_FAILURE",
        "An issue occurred during the self-test execution",
    )
    SAB_NOT_READY = (
        0x13,
        "SAB_NOT_READY",
        "HSM is not ready to provide the requested service (SAB Init not done)",
    )
    SAB_FEATURE_DISABLED = (0x14, "SAB_FEATURE_DISABLED", "The feature is currently disabled")
    SAB_KEY_GROUP_FULL = (
        0x19,
        "SAB_KEY_GROUP_FULL",
        "Not enough space to store the key in the key group",
    )
    SAB_CANNOT_RETRIEVE_KEY_GROUP = (
        0x1A,
        "SAB_CANNOT_RETRIEVE_KEY_GROUP",
        "Impossible to retrieve the key group",
    )
    SAB_KEY_NOT_SUPPORTED = (0x1B, "SAB_KEY_NOT_SUPPORTED", "Key not supported")
    SAB_CANNOT_DELETE_PERMANENT_KEY = (
        0x1C,
        "SAB_CANNOT_DELETE_PERMANENT_KEY",
        "Trying to delete a permanent key",
    )
    SAB_OUT_TOO_SMALL = (0x1D, "SAB_OUT_TOO_SMALL", "Output buffer size is too small")
    SAB_FATAL_FAILURE = (0xFF, "SAB_FATAL_FAILURE", "Fatal failure")


class EleFwStatus(SpsdkSoftEnum):
    """ELE Firmware status enumeration.

    This enumeration defines the possible states of the ELE (EdgeLock Enclave) firmware,
    indicating whether the firmware is properly authenticated and operational or not in place.
    """

    ELE_FW_STATUS_NOT_IN_PLACE = (0, "ELE_FW_STATUS_NOT_IN_PLACE", "Not in place")
    ELE_FW_STATUS_IN_PLACE = (1, "ELE_FW_STATUS_IN_PLACE", "Authenticated and operational")


class EleInfo2Commit(SpsdkSoftEnum):
    """ELE Information type to be committed.

    Enumeration of information types that can be committed to the EdgeLock Enclave (ELE).
    This class defines the available commitment options for both NXP and OEM containers,
    including SRK revocation and firmware fuse version settings.
    """

    NXP_SRK_REVOCATION = (0x1 << 0, "NXP_SRK_REVOCATION", "SRK revocation of the NXP container")
    NXP_FW_FUSE = (0x1 << 1, "NXP_FW_FUSE", "FW fuse version of the NXP container")
    OEM_SRK_REVOCATION = (0x1 << 4, "OEM_SRK_REVOCATION", "SRK revocation of the OEM container")
    OEM_FW_FUSE = (0x1 << 5, "OEM_FW_FUSE", "FW fuse version of the OEM container")


class KeyBlobEncryptionAlgorithm(SpsdkSoftEnum):
    """ELE KeyBlob encryption algorithm enumeration.

    This enumeration defines the supported encryption algorithms for KeyBlob operations
    in the EdgeLock Enclave (ELE), including AES and SM4 cipher modes.
    """

    AES_CBC = (0x03, "AES_CBC", "KeyBlob encryption algorithm AES CBC")
    AES_CTR = (0x04, "AES_CTR", "KeyBlob encryption algorithm AES CTR")
    AES_XTS = (0x37, "AES_XTS", "KeyBlob encryption algorithm AES XTS")
    SM4_CBC = (0x2B, "SM4_CBC", "KeyBlob encryption algorithm SM4 CBC")


class KeyBlobEncryptionIeeCtrModes(SpsdkSoftEnum):
    """IEE CTR mode enumeration for keyblob encryption.

    This enumeration defines the available AES CTR (Counter) modes for IEE (Inline Encryption Engine)
    keyblob encryption, including address binding options and keystream-only mode.
    """

    AesCTRWAddress = (0x02, "CTR_WITH_ADDRESS", " AES CTR w address binding mode")
    AesCTRWOAddress = (0x03, "CTR_WITHOUT_ADDRESS", " AES CTR w/o address binding mode")
    AesCTRkeystream = (0x04, "CTR_KEY_STREAM", "AES CTR keystream only")


class EleTrngState(SpsdkSoftEnum):
    """ELE TRNG (True Random Number Generator) state enumeration.

    This enumeration defines the possible states of the EdgeLock Enclave True Random
    Number Generator, providing status information for TRNG operations including
    initialization, entropy generation, and error conditions.
    """

    ELE_TRNG_NOT_READY = (
        0x0,
        "ELE_TRNG_NOT_READY",
        "True random generator not started yet. Use 'start-trng' command",
    )
    ELE_TRNG_PROGRAM = (0x1, "ELE_TRNG_PROGRAM", "TRNG is in program mode")
    ELE_TRNG_GENERATING_ENTROPY = (
        0x2,
        "ELE_TRNG_GENERATING_ENTROPY",
        "TRNG is still generating entropy",
    )
    ELE_TRNG_READY = (0x3, "ELE_TRNG_READY", "TRNG entropy is valid and ready to be read")
    ELE_TRNG_ERROR = (0x4, "ELE_TRNG_ERROR", "TRNG encounter an error while generating entropy")


class EleCsalState(SpsdkSoftEnum):
    """ELE CSAL state enumeration.

    Enumeration defining the possible states of EdgeLock secure enclave random context
    initialization (CSAL - Cryptographic Services Abstraction Layer).
    """

    ELE_CSAL_NOT_READY = (
        0x0,
        "ELE_CSAL_NOT_READY",
        "EdgeLock secure enclave random context initialization is not done yet",
    )
    ELE_CSAL_ON_GOING = (
        0x1,
        "ELE_CSAL_ON_GOING",
        "EdgeLock secure enclave random context initialization is on-going",
    )
    ELE_CSAL_READY = (
        0x2,
        "ELE_CSAL_READY",
        "EdgeLock secure enclave random context initialization succeed",
    )
    ELE_CSAL_ERROR = (
        0x3,
        "ELE_CSAL_ERROR",
        "EdgeLock secure enclave random context initialization failed",
    )
    ELE_CSAL_PAUSE = (
        0x4,
        "ELE_CSAL_PAUSE",
        "EdgeLock secure enclave random context initialization is in 'pause' mode",
    )


class EleImemState(SpsdkSoftEnum):
    """ELE IMEM state enumeration.

    This enumeration defines the possible states of the ELE (EdgeLock Enclave) IMEM
    (Instruction Memory) indicating whether the memory is fully loaded or has been
    lost during power transitions.
    """

    ELE_IMEM_LOADED = (
        0xCA,
        "ELE_IMEM_LOADED",
        "The IMEM is fully loaded and all ELE functionality can be used",
    )
    ELE_IMEM_LOST = (
        0xFE,
        "ELE_IMEM_LOST",
        (
            "Some IMEM regions have been lost during power down and fw "
            "must be re-installed to use all ELE features"
        ),
    )


class HseMessageIDs(SpsdkSoftEnum):
    """HSE Service Message IDs enumeration.

    This enumeration defines message identifiers for HSE (Hardware Security Engine) services
    including system management, key operations, cryptographic services, and firmware operations.
    Each entry contains the numeric ID, symbolic name, and description of the HSE service.
    """

    SET_ATTR = (0x00000001, "HSE_SRV_ID_SET_ATTR", "Set attribute service")
    GET_ATTR = (0x00A50002, "HSE_SRV_ID_GET_ATTR", "Get attribute service")
    CANCEL = (0x00A50004, "HSE_SRV_ID_CANCEL", "Cancel service")
    FIRMWARE_UPDATE = (0x00000005, "HSE_SRV_ID_FIRMWARE_UPDATE", "Firmware update service")
    SYS_AUTH_REQ = (0x00000006, "HSE_SRV_ID_SYS_AUTH_REQ", "System authorization request")
    SYS_AUTH_RESP = (0x00000007, "HSE_SRV_ID_SYS_AUTH_RESP", "System authorization response")
    BOOT_DATA_IMAGE_SIGN = (
        0x00000008,
        "HSE_SRV_ID_BOOT_DATA_IMAGE_SIGN",
        "Boot data image sign service",
    )
    BOOT_DATA_IMAGE_VERIFY = (
        0x00000009,
        "HSE_SRV_ID_BOOT_DATA_IMAGE_VERIFY",
        "Boot data image verify service",
    )
    IMPORT_EXPORT_STREAM_CTX = (
        0x00A5000A,
        "HSE_SRV_ID_IMPORT_EXPORT_STREAM_CTX",
        "Import/export stream context",
    )

    ERASE_HSE_NVM_DATA = (0x00000050, "HSE_SRV_ID_ERASE_HSE_NVM_DATA", "Erase HSE NVM data")
    ERASE_FW = (0x00000057, "HSE_SRV_ID_ERASE_FW", "Erase firmware")
    ACTIVATE_PASSIVE_BLOCK = (
        0x00000051,
        "HSE_SRV_ID_ACTIVATE_PASSIVE_BLOCK",
        "Activate passive block",
    )
    SBAF_UPDATE = (0x00000053, "HSE_SRV_ID_SBAF_UPDATE", "SBAF update service")
    FW_INTEGRITY_CHECK = (0x00000054, "HSE_SRV_ID_FW_INTEGRITY_CHECK", "Firmware integrity check")
    PUBLISH_NVM_KEYSTORE_RAM_TO_FLASH = (
        0x00000055,
        "HSE_SRV_ID_PUBLISH_NVM_KEYSTORE_RAM_TO_FLASH",
        "Publish NVM keystore RAM to flash",
    )
    CONFIG_COUNTER = (0x00000052, "HSE_SRV_ID_CONFIG_COUNTER", "Configure counter")

    LOAD_ECC_CURVE = (0x00000100, "HSE_SRV_ID_LOAD_ECC_CURVE", "Load ECC curve")
    FORMAT_KEY_CATALOGS = (0x00000101, "HSE_SRV_ID_FORMAT_KEY_CATALOGS", "Format key catalogs")
    ERASE_KEY = (0x00000102, "HSE_SRV_ID_ERASE_KEY", "Erase key")
    GET_KEY_INFO = (0x00A50103, "HSE_SRV_ID_GET_KEY_INFO", "Get key information")
    IMPORT_KEY = (0x00000104, "HSE_SRV_ID_IMPORT_KEY", "Import key")
    EXPORT_KEY = (0x00000105, "HSE_SRV_ID_EXPORT_KEY", "Export key")
    KEY_GENERATE = (0x00000106, "HSE_SRV_ID_KEY_GENERATE", "Generate key")
    KEY_DERIVE = (0x00000108, "HSE_SRV_ID_KEY_DERIVE", "Derive key")
    KEY_DERIVE_COPY = (0x00000109, "HSE_SRV_ID_KEY_DERIVE_COPY", "Derive key copy")
    KEY_VERIFY = (0x0000010B, "HSE_SRV_ID_KEY_VERIFY", "Verify key")

    SHE_LOAD_KEY = (0x0000A101, "HSE_SRV_ID_SHE_LOAD_KEY", "SHE load key")
    SHE_LOAD_PLAIN_KEY = (0x0000A102, "HSE_SRV_ID_SHE_LOAD_PLAIN_KEY", "SHE load plain key")
    SHE_EXPORT_RAM_KEY = (0x0000A103, "HSE_SRV_ID_SHE_EXPORT_RAM_KEY", "SHE export RAM key")
    SHE_GET_ID = (0x0000A104, "HSE_SRV_ID_SHE_GET_ID", "SHE get ID")
    SHE_BOOT_OK = (0x0000A105, "HSE_SRV_ID_SHE_BOOT_OK", "SHE boot OK")
    SHE_BOOT_FAILURE = (0x0000A106, "HSE_SRV_ID_SHE_BOOT_FAILURE", "SHE boot failure")

    HASH = (0x00A50200, "HSE_SRV_ID_HASH", "Hash service")
    MAC = (0x00A50201, "HSE_SRV_ID_MAC", "MAC service")
    FAST_CMAC = (0x00A50202, "HSE_SRV_ID_FAST_CMAC", "Fast CMAC service")
    SYM_CIPHER = (0x00A50203, "HSE_SRV_ID_SYM_CIPHER", "Symmetric cipher service")
    AEAD = (0x00A50204, "HSE_SRV_ID_AEAD", "AEAD service")
    RSA_CIPHER = (0x00000207, "HSE_SRV_ID_RSA_CIPHER", "RSA cipher service")

    GET_RANDOM_NUM = (0x00000300, "HSE_SRV_ID_GET_RANDOM_NUM", "Get random number")

    INCREMENT_COUNTER = (0x00A50400, "HSE_SRV_ID_INCREMENT_COUNTER", "Increment counter")
    READ_COUNTER = (0x00A50401, "HSE_SRV_ID_READ_COUNTER", "Read counter")

    SMR_ENTRY_INSTALL = (0x00000501, "HSE_SRV_ID_SMR_ENTRY_INSTALL", "SMR entry install")
    SMR_VERIFY = (0x00000502, "HSE_SRV_ID_SMR_VERIFY", "SMR verify")
    CORE_RESET_ENTRY_INSTALL = (
        0x00000503,
        "HSE_SRV_ID_CORE_RESET_ENTRY_INSTALL",
        "Core reset entry install",
    )
    ON_DEMAND_CORE_RESET = (0x00000504, "HSE_SRV_ID_ON_DEMAND_CORE_RESET", "On-demand core reset")
    SMR_ENTRY_ERASE = (0x00000505, "HSE_SRV_ID_SMR_ENTRY_ERASE", "SMR entry erase")
    CORE_RESET_ENTRY_ERASE = (
        0x00000506,
        "HSE_SRV_ID_CORE_RESET_ENTRY_ERASE",
        "Core reset entry erase",
    )


class HseResponseStatus(SpsdkEnum):
    """HSE service response status codes enumeration.

    This enumeration defines all possible response status codes returned by HSE (Hardware Security Engine)
    services, including success responses, verification failures, parameter errors, operation restrictions,
    and access failures. Each status code contains the numeric value, symbolic name, and description.
    """

    # Success response
    OK = (0x55A5AA33, "HSE_SRV_RSP_OK", "HSE service successfully executed with no error.")

    # Verification and parameter errors
    VERIFY_FAILED = (
        0x55A5A164,
        "HSE_SRV_RSP_VERIFY_FAILED",
        "HSE signals that a verification request fails (e.g. MAC and Signature verification).",
    )
    INVALID_ADDR = (0x55A5A26A, "HSE_SRV_RSP_INVALID_ADDR", "The address parameters are invalid.")
    INVALID_PARAM = (
        0x55A5A399,
        "HSE_SRV_RSP_INVALID_PARAM",
        "The HSE request parameters are invalid.",
    )

    # Operation restrictions
    NOT_SUPPORTED = (
        0xAA55A11E,
        "HSE_SRV_RSP_NOT_SUPPORTED",
        "The operation or feature not supported.",
    )
    NOT_ALLOWED = (
        0xAA55A21C,
        "HSE_SRV_RSP_NOT_ALLOWED",
        "The operation is not allowed because of some restrictions.",
    )
    NOT_ENOUGH_SPACE = (
        0xAA55A371,
        "HSE_SRV_RSP_NOT_ENOUGH_SPACE",
        "There is no enough space to perform service.",
    )

    # Access failures
    READ_FAILURE = (
        0xAA55A427,
        "HSE_SRV_RSP_READ_FAILURE",
        "The service request failed because read access was denied.",
    )
    WRITE_FAILURE = (
        0xAA55A517,
        "HSE_SRV_RSP_WRITE_FAILURE",
        "The service request failed because write access was denied.",
    )
    STREAMING_MODE_FAILURE = (
        0xAA55A6B1,
        "HSE_SRV_RSP_STREAMING_MODE_FAILURE",
        "The service request that uses streaming mode failed.",
    )

    # Key-related errors
    KEY_NOT_AVAILABLE = (
        0xA5AA51B2,
        "HSE_SRV_RSP_KEY_NOT_AVAILABLE",
        "Key is locked due to failed boot measurement or an active debugger.",
    )
    KEY_INVALID = (
        0xA5AA52B4,
        "HSE_SRV_RSP_KEY_INVALID",
        "The key usage flags don't allow to perform the requested crypto operation.",
    )
    KEY_EMPTY = (0xA5AA5317, "HSE_SRV_RSP_KEY_EMPTY", "Specified key slot is empty.")
    KEY_WRITE_PROTECTED = (
        0xA5AA5436,
        "HSE_SRV_RSP_KEY_WRITE_PROTECTED",
        "Key slot to be loaded is protected with WRITE PROTECTION restriction flag.",
    )
    KEY_UPDATE_ERROR = (
        0xA5AA5563,
        "HSE_SRV_RSP_KEY_UPDATE_ERROR",
        "Specified key slot cannot be updated due to errors in verification of the parameters.",
    )

    # General errors
    MEMORY_FAILURE = (
        0x33D6D136,
        "HSE_SRV_RSP_MEMORY_FAILURE",
        "Detect physical errors, flipped bits etc., during memory read or write operations.",
    )
    CANCEL_FAILURE = (0x33D6D261, "HSE_SRV_RSP_CANCEL_FAILURE", "The service can not be canceled.")
    CANCELED = (0x33D6D396, "HSE_SRV_RSP_CANCELED", "The service has been canceled.")
    GENERAL_ERROR = (
        0x33D6D4F1,
        "HSE_SRV_RSP_GENERAL_ERROR",
        "Error not covered by the other error codes is detected inside HSE.",
    )
    COUNTER_OVERFLOW = (
        0x33D6D533,
        "HSE_SRV_RSP_COUNTER_OVERFLOW",
        "The monotonic counter overflows.",
    )

    # SHE-specific errors
    SHE_NO_SECURE_BOOT = (
        0x33D6D623,
        "HSE_SRV_RSP_SHE_NO_SECURE_BOOT",
        "HSE did not perform SHE based secure Boot.",
    )
    SHE_BOOT_SEQUENCE_ERROR = (
        0x33D7D83A,
        "HSE_SRV_RSP_SHE_BOOT_SEQUENCE_ERROR",
        "Received SHE_BOOT_OK or SHE_BOOT_FAILURE more then one time.",
    )
    RNG_INIT_IN_PROGRESS = (
        0x33D7D92A,
        "HSE_SRV_RSP_RNG_INIT_IN_PROGRESS",
        "RNG Initialization is in Progress.",
    )

    # IPSEC-specific errors
    IPSEC_INVALID_DATA = (
        0xDD333133,
        "HSE_SRV_RSP_IPSEC_INVALID_DATA",
        "Invalid (malformed) IP packet.",
    )
    IPSEC_REPLAY_DETECTED = (
        0xDD3332DD,
        "HSE_SRV_RSP_IPSEC_REPLAY_DETECTED",
        "Valid packet but replay detected.",
    )
    IPSEC_REPLAY_LATE = (
        0xDD3333A5,
        "HSE_SRV_RSP_IPSEC_REPLAY_LATE",
        "Valid packet but frame late in sequence.",
    )
    IPSEC_SEQ_NUM_OVERFLOW = (
        0xDD33343D,
        "HSE_SRV_RSP_IPSEC_SEQNUM_OVERFLOW",
        "Sequence number overflow.",
    )
    IPSEC_CE_DROP = (0xDD33A15A, "HSE_SRV_RSP_IPSEC_CE_DROP", "Decap CE DROP (ECN issue) error.")
    IPSEC_TTL_EXCEEDED = (
        0xDD33A2D3,
        "HSE_SRV_RSP_IPSEC_TTL_EXCEEDED",
        "Packet decrypted but TTL exceeded.",
    )
    IPSEC_VALID_DUMMY_PAYLOAD = (
        0xDD33A3D5,
        "HSE_SRV_RSP_IPSEC_VALID_DUMMY_PAYLOAD",
        "Valid Dummy Payload (type 59).",
    )
    IPSEC_HEADER_LEN_OVERFLOW = (
        0xDD33A4D9,
        "HSE_SRV_RSP_IPSEC_HEADER_LEN_OVERFLOW",
        "Operation successful, but IPsec additions cause overflow of IP header length field.",
    )
    IPSEC_PADDING_CHECK_FAIL = (
        0xDD33A53A,
        "HSE_SRV_RSP_IPSEC_PADDING_CHECK_FAIL",
        "IPsec padding check error found.",
    )

    # Fuse-related errors
    FUSE_WRITE_FAILURE = (
        0xBB4456E7,
        "HSE_SRV_RSP_FUSE_WRITE_FAILURE",
        "Fuse write operation failed.",
    )
    FUSE_VDD_GND = (
        0xBB4457F3,
        "HSE_SRV_RSP_FUSE_VDD_GND",
        "EFUSE_VDD connected to ground during fuse write operation.",
    )

    # SBAF-related errors
    SBAF_UPDATE_REQUIRED = (
        0xCC66FEAD,
        "HSE_SRV_RSP_SBAF_UPDATE_REQUIRED",
        "Operation is dependent on Secure BAF version, which on the device happens to be old.",
    )
