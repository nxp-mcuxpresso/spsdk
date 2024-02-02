#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Error codes defined by the SDP protocol."""

from spsdk.utils.spsdk_enum import SpsdkEnum


########################################################################################################################
# SDP Status Codes (Errors)
########################################################################################################################
class StatusCode(SpsdkEnum):
    """SDP status codes."""

    SUCCESS = (0, "Success", "Success")
    CMD_FAILURE = (1, "CommandFailure", "Command Failure")
    HAB_IS_LOCKED = (2, "HabIsLocked", "HAB Is Locked")
    READ_DATA_FAILURE = (10, "ReadDataFailure", "Read Register/Data Failure")
    WRITE_REGISTER_FAILURE = (11, "WriteRegisterFailure", "Write Register Failure")
    WRITE_IMAGE_FAILURE = (12, "WriteImageFailure", "Write Image Failure")
    WRITE_DCD_FAILURE = (13, "WriteDcdFailure", "Write DCD Failure")
    WRITE_CSF_FAILURE = (14, "WriteCsfFailure", "Write CSF Failure")
    SKIP_DCD_HEADER_FAILURE = (15, "SkipDcdHeaderFailure", "Skip DCD Header Failure")


########################################################################################################################
# HAB Status Codes (Errors)
########################################################################################################################
class HabStatusInfo(SpsdkEnum):
    """HAB status codes."""

    UNKNOWN = (0x00, "UNKNOWN", "Unknown")
    WARNING = (0x69, "WARNING", "Warning")
    ERROR = (0x33, "ERROR", "Failure")
    SUCCESS = (0xF0, "SUCCESS", "Success")


class HabErrorReason(SpsdkEnum):
    """HAB Error Reason."""

    UNKNOWN = (0x00, "UNKNOWN", "Unknown Reason")
    ENGINE_FAILURE = (0x30, "ENGINE_FAILURE", "Engine Failure")
    INVALID_ADDRESS = (0x22, "INVALID_ADDRESS", "Invalid Address: Access Denied")
    INVALID_ASSERTION = (0x0C, "INVALID_ASSERTION", "Invalid Assertion")
    INVALID_CERTIFICATE = (0x21, "INVALID_CERTIFICATE", "Invalid Certificate")
    INVALID_COMMAND = (0x06, "INVALID_COMMAND", "Invalid Command: Malformed")
    INVALID_CSF = (0x11, "INVALID_CSF", "Invalid CSF")
    INVALID_DCD = (0x27, "INVALID_DCD", "Invalid DCD")
    INVALID_IVT = (0x05, "INVALID_IVT", "Invalid IVT")
    INVALID_KEY = (0x1D, "INVALID_KEY", "Invalid Key")
    INVALID_MAC = (0x32, "INVALID_MAC", "Invalid MAC")
    INVALID_BLOB = (0x31, "INVALID_BLOB", "Invalid Blob")
    INVALID_INDEX = (0x0F, "INVALID_INDEX", "Invalid Index: Access Denied")
    FAILED_CALLBACK = (0x1E, "FAILED_CALLBACK", "Failed Callback Function")
    INVALID_SIGNATURE = (0x18, "INVALID_SIGNATURE", "Invalid Signature")
    INVALID_DATA_SIZE = (0x17, "INVALID_DATA_SIZE", "Invalid Data Size")
    MEMORY_FAILURE = (0x2E, "MEMORY_FAILURE", "Memory Failure")
    CALL_OUT_OF_SEQUENCE = (0x28, "CALL_OUT_OF_SEQUENCE", "Function Called Out Of Sequence")
    EXPIRED_POLL_COUNT = (0x2B, "EXPIRED_POLL_COUNT", "Expired Poll Count")
    EXHAUSTED_STORAGE_REGION = (0x2D, "EXHAUSTED_STORAGE_REGION", "Exhausted Storage Region")
    UNSUPPORTED_ALGORITHM = (0x12, "UNSUPPORTED_ALGORITHM", "Unsupported Algorithm")
    UNSUPPORTED_COMMAND = (0x03, "UNSUPPORTED_COMMAND", "Unsupported Command")
    UNSUPPORTED_ENGINE = (0x0A, "UNSUPPORTED_ENGINE", "Unsupported Engine")
    UNSUPPORTED_CONF_ITEM = (0x24, "UNSUPPORTED_CONF_ITEM", "Unsupported Configuration Item")
    UNSUPPORTED_KEY_OR_PARAM = (
        0x1B,
        "UNSUPPORTED_KEY_OR_PARAM",
        "Unsupported Key Type or Parameters",
    )
    UNSUPPORTED_PROTOCOL = (0x14, "UNSUPPORTED_PROTOCOL", "Unsupported Protocol")
    UNSUITABLE_STATE = (0x09, "UNSUITABLE_STATE", "Unsuitable State")


class HabErrorContext(SpsdkEnum):
    """HAB Error Context."""

    HAB_CTX_ANY = (0x00, "HAB_CTX_ANY", "Match any context in hab_rvt.report_event()")
    HAB_FAB_TEST = (0xFF, "HAB_FAB_TEST", "Event logged in hab_fab_test()")
    HAB_RVT_ENTRY = (0xE1, "HAB_RVT_ENTRY", "Event logged in hab_rvt.entry()")
    RVT_CHECK_TARGET = (0x33, "RVT_CHECK_TARGET", "Event logged in hab_rvt.check_target()")
    RVT_AUTHENTICATE_IMG = (0x0A, "v", "Event logged in hab_rvt.authenticate_image()")
    RVT_RUN_DCD = (0xDD, "RVT_RUN_DCD", "Event logged in hab_rvt.run_dcd()")
    RVT_RUN_CSF = (0xCF, "RVT_RUN_CSF", "Event logged in hab_rvt.run_csf()")
    RVT_CSF_DCD_CMD = (0xC0, "RVT_CSF_DCD_CMD", "Event logged executing CSF or DCD command")
    RVT_ASSERT = (0xA0, "RVT_ASSERT", "Event logged in hab_rvt.assert()")
    RVT_EXIT = (0xEE, "RVT_EXIT", "Event logged in hab_rvt.exit()")
    AUTH_DATA_BLOCK = (0xDB, "AUTH_DATA_BLOCK", "Authenticated data block")
