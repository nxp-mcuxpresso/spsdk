#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Error codes defined by the SDP protocol."""

from spsdk.utils.easy_enum import Enum


########################################################################################################################
# SDP Status Codes (Errors)
########################################################################################################################
class StatusCode(Enum):
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
class HabStatusInfo(Enum):
    """HAB status codes."""

    UNKNOWN = (0x00, "Unknown")
    WARNING = (0x69, "Warning")
    ERROR = (0x33, "Failure")
    SUCCESS = (0xF0, "Success")


class HabErrorReason(Enum):
    """HAB Error Reason."""

    UNKNOWN = (0x00, "Unknown Reason")
    ENGINE_FAILURE = (0x30, "Engine Failure")
    INVALID_ADDRESS = (0x22, "Invalid Address: Access Denied")
    INVALID_ASSERTION = (0x0C, "Invalid Assertion")
    INVALID_CERTIFICATE = (0x21, "Invalid Certificate")
    INVALID_COMMAND = (0x06, "Invalid Command: Malformed")
    INVALID_CSF = (0x11, "Invalid CSF")
    INVALID_DCD = (0x27, "Invalid DCD")
    INVALID_IVT = (0x05, "Invalid IVT")
    INVALID_KEY = (0x1D, "Invalid Key")
    INVALID_MAC = (0x32, "Invalid MAC")
    INVALID_BLOB = (0x31, "Invalid Blob")
    INVALID_INDEX = (0x0F, "Invalid Index: Access Denied")
    FAILED_CALLBACK = (0x1E, "Failed Callback Function")
    INVALID_SIGNATURE = (0x18, "Invalid Signature")
    INVALID_DATA_SIZE = (0x17, "Invalid Data Size")
    MEMORY_FAILURE = (0x2E, "Memory Failure")
    CALL_OUT_OF_SEQUENCE = (0x28, "Function Called Out Of Sequence")
    EXPIRED_POLL_COUNT = (0x2B, "Expired Poll Count")
    EXHAUSTED_STORAGE_REGION = (0x2D, "Exhausted Storage Region")
    UNSUPPORTED_ALGORITHM = (0x12, "Unsupported Algorithm")
    UNSUPPORTED_COMMAND = (0x03, "Unsupported Command")
    UNSUPPORTED_ENGINE = (0x0A, "Unsupported Engine")
    UNSUPPORTED_CONF_ITEM = (0x24, "Unsupported Configuration Item")
    UNSUPPORTED_KEY_OR_PARAM = (0x1B, "Unsupported Key Type or Parameters")
    UNSUPPORTED_PROTOCOL = (0x14, "Unsupported Protocol")
    UNSUITABLE_STATE = (0x09, "Unsuitable State")


class HabErrorContext(Enum):
    """HAB Error Context."""

    HAB_CTX_ANY = (0x00, "Match any context in hab_rvt.report_event()")
    HAB_FAB_TEST = (0xFF, "Event logged in hab_fab_test()")
    HAB_RVT_ENTRY = (0xE1, "Event logged in hab_rvt.entry()")
    RVT_CHECK_TARGET = (0x33, "Event logged in hab_rvt.check_target()")
    RVT_AUTHENTICATE_IMG = (0x0A, "Event logged in hab_rvt.authenticate_image()")
    RVT_RUN_DCD = (0xDD, "Event logged in hab_rvt.run_dcd()")
    RVT_RUN_CSF = (0xCF, "Event logged in hab_rvt.run_csf()")
    RVT_CSF_DCD_CMD = (0xC0, "Event logged executing CSF or DCD command")
    RVT_ASSERT = (0xA0, "Event logged in hab_rvt.assert()")
    RVT_EXIT = (0xEE, "Event logged in hab_rvt.exit()")
    AUTH_DATA_BLOCK = (0xDB, "Authenticated data block")
