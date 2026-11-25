#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for SPSDK_WARNING_STRICT functionality (promote SPSDK warnings to errors)."""

import logging
import os
import subprocess
import sys
from collections.abc import Iterator
from unittest import mock

import pytest

from spsdk import (
    SPSDKWarningStrictHandler,
    configure_logging,
    get_logger,
    is_warning_strict,
    set_warning_strict,
)
from spsdk.apps.utils import spsdk_logger
from spsdk.exceptions import SPSDKError, SPSDKWarningError
from spsdk.utils.schema_validator import check_unknown_properties


def _strict_handlers() -> list[logging.Handler]:
    """Get all strict warning handlers installed on the 'spsdk' logger.

    :return: List of installed SPSDKWarningStrictHandler instances.
    """
    return [
        h for h in logging.getLogger("spsdk").handlers if isinstance(h, SPSDKWarningStrictHandler)
    ]


@pytest.fixture(name="warning_strict")
def fixture_warning_strict() -> Iterator[None]:
    """Enable strict warning mode for the test and restore the original state afterwards.

    :return: Iterator yielding once while strict mode is enabled.
    """
    original = is_warning_strict()
    set_warning_strict(True)
    try:
        yield
    finally:
        set_warning_strict(original)


def test_default_warning_is_only_logged(caplog: pytest.LogCaptureFixture) -> None:
    """Test that warnings are only logged when strict mode is disabled (default)."""
    assert not is_warning_strict()
    assert not _strict_handlers()
    logger = get_logger("spsdk.test.warning_strict.default")
    with caplog.at_level(logging.WARNING, logger="spsdk"):
        logger.warning("Default warning")
    assert "Default warning" in caplog.text


@pytest.mark.usefixtures("warning_strict")
def test_strict_warning_raises(caplog: pytest.LogCaptureFixture) -> None:
    """Test that a warning raises SPSDKWarningError and is still logged in strict mode."""
    logger = get_logger("spsdk.test.warning_strict.raise")
    with caplog.at_level(logging.WARNING, logger="spsdk"):
        with pytest.raises(SPSDKWarningError, match="Strict warning 42"):
            logger.warning("Strict warning %d", 42)  # pylint: disable=logging-too-many-args
    # warning must be dispatched to other handlers before raising
    assert "Strict warning 42" in caplog.text


@pytest.mark.usefixtures("warning_strict")
def test_strict_warning_is_spsdk_error() -> None:
    """Test that the promoted warning can be caught as a generic SPSDKError."""
    with pytest.raises(SPSDKError):
        logging.getLogger("spsdk.test.warning_strict.std_logger").warning("Std logger warning")


@pytest.mark.usefixtures("warning_strict")
def test_strict_does_not_affect_other_levels(caplog: pytest.LogCaptureFixture) -> None:
    """Test that strict mode does not affect trace, debug, info, error and critical messages."""
    logger = get_logger("spsdk.test.warning_strict.levels")
    with caplog.at_level(logging.DEBUG - 5, logger="spsdk"):
        logger.trace("Trace message")
        logger.debug("Debug message")
        logger.info("Info message")
        logger.error("Error message")
        logger.critical("Critical message")
    for message in ("Debug message", "Info message", "Error message", "Critical message"):
        assert message in caplog.text


@pytest.mark.usefixtures("warning_strict")
def test_strict_does_not_affect_non_spsdk_loggers() -> None:
    """Test that warnings from loggers outside the 'spsdk' namespace are not promoted."""
    logging.getLogger("other_package.module").warning("Foreign warning")


@pytest.mark.usefixtures("warning_strict")
def test_strict_respects_logger_level() -> None:
    """Test that a warning filtered out by a logger level is not promoted."""
    logger = get_logger("spsdk.test.warning_strict.filtered")
    original_level = logger.level
    logger.setLevel(logging.ERROR)
    try:
        logger.warning("Filtered warning")
    finally:
        logger.setLevel(original_level)


def test_set_warning_strict_toggle() -> None:
    """Test enabling/disabling strict mode at runtime does not duplicate the handler."""
    original = is_warning_strict()
    try:
        set_warning_strict(True)
        set_warning_strict(True)
        assert is_warning_strict()
        assert len(_strict_handlers()) == 1
        set_warning_strict(False)
        assert not is_warning_strict()
        assert not _strict_handlers()
        get_logger("spsdk.test.warning_strict.toggle").warning("No raise after disable")
    finally:
        set_warning_strict(original)


@pytest.mark.usefixtures("warning_strict")
def test_strict_survives_install() -> None:
    """Test that the strict handler stays installed after spsdk_logger.install()."""
    spsdk_logger.install(level=logging.WARNING, create_debug_logger=False)
    assert len(_strict_handlers()) == 1
    with pytest.raises(SPSDKWarningError):
        get_logger("spsdk.test.warning_strict.install").warning("After install")


@pytest.mark.usefixtures("warning_strict")
def test_strict_survives_configure_logging() -> None:
    """Test that the strict handler is re-installed after configure_logging() (dictConfig)."""
    spsdk_root = logging.getLogger("spsdk")
    original_handlers = list(spsdk_root.handlers)
    original_level = spsdk_root.level
    original_propagate = spsdk_root.propagate
    try:
        configure_logging(
            {
                "version": 1,
                "disable_existing_loggers": False,
                "loggers": {"spsdk": {"level": "DEBUG", "handlers": [], "propagate": True}},
            }
        )
        assert len(_strict_handlers()) == 1
        with pytest.raises(SPSDKWarningError):
            get_logger("spsdk.test.warning_strict.dict_config").warning("After dictConfig")
    finally:
        spsdk_root.handlers = original_handlers
        spsdk_root.setLevel(original_level)
        spsdk_root.propagate = original_propagate


@pytest.mark.usefixtures("warning_strict")
def test_strict_no_double_raise_with_schema_strict() -> None:
    """Test that SPSDK_SCHEMA_STRICT still raises its own error and is not duplicated."""
    schema = {"type": "object", "properties": {"known": {"type": "string"}}}
    with mock.patch("spsdk.utils.schema_validator.SPSDK_SCHEMA_STRICT", True):
        with pytest.raises(SPSDKError) as exc_info:
            check_unknown_properties({"unknown": 1}, schema)
    # Raised directly by schema strict check, not by the promoted warning
    assert not isinstance(exc_info.value, SPSDKWarningError)


@pytest.mark.usefixtures("warning_strict")
def test_strict_promotes_schema_warning() -> None:
    """Test that a regular SPSDK warning (unknown config property) is promoted in strict mode."""
    schema = {"type": "object", "properties": {"known": {"type": "string"}}}
    with mock.patch("spsdk.utils.schema_validator.SPSDK_SCHEMA_STRICT", False):
        with pytest.raises(SPSDKWarningError, match="Unknown property"):
            check_unknown_properties({"unknown": 1}, schema)


@pytest.mark.parametrize(
    "env_value,expected",
    [("1", True), ("True", True), ("0", False), ("", False)],
)
def test_env_variable_enables_strict(env_value: str, expected: bool) -> None:
    """Test that the SPSDK_WARNING_STRICT environment variable is evaluated on import.

    :param env_value: Value of the environment variable.
    :param expected: Expected strict mode state.
    """
    env = dict(os.environ, SPSDK_WARNING_STRICT=env_value)
    code = (
        "import logging, spsdk, spsdk.exceptions\n"
        "print(spsdk.SPSDK_WARNING_STRICT, spsdk.is_warning_strict())\n"
        "try:\n"
        "    logging.getLogger('spsdk.x').warning('w')\n"
        "    print('logged')\n"
        "except spsdk.exceptions.SPSDKWarningError:\n"
        "    print('raised')\n"
    )
    result = subprocess.run(  # nosec B603
        [sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True
    )
    lines = result.stdout.strip().splitlines()
    assert lines[0] == f"{expected} {expected}"
    assert lines[1] == ("raised" if expected else "logged")
