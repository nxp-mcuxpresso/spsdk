#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Comprehensive pytest tests for nxpdebugmbox CLI application.

Tests cover all command groups and subcommands using --help invocations and
hardware-free subcommands (get-families, get-template, etc.) to maximize
code coverage without requiring real debug probe hardware.
"""

import contextlib
import os
import struct
from collections.abc import Iterator
from unittest.mock import MagicMock

import pytest
from typing_extensions import Never

import spsdk.apps.nxpdebugmbox as nxpdebugmbox
from spsdk.apps.nxpdebugmbox import (
    DebugMailboxParams,
    DebugProbeParams,
    list_probes,
    main,
    read_from_flash,
    reset,
)
from spsdk.apps.nxpdebugmbox import test_connection as nxpdebugmbox_test_connection
from spsdk.apps.utils.utils import SPSDKAppError
from spsdk.exceptions import SPSDKError
from spsdk.utils.family import FamilyRevision
from tests.cli_runner import CliRunner
from tests.debuggers.debug_probe_virtual import DebugProbeVirtual

# Family used for hardware-free template/family tests
DAT_FAMILY = "lpc55s69"


# ---------------------------------------------------------------------------
# Top-level tests
# ---------------------------------------------------------------------------


def test_nxpdebugmbox_help(cli_runner: CliRunner) -> None:
    """Test top-level --help output."""
    result = cli_runner.invoke(main, ["--help"])
    assert "Show this message and exit." in result.output


def test_nxpdebugmbox_get_families(cli_runner: CliRunner) -> None:
    """Test top-level get-families command."""
    result = cli_runner.invoke(main, ["get-families"])
    assert result.output  # Should list supported families


@pytest.mark.parametrize(
    ("root_options", "expected_reset"),
    [
        ([], True),
        (["-n"], False),
        (["--no-reset"], False),
    ],
)
def test_nxpdebugmbox_no_reset_option(
    cli_runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
    root_options: list[str],
    expected_reset: bool,
) -> None:
    """Test root --no-reset option controls debug mailbox reset."""
    captured: dict[str, bool] = {}

    def fake_famode(
        _family: FamilyRevision,
        _debug_probe_params: DebugProbeParams,
        debug_mailbox_params: DebugMailboxParams,
        _message: str,
    ) -> None:
        captured["reset"] = debug_mailbox_params.reset

    monkeypatch.setattr("spsdk.apps.nxpdebugmbox.famode", fake_famode)

    cli_runner.invoke(main, [*root_options, "cmd", "-f", "kw47b42zb7", "famode"])

    assert captured["reset"] is expected_reset


# ---------------------------------------------------------------------------
# famode-image group
# ---------------------------------------------------------------------------


def test_famode_image_help(cli_runner: CliRunner) -> None:
    """Test famode-image group --help."""
    result = cli_runner.invoke(main, ["famode-image", "--help"])
    assert "Show this message and exit." in result.output


@pytest.mark.parametrize(
    "subcommand",
    ["export", "parse", "get-templates"],
)
def test_famode_image_subcommands_help(cli_runner: CliRunner, subcommand: str) -> None:
    """Test famode-image subcommand --help outputs."""
    result = cli_runner.invoke(main, ["famode-image", subcommand, "--help"])
    assert "Show this message and exit." in result.output


def test_famode_image_get_families(cli_runner: CliRunner) -> None:
    """Test famode-image get-families lists supported families."""
    result = cli_runner.invoke(main, ["famode-image", "get-families"])
    assert result.output


# ---------------------------------------------------------------------------
# dat group
# ---------------------------------------------------------------------------


def test_dat_help(cli_runner: CliRunner) -> None:
    """Test dat group --help."""
    result = cli_runner.invoke(main, ["dat", "--help"])
    assert "Show this message and exit." in result.output


def test_dat_auth_help(cli_runner: CliRunner) -> None:
    """Test dat auth --help."""
    result = cli_runner.invoke(main, ["dat", "auth", "--help"])
    assert "Show this message and exit." in result.output


def test_dat_auth_debug_artifacts_option(cli_runner: CliRunner) -> None:
    """The dat auth command exposes the --debug-artifacts / -da option."""
    result = cli_runner.invoke(main, ["dat", "auth", "--help"])
    assert "--debug-artifacts" in result.output
    assert "-da" in result.output
    assert "DAC and signed DAR binaries" in result.output


def test_dat_export_dar_help(cli_runner: CliRunner) -> None:
    """The dat export-dar command exposes its required input options."""
    result = cli_runner.invoke(main, ["dat", "export-dar", "--help"])
    assert "--config" in result.output
    assert "--dac" in result.output
    assert "--output" in result.output


def test_dat_export_dar(monkeypatch: pytest.MonkeyPatch, tmp_path: str) -> None:
    """The DAR export helper writes the generated binary without a debug probe."""
    config = MagicMock()
    family = MagicMock()
    dac = MagicMock()
    dar = MagicMock()
    verifier = MagicMock(has_errors=False)
    dar.verify.return_value = verifier
    dar.export.return_value = b"dar-data"
    output_path = os.path.join(str(tmp_path), "dar.bin")

    monkeypatch.setattr(nxpdebugmbox.FamilyRevision, "load_from_config", lambda _: family)
    monkeypatch.setattr(nxpdebugmbox.DebugAuthenticationChallenge, "parse", lambda *_, **__: dac)
    dar_class = MagicMock(load_from_config=lambda **_: dar)
    monkeypatch.setattr(nxpdebugmbox.DebugAuthenticateResponse, "_get_class", lambda *_: dar_class)
    monkeypatch.setattr(nxpdebugmbox, "load_binary", lambda _: b"dac-data")
    nxpdebugmbox.export_dar(config=config, dac_path="dac.bin", output=output_path)

    assert os.path.isfile(output_path)
    with open(output_path, "rb") as output_file:
        assert output_file.read() == b"dar-data"


def test_dat_auth_missing_file_fails(cli_runner: CliRunner) -> None:
    """Test dat auth with a missing config file returns non-zero exit code."""
    cli_runner.invoke(
        main,
        ["dat", "auth", "--config", "/nonexistent/path/dat_auth.yaml"],
        expected_code=-1,
    )


def test_dat_get_template(cli_runner: CliRunner, tmp_path: str) -> None:
    """Test dat get-template generates YAML template without hardware."""
    out_file = os.path.join(str(tmp_path), "dat_template.yaml")
    cli_runner.invoke(
        main,
        ["dat", "get-template", "--family", DAT_FAMILY, "-o", out_file],
    )
    assert os.path.isfile(out_file)


def test_dat_get_template_help(cli_runner: CliRunner) -> None:
    """Test dat get-template --help."""
    result = cli_runner.invoke(main, ["dat", "get-template", "--help"])
    assert "Show this message and exit." in result.output


def test_dat_get_families(cli_runner: CliRunner) -> None:
    """Test dat get-families lists supported families."""
    result = cli_runner.invoke(main, ["dat", "get-families"])
    assert result.output


# dat dc sub-group
def test_dat_dc_help(cli_runner: CliRunner) -> None:
    """Test dat dc group --help."""
    result = cli_runner.invoke(main, ["dat", "dc", "--help"])
    assert "Show this message and exit." in result.output


@pytest.mark.parametrize("subcommand", ["export", "get-template"])
def test_dat_dc_subcommands_help(cli_runner: CliRunner, subcommand: str) -> None:
    """Test dat dc subcommand --help."""
    result = cli_runner.invoke(main, ["dat", "dc", subcommand, "--help"])
    assert "Show this message and exit." in result.output


def test_dat_dc_get_families(cli_runner: CliRunner) -> None:
    """Test dat dc get-families lists supported families."""
    result = cli_runner.invoke(main, ["dat", "dc", "get-families"])
    assert result.output


def test_dat_dc_get_template(cli_runner: CliRunner, tmp_path: str) -> None:
    """Test dat dc get-template generates a template YAML."""
    out_file = os.path.join(str(tmp_path), "dc_template.yaml")
    cli_runner.invoke(
        main,
        ["dat", "dc", "get-template", "--family", DAT_FAMILY, "-o", out_file],
    )
    assert os.path.isfile(out_file)


# ---------------------------------------------------------------------------
# mem-tool group
# ---------------------------------------------------------------------------


def test_mem_tool_help(cli_runner: CliRunner) -> None:
    """Test mem-tool group --help."""
    result = cli_runner.invoke(main, ["mem-tool", "--help"])
    assert "Show this message and exit." in result.output


@pytest.mark.parametrize("subcommand", ["read-memory", "write-memory", "test-connection"])
def test_mem_tool_subcommands_help(cli_runner: CliRunner, subcommand: str) -> None:
    """Test mem-tool subcommand --help."""
    result = cli_runner.invoke(main, ["mem-tool", subcommand, "--help"])
    assert "Show this message and exit." in result.output


def test_mem_tool_get_families(cli_runner: CliRunner) -> None:
    """Test mem-tool get-families lists supported families."""
    result = cli_runner.invoke(main, ["mem-tool", "get-families"])
    assert result.output


def test_mem_tool_test_connection_failure_returns_false(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test mem-tool test_connection returns False on probe/open failures.

    This is a regression test for user-facing behavior: failures during probe
    opening should not bubble up as SPSDKAppError from the helper function.
    """

    @contextlib.contextmanager
    def failing_open_debug_probe(*args: object, **kwargs: object) -> Iterator[Never]:
        raise SPSDKError("The memory access port is not found!")

    monkeypatch.setattr("spsdk.apps.nxpdebugmbox.open_debug_probe", failing_open_debug_probe)
    debug_probe_params = DebugProbeParams(
        interface="virtual", serial_no="dummy", debug_probe_user_params={}
    )

    result = nxpdebugmbox_test_connection(
        family=FamilyRevision(name=DAT_FAMILY),
        debug_probe_params=debug_probe_params,
        destination="cpu_mem",
    )

    assert result is False


def test_mem_tool_test_connection_command_failure_has_nonzero_exit(
    cli_runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """mem-tool test-connection command returns non-zero exit code on failure."""

    monkeypatch.setattr("spsdk.apps.nxpdebugmbox.test_connection", lambda *args, **kwargs: False)

    cmd = [
        "-i",
        "virtual",
        "-s",
        DebugProbeVirtual.UNIQUE_SERIAL,
        "mem-tool",
        "test-connection",
        "-f",
        DAT_FAMILY,
    ]
    cli_runner.invoke(main, cmd, expected_code=1)


def test_mem_tool_test_connection_shows_debug_access_status_table_on_failure(
    cli_runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """mem-tool test-connection always prints the gating status table on failure."""
    monkeypatch.setattr("spsdk.apps.nxpdebugmbox.test_ahb_access", lambda probe: False)
    cmd = [
        "-i",
        "virtual",
        "-s",
        DebugProbeVirtual.UNIQUE_SERIAL,
        "mem-tool",
        "test-connection",
        "-f",
        DAT_FAMILY,
    ]

    result = cli_runner.invoke(main, cmd, expected_code=1)

    assert "System bus (AHB) access" in result.output
    assert "Debug Port IDR readable" in result.output


def test_mem_tool_test_connection_debug_port_destination_limits_table_depth(
    cli_runner: CliRunner,
) -> None:
    """mem-tool test-connection -d debug_port only shows the first two gates."""
    cmd = [
        "-i",
        "virtual",
        "-s",
        DebugProbeVirtual.UNIQUE_SERIAL,
        "mem-tool",
        "test-connection",
        "-f",
        DAT_FAMILY,
        "-d",
        "debug_port",
    ]

    result = cli_runner.invoke(main, cmd)

    assert "successfully" in result.output


def test_connection_logs_table_on_success(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """test_connection() logs the debug-access status table at INFO level on success."""
    fake_probe = MagicMock(
        spec=[
            "connect_safe",
            "debug_access_status",
            "DEBUG_ACCESS_STATUS_LABELS",
            "get_not_applicable_debug_access_gates",
            "get_never_tested_debug_access_gates",
        ]
    )
    fake_probe.debug_access_status = {
        "probe_opened": True,
        "probe_connected": True,
        "dp_idr_ok": True,
    }
    fake_probe.DEBUG_ACCESS_STATUS_LABELS = {
        "probe_opened": "Debug probe opened",
        "probe_connected": "Probe attached to target",
        "dp_idr_ok": "Debug Port IDR readable",
    }
    fake_probe.get_not_applicable_debug_access_gates.return_value = set()
    fake_probe.get_never_tested_debug_access_gates.return_value = set()

    @contextlib.contextmanager
    def fake_open_debug_probe(*args: object, **kwargs: object) -> Iterator[MagicMock]:
        yield fake_probe

    monkeypatch.setattr("spsdk.apps.nxpdebugmbox.open_debug_probe", fake_open_debug_probe)
    monkeypatch.setattr("spsdk.apps.nxpdebugmbox.test_ahb_access", lambda probe: True)
    debug_probe_params = DebugProbeParams(
        interface="virtual", serial_no=DebugProbeVirtual.UNIQUE_SERIAL, debug_probe_user_params={}
    )

    caplog.set_level("INFO", logger="spsdk.apps.nxpdebugmbox")
    result = nxpdebugmbox_test_connection(
        family=FamilyRevision(name=DAT_FAMILY),
        debug_probe_params=debug_probe_params,
        destination="cpu_mem",
    )

    assert result is True
    assert any("Debug-access gating status" in record.message for record in caplog.records)


def test_connection_shows_table_when_connect_safe_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """test_connection() still prints the gating table when connect_safe() itself fails.

    Regression test: on real hardware, unplugging the SWD/JTAG connector before running
    ``mem-tool test-connection`` made ``connect_safe()`` raise before the inner try/finally
    that renders the table was entered, so the table was silently skipped even though
    ``debug_access_status["probe_connected"]`` was already correctly recorded as False.
    """
    fake_probe = MagicMock(
        spec=[
            "connect_safe",
            "debug_access_status",
            "DEBUG_ACCESS_STATUS_LABELS",
            "get_not_applicable_debug_access_gates",
            "get_never_tested_debug_access_gates",
        ]
    )
    fake_probe.debug_access_status = {
        "probe_opened": True,
        "probe_connected": False,
        "dp_idr_ok": None,
    }
    fake_probe.DEBUG_ACCESS_STATUS_LABELS = {
        "probe_opened": "Debug probe opened",
        "probe_connected": "Probe attached to target",
        "dp_idr_ok": "Debug Port IDR readable",
    }
    fake_probe.connect_safe.side_effect = SPSDKError("SWD connector disconnected")
    fake_probe.get_not_applicable_debug_access_gates.return_value = set()
    fake_probe.get_never_tested_debug_access_gates.return_value = set()

    @contextlib.contextmanager
    def fake_open_debug_probe(*args: object, **kwargs: object) -> Iterator[MagicMock]:
        yield fake_probe

    monkeypatch.setattr("spsdk.apps.nxpdebugmbox.open_debug_probe", fake_open_debug_probe)
    echoed: list[str] = []
    monkeypatch.setattr("spsdk.apps.nxpdebugmbox.click.echo", echoed.append)
    debug_probe_params = DebugProbeParams(
        interface="virtual", serial_no=DebugProbeVirtual.UNIQUE_SERIAL, debug_probe_user_params={}
    )

    result = nxpdebugmbox_test_connection(
        family=FamilyRevision(name=DAT_FAMILY),
        debug_probe_params=debug_probe_params,
        destination="cpu_mem",
    )

    assert result is False
    assert any("Probe attached to target" in text for text in echoed)


# ---------------------------------------------------------------------------
# tool group
# ---------------------------------------------------------------------------


def test_tool_help(cli_runner: CliRunner) -> None:
    """Test tool group --help."""
    result = cli_runner.invoke(main, ["tool", "--help"])
    assert "Show this message and exit." in result.output


@pytest.mark.parametrize(
    "subcommand", ["reset", "get-uuid", "halt", "resume", "execute", "list-probes"]
)
def test_tool_subcommands_help(cli_runner: CliRunner, subcommand: str) -> None:
    """Test tool subcommand --help."""
    result = cli_runner.invoke(main, ["tool", subcommand, "--help"])
    assert "Show this message and exit." in result.output


def test_tool_get_families(cli_runner: CliRunner) -> None:
    """Test tool get-families lists supported families."""
    result = cli_runner.invoke(main, ["tool", "get-families"])
    assert result.output


def test_tool_reset_uses_debug_mailbox_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test tool reset uses DebugMailbox reset by default."""
    calls: list[bool] = []

    def fail_perform_reset(*args: object, **kwargs: object) -> None:
        raise AssertionError("Generic debug probe reset must not be used by default")

    @contextlib.contextmanager
    def fake_open_debugmbox(
        family: FamilyRevision,
        debug_probe_params: DebugProbeParams,
        debug_mailbox_params: DebugMailboxParams,
    ) -> Iterator[None]:
        calls.append(debug_mailbox_params.reset)
        yield None

    monkeypatch.setattr("spsdk.apps.nxpdebugmbox._open_debugmbox", fake_open_debugmbox)
    monkeypatch.setattr("spsdk.apps.nxpdebugmbox.perform_reset", fail_perform_reset)
    debug_probe_params = DebugProbeParams(
        interface="virtual", serial_no="dummy", debug_probe_user_params={}
    )
    debug_mailbox_params = DebugMailboxParams(reset=False, more_delay=0.0, operation_timeout=1000)

    reset(
        family=FamilyRevision(name="mimxrt1166"),
        debug_probe_params=debug_probe_params,
        debug_mailbox_params=debug_mailbox_params,
        hard_reset=False,
    )

    assert calls == [True]


@pytest.mark.parametrize(
    ("hard_reset", "nvic_reset", "expected_nvic"),
    [(True, False, False), (False, True, True)],
)
def test_tool_reset_forces_requested_reset_type(
    monkeypatch: pytest.MonkeyPatch,
    hard_reset: bool,
    nvic_reset: bool,
    expected_nvic: bool,
) -> None:
    """Test tool reset forwards explicitly selected reset type."""
    calls: list[bool | None] = []

    class FakeProbe:
        """Fake debug probe for reset test."""

    @contextlib.contextmanager
    def fake_open_debug_probe(*args: object, **kwargs: object) -> Iterator[FakeProbe]:
        yield FakeProbe()

    def fake_perform_reset(
        debug_probe: FakeProbe, family: FamilyRevision, nvic: bool | None = None
    ) -> None:
        calls.append(nvic)

    def fail_open_debugmbox(*args: object, **kwargs: object) -> Iterator[Never]:
        raise AssertionError("DebugMailbox reset must not be used for explicit reset type")

    monkeypatch.setattr("spsdk.apps.nxpdebugmbox.open_debug_probe", fake_open_debug_probe)
    monkeypatch.setattr("spsdk.apps.nxpdebugmbox._open_debugmbox", fail_open_debugmbox)
    monkeypatch.setattr("spsdk.apps.nxpdebugmbox.perform_reset", fake_perform_reset)
    debug_probe_params = DebugProbeParams(
        interface="virtual", serial_no="dummy", debug_probe_user_params={}
    )
    debug_mailbox_params = DebugMailboxParams(reset=False, more_delay=0.0, operation_timeout=1000)

    reset(
        family=FamilyRevision(name="mimxrt1166"),
        debug_probe_params=debug_probe_params,
        debug_mailbox_params=debug_mailbox_params,
        hard_reset=hard_reset,
        nvic_reset=nvic_reset,
    )

    assert calls == [expected_nvic]


def _make_vector_table(sp: int, pc: int, padding: bytes = b"\x00" * 8) -> bytes:
    """Build a minimal fake Cortex-M vector table (offset 0=SP, offset 4=PC/Reset_Handler)."""
    return struct.pack("<II", sp, pc) + padding


def test_tool_execute_writes_binary_sets_registers_and_resumes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """execute() writes the binary, sets PC/SP from the vector table, and resumes the core."""
    binary = _make_vector_table(sp=0x2004_0000, pc=0x2000_0101)

    fake_probe = MagicMock(spec=nxpdebugmbox.DebugProbeCoreSightOnly)

    @contextlib.contextmanager
    def fake_open_debug_probe(*args: object, **kwargs: object) -> Iterator[MagicMock]:
        yield fake_probe

    monkeypatch.setattr("spsdk.apps.nxpdebugmbox.open_debug_probe", fake_open_debug_probe)
    debug_probe_params = DebugProbeParams(
        interface="virtual", serial_no=DebugProbeVirtual.UNIQUE_SERIAL, debug_probe_user_params={}
    )

    nxpdebugmbox.execute(
        family=FamilyRevision(name=DAT_FAMILY),
        debug_probe_params=debug_probe_params,
        address=0x2000_0000,
        data=binary,
    )

    fake_probe.mem_block_write.assert_called_once_with(addr=0x2000_0000, data=binary)
    fake_probe.set_registers_and_resume.assert_called_once_with(pc=0x2000_0101, sp=0x2004_0000)


def test_tool_execute_without_binary_reads_vector_table_from_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """execute() with no binary reads the existing vector table from ADDRESS on the target.

    This covers the "restart an already-flashed bootable image" use case, e.g. reissuing
    execution from a boot address such as 0x0 on LPC devices, without writing anything.
    """
    existing_vector_table = _make_vector_table(sp=0x2000_8000, pc=0x0000_0201)

    fake_probe = MagicMock(spec=nxpdebugmbox.DebugProbeCoreSightOnly)
    fake_probe.mem_block_read.return_value = existing_vector_table

    @contextlib.contextmanager
    def fake_open_debug_probe(*args: object, **kwargs: object) -> Iterator[MagicMock]:
        yield fake_probe

    monkeypatch.setattr("spsdk.apps.nxpdebugmbox.open_debug_probe", fake_open_debug_probe)
    debug_probe_params = DebugProbeParams(
        interface="virtual", serial_no=DebugProbeVirtual.UNIQUE_SERIAL, debug_probe_user_params={}
    )

    nxpdebugmbox.execute(
        family=FamilyRevision(name=DAT_FAMILY),
        debug_probe_params=debug_probe_params,
        address=0x0,
    )

    fake_probe.mem_block_read.assert_called_once_with(addr=0x0, size=8)
    fake_probe.mem_block_write.assert_not_called()
    fake_probe.set_registers_and_resume.assert_called_once_with(pc=0x0000_0201, sp=0x2000_8000)


def test_tool_execute_explicit_pc_sp_override_binary_vector_table(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """execute() prefers explicit --pc/--sp over the binary's vector table (with a warning)."""
    binary = _make_vector_table(sp=0x2004_0000, pc=0x2000_0101)

    fake_probe = MagicMock(spec=nxpdebugmbox.DebugProbeCoreSightOnly)

    @contextlib.contextmanager
    def fake_open_debug_probe(*args: object, **kwargs: object) -> Iterator[MagicMock]:
        yield fake_probe

    monkeypatch.setattr("spsdk.apps.nxpdebugmbox.open_debug_probe", fake_open_debug_probe)
    debug_probe_params = DebugProbeParams(
        interface="virtual", serial_no=DebugProbeVirtual.UNIQUE_SERIAL, debug_probe_user_params={}
    )

    nxpdebugmbox.execute(
        family=FamilyRevision(name=DAT_FAMILY),
        debug_probe_params=debug_probe_params,
        address=0x2000_0000,
        data=binary,
        pc=0x2000_0200,
        sp=0x2004_8000,
    )

    fake_probe.set_registers_and_resume.assert_called_once_with(pc=0x2000_0200, sp=0x2004_8000)


def test_tool_execute_requires_pc_sp_when_binary_too_small(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """execute() raises SPSDKAppError if the binary has no vector table and --pc/--sp are missing."""
    fake_probe = MagicMock(spec=nxpdebugmbox.DebugProbeCoreSightOnly)

    @contextlib.contextmanager
    def fake_open_debug_probe(*args: object, **kwargs: object) -> Iterator[MagicMock]:
        yield fake_probe

    monkeypatch.setattr("spsdk.apps.nxpdebugmbox.open_debug_probe", fake_open_debug_probe)
    debug_probe_params = DebugProbeParams(
        interface="virtual", serial_no=DebugProbeVirtual.UNIQUE_SERIAL, debug_probe_user_params={}
    )

    with pytest.raises(SPSDKAppError):
        nxpdebugmbox.execute(
            family=FamilyRevision(name=DAT_FAMILY),
            debug_probe_params=debug_probe_params,
            address=0x2000_0000,
            data=b"\x01\x02",  # too small to contain a vector table
        )


def test_tool_execute_rejects_non_coresight_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    """execute() raises SPSDKAppError for debug probes without CoreSight core-register access."""

    class NotCoreSightProbe:
        """Stand-in for a probe that isn't a DebugProbeCoreSightOnly (e.g. DSC)."""

        def connect_safe(self) -> None:
            pass

    @contextlib.contextmanager
    def fake_open_debug_probe(*args: object, **kwargs: object) -> Iterator[NotCoreSightProbe]:
        yield NotCoreSightProbe()

    monkeypatch.setattr("spsdk.apps.nxpdebugmbox.open_debug_probe", fake_open_debug_probe)
    debug_probe_params = DebugProbeParams(
        interface="virtual", serial_no=DebugProbeVirtual.UNIQUE_SERIAL, debug_probe_user_params={}
    )

    with pytest.raises(SPSDKAppError):
        nxpdebugmbox.execute(
            family=FamilyRevision(name=DAT_FAMILY),
            debug_probe_params=debug_probe_params,
            address=0x2000_0000,
            data=_make_vector_table(sp=0x2004_0000, pc=0x2000_0101),
        )


def test_tool_execute_command_end_to_end_with_virtual_probe(cli_runner: CliRunner) -> None:
    """tool execute command runs end-to-end against the virtual probe without error."""
    binary = _make_vector_table(sp=0x2004_0000, pc=0x2000_0101)

    cmd = [
        "-i",
        "virtual",
        "-s",
        DebugProbeVirtual.UNIQUE_SERIAL,
        "tool",
        "execute",
        "-f",
        DAT_FAMILY,
        "-a",
        "0x20000000",
        "-h",
        binary.hex(),
    ]
    result = cli_runner.invoke(main, cmd)

    assert "loaded" in result.output.lower() or "started" in result.output.lower()


def test_list_probes_filters_by_debug_probe_family(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test list-probes uses family-derived architecture and debug probe options."""
    captured: dict[str, object] = {}

    def fake_get_connected_probes(**kwargs: object) -> list[object]:
        captured.update(kwargs)
        return []

    monkeypatch.setattr("spsdk.apps.nxpdebugmbox.get_connected_probes", fake_get_connected_probes)
    debug_probe_params = DebugProbeParams(
        interface="virtual",
        serial_no="dummy",
        debug_probe_user_params={"protocol": "jtag"},
    )

    list_probes(FamilyRevision(name="mimxrt1166"), debug_probe_params)

    assert captured["interface"] == "virtual"
    assert captured["hardware_id"] == "dummy"
    assert captured["architecture"] == "arm-cortex"
    assert captured["options"] == debug_probe_params.debug_probe_user_params


def test_list_probes_without_family_does_not_filter_by_architecture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test list-probes without family lists probes for all architectures."""
    captured: dict[str, object] = {}

    def fake_get_connected_probes(**kwargs: object) -> list[object]:
        captured.update(kwargs)
        return []

    monkeypatch.setattr("spsdk.apps.nxpdebugmbox.get_connected_probes", fake_get_connected_probes)
    debug_probe_params = DebugProbeParams(
        interface="virtual",
        serial_no="dummy",
        debug_probe_user_params={"protocol": "jtag"},
    )

    list_probes(None, debug_probe_params)

    assert captured["interface"] == "virtual"
    assert captured["hardware_id"] == "dummy"
    assert captured["architecture"] is None
    # No family was supplied, so no family/revision/test_address should be injected.
    assert "family" not in debug_probe_params.debug_probe_user_params
    assert "revision" not in debug_probe_params.debug_probe_user_params
    assert captured["options"] == debug_probe_params.debug_probe_user_params


def test_tool_list_probes_cli_without_family(
    cli_runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test 'tool list-probes' CLI command works without the --family option."""

    def fake_get_connected_probes(**kwargs: object) -> list[object]:
        assert kwargs["architecture"] is None
        return []

    monkeypatch.setattr("spsdk.apps.nxpdebugmbox.get_connected_probes", fake_get_connected_probes)

    # cli_runner.invoke() asserts exit_code == 0; previously this failed with
    # "Missing option '-f' / '--family'" because --family was mandatory.
    result = cli_runner.invoke(main, ["tool", "list-probes"])
    assert "No debug probes found in the system." in result.output


# ---------------------------------------------------------------------------
# sda group
# ---------------------------------------------------------------------------


def test_sda_help(cli_runner: CliRunner) -> None:
    """Test sda group --help."""
    result = cli_runner.invoke(main, ["sda", "--help"])
    assert "Show this message and exit." in result.output


def test_sda_auth_help(cli_runner: CliRunner) -> None:
    """Test sda auth --help."""
    result = cli_runner.invoke(main, ["sda", "auth", "--help"])
    assert "Show this message and exit." in result.output


def test_sda_get_families(cli_runner: CliRunner) -> None:
    """Test sda get-families lists supported families."""
    result = cli_runner.invoke(main, ["sda", "get-families"])
    assert result.output


# ---------------------------------------------------------------------------
# cmd group
# ---------------------------------------------------------------------------


def test_cmd_help(cli_runner: CliRunner) -> None:
    """Test cmd group --help."""
    result = cli_runner.invoke(main, ["cmd", "--help"])
    assert "Show this message and exit." in result.output


@pytest.mark.parametrize(
    "subcommand",
    [
        "start",
        "exit",
        "erase",
        "famode",
        "ispmode",
        "token-auth",
        "get-crp",
        "start-debug-session",
        "erase-one-sector",
        "write-to-flash",
        "read-from-flash",
        "get-dac",
        "send-dar",
        "set-bricked-mode",
        "program-lifecycle",
        "nxp-ssf-insert-duk",
        "nxp-exec-prov-fw",
        "nxp-ssf-insert-cert",
        "password-auth",
    ],
)
def test_cmd_subcommands_help(cli_runner: CliRunner, subcommand: str) -> None:
    """Test cmd subcommand --help (requires -f family before subcommand name)."""
    result = cli_runner.invoke(main, ["cmd", "-f", DAT_FAMILY, subcommand, "--help"])
    assert "Show this message and exit." in result.output


def test_cmd_get_families(cli_runner: CliRunner) -> None:
    """Test cmd get-families lists supported families."""
    result = cli_runner.invoke(main, ["cmd", "-f", DAT_FAMILY, "get-families"])
    assert result.output


# ---------------------------------------------------------------------------
# program-lifecycle command tests
# ---------------------------------------------------------------------------


PL_FAMILY = "mcxc353"


def test_program_lifecycle_help(cli_runner: CliRunner) -> None:
    """Test program-lifecycle --help output."""
    result = cli_runner.invoke(main, ["cmd", "-f", DAT_FAMILY, "program-lifecycle", "--help"])
    assert "Show this message and exit." in result.output
    assert "--lifecycle" in result.output or "-l" in result.output


def test_program_lifecycle_for_mcxc353(
    cli_runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MCXC353 forwards the requested lifecycle to the mailbox helper."""
    captured: dict[str, int] = {}

    def fake_program_lifecycle(
        _family: FamilyRevision,
        _debug_probe_params: DebugProbeParams,
        _debug_mailbox_params: DebugMailboxParams,
        lifecycle: int,
    ) -> None:
        captured["lifecycle"] = lifecycle

    monkeypatch.setattr("spsdk.apps.nxpdebugmbox.program_lifecycle", fake_program_lifecycle)

    result = cli_runner.invoke(
        main,
        ["cmd", "-f", PL_FAMILY, "program-lifecycle", "-l", "IN_FIELD1", "-y"],
    )

    assert captured["lifecycle"] == 0x9635_F807
    assert "Program lifecycle IN_FIELD1 (0x9635f807) succeeded" in result.output


def test_program_lifecycle_confirmation(
    cli_runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MCXC353 lifecycle programming asks for confirmation after validation."""
    captured: list[int] = []
    monkeypatch.setattr(
        "spsdk.apps.nxpdebugmbox.program_lifecycle",
        lambda _family, _probe, _mailbox, lifecycle: captured.append(lifecycle),
    )

    result = cli_runner.invoke(
        main,
        ["cmd", "-f", PL_FAMILY, "program-lifecycle", "-l", "IN_FIELD2"],
        input="y\n",
    )

    assert "Continue?" in result.output
    assert captured == [0x9635_F00F]


def test_program_lifecycle_bricked_requires_force(cli_runner: CliRunner) -> None:
    """The destructive BRICKED target requires explicit force."""
    result = cli_runner.invoke(
        main,
        ["cmd", "-f", PL_FAMILY, "program-lifecycle", "-l", "BRICKED", "-y"],
        expected_code=1,
    )
    assert "requires --force" in str(result.exception)


def test_program_lifecycle_bricked_with_force(
    cli_runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BRICKED may be programmed only with force and confirmation bypass."""
    captured: list[int] = []
    monkeypatch.setattr(
        "spsdk.apps.nxpdebugmbox.program_lifecycle",
        lambda _family, _probe, _mailbox, lifecycle: captured.append(lifecycle),
    )

    cli_runner.invoke(
        main,
        [
            "cmd",
            "-f",
            PL_FAMILY,
            "program-lifecycle",
            "-l",
            "BRICKED",
            "--force",
            "-y",
        ],
    )

    assert captured == [0x9635_A55A]


def test_program_lifecycle_rejects_nxp_field_return(cli_runner: CliRunner) -> None:
    """NXP field return is not a symbolic name the device database defines.

    The current MCXC353 ROM IFR map does not expose an NXP_FIELD_RETURN enum
    value for the lifecycle bitfield, so the name cannot be resolved at all
    (regardless of --force).
    """
    result = cli_runner.invoke(
        main,
        [
            "cmd",
            "-f",
            PL_FAMILY,
            "program-lifecycle",
            "-l",
            "NXP_FIELD_RETURN",
            "--force",
            "-y",
        ],
        expected_code=1,
    )
    assert "Cannot resolve lifecycle" in str(result.exception)
    assert "NXP_FIELD_RETURN" in str(result.exception)


def test_program_lifecycle_rejects_unknown_state(cli_runner: CliRunner) -> None:
    """An invalid lifecycle string is rejected before mailbox traffic."""
    cmd = ["cmd", "-f", PL_FAMILY, "program-lifecycle", "-l", "NOT_A_STATE"]
    result = cli_runner.invoke(main, cmd, expected_code=1)
    err = str(result.exception)
    assert PL_FAMILY in err
    assert "NOT_A_STATE" in err


def test_program_lifecycle_rejects_out_of_range(cli_runner: CliRunner) -> None:
    """A value larger than 32 bits is rejected before any mailbox traffic."""
    cmd = ["cmd", "-f", PL_FAMILY, "program-lifecycle", "-l", "0x1_0000_0000"]
    result = cli_runner.invoke(main, cmd, expected_code=1)
    assert "32-bit" in str(result.exception)


def test_program_lifecycle_unsupported_family(cli_runner: CliRunner) -> None:
    """Families without the program_lifecycle sub-feature are rejected."""
    cmd = ["cmd", "-f", DAT_FAMILY, "program-lifecycle", "-l", "0x9635f807"]
    result = cli_runner.invoke(main, cmd, expected_code=1)
    assert "not supported" in str(result.exception)


# ---------------------------------------------------------------------------
# cmd read-from-flash
# ---------------------------------------------------------------------------


def _dbg_params() -> tuple[DebugProbeParams, DebugMailboxParams]:
    """Return dummy debug probe and mailbox parameters for read-from-flash tests."""
    return (
        DebugProbeParams(interface="virtual", serial_no="dummy", debug_probe_user_params={}),
        DebugMailboxParams(reset=False, more_delay=0.0, operation_timeout=1000),
    )


def test_read_from_flash_unsupported_family() -> None:
    """read-from-flash is rejected for families without database support."""
    probe_params, mbox_params = _dbg_params()
    with pytest.raises(SPSDKAppError, match="not supported"):
        read_from_flash(FamilyRevision(DAT_FAMILY), probe_params, mbox_params, address=0, count=16)


def test_read_from_flash_unaligned_address(
    monkeypatch: pytest.MonkeyPatch, tmp_path: os.PathLike
) -> None:
    """read-from-flash accepts unaligned addresses (the ROM has no alignment requirement)."""

    class FakeReadCmd:
        """Fake ReadFromFlash returning deterministic words per address."""

        def __init__(self, dm: object) -> None:
            pass

        def run(self, params: list[int]) -> list[int]:
            base = params[0]
            return [base, base + 4, base + 8, base + 12]

    @contextlib.contextmanager
    def fake_open_debugmbox(*args: object, **kwargs: object) -> Iterator[object]:
        yield object()

    monkeypatch.setattr("spsdk.apps.nxpdebugmbox._open_debugmbox", fake_open_debugmbox)
    monkeypatch.setattr("spsdk.apps.nxpdebugmbox.dm_commands.ReadFromFlash", FakeReadCmd)

    out_file = os.path.join(tmp_path, "flash.bin")
    probe_params, mbox_params = _dbg_params()
    # Address 0x1004 is intentionally not 16-byte aligned.
    read_from_flash(
        FamilyRevision("mcxa255"),
        probe_params,
        mbox_params,
        address=0x1004,
        count=16,
        output=out_file,
    )
    expected = struct.pack("<4I", 0x1004, 0x1008, 0x100C, 0x1010)
    with open(out_file, "rb") as f:
        assert f.read() == expected


@pytest.mark.parametrize("family", ["mcxa255", "mcxl255"])
def test_read_from_flash_success(
    monkeypatch: pytest.MonkeyPatch, tmp_path: os.PathLike, family: str
) -> None:
    """read-from-flash loops 16-byte reads and stores the data to a file."""

    class FakeReadCmd:
        """Fake ReadFromFlash returning deterministic words per address."""

        def __init__(self, dm: object) -> None:
            pass

        def run(self, params: list[int]) -> list[int]:
            base = params[0]
            return [base, base + 4, base + 8, base + 12]

    @contextlib.contextmanager
    def fake_open_debugmbox(*args: object, **kwargs: object) -> Iterator[object]:
        yield object()

    monkeypatch.setattr("spsdk.apps.nxpdebugmbox._open_debugmbox", fake_open_debugmbox)
    monkeypatch.setattr("spsdk.apps.nxpdebugmbox.dm_commands.ReadFromFlash", FakeReadCmd)

    out_file = os.path.join(tmp_path, "flash.bin")
    probe_params, mbox_params = _dbg_params()
    read_from_flash(
        FamilyRevision(family),
        probe_params,
        mbox_params,
        address=0x1000,
        count=32,
        output=out_file,
    )
    expected = struct.pack("<4I", 0x1000, 0x1004, 0x1008, 0x100C) + struct.pack(
        "<4I", 0x1010, 0x1014, 0x1018, 0x101C
    )
    with open(out_file, "rb") as f:
        assert f.read() == expected


def test_read_from_flash_hexdump_to_stdout(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    """read-from-flash prints a hex dump when no output file is given."""

    class FakeReadCmd:
        """Fake ReadFromFlash returning a constant response."""

        def __init__(self, dm: object) -> None:
            pass

        def run(self, params: list[int]) -> list[int]:
            return [0x11111111, 0x22222222, 0x33333333, 0x44444444]

    @contextlib.contextmanager
    def fake_open_debugmbox(*args: object, **kwargs: object) -> Iterator[object]:
        yield object()

    monkeypatch.setattr("spsdk.apps.nxpdebugmbox._open_debugmbox", fake_open_debugmbox)
    monkeypatch.setattr("spsdk.apps.nxpdebugmbox.dm_commands.ReadFromFlash", FakeReadCmd)

    probe_params, mbox_params = _dbg_params()
    read_from_flash(FamilyRevision("mcxa255"), probe_params, mbox_params, address=0, count=16)
    captured = capsys.readouterr()
    assert "11" in captured.out
