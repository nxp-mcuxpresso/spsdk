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

import pytest
from typing_extensions import Never

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


# ---------------------------------------------------------------------------
# tool group
# ---------------------------------------------------------------------------


def test_tool_help(cli_runner: CliRunner) -> None:
    """Test tool group --help."""
    result = cli_runner.invoke(main, ["tool", "--help"])
    assert "Show this message and exit." in result.output


@pytest.mark.parametrize("subcommand", ["reset", "get-uuid", "halt", "resume", "list-probes"])
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
