#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for the PFR CMPA merge utility (core and CLI)."""

import os

import pytest

from spsdk.apps import pfr as cli
from spsdk.pfr.exceptions import SPSDKPfrError
from spsdk.pfr.pfr import CMPA
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_binary, write_file
from tests.cli_runner import CliRunner

FAMILY = "mcxl255"
ERASE_TOKEN_REGS = [
    "SI_ERASE_TOKEN0",
    "SI_ERASE_TOKEN1",
    "SI_ERASE_TOKEN2",
    "SI_ERASE_TOKEN3",
]
ERASE_TOKEN_OFFSET = 0xD0
ERASE_TOKEN_LEN = 16


def _blank_cmpa(family: str = FAMILY) -> bytes:
    """Return a default CMPA binary for the given family."""
    return CMPA(FamilyRevision(family)).export(add_seal=False, draw=False)


def _device_cmpa(token: bytes, family: str = FAMILY) -> bytes:
    """Return a CMPA binary with the erase-token field set to ``token``."""
    data = bytearray(_blank_cmpa(family))
    data[ERASE_TOKEN_OFFSET : ERASE_TOKEN_OFFSET + ERASE_TOKEN_LEN] = token
    return bytes(data)


def test_merge_binary_copies_selected_registers() -> None:
    """merge_binary copies the selected register bytes and preserves everything else."""
    main = _blank_cmpa()
    token = bytes(range(ERASE_TOKEN_LEN))
    device = _device_cmpa(token)

    merged = CMPA.merge_binary(main, device, ERASE_TOKEN_REGS, FamilyRevision(FAMILY))

    assert len(merged) == len(main)
    assert merged[ERASE_TOKEN_OFFSET : ERASE_TOKEN_OFFSET + ERASE_TOKEN_LEN] == token
    # Everything outside the token range must equal the main binary.
    assert merged[:ERASE_TOKEN_OFFSET] == main[:ERASE_TOKEN_OFFSET]
    assert (
        merged[ERASE_TOKEN_OFFSET + ERASE_TOKEN_LEN :]
        == main[ERASE_TOKEN_OFFSET + ERASE_TOKEN_LEN :]
    )


def test_merge_binary_subset_of_registers() -> None:
    """Only the explicitly listed registers are merged."""
    main = _blank_cmpa()
    token = bytes(range(0x10, 0x20))
    device = _device_cmpa(token)

    merged = CMPA.merge_binary(main, device, ["SI_ERASE_TOKEN0"], FamilyRevision(FAMILY))

    # First word taken from device, the remaining token words stay as in main.
    assert merged[ERASE_TOKEN_OFFSET : ERASE_TOKEN_OFFSET + 4] == token[:4]
    assert merged[ERASE_TOKEN_OFFSET + 4 : ERASE_TOKEN_OFFSET + ERASE_TOKEN_LEN] == (
        main[ERASE_TOKEN_OFFSET + 4 : ERASE_TOKEN_OFFSET + ERASE_TOKEN_LEN]
    )


def test_merge_binary_empty_register_list_raises() -> None:
    """An empty register list is rejected."""
    main = _blank_cmpa()
    with pytest.raises(SPSDKPfrError, match="At least one register"):
        CMPA.merge_binary(main, main, [], FamilyRevision(FAMILY))


def test_merge_binary_unknown_register_raises() -> None:
    """An unknown register name is rejected."""
    main = _blank_cmpa()
    with pytest.raises(SPSDKPfrError, match="does not exist"):
        CMPA.merge_binary(main, main, ["NOT_A_REGISTER"], FamilyRevision(FAMILY))


def test_merge_binary_short_binary_raises() -> None:
    """A binary shorter than the page size is rejected."""
    main = _blank_cmpa()
    with pytest.raises(SPSDKPfrError, match="too short"):
        CMPA.merge_binary(main, main[:-1], ERASE_TOKEN_REGS, FamilyRevision(FAMILY))


def test_cmpa_merge_cli_registers(cli_runner: CliRunner, tmpdir: str) -> None:
    """The cmpa-merge CLI merges the token registers from the device binary."""
    token = bytes(range(ERASE_TOKEN_LEN))
    main_path = os.path.join(tmpdir, "main.bin")
    device_path = os.path.join(tmpdir, "device.bin")
    out_path = os.path.join(tmpdir, "out.bin")
    write_file(_blank_cmpa(), main_path, mode="wb")
    write_file(_device_cmpa(token), device_path, mode="wb")

    cli_runner.invoke(
        cli.main,
        [
            "cmpa-merge",
            "--family",
            FAMILY,
            "--main-cmpa",
            main_path,
            "--device-cmpa",
            device_path,
            "--output-cmpa",
            out_path,
            "--registers",
            ",".join(ERASE_TOKEN_REGS),
        ],
    )

    merged = load_binary(out_path)
    assert merged[ERASE_TOKEN_OFFSET : ERASE_TOKEN_OFFSET + ERASE_TOKEN_LEN] == token


@pytest.mark.parametrize("family", ["mcxl255", "mcxa255", "mcxa366"])
def test_cmpa_merge_cli_si_erase_token(cli_runner: CliRunner, tmpdir: str, family: str) -> None:
    """--si-erase-token resolves the family's token registers automatically."""
    token = bytes(range(ERASE_TOKEN_LEN))
    main_path = os.path.join(tmpdir, "main.bin")
    device_path = os.path.join(tmpdir, "device.bin")
    out_path = os.path.join(tmpdir, "out.bin")
    write_file(_blank_cmpa(family), main_path, mode="wb")
    write_file(_device_cmpa(token, family), device_path, mode="wb")

    cli_runner.invoke(
        cli.main,
        [
            "cmpa-merge",
            "--family",
            family,
            "--main-cmpa",
            main_path,
            "--device-cmpa",
            device_path,
            "--output-cmpa",
            out_path,
            "--si-erase-token",
        ],
    )

    merged = load_binary(out_path)
    assert merged[ERASE_TOKEN_OFFSET : ERASE_TOKEN_OFFSET + ERASE_TOKEN_LEN] == token


def test_cmpa_merge_cli_registers_config(cli_runner: CliRunner, tmpdir: str) -> None:
    """The cmpa-merge CLI accepts a static YAML register list."""
    token = bytes(range(ERASE_TOKEN_LEN))
    main_path = os.path.join(tmpdir, "main.bin")
    device_path = os.path.join(tmpdir, "device.bin")
    out_path = os.path.join(tmpdir, "out.bin")
    regs_path = os.path.join(tmpdir, "regs.yaml")
    write_file(_blank_cmpa(), main_path, mode="wb")
    write_file(_device_cmpa(token), device_path, mode="wb")
    write_file(
        "registers:\n" + "".join(f"  - {name}\n" for name in ERASE_TOKEN_REGS),
        regs_path,
    )

    cli_runner.invoke(
        cli.main,
        [
            "cmpa-merge",
            "--family",
            FAMILY,
            "--main-cmpa",
            main_path,
            "--device-cmpa",
            device_path,
            "--output-cmpa",
            out_path,
            "--registers-config",
            regs_path,
        ],
    )

    merged = load_binary(out_path)
    assert merged[ERASE_TOKEN_OFFSET : ERASE_TOKEN_OFFSET + ERASE_TOKEN_LEN] == token


def test_cmpa_merge_cli_requires_one_register_source(cli_runner: CliRunner, tmpdir: str) -> None:
    """Providing neither register source fails."""
    main_path = os.path.join(tmpdir, "main.bin")
    device_path = os.path.join(tmpdir, "device.bin")
    out_path = os.path.join(tmpdir, "out.bin")
    write_file(_blank_cmpa(), main_path, mode="wb")
    write_file(_blank_cmpa(), device_path, mode="wb")

    result = cli_runner.invoke(
        cli.main,
        [
            "cmpa-merge",
            "--family",
            FAMILY,
            "--main-cmpa",
            main_path,
            "--device-cmpa",
            device_path,
            "--output-cmpa",
            out_path,
        ],
        expected_code=1,
    )
    assert "exactly one of --registers" in str(result.exception)


def test_cmpa_merge_cli_rejects_both_register_sources(cli_runner: CliRunner, tmpdir: str) -> None:
    """Providing both register sources fails."""
    main_path = os.path.join(tmpdir, "main.bin")
    device_path = os.path.join(tmpdir, "device.bin")
    out_path = os.path.join(tmpdir, "out.bin")
    regs_path = os.path.join(tmpdir, "regs.yaml")
    write_file(_blank_cmpa(), main_path, mode="wb")
    write_file(_blank_cmpa(), device_path, mode="wb")
    write_file("registers:\n  - SI_ERASE_TOKEN0\n", regs_path)

    result = cli_runner.invoke(
        cli.main,
        [
            "cmpa-merge",
            "--family",
            FAMILY,
            "--main-cmpa",
            main_path,
            "--device-cmpa",
            device_path,
            "--output-cmpa",
            out_path,
            "--registers",
            "SI_ERASE_TOKEN0",
            "--registers-config",
            regs_path,
        ],
        expected_code=1,
    )
    assert "exactly one of --registers" in str(result.exception)
