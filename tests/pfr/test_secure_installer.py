#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for Secure Installer Eraser functionality.

This test module provides comprehensive testing for the SecureInstallerEraser class,
verifying its ability to erase Secure Installer from supported NXP MCU devices while
honoring the ROM-side preconditions documented in
"""

from collections.abc import Callable
from unittest.mock import MagicMock

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.mboot.commands import CommandTag
from spsdk.mboot.error_codes import StatusCode
from spsdk.mboot.exceptions import McuBootCommandError
from spsdk.pfr.secure_installer import SecureInstallerEraser, SIStatus
from spsdk.utils.family import FamilyRevision

# CMPA header magic expected by ROM (upper 16 bits at CMPA+0 == 0x5963 on MCXL255).
# Little-endian word with lower 16 bits cleared.
_VALID_CMPA_HEADER_BYTES = b"\x00\x00\x63\x59"
_INVALID_CMPA_HEADER_BYTES = b"\x00\x00\x00\x00"

# Per-phantom SI region/CMPA addresses (verified from L20 ROM
# ``set_ahbsc_access_permissions_for_si()`` and ``ifrmap.h``).
_FAMILY_ADDRESSES = {
    "mcxl253": {"cmpa": 0x3E000, "si_probe": 0x26000},
    "mcxl254": {"cmpa": 0x5E000, "si_probe": 0x46000},
    "mcxl255": {"cmpa": 0x7E000, "si_probe": 0x66000},
    "mcxa255": {"cmpa": 0x7E000, "si_probe": 0x60000},
    "mcxa366": {"cmpa": 0xFE000, "si_probe": 0xC0000},
}


def _make_read_memory_handler(
    cmpa: int,
    header: bytes = _VALID_CMPA_HEADER_BYTES,
    erase_token: bytes = b"\xff" * 16,
    delete_installer: bytes = b"\xff" * 4,
    probe: bytes | None = b"\xff\xff\xff\xff",
    probe_address: int | None = None,
) -> Callable[[int, int], bytes | None]:
    """Build an address-aware ``read_memory`` side_effect that returns blank fields by default.

    The mock answers reads at four addresses:

    * ``cmpa + 0x00`` (4 bytes) → ``header``
    * ``cmpa + 0xD0`` (16 bytes) → ``erase_token``
    * ``cmpa + 0xE0`` (4 bytes) → ``delete_installer``
    * ``probe_address``       → ``probe`` (None to simulate MEMORY_RANGE_INVALID)

    Any other address returns ``b"\\xff"`` repeated to the requested length so unrelated
    reads do not break the test.
    """

    def _read(address: int, length: int) -> bytes | None:
        if address == cmpa:
            return header
        if address == cmpa + 0xD0:
            return erase_token[:length]
        if address == cmpa + 0xE0:
            return delete_installer[:length]
        if probe_address is not None and address == probe_address:
            return probe
        return b"\xff" * length

    return _read


def _build_mboot(
    family_name: str = "mcxl255",
    *,
    header: bytes = _VALID_CMPA_HEADER_BYTES,
    erase_token: bytes = b"\xff" * 16,
    delete_installer: bytes = b"\xff" * 4,
    probe: bytes | None = b"\xff\xff\xff\xff",
    probe_status: int = StatusCode.SUCCESS.tag,
) -> MagicMock:
    """Construct a configured mock McuBoot for the given family with blank-by-default fields."""
    addrs = _FAMILY_ADDRESSES.get(family_name, {"cmpa": 0x7E000, "si_probe": 0x66000})
    mock = MagicMock()
    mock.write_memory.return_value = True
    mock.reset.return_value = True
    mock.status_string = "OK"
    mock.status_code = probe_status
    mock.read_memory.side_effect = _make_read_memory_handler(
        cmpa=addrs["cmpa"],
        header=header,
        erase_token=erase_token,
        delete_installer=delete_installer,
        probe=probe,
        probe_address=addrs["si_probe"],
    )
    return mock


@pytest.fixture
def mock_mboot() -> MagicMock:
    """Default fully-blank mock for an mcxl255 device (CMPA header valid, all fields blank)."""
    return _build_mboot("mcxl255")


def _make_available_commands_raw(include_receive_sb: bool) -> list[int]:
    """Build a raw available-commands bitmask value for mocking get_property."""
    if include_receive_sb:
        return [1 << (CommandTag.RECEIVE_SB_FILE.tag - 1)]
    return [0]


class TestSecureInstallerEraser:
    """Test suite for SecureInstallerEraser class."""

    @pytest.mark.parametrize(
        "family_name",
        ["mcxl255", "mcxl253", "mcxl254", "mcxa255", "mcxa265", "mcxa256", "mcxa366", "mcxa365"],
    )
    def test_eraser_initialization_supported_families(self, family_name: str) -> None:
        """SecureInstallerEraser can be initialized with all supported families."""
        mock_mboot = _build_mboot(family_name)
        family = FamilyRevision(family_name)
        eraser = SecureInstallerEraser(mock_mboot, family)

        assert eraser.mboot == mock_mboot
        assert eraser.family == family
        assert eraser.delete_installer_magic == 0x4027FF65
        assert eraser.delete_installer_offset == 0xE0
        assert eraser.erase_token_offset == 0xD0

    def test_eraser_initialization_unsupported_family(self, mock_mboot: MagicMock) -> None:
        """Unsupported families raise SPSDKError on construction."""
        family = FamilyRevision("lpc55s69")
        with pytest.raises(SPSDKError) as exc_info:
            SecureInstallerEraser(mock_mboot, family)

        assert "does not support Secure Installer erasure" in str(exc_info.value)

    def test_erase_with_reset(self, mock_mboot: MagicMock) -> None:
        """Erase writes magic to CMPA+0xE0 and resets the device by default."""
        family = FamilyRevision("mcxl255")
        eraser = SecureInstallerEraser(mock_mboot, family)

        eraser.erase(reset=True)

        mock_mboot.write_memory.assert_called_once()
        call_args = mock_mboot.write_memory.call_args
        address = call_args[0][0] if call_args[0] else call_args[1]["address"]
        assert address == 0x7E0E0  # CMPA + 0xE0

        data = call_args[0][1] if len(call_args[0]) > 1 else call_args[1]["data"]
        assert data == b"\x65\xff\x27\x40"  # 0x4027FF65 little-endian

        # SI erase must reset without reopening: the ROM erases the SI on the next
        # boot, so the connection cannot be reliably reopened (see blhost `reset`).
        mock_mboot.reset.assert_called_once_with(reopen=False)

    def test_erase_without_reset(self) -> None:
        """`reset=False` skips the reset step but still writes the magic."""
        mock_mboot = _build_mboot("mcxa366")
        family = FamilyRevision("mcxa366")
        eraser = SecureInstallerEraser(mock_mboot, family)

        eraser.erase(reset=False)

        mock_mboot.write_memory.assert_called_once()
        mock_mboot.reset.assert_not_called()

    def test_erase_write_failure(self, mock_mboot: MagicMock) -> None:
        """SPSDKError is raised when write_memory returns False."""
        family = FamilyRevision("mcxl255")
        mock_mboot.write_memory.return_value = False
        mock_mboot.status_string = "Write failed"
        eraser = SecureInstallerEraser(mock_mboot, family)

        with pytest.raises(SPSDKError) as exc_info:
            eraser.erase(reset=True)

        assert "Failed to write DELETE_INSTALLER_MAGIC" in str(exc_info.value)

    def test_erase_aborts_when_cmpa_header_marker_invalid(self) -> None:
        """Erase aborts when the CMPA header marker doesn't match the ROM-expected value.

        Mirrors ``SI_IsEraseRequested`` ROM guard: without ``0x5963`` at CMPA+0
        upper-half the ROM silently ignores the magic.
        """
        mock_mboot = _build_mboot("mcxl255", header=_INVALID_CMPA_HEADER_BYTES)
        eraser = SecureInstallerEraser(mock_mboot, FamilyRevision("mcxl255"))

        with pytest.raises(SPSDKError) as exc_info:
            eraser.erase(reset=True)

        assert "CMPA header marker" in str(exc_info.value)
        assert "silently ignore" in str(exc_info.value)
        mock_mboot.write_memory.assert_not_called()
        mock_mboot.reset.assert_not_called()

    def test_erase_aborts_when_cmpa_header_cannot_be_read(self) -> None:
        """Erase aborts when the CMPA header read itself fails (safe default)."""
        mock_mboot = _build_mboot("mcxl255")
        addrs = _FAMILY_ADDRESSES["mcxl255"]

        def _read(address: int, length: int) -> bytes | None:
            if address == addrs["cmpa"]:
                return None  # simulate read failure on header
            return b"\xff" * length

        mock_mboot.read_memory.side_effect = _read
        eraser = SecureInstallerEraser(mock_mboot, FamilyRevision("mcxl255"))

        with pytest.raises(SPSDKError) as exc_info:
            eraser.erase(reset=True)

        assert "CMPA header marker" in str(exc_info.value)
        mock_mboot.write_memory.assert_not_called()

    def test_erase_aborts_when_erase_token_already_programmed(self) -> None:
        """Erase aborts when the ERASE_TOKEN field is not blank (ROM already accepted erase)."""
        mock_mboot = _build_mboot("mcxl255", erase_token=b"\xaa" * 16)
        eraser = SecureInstallerEraser(mock_mboot, FamilyRevision("mcxl255"))

        with pytest.raises(SPSDKError) as exc_info:
            eraser.erase(reset=True)

        assert "ERASE_TOKEN" in str(exc_info.value)
        assert "cumulative" in str(exc_info.value).lower()
        mock_mboot.write_memory.assert_not_called()
        mock_mboot.reset.assert_not_called()

    def test_erase_aborts_when_delete_installer_is_not_blank(self) -> None:
        """Erase aborts when DELETE_INSTALLER word has been partially programmed."""
        mock_mboot = _build_mboot("mcxl255", delete_installer=b"\x00\xff\xff\xff")
        eraser = SecureInstallerEraser(mock_mboot, FamilyRevision("mcxl255"))

        with pytest.raises(SPSDKError) as exc_info:
            eraser.erase(reset=True)

        assert "DELETE_INSTALLER" in str(exc_info.value)
        assert "cumulative write" in str(exc_info.value)
        mock_mboot.write_memory.assert_not_called()
        mock_mboot.reset.assert_not_called()

    def test_erase_reports_already_programmed_delete_installer_magic(self) -> None:
        """Erase reports that DELETE_INSTALLER already contains the magic value."""
        mock_mboot = _build_mboot("mcxl255", delete_installer=b"\x65\xff\x27\x40")
        eraser = SecureInstallerEraser(mock_mboot, FamilyRevision("mcxl255"))

        with pytest.raises(SPSDKError) as exc_info:
            eraser.erase(reset=True)

        assert "already contains DELETE_INSTALLER_MAGIC" in str(exc_info.value)
        mock_mboot.write_memory.assert_not_called()

    def test_erase_aborts_when_delete_installer_cannot_be_read(self) -> None:
        """Erase aborts when the DELETE_INSTALLER read fails."""
        mock_mboot = _build_mboot("mcxl255")
        addrs = _FAMILY_ADDRESSES["mcxl255"]

        def _read(address: int, length: int) -> bytes | None:
            if address == addrs["cmpa"]:
                return _VALID_CMPA_HEADER_BYTES
            if address == addrs["cmpa"] + 0xD0:
                return b"\xff" * length
            if address == addrs["cmpa"] + 0xE0:
                return None
            return b"\xff" * length

        mock_mboot.read_memory.side_effect = _read
        eraser = SecureInstallerEraser(mock_mboot, FamilyRevision("mcxl255"))

        with pytest.raises(SPSDKError) as exc_info:
            eraser.erase(reset=True)

        assert "Unable to read DELETE_INSTALLER field" in str(exc_info.value)
        mock_mboot.write_memory.assert_not_called()

    def test_erase_reset_failure(self, mock_mboot: MagicMock) -> None:
        """SPSDKError is raised when reset() returns False after a successful write."""
        family = FamilyRevision("mcxl255")
        mock_mboot.reset.return_value = False
        mock_mboot.status_string = "Reset failed"
        eraser = SecureInstallerEraser(mock_mboot, family)

        with pytest.raises(SPSDKError) as exc_info:
            eraser.erase(reset=True)

        assert "Failed to reset device" in str(exc_info.value)

    @staticmethod
    def _build_cumulative_write_mboot(
        family_name: str = "mcxa366",
        *,
        signal: str = "raise",
        token_blank_after: bool = True,
    ) -> tuple[MagicMock, dict]:
        """Build a mock where the DELETE_INSTALLER phrase reads blank but is not erased.

        The in-place magic write signals a cumulative-write (either by raising
        ``McuBootCommandError`` when ``signal == "raise"`` or by returning ``False``
        with a cumulative ``status_code`` when ``signal == "false"``) until the CMPA
        sector is erased. Reads reflect the rewrite: ``CMPA + 0xE0`` reads the magic
        only after the trailing chunk that carries it is programmed, and the
        ERASE_TOKEN phrase reads blank (or ``0x00`` when ``token_blank_after`` is
        ``False`` to exercise the post-rewrite verification).
        """
        addrs = _FAMILY_ADDRESSES[family_name]
        cmpa = addrs["cmpa"]
        magic = b"\x65\xff\x27\x40"
        state = {"erased": False, "magic_programmed": False}

        def _read(address: int, length: int) -> bytes | None:
            if address == cmpa and length == 4:
                return _VALID_CMPA_HEADER_BYTES
            if address == cmpa:  # full-CMPA snapshot read for the rewrite
                return _VALID_CMPA_HEADER_BYTES + b"\xff" * (length - 4)
            if address == cmpa + 0xD0:
                return (b"\xff" if token_blank_after else b"\x00") * length
            if address == cmpa + 0xE0 and length == 4:
                return magic if state["magic_programmed"] else b"\xff\xff\xff\xff"
            if address == addrs["si_probe"]:
                return b"\xff\xff\xff\xff"
            return b"\xff" * length

        def _write(address: int, data: bytes) -> bool:
            if address == cmpa + 0xE0 and len(data) == 4:  # in-place magic attempt
                if not state["erased"]:
                    if signal == "raise":
                        raise McuBootCommandError(
                            "WriteMemory", StatusCode.MEMORY_CUMULATIVE_WRITE.tag
                        )
                    return False
                state["magic_programmed"] = True
                return True
            if address == cmpa + 0xE0:  # trailing rewrite chunk that carries the magic
                state["magic_programmed"] = True
            return True

        def _erase(address: int, length: int) -> bool:
            state["erased"] = True
            return True

        mock = MagicMock()
        mock.read_memory.side_effect = _read
        mock.write_memory.side_effect = _write
        mock.flash_erase_region.side_effect = _erase
        mock.reset.return_value = True
        mock.status_string = "OK"
        mock.status_code = (
            StatusCode.MEMORY_CUMULATIVE_WRITE.tag if signal == "false" else StatusCode.SUCCESS.tag
        )
        return mock, state

    def test_erase_falls_back_to_cmpa_rewrite_on_cumulative_write(self) -> None:
        """A cumulative-write on the in-place magic write triggers a CMPA sector rewrite."""
        mock_mboot, _ = self._build_cumulative_write_mboot("mcxa366")
        eraser = SecureInstallerEraser(mock_mboot, FamilyRevision("mcxa366"))

        eraser.erase(reset=True)

        # CMPA sector was erased and the device reset once.
        mock_mboot.flash_erase_region.assert_called_once()
        assert mock_mboot.flash_erase_region.call_args[0][0] == 0xFE000
        mock_mboot.reset.assert_called_once()

        # The reprogram skipped the ERASE_TOKEN phrase (0xD0-0xDF) and wrote the magic.
        chunk_writes = [c for c in mock_mboot.write_memory.call_args_list if len(c[0][1]) > 4]
        written = {c[0][0]: c[0][1] for c in chunk_writes}
        assert 0xFE000 in written  # header/config chunk
        assert 0xFE0E0 in written  # DELETE_INSTALLER chunk
        assert 0xFE0D0 not in written  # ERASE_TOKEN phrase left untouched (erased)
        assert len(written[0xFE000]) == 0xD0  # first chunk stops before the token phrase
        assert written[0xFE0E0][:4] == b"\x65\xff\x27\x40"  # magic at CMPA+0xE0

    def test_erase_falls_back_when_write_returns_false_with_cumulative_status(self) -> None:
        """Fallback also triggers when write_memory returns False with a cumulative status."""
        mock_mboot, _ = self._build_cumulative_write_mboot("mcxa366", signal="false")
        eraser = SecureInstallerEraser(mock_mboot, FamilyRevision("mcxa366"))

        eraser.erase(reset=True)

        mock_mboot.flash_erase_region.assert_called_once()
        mock_mboot.reset.assert_called_once()

    def test_erase_rewrite_aborts_when_token_not_blank_after(self) -> None:
        """The rewrite verify aborts (no reset) when ERASE_TOKEN is not blank afterwards."""
        mock_mboot, _ = self._build_cumulative_write_mboot("mcxa366", token_blank_after=False)
        eraser = SecureInstallerEraser(mock_mboot, FamilyRevision("mcxa366"))

        with pytest.raises(SPSDKError) as exc_info:
            eraser.erase(reset=True)

        assert "ERASE_TOKEN phrase" in str(exc_info.value)
        assert "not blank after" in str(exc_info.value)
        mock_mboot.reset.assert_not_called()

    def test_erase_rewrite_aborts_when_cmpa_read_fails(self) -> None:
        """The rewrite aborts if the current CMPA snapshot cannot be read."""
        mock_mboot, _ = self._build_cumulative_write_mboot("mcxa366")

        addrs = _FAMILY_ADDRESSES["mcxa366"]
        cmpa = addrs["cmpa"]

        def _read(address: int, length: int) -> bytes | None:
            if address == cmpa and length == 4:
                return _VALID_CMPA_HEADER_BYTES
            if address == cmpa:  # full snapshot read fails
                return None
            if address == cmpa + 0xD0:
                return b"\xff" * length
            if address == cmpa + 0xE0 and length == 4:
                return b"\xff\xff\xff\xff"
            return b"\xff" * length

        mock_mboot.read_memory.side_effect = _read
        eraser = SecureInstallerEraser(mock_mboot, FamilyRevision("mcxa366"))

        with pytest.raises(SPSDKError) as exc_info:
            eraser.erase(reset=True)

        assert "Unable to read the current CMPA" in str(exc_info.value)
        mock_mboot.flash_erase_region.assert_not_called()
        mock_mboot.reset.assert_not_called()

    @staticmethod
    def _build_blank_cmpa_mboot(
        family_name: str = "mcxa366", fill: int = 0xFF
    ) -> tuple[MagicMock, dict]:
        """Build a mock for a fully-blank CMPA (all ``fill``) that reflects provisioning.

        ``fill`` is the byte the unprovisioned CMPA reads back as (``0xFF`` erased, or
        ``0x00`` on parts that store an unprogrammed CMPA as zeros). Before
        programming, the header word and full CMPA snapshot read blank; after the
        chunk writes, the header reads the ROM marker and the DELETE_INSTALLER word
        reads the magic, so the post-provision verification passes.
        """
        addrs = _FAMILY_ADDRESSES[family_name]
        cmpa = addrs["cmpa"]
        magic = b"\x65\xff\x27\x40"
        blank = bytes([fill])
        state = {"header_written": False, "magic_written": False}

        def _read(address: int, length: int) -> bytes | None:
            if address == cmpa and length == 4:
                return _VALID_CMPA_HEADER_BYTES if state["header_written"] else blank * 4
            if address == cmpa:  # full-CMPA snapshot (blank fill)
                return blank * length
            if address == cmpa + 0xD0:  # token phrase reads erased (0xFF) after erase
                return b"\xff" * length
            if address == cmpa + 0xE0 and length == 4:
                return magic if state["magic_written"] else blank * 4
            if address == addrs["si_probe"]:
                return b"\xff\xff\xff\xff"
            return b"\xff" * length

        def _write(address: int, data: bytes) -> bool:
            if address == cmpa:  # header/config chunk
                state["header_written"] = True
            if address == cmpa + 0xE0:  # trailing chunk carrying the magic
                state["magic_written"] = True
            return True

        mock = MagicMock()
        mock.read_memory.side_effect = _read
        mock.write_memory.side_effect = _write
        mock.flash_erase_region.return_value = True
        mock.reset.return_value = True
        mock.status_string = "OK"
        mock.status_code = StatusCode.SUCCESS.tag
        return mock, state

    def test_erase_proceeds_when_delete_installer_all_zeros(self) -> None:
        """An all-0x00 DELETE_INSTALLER field is treated as blank (ROM only checks == magic)."""
        mock_mboot = _build_mboot("mcxa366", delete_installer=b"\x00\x00\x00\x00")
        eraser = SecureInstallerEraser(mock_mboot, FamilyRevision("mcxa366"))

        eraser.erase(reset=True)

        # Guard must not abort on 0x00; it proceeds to write the magic and reset.
        mock_mboot.write_memory.assert_called_once()
        data = mock_mboot.write_memory.call_args[0][1]
        assert data == b"\x65\xff\x27\x40"
        mock_mboot.reset.assert_called_once()

    def test_erase_provisions_when_cmpa_all_zeros(self) -> None:
        """An invalid header with an all-0x00 CMPA is provisioned (not refused)."""
        mock_mboot, _ = self._build_blank_cmpa_mboot("mcxa366", fill=0x00)
        eraser = SecureInstallerEraser(mock_mboot, FamilyRevision("mcxa366"))

        eraser.erase(reset=True)

        mock_mboot.flash_erase_region.assert_called_once()
        mock_mboot.reset.assert_called_once()
        chunk_writes = [c for c in mock_mboot.write_memory.call_args_list if len(c[0][1]) > 4]
        written = {c[0][0]: c[0][1] for c in chunk_writes}
        assert written[0xFE0E0][:4] == b"\x65\xff\x27\x40"
        assert 0xFE0D0 not in written  # ERASE_TOKEN phrase left erased

    def test_erase_provisions_default_cmpa_on_blank_flash(self) -> None:
        """On a fully-blank CMPA the eraser provisions a default CMPA carrying the magic."""
        mock_mboot, _ = self._build_blank_cmpa_mboot("mcxa366")
        eraser = SecureInstallerEraser(mock_mboot, FamilyRevision("mcxa366"))

        eraser.erase(reset=True)

        mock_mboot.flash_erase_region.assert_called_once()
        assert mock_mboot.flash_erase_region.call_args[0][0] == 0xFE000
        mock_mboot.reset.assert_called_once()

        chunk_writes = [c for c in mock_mboot.write_memory.call_args_list if len(c[0][1]) > 4]
        written = {c[0][0]: c[0][1] for c in chunk_writes}
        # Header/config chunk carries the ROM header marker 0x5963 at CMPA+0.
        assert 0xFE000 in written
        assert written[0xFE000][:4] == _VALID_CMPA_HEADER_BYTES
        assert len(written[0xFE000]) == 0xD0  # stops before the ERASE_TOKEN phrase
        # Trailing chunk carries DELETE_INSTALLER_MAGIC at CMPA+0xE0.
        assert written[0xFE0E0][:4] == b"\x65\xff\x27\x40"
        assert 0xFE0D0 not in written  # ERASE_TOKEN phrase left erased

    def test_erase_refuses_when_header_invalid_and_cmpa_not_blank(self) -> None:
        """An invalid header with a non-blank CMPA is refused (no auto-provision)."""
        addrs = _FAMILY_ADDRESSES["mcxa366"]
        cmpa = addrs["cmpa"]
        mock_mboot = MagicMock()
        mock_mboot.reset.return_value = True
        mock_mboot.write_memory.return_value = True
        mock_mboot.status_code = StatusCode.SUCCESS.tag

        def _read(address: int, length: int) -> bytes | None:
            if address == cmpa and length == 4:
                return b"\x11\x22\x33\x44"  # invalid marker
            if address == cmpa:  # full CMPA snapshot: not all 0xFF
                return b"\x11\x22\x33\x44" + b"\xff" * (length - 4)
            return b"\xff" * length

        mock_mboot.read_memory.side_effect = _read
        eraser = SecureInstallerEraser(mock_mboot, FamilyRevision("mcxa366"))

        with pytest.raises(SPSDKError) as exc_info:
            eraser.erase(reset=True)

        assert "CMPA header marker" in str(exc_info.value)
        assert "silently ignore" in str(exc_info.value)
        mock_mboot.flash_erase_region.assert_not_called()
        mock_mboot.write_memory.assert_not_called()
        mock_mboot.reset.assert_not_called()

    @pytest.mark.parametrize(
        "family_name,expected_cmpa,expected_probe",
        [
            ("mcxl253", "0x0003e000", 0x26000),
            ("mcxl254", "0x0005e000", 0x46000),
            ("mcxl255", "0x0007e000", 0x66000),
            ("mcxa255", "0x0007e000", 0x60000),
            ("mcxa366", "0x000fe000", 0xC0000),
        ],
    )
    def test_get_device_info(
        self, family_name: str, expected_cmpa: str, expected_probe: int
    ) -> None:
        """get_device_info exposes the configured device addresses."""
        mock_mboot = _build_mboot(family_name)
        family = FamilyRevision(family_name)
        eraser = SecureInstallerEraser(mock_mboot, family)

        info = eraser.get_device_info()

        assert info["family"] == str(family)
        assert info["cmpa_address"] == expected_cmpa
        assert info["delete_installer_magic"] == "0x4027ff65"
        assert info["delete_installer_offset"] == "0xE0"
        assert info["erase_token_offset"] == "0xD0"
        assert info["si_probe_address"] == f"0x{expected_probe:08x}"

    def test_get_device_info_includes_header_marker_for_mcxl(self) -> None:
        """MCXL families expose the CMPA header marker in device info."""
        mock_mboot = _build_mboot("mcxl255")
        eraser = SecureInstallerEraser(mock_mboot, FamilyRevision("mcxl255"))

        info = eraser.get_device_info()

        assert "cmpa_header_marker" in info
        assert info["cmpa_header_marker"].lower() == "0x5963"

    @pytest.mark.parametrize(
        "family_name,expected_cmpa,expected_probe",
        [
            ("mcxl253", 0x3E000, 0x26000),
            ("mcxl254", 0x5E000, 0x46000),
            ("mcxl255", 0x7E000, 0x66000),
        ],
    )
    def test_mcxl_phantom_addresses(
        self, family_name: str, expected_cmpa: int, expected_probe: int
    ) -> None:
        """Each MCXL phantom uses its phantom-specific CMPA / SI probe address."""
        mock_mboot = _build_mboot(family_name)
        eraser = SecureInstallerEraser(mock_mboot, FamilyRevision(family_name))

        assert eraser.cmpa_address == expected_cmpa
        assert eraser.si_probe_address == expected_probe
        assert eraser.cmpa_header_marker == 0x5963
        assert eraser.erase_token_offset == 0xD0
        assert eraser.delete_installer_offset == 0xE0
        target = eraser.cmpa_address + eraser.delete_installer_offset
        assert target == expected_cmpa + 0xE0

    def test_mcxa366_addresses(self) -> None:
        """mcxa366 retains its existing CMPA / probe addresses (different ROM)."""
        mock_mboot = _build_mboot("mcxa366")
        eraser = SecureInstallerEraser(mock_mboot, FamilyRevision("mcxa366"))

        assert eraser.cmpa_address == 0xFE000
        assert eraser.si_probe_address == 0xC0000
        target = eraser.cmpa_address + eraser.delete_installer_offset
        assert target == 0xFE0E0

    def test_magic_value_byte_order(self, mock_mboot: MagicMock) -> None:
        """Magic value is written in little-endian byte order."""
        family = FamilyRevision("mcxl255")
        eraser = SecureInstallerEraser(mock_mboot, family)

        eraser.erase(reset=False)

        call_args = mock_mboot.write_memory.call_args
        data = call_args[0][1] if len(call_args[0]) > 1 else call_args[1]["data"]
        assert len(data) == 4
        assert data == b"\x65\xff\x27\x40"
        assert int.from_bytes(data, byteorder="little") == 0x4027FF65


class TestReadEraseToken:
    """Tests for reading back the device-unique SI erase token."""

    # ROM example token from SI_IsEraseTokenValid (little-endian words on the wire).
    _TOKEN_BYTES = (
        (0xDEADBEEF).to_bytes(4, "little")
        + (0xCAFEBABE).to_bytes(4, "little")
        + (0x8BADF00D).to_bytes(4, "little")
        + (0xFEEDFACE).to_bytes(4, "little")
    )

    def test_read_erase_token_programmed(self) -> None:
        """A non-blank token is returned verbatim with programmed=True."""
        mock_mboot = _build_mboot("mcxl255", erase_token=self._TOKEN_BYTES)
        eraser = SecureInstallerEraser(mock_mboot, FamilyRevision("mcxl255"))

        token, programmed = eraser.read_erase_token()

        assert token == self._TOKEN_BYTES
        assert programmed is True

    def test_read_erase_token_blank(self) -> None:
        """A blank (all 0xFF) token reports programmed=False."""
        mock_mboot = _build_mboot("mcxl255")
        eraser = SecureInstallerEraser(mock_mboot, FamilyRevision("mcxl255"))

        token, programmed = eraser.read_erase_token()

        assert token == b"\xff" * 16
        assert programmed is False

    def test_read_erase_token_all_zeros_is_blank(self) -> None:
        """An all-0x00 token (unprogrammed on some parts, e.g. mcxa266) reports programmed=False."""
        mock_mboot = _build_mboot("mcxl255", erase_token=b"\x00" * 16)
        eraser = SecureInstallerEraser(mock_mboot, FamilyRevision("mcxl255"))

        token, programmed = eraser.read_erase_token()

        assert token == b"\x00" * 16
        assert programmed is False

    def test_read_erase_token_read_failure_raises(self) -> None:
        """A failed read raises rather than returning bogus data."""
        mock_mboot = _build_mboot("mcxl255")
        mock_mboot.read_memory.side_effect = lambda address, length: None
        eraser = SecureInstallerEraser(mock_mboot, FamilyRevision("mcxl255"))

        with pytest.raises(SPSDKError):
            eraser.read_erase_token()

    def test_erase_token_as_registers(self) -> None:
        """The 16-byte token splits into four little-endian 32-bit register values."""
        mock_mboot = _build_mboot("mcxl255")
        eraser = SecureInstallerEraser(mock_mboot, FamilyRevision("mcxl255"))

        registers = eraser.erase_token_as_registers(self._TOKEN_BYTES)

        assert registers == {
            "SI_ERASE_TOKEN0": 0xDEADBEEF,
            "SI_ERASE_TOKEN1": 0xCAFEBABE,
            "SI_ERASE_TOKEN2": 0x8BADF00D,
            "SI_ERASE_TOKEN3": 0xFEEDFACE,
        }

    def test_erase_token_as_registers_mcxa_naming(self) -> None:
        """MCXA255 parts name the token registers ERASE_TOKEN0..3 (no SI_ prefix)."""
        mock_mboot = _build_mboot("mcxa255")
        eraser = SecureInstallerEraser(mock_mboot, FamilyRevision("mcxa255"))

        registers = eraser.erase_token_as_registers(self._TOKEN_BYTES)

        assert registers == {
            "ERASE_TOKEN0": 0xDEADBEEF,
            "ERASE_TOKEN1": 0xCAFEBABE,
            "ERASE_TOKEN2": 0x8BADF00D,
            "ERASE_TOKEN3": 0xFEEDFACE,
        }

    def test_erase_token_as_registers_invalid_length(self) -> None:
        """A token of the wrong length is rejected."""
        mock_mboot = _build_mboot("mcxl255")
        eraser = SecureInstallerEraser(mock_mboot, FamilyRevision("mcxl255"))

        with pytest.raises(SPSDKError):
            eraser.erase_token_as_registers(b"\x00" * 8)


class TestCheckSIStatus:
    """Tests for the ROM-aligned `check_si_status` method."""

    def test_si_present_valid_when_receive_sb_available(self) -> None:
        """SI reports PRESENT_VALID when receive-sb-file is exposed by ROM."""
        mock_mboot = _build_mboot("mcxl255")
        mock_mboot.get_property.return_value = _make_available_commands_raw(include_receive_sb=True)
        eraser = SecureInstallerEraser(mock_mboot, FamilyRevision("mcxl255"))

        status, erase_token_programmed = eraser.check_si_status()

        assert status == SIStatus.PRESENT_VALID
        assert erase_token_programmed is False

    def test_si_erased_when_erase_token_programmed_takes_precedence(self) -> None:
        """ERASE_TOKEN being programmed wins over every other signal."""
        mock_mboot = _build_mboot("mcxl255", erase_token=b"\x11" * 16)
        # Even if receive-sb-file says SI is present, programmed token => ERASED + warn
        mock_mboot.get_property.return_value = _make_available_commands_raw(include_receive_sb=True)
        eraser = SecureInstallerEraser(mock_mboot, FamilyRevision("mcxl255"))

        status, erase_token_programmed = eraser.check_si_status()

        assert status == SIStatus.ERASED
        assert erase_token_programmed is True

    def test_si_erased_when_token_programmed_and_receive_sb_absent(self) -> None:
        """Token programmed + receive-sb missing => clean ERASED state on any phantom."""
        mock_mboot = _build_mboot("mcxl254", erase_token=b"\x42" * 16)
        mock_mboot.get_property.return_value = _make_available_commands_raw(
            include_receive_sb=False
        )
        eraser = SecureInstallerEraser(mock_mboot, FamilyRevision("mcxl254"))

        status, erase_token_programmed = eraser.check_si_status()

        assert status == SIStatus.ERASED
        assert erase_token_programmed is True

    def test_si_unknown_when_blank_token_and_probe_succeeds(self) -> None:
        """Blank token, no receive-sb, probe succeeds => no SI present (UNKNOWN)."""
        mock_mboot = _build_mboot("mcxl255")
        mock_mboot.get_property.return_value = _make_available_commands_raw(
            include_receive_sb=False
        )
        eraser = SecureInstallerEraser(mock_mboot, FamilyRevision("mcxl255"))

        status, erase_token_programmed = eraser.check_si_status()

        assert status == SIStatus.UNKNOWN
        assert erase_token_programmed is False

    def test_si_corrupted_when_probe_returns_memory_range_invalid(self) -> None:
        """Blank token, probe rejected with MEMORY_RANGE_INVALID => PRESENT_CORRUPTED."""
        mock_mboot = _build_mboot(
            "mcxl255", probe=None, probe_status=StatusCode.MEMORY_RANGE_INVALID.tag
        )
        mock_mboot.get_property.return_value = _make_available_commands_raw(
            include_receive_sb=False
        )
        eraser = SecureInstallerEraser(mock_mboot, FamilyRevision("mcxl255"))

        status, erase_token_programmed = eraser.check_si_status()

        assert status == SIStatus.PRESENT_CORRUPTED
        assert erase_token_programmed is False

    def test_si_corrupted_when_probe_raises_memory_range_invalid(self) -> None:
        """Probe raising MEMORY_RANGE_INVALID is mapped to PRESENT_CORRUPTED."""
        mock_mboot = _build_mboot("mcxl255")
        mock_mboot.get_property.return_value = _make_available_commands_raw(
            include_receive_sb=False
        )
        addrs = _FAMILY_ADDRESSES["mcxl255"]
        original_handler = mock_mboot.read_memory.side_effect

        def _raising(address: int, length: int) -> bytes | None:
            if address == addrs["si_probe"]:
                raise McuBootCommandError("ReadMemory", StatusCode.MEMORY_RANGE_INVALID.tag)
            return original_handler(address, length)

        mock_mboot.read_memory.side_effect = _raising
        eraser = SecureInstallerEraser(mock_mboot, FamilyRevision("mcxl255"))

        status, erase_token_programmed = eraser.check_si_status()

        assert status == SIStatus.PRESENT_CORRUPTED
        assert erase_token_programmed is False

    def test_si_unknown_when_probe_fails_with_other_error(self) -> None:
        """Probe failing with an unexpected status code => UNKNOWN."""
        mock_mboot = _build_mboot("mcxl255", probe=None, probe_status=StatusCode.FAIL.tag)
        mock_mboot.get_property.return_value = _make_available_commands_raw(
            include_receive_sb=False
        )
        eraser = SecureInstallerEraser(mock_mboot, FamilyRevision("mcxl255"))

        status, erase_token_programmed = eraser.check_si_status()

        assert status == SIStatus.UNKNOWN
        assert erase_token_programmed is False

    def test_check_status_treats_unreadable_erase_token_as_programmed(self) -> None:
        """When the erase token cannot be read, status defaults to ERASED (safe)."""
        mock_mboot = _build_mboot("mcxl255")
        addrs = _FAMILY_ADDRESSES["mcxl255"]

        def _read(address: int, length: int) -> bytes | None:
            if address == addrs["cmpa"] + 0xD0:
                return None
            return b"\xff" * length

        mock_mboot.read_memory.side_effect = _read
        # receive-sb-file not available — would have fallen to probe / UNKNOWN otherwise.
        mock_mboot.get_property.return_value = _make_available_commands_raw(
            include_receive_sb=False
        )
        eraser = SecureInstallerEraser(mock_mboot, FamilyRevision("mcxl255"))

        status, erase_token_programmed = eraser.check_si_status()

        assert status == SIStatus.ERASED
        assert erase_token_programmed is True

    def test_check_status_when_get_property_fails_and_token_blank(self) -> None:
        """get_property failure with blank token and successful probe => UNKNOWN."""
        mock_mboot = _build_mboot("mcxl255")
        mock_mboot.get_property.side_effect = Exception("comm error")
        eraser = SecureInstallerEraser(mock_mboot, FamilyRevision("mcxl255"))

        status, erase_token_programmed = eraser.check_si_status()

        assert status == SIStatus.UNKNOWN
        assert erase_token_programmed is False
