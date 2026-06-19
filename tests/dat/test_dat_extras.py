#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Tests for DAT extras: dar_packet verify, debug_mailbox, dm_commands."""

import os
from typing import cast
from unittest.mock import MagicMock

import pytest

from spsdk.dat.dac_packet import DebugAuthenticationChallenge as DAC
from spsdk.dat.dar_packet import (
    DebugAuthenticateResponse,
    DebugAuthenticateResponseECC_256,
    DebugAuthenticateResponseECC_384,
    DebugAuthenticateResponseECC_521,
    DebugAuthenticateResponseEdgelockEnclaveV2,
    DebugAuthenticateResponseRSA,
)
from spsdk.dat.debug_credential import DebugCredentialCertificate as DC
from spsdk.dat.debug_credential import ProtocolVersion
from spsdk.dat.debug_mailbox import DebugMailbox
from spsdk.dat.dm_commands import (
    DebugAuthenticationStart,
    DebugMailboxCommand,
    DebugMailboxCommandID,
    EnterBlankDebugAuthentication,
    EnterISPMode,
    EraseFlash,
    ExitDebugMailbox,
    GetCRPLevel,
    NxpDebugAuthenticationStart,
    SetFaultAnalysisMode,
    StartDebugMailbox,
    StartDebugSession,
)
from spsdk.exceptions import SPSDKError
from spsdk.utils.config import Config
from spsdk.utils.exceptions import SPSDKTimeoutError
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_binary, use_working_directory
from spsdk.utils.verifier import VerifierResult

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_dac(family: FamilyRevision) -> DAC:
    """Load a real DAC from the test data directory."""
    dac_bytes = load_binary(os.path.join(DATA_DIR, "sample_dac.bin"))
    return DAC.parse(dac_bytes, family)


def _make_dc(family: FamilyRevision) -> DC:
    """Load a real DC from the test data directory (RSA 2048)."""
    with use_working_directory(DATA_DIR):
        cfg = Config.create_from_file("new_dck_rsa2048.yml")
        dc = DC.load_from_config(cfg)
        dc.sign()
    return dc


def _make_mock_dm(paramlen: int = 0, resplen: int = 0) -> MagicMock:
    """Return a MagicMock that behaves like a DebugMailbox."""
    dm = MagicMock(spec=DebugMailbox)
    dm.registers = {
        "CSW": {"address": 0x00, "bits": {"REQ_PENDING": 0x02}},
        "REQUEST": {"address": 0x04},
        "RETURN": {"address": 0x08},
        "IDR": {"address": 0xFC, "expected": 0x002A0000},
    }
    dm.command_delays = {}
    dm.non_standard_statuses = {}
    return dm


# ---------------------------------------------------------------------------
# dar_packet  – __repr__ and __str__
# ---------------------------------------------------------------------------


class TestDarReprStr:
    """Tests for __repr__ and __str__ of DebugAuthenticateResponse."""

    def setup_method(self) -> None:
        self.family = FamilyRevision("lpc55s69")
        self.dac = _make_dac(self.family)
        self.dc = _make_dc(self.family)

    def test_repr(self) -> None:
        dar = DebugAuthenticateResponseRSA(
            family=self.family,
            debug_credential=self.dc,
            auth_beacon=0,
            dac=self.dac,
            sign_provider=None,
        )
        r = repr(dar)
        assert "DAR" in r or "SOCC" in r

    def test_str_contains_expected_fields(self) -> None:
        dar = DebugAuthenticateResponseRSA(
            family=self.family,
            debug_credential=self.dc,
            auth_beacon=42,
            dac=self.dac,
            sign_provider=None,
        )
        s = str(dar)
        assert "Authentication Beacon" in s
        assert "DAC" in s
        assert "DC" in s

    def test_auth_beacon_truncation(self) -> None:
        """beacon > 0xFFFF should be truncated."""
        dar = DebugAuthenticateResponseRSA(
            family=self.family,
            debug_credential=self.dc,
            auth_beacon=0x1FFFF,
            dac=self.dac,
            sign_provider=None,
        )
        assert dar.auth_beacon <= 0xFFFF


# ---------------------------------------------------------------------------
# dar_packet  – _get_class
# ---------------------------------------------------------------------------


class TestGetClass:
    """Tests for DebugAuthenticateResponse._get_class()."""

    @pytest.mark.parametrize(
        "version_str, expected_cls",
        [
            ("1.0", DebugAuthenticateResponseRSA),
            ("1.1", DebugAuthenticateResponseRSA),
            ("2.0", DebugAuthenticateResponseECC_256),
            ("2.1", DebugAuthenticateResponseECC_384),
            ("2.2", DebugAuthenticateResponseECC_521),
        ],
    )
    def test_version_mapping(self, version_str: str, expected_cls: type) -> None:
        family = FamilyRevision("lpc55s69")
        ver = ProtocolVersion(version_str)
        cls = DebugAuthenticateResponse._get_class(family, ver)
        assert cls is expected_cls


# ---------------------------------------------------------------------------
# dar_packet  – _use_pss_padding
# ---------------------------------------------------------------------------


class TestUsePssPadding:
    """Test _use_pss_padding returns a bool."""

    def test_lpc55s69_returns_bool(self) -> None:
        family = FamilyRevision("lpc55s69")
        result = DebugAuthenticateResponse._use_pss_padding(family)
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# dar_packet  – verify()
# ---------------------------------------------------------------------------


class TestVerify:
    """Tests for DebugAuthenticateResponse.verify()."""

    def setup_method(self) -> None:
        self.family = FamilyRevision("lpc55s69")
        self.dac = _make_dac(self.family)
        self.dc = _make_dc(self.family)

    def _make_dar(self, dac: object = None, dc: object = None):  # type: ignore[no-untyped-def, return]
        return DebugAuthenticateResponseRSA(
            family=self.family,
            debug_credential=dc or self.dc,  # type: ignore[arg-type]
            auth_beacon=0,
            dac=dac or self.dac,  # type: ignore[arg-type]
            sign_provider=None,
        )

    def test_verify_mismatched_protocol_version(self) -> None:
        """Mismatched protocol version should produce an ERROR record."""
        mock_dc = MagicMock()
        mock_dc.version = ProtocolVersion("2.0")
        mock_dc.socc = self.dac.socc
        mock_dc.uuid = self.dac.uuid  # matching UUID
        mock_dc.calculate_hash.return_value = self.dac.rotid_rkth_hash
        dar = self._make_dar(dc=mock_dc)
        result = dar.verify()
        version_record = next(r for r in result.records if "Protocol version" in r.name)
        assert version_record.result == VerifierResult.ERROR

    def test_verify_mismatched_socc_between_dac_and_dc(self) -> None:
        """DAC.socc != DC.socc should produce an ERROR record."""
        mock_dc = MagicMock()
        mock_dc.version = self.dac.version
        mock_dc.socc = 0xDEAD  # different from DAC socc
        mock_dc.uuid = self.dac.uuid
        mock_dc.calculate_hash.return_value = self.dac.rotid_rkth_hash
        dar = self._make_dar(dc=mock_dc)
        result = dar.verify()
        socc_record = next(r for r in result.records if "SOCC" in r.name)
        assert socc_record.result == VerifierResult.ERROR

    def test_verify_socc_mismatch_with_family(self) -> None:
        """DAC.socc != family SOCC should produce an ERROR record."""
        mock_dac = MagicMock()
        mock_dac.version = self.dc.version
        mock_dac.socc = 0xABCD  # wrong SOCC – won't match family
        mock_dac.uuid = self.dc.uuid
        mock_dac.rotid_rkth_hash = self.dac.rotid_rkth_hash
        mock_dac.challenge = self.dac.challenge
        mock_dc = MagicMock()
        mock_dc.version = self.dc.version
        mock_dc.socc = 0xABCD  # same as DAC but wrong for family
        mock_dc.uuid = self.dc.uuid
        mock_dc.calculate_hash.return_value = b""
        dar = self._make_dar(dac=mock_dac, dc=mock_dc)
        result = dar.verify()
        socc_record = next(r for r in result.records if "SOCC" in r.name)
        assert socc_record.result == VerifierResult.ERROR

    def test_verify_general_uuid_warning(self) -> None:
        """DC UUID all-zeros should produce a WARNING."""
        mock_dc = MagicMock()
        mock_dc.version = self.dac.version
        mock_dc.socc = self.dac.socc
        mock_dc.uuid = bytes(16)  # all zeros = general UUID
        mock_dc.calculate_hash.return_value = self.dac.rotid_rkth_hash
        dar = self._make_dar(dc=mock_dc)
        result = dar.verify()
        uuid_record = next(r for r in result.records if "UUID" in r.name)
        assert uuid_record.result == VerifierResult.WARNING

    def test_verify_mismatched_uuid(self) -> None:
        """DAC UUID != DC UUID should produce an ERROR."""
        mock_dc = MagicMock()
        mock_dc.version = self.dac.version
        mock_dc.socc = self.dac.socc
        mock_dc.uuid = bytes(range(16))  # non-zero but different
        mock_dc.calculate_hash.return_value = self.dac.rotid_rkth_hash
        dar = self._make_dar(dc=mock_dc)
        result = dar.verify()
        uuid_record = next(r for r in result.records if "UUID" in r.name)
        assert uuid_record.result == VerifierResult.ERROR

    def test_verify_success(self) -> None:
        """Matching DAC/DC should produce SUCCEEDED for version, SOCC, UUID."""
        mock_dc = MagicMock()
        mock_dc.version = self.dac.version
        mock_dc.socc = self.dac.socc
        mock_dc.uuid = self.dac.uuid  # match exactly
        mock_dc.calculate_hash.return_value = self.dac.rotid_rkth_hash
        dar = self._make_dar(dc=mock_dc)
        result = dar.verify()
        version_record = next(r for r in result.records if "Protocol version" in r.name)
        socc_record = next(r for r in result.records if "SOCC" in r.name)
        uuid_record = next(r for r in result.records if "UUID" in r.name)
        assert version_record.result == VerifierResult.SUCCEEDED
        assert socc_record.result == VerifierResult.SUCCEEDED
        assert uuid_record.result == VerifierResult.SUCCEEDED


# ---------------------------------------------------------------------------
# dar_packet  – EleV2 __repr__
# ---------------------------------------------------------------------------


class TestEleV2Repr:
    """Tests for DebugAuthenticateResponseEdgelockEnclaveV2.__repr__."""

    def test_repr_contains_ele(self) -> None:
        family = FamilyRevision("lpc55s69")
        dac = _make_dac(family)
        dc = _make_dc(family)
        sign_message = MagicMock()
        dar = DebugAuthenticateResponseEdgelockEnclaveV2(
            family=family,
            debug_credential=dc,
            auth_beacon=0,
            dac=dac,
            sign_message=sign_message,
        )
        r = repr(dar)
        assert "ELE" in r or "SOCC" in r


# ---------------------------------------------------------------------------
# debug_mailbox  – DebugMailbox  (unit tests with MagicMock)
# ---------------------------------------------------------------------------


def _make_mailbox_no_init(family_str: str = "lpc55s69") -> DebugMailbox:
    """Create a DebugMailbox instance bypassing __init__ for unit testing."""
    dm = object.__new__(DebugMailbox)
    dm.family = FamilyRevision(family_str)
    dm.dbgmlbx_ap_ix = 2
    dm.non_standard_statuses = {}
    dm.command_delays = {}
    dm.reset = False
    dm.moredelay = 0.0
    dm.op_timeout = 1000
    from spsdk.dat.debug_mailbox import REGISTERS

    dm.registers = REGISTERS
    dm.debug_probe = MagicMock()
    dm.debug_probe.get_coresight_ap_address.return_value = 0
    return dm


class TestDebugMailboxReadIdr:
    """Tests for DebugMailbox.read_idr()."""

    def test_read_idr_matching(self) -> None:
        """When IDR matches expected, no warning is raised."""
        dm = _make_mailbox_no_init()
        dm.debug_probe.coresight_reg_read_safe.return_value = 0x002A0000  # type: ignore[attr-defined]
        result = dm.read_idr()
        assert result == 0x002A0000

    def test_read_idr_mismatch_still_returns(self) -> None:
        """When IDR doesn't match, a warning is logged but value is returned."""
        dm = _make_mailbox_no_init()
        unexpected = 0xDEADBEEF
        dm.debug_probe.coresight_reg_read_safe.return_value = unexpected  # type: ignore[attr-defined]
        result = dm.read_idr()
        assert result == unexpected


class TestDebugMailboxClose:
    """Tests for DebugMailbox.close()."""

    def test_close_calls_probe_close(self) -> None:
        dm = _make_mailbox_no_init()
        dm.close()
        dm.debug_probe.close.assert_called_once()  # type: ignore[attr-defined]


class TestDebugMailboxSpinRead:
    """Tests for DebugMailbox.spin_read()."""

    def test_spin_read_success(self) -> None:
        dm = _make_mailbox_no_init()
        dm.debug_probe.coresight_reg_read_safe.return_value = 0xCAFEBABE  # type: ignore[attr-defined]
        result = dm.spin_read(dm.registers["RETURN"]["address"])
        assert result == 0xCAFEBABE

    def test_spin_read_timeout(self) -> None:
        """spin_read should raise SPSDKTimeoutError when all reads fail."""
        from spsdk.exceptions import SPSDKError

        dm = _make_mailbox_no_init()
        dm.op_timeout = 1  # very short timeout
        dm.debug_probe.coresight_reg_read_safe.side_effect = SPSDKError("read fail")  # type: ignore[attr-defined]
        with pytest.raises(SPSDKTimeoutError):
            dm.spin_read(dm.registers["RETURN"]["address"])


class TestDebugMailboxSpinWrite:
    """Tests for DebugMailbox.spin_write()."""

    def test_spin_write_success(self) -> None:
        """spin_write completes when CSW REQ_PENDING clears."""
        dm = _make_mailbox_no_init()
        # First call writes, then CSW reads return 0 (REQ_PENDING cleared)
        dm.debug_probe.coresight_reg_read_safe.return_value = 0x00  # type: ignore[attr-defined]
        dm.spin_write(dm.registers["REQUEST"]["address"], 0x1234)
        dm.debug_probe.coresight_reg_write_safe.assert_called()  # type: ignore[attr-defined]

    def test_spin_write_timeout(self) -> None:
        """spin_write raises SPSDKTimeoutError on persistent REQ_PENDING."""
        dm = _make_mailbox_no_init()
        dm.op_timeout = 1
        # REQ_PENDING never clears
        cast(MagicMock, dm.debug_probe.coresight_reg_read_safe).return_value = (
            0x02  # REQ_PENDING set
        )
        with pytest.raises(SPSDKTimeoutError):
            dm.spin_write(dm.registers["REQUEST"]["address"], 0x01)


# ---------------------------------------------------------------------------
# dm_commands  – subcommand class attributes
# ---------------------------------------------------------------------------


class TestSubcommandClasses:
    """Test that subcommand classes have correct CMD IDs."""

    def test_start_debug_mailbox_cmd(self) -> None:
        assert StartDebugMailbox.CMD == DebugMailboxCommandID.START

    def test_get_crp_level_cmd(self) -> None:
        assert GetCRPLevel.CMD == DebugMailboxCommandID.GET_CRP_LEVEL

    def test_erase_flash_cmd(self) -> None:
        assert EraseFlash.CMD == DebugMailboxCommandID.ERASE_FLASH

    def test_exit_debug_mailbox_cmd(self) -> None:
        assert ExitDebugMailbox.CMD == DebugMailboxCommandID.EXIT

    def test_enter_isp_mode_paramlen(self) -> None:
        dm = _make_mock_dm()
        cmd = EnterISPMode(dm)
        assert cmd.paramlen == 1

    def test_enter_blank_debug_auth_paramlen(self) -> None:
        dm = _make_mock_dm()
        cmd = EnterBlankDebugAuthentication(dm)
        assert cmd.paramlen == 8

    def test_debug_authentication_start_resplen(self) -> None:
        dm = _make_mock_dm()
        cmd = DebugAuthenticationStart(dm)
        assert cmd.resplen == 26

    def test_nxp_debug_authentication_start_resplen(self) -> None:
        dm = _make_mock_dm()
        cmd = NxpDebugAuthenticationStart(dm)
        assert cmd.resplen == 26

    def test_set_fault_analysis_mode_default_paramlen(self) -> None:
        dm = _make_mock_dm()
        cmd = SetFaultAnalysisMode(dm)
        assert cmd.paramlen == 0

    def test_start_debug_session_cmd(self) -> None:
        assert StartDebugSession.CMD == DebugMailboxCommandID.START_DBG_SESSION


# ---------------------------------------------------------------------------
# dm_commands  – DebugMailboxCommand.run() and run_safe()
# ---------------------------------------------------------------------------


class TestDebugMailboxCommandRun:
    """Tests for DebugMailboxCommand.run()."""

    def _make_dm_cmd(self, paramlen: int = 0, resplen: int = 0) -> tuple:  # type: ignore[type-arg]
        dm = _make_mock_dm()
        cmd = DebugMailboxCommand(dm, paramlen=paramlen, resplen=resplen)
        cmd.CMD = DebugMailboxCommandID.START
        return cmd, dm

    def test_run_no_params_no_resp_success(self) -> None:
        """run() with no params and no response succeeds."""
        cmd, dm = self._make_dm_cmd()  # type: ignore[misc]
        dm.spin_read.return_value = 0x00000000  # status=0, resplen=0  # type: ignore
        dm.spin_write.return_value = None  # type: ignore[has-type]
        result = cmd.run()  # type: ignore[has-type]
        assert isinstance(result, list)

    def test_run_params_length_mismatch_raises(self) -> None:
        """run() raises SPSDKError when param count doesn't match paramlen."""
        cmd, dm = self._make_dm_cmd(paramlen=2)  # type: ignore[misc, func-returns-value]
        with pytest.raises(SPSDKError, match="parameters length"):
            cmd.run(params=[1])  # only 1 param, expects 2  # type: ignore

    def test_run_error_status_raises(self) -> None:
        """run() raises SPSDKError when device returns non-zero status."""
        cmd, dm = self._make_dm_cmd(resplen=2)  # type: ignore[misc, func-returns-value]
        # status=0x0001, resplen=0 -> error
        dm.spin_read.return_value = 0x00000001  # type: ignore[has-type]
        dm.spin_write.return_value = None  # type: ignore[has-type]
        with pytest.raises(SPSDKError):
            cmd.run()  # type: ignore[has-type]

    def test_run_safe_returns_none_on_timeout(self) -> None:
        """run_safe() returns None when timeout, if raise_if_failure=False."""
        cmd, dm = self._make_dm_cmd()  # type: ignore[misc]
        dm.spin_write.side_effect = SPSDKTimeoutError("timeout")  # type: ignore[has-type]
        result = cmd.run_safe(raise_if_failure=False)  # type: ignore[has-type]
        assert result is None

    def test_run_safe_raises_on_timeout(self) -> None:
        """run_safe() re-raises SPSDKTimeoutError if raise_if_failure=True."""
        cmd, dm = self._make_dm_cmd()  # type: ignore[misc]
        dm.spin_write.side_effect = SPSDKTimeoutError("timeout")  # type: ignore[has-type]
        with pytest.raises(SPSDKTimeoutError):
            cmd.run_safe(raise_if_failure=True)  # type: ignore[has-type]

    def test_run_safe_success(self) -> None:
        """run_safe() returns result on success."""
        cmd, dm = self._make_dm_cmd()  # type: ignore[misc]
        dm.spin_read.return_value = 0x00000000  # type: ignore[has-type]
        dm.spin_write.return_value = None  # type: ignore[has-type]
        result = cmd.run_safe()  # type: ignore[has-type]
        assert result is not None

    def test_run_params_bad_ack_raises(self) -> None:
        """run() raises when device ACK is not 0xA5A5."""
        cmd, dm = self._make_dm_cmd(paramlen=1)  # type: ignore[misc, func-returns-value]
        # Return a value that is NOT 0xA5A5 in the lower 16 bits
        dm.spin_read.return_value = 0x00000000  # type: ignore[has-type]
        dm.spin_write.return_value = None  # type: ignore[has-type]
        with pytest.raises(SPSDKError):
            cmd.run(params=[0x1234])  # type: ignore[has-type]

    def test_run_resplen_mismatch_raises(self) -> None:
        """run() raises SPSDKError when device resplen doesn't match expected."""
        cmd, dm = self._make_dm_cmd(resplen=3)  # type: ignore[misc, func-returns-value]
        # status=0, resplen=1 (different from expected 3)
        dm.spin_read.return_value = (1 << 16) | 0x0000  # type: ignore[has-type]
        dm.spin_write.return_value = None  # type: ignore[has-type]
        with pytest.raises(SPSDKError):
            cmd.run()  # type: ignore[has-type]
