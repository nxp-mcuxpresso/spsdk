#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Additional tests for spsdk/dat/dar_packet.py – second supplement file.

Targets remaining uncovered lines:
  127, 164, 182-190, 207, 221-226, 238-240, 254-266, 287, 297,
  313, 320, 361, 564-565, 585-610, 630-656, 668-695
"""

import os
from unittest.mock import MagicMock, patch

import pytest

from spsdk.dat.dac_packet import DebugAuthenticationChallenge as DAC
from spsdk.dat.dar_packet import (
    DebugAuthenticateResponse,
    DebugAuthenticateResponseECC_256,
    DebugAuthenticateResponseEdgelockEnclaveV2,
    DebugAuthenticateResponseRSA,
)
from spsdk.dat.debug_credential import DebugCredentialCertificate as DC
from spsdk.dat.debug_credential import ProtocolVersion
from spsdk.exceptions import SPSDKError, SPSDKNotImplementedError, SPSDKValueError
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_binary, use_working_directory
from spsdk.utils.verifier import VerifierResult

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_dac_rsa(family: FamilyRevision) -> DAC:
    dac_bytes = load_binary(os.path.join(DATA_DIR, "sample_dac.bin"))
    return DAC.parse(dac_bytes, family)


def _load_dc_rsa(family: FamilyRevision) -> DC:
    with use_working_directory(DATA_DIR):
        cfg = Config.create_from_file("new_dck_rsa2048.yml")
        dc = DC.load_from_config(cfg)
        dc.sign()
    return dc


def _load_dac_ecc(family: FamilyRevision) -> DAC:
    dac_bytes = load_binary(os.path.join(DATA_DIR, "sample_dac_ecc.bin"))
    return DAC.parse(dac_bytes, family)


def _load_dc_ecc256(family: FamilyRevision) -> DC:
    with use_working_directory(DATA_DIR):
        cfg = Config.create_from_file("new_dck_secp256.yml")
        dc = DC.load_from_config(cfg)
        dc.sign()
    return dc


# ---------------------------------------------------------------------------
# Line 127 – _get_signature raises when sign_provider.sign returns falsy
# ---------------------------------------------------------------------------


class TestGetSignatureEmptyReturn:
    def test_signature_provider_returns_empty_raises(self) -> None:
        family = FamilyRevision("lpc55s69")
        dac = _load_dac_rsa(family)
        dc = _load_dc_rsa(family)
        mock_sp = MagicMock()
        mock_sp.sign.return_value = b""
        dar = DebugAuthenticateResponseRSA(
            family=family,
            debug_credential=dc,
            auth_beacon=0,
            dac=dac,
            sign_provider=mock_sp,
        )
        with pytest.raises(SPSDKError, match="Signature is not present"):
            dar._get_signature()


# ---------------------------------------------------------------------------
# Line 164 – DebugAuthenticateResponse.parse raises SPSDKNotImplementedError
# ---------------------------------------------------------------------------


class TestBaseParseRaises:
    def test_base_parse_raises(self) -> None:
        with pytest.raises(SPSDKNotImplementedError):
            DebugAuthenticateResponse.parse(b"\x00" * 10)


# ---------------------------------------------------------------------------
# Lines 182-190 – load_from_config with no DAC raises SPSDKValueError
# ---------------------------------------------------------------------------


class TestLoadFromConfigNoDac:
    def test_raises_when_no_dac(self) -> None:
        with pytest.raises(SPSDKValueError, match="DAC object must be specified"):
            DebugAuthenticateResponseRSA.load_from_config(MagicMock(), dac=None)

    def test_ele_v2_raises_when_no_dac(self) -> None:
        with pytest.raises(SPSDKValueError, match="DAC object must be specified"):
            DebugAuthenticateResponseEdgelockEnclaveV2.load_from_config(MagicMock(), dac=None)


# ---------------------------------------------------------------------------
# Line 207 – _use_pss_padding returns True for families with pss_padding=True
# ---------------------------------------------------------------------------


class TestUsePssPaddingExtended:
    def test_pss_padding_true_for_mimx8qxp(self) -> None:
        family = FamilyRevision("mimx8qxp")
        result = DebugAuthenticateResponse._use_pss_padding(family)
        assert result is True

    def test_pss_padding_false_for_lpc55s69(self) -> None:
        family = FamilyRevision("lpc55s69")
        result = DebugAuthenticateResponse._use_pss_padding(family)
        assert result is False


# ---------------------------------------------------------------------------
# Lines 221-226 – get_validation_schemas
# ---------------------------------------------------------------------------


class TestGetValidationSchemasExtended:
    def test_returns_list_for_lpc55s69(self) -> None:
        family = FamilyRevision("lpc55s69")
        schemas = DebugAuthenticateResponse.get_validation_schemas(family)
        assert isinstance(schemas, list)
        assert len(schemas) == 2

    def test_returns_list_for_lpc55s36(self) -> None:
        family = FamilyRevision("lpc55s36")
        schemas = DebugAuthenticateResponse.get_validation_schemas(family)
        assert isinstance(schemas, list)


# ---------------------------------------------------------------------------
# Lines 238-240 – get_validation_schemas_from_cfg
# ---------------------------------------------------------------------------


class TestGetValidationSchemasFromCfgExtended:
    def test_with_rsa_family(self) -> None:
        with use_working_directory(DATA_DIR):
            cfg = Config.create_from_file("new_dck_rsa2048.yml")
        with patch.object(
            DebugAuthenticateResponse,
            "_get_class_from_cfg",
            return_value=DebugAuthenticateResponseRSA,
        ):
            schemas = DebugAuthenticateResponse.get_validation_schemas_from_cfg(cfg)
        assert isinstance(schemas, list)
        assert len(schemas) >= 1


# ---------------------------------------------------------------------------
# Lines 254-266 – _get_class_from_cfg
# ---------------------------------------------------------------------------


class TestGetClassFromCfgExtended:
    def test_classic_rsa_family_returns_rsa_class(self) -> None:
        # This test patches _get_class_from_cfg by calling _get_class directly
        # to avoid needing a 'certificate' key in the config
        family = FamilyRevision("lpc55s69")
        cls = DebugAuthenticateResponse._get_class(family, ProtocolVersion("1.0"))
        assert cls is DebugAuthenticateResponseRSA

    def test_ele_v2_family_returns_ele_v2_class(self) -> None:
        family = FamilyRevision("mimx9596")
        mock_cfg = MagicMock(spec=Config)
        with patch("spsdk.dat.dar_packet.FamilyRevision.load_from_config", return_value=family):
            cls = DebugAuthenticateResponse._get_class_from_cfg(mock_cfg)
        assert cls is DebugAuthenticateResponseEdgelockEnclaveV2


# ---------------------------------------------------------------------------
# Line 287 – _get_class returns EleV2 when family is ELE v2
# ---------------------------------------------------------------------------


class TestGetClassEleV2Extended:
    def test_get_class_returns_ele_v2_for_mimx9596(self) -> None:
        family = FamilyRevision("mimx9596")
        cls = DebugAuthenticateResponse._get_class(family, ProtocolVersion("2.0"))
        assert cls is DebugAuthenticateResponseEdgelockEnclaveV2


# ---------------------------------------------------------------------------
# Line 297 – get_config raises SPSDKNotImplementedError
# ---------------------------------------------------------------------------


class TestGetConfigRaisesExtended:
    def test_get_config_raises(self) -> None:
        family = FamilyRevision("lpc55s69")
        dac = _load_dac_rsa(family)
        dc = _load_dc_rsa(family)
        dar = DebugAuthenticateResponseRSA(
            family=family,
            debug_credential=dc,
            auth_beacon=0,
            dac=dac,
            sign_provider=None,
        )
        with pytest.raises(SPSDKNotImplementedError):
            dar.get_config()


# ---------------------------------------------------------------------------
# Line 313 – _verify_rot_hash with dac_rot_type == "not_available"
# ---------------------------------------------------------------------------


class TestVerifyRotHashNotAvailableExtended:
    def test_not_available_succeeds(self) -> None:
        family = FamilyRevision("rw612")
        mock_dac = MagicMock()
        mock_dac.version = ProtocolVersion("1.0")
        mock_dac.socc = 0
        mock_dac.uuid = bytes(16)
        mock_dac.rotid_rkth_hash = b"\x00" * 32
        mock_dac.challenge = b"\xaa" * 32
        mock_dc = MagicMock()
        mock_dc.version = ProtocolVersion("1.0")
        mock_dc.socc = 0
        mock_dc.uuid = bytes(16)
        mock_dc.calculate_hash.return_value = b"\x00" * 32
        dar = DebugAuthenticateResponseRSA(
            family=family,
            debug_credential=mock_dc,
            auth_beacon=0,
            dac=mock_dac,
            sign_provider=None,
        )
        record = dar._verify_rot_hash()
        assert record.result == VerifierResult.SUCCEEDED
        assert "Not used" in record.value  # type: ignore[operator]


# ---------------------------------------------------------------------------
# Line 320 – _verify_rot_hash returns ERROR when hashes mismatch
# ---------------------------------------------------------------------------


class TestVerifyRotHashMismatchExtended:
    def test_hash_mismatch_returns_error(self) -> None:
        family = FamilyRevision("lpc55s69")
        mock_dac = MagicMock()
        mock_dac.version = ProtocolVersion("1.0")
        mock_dac.socc = 0
        mock_dac.uuid = bytes(16)
        mock_dac.rotid_rkth_hash = b"\x11" * 32
        mock_dac.challenge = b"\xaa" * 32
        mock_dc = MagicMock()
        mock_dc.version = ProtocolVersion("1.0")
        mock_dc.socc = 0
        mock_dc.uuid = bytes(16)
        mock_dc.calculate_hash.return_value = b"\x22" * 32
        dar = DebugAuthenticateResponseRSA(
            family=family,
            debug_credential=mock_dc,
            auth_beacon=0,
            dac=mock_dac,
            sign_provider=None,
        )
        record = dar._verify_rot_hash()
        assert record.result == VerifierResult.ERROR


# ---------------------------------------------------------------------------
# Line 361 – verify() for ELE-based family generates WARNING for protocol version
# ---------------------------------------------------------------------------


class TestVerifyEleBasedProtocolWarningExtended:
    def test_ele_based_family_protocol_warning(self) -> None:
        family = FamilyRevision("mimx8ulp")
        mock_dac = MagicMock()
        mock_dac.version = ProtocolVersion("1.0")
        mock_dac.socc = 0
        mock_dac.uuid = bytes(16)
        mock_dac.rotid_rkth_hash = b"\x00" * 32
        mock_dac.challenge = b"\x00" * 32
        mock_dc = MagicMock()
        mock_dc.version = ProtocolVersion("1.0")
        mock_dc.socc = 0
        mock_dc.uuid = bytes(16)
        mock_dc.calculate_hash.return_value = b"\x00" * 32
        dar = DebugAuthenticateResponseRSA(
            family=family,
            debug_credential=mock_dc,
            auth_beacon=0,
            dac=mock_dac,
            sign_provider=None,
        )
        result = dar.verify()
        proto_record = next(r for r in result.records if "Protocol version" in r.name)
        assert proto_record.result == VerifierResult.WARNING


# ---------------------------------------------------------------------------
# DebugAuthenticateResponseECC._get_common_data includes UUID
# ---------------------------------------------------------------------------


class TestECCGetCommonDataExtended:
    def test_common_data_includes_uuid(self) -> None:
        family = FamilyRevision("lpc55s36")
        dac = _load_dac_ecc(family)
        dc = _load_dc_ecc256(family)
        dar = DebugAuthenticateResponseECC_256(
            family=family,
            debug_credential=dc,
            auth_beacon=0,
            dac=dac,
            sign_provider=None,
        )
        data = dar._get_common_data()
        dc_size = len(dc.export())
        uuid_in_data = data[dc_size + 4 : dc_size + 4 + 16]
        assert uuid_in_data == dac.uuid


# ---------------------------------------------------------------------------
# EleV2 __repr__ and export (lines 564-565, 585-610)
# ---------------------------------------------------------------------------


class TestEleV2DarReprAndExportExtended:
    def _make(self):  # type: ignore[return-value, no-untyped-def]
        family = FamilyRevision("lpc55s69")
        dac = _load_dac_rsa(family)
        dc = _load_dc_rsa(family)
        sign_message = MagicMock()
        sign_message.export.return_value = b"\xca\xfe" * 16
        return DebugAuthenticateResponseEdgelockEnclaveV2(
            family=family,
            debug_credential=dc,
            auth_beacon=0,
            dac=dac,
            sign_message=sign_message,
        )

    def test_repr_contains_ele_v2(self) -> None:
        dar = self._make()
        r = repr(dar)
        assert "ELE v2" in r

    def test_export_calls_sign_message(self) -> None:
        dar = self._make()
        result = dar.export()
        dar.sign_message.update_fields.assert_called_once()
        dar.sign_message.export.assert_called_once()
        assert result == b"\xca\xfe" * 16


# ---------------------------------------------------------------------------
# EleV2 get_validation_schemas (lines 630-656)
# ---------------------------------------------------------------------------


class TestEleV2GetValidationSchemasExtended:
    def test_returns_list(self) -> None:
        family = FamilyRevision("mimx9596")
        schemas = DebugAuthenticateResponseEdgelockEnclaveV2.get_validation_schemas(family)
        assert isinstance(schemas, list)
        assert len(schemas) >= 3


# ---------------------------------------------------------------------------
# EleV2 _verify_rot_hash (lines 668-695)
# ---------------------------------------------------------------------------


class TestEleV2VerifyRotHashExtended:
    def _make_dar(self, family: object, srk_hash: bytes = b"\xaa" * 64, rkth: bytes = b"\xaa" * 32):  # type: ignore[no-untyped-def]
        mock_dac = MagicMock()
        mock_dac.version = ProtocolVersion("1.0")
        mock_dac.socc = 0
        mock_dac.uuid = bytes(16)
        mock_dac.rotid_rkth_hash = rkth
        mock_dac.challenge = b"\x00" * 32
        mock_dc = MagicMock()
        mock_dc.version = ProtocolVersion("1.0")
        mock_dc.socc = 0
        mock_dc.uuid = bytes(16)
        mock_dc.calculate_hash.return_value = b"\x00" * 32
        mock_sign_msg = MagicMock()
        mock_sign_msg.get_srk_hash.return_value = srk_hash
        mock_sign_msg.srk_count = 1
        mock_sign_msg.export.return_value = b""
        return DebugAuthenticateResponseEdgelockEnclaveV2(
            family=family,  # type: ignore[arg-type]
            debug_credential=mock_dc,
            auth_beacon=0,
            dac=mock_dac,
            sign_message=mock_sign_msg,
        )

    def test_not_available_rot_type_succeeds(self) -> None:
        family = FamilyRevision("mimx9596")  # dac_rot_type=not_available
        dar = self._make_dar(family)
        record = dar._verify_rot_hash()
        assert record.result == VerifierResult.SUCCEEDED
        assert "Not used" in record.value

    def test_matching_srk_hash_succeeds(self) -> None:
        family = FamilyRevision("lpc55s69")
        dar = self._make_dar(family, srk_hash=b"\xaa" * 64, rkth=b"\xaa" * 32)
        record = dar._verify_rot_hash()
        assert record.result == VerifierResult.SUCCEEDED

    def test_mismatching_srk_hash_error(self) -> None:
        family = FamilyRevision("lpc55s69")
        dar = self._make_dar(family, srk_hash=b"\xaa" * 64, rkth=b"\xbb" * 32)
        record = dar._verify_rot_hash()
        assert record.result == VerifierResult.ERROR


# ---------------------------------------------------------------------------
# EleV2 full verify()
# ---------------------------------------------------------------------------


class TestEleV2VerifyExtended:
    def test_verify_returns_verifier(self) -> None:
        family = FamilyRevision("mimx9596")
        mock_dac = MagicMock()
        mock_dac.version = ProtocolVersion("1.0")
        mock_dac.socc = 0
        mock_dac.uuid = bytes(16)
        mock_dac.rotid_rkth_hash = b"\x00" * 32
        mock_dac.challenge = b"\x00" * 32
        mock_dc = MagicMock()
        mock_dc.version = ProtocolVersion("1.0")
        mock_dc.socc = 0
        mock_dc.uuid = bytes(16)
        mock_dc.calculate_hash.return_value = b"\x00" * 32
        mock_sign_msg = MagicMock()
        mock_sign_msg.get_srk_hash.return_value = b"\x00" * 64
        mock_sign_msg.srk_count = 1
        mock_sign_msg.export.return_value = b""
        dar = DebugAuthenticateResponseEdgelockEnclaveV2(
            family=family,
            debug_credential=mock_dc,
            auth_beacon=0,
            dac=mock_dac,
            sign_message=mock_sign_msg,
        )
        result = dar.verify()
        assert len(result.records) > 0


# ---------------------------------------------------------------------------
# RSA _get_common_data appends 4-byte beacon only (no UUID)
# ---------------------------------------------------------------------------


class TestRSAGetCommonDataExtended:
    def test_common_data_has_dc_plus_beacon(self) -> None:
        family = FamilyRevision("lpc55s69")
        dac = _load_dac_rsa(family)
        dc = _load_dc_rsa(family)
        dar = DebugAuthenticateResponseRSA(
            family=family,
            debug_credential=dc,
            auth_beacon=7,
            dac=dac,
            sign_provider=None,
        )
        data = dar._get_common_data()
        dc_bytes = dc.export()
        assert data[: len(dc_bytes)] == dc_bytes
        assert data[len(dc_bytes) : len(dc_bytes) + 4] == b"\x07\x00\x00\x00"
        assert len(data) == len(dc_bytes) + 4


# ---------------------------------------------------------------------------
# _get_data_for_signature includes DAC challenge at end
# ---------------------------------------------------------------------------


class TestGetDataForSignatureExtended:
    def test_includes_challenge(self) -> None:
        family = FamilyRevision("lpc55s69")
        dac = _load_dac_rsa(family)
        dc = _load_dc_rsa(family)
        dar = DebugAuthenticateResponseRSA(
            family=family,
            debug_credential=dc,
            auth_beacon=0,
            dac=dac,
            sign_provider=None,
        )
        data = dar._get_data_for_signature()
        assert data.endswith(dac.challenge)
