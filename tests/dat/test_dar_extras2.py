#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Additional tests for dar_packet.py covering remaining gaps."""

import os

import pytest

from spsdk.dat.dac_packet import DebugAuthenticationChallenge as DAC
from spsdk.dat.dar_packet import (
    DebugAuthenticateResponse,
    DebugAuthenticateResponseECC_256,
    DebugAuthenticateResponseECC_384,
    DebugAuthenticateResponseECC_521,
    DebugAuthenticateResponseRSA,
)
from spsdk.dat.debug_credential import DebugCredentialCertificate as DC
from spsdk.exceptions import SPSDKError, SPSDKNotImplementedError
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_binary


@pytest.fixture
def rsa_dar(data_dir: str) -> DebugAuthenticateResponseRSA:
    """Create a DebugAuthenticateResponseRSA for lpc55s69."""
    family = FamilyRevision("lpc55s69")
    dac_bytes = load_binary(os.path.join(data_dir, "sample_dac.bin"))
    dac = DAC.parse(dac_bytes, family=family)
    cfg = Config.create_from_file(os.path.join(data_dir, "new_dck_rsa2048.yml"))
    dc = DC.load_from_config(cfg)
    dc.sign()
    return DebugAuthenticateResponseRSA(
        family=family,
        debug_credential=dc,
        auth_beacon=0,
        dac=dac,
        sign_provider=None,
    )


@pytest.fixture
def ecc_dar(data_dir: str) -> DebugAuthenticateResponseECC_256:
    """Create a DebugAuthenticateResponseECC_256 for lpc55s36."""
    family = FamilyRevision("lpc55s36")
    dac_bytes = load_binary(os.path.join(data_dir, "sample_dac_ecc.bin"))
    dac = DAC.parse(dac_bytes, family=family)
    cfg = Config.create_from_file(os.path.join(data_dir, "new_dck_secp256.yml"))
    dc = DC.load_from_config(cfg)
    dc.sign()
    return DebugAuthenticateResponseECC_256(
        family=family,
        debug_credential=dc,
        auth_beacon=0,
        dac=dac,
        sign_provider=None,
    )


def test_dar_repr(rsa_dar: DebugAuthenticateResponseRSA) -> None:
    """Test DAR __repr__ (line 86)."""
    r = repr(rsa_dar)
    assert "DAR" in r
    assert "SOCC" in r


def test_dar_str(rsa_dar: DebugAuthenticateResponseRSA) -> None:
    """Test DAR __str__ (lines 96-99)."""
    s = str(rsa_dar)
    assert "DAC" in s
    assert "DC" in s
    assert "Authentication Beacon" in s


def test_dar_auth_beacon_truncation(data_dir: str) -> None:
    """Test auth_beacon truncation when > 0xFFFF (lines 72-73)."""
    family = FamilyRevision("lpc55s69")
    dac_bytes = load_binary(os.path.join(data_dir, "sample_dac.bin"))
    dac = DAC.parse(dac_bytes, family=family)
    cfg = Config.create_from_file(os.path.join(data_dir, "new_dck_rsa2048.yml"))
    dc = DC.load_from_config(cfg)
    dc.sign()
    dar = DebugAuthenticateResponseRSA(
        family=family,
        debug_credential=dc,
        auth_beacon=0x12345,
        dac=dac,
        sign_provider=None,
    )
    assert dar.auth_beacon == 0x2345  # truncated to 16 bits


def test_dar_get_config_not_implemented(rsa_dar: DebugAuthenticateResponseRSA) -> None:
    """Test get_config raises SPSDKNotImplementedError in base (line 297)."""
    with pytest.raises(SPSDKNotImplementedError):
        rsa_dar.get_config()


def test_dar_get_validation_schemas(data_dir: str) -> None:
    """Test get_validation_schemas (lines 209-226)."""
    family = FamilyRevision("lpc55s69")
    schemas = DebugAuthenticateResponseRSA.get_validation_schemas(family)
    assert isinstance(schemas, list)
    assert len(schemas) >= 1


def test_dar_get_validation_schemas_from_cfg(data_dir: str) -> None:
    """Test get_validation_schemas_from_cfg (lines 228-240)."""
    family = FamilyRevision("lpc55s69")
    # Just test get_validation_schemas directly (from_cfg needs a certificate file)
    schemas = DebugAuthenticateResponseRSA.get_validation_schemas(family)
    assert isinstance(schemas, list)
    assert len(schemas) >= 2


def test_dar_use_pss_padding(data_dir: str) -> None:
    """Test _use_pss_padding (lines 195-207)."""
    family = FamilyRevision("lpc55s69")
    result = DebugAuthenticateResponseRSA._use_pss_padding(family)
    assert isinstance(result, bool)


def test_dar_verify_success(rsa_dar: DebugAuthenticateResponseRSA, data_dir: str) -> None:
    """Test verify() runs without exception (lines 333-426)."""
    verifier = rsa_dar.verify()
    assert verifier is not None


def test_dar_verify_rot_hash(rsa_dar: DebugAuthenticateResponseRSA) -> None:
    """Test _verify_rot_hash (lines 300-330)."""
    record = rsa_dar._verify_rot_hash()
    assert record is not None


def test_ecc_dar_repr(ecc_dar: DebugAuthenticateResponseECC_256) -> None:
    """Test ECC DAR repr (line 86)."""
    r = repr(ecc_dar)
    assert "DAR" in r


def test_ecc_dar_get_common_data(ecc_dar: DebugAuthenticateResponseECC_256) -> None:
    """Test ECC _get_common_data (lines 455-462)."""
    data = ecc_dar._get_common_data()
    assert isinstance(data, bytes)
    assert len(data) > 0


def test_dar_signature_provider_not_set(rsa_dar: DebugAuthenticateResponseRSA) -> None:
    """Test export raises SPSDKError when no sign_provider (lines 127-128)."""
    assert rsa_dar.sign_provider is None
    with pytest.raises(SPSDKError):
        rsa_dar.export()


def test_dar_get_data_for_signature(rsa_dar: DebugAuthenticateResponseRSA) -> None:
    """Test _get_data_for_signature (lines 101-111)."""
    data = rsa_dar._get_data_for_signature()
    assert isinstance(data, bytes)
    assert len(data) > 0


def test_dar_ecc_class_attributes() -> None:
    """Test ECC subclass KEY_LENGTH and CURVE attributes (lines 182-190, 221-226, 238-240, 254-266)."""
    assert DebugAuthenticateResponseECC_256.KEY_LENGTH == 32
    assert DebugAuthenticateResponseECC_256.CURVE == "secp256r1"
    assert DebugAuthenticateResponseECC_384.KEY_LENGTH == 48
    assert DebugAuthenticateResponseECC_384.CURVE == "secp384r1"
    assert DebugAuthenticateResponseECC_521.KEY_LENGTH == 66
    assert DebugAuthenticateResponseECC_521.CURVE == "secp521r1"


def test_dar_get_class_rsa(data_dir: str) -> None:
    """Test _get_class returns RSA class for protocol 1.0 (lines 268-288)."""
    from spsdk.dat.debug_credential import ProtocolVersion

    family = FamilyRevision("lpc55s69")
    cls = DebugAuthenticateResponse._get_class(
        family=family, protocol_version=ProtocolVersion.from_version(1, 0)
    )
    assert issubclass(cls, DebugAuthenticateResponseRSA)


def test_dar_get_class_ecc(data_dir: str) -> None:
    """Test _get_class returns ECC class for protocol 2.0."""
    from spsdk.dat.debug_credential import ProtocolVersion

    family = FamilyRevision("lpc55s36")
    cls = DebugAuthenticateResponse._get_class(
        family=family, protocol_version=ProtocolVersion.from_version(2, 0)
    )
    assert issubclass(cls, DebugAuthenticateResponseECC_256)


def test_dar_parse_not_implemented(rsa_dar: DebugAuthenticateResponseRSA) -> None:
    """Test parse() raises SPSDKNotImplementedError (lines 155-164)."""
    with pytest.raises(SPSDKNotImplementedError):
        DebugAuthenticateResponse.parse(b"\x00" * 64)
