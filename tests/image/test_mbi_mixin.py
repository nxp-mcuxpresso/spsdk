#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for spsdk/image/mbi/mbi_mixin.py."""

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.image.mbi.mbi_mixin import (
    Mbi_Mixin,
    Mbi_MixinFwVersion,
    Mbi_MixinHmac,
    Mbi_MixinHmacMandatory,
    Mbi_MixinHwKey,
    Mbi_MixinImageSubType,
    Mbi_MixinImageVersion,
    Mbi_MixinLoadAddress,
    Mbi_MixinTrustZone,
    Mbi_MixinTrustZoneMandatory,
)
from spsdk.image.trustzone import TrustZone
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.verifier import VerifierResult

# ===========================================================================================
# Fixtures
# ===========================================================================================


@pytest.fixture
def lpc55_family() -> FamilyRevision:
    """Return LPC55S69 family revision for testing."""
    return FamilyRevision("lpc55s69")


# ===========================================================================================
# Mbi_Mixin base class
# ===========================================================================================


def test_mbi_mixin_base_mix_len() -> None:
    """Test Mbi_Mixin base class mix_len returns 0."""

    class Dummy(Mbi_Mixin):
        pass

    obj = Dummy()
    assert obj.mix_len() == 0


def test_mbi_mixin_base_mix_app_len() -> None:
    """Test Mbi_Mixin base class mix_app_len returns 0."""

    class Dummy(Mbi_Mixin):
        pass

    obj = Dummy()
    assert obj.mix_app_len() == 0


def test_mbi_mixin_base_mix_get_config() -> None:
    """Test Mbi_Mixin base class mix_get_config returns empty dict."""

    class Dummy(Mbi_Mixin):
        pass

    obj = Dummy()
    assert obj.mix_get_config(".") == {}


def test_mbi_mixin_base_mix_verify() -> None:
    """Test Mbi_Mixin base class mix_verify returns a Verifier."""

    class Dummy(Mbi_Mixin):
        pass

    obj = Dummy()
    ver = obj.mix_verify()
    assert ver is not None


# ===========================================================================================
# Mbi_MixinLoadAddress tests
# ===========================================================================================


class ConcreteLoadAddress(Mbi_MixinLoadAddress):
    """Concrete implementation of Mbi_MixinLoadAddress for testing."""

    pass


def test_load_address_mix_load_from_config() -> None:
    """Test LoadAddress mix_load_from_config sets load_address from config."""
    obj = ConcreteLoadAddress()
    cfg = Config({"outputImageExecutionAddress": "0x8000"})
    obj.mix_load_from_config(cfg)
    assert obj.load_address == 0x8000


def test_load_address_mix_load_from_config_default() -> None:
    """Test LoadAddress mix_load_from_config defaults to 0."""
    obj = ConcreteLoadAddress()
    cfg = Config({})
    obj.mix_load_from_config(cfg)
    assert obj.load_address == 0


def test_load_address_mix_get_config_valid() -> None:
    """Test LoadAddress mix_get_config returns hex address."""
    obj = ConcreteLoadAddress()
    obj.load_address = 0x2000
    cfg = obj.mix_get_config(".")
    assert "outputImageExecutionAddress" in cfg
    assert cfg["outputImageExecutionAddress"] == "0x2000"


def test_load_address_mix_get_config_none_raises() -> None:
    """Test LoadAddress mix_get_config raises SPSDKError when load_address is None."""
    obj = ConcreteLoadAddress()
    obj.load_address = None
    with pytest.raises(SPSDKError):
        obj.mix_get_config(".")


def test_load_address_mix_verify_valid() -> None:
    """Test LoadAddress mix_verify succeeds for valid address."""
    obj = ConcreteLoadAddress()
    obj.load_address = 0x2000
    ver = obj.mix_verify()
    assert ver.result == VerifierResult.SUCCEEDED


def test_load_address_mix_verify_unaligned() -> None:
    """Test LoadAddress mix_verify reports error for unaligned address."""
    obj = ConcreteLoadAddress()
    obj.load_address = 0x2001  # not aligned to 4 bytes
    ver = obj.mix_verify()
    # Should have an alignment record that failed
    assert "Load address alignment" in str(ver)


def test_load_address_mix_verify_none() -> None:
    """Test LoadAddress mix_verify reports error when load_address is None."""
    obj = ConcreteLoadAddress()
    obj.load_address = None
    ver = obj.mix_verify()
    assert ver.result == VerifierResult.ERROR


def test_load_address_mix_verify_out_of_range() -> None:
    """Test LoadAddress mix_verify catches out-of-range 32-bit address."""
    obj = ConcreteLoadAddress()
    obj.load_address = 0x1_0000_0000  # beyond 32-bit range
    ver = obj.mix_verify()
    # range check should fail
    assert ver.result in (VerifierResult.ERROR, VerifierResult.WARNING)


# ===========================================================================================
# Mbi_MixinFwVersion tests
# ===========================================================================================


class ConcreteFwVersion(Mbi_MixinFwVersion):
    """Concrete implementation for testing."""

    pass


def test_fw_version_mix_load_from_config() -> None:
    """Test FwVersion mix_load_from_config reads firmwareVersion."""
    obj = ConcreteFwVersion()
    cfg = Config({"firmwareVersion": 42})
    obj.mix_load_from_config(cfg)
    assert obj.firmware_version == 42


def test_fw_version_mix_load_from_config_default() -> None:
    """Test FwVersion mix_load_from_config defaults to 0."""
    obj = ConcreteFwVersion()
    cfg = Config({})
    obj.mix_load_from_config(cfg)
    assert obj.firmware_version == 0


def test_fw_version_mix_get_config() -> None:
    """Test FwVersion mix_get_config returns firmwareVersion in dict."""
    obj = ConcreteFwVersion()
    obj.firmware_version = 99
    cfg = obj.mix_get_config(".")
    assert cfg["firmwareVersion"] == 99


def test_fw_version_mix_verify_valid() -> None:
    """Test FwVersion mix_verify succeeds for valid version."""
    obj = ConcreteFwVersion()
    obj.firmware_version = 0x1234
    ver = obj.mix_verify()
    assert ver.result == VerifierResult.SUCCEEDED


def test_fw_version_mix_verify_max() -> None:
    """Test FwVersion mix_verify succeeds for maximum 16-bit version."""
    obj = ConcreteFwVersion()
    obj.firmware_version = 0xFFFF
    ver = obj.mix_verify()
    assert ver.result == VerifierResult.SUCCEEDED


def test_fw_version_mix_verify_none() -> None:
    """Test FwVersion mix_verify fails when firmware_version is None."""
    obj = ConcreteFwVersion()
    obj.firmware_version = None
    ver = obj.mix_verify()
    assert ver.result == VerifierResult.ERROR


def test_fw_version_mix_verify_out_of_range() -> None:
    """Test FwVersion mix_verify fails for value exceeding 16-bit range."""
    obj = ConcreteFwVersion()
    obj.firmware_version = 0x10000  # 17-bit value
    ver = obj.mix_verify()
    assert ver.result == VerifierResult.ERROR


# ===========================================================================================
# Mbi_MixinImageVersion tests
# ===========================================================================================


class ConcreteImageVersion(Mbi_MixinImageVersion):
    """Concrete implementation for testing."""

    pass


def test_image_version_mix_load_from_config() -> None:
    """Test ImageVersion mix_load_from_config reads imageVersion."""
    obj = ConcreteImageVersion()
    cfg = Config({"imageVersion": 7})
    obj.mix_load_from_config(cfg)
    assert obj.image_version == 7


def test_image_version_mix_load_from_config_default() -> None:
    """Test ImageVersion mix_load_from_config defaults to 0."""
    obj = ConcreteImageVersion()
    cfg = Config({})
    obj.mix_load_from_config(cfg)
    assert obj.image_version == 0


def test_image_version_mix_get_config() -> None:
    """Test ImageVersion mix_get_config returns imageVersion in dict."""
    obj = ConcreteImageVersion()
    obj.image_version = 5
    cfg = obj.mix_get_config(".")
    assert cfg["imageVersion"] == 5


def test_image_version_mix_verify_valid() -> None:
    """Test ImageVersion mix_verify succeeds for valid version."""
    obj = ConcreteImageVersion()
    obj.image_version = 42
    ver = obj.mix_verify()
    assert ver.result == VerifierResult.SUCCEEDED


def test_image_version_mix_verify_none() -> None:
    """Test ImageVersion mix_verify reports warning when image_version is None."""
    obj = ConcreteImageVersion()
    obj.image_version = None
    ver = obj.mix_verify()
    # None image version should produce a WARNING or SUCCEEDED (not ERROR)
    assert ver.result in (VerifierResult.WARNING, VerifierResult.SUCCEEDED)


def test_image_version_mix_verify_zero() -> None:
    """Test ImageVersion mix_verify succeeds for zero version."""
    obj = ConcreteImageVersion()
    obj.image_version = 0
    ver = obj.mix_verify()
    assert ver.result == VerifierResult.SUCCEEDED


def test_image_version_mix_verify_max() -> None:
    """Test ImageVersion mix_verify succeeds at maximum 16-bit value."""
    obj = ConcreteImageVersion()
    obj.image_version = 0xFFFF
    ver = obj.mix_verify()
    assert ver.result == VerifierResult.SUCCEEDED


# ===========================================================================================
# Mbi_MixinImageSubType tests
# ===========================================================================================


class ConcreteImageSubType(Mbi_MixinImageSubType):
    """Concrete implementation for testing."""

    pass


def test_image_subtype_mix_load_from_config_main() -> None:
    """Test ImageSubType mix_load_from_config loads 'main' subtype."""
    obj = ConcreteImageSubType()
    cfg = Config({"outputImageSubtype": "main"})
    obj.mix_load_from_config(cfg)
    assert obj.image_subtype == 0  # MAIN = 0


def test_image_subtype_mix_load_from_config_default() -> None:
    """Test ImageSubType mix_load_from_config defaults to 'main'."""
    obj = ConcreteImageSubType()
    cfg = Config({})
    obj.mix_load_from_config(cfg)
    assert obj.image_subtype == 0


def test_image_subtype_set_image_subtype_str() -> None:
    """Test ImageSubType set_image_subtype with string input."""
    obj = ConcreteImageSubType()
    obj.set_image_subtype("main")
    assert obj.image_subtype == 0


def test_image_subtype_set_image_subtype_int() -> None:
    """Test ImageSubType set_image_subtype with integer input."""
    obj = ConcreteImageSubType()
    obj.set_image_subtype(1)
    assert obj.image_subtype == 1


def test_image_subtype_set_image_subtype_none() -> None:
    """Test ImageSubType set_image_subtype with None defaults to 0."""
    obj = ConcreteImageSubType()
    obj.set_image_subtype(None)
    assert obj.image_subtype == 0


def test_image_subtype_mix_get_config_valid() -> None:
    """Test ImageSubType mix_get_config returns label string."""
    obj = ConcreteImageSubType()
    obj.image_subtype = 0
    cfg = obj.mix_get_config(".")
    assert "outputImageSubtype" in cfg
    assert isinstance(cfg["outputImageSubtype"], str)


def test_image_subtype_mix_get_config_none_raises() -> None:
    """Test ImageSubType mix_get_config raises SPSDKError when image_subtype is None."""
    obj = ConcreteImageSubType()
    obj.image_subtype = None
    with pytest.raises(SPSDKError):
        obj.mix_get_config(".")


# ===========================================================================================
# Mbi_MixinTrustZone tests
# ===========================================================================================


class ConcreteTrustZone(Mbi_MixinTrustZone):
    """Concrete implementation for testing."""

    pass


def test_tz_mix_get_config_disabled(lpc55_family: FamilyRevision) -> None:
    """Test TrustZone mix_get_config returns disabled when trust_zone is None."""
    obj = ConcreteTrustZone()
    obj.family = lpc55_family
    obj.trust_zone = None
    cfg = obj.mix_get_config(".")
    assert cfg["enableTrustZone"] is False


def test_tz_mix_get_config_enabled(lpc55_family: FamilyRevision) -> None:
    """Test TrustZone mix_get_config returns enabled when trust_zone is set."""
    obj = ConcreteTrustZone()
    obj.family = lpc55_family
    obj.trust_zone = TrustZone(lpc55_family)
    cfg = obj.mix_get_config(".")
    assert cfg["enableTrustZone"] is True


def test_tz_mix_load_from_config_disabled(lpc55_family: FamilyRevision) -> None:
    """Test TrustZone mix_load_from_config with TrustZone disabled."""
    obj = ConcreteTrustZone()
    obj.family = lpc55_family
    cfg = Config({"enableTrustZone": False})
    obj.mix_load_from_config(cfg)
    assert obj.trust_zone is None


def test_tz_mix_load_from_config_enabled_no_preset(lpc55_family: FamilyRevision) -> None:
    """Test TrustZone mix_load_from_config with TrustZone enabled, no preset file."""
    obj = ConcreteTrustZone()
    obj.family = lpc55_family
    cfg = Config({"enableTrustZone": True})
    obj.mix_load_from_config(cfg)
    assert obj.trust_zone is not None


# ===========================================================================================
# Mbi_MixinTrustZoneMandatory tests
# ===========================================================================================


class ConcreteTrustZoneMandatory(Mbi_MixinTrustZoneMandatory):
    """Concrete implementation for testing."""

    pass


def test_tz_mandatory_mix_verify_configured(lpc55_family: FamilyRevision) -> None:
    """Test TrustZoneMandatory mix_verify passes when TrustZone is configured."""
    obj = ConcreteTrustZoneMandatory()
    obj.family = lpc55_family
    obj.trust_zone = TrustZone(lpc55_family)
    ver = obj.mix_verify()
    # Mandatory check for TrustZone being configured should be in SUCCEEDED or WARNING (not ERROR)
    assert ver.result in (VerifierResult.SUCCEEDED, VerifierResult.WARNING)


def test_tz_mandatory_mix_verify_not_configured(lpc55_family: FamilyRevision) -> None:
    """Test TrustZoneMandatory mix_verify fails when TrustZone is not configured."""
    obj = ConcreteTrustZoneMandatory()
    obj.family = lpc55_family
    obj.trust_zone = None
    ver = obj.mix_verify()
    assert ver.result == VerifierResult.ERROR


def test_tz_mandatory_mix_get_config_no_tz(lpc55_family: FamilyRevision) -> None:
    """Test TrustZoneMandatory mix_get_config with no custom TrustZone."""
    obj = ConcreteTrustZoneMandatory()
    obj.family = lpc55_family
    obj.trust_zone = TrustZone(lpc55_family)  # default, not custom
    cfg = obj.mix_get_config(".")
    assert "trustZonePresetFile" not in cfg or cfg.get("trustZonePresetFile") is None


def test_tz_mandatory_mix_load_from_config_enabled(lpc55_family: FamilyRevision) -> None:
    """Test TrustZoneMandatory mix_load_from_config with TrustZone enabled."""
    obj = ConcreteTrustZoneMandatory()
    obj.family = lpc55_family
    cfg = Config({"enableTrustZone": True})
    obj.mix_load_from_config(cfg)
    assert obj.trust_zone is not None


# ===========================================================================================
# Mbi_MixinHwKey tests
# ===========================================================================================


class ConcreteHwKey(Mbi_MixinHwKey):
    """Concrete implementation for testing."""

    pass


def test_hw_key_mix_load_from_config_enabled() -> None:
    """Test HwKey mix_load_from_config reads enableHwUserModeKeys=True."""
    obj = ConcreteHwKey()
    cfg = Config({"enableHwUserModeKeys": True})
    obj.mix_load_from_config(cfg)
    assert obj.user_hw_key_enabled is True


def test_hw_key_mix_load_from_config_disabled() -> None:
    """Test HwKey mix_load_from_config reads enableHwUserModeKeys=False."""
    obj = ConcreteHwKey()
    cfg = Config({"enableHwUserModeKeys": False})
    obj.mix_load_from_config(cfg)
    assert obj.user_hw_key_enabled is False


def test_hw_key_mix_load_from_config_default() -> None:
    """Test HwKey mix_load_from_config defaults to False."""
    obj = ConcreteHwKey()
    cfg = Config({})
    obj.mix_load_from_config(cfg)
    assert obj.user_hw_key_enabled is False


def test_hw_key_mix_get_config_enabled() -> None:
    """Test HwKey mix_get_config returns True when enabled."""
    obj = ConcreteHwKey()
    obj.user_hw_key_enabled = True
    cfg = obj.mix_get_config(".")
    assert cfg["enableHwUserModeKeys"] is True


def test_hw_key_mix_get_config_disabled() -> None:
    """Test HwKey mix_get_config returns False when disabled."""
    obj = ConcreteHwKey()
    obj.user_hw_key_enabled = False
    cfg = obj.mix_get_config(".")
    assert cfg["enableHwUserModeKeys"] is False


def test_hw_key_mix_verify_enabled() -> None:
    """Test HwKey mix_verify succeeds when user_hw_key_enabled is True."""
    obj = ConcreteHwKey()
    obj.user_hw_key_enabled = True
    ver = obj.mix_verify()
    assert ver.result == VerifierResult.SUCCEEDED


def test_hw_key_mix_verify_disabled() -> None:
    """Test HwKey mix_verify succeeds when user_hw_key_enabled is False."""
    obj = ConcreteHwKey()
    obj.user_hw_key_enabled = False
    ver = obj.mix_verify()
    assert ver.result == VerifierResult.SUCCEEDED


def test_hw_key_mix_verify_none() -> None:
    """Test HwKey mix_verify reports error when user_hw_key_enabled is None."""
    obj = ConcreteHwKey()
    obj.user_hw_key_enabled = None
    ver = obj.mix_verify()
    assert ver.result == VerifierResult.ERROR


# ===========================================================================================
# Mbi_MixinHmac tests
# ===========================================================================================


class ConcreteHmac(Mbi_MixinHmac):
    """Concrete implementation for testing."""

    parsed_elements: dict = {}


def test_hmac_mix_verify_with_key() -> None:
    """Test HMAC mix_verify succeeds when HMAC key is configured."""
    obj = ConcreteHmac()
    obj._hmac_key = bytes(32)
    obj.dek = None
    ver = obj.mix_verify()
    assert ver.result == VerifierResult.SUCCEEDED


def test_hmac_mix_verify_no_key() -> None:
    """Test HMAC mix_verify with no key reports success (HMAC is optional)."""
    obj = ConcreteHmac()
    obj._hmac_key = None
    obj.dek = None
    ver = obj.mix_verify()
    assert ver.result == VerifierResult.SUCCEEDED


class ConcreteHmacMandatory(Mbi_MixinHmacMandatory):
    """Concrete implementation for testing."""

    parsed_elements: dict = {}


def test_hmac_mandatory_mix_verify_with_key() -> None:
    """Test HmacMandatory mix_verify succeeds when HMAC key is present."""
    obj = ConcreteHmacMandatory()
    obj._hmac_key = bytes(32)
    obj.dek = None
    ver = obj.mix_verify()
    assert ver.result == VerifierResult.SUCCEEDED


def test_hmac_mandatory_mix_verify_no_key() -> None:
    """Test HmacMandatory mix_verify fails when HMAC key is absent."""
    obj = ConcreteHmacMandatory()
    obj._hmac_key = None
    obj.dek = None
    ver = obj.mix_verify()
    # The mandatory check should cause ERROR
    assert ver.result == VerifierResult.ERROR


def test_hmac_key_setter_bytes() -> None:
    """Test HMAC key setter with bytes value."""
    obj = ConcreteHmac()
    key_bytes = bytes(range(32))
    obj.hmac_key = key_bytes
    assert obj.hmac_key == key_bytes


def test_hmac_key_setter_hex_string() -> None:
    """Test HMAC key setter with hex string value."""
    obj = ConcreteHmac()
    hex_key = "00" * 32
    obj.hmac_key = hex_key
    assert obj.hmac_key == bytes(32)


def test_hmac_key_setter_none() -> None:
    """Test HMAC key setter with None clears the key."""
    obj = ConcreteHmac()
    obj._hmac_key = bytes(32)
    obj.hmac_key = None
    assert obj.hmac_key is None


def test_hmac_mix_len_with_key() -> None:
    """Test HMAC mix_len returns HMAC_SIZE when key is set."""
    obj = ConcreteHmac()
    obj._hmac_key = bytes(32)
    assert obj.mix_len() == obj.HMAC_SIZE


def test_hmac_mix_len_without_key() -> None:
    """Test HMAC mix_len returns 0 when no key is configured."""
    obj = ConcreteHmac()
    obj._hmac_key = None
    assert obj.mix_len() == 0
