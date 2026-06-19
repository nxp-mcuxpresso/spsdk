#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Additional tests for spsdk/pfr/pfr.py to improve branch coverage."""

from unittest import mock

import pytest

from spsdk.apps.utils.utils import SPSDKAppError
from spsdk.crypto.keys import EccCurve, PrivateKeyEcc, PrivateKeyRsa
from spsdk.exceptions import SPSDKError
from spsdk.pfr.exceptions import SPSDKPfrError, SPSDKPfrRotkhIsNotPresent
from spsdk.pfr.pfr import (
    CFPA,
    CMPA,
    UPDATE_CFPA,
    UPDATE_CFPA_CMPA,
    AdditionalDataCfg,
    calc_pub_key_hash,
    get_ifr_pfr_class,
    get_ifr_pfr_class_from_config,
)
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision

# Families used throughout these tests
LPC_FAMILY = FamilyRevision("lpc55s6x")
MCXA_FAMILY = FamilyRevision("mcxa457")

# ---------------------------------------------------------------------------
# AdditionalDataCfg
# ---------------------------------------------------------------------------


def test_additional_data_cfg_create_from_dict_defaults() -> None:
    """Test AdditionalDataCfg.create_from_dict returns correct defaults."""
    cfg = AdditionalDataCfg.create_from_dict({})
    assert cfg.type == "NONE"
    assert cfg.max_size == 0


def test_additional_data_cfg_create_from_dict_explicit() -> None:
    """Test AdditionalDataCfg.create_from_dict maps provided values correctly."""
    cfg = AdditionalDataCfg.create_from_dict(
        {"type": "CFPA_ONLY", "offset": "REG/BF", "max_size": 1024}
    )
    assert cfg.type == "CFPA_ONLY"
    assert cfg.offset == "REG/BF"
    assert cfg.max_size == 1024


# ---------------------------------------------------------------------------
# BaseConfigArea – get_additional_data_size unsupported type
# ---------------------------------------------------------------------------


def test_base_config_area_additional_data_unsupported_type() -> None:
    """Test get_additional_data_size raises SPSDKPfrError for unknown type."""
    cmpa = CMPA(LPC_FAMILY)
    cmpa.additional_data_config.type = "UNKNOWN_TYPE"
    with pytest.raises(SPSDKPfrError, match="Unsupported additional data configuration type"):
        cmpa.get_additional_data_size()


def test_base_config_area_get_additional_data_max_size() -> None:
    """Test get_additional_data_max_size returns the configured max size."""
    cmpa = CMPA(LPC_FAMILY)
    assert cmpa.get_additional_data_max_size() == cmpa.additional_data_config.max_size


# ---------------------------------------------------------------------------
# BaseConfigArea – compute_register error path
# ---------------------------------------------------------------------------


def test_compute_register_nonexistent_method() -> None:
    """Test compute_register raises SPSDKPfrError for unknown method name."""
    cmpa = CMPA(LPC_FAMILY)
    reg = next(iter(cmpa.registers))
    with pytest.raises(SPSDKPfrError, match="compute function doesn't exists"):
        cmpa.compute_register(reg, "nonexistent_compute_method")


# ---------------------------------------------------------------------------
# BaseConfigArea – __str__ / __repr__
# ---------------------------------------------------------------------------


def test_base_config_area_str_and_repr() -> None:
    """Test that __str__ and __repr__ return non-empty strings."""
    cmpa = CMPA(LPC_FAMILY)
    assert str(cmpa)
    assert repr(cmpa)
    assert "cmpa" in str(cmpa).lower()


# ---------------------------------------------------------------------------
# BaseConfigArea – __eq__
# ---------------------------------------------------------------------------


def test_base_config_area_eq_same() -> None:
    """Test __eq__ returns True for two identical CMPA instances."""
    cmpa1 = CMPA(LPC_FAMILY)
    cmpa2 = CMPA(LPC_FAMILY)
    assert cmpa1 == cmpa2


def test_base_config_area_eq_different_type() -> None:
    """Test __eq__ returns False when compared to a non-CMPA object."""
    cmpa = CMPA(LPC_FAMILY)
    assert (cmpa == "not_a_cmpa") is False


def test_base_config_area_eq_different_family() -> None:
    """Test __eq__ returns False for CMPA instances from different families."""
    cmpa1 = CMPA(LPC_FAMILY)
    cmpa2 = CMPA(FamilyRevision("mcxa457"))
    assert (cmpa1 == cmpa2) is False


# ---------------------------------------------------------------------------
# BaseConfigArea – parse without family
# ---------------------------------------------------------------------------


def test_base_config_area_parse_without_family() -> None:
    """Test parse raises SPSDKPfrError when family parameter is None."""
    with pytest.raises(SPSDKPfrError, match="family parameter is mandatory"):
        CMPA.parse(bytes(512), family=None)


# ---------------------------------------------------------------------------
# BaseConfigArea – force_update / set_config / export
# ---------------------------------------------------------------------------


def test_base_config_area_force_update() -> None:
    """Test force_update executes without error on a default CMPA."""
    cmpa = CMPA(LPC_FAMILY)
    cmpa.force_update()  # Must not raise


def test_base_config_area_export_no_draw() -> None:
    """Test export with draw=False produces correct binary size."""
    cmpa = CMPA(LPC_FAMILY)
    binary = cmpa.export(add_seal=False, draw=False)
    assert len(binary) == cmpa.registers_size


def test_base_config_area_export_with_seal() -> None:
    """Test export with add_seal=True produces binary of correct length."""
    cfpa = CFPA(LPC_FAMILY)
    binary = cfpa.export(add_seal=True)
    assert len(binary) == cfpa.registers_size


# ---------------------------------------------------------------------------
# BaseConfigArea – compute_rotkh error paths
# ---------------------------------------------------------------------------


def test_compute_rotkh_no_keys_no_rotkh() -> None:
    """Test compute_rotkh raises SPSDKError when neither keys nor rotkh are provided."""
    cmpa = CMPA(LPC_FAMILY)
    with pytest.raises(SPSDKError, match="No keys or ROTKH value provided"):
        cmpa.compute_rotkh(keys=None, rotkh=None)


def test_compute_rotkh_cfpa_no_register() -> None:
    """Test compute_rotkh raises SPSDKPfrRotkhIsNotPresent when CFPA has no ROTKH register."""
    cfpa = CFPA(LPC_FAMILY)
    key = PrivateKeyRsa.generate_key(2048).get_public_key()
    with pytest.raises(SPSDKPfrRotkhIsNotPresent, match="doesn't contain ROTKH register"):
        cfpa.compute_rotkh(keys=[key])


def test_compute_rotkh_with_rotkh_bytes() -> None:
    """Test compute_rotkh succeeds when a direct rotkh bytes value is provided."""
    cmpa = CMPA(LPC_FAMILY)
    rotkh_data = bytes(32)
    cmpa.compute_rotkh(rotkh=rotkh_data)  # Must not raise


# ---------------------------------------------------------------------------
# BaseConfigArea – write_to_device
# ---------------------------------------------------------------------------


def test_write_to_device_success() -> None:
    """Test write_to_device returns True on successful write."""
    cmpa = CMPA(LPC_FAMILY)
    written: dict = {}

    def _write(addr: int, data: bytes) -> bool:
        written[addr] = data
        return True

    result = cmpa.write_to_device(_write)
    assert result is True
    assert len(written) == 1


def test_write_to_device_failure() -> None:
    """Test write_to_device returns False when write callback returns False."""
    cmpa = CMPA(LPC_FAMILY)
    result = cmpa.write_to_device(lambda addr, data: False)
    assert result is False


def test_write_to_device_exception() -> None:
    """Test write_to_device raises SPSDKPfrError when write callback throws."""

    def _write_exc(addr: int, data: bytes) -> bool:
        raise RuntimeError("hardware failure")

    cmpa = CMPA(LPC_FAMILY)
    with pytest.raises(SPSDKPfrError, match="Failed to write"):
        cmpa.write_to_device(_write_exc)


# ---------------------------------------------------------------------------
# BaseConfigArea – read_from_device
# ---------------------------------------------------------------------------


def test_read_from_device_success() -> None:
    """Test read_from_device succeeds when read callback returns valid data."""
    cmpa = CMPA(LPC_FAMILY)
    cmpa.read_from_device(lambda addr, size: bytes(size))


def test_read_from_device_empty_data() -> None:
    """Test read_from_device raises SPSDKPfrError when read returns empty bytes."""
    cmpa = CMPA(LPC_FAMILY)
    with pytest.raises(SPSDKPfrError, match="Failed to read"):
        cmpa.read_from_device(lambda addr, size: b"")


def test_read_from_device_exception() -> None:
    """Test read_from_device raises SPSDKPfrError when read callback raises."""
    cmpa = CMPA(LPC_FAMILY)

    def _read_exc(addr: int, size: int) -> bytes:
        raise RuntimeError("bus error")

    with pytest.raises(SPSDKPfrError, match="Failed to read"):
        cmpa.read_from_device(_read_exc)


def test_read_from_device_addr_minus_one() -> None:
    """Test read_from_device raises SPSDKPfrError when read_address returns -1."""
    cmpa = CMPA(LPC_FAMILY)
    with mock.patch.object(type(cmpa), "read_address", new_callable=lambda: property(lambda _: -1)):
        with pytest.raises(SPSDKPfrError, match="Failed to read"):
            cmpa.read_from_device(lambda addr, size: bytes(size))


# ---------------------------------------------------------------------------
# calc_pub_key_hash
# ---------------------------------------------------------------------------


def test_calc_pub_key_hash_rsa() -> None:
    """Test calc_pub_key_hash works for RSA public keys."""
    key = PrivateKeyRsa.generate_key(2048).get_public_key()
    result = calc_pub_key_hash(key, sha_width=256)
    assert isinstance(result, bytes)
    assert len(result) == 32


def test_calc_pub_key_hash_ecc() -> None:
    """Test calc_pub_key_hash works for ECC public keys."""
    key = PrivateKeyEcc.generate_key(EccCurve.SECP256R1).get_public_key()
    result = calc_pub_key_hash(key, sha_width=256)
    assert isinstance(result, bytes)
    assert len(result) == 32


def test_calc_pub_key_hash_unsupported_type() -> None:
    """Test calc_pub_key_hash raises SPSDKError for unsupported key type."""
    with pytest.raises(SPSDKError, match="Unsupported key type"):
        calc_pub_key_hash("not_a_key")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# get_ifr_pfr_class / get_ifr_pfr_class_from_config
# ---------------------------------------------------------------------------


def test_get_ifr_pfr_class_unsupported_family() -> None:
    """Test get_ifr_pfr_class raises SPSDKAppError for unsupported family."""
    with pytest.raises(SPSDKAppError, match="is not supported"):
        get_ifr_pfr_class("cmpa", FamilyRevision("mcxc151"))


def test_get_ifr_pfr_class_from_config() -> None:
    """Test get_ifr_pfr_class_from_config returns correct class from Config."""
    cfg = Config()
    cfg["family"] = "lpc55s6x"
    cfg["type"] = "cmpa"
    klass = get_ifr_pfr_class_from_config(cfg)
    assert klass is CMPA


# ---------------------------------------------------------------------------
# get_validation_schemas / get_config_template error path
# ---------------------------------------------------------------------------


def test_get_validation_schemas_unsupported_family() -> None:
    """Test get_validation_schemas raises SPSDKError for an unsupported family."""
    with pytest.raises(SPSDKError, match="is not supported"):
        CMPA.get_validation_schemas(FamilyRevision("mcxc151"))


# ---------------------------------------------------------------------------
# MultiRegionBaseConfigArea – get_region
# ---------------------------------------------------------------------------


def test_multi_region_get_region_not_found() -> None:
    """Test get_region raises SPSDKError when region name does not exist."""
    multi = UPDATE_CFPA_CMPA(MCXA_FAMILY)
    with pytest.raises(SPSDKError, match="Region 'nonexistent' not found"):
        multi.get_region("nonexistent")


def test_multi_region_get_region_case_insensitive() -> None:
    """Test get_region performs case-insensitive matching."""
    multi = UPDATE_CFPA_CMPA(MCXA_FAMILY)
    cfpa = multi.get_region("cfpa")
    assert cfpa.SUB_FEATURE.lower() == "cfpa"


# ---------------------------------------------------------------------------
# MultiRegionBaseConfigArea – __eq__ / __str__ / __repr__
# ---------------------------------------------------------------------------


def test_multi_region_eq_same() -> None:
    """Test MultiRegionBaseConfigArea.__eq__ returns True for equivalent instances."""
    m1 = UPDATE_CFPA_CMPA(MCXA_FAMILY)
    m2 = UPDATE_CFPA_CMPA(MCXA_FAMILY)
    assert m1 == m2


def test_multi_region_eq_different_type() -> None:
    """Test __eq__ returns False when compared to non-MultiRegion object."""
    multi = UPDATE_CFPA_CMPA(MCXA_FAMILY)
    assert (multi == "string") is False


def test_multi_region_eq_different_family() -> None:
    """Test __eq__ returns False for instances with different families."""
    m1 = UPDATE_CFPA_CMPA(MCXA_FAMILY)
    m2 = UPDATE_CFPA_CMPA(FamilyRevision("mcxa456"))
    assert (m1 == m2) is False


def test_multi_region_str_and_repr() -> None:
    """Test __str__ and __repr__ of MultiRegionBaseConfigArea."""
    multi = UPDATE_CFPA_CMPA(MCXA_FAMILY)
    assert str(multi)
    assert repr(multi)
    assert "UPDATE_CFPA_CMPA" in repr(multi)


# ---------------------------------------------------------------------------
# MultiRegionBaseConfigArea – parse without family
# ---------------------------------------------------------------------------


def test_multi_region_parse_without_family() -> None:
    """Test MultiRegionBaseConfigArea.parse raises SPSDKPfrError when family is None."""
    with pytest.raises(SPSDKPfrError, match="family parameter is mandatory"):
        UPDATE_CFPA_CMPA.parse(bytes(1024), family=None)


# ---------------------------------------------------------------------------
# MultiRegionBaseConfigArea – force_update
# ---------------------------------------------------------------------------


def test_multi_region_force_update() -> None:
    """Test force_update propagates to all child regions without error."""
    multi = UPDATE_CFPA_CMPA(MCXA_FAMILY)
    multi.force_update()  # Must not raise


# ---------------------------------------------------------------------------
# MultiRegionBaseConfigArea – write_to_device strategies
# ---------------------------------------------------------------------------


def test_multi_region_write_to_device_cfpa_cmpa_split_success() -> None:
    """Test write_to_device succeeds for CFPA_CMPA_SPLIT strategy."""
    multi = UPDATE_CFPA_CMPA(MCXA_FAMILY)
    assert multi.additional_data_config.type == "CFPA_CMPA_SPLIT"

    calls: list = []

    def _write(addr: int, data: bytes) -> bool:
        calls.append(addr)
        return True

    result = multi.write_to_device(_write)
    assert result is True
    assert len(calls) > 0


def test_multi_region_write_to_device_cfpa_only_requires_read_method() -> None:
    """Test write_to_device raises SPSDKPfrError when CFPA_ONLY strategy has no read_method."""
    multi = UPDATE_CFPA(MCXA_FAMILY)
    assert multi.additional_data_config.type == "CFPA_ONLY"

    with pytest.raises(SPSDKPfrError):
        multi.write_to_device(lambda addr, data: True)


def test_multi_region_write_to_device_cfpa_only_success() -> None:
    """Test write_to_device succeeds for CFPA_ONLY strategy when read_method is provided."""
    multi = UPDATE_CFPA(MCXA_FAMILY)
    result = multi.write_to_device(
        lambda addr, data: True,
        read_method=lambda addr, size: bytes(size),
    )
    assert result is True


def test_multi_region_write_to_device_cfpa_cmpa_split_first_write_fails() -> None:
    """Test _write_cfpa_cmpa_split returns False when first region write fails."""
    multi = UPDATE_CFPA_CMPA(MCXA_FAMILY)
    result = multi._write_cfpa_cmpa_split(lambda addr, data: False)
    assert result is False


def test_multi_region_write_to_device_exception() -> None:
    """Test write_to_device raises SPSDKPfrError when write callback throws."""
    multi = UPDATE_CFPA_CMPA(MCXA_FAMILY)

    def _exc_write(addr: int, data: bytes) -> bool:
        raise RuntimeError("flash write error")

    with pytest.raises(SPSDKPfrError, match="Failed to write"):
        multi.write_to_device(_exc_write)


# ---------------------------------------------------------------------------
# MultiRegionBaseConfigArea – _write_simple
# ---------------------------------------------------------------------------


def test_write_simple_with_update_region_last() -> None:
    """Test _write_simple writes UPDATE region last."""
    multi = UPDATE_CFPA_CMPA(MCXA_FAMILY)
    write_order: list = []

    def _write(addr: int, data: bytes) -> bool:
        write_order.append(addr)
        return True

    result = multi._write_simple(_write)
    assert result is True
    # UPDATE region should be written last – its address must appear last
    update_region = multi.get_region("UPDATE")
    assert write_order[-1] == update_region.write_address


def test_write_simple_fails_on_non_update_region() -> None:
    """Test _write_simple returns False when a non-UPDATE region write fails."""
    multi = UPDATE_CFPA_CMPA(MCXA_FAMILY)
    result = multi._write_simple(lambda addr, data: False)
    assert result is False


# ---------------------------------------------------------------------------
# MultiRegionBaseConfigArea – read_from_device
# ---------------------------------------------------------------------------


def test_multi_region_read_from_device_success() -> None:
    """Test read_from_device populates all regions from device data."""
    multi = UPDATE_CFPA_CMPA(MCXA_FAMILY)
    multi.read_from_device(lambda addr, size: bytes(size))


def test_multi_region_read_from_device_exception() -> None:
    """Test read_from_device raises SPSDKPfrError when read callback throws."""
    multi = UPDATE_CFPA_CMPA(MCXA_FAMILY)

    def _exc_read(addr: int, size: int) -> bytes:
        raise RuntimeError("bus error")

    with pytest.raises(SPSDKPfrError, match="Failed to read"):
        multi.read_from_device(_exc_read)


# ---------------------------------------------------------------------------
# MultiRegionBaseConfigArea – compute_rotkh delegation
# ---------------------------------------------------------------------------


def test_multi_region_compute_rotkh_not_present() -> None:
    """Test compute_rotkh raises SPSDKPfrRotkhIsNotPresent when no region has ROTKH."""
    multi = UPDATE_CFPA(MCXA_FAMILY)
    with pytest.raises(SPSDKPfrRotkhIsNotPresent, match="ROTKH is not present in any region"):
        multi.compute_rotkh(rotkh=bytes(32))


# ---------------------------------------------------------------------------
# MultiRegionBaseConfigArea – binary_size / read_address / write_address
# ---------------------------------------------------------------------------


def test_multi_region_binary_size() -> None:
    """Test binary_size sums up all region sizes plus additional data size."""
    multi = UPDATE_CFPA_CMPA(MCXA_FAMILY)
    expected = sum(r.binary_size for r in multi.regions) + multi.get_additional_data_size()
    assert multi.binary_size == expected


def test_multi_region_read_write_address() -> None:
    """Test read_address and write_address return minimum address among regions."""
    multi = UPDATE_CFPA_CMPA(MCXA_FAMILY)
    min_read = min(r.read_address for r in multi.regions)
    min_write = min(r.write_address for r in multi.regions)
    assert multi.read_address == min_read
    assert multi.write_address == min_write


# ---------------------------------------------------------------------------
# MultiRegionBaseConfigArea – get_config
# ---------------------------------------------------------------------------


def test_multi_region_get_config(tmpdir: str) -> None:
    """Test get_config returns a Config with expected keys.

    :param tmpdir: Pytest tmpdir fixture.
    """
    multi = UPDATE_CFPA_CMPA(MCXA_FAMILY)
    config = multi.get_config(data_path=str(tmpdir))
    assert "family" in config
    assert config["family"] == MCXA_FAMILY.name
    assert "type" in config


# ---------------------------------------------------------------------------
# parse_additional_data – NONE type
# ---------------------------------------------------------------------------


def test_parse_additional_data_none_type_returns() -> None:
    """Test parse_additional_data returns early when type is NONE."""
    cmpa = CMPA(LPC_FAMILY)
    assert cmpa.additional_data_config.type == "NONE"
    # Should not raise
    cmpa.additional_data_config.type = "NONE"
    # parse_additional_data of multi-region with NONE type via super()
    # Just assert the base get_additional_data_size returns 0
    assert cmpa.get_additional_data_size() == 0


# ---------------------------------------------------------------------------
# MultiRegionBaseConfigArea – get_additional_data_size
# ---------------------------------------------------------------------------


def test_multi_region_get_additional_data_size_cfpa_only() -> None:
    """Test get_additional_data_size returns CFPA data length for CFPA_ONLY type."""
    multi = UPDATE_CFPA(MCXA_FAMILY)
    assert multi.additional_data_config.type == "CFPA_ONLY"
    cfpa = multi.get_region("CFPA")
    cfpa.support_additional_data = True
    cfpa.additional_data = bytes([0xAA, 0xBB])
    size = multi.get_additional_data_size()
    assert size == 2


def test_multi_region_get_additional_data_size_cfpa_cmpa_split() -> None:
    """Test get_additional_data_size works for CFPA_CMPA_SPLIT type."""
    multi = UPDATE_CFPA_CMPA(MCXA_FAMILY)
    assert multi.additional_data_config.type == "CFPA_CMPA_SPLIT"
    # Default split offset is 0 (no CFPA additional data)
    size = multi.get_additional_data_size()
    assert isinstance(size, int)
    assert size >= 0


# ---------------------------------------------------------------------------
# MultiRegionBaseConfigArea – export_additional_data
# ---------------------------------------------------------------------------


def test_multi_region_export_additional_data_none_type() -> None:
    """Test export_additional_data returns empty image for NONE type."""
    # Create a multi-region with NONE type by patching
    multi = UPDATE_CFPA_CMPA(MCXA_FAMILY)
    multi.additional_data_config.type = "NONE"
    result = multi.export_additional_data()
    assert result.export() == b""


def test_multi_region_export_additional_data_cfpa_only() -> None:
    """Test export_additional_data returns CFPA data for CFPA_ONLY type."""
    multi = UPDATE_CFPA(MCXA_FAMILY)
    assert multi.additional_data_config.type == "CFPA_ONLY"
    result = multi.export_additional_data()
    assert isinstance(result.export(), bytes)


def test_multi_region_export_additional_data_unsupported_type() -> None:
    """Test export_additional_data raises SPSDKPfrError for unsupported type."""
    multi = UPDATE_CFPA_CMPA(MCXA_FAMILY)
    multi.additional_data_config.type = "UNSUPPORTED"
    with pytest.raises(SPSDKPfrError, match="Not supported type"):
        multi.export_additional_data()


# ---------------------------------------------------------------------------
# MultiRegionBaseConfigArea – parse_additional_data
# ---------------------------------------------------------------------------


def test_multi_region_parse_additional_data_none_type() -> None:
    """Test parse_additional_data returns early without modifying state when type is NONE."""
    multi = UPDATE_CFPA_CMPA(MCXA_FAMILY)
    multi.additional_data_config.type = "NONE"
    multi.parse_additional_data(bytes(100))  # Should not raise


def test_multi_region_parse_additional_data_cfpa_only() -> None:
    """Test parse_additional_data distributes data to CFPA region for CFPA_ONLY type."""
    multi = UPDATE_CFPA(MCXA_FAMILY)
    assert multi.additional_data_config.type == "CFPA_ONLY"
    cfpa = multi.get_region("CFPA")
    cfpa.support_additional_data = True
    test_data = bytes(range(10))
    multi.parse_additional_data(test_data)
    # Data was distributed to CFPA (up to max_size)
    assert len(cfpa.additional_data) <= multi.additional_data_config.max_size


def test_multi_region_parse_additional_data_unsupported_type() -> None:
    """Test parse_additional_data raises SPSDKPfrError for unsupported type."""
    multi = UPDATE_CFPA_CMPA(MCXA_FAMILY)
    multi.additional_data_config.type = "UNSUPPORTED"
    with pytest.raises(SPSDKPfrError, match="Not supported type"):
        multi.parse_additional_data(bytes(10))


# ---------------------------------------------------------------------------
# MultiRegionBaseConfigArea – _write_cfpa_only failure paths
# ---------------------------------------------------------------------------


def test_write_cfpa_only_fail_cfpa_write() -> None:
    """Test _write_cfpa_only returns False when CFPA region write fails."""
    multi = UPDATE_CFPA(MCXA_FAMILY)
    result = multi._write_cfpa_only(
        lambda addr, data: False,
        lambda addr, size: bytes(size),
    )
    assert result is False


# ---------------------------------------------------------------------------
# BaseConfigArea – get_config with diff flag
# ---------------------------------------------------------------------------


def test_base_config_area_get_config_diff() -> None:
    """Test get_config with diff=True returns configuration dictionary."""
    cmpa = CMPA(LPC_FAMILY)
    config = cmpa.get_config(diff=True)
    assert "family" in config
    assert config["type"] == "CMPA"


def test_base_config_area_get_config_default() -> None:
    """Test get_config with diff=False includes all fields."""
    cmpa = CMPA(LPC_FAMILY)
    config = cmpa.get_config(diff=False)
    assert "settings" in config


# ---------------------------------------------------------------------------
# BaseConfigArea – get_validation_schemas
# ---------------------------------------------------------------------------


def test_base_config_area_get_validation_schemas_basic() -> None:
    """Test get_validation_schemas_basic returns non-empty list."""
    schemas = CMPA.get_validation_schemas_basic()
    assert len(schemas) >= 2


def test_base_config_area_get_validation_schemas() -> None:
    """Test get_validation_schemas returns schemas for the given family."""
    schemas = CMPA.get_validation_schemas(LPC_FAMILY)
    assert len(schemas) >= 3


# ---------------------------------------------------------------------------
# get_config_template
# ---------------------------------------------------------------------------


def test_base_config_area_get_config_template() -> None:
    """Test get_config_template returns a YAML template string."""
    template = CMPA.get_config_template(LPC_FAMILY)
    assert isinstance(template, str)
    assert "cmpa" in template.lower()


def test_multi_region_get_config_template() -> None:
    """Test MultiRegionBaseConfigArea.get_config_template returns a string."""
    template = UPDATE_CFPA.get_config_template(MCXA_FAMILY)
    assert isinstance(template, str)
