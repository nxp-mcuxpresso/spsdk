#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Unit tests for the HSE Core Reset module."""

import os
from typing import Any, Dict

import pytest
import yaml

from spsdk.exceptions import SPSDKError, SPSDKKeyError, SPSDKValueError
from spsdk.image.hse.common import CoreId
from spsdk.image.hse.core_reset import CoreResetEntry, HseCrSanction, HseCrStartOption, HseSmrMap
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import write_file
from spsdk.utils.schema_validator import CommentedConfig


@pytest.fixture
def family() -> FamilyRevision:
    """Return a family revision for testing."""
    return FamilyRevision("mcxe31b")


@pytest.fixture
def core_reset_config() -> Dict[str, Any]:
    """Return a basic Core Reset entry configuration for testing."""
    return {
        "family": "mcxe31b",
        "coreId": "M7_0",
        "crSanction": "KEEP_CORE_IN_RESET",
        "preBootSmrMap": "0x00000001",
        "passResetAddr": "0x00400000",
        "altPreBootSmrMap": "0x00000000",
        "altResetAddr": "0x00000000",
        "postBootSmrMap": "0x00000000",
        "startOption": "AUTO_START",
    }


def test_hse_smr_map_basic() -> None:
    """Test basic HseSmrMap functionality."""
    # Test individual SMR flags
    assert HseSmrMap.SMR_0 == 1
    assert HseSmrMap.SMR_1 == 2
    assert HseSmrMap.SMR_31 == (1 << 31)

    # Test combining flags
    combined = HseSmrMap.SMR_0 | HseSmrMap.SMR_1
    assert combined == 3

    # Test NONE
    assert HseSmrMap.NONE == 0


def test_hse_smr_map_from_list() -> None:
    """Test creating SMR map from list of indices."""
    smr_map = HseSmrMap.from_list(["SMR_0"])
    assert smr_map == HseSmrMap.SMR_0

    smr_map = HseSmrMap.from_list(["SMR_0", "SMR_1", "SMR_2"])
    expected = HseSmrMap.SMR_0 | HseSmrMap.SMR_1 | HseSmrMap.SMR_2
    assert smr_map == expected

    smr_map = HseSmrMap.from_list([])
    assert smr_map == HseSmrMap.NONE

    with pytest.raises(SPSDKKeyError, match="SMR_32"):
        HseSmrMap.from_list(["SMR_32"])


def test_hse_smr_map_from_int() -> None:
    """Test creating SMR map from integer value."""
    # Valid values
    smr_map = HseSmrMap.from_int(0)
    assert smr_map == HseSmrMap.NONE

    smr_map = HseSmrMap.from_int(1)
    assert smr_map == HseSmrMap.SMR_0

    smr_map = HseSmrMap.from_int(0xFFFFFFFF)
    assert smr_map.value == 0xFFFFFFFF

    # Invalid values
    with pytest.raises(SPSDKValueError, match="SMR map value must be 0-0xFFFFFFFF"):
        HseSmrMap.from_int(-1)

    with pytest.raises(SPSDKValueError, match="SMR map value must be 0-0xFFFFFFFF"):
        HseSmrMap.from_int(0x100000000)


def test_hse_smr_map_to_list() -> None:
    """Test converting SMR map to list of indices."""
    # Single SMR
    indices = HseSmrMap.SMR_0.to_list()
    assert indices == [HseSmrMap.SMR_0]

    # Multiple SMRs
    smr_map = HseSmrMap.SMR_0 | HseSmrMap.SMR_2 | HseSmrMap.SMR_31
    indices = smr_map.to_list()
    assert indices == [HseSmrMap.SMR_0, HseSmrMap.SMR_2, HseSmrMap.SMR_31]

    # No SMRs
    indices = HseSmrMap.NONE.to_list()
    assert indices == [HseSmrMap.NONE]


def test_core_reset_entry_init(family: FamilyRevision) -> None:
    """Test basic initialization of CoreResetEntry."""
    cr_entry = CoreResetEntry(
        family=family,
        core_id=CoreId.CORE_M7_0,
        cr_sanction=HseCrSanction.KEEP_CORE_IN_RESET,
        pre_boot_smr_map=HseSmrMap.SMR_0,
        pass_reset_addr=0x00400000,
        alt_pre_boot_smr_map=HseSmrMap.NONE,
        alt_reset_addr=0,
        post_boot_smr_map=HseSmrMap.NONE,
        start_option=HseCrStartOption.AUTO_START,
    )

    assert cr_entry.family == family
    assert cr_entry.core_id == CoreId.CORE_M7_0
    assert cr_entry.cr_sanction == HseCrSanction.KEEP_CORE_IN_RESET
    assert cr_entry.pre_boot_smr_map == HseSmrMap.SMR_0
    assert cr_entry.pass_reset_addr == 0x00400000
    assert cr_entry.alt_pre_boot_smr_map == HseSmrMap.NONE
    assert cr_entry.alt_reset_addr == 0
    assert cr_entry.post_boot_smr_map == HseSmrMap.NONE
    assert cr_entry.start_option == HseCrStartOption.AUTO_START


def test_core_reset_entry_convert_smr_map(family: FamilyRevision) -> None:
    """Test SMR map conversion in CoreResetEntry."""
    # Test with HseSmrMap
    cr_entry = CoreResetEntry(
        family=family,
        pre_boot_smr_map=HseSmrMap.SMR_0 | HseSmrMap.SMR_1,
    )
    assert cr_entry.pre_boot_smr_map == (HseSmrMap.SMR_0 | HseSmrMap.SMR_1)

    # Test with integer
    cr_entry = CoreResetEntry(
        family=family,
        pre_boot_smr_map=3,  # SMR_0 | SMR_1
    )
    assert cr_entry.pre_boot_smr_map == (HseSmrMap.SMR_0 | HseSmrMap.SMR_1)

    # Test with list of indices
    cr_entry = CoreResetEntry(
        family=family,
        pre_boot_smr_map=[0, 1],
    )
    assert cr_entry.pre_boot_smr_map == (HseSmrMap.SMR_0 | HseSmrMap.SMR_1)

    # Test with invalid type
    with pytest.raises(SPSDKError, match="Invalid input number"):
        CoreResetEntry(
            family=family,
            pre_boot_smr_map="invalid",  # type: ignore
        )


def test_core_reset_entry_export_parse(family: FamilyRevision) -> None:
    """Test exporting and parsing CoreResetEntry."""
    original = CoreResetEntry(
        family=family,
        core_id=CoreId.CORE_M7_1,
        cr_sanction=HseCrSanction.DIS_INDIV_KEYS,
        pre_boot_smr_map=HseSmrMap.SMR_0 | HseSmrMap.SMR_1,
        pass_reset_addr=0x00400000,
        alt_pre_boot_smr_map=HseSmrMap.SMR_2,
        alt_reset_addr=0x00500000,
        post_boot_smr_map=HseSmrMap.SMR_3,
        start_option=HseCrStartOption.MANUAL_START,
    )

    # Export to binary
    exported_data = original.export()

    # Parse from binary
    parsed = CoreResetEntry.parse(exported_data, family)

    # Verify all fields match
    assert parsed.family == original.family
    assert parsed.core_id == original.core_id
    assert parsed.cr_sanction == original.cr_sanction
    assert parsed.pre_boot_smr_map == original.pre_boot_smr_map
    assert parsed.pass_reset_addr == original.pass_reset_addr
    assert parsed.alt_pre_boot_smr_map == original.alt_pre_boot_smr_map
    assert parsed.alt_reset_addr == original.alt_reset_addr
    assert parsed.post_boot_smr_map == original.post_boot_smr_map
    assert parsed.start_option == original.start_option


def test_core_reset_entry_parse_insufficient_data() -> None:
    """Test parsing CoreResetEntry with insufficient data."""
    family = FamilyRevision("mcxe31b")

    with pytest.raises(SPSDKValueError, match="Insufficient data for Core Reset entry"):
        CoreResetEntry.parse(b"\x00\x01\x02\x03", family)


def test_core_reset_entry_parse_invalid_enum_values(family: FamilyRevision) -> None:
    """Test parsing CoreResetEntry with invalid enum values."""
    # Create data with invalid core ID
    data = b"\xff"  # Invalid core ID
    data += b"\x00" * (CoreResetEntry.SIZE - 1)  # Fill rest with zeros

    with pytest.raises(SPSDKValueError, match="Invalid enum value in Core Reset entry"):
        CoreResetEntry.parse(data, family)


def test_core_reset_entry_load_from_config(core_reset_config: dict) -> None:
    """Test loading CoreResetEntry from configuration."""
    config = Config(core_reset_config)
    cr_entry = CoreResetEntry.load_from_config(config)

    assert cr_entry.family.name == "mcxe31b"
    assert cr_entry.core_id == CoreId.CORE_M7_0
    assert cr_entry.cr_sanction == HseCrSanction.KEEP_CORE_IN_RESET
    assert cr_entry.pre_boot_smr_map == HseSmrMap.SMR_0
    assert cr_entry.pass_reset_addr == 0x00400000
    assert cr_entry.alt_pre_boot_smr_map == HseSmrMap.NONE
    assert cr_entry.alt_reset_addr == 0
    assert cr_entry.post_boot_smr_map == HseSmrMap.NONE
    assert cr_entry.start_option == HseCrStartOption.AUTO_START


def test_core_reset_entry_get_config(family: FamilyRevision) -> None:
    """Test getting configuration from CoreResetEntry."""
    cr_entry = CoreResetEntry(
        family=family,
        core_id=CoreId.CORE_M7_1,
        cr_sanction=HseCrSanction.RESET_SOC,
        pre_boot_smr_map=HseSmrMap.SMR_0 | HseSmrMap.SMR_1,
        pass_reset_addr=0x00400000,
        alt_pre_boot_smr_map=HseSmrMap.SMR_2,
        alt_reset_addr=0x00500000,
        post_boot_smr_map=HseSmrMap.SMR_3,
        start_option=HseCrStartOption.MANUAL_START,
    )

    config = cr_entry.get_config()

    assert config["family"] == "mcxe31b"
    assert config["coreId"] == "M7_1"
    assert config["crSanction"] == "RESET_SOC"
    assert config["preBootSmrMap"] == "0x00000003"
    assert config["passResetAddr"] == "0x00400000"
    assert config["altPreBootSmrMap"] == "0x00000004"
    assert config["altResetAddr"] == "0x00500000"
    assert config["postBootSmrMap"] == "0x00000008"
    assert config["startOption"] == "MANUAL_START"


def test_core_reset_entry_verify_valid(family: FamilyRevision) -> None:
    """Test verification of valid CoreResetEntry."""
    cr_entry = CoreResetEntry(
        family=family,
        core_id=CoreId.CORE_M7_0,
        cr_sanction=HseCrSanction.KEEP_CORE_IN_RESET,
        pre_boot_smr_map=HseSmrMap.SMR_0,
        pass_reset_addr=0x00400000,  # Aligned to 4 bytes
        alt_pre_boot_smr_map=HseSmrMap.NONE,
        alt_reset_addr=0,
        post_boot_smr_map=HseSmrMap.NONE,
        start_option=HseCrStartOption.AUTO_START,
    )

    verifier = cr_entry.verify()

    # Should have no errors
    assert verifier.has_errors is False


def test_core_reset_entry_verify_invalid_smr_config(family: FamilyRevision) -> None:
    """Test verification with invalid SMR configuration."""
    cr_entry = CoreResetEntry(
        family=family,
        pre_boot_smr_map=HseSmrMap.NONE,  # preBootSmrMap == 0
        alt_pre_boot_smr_map=HseSmrMap.SMR_1,  # altPreBootSmrMap != 0
    )

    verifier = cr_entry.verify()

    # Should have error about SMR map configuration
    assert verifier.has_errors is True


def test_core_reset_entry_binary_size_consistency(family: FamilyRevision) -> None:
    """Test that exported binary size is consistent."""
    cr_entry = CoreResetEntry(
        family=family,
        core_id=CoreId.CORE_M7_0,
        cr_sanction=HseCrSanction.KEEP_CORE_IN_RESET,
        pre_boot_smr_map=HseSmrMap.SMR_0,
        pass_reset_addr=0x00400000,
    )

    exported_data = cr_entry.export()

    # Size should match the calculated SIZE
    assert len(exported_data) == CoreResetEntry.SIZE


def test_core_reset_entry_template(family: FamilyRevision, tmp_path: str) -> None:
    """Test generating a template configuration."""
    template = CoreResetEntry.get_config_template(family)

    # Verify template is valid YAML
    template_dict = yaml.safe_load(template)

    # Check required fields are present
    assert "family" in template_dict
    assert "coreId" in template_dict
    assert "crSanction" in template_dict
    assert "preBootSmrMap" in template_dict
    assert "startOption" in template_dict

    # Save template to file
    yaml_data = CommentedConfig(
        main_title=("Core Reset entry configuration:"),
        schemas=CoreResetEntry.get_validation_schemas(family),
    ).get_template()
    template_file = os.path.join(tmp_path, "cr_entry_template.yaml")
    write_file(yaml_data, template_file)

    # Load template as config
    config = Config.create_from_file(template_file)

    # Verify schema validation
    schemas = CoreResetEntry.get_validation_schemas(family)
    config.check(schemas)
