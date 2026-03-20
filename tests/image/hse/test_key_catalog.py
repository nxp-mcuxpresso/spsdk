#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Unit tests for the HSE key catalog module."""

import os
from typing import Any, Dict

import pytest
import yaml

from spsdk.exceptions import SPSDKParsingError, SPSDKVerificationError
from spsdk.image.hse.common import HseKeyBits, KeyType
from spsdk.image.hse.key_catalog import KeyCatalogCfg, KeyGroupCfgEntry, KeyGroupOwner, MuMask
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import write_file


@pytest.fixture
def family() -> FamilyRevision:
    """Return a family revision for testing."""
    return FamilyRevision("mcxe31b")


@pytest.fixture
def key_group_config() -> Dict[str, Any]:
    """Return a basic key group configuration for testing."""
    return {
        "muMask": "ALL",
        "groupOwner": "ANY",
        "keyType": "AES",
        "numOfKeySlots": 10,
        "maxKeyBitLen": 256,
    }


@pytest.fixture
def key_catalog_config() -> Dict[str, Any]:
    """Return a basic key catalog configuration for testing."""
    return {
        "family": "mcxe31b",
        "nvmKeyGroups": [
            {
                "muMask": "ALL",
                "groupOwner": "ANY",
                "keyType": "SHE",
                "numOfKeySlots": 10,
                "maxKeyBitLen": 256,
            },
            {
                "muMask": "ALL",
                "groupOwner": "CUST",
                "keyType": "AES",
                "numOfKeySlots": 5,
                "maxKeyBitLen": 256,
            },
        ],
        "ramKeyGroups": [
            {
                "muMask": "ALL",
                "groupOwner": "ANY",
                "keyType": "AES",
                "numOfKeySlots": 5,
                "maxKeyBitLen": 128,
            },
        ],
    }


def test_mu_mask_enum() -> None:
    """Test MuMask enumeration."""
    assert MuMask.NONE.tag == 0
    assert MuMask.MU0.tag == 1
    assert MuMask.MU1.tag == 2
    assert MuMask.ALL.tag == 3

    assert MuMask.from_label("ALL") == MuMask.ALL
    assert MuMask.from_tag(1) == MuMask.MU0


def test_key_group_owner_enum() -> None:
    """Test KeyGroupOwner enumeration."""
    assert KeyGroupOwner.ANY.tag == 0
    assert KeyGroupOwner.CUST.tag == 1
    assert KeyGroupOwner.OEM.tag == 2

    assert KeyGroupOwner.from_label("CUST") == KeyGroupOwner.CUST
    assert KeyGroupOwner.from_tag(2) == KeyGroupOwner.OEM


def test_key_group_cfg_entry_init() -> None:
    """Test basic initialization of KeyGroupCfgEntry class."""
    key_group = KeyGroupCfgEntry(
        mu_mask=MuMask.ALL,
        group_owner=KeyGroupOwner.ANY,
        key_type=KeyType.AES,
        num_of_key_slots=10,
        max_key_bit_len=HseKeyBits.KEY256_BITS,
    )

    assert key_group.mu_mask == MuMask.ALL
    assert key_group.group_owner == KeyGroupOwner.ANY
    assert key_group.key_type == KeyType.AES
    assert key_group.num_of_key_slots == 10
    assert key_group.max_key_bit_len == HseKeyBits.KEY256_BITS


def test_key_group_cfg_entry_export_parse() -> None:
    """Test exporting and parsing KeyGroupCfgEntry."""
    # Create a key group entry
    key_group = KeyGroupCfgEntry(
        mu_mask=MuMask.MU0,
        group_owner=KeyGroupOwner.CUST,
        key_type=KeyType.ECC_PAIR,
        num_of_key_slots=5,
        max_key_bit_len=HseKeyBits.KEY256_BITS,
    )

    # Export to binary
    exported_data = key_group.export()

    # Verify size
    assert len(exported_data) == KeyGroupCfgEntry.get_size()

    # Parse from binary
    parsed_group = KeyGroupCfgEntry.parse(exported_data)

    # Verify parsed data matches original
    assert parsed_group.mu_mask == key_group.mu_mask
    assert parsed_group.group_owner == key_group.group_owner
    assert parsed_group.key_type == key_group.key_type
    assert parsed_group.num_of_key_slots == key_group.num_of_key_slots
    assert parsed_group.max_key_bit_len == key_group.max_key_bit_len


def test_key_group_cfg_entry_parse_invalid_data() -> None:
    """Test parsing invalid data."""
    # Test with empty data
    with pytest.raises(SPSDKParsingError, match="No data set for key group configuration"):
        KeyGroupCfgEntry.parse(b"")

    # Test with too short data
    with pytest.raises(SPSDKParsingError, match="Invalid data length for key group configuration"):
        KeyGroupCfgEntry.parse(b"123")


def test_key_group_cfg_entry_load_from_config(key_group_config: dict) -> None:
    """Test loading KeyGroupCfgEntry from configuration."""
    config = Config(key_group_config)
    key_group = KeyGroupCfgEntry.load_from_config(config)

    assert key_group.mu_mask == MuMask.ALL
    assert key_group.group_owner == KeyGroupOwner.ANY
    assert key_group.key_type == KeyType.AES
    assert key_group.num_of_key_slots == 10
    assert key_group.max_key_bit_len == HseKeyBits.KEY256_BITS


def test_key_group_cfg_entry_get_config() -> None:
    """Test getting configuration from KeyGroupCfgEntry."""
    key_group = KeyGroupCfgEntry(
        mu_mask=MuMask.MU1,
        group_owner=KeyGroupOwner.OEM,
        key_type=KeyType.RSA_PAIR,
        num_of_key_slots=3,
        max_key_bit_len=HseKeyBits.KEY2048_BITS,
    )

    config = key_group.get_config()

    assert config["muMask"] == "MU1"
    assert config["groupOwner"] == "OEM"
    assert config["keyType"] == "RSA_PAIR"
    assert config["numOfKeySlots"] == 3
    assert config["maxKeyBitLen"] == 2048


def test_key_group_cfg_entry_string_representation() -> None:
    """Test string representation of KeyGroupCfgEntry."""
    key_group = KeyGroupCfgEntry(
        mu_mask=MuMask.ALL,
        group_owner=KeyGroupOwner.ANY,
        key_type=KeyType.AES,
        num_of_key_slots=10,
        max_key_bit_len=HseKeyBits.KEY256_BITS,
    )

    # Test __str__
    str_repr = str(key_group)
    assert "Key Group Configuration:" in str_repr
    assert "MU Mask: ALL" in str_repr
    assert "Group Owner: ANY" in str_repr
    assert "Key Type: AES" in str_repr
    assert "Number of Key Slots: 10" in str_repr
    assert "Max Key Bit Length: 256" in str_repr

    # Test __repr__
    repr_str = repr(key_group)
    assert "HseKeyGroupCfgEntry" in repr_str
    assert "type=AES" in repr_str
    assert "owner=ANY" in repr_str
    assert "slots=10" in repr_str


def test_key_catalog_cfg_init(family: FamilyRevision) -> None:
    """Test basic initialization of KeyCatalogCfg class."""
    nvm_groups = [
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.SHE,
            num_of_key_slots=10,
            max_key_bit_len=HseKeyBits.KEY256_BITS,
        ),
    ]

    ram_groups = [
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.AES,
            num_of_key_slots=5,
            max_key_bit_len=HseKeyBits.KEY128_BITS,
        ),
    ]

    catalog = KeyCatalogCfg(
        family=family,
        nvm_key_groups=nvm_groups,
        ram_key_groups=ram_groups,
    )

    assert catalog.family == family
    assert len(catalog.nvm_key_groups) == 1
    assert len(catalog.ram_key_groups) == 1


def test_key_catalog_cfg_validation_empty_nvm() -> None:
    """Test validation fails with empty NVM catalog."""
    family = FamilyRevision("mcxe31b")

    ram_groups = [
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.AES,
            num_of_key_slots=5,
            max_key_bit_len=HseKeyBits.KEY128_BITS,
        ),
    ]

    with pytest.raises(
        SPSDKVerificationError, match="At least one group must be defined for NVM key catalog"
    ):
        KeyCatalogCfg(
            family=family,
            nvm_key_groups=[],
            ram_key_groups=ram_groups,
        ).verify().validate()


def test_key_catalog_cfg_validation_empty_ram() -> None:
    """Test validation fails with empty RAM catalog."""
    family = FamilyRevision("mcxe31b")

    nvm_groups = [
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.SHE,
            num_of_key_slots=10,
            max_key_bit_len=HseKeyBits.KEY256_BITS,
        ),
    ]

    with pytest.raises(
        SPSDKVerificationError, match="At least one group must be defined for RAM key catalog"
    ):
        KeyCatalogCfg(
            family=family,
            nvm_key_groups=nvm_groups,
            ram_key_groups=[],
        ).verify().validate()


def test_key_catalog_cfg_validation_she_group_owner() -> None:
    """Test validation fails when SHE group doesn't have ANY owner."""
    family = FamilyRevision("mcxe31b")

    nvm_groups = [
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.CUST,  # Invalid for SHE
            key_type=KeyType.SHE,
            num_of_key_slots=10,
            max_key_bit_len=HseKeyBits.KEY256_BITS,
        ),
    ]

    ram_groups = [
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.AES,
            num_of_key_slots=5,
            max_key_bit_len=HseKeyBits.KEY128_BITS,
        ),
    ]

    with pytest.raises(SPSDKVerificationError, match="SHE key group has correct owner 'ANY'"):
        KeyCatalogCfg(
            family=family,
            nvm_key_groups=nvm_groups,
            ram_key_groups=ram_groups,
        ).verify().validate()


def test_key_catalog_cfg_validation_she_group_position() -> None:
    """Test validation fails when first SHE group is not at index 0."""
    family = FamilyRevision("mcxe31b")

    nvm_groups = [
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.AES,
            num_of_key_slots=5,
            max_key_bit_len=HseKeyBits.KEY256_BITS,
        ),
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.SHE,  # SHE at index 1, should be at 0
            num_of_key_slots=10,
            max_key_bit_len=HseKeyBits.KEY256_BITS,
        ),
    ]

    ram_groups = [
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.AES,
            num_of_key_slots=5,
            max_key_bit_len=HseKeyBits.KEY128_BITS,
        ),
    ]

    with pytest.raises(
        SPSDKVerificationError,
        match="First SHE key group is at index 1 - must be mapped to group 0 in NVM catalog",
    ):
        KeyCatalogCfg(
            family=family,
            nvm_key_groups=nvm_groups,
            ram_key_groups=ram_groups,
        ).verify().validate()


def test_key_catalog_cfg_validation_shared_secret_in_nvm() -> None:
    """Test validation fails when SHARED_SECRET is in NVM catalog."""
    family = FamilyRevision("mcxe31b")

    nvm_groups = [
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.SHARED_SECRET,  # Not allowed in NVM
            num_of_key_slots=5,
            max_key_bit_len=HseKeyBits.KEY256_BITS,
        ),
    ]

    ram_groups = [
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.AES,
            num_of_key_slots=5,
            max_key_bit_len=HseKeyBits.KEY128_BITS,
        ),
    ]

    with pytest.raises(
        SPSDKVerificationError, match="SHARED_SECRET key groups can only be used in RAM key catalog"
    ):
        KeyCatalogCfg(
            family=family,
            nvm_key_groups=nvm_groups,
            ram_key_groups=ram_groups,
        ).verify().validate()


def test_key_catalog_cfg_validation_rsa_pair_in_ram() -> None:
    """Test validation fails when RSA_PAIR is in RAM catalog."""
    family = FamilyRevision("mcxe31b")

    nvm_groups = [
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.AES,
            num_of_key_slots=5,
            max_key_bit_len=HseKeyBits.KEY256_BITS,
        ),
    ]

    ram_groups = [
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.RSA_PAIR,  # Not allowed in RAM
            num_of_key_slots=3,
            max_key_bit_len=HseKeyBits.KEY2048_BITS,
        ),
    ]

    with pytest.raises(
        SPSDKVerificationError, match="RSA_PAIR key groups can only be used in NVM key catalog"
    ):
        KeyCatalogCfg(
            family=family,
            nvm_key_groups=nvm_groups,
            ram_key_groups=ram_groups,
        ).verify().validate()


def test_key_catalog_cfg_validation_ram_owner() -> None:
    """Test validation fails when RAM group doesn't have ANY owner."""
    family = FamilyRevision("mcxe31b")

    nvm_groups = [
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.AES,
            num_of_key_slots=5,
            max_key_bit_len=HseKeyBits.KEY256_BITS,
        ),
    ]

    ram_groups = [
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.CUST,  # Invalid for RAM
            key_type=KeyType.AES,
            num_of_key_slots=5,
            max_key_bit_len=HseKeyBits.KEY128_BITS,
        ),
    ]

    with pytest.raises(
        SPSDKVerificationError, match="RAM key group has invalid owner 'CUST' - must be 'ANY'"
    ):
        KeyCatalogCfg(
            family=family,
            nvm_key_groups=nvm_groups,
            ram_key_groups=ram_groups,
        ).verify().validate()


def test_key_catalog_cfg_export_parse(family: FamilyRevision) -> None:
    """Test exporting and parsing KeyCatalogCfg."""
    # Create a key catalog
    nvm_groups = [
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.SHE,
            num_of_key_slots=10,
            max_key_bit_len=HseKeyBits.KEY256_BITS,
        ),
        KeyGroupCfgEntry(
            mu_mask=MuMask.MU0,
            group_owner=KeyGroupOwner.CUST,
            key_type=KeyType.AES,
            num_of_key_slots=5,
            max_key_bit_len=HseKeyBits.KEY128_BITS,
        ),
    ]

    ram_groups = [
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.ECC_PAIR,
            num_of_key_slots=3,
            max_key_bit_len=HseKeyBits.KEY256_BITS,
        ),
    ]

    catalog = KeyCatalogCfg(
        family=family,
        nvm_key_groups=nvm_groups,
        ram_key_groups=ram_groups,
    )

    # Export to binary
    exported_data = catalog.export()

    # Verify sizes
    expected_nvm_size = (len(nvm_groups) + 1) * KeyGroupCfgEntry.get_size()  # +1 for terminator
    expected_ram_size = (len(ram_groups) + 1) * KeyGroupCfgEntry.get_size()  # +1 for terminator
    assert len(exported_data) == expected_nvm_size + expected_ram_size

    # Parse from binary
    parsed_catalog = KeyCatalogCfg.parse(exported_data, family)

    # Verify parsed data matches original
    assert len(parsed_catalog.nvm_key_groups) == len(catalog.nvm_key_groups)
    assert len(parsed_catalog.ram_key_groups) == len(catalog.ram_key_groups)

    for orig, parsed in zip(catalog.nvm_key_groups, parsed_catalog.nvm_key_groups):
        assert parsed.mu_mask == orig.mu_mask
        assert parsed.group_owner == orig.group_owner
        assert parsed.key_type == orig.key_type
        assert parsed.num_of_key_slots == orig.num_of_key_slots
        assert parsed.max_key_bit_len == orig.max_key_bit_len

    for orig, parsed in zip(catalog.ram_key_groups, parsed_catalog.ram_key_groups):
        assert parsed.mu_mask == orig.mu_mask
        assert parsed.group_owner == orig.group_owner
        assert parsed.key_type == orig.key_type
        assert parsed.num_of_key_slots == orig.num_of_key_slots
        assert parsed.max_key_bit_len == orig.max_key_bit_len


def test_key_catalog_cfg_parse_invalid_data() -> None:
    """Test parsing invalid data."""
    family = FamilyRevision("mcxe31b")

    # Test with empty data
    with pytest.raises(SPSDKParsingError, match="Missing data for key catalog configuration"):
        KeyCatalogCfg.parse(b"", family)

    # Test with incomplete data (no terminator)
    incomplete_data = KeyGroupCfgEntry(
        mu_mask=MuMask.ALL,
        group_owner=KeyGroupOwner.ANY,
        key_type=KeyType.AES,
        num_of_key_slots=5,
        max_key_bit_len=HseKeyBits.KEY256_BITS,
    ).export()

    with pytest.raises(SPSDKParsingError, match="Could not find NVM catalog terminator"):
        KeyCatalogCfg.parse(incomplete_data, family)


def test_key_catalog_cfg_load_from_config(key_catalog_config: dict) -> None:
    """Test loading KeyCatalogCfg from configuration."""
    config = Config(key_catalog_config)
    catalog = KeyCatalogCfg.load_from_config(config)

    assert catalog.family.name == "mcxe31b"
    assert len(catalog.nvm_key_groups) == 2
    assert len(catalog.ram_key_groups) == 1

    # Check first NVM group (SHE)
    assert catalog.nvm_key_groups[0].key_type == KeyType.SHE
    assert catalog.nvm_key_groups[0].group_owner == KeyGroupOwner.ANY
    assert catalog.nvm_key_groups[0].num_of_key_slots == 10

    # Check second NVM group (AES)
    assert catalog.nvm_key_groups[1].key_type == KeyType.AES
    assert catalog.nvm_key_groups[1].group_owner == KeyGroupOwner.CUST
    assert catalog.nvm_key_groups[1].num_of_key_slots == 5

    # Check RAM group
    assert catalog.ram_key_groups[0].key_type == KeyType.AES
    assert catalog.ram_key_groups[0].max_key_bit_len == HseKeyBits.KEY128_BITS


def test_key_catalog_cfg_get_config(family: FamilyRevision) -> None:
    """Test getting configuration from KeyCatalogCfg."""
    nvm_groups = [
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.SHE,
            num_of_key_slots=10,
            max_key_bit_len=HseKeyBits.KEY256_BITS,
        ),
    ]

    ram_groups = [
        KeyGroupCfgEntry(
            mu_mask=MuMask.MU0,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.AES,
            num_of_key_slots=5,
            max_key_bit_len=HseKeyBits.KEY128_BITS,
        ),
    ]

    catalog = KeyCatalogCfg(
        family=family,
        nvm_key_groups=nvm_groups,
        ram_key_groups=ram_groups,
    )

    config = catalog.get_config()

    assert config["family"] == family.name
    assert config["revision"] == family.revision
    assert len(config["nvmKeyGroups"]) == 1
    assert len(config["ramKeyGroups"]) == 1

    # Check NVM group config
    nvm_config = config["nvmKeyGroups"][0]
    assert nvm_config["keyType"] == "SHE"
    assert nvm_config["muMask"] == "ALL"
    assert nvm_config["groupOwner"] == "ANY"
    assert nvm_config["numOfKeySlots"] == 10
    assert nvm_config["maxKeyBitLen"] == 256

    # Check RAM group config
    ram_config = config["ramKeyGroups"][0]
    assert ram_config["keyType"] == "AES"
    assert ram_config["muMask"] == "MU0"
    assert ram_config["numOfKeySlots"] == 5
    assert ram_config["maxKeyBitLen"] == 128


def test_key_catalog_cfg_config_roundtrip(family: FamilyRevision) -> None:
    """Test round-trip from KeyCatalogCfg to config and back."""
    # Create original catalog
    nvm_groups = [
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.SHE,
            num_of_key_slots=10,
            max_key_bit_len=HseKeyBits.KEY256_BITS,
        ),
        KeyGroupCfgEntry(
            mu_mask=MuMask.MU1,
            group_owner=KeyGroupOwner.OEM,
            key_type=KeyType.RSA_PUB,
            num_of_key_slots=3,
            max_key_bit_len=HseKeyBits.KEY2048_BITS,
        ),
    ]

    ram_groups = [
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.ECC_PAIR,
            num_of_key_slots=5,
            max_key_bit_len=HseKeyBits.KEY384_BITS,
        ),
    ]

    original_catalog = KeyCatalogCfg(
        family=family,
        nvm_key_groups=nvm_groups,
        ram_key_groups=ram_groups,
    )

    # Get config
    config_dict = original_catalog.get_config()
    config = Config(config_dict)

    # Create new catalog from config
    new_catalog = KeyCatalogCfg.load_from_config(config)

    # Verify new catalog matches original
    assert len(new_catalog.nvm_key_groups) == len(original_catalog.nvm_key_groups)
    assert len(new_catalog.ram_key_groups) == len(original_catalog.ram_key_groups)

    for orig, new in zip(original_catalog.nvm_key_groups, new_catalog.nvm_key_groups):
        assert new.mu_mask == orig.mu_mask
        assert new.group_owner == orig.group_owner
        assert new.key_type == orig.key_type
        assert new.num_of_key_slots == orig.num_of_key_slots
        assert new.max_key_bit_len == orig.max_key_bit_len


def test_key_catalog_cfg_string_representation(family: FamilyRevision) -> None:
    """Test string representation of KeyCatalogCfg."""
    nvm_groups = [
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.SHE,
            num_of_key_slots=10,
            max_key_bit_len=HseKeyBits.KEY256_BITS,
        ),
    ]

    ram_groups = [
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.AES,
            num_of_key_slots=5,
            max_key_bit_len=HseKeyBits.KEY128_BITS,
        ),
    ]

    catalog = KeyCatalogCfg(
        family=family,
        nvm_key_groups=nvm_groups,
        ram_key_groups=ram_groups,
    )

    # Test __str__
    str_repr = str(catalog)
    assert "HSE Key Catalog Configuration:" in str_repr
    assert "NVM Key Catalog:" in str_repr
    assert "RAM Key Catalog:" in str_repr
    assert "Number of groups: 1" in str_repr
    assert "Key Type: SHE" in str_repr
    assert "Key Type: AES" in str_repr

    # Test __repr__
    repr_str = repr(catalog)
    assert "KeyCatalogCfg" in repr_str
    assert f"family={family}" in repr_str
    assert "NVM groups=1" in repr_str
    assert "RAM groups=1" in repr_str


def test_key_catalog_cfg_template(family: FamilyRevision, tmp_path: str) -> None:
    """Test generating a template configuration."""
    template = KeyCatalogCfg.get_config_template(family)

    # Verify template is valid YAML
    template_dict = yaml.safe_load(template)

    # Check required fields are present
    assert "family" in template_dict
    assert "nvmKeyGroups" in template_dict
    assert "ramKeyGroups" in template_dict

    # Save template to file and verify it can be loaded
    template_file = os.path.join(tmp_path, "key_catalog_template.yaml")
    write_file(template, template_file)

    # Load template as config
    config = Config.create_from_file(template_file)

    # Verify schema validation
    schemas = KeyCatalogCfg.get_validation_schemas(family)
    config.check(schemas)


def test_key_catalog_cfg_sizes(family: FamilyRevision) -> None:
    """Test catalog size calculations."""
    nvm_groups = [
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.SHE,
            num_of_key_slots=10,
            max_key_bit_len=HseKeyBits.KEY256_BITS,
        ),
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.CUST,
            key_type=KeyType.AES,
            num_of_key_slots=5,
            max_key_bit_len=HseKeyBits.KEY256_BITS,
        ),
    ]

    ram_groups = [
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.AES,
            num_of_key_slots=5,
            max_key_bit_len=HseKeyBits.KEY128_BITS,
        ),
    ]

    catalog = KeyCatalogCfg(
        family=family,
        nvm_key_groups=nvm_groups,
        ram_key_groups=ram_groups,
    )

    # Verify NVM catalog size (2 groups + 1 terminator)
    expected_nvm_size = 3 * KeyGroupCfgEntry.get_size()
    assert catalog.nvm_catalog_cfg_size == expected_nvm_size

    # Verify RAM catalog size (1 group + 1 terminator)
    expected_ram_size = 2 * KeyGroupCfgEntry.get_size()
    assert catalog.ram_catalog_cfg_size == expected_ram_size


def test_key_catalog_cfg_export_nvm_catalog(family: FamilyRevision) -> None:
    """Test exporting NVM catalog separately."""
    nvm_groups = [
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.SHE,
            num_of_key_slots=10,
            max_key_bit_len=HseKeyBits.KEY256_BITS,
        ),
    ]

    ram_groups = [
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.AES,
            num_of_key_slots=5,
            max_key_bit_len=HseKeyBits.KEY128_BITS,
        ),
    ]

    catalog = KeyCatalogCfg(
        family=family,
        nvm_key_groups=nvm_groups,
        ram_key_groups=ram_groups,
    )

    nvm_data = catalog.export_nvm_catalog()

    # Verify size (1 group + 1 terminator)
    expected_size = 2 * KeyGroupCfgEntry.get_size()
    assert len(nvm_data) == expected_size

    # Verify terminator is all zeros
    terminator_offset = KeyGroupCfgEntry.get_size()
    terminator = nvm_data[terminator_offset:]
    assert all(b == 0 for b in terminator)


def test_key_catalog_cfg_export_ram_catalog(family: FamilyRevision) -> None:
    """Test exporting RAM catalog separately."""
    nvm_groups = [
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.SHE,
            num_of_key_slots=10,
            max_key_bit_len=HseKeyBits.KEY256_BITS,
        ),
    ]

    ram_groups = [
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.AES,
            num_of_key_slots=5,
            max_key_bit_len=HseKeyBits.KEY128_BITS,
        ),
        KeyGroupCfgEntry(
            mu_mask=MuMask.MU0,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.ECC_PAIR,
            num_of_key_slots=3,
            max_key_bit_len=HseKeyBits.KEY256_BITS,
        ),
    ]

    catalog = KeyCatalogCfg(
        family=family,
        nvm_key_groups=nvm_groups,
        ram_key_groups=ram_groups,
    )

    ram_data = catalog.export_ram_catalog()

    # Verify size (2 groups + 1 terminator)
    expected_size = 3 * KeyGroupCfgEntry.get_size()
    assert len(ram_data) == expected_size

    # Verify terminator is all zeros
    terminator_offset = 2 * KeyGroupCfgEntry.get_size()
    terminator = ram_data[terminator_offset:]
    assert all(b == 0 for b in terminator)


def test_key_catalog_cfg_she_group_beyond_index_4() -> None:
    """Test validation fails when SHE group is beyond index 4."""
    family = FamilyRevision("mcxe31b")

    # Create 5 non-SHE groups, then a SHE group at index 5
    nvm_groups = [
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.AES,
            num_of_key_slots=5,
            max_key_bit_len=HseKeyBits.KEY256_BITS,
        )
        for _ in range(5)
    ]

    # Add SHE group at index 5 (invalid)
    nvm_groups.append(
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.SHE,
            num_of_key_slots=10,
            max_key_bit_len=HseKeyBits.KEY256_BITS,
        )
    )

    ram_groups = [
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.AES,
            num_of_key_slots=5,
            max_key_bit_len=HseKeyBits.KEY128_BITS,
        ),
    ]

    with pytest.raises(SPSDKVerificationError, match="SHE key group at valid position 0-4"):
        KeyCatalogCfg(
            family=family,
            nvm_key_groups=nvm_groups,
            ram_key_groups=ram_groups,
        ).verify().validate()


def test_key_catalog_cfg_various_key_types(family: FamilyRevision) -> None:
    """Test catalog with various key types."""
    nvm_groups = [
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.SHE,
            num_of_key_slots=10,
            max_key_bit_len=HseKeyBits.KEY256_BITS,
        ),
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.CUST,
            key_type=KeyType.AES,
            num_of_key_slots=5,
            max_key_bit_len=HseKeyBits.KEY256_BITS,
        ),
        KeyGroupCfgEntry(
            mu_mask=MuMask.MU0,
            group_owner=KeyGroupOwner.OEM,
            key_type=KeyType.HMAC,
            num_of_key_slots=3,
            max_key_bit_len=HseKeyBits.KEY512_BITS,
        ),
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.CUST,
            key_type=KeyType.ECC_PUB,
            num_of_key_slots=4,
            max_key_bit_len=HseKeyBits.KEY384_BITS,
        ),
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.RSA_PAIR,
            num_of_key_slots=2,
            max_key_bit_len=HseKeyBits.KEY2048_BITS,
        ),
    ]

    ram_groups = [
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.AES,
            num_of_key_slots=5,
            max_key_bit_len=HseKeyBits.KEY128_BITS,
        ),
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.ECC_PAIR,
            num_of_key_slots=3,
            max_key_bit_len=HseKeyBits.KEY256_BITS,
        ),
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.SHARED_SECRET,
            num_of_key_slots=2,
            max_key_bit_len=HseKeyBits.KEY256_BITS,
        ),
    ]

    catalog = KeyCatalogCfg(
        family=family,
        nvm_key_groups=nvm_groups,
        ram_key_groups=ram_groups,
    )

    # Export and parse to verify all key types work correctly
    exported_data = catalog.export()
    parsed_catalog = KeyCatalogCfg.parse(exported_data, family)

    assert len(parsed_catalog.nvm_key_groups) == len(nvm_groups)
    assert len(parsed_catalog.ram_key_groups) == len(ram_groups)

    # Verify all key types are preserved
    for orig, parsed in zip(nvm_groups, parsed_catalog.nvm_key_groups):
        assert parsed.key_type == orig.key_type


def test_key_catalog_cfg_binary_roundtrip(family: FamilyRevision) -> None:
    """Test complete binary export/parse roundtrip."""
    nvm_groups = [
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.SHE,
            num_of_key_slots=10,
            max_key_bit_len=HseKeyBits.KEY256_BITS,
        ),
        KeyGroupCfgEntry(
            mu_mask=MuMask.MU1,
            group_owner=KeyGroupOwner.CUST,
            key_type=KeyType.AES,
            num_of_key_slots=5,
            max_key_bit_len=HseKeyBits.KEY192_BITS,
        ),
        KeyGroupCfgEntry(
            mu_mask=MuMask.MU0,
            group_owner=KeyGroupOwner.OEM,
            key_type=KeyType.ECC_PUB,
            num_of_key_slots=3,
            max_key_bit_len=HseKeyBits.KEY384_BITS,
        ),
    ]

    ram_groups = [
        KeyGroupCfgEntry(
            mu_mask=MuMask.ALL,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.AES,
            num_of_key_slots=8,
            max_key_bit_len=HseKeyBits.KEY128_BITS,
        ),
        KeyGroupCfgEntry(
            mu_mask=MuMask.MU1,
            group_owner=KeyGroupOwner.ANY,
            key_type=KeyType.HMAC,
            num_of_key_slots=4,
            max_key_bit_len=HseKeyBits.KEY512_BITS,
        ),
    ]

    original_catalog = KeyCatalogCfg(
        family=family,
        nvm_key_groups=nvm_groups,
        ram_key_groups=ram_groups,
    )

    # Export to binary
    binary_data = original_catalog.export()

    # Parse from binary
    parsed_catalog = KeyCatalogCfg.parse(binary_data, family)

    # Verify all fields match
    assert len(parsed_catalog.nvm_key_groups) == len(original_catalog.nvm_key_groups)
    assert len(parsed_catalog.ram_key_groups) == len(original_catalog.ram_key_groups)

    for orig, parsed in zip(original_catalog.nvm_key_groups, parsed_catalog.nvm_key_groups):
        assert parsed.mu_mask == orig.mu_mask
        assert parsed.group_owner == orig.group_owner
        assert parsed.key_type == orig.key_type
        assert parsed.num_of_key_slots == orig.num_of_key_slots
        assert parsed.max_key_bit_len == orig.max_key_bit_len

    for orig, parsed in zip(original_catalog.ram_key_groups, parsed_catalog.ram_key_groups):
        assert parsed.mu_mask == orig.mu_mask
        assert parsed.group_owner == orig.group_owner
        assert parsed.key_type == orig.key_type
        assert parsed.num_of_key_slots == orig.num_of_key_slots
        assert parsed.max_key_bit_len == orig.max_key_bit_len

    # Export again and verify binary data is identical
    re_exported_data = parsed_catalog.export()
    assert re_exported_data == binary_data


def test_key_catalog_cfg_get_size() -> None:
    """Test KeyGroupCfgEntry.get_size() method."""
    size = KeyGroupCfgEntry.get_size()

    # Size should be: 1 (mu_mask) + 1 (group_owner) + 1 (key_type) + 1 (num_slots) + 2 (max_key_bit_len) + 2 (reserved)
    assert size == 8


def test_key_group_cfg_entry_config_roundtrip(key_group_config: dict) -> None:
    """Test round-trip from KeyGroupCfgEntry to config and back."""
    # Create original key group
    config = Config(key_group_config)
    original_group = KeyGroupCfgEntry.load_from_config(config)

    # Get config
    config_dict = original_group.get_config()
    new_config = Config(config_dict)

    # Create new key group from config
    new_group = KeyGroupCfgEntry.load_from_config(new_config)

    # Verify new group matches original
    assert new_group.mu_mask == original_group.mu_mask
    assert new_group.group_owner == original_group.group_owner
    assert new_group.key_type == original_group.key_type
    assert new_group.num_of_key_slots == original_group.num_of_key_slots
    assert new_group.max_key_bit_len == original_group.max_key_bit_len


def test_key_catalog_cfg_parse_missing_ram_data() -> None:
    """Test parsing fails when RAM catalog data is missing."""
    family = FamilyRevision("mcxe31b")

    # Create NVM catalog with terminator only
    nvm_data = KeyGroupCfgEntry(
        mu_mask=MuMask.ALL,
        group_owner=KeyGroupOwner.ANY,
        key_type=KeyType.AES,
        num_of_key_slots=5,
        max_key_bit_len=HseKeyBits.KEY256_BITS,
    ).export()

    # Add terminator
    nvm_data += bytes(KeyGroupCfgEntry.get_size())

    # No RAM data
    with pytest.raises(SPSDKParsingError, match="Missing RAM catalog data"):
        KeyCatalogCfg.parse(nvm_data, family)


def test_key_catalog_cfg_supported_families() -> None:
    """Test that get_supported_families returns expected families."""
    families = KeyCatalogCfg.get_supported_families()
    assert isinstance(families, list)
    assert len(families) > 0
