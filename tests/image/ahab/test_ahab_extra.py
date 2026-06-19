#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for AHAB (Advanced High Assurance Boot) image handling."""

import pytest

from spsdk.image.ahab.ahab_data import (
    AhabChipContainerConfig,
    AHABSignHashAlgorithm,
    create_chip_config,
)
from spsdk.image.ahab.ahab_iae import ImageArrayEntry
from spsdk.image.ahab.ahab_sign_block import SignatureBlock
from spsdk.utils.family import FamilyRevision

# Shared helpers / fixtures

FAMILY = FamilyRevision("mimxrt1189")


@pytest.fixture(scope="module")
def chip_config() -> AhabChipContainerConfig:
    """Return a chip container config for mimxrt1189 (SCFW metadata family)."""
    return AhabChipContainerConfig(base=create_chip_config(family=FAMILY))


@pytest.fixture
def simple_image() -> bytes:
    """Return 512 bytes of dummy image data."""
    return bytes(range(256)) * 2


@pytest.fixture
def basic_iae(chip_config: AhabChipContainerConfig, simple_image: bytes) -> ImageArrayEntry:
    """Return a simple, valid ImageArrayEntry for testing."""
    flags = ImageArrayEntry.create_flags(
        image_type=0,
        core_id=0,
        hash_type=AHABSignHashAlgorithm.SHA256,
    )
    iae = ImageArrayEntry(
        chip_config=chip_config,
        image=simple_image,
        image_offset=0x400,
        load_address=0x2000_0000,
        entry_point=0x2000_0000,
        flags=flags,
        image_meta_data=0,
    )
    iae.update_fields()
    return iae


# ImageArrayEntry – basic construction & properties


def test_iae_repr(basic_iae: ImageArrayEntry) -> None:
    """__repr__ should include the load address."""
    r = repr(basic_iae)
    assert "AHAB Image Array Entry" in r
    assert "0x20000000" in r


def test_iae_str_contains_sections(basic_iae: ImageArrayEntry) -> None:
    """__str__ should include all expected attribute names."""
    s = str(basic_iae)
    assert "Image size" in s
    assert "Load address" in s
    assert "Flags" in s


def test_iae_equality(chip_config: AhabChipContainerConfig, simple_image: bytes) -> None:
    """Two IAEs with the same parameters should be equal."""
    flags = ImageArrayEntry.create_flags(0, 0, AHABSignHashAlgorithm.SHA256)
    kwargs = dict(
        chip_config=chip_config,
        image=simple_image,
        image_offset=0x400,
        load_address=0x8000,
        entry_point=0x8000,
        flags=flags,
        image_meta_data=0,
    )
    iae1 = ImageArrayEntry(**kwargs)  # type: ignore[arg-type]
    iae1.update_fields()
    iae2 = ImageArrayEntry(**kwargs)  # type: ignore[arg-type]
    iae2.update_fields()
    assert iae1 == iae2


def test_iae_inequality_different_load_address(
    chip_config: AhabChipContainerConfig, simple_image: bytes
) -> None:
    """Two IAEs with different load addresses should not be equal."""
    flags = ImageArrayEntry.create_flags(0, 0, AHABSignHashAlgorithm.SHA256)
    iae1 = ImageArrayEntry(chip_config=chip_config, image=simple_image, flags=flags)
    iae1.load_address = 0x1000
    iae2 = ImageArrayEntry(chip_config=chip_config, image=simple_image, flags=flags)
    iae2.load_address = 0x2000
    assert iae1 != iae2


def test_iae_not_equal_to_non_iae(basic_iae: ImageArrayEntry) -> None:
    """IAE should not equal a non-IAE object."""
    assert basic_iae != "not an IAE"
    assert basic_iae != 42


# ImageArrayEntry – create_flags


def test_create_flags_basic() -> None:
    """create_flags returns integer with expected bit layout."""
    flags = ImageArrayEntry.create_flags(
        image_type=1,
        core_id=2,
        hash_type=AHABSignHashAlgorithm.SHA256,
        is_encrypted=False,
        boot_flags=0,
    )
    assert isinstance(flags, int)
    # image_type in bits 0-3
    assert (flags & 0xF) == 1
    # core_id in bits 4-7
    assert ((flags >> 4) & 0xF) == 2


def test_create_flags_encrypted() -> None:
    """create_flags with is_encrypted=True should set the encryption bit."""
    flags = ImageArrayEntry.create_flags(
        image_type=0,
        core_id=0,
        hash_type=AHABSignHashAlgorithm.SHA256,
        is_encrypted=True,
    )
    enc_bit = (flags >> ImageArrayEntry.FLAGS_IS_ENCRYPTED_OFFSET) & 1
    assert enc_bit == 1


def test_create_flags_image_descriptor() -> None:
    """create_flags with is_image_descriptor=True should set descriptor bit."""
    flags = ImageArrayEntry.create_flags(
        image_type=0,
        core_id=0,
        hash_type=AHABSignHashAlgorithm.SHA256,
        is_image_descriptor=True,
    )
    desc_bit = (flags >> ImageArrayEntry.FLAGS_IMAGE_DESCRIPTOR_OFFSET) & 1
    assert desc_bit == 1


# ImageArrayEntry – create_meta / create_meta_sm


def test_create_meta_basic() -> None:
    """create_meta should encode CPU and partition IDs in the right bits."""
    meta = ImageArrayEntry.create_meta(start_cpu_id=3, mu_cpu_id=5, start_partition_id=2)
    assert isinstance(meta, int)
    assert (meta & 0x3FF) == 3
    assert ((meta >> 10) & 0x3FF) == 5
    assert ((meta >> 20) & 0xFF) == 2


def test_create_meta_sm_basic() -> None:
    """create_meta_sm should encode cpu_id in bits 7:0."""
    meta = ImageArrayEntry.create_meta_sm(start_cpu_id=1)
    assert (meta & 0xFF) == 1


def test_create_meta_sm_cm33_includes_msel_flags() -> None:
    """For cpu_id=0 (CM33), msel and flags should be encoded."""
    meta = ImageArrayEntry.create_meta_sm(start_cpu_id=0, msel=3, flags=7)
    assert ((meta >> 16) & 0xFF) == 3  # msel
    assert ((meta >> 24) & 0xFF) == 7  # flags


def test_create_meta_sm_invalid_cpu_id() -> None:
    """create_meta_sm should raise SPSDKValueError for out-of-range cpu_id."""
    from spsdk.exceptions import SPSDKValueError

    with pytest.raises(SPSDKValueError):
        ImageArrayEntry.create_meta_sm(start_cpu_id=256)


def test_create_meta_sm_invalid_msel() -> None:
    """create_meta_sm should raise SPSDKValueError for out-of-range msel."""
    from spsdk.exceptions import SPSDKValueError

    with pytest.raises(SPSDKValueError):
        ImageArrayEntry.create_meta_sm(start_cpu_id=0, msel=256)


def test_create_meta_sm_invalid_flags() -> None:
    """create_meta_sm should raise SPSDKValueError for out-of-range flags."""
    from spsdk.exceptions import SPSDKValueError

    with pytest.raises(SPSDKValueError):
        ImageArrayEntry.create_meta_sm(start_cpu_id=0, flags=256)


# ImageArrayEntry – get_hash_from_flags


def test_get_hash_from_flags_sha256(basic_iae: ImageArrayEntry) -> None:
    """Hash algorithm extracted from flags should match what was set."""
    flags = ImageArrayEntry.create_flags(0, 0, AHABSignHashAlgorithm.SHA256)
    alg = basic_iae.get_hash_from_flags(flags)
    assert alg == AHABSignHashAlgorithm.SHA256


def test_get_hash_from_flags_sha384(basic_iae: ImageArrayEntry) -> None:
    """SHA384 hash should be extractable from flags."""
    flags = ImageArrayEntry.create_flags(0, 0, AHABSignHashAlgorithm.SHA384)
    alg = basic_iae.get_hash_from_flags(flags)
    assert alg == AHABSignHashAlgorithm.SHA384


# ImageArrayEntry – export / parse round-trip


def test_iae_export_length(basic_iae: ImageArrayEntry) -> None:
    """Exported IAE should have the expected fixed length."""
    data = basic_iae.export()
    assert len(data) == ImageArrayEntry.fixed_length()


def test_iae_export_parse_round_trip(
    chip_config: AhabChipContainerConfig, basic_iae: ImageArrayEntry
) -> None:
    """parse(export(iae)) should produce an equal IAE."""
    exported = basic_iae.export()
    parsed = ImageArrayEntry.parse(exported, chip_config)
    assert parsed == basic_iae


def test_iae_parse_invalid_length(chip_config: AhabChipContainerConfig) -> None:
    """parse with too-short data should raise a verification error."""
    with pytest.raises(Exception):
        ImageArrayEntry.parse(b"\x00" * 4, chip_config)


# ImageArrayEntry – flags properties


def test_flags_is_encrypted_false(basic_iae: ImageArrayEntry) -> None:
    """An unencrypted IAE should report flags_is_encrypted as False."""
    assert basic_iae.flags_is_encrypted is False


def test_flags_is_encrypted_true(chip_config: AhabChipContainerConfig) -> None:
    """An encrypted IAE should report flags_is_encrypted as True."""
    flags = ImageArrayEntry.create_flags(0, 0, AHABSignHashAlgorithm.SHA256, is_encrypted=True)
    iae = ImageArrayEntry(
        chip_config=chip_config,
        flags=flags,
        image=bytes(16),
    )
    assert iae.flags_is_encrypted is True


def test_flags_is_image_descriptor_false(basic_iae: ImageArrayEntry) -> None:
    """Default IAE should not be flagged as image descriptor."""
    assert basic_iae.flags_is_image_descriptor is False


def test_flags_boot_flags_zero(basic_iae: ImageArrayEntry) -> None:
    """Default boot flags should be zero."""
    assert basic_iae.flags_boot_flags == 0


# ImageArrayEntry – metadata properties


def test_metadata_start_cpu_id(chip_config: AhabChipContainerConfig) -> None:
    """metadata_start_cpu_id should decode the CPU ID from image_meta_data."""
    meta = ImageArrayEntry.create_meta(start_cpu_id=5, mu_cpu_id=0, start_partition_id=0)
    iae = ImageArrayEntry(chip_config=chip_config, image_meta_data=meta)
    assert iae.metadata_start_cpu_id == 5


def test_metadata_mu_cpu_id(chip_config: AhabChipContainerConfig) -> None:
    """metadata_mu_cpu_id should decode the MU CPU ID from image_meta_data."""
    meta = ImageArrayEntry.create_meta(start_cpu_id=0, mu_cpu_id=7, start_partition_id=0)
    iae = ImageArrayEntry(chip_config=chip_config, image_meta_data=meta)
    assert iae.metadata_mu_cpu_id == 7


def test_metadata_start_partition_id(chip_config: AhabChipContainerConfig) -> None:
    """metadata_start_partition_id should decode the partition ID."""
    meta = ImageArrayEntry.create_meta(start_cpu_id=0, mu_cpu_id=0, start_partition_id=3)
    iae = ImageArrayEntry(chip_config=chip_config, image_meta_data=meta)
    assert iae.metadata_start_partition_id == 3


# ImageArrayEntry – image_offset property setter / getter


def test_image_offset_roundtrip(chip_config: AhabChipContainerConfig) -> None:
    """Setting image_offset should be retrievable back (adjusted by container_offset)."""
    iae = ImageArrayEntry(chip_config=chip_config)
    offset = 0x1000 + chip_config.container_offset
    iae.image_offset = offset
    assert iae.image_offset == offset


# ImageArrayEntry – verify


def test_iae_verify_valid(basic_iae: ImageArrayEntry) -> None:
    """A properly constructed IAE should verify without errors."""
    verifier = basic_iae.verify()
    # No ERROR records expected
    from spsdk.utils.verifier import VerifierResult

    assert verifier.result in (VerifierResult.SUCCEEDED, VerifierResult.WARNING)


def test_iae_verify_missing_hash(chip_config: AhabChipContainerConfig, simple_image: bytes) -> None:
    """Verify should report error when image_hash is None."""
    flags = ImageArrayEntry.create_flags(0, 0, AHABSignHashAlgorithm.SHA256)
    iae = ImageArrayEntry(
        chip_config=chip_config,
        image=simple_image,
        flags=flags,
        image_hash=None,
    )
    iae.image_hash = None
    verifier = iae.verify()
    assert verifier.result.name in ("ERROR", "WARNING")


def test_iae_verify_zero_hash(chip_config: AhabChipContainerConfig, simple_image: bytes) -> None:
    """Verify should report error or warning for all-zero hash."""
    flags = ImageArrayEntry.create_flags(0, 0, AHABSignHashAlgorithm.SHA256)
    iae = ImageArrayEntry(
        chip_config=chip_config,
        image=simple_image,
        flags=flags,
        image_hash=bytes(ImageArrayEntry.HASH_LEN),
    )
    verifier = iae.verify()
    assert verifier.result.name in ("ERROR", "WARNING")


# ImageArrayEntry – update_fields


def test_update_fields_sets_hash(chip_config: AhabChipContainerConfig) -> None:
    """update_fields should compute and set image_hash when it was None."""
    image = bytes(range(256))
    flags = ImageArrayEntry.create_flags(0, 0, AHABSignHashAlgorithm.SHA256)
    iae = ImageArrayEntry(
        chip_config=chip_config,
        image=image,
        flags=flags,
        image_hash=None,
    )
    assert iae.image_hash is None
    iae.update_fields()
    assert iae.image_hash is not None
    assert len(iae.image_hash) == ImageArrayEntry.HASH_LEN


def test_update_fields_preserves_existing_hash(
    chip_config: AhabChipContainerConfig,
) -> None:
    """update_fields should NOT overwrite an existing image_hash."""
    image = bytes(16)
    flags = ImageArrayEntry.create_flags(0, 0, AHABSignHashAlgorithm.SHA256)
    existing_hash = bytes(range(64))
    iae = ImageArrayEntry(
        chip_config=chip_config,
        image=image,
        flags=flags,
        image_hash=existing_hash,
    )
    iae.update_fields()
    assert iae.image_hash == existing_hash


# ImageArrayEntry – get_valid_alignment / get_valid_offset


def test_get_valid_alignment_positive(basic_iae: ImageArrayEntry) -> None:
    """get_valid_alignment should return a positive integer."""
    alignment = basic_iae.get_valid_alignment()
    assert alignment > 0


def test_get_valid_offset(basic_iae: ImageArrayEntry) -> None:
    """get_valid_offset should return an aligned offset."""
    alignment = basic_iae.get_valid_alignment()
    offset = basic_iae.get_valid_offset(1)
    assert offset % alignment == 0


# ImageArrayEntry – get_config


def test_iae_get_config(basic_iae: ImageArrayEntry, tmp_path: str) -> None:
    """get_config should return a Config with expected keys."""
    cfg = basic_iae.get_config(index=0, image_index=0, data_path=str(tmp_path))
    assert "image_offset" in cfg
    assert "load_address" in cfg
    assert "image_type" in cfg
    assert "core_id" in cfg
    assert "hash_type" in cfg


# SignatureBlock – basic construction


@pytest.fixture
def sign_block(chip_config: AhabChipContainerConfig) -> SignatureBlock:
    """Return a minimal SignatureBlock with no cryptographic content."""
    return SignatureBlock(chip_config=chip_config)


def test_sign_block_repr(sign_block: SignatureBlock) -> None:
    """__repr__ should contain 'AHAB Signature Block'."""
    assert "AHAB Signature Block" in repr(sign_block)


def test_sign_block_str(sign_block: SignatureBlock) -> None:
    """__str__ should list component presence."""
    s = str(sign_block)
    assert "SRK Table" in s
    assert "Certificate" in s
    assert "Signature" in s
    assert "Blob" in s


def test_sign_block_equality(chip_config: AhabChipContainerConfig) -> None:
    """Two default SignatureBlocks should be equal."""
    sb1 = SignatureBlock(chip_config=chip_config)
    sb2 = SignatureBlock(chip_config=chip_config)
    assert sb1 == sb2


def test_sign_block_not_equal_to_str(sign_block: SignatureBlock) -> None:
    """SignatureBlock should not equal a string."""
    assert sign_block != "not a signature block"


# SignatureBlock – format string


def test_sign_block_format_is_string() -> None:
    """SignatureBlock.format() should return a non-empty string."""
    fmt = SignatureBlock.format()
    assert isinstance(fmt, str)
    assert len(fmt) > 0


# SignatureBlock – length


def test_sign_block_len_is_positive(sign_block: SignatureBlock) -> None:
    """len(SignatureBlock) should return a positive integer after update_fields."""
    length = len(sign_block)
    assert length > 0


# ImageArrayEntry – load_binary_data_from_file helper


def test_load_binary_data_from_file(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """load_binary_data_from_file should read a binary file correctly."""
    from spsdk.image.ahab.ahab_iae import load_binary_data_from_file

    data = b"\xde\xad\xbe\xef" * 16
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(data)
    result = load_binary_data_from_file(str(test_file))
    assert result == data


# iae_header_position – container header table ordering


def test_iae_header_position_reorders_header_table(
    chip_config: AhabChipContainerConfig,
) -> None:
    """IAE entries with iae_header_position should be emitted in position order in header table.

    The test creates two IAE entries (list order [A, B]) and sets their
    iae_header_position so that B appears first in the signed container header
    table.  This is needed for the i.MX95 B0 fast-boot dummy image ordering
    (SPSDK-6509): the dummy entry must be first in the header but its data
    offset should come after the real OEI DDR image.
    """
    from struct import unpack_from

    from spsdk.image.ahab.ahab_container import AHABContainer

    # Create two IAEs with distinguishable load_addresses
    iae_a = ImageArrayEntry(
        chip_config=chip_config,
        image=bytes(1024),
        image_offset=0x1000,
        load_address=0xAAAA_0000,
        entry_point=0xAAAA_0001,
        flags=ImageArrayEntry.create_flags(
            image_type=0, core_id=0, hash_type=AHABSignHashAlgorithm.SHA256
        ),
        image_meta_data=0,
    )
    iae_b = ImageArrayEntry(
        chip_config=chip_config,
        image=bytes(0),
        image_offset=0x2000,
        load_address=0xBBBB_0000,
        entry_point=0,
        flags=ImageArrayEntry.create_flags(
            image_type=0, core_id=0, hash_type=AHABSignHashAlgorithm.SHA384
        ),
        image_meta_data=0,
    )

    # List order: [A, B].  Header order: B first, A second.
    iae_a.iae_header_position = 1
    iae_b.iae_header_position = 0

    # Create container with the image array
    container = AHABContainer(
        chip_config=chip_config.base,
        image_array=[iae_a, iae_b],
    )
    container.update_fields()

    exported = container.export()

    # Container header is 16 bytes, then IAE entries at 128 bytes each.
    # First IAE in header should be B (load_address 0xBBBB_0000).
    header_offset = 16
    # IAE format: offset(4B) + size(4B) + load_address(8B) = offset 8 in entry
    first_load_addr = unpack_from("<Q", exported, header_offset + 8)[0]
    second_load_addr = unpack_from("<Q", exported, header_offset + 128 + 8)[0]

    assert (
        first_load_addr == 0xBBBB_0000
    ), f"First IAE in header should be B (0xBBBB0000), got 0x{first_load_addr:X}"
    assert (
        second_load_addr == 0xAAAA_0000
    ), f"Second IAE in header should be A (0xAAAA0000), got 0x{second_load_addr:X}"

    # Verify list order is preserved (image_array still [A, B])
    assert container.image_array[0] is iae_a
    assert container.image_array[1] is iae_b
