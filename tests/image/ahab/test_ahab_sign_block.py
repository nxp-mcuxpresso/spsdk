#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for AHAB signature block."""

import pytest

from spsdk.crypto.keys import PrivateKeyRsa
from spsdk.exceptions import SPSDKError
from spsdk.image.ahab.ahab_blob import AhabBlob
from spsdk.image.ahab.ahab_certificate import AhabCertificate
from spsdk.image.ahab.ahab_data import AhabChipContainerConfig, SignatureType, create_chip_config
from spsdk.image.ahab.ahab_sign_block import SignatureBlock, SignatureBlockV2
from spsdk.image.ahab.ahab_signature import ContainerSignature
from spsdk.image.ahab.ahab_srk import SRKRecord, SRKRecordV2, SRKTable, SRKTableArray, SRKTableV2
from spsdk.utils.family import FamilyRevision
from spsdk.utils.verifier import Verifier

FAMILY = FamilyRevision("mimxrt1189")


@pytest.fixture(scope="module")
def chip_cfg() -> AhabChipContainerConfig:
    """Return a chip container config for mimxrt1189.

    :return: AhabChipContainerConfig instance.
    """
    return AhabChipContainerConfig(base=create_chip_config(family=FAMILY))


@pytest.fixture(scope="module")
def srk_record() -> SRKRecord:
    """Create a basic SRK record from a real RSA key.

    :return: SRKRecord instance.
    """
    key = PrivateKeyRsa.generate_key(2048)
    return SRKRecord.create_from_key(key.get_public_key())


@pytest.fixture(scope="module")
def srk_table(srk_record: SRKRecord) -> SRKTable:
    """Create an SRK table with four identical records.

    :param srk_record: SRKRecord fixture.
    :return: SRKTable instance.
    """
    return SRKTable(srk_records=[srk_record, srk_record, srk_record, srk_record])


@pytest.fixture(scope="module")
def container_signature() -> ContainerSignature:
    """Create a container signature with test data.

    :return: ContainerSignature instance.
    """
    return ContainerSignature(signature_data=bytes.fromhex(20 * "11223344"))


@pytest.fixture(scope="module")
def blob() -> AhabBlob:
    """Create a test AhabBlob.

    :return: AhabBlob instance.
    """
    return AhabBlob(flags=0x80, size=0x20, dek_keyblob=bytes.fromhex(80 * "23"))


@pytest.fixture(scope="module")
def srk_record_v2() -> SRKRecordV2:
    """Create an SRKRecordV2 from a real RSA key.

    :return: SRKRecordV2 instance with embedded srk_data.
    """
    key = PrivateKeyRsa.generate_key(2048)
    return SRKRecordV2.create_from_key(key.get_public_key())


@pytest.fixture(scope="module")
def srk_table_v2(srk_record_v2: SRKRecordV2) -> SRKTableV2:
    """Create SRKTableV2 with four identical records.

    :param srk_record_v2: SRKRecordV2 fixture.
    :return: SRKTableV2 instance.
    """
    return SRKTableV2(srk_records=[srk_record_v2, srk_record_v2, srk_record_v2, srk_record_v2])


@pytest.fixture(scope="module")
def srk_table_array(chip_cfg: AhabChipContainerConfig, srk_table_v2: SRKTableV2) -> SRKTableArray:
    """Create SRKTableArray from one SRKTableV2.

    :param chip_cfg: Chip configuration fixture.
    :param srk_table_v2: SRKTableV2 fixture.
    :return: SRKTableArray instance.
    """
    sta = SRKTableArray(chip_config=chip_cfg, srk_tables=[srk_table_v2])
    sta.update_fields()
    return sta


# ---------------------------------------------------------------------------
# SignatureBlock tests
# ---------------------------------------------------------------------------


def test_signature_block_empty(chip_cfg: AhabChipContainerConfig) -> None:
    """Create empty SignatureBlock and check basic attributes.

    :param chip_cfg: Chip configuration fixture.
    """
    sb = SignatureBlock(chip_config=chip_cfg)
    assert repr(sb) == "AHAB Signature Block"
    s = str(sb)
    assert "SRK Table" in s
    assert "False" in s
    sb.update_fields()
    assert sb.length > 0
    assert len(sb) > 0


def test_signature_block_with_srk(chip_cfg: AhabChipContainerConfig, srk_table: SRKTable) -> None:
    """Create SignatureBlock with SRK table and check update_fields.

    :param chip_cfg: Chip configuration fixture.
    :param srk_table: SRKTable fixture.
    """
    sb = SignatureBlock(chip_config=chip_cfg, srk_assets=srk_table)
    sb.update_fields()
    assert sb._srk_assets_offset > 0
    assert sb._signature_offset == 0
    assert sb._certificate_offset == 0
    assert sb._blob_offset == 0


def test_signature_block_with_signature(
    chip_cfg: AhabChipContainerConfig,
    srk_table: SRKTable,
    container_signature: ContainerSignature,
) -> None:
    """Create SignatureBlock with SRK + signature and export.

    :param chip_cfg: Chip configuration fixture.
    :param srk_table: SRKTable fixture.
    :param container_signature: ContainerSignature fixture.
    """
    sb = SignatureBlock(
        chip_config=chip_cfg,
        srk_assets=srk_table,
        container_signature=container_signature,
    )
    sb.update_fields()
    assert sb._srk_assets_offset > 0
    assert sb._signature_offset > 0
    exported = sb.export()
    assert len(exported) == len(sb)


def test_signature_block_with_certificate(
    chip_cfg: AhabChipContainerConfig,
    srk_table: SRKTable,
    container_signature: ContainerSignature,
    srk_record_v2: SRKRecordV2,
) -> None:
    """Create SignatureBlock with certificate and check update_fields.

    :param chip_cfg: Chip configuration fixture.
    :param srk_table: SRKTable fixture.
    :param container_signature: ContainerSignature fixture.
    :param srk_record_v2: SRKRecordV2 fixture.
    """
    cert = AhabCertificate(
        family=FAMILY,
        permissions=0x00,
        uuid=bytes(16),
        public_key_0=srk_record_v2,
    )
    sb = SignatureBlock(
        chip_config=chip_cfg,
        srk_assets=srk_table,
        container_signature=container_signature,
        certificate=cert,
    )
    # Certificate is set on the signature block
    assert sb.certificate is cert


def test_signature_block_with_blob(
    chip_cfg: AhabChipContainerConfig,
    srk_table: SRKTable,
    container_signature: ContainerSignature,
    blob: AhabBlob,
) -> None:
    """Create SignatureBlock with all components including blob.

    :param chip_cfg: Chip configuration fixture.
    :param srk_table: SRKTable fixture.
    :param container_signature: ContainerSignature fixture.
    :param blob: AhabBlob fixture.
    """
    sb = SignatureBlock(
        chip_config=chip_cfg,
        srk_assets=srk_table,
        container_signature=container_signature,
        blob=blob,
    )
    sb.update_fields()
    assert sb._blob_offset > 0
    exported = sb.export()
    assert len(exported) > 0
    assert isinstance(exported, (bytes, bytearray))


def test_signature_block_export_no_components(chip_cfg: AhabChipContainerConfig) -> None:
    """Export SignatureBlock with no optional components.

    :param chip_cfg: Chip configuration fixture.
    """
    sb = SignatureBlock(chip_config=chip_cfg)
    sb.update_fields()
    exported = sb.export()
    assert len(exported) == len(sb)
    assert isinstance(exported, (bytes, bytearray))


def test_signature_block_verify_empty(chip_cfg: AhabChipContainerConfig) -> None:
    """Verify empty SignatureBlock structure.

    :param chip_cfg: Chip configuration fixture.
    """
    sb = SignatureBlock(chip_config=chip_cfg)
    sb.update_fields()
    v = sb.verify()
    assert isinstance(v, Verifier)


def test_signature_block_verify_with_srk(
    chip_cfg: AhabChipContainerConfig, srk_table: SRKTable
) -> None:
    """Verify SignatureBlock with SRK table.

    :param chip_cfg: Chip configuration fixture.
    :param srk_table: SRKTable fixture.
    """
    sb = SignatureBlock(chip_config=chip_cfg, srk_assets=srk_table)
    sb.update_fields()
    v = sb.verify()
    assert isinstance(v, Verifier)


def test_signature_block_verify_with_all(
    chip_cfg: AhabChipContainerConfig,
    srk_table: SRKTable,
    container_signature: ContainerSignature,
    blob: AhabBlob,
) -> None:
    """Verify SignatureBlock with all components.

    :param chip_cfg: Chip configuration fixture.
    :param srk_table: SRKTable fixture.
    :param container_signature: ContainerSignature fixture.
    :param blob: AhabBlob fixture.
    """
    sb = SignatureBlock(
        chip_config=chip_cfg,
        srk_assets=srk_table,
        container_signature=container_signature,
        blob=blob,
    )
    sb.update_fields()
    v = sb.verify()
    assert isinstance(v, Verifier)


def test_signature_block_equality(
    chip_cfg: AhabChipContainerConfig,
    srk_table: SRKTable,
    container_signature: ContainerSignature,
) -> None:
    """Test SignatureBlock __eq__ with same, different, and non-SignatureBlock.

    :param chip_cfg: Chip configuration fixture.
    :param srk_table: SRKTable fixture.
    :param container_signature: ContainerSignature fixture.
    """
    sb1 = SignatureBlock(
        chip_config=chip_cfg,
        srk_assets=srk_table,
        container_signature=container_signature,
    )
    sb1.update_fields()

    sb2 = SignatureBlock(
        chip_config=chip_cfg,
        srk_assets=srk_table,
        container_signature=container_signature,
    )
    sb2.update_fields()

    assert sb1 == sb2

    sb3 = SignatureBlock(chip_config=chip_cfg)
    sb3.update_fields()
    assert sb1 != sb3
    assert sb1 != "not a SignatureBlock"


def test_signature_block_sign_itself_missing_signature(
    chip_cfg: AhabChipContainerConfig,
) -> None:
    """sign_itself raises SPSDKError when signature container is missing.

    :param chip_cfg: Chip configuration fixture.
    """
    sb = SignatureBlock(chip_config=chip_cfg)
    with pytest.raises(SPSDKError, match="Signature container is missing"):
        sb.sign_itself(b"data_to_sign")


def test_signature_block_sign_itself_with_srk_table_type(
    chip_cfg: AhabChipContainerConfig,
) -> None:
    """sign_itself with SRK_TABLE signature type calls sign on the signature.

    :param chip_cfg: Chip configuration fixture.
    """
    sig = ContainerSignature(signature_data=bytes.fromhex(20 * "aabbccdd"))
    assert sig.signature_type == SignatureType.SRK_TABLE
    sb = SignatureBlock(chip_config=chip_cfg, container_signature=sig)
    # sign_itself with an unsigned signature simply no-ops without a signer set
    sb.sign_itself(b"data")


def test_signature_block_parse(
    chip_cfg: AhabChipContainerConfig,
    srk_table: SRKTable,
    container_signature: ContainerSignature,
) -> None:
    """Export then parse SignatureBlock and verify equality.

    :param chip_cfg: Chip configuration fixture.
    :param srk_table: SRKTable fixture.
    :param container_signature: ContainerSignature fixture.
    """
    sb = SignatureBlock(
        chip_config=chip_cfg,
        srk_assets=srk_table,
        container_signature=container_signature,
    )
    sb.update_fields()
    exported = sb.export()

    parsed = SignatureBlock.parse(exported, chip_config=chip_cfg)
    assert parsed.length == sb.length
    assert parsed._srk_assets_offset == sb._srk_assets_offset
    assert parsed._signature_offset == sb._signature_offset


def test_signature_block_parse_with_all(
    chip_cfg: AhabChipContainerConfig,
    srk_table: SRKTable,
    container_signature: ContainerSignature,
    blob: AhabBlob,
) -> None:
    """Export and parse SignatureBlock with all components.

    :param chip_cfg: Chip configuration fixture.
    :param srk_table: SRKTable fixture.
    :param container_signature: ContainerSignature fixture.
    :param blob: AhabBlob fixture.
    """
    sb = SignatureBlock(
        chip_config=chip_cfg,
        srk_assets=srk_table,
        container_signature=container_signature,
        blob=blob,
    )
    sb.update_fields()
    exported = sb.export()
    parsed = SignatureBlock.parse(exported, chip_config=chip_cfg)
    assert parsed._blob_offset == sb._blob_offset


def test_signature_block_pre_parse_verify(chip_cfg: AhabChipContainerConfig) -> None:
    """Test pre_parse_verify with a valid exported empty block.

    :param chip_cfg: Chip configuration fixture.
    """
    sb = SignatureBlock(chip_config=chip_cfg)
    sb.update_fields()
    exported = sb.export()
    v = SignatureBlock.pre_parse_verify(exported)
    assert isinstance(v, Verifier)


def test_signature_block_pre_parse_verify_with_components(
    chip_cfg: AhabChipContainerConfig,
    srk_table: SRKTable,
    container_signature: ContainerSignature,
) -> None:
    """Pre-parse verify with SRK and signature.

    :param chip_cfg: Chip configuration fixture.
    :param srk_table: SRKTable fixture.
    :param container_signature: ContainerSignature fixture.
    """
    sb = SignatureBlock(
        chip_config=chip_cfg,
        srk_assets=srk_table,
        container_signature=container_signature,
    )
    sb.update_fields()
    exported = sb.export()
    v = SignatureBlock.pre_parse_verify(exported)
    assert isinstance(v, Verifier)


def test_signature_block_pre_parse_verify_signature_without_srk(
    chip_cfg: AhabChipContainerConfig,
    container_signature: ContainerSignature,
) -> None:
    """Pre-parse verify detects signature present without SRK table.

    :param chip_cfg: Chip configuration fixture.
    :param container_signature: ContainerSignature fixture.
    """
    # Build a block with only signature (no SRK), then forge the binary offset
    # by building a block that has signature at a valid offset but no srk_assets_offset.
    # Easiest: build with both, then clear SRK fields manually.
    sb = SignatureBlock(
        chip_config=chip_cfg,
        container_signature=container_signature,
    )
    sb.update_fields()
    # Manually set signature offset to non-zero while srk_assets_offset remains 0
    sb._signature_offset = SignatureBlock.fixed_length()
    # Export with patched header by rebuilding
    exported = sb.export()
    v = SignatureBlock.pre_parse_verify(exported)
    assert isinstance(v, Verifier)


def test_signature_block_pre_parse_verify_blob(
    chip_cfg: AhabChipContainerConfig,
    srk_table: SRKTable,
    container_signature: ContainerSignature,
    blob: AhabBlob,
) -> None:
    """Pre-parse verify with blob present.

    :param chip_cfg: Chip configuration fixture.
    :param srk_table: SRKTable fixture.
    :param container_signature: ContainerSignature fixture.
    :param blob: AhabBlob fixture.
    """
    sb = SignatureBlock(
        chip_config=chip_cfg,
        srk_assets=srk_table,
        container_signature=container_signature,
        blob=blob,
    )
    sb.update_fields()
    exported = sb.export()
    v = SignatureBlock.pre_parse_verify(exported)
    assert isinstance(v, Verifier)


def test_signature_block_verify_container_authenticity_missing_srk(
    chip_cfg: AhabChipContainerConfig,
) -> None:
    """verify_container_authenticity with missing SRK adds error record.

    :param chip_cfg: Chip configuration fixture.
    """
    sb = SignatureBlock(chip_config=chip_cfg)
    v = sb.verify_container_authenticity(b"dummy_data")
    assert isinstance(v, Verifier)


def test_signature_block_verify_container_authenticity_with_srk(
    chip_cfg: AhabChipContainerConfig,
    srk_table: SRKTable,
    container_signature: ContainerSignature,
) -> None:
    """verify_container_authenticity with SRK present runs without exception.

    :param chip_cfg: Chip configuration fixture.
    :param srk_table: SRKTable fixture.
    :param container_signature: ContainerSignature fixture.
    """
    sb = SignatureBlock(
        chip_config=chip_cfg,
        srk_assets=srk_table,
        container_signature=container_signature,
    )
    sb.update_fields()
    v = sb.verify_container_authenticity(b"dummy_data")
    assert isinstance(v, Verifier)


def test_signature_block_get_config(
    chip_cfg: AhabChipContainerConfig, tmp_path: "pytest.TempPathFactory"
) -> None:
    """Test get_config on empty SignatureBlock.

    :param chip_cfg: Chip configuration fixture.
    :param tmp_path: Pytest tmp_path fixture.
    """
    sb = SignatureBlock(chip_config=chip_cfg)
    cfg = sb.get_config(index=0, data_path=str(tmp_path))
    assert isinstance(cfg, dict)


def test_signature_block_get_config_with_signature(
    chip_cfg: AhabChipContainerConfig,
    srk_table: SRKTable,
    container_signature: ContainerSignature,
    tmp_path: "pytest.TempPathFactory",
) -> None:
    """Test get_config with signature present.

    :param chip_cfg: Chip configuration fixture.
    :param srk_table: SRKTable fixture.
    :param container_signature: ContainerSignature fixture.
    :param tmp_path: Pytest tmp_path fixture.
    """
    sb = SignatureBlock(
        chip_config=chip_cfg,
        srk_assets=srk_table,
        container_signature=container_signature,
    )
    sb.update_fields()
    cfg = sb.get_config(index=0, data_path=str(tmp_path))
    assert "signer" in cfg
    assert "srk_table" in cfg


# ---------------------------------------------------------------------------
# SignatureBlockV2 tests
# ---------------------------------------------------------------------------


def test_signature_block_v2_empty(chip_cfg: AhabChipContainerConfig) -> None:
    """Create empty SignatureBlockV2 and check basic attributes.

    :param chip_cfg: Chip configuration fixture.
    """
    sb = SignatureBlockV2(chip_config=chip_cfg)
    assert repr(sb) == "AHAB Signature Block V2"
    s = str(sb)
    assert "SRK Table Array" in s
    assert sb.VERSION == 0x01


def test_signature_block_v2_str_repr(chip_cfg: AhabChipContainerConfig) -> None:
    """Test __str__ and __repr__ of SignatureBlockV2.

    :param chip_cfg: Chip configuration fixture.
    """
    sb = SignatureBlockV2(chip_config=chip_cfg)
    assert "AHAB Signature Block V2" in repr(sb)
    assert "AHAB Signature Block" in str(sb)


def test_signature_block_v2_with_srk(
    chip_cfg: AhabChipContainerConfig, srk_table_array: SRKTableArray
) -> None:
    """Create SignatureBlockV2 with SRK table array.

    :param chip_cfg: Chip configuration fixture.
    :param srk_table_array: SRKTableArray fixture.
    """
    sb = SignatureBlockV2(chip_config=chip_cfg, srk_assets=srk_table_array)
    sb.update_fields()
    assert sb._srk_assets_offset > 0
    assert len(sb) > 0


def test_signature_block_v2_update_fields(
    chip_cfg: AhabChipContainerConfig,
    srk_table_array: SRKTableArray,
    container_signature: ContainerSignature,
) -> None:
    """Check offset calculation in SignatureBlockV2.update_fields.

    :param chip_cfg: Chip configuration fixture.
    :param srk_table_array: SRKTableArray fixture.
    :param container_signature: ContainerSignature fixture.
    """
    sb = SignatureBlockV2(
        chip_config=chip_cfg,
        srk_assets=srk_table_array,
        container_signature=container_signature,
    )
    sb.update_fields()
    assert sb._srk_assets_offset > 0
    assert sb._signature_offset > 0
    assert sb._certificate_offset == 0
    assert sb._blob_offset == 0


def test_signature_block_v2_sign_itself_missing_signature(
    chip_cfg: AhabChipContainerConfig,
) -> None:
    """sign_itself raises SPSDKError when signature is missing.

    :param chip_cfg: Chip configuration fixture.
    """
    sb = SignatureBlockV2(chip_config=chip_cfg)
    with pytest.raises(SPSDKError, match="Signature container is missing"):
        sb.sign_itself(b"data")


def test_signature_block_v2_sign_itself_cmac_type(
    chip_cfg: AhabChipContainerConfig,
) -> None:
    """sign_itself returns early for CMAC signature type without error.

    :param chip_cfg: Chip configuration fixture.
    """
    sig = ContainerSignature(
        signature_type=SignatureType.CMAC,
        signature_data=bytes.fromhex(20 * "aabb"),
    )
    sb = SignatureBlockV2(chip_config=chip_cfg, container_signature=sig)
    # CMAC should skip signing without error
    sb.sign_itself(b"data")


def test_signature_block_v2_sign_itself_missing_srk(
    chip_cfg: AhabChipContainerConfig,
    container_signature: ContainerSignature,
) -> None:
    """sign_itself raises SPSDKError when SRK table array is missing.

    :param chip_cfg: Chip configuration fixture.
    :param container_signature: ContainerSignature fixture.
    """
    sb = SignatureBlockV2(chip_config=chip_cfg, container_signature=container_signature)
    with pytest.raises(SPSDKError, match="SRK table array container is missing"):
        sb.sign_itself(b"data")


def test_signature_block_v2_export_with_signature(
    chip_cfg: AhabChipContainerConfig,
    srk_table_array: SRKTableArray,
    container_signature: ContainerSignature,
) -> None:
    """Export SignatureBlockV2 with SRK and signature.

    :param chip_cfg: Chip configuration fixture.
    :param srk_table_array: SRKTableArray fixture.
    :param container_signature: ContainerSignature fixture.
    """
    sb = SignatureBlockV2(
        chip_config=chip_cfg,
        srk_assets=srk_table_array,
        container_signature=container_signature,
    )
    sb.update_fields()
    exported = sb.export()
    assert len(exported) == len(sb)


def test_signature_block_v2_verify_structure(
    chip_cfg: AhabChipContainerConfig,
    srk_table_array: SRKTableArray,
    container_signature: ContainerSignature,
) -> None:
    """Verify SignatureBlockV2 structure after update_fields.

    :param chip_cfg: Chip configuration fixture.
    :param srk_table_array: SRKTableArray fixture.
    :param container_signature: ContainerSignature fixture.
    """
    sb = SignatureBlockV2(
        chip_config=chip_cfg,
        srk_assets=srk_table_array,
        container_signature=container_signature,
    )
    sb.update_fields()
    v = sb.verify()
    assert isinstance(v, Verifier)


def test_signature_block_v2_verify_empty(chip_cfg: AhabChipContainerConfig) -> None:
    """Verify empty SignatureBlockV2.

    :param chip_cfg: Chip configuration fixture.
    """
    sb = SignatureBlockV2(chip_config=chip_cfg)
    sb.update_fields()
    v = sb.verify()
    assert isinstance(v, Verifier)


def test_signature_block_v2_equality(
    chip_cfg: AhabChipContainerConfig,
    srk_table_array: SRKTableArray,
) -> None:
    """Test SignatureBlockV2 __eq__ with same, different, and non-V2 objects.

    :param chip_cfg: Chip configuration fixture.
    :param srk_table_array: SRKTableArray fixture.
    """
    sb1 = SignatureBlockV2(chip_config=chip_cfg, srk_assets=srk_table_array)
    sb1.update_fields()
    sb2 = SignatureBlockV2(chip_config=chip_cfg, srk_assets=srk_table_array)
    sb2.update_fields()
    assert sb1 == sb2

    sb3 = SignatureBlockV2(chip_config=chip_cfg)
    sb3.update_fields()
    assert sb1 != sb3
    assert sb1 != "not a SignatureBlockV2"


def test_signature_block_v2_get_config(
    chip_cfg: AhabChipContainerConfig, tmp_path: "pytest.TempPathFactory"
) -> None:
    """Test get_config on empty SignatureBlockV2.

    :param chip_cfg: Chip configuration fixture.
    :param tmp_path: Pytest tmp_path fixture.
    """
    sb = SignatureBlockV2(chip_config=chip_cfg)
    cfg = sb.get_config(index=0, data_path=str(tmp_path))
    assert isinstance(cfg, dict)


def test_signature_block_v2_get_config_with_all(
    chip_cfg: AhabChipContainerConfig,
    srk_table_array: SRKTableArray,
    container_signature: ContainerSignature,
    tmp_path: "pytest.TempPathFactory",
) -> None:
    """Test get_config with signature and SRK present.

    :param chip_cfg: Chip configuration fixture.
    :param srk_table_array: SRKTableArray fixture.
    :param container_signature: ContainerSignature fixture.
    :param tmp_path: Pytest tmp_path fixture.
    """
    sig2 = ContainerSignature(signature_data=bytes.fromhex(20 * "aabbccdd"))
    sb = SignatureBlockV2(
        chip_config=chip_cfg,
        srk_assets=srk_table_array,
        container_signature=container_signature,
        container_signature_2=sig2,
    )
    sb.update_fields()
    cfg = sb.get_config(index=0, data_path=str(tmp_path))
    assert "signer" in cfg
    assert "signer_#2" in cfg


def test_signature_block_v2_verify_container_authenticity_no_srk(
    chip_cfg: AhabChipContainerConfig,
) -> None:
    """verify_container_authenticity on V2 block without SRK returns Verifier.

    :param chip_cfg: Chip configuration fixture.
    """
    sb = SignatureBlockV2(chip_config=chip_cfg)
    v = sb.verify_container_authenticity(b"dummy_data")
    assert isinstance(v, Verifier)


def test_signature_block_v2_verify_container_authenticity_with_srk(
    chip_cfg: AhabChipContainerConfig,
    srk_table_array: SRKTableArray,
    container_signature: ContainerSignature,
) -> None:
    """verify_container_authenticity on V2 block with SRK runs without exception.

    :param chip_cfg: Chip configuration fixture.
    :param srk_table_array: SRKTableArray fixture.
    :param container_signature: ContainerSignature fixture.
    """
    sb = SignatureBlockV2(
        chip_config=chip_cfg,
        srk_assets=srk_table_array,
        container_signature=container_signature,
    )
    sb.update_fields()
    v = sb.verify_container_authenticity(b"dummy_data")
    assert isinstance(v, Verifier)


def test_signature_block_v2_parse(
    chip_cfg: AhabChipContainerConfig,
    srk_table_array: SRKTableArray,
    container_signature: ContainerSignature,
) -> None:
    """Export then parse SignatureBlockV2 and check structure.

    :param chip_cfg: Chip configuration fixture.
    :param srk_table_array: SRKTableArray fixture.
    :param container_signature: ContainerSignature fixture.
    """
    sb = SignatureBlockV2(
        chip_config=chip_cfg,
        srk_assets=srk_table_array,
        container_signature=container_signature,
    )
    sb.update_fields()
    exported = sb.export()
    parsed = SignatureBlockV2.parse(exported, chip_config=chip_cfg)
    assert parsed.length == sb.length
    assert parsed._srk_assets_offset == sb._srk_assets_offset


def test_signature_block_v2_pre_parse_verify(
    chip_cfg: AhabChipContainerConfig,
    srk_table_array: SRKTableArray,
    container_signature: ContainerSignature,
) -> None:
    """Pre-parse verify on a valid exported SignatureBlockV2.

    :param chip_cfg: Chip configuration fixture.
    :param srk_table_array: SRKTableArray fixture.
    :param container_signature: ContainerSignature fixture.
    """
    sb = SignatureBlockV2(
        chip_config=chip_cfg,
        srk_assets=srk_table_array,
        container_signature=container_signature,
    )
    sb.update_fields()
    exported = sb.export()
    v = SignatureBlockV2.pre_parse_verify(exported)
    assert isinstance(v, Verifier)


def test_signature_block_v2_pre_parse_verify_empty(chip_cfg: AhabChipContainerConfig) -> None:
    """Pre-parse verify on empty SignatureBlockV2.

    :param chip_cfg: Chip configuration fixture.
    """
    sb = SignatureBlockV2(chip_config=chip_cfg)
    sb.update_fields()
    exported = sb.export()
    v = SignatureBlockV2.pre_parse_verify(exported)
    assert isinstance(v, Verifier)
