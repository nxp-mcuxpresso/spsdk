#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Extra.image.ahab.ahab_srk."""

from typing import cast

import pytest

from spsdk.crypto.keys import PrivateKeyEcc, PrivateKeyRsa, PublicKeyEcc, PublicKeyRsa
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.image.ahab.ahab_data import (
    AhabChipContainerConfig,
    AHABSignAlgorithm,
    AHABSignHashAlgorithm,
    create_chip_config,
)
from spsdk.image.ahab.ahab_srk import (
    SRKData,
    SRKRecord,
    SRKRecordV2,
    SRKTable,
    SRKTableArray,
    SRKTableV2,
    get_key_by_val,
)
from spsdk.utils.family import FamilyRevision

FAMILY = FamilyRevision("mimxrt1189")


@pytest.fixture(scope="module")
def chip_config_container() -> AhabChipContainerConfig:
    """Return an AhabChipContainerConfig for mimxrt1189."""
    return AhabChipContainerConfig(base=create_chip_config(family=FAMILY))


@pytest.fixture
def ecc256_pub() -> None:
    """Generate a P-256 public key."""
    return PrivateKeyEcc.generate_key("secp256r1").get_public_key()  # type: ignore[return-value, arg-type]


@pytest.fixture
def ecc384_pub() -> None:
    """Generate a P-384 public key."""
    return PrivateKeyEcc.generate_key("secp384r1").get_public_key()  # type: ignore[return-value, arg-type]


@pytest.fixture
def ecc521_pub() -> None:
    """Generate a P-521 public key."""
    return PrivateKeyEcc.generate_key("secp521r1").get_public_key()  # type: ignore[return-value, arg-type]


@pytest.fixture
def rsa2048_pub() -> None:
    """Generate an RSA-2048 public key."""
    return PrivateKeyRsa.generate_key(2048).get_public_key()  # type: ignore[return-value]


@pytest.fixture
def rsa4096_pub() -> None:
    """Generate an RSA-4096 public key."""
    return PrivateKeyRsa.generate_key(4096).get_public_key()  # type: ignore[return-value]


# get_key_by_val


def test_get_key_by_val_found() -> None:
    """get_key_by_val returns the correct key when value exists."""
    d = {"a": 1, "b": 2}
    assert get_key_by_val(d, 1) == "a"
    assert get_key_by_val(d, 2) == "b"


def test_get_key_by_val_not_found() -> None:
    """get_key_by_val raises SPSDKValueError when value is missing."""
    with pytest.raises(SPSDKValueError, match="not available"):
        get_key_by_val({"x": 10}, 99)


# SRKRecord – repr / str


def test_srk_record_repr(ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """__repr__ returns a human-readable string for SRKRecord."""
    srk = SRKRecord.create_from_key(ecc256_pub)
    r = repr(srk)
    assert "AHAB SRK record" in r


def test_srk_record_str(ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """__str__ includes key name, flags and crypto param value."""
    srk = SRKRecord.create_from_key(ecc256_pub)
    s = str(srk)
    assert "AHAB SRK Record" in s
    assert "SRK flags" in s
    assert "Crypto param value" in s


def test_srk_record_str_includes_params(ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKRecord.__str__ includes Param 1 and Param 2 values."""
    srk = SRKRecord.create_from_key(ecc256_pub)
    s = str(srk)
    assert "Param 1 value" in s
    assert "Param 2 value" in s


# SRKRecord – create_from_key with different key types


def test_srk_record_create_from_ecc256(ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKRecord created from P-256 key uses ECDSA and SHA256."""
    srk = SRKRecord.create_from_key(ecc256_pub)
    assert srk.signing_algorithm == AHABSignAlgorithm.ECDSA
    assert srk.hash_algorithm.label == "SHA256"
    assert srk.key_size == SRKRecord.ECC_KEY_TYPE[ecc256_pub.curve]


def test_srk_record_create_from_ecc384(ecc384_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKRecord created from P-384 key uses ECDSA and SHA384."""
    srk = SRKRecord.create_from_key(ecc384_pub)
    assert srk.signing_algorithm == AHABSignAlgorithm.ECDSA
    assert srk.hash_algorithm.label == "SHA384"


def test_srk_record_create_from_ecc521(ecc521_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKRecord created from P-521 key uses ECDSA and SHA512."""
    srk = SRKRecord.create_from_key(ecc521_pub)
    assert srk.signing_algorithm == AHABSignAlgorithm.ECDSA
    assert srk.hash_algorithm.label == "SHA512"


def test_srk_record_create_from_rsa2048(rsa2048_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKRecord created from RSA-2048 key uses RSA_PSS."""
    srk = SRKRecord.create_from_key(rsa2048_pub)
    assert srk.signing_algorithm == AHABSignAlgorithm.RSA_PSS
    assert srk.key_size == SRKRecord.RSA_KEY_TYPE[2048]


def test_srk_record_create_from_rsa4096(rsa4096_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKRecord created from RSA-4096 key."""
    srk = SRKRecord.create_from_key(rsa4096_pub)
    assert srk.signing_algorithm == AHABSignAlgorithm.RSA_PSS
    assert srk.key_size == SRKRecord.RSA_KEY_TYPE[4096]


def test_srk_record_create_from_rsa2048_legacy(rsa2048_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKRecord created with legacy RSA exponent size."""
    srk = SRKRecord.create_from_key(rsa2048_pub, legacy_rsa_exponent_size=True)
    srk.update_fields()
    data = srk.export()
    srk2 = SRKRecord.parse(data)
    # round-trip works with legacy mode
    assert srk2.signing_algorithm == AHABSignAlgorithm.RSA_PSS


# SRKRecord – export / parse round-trips


def test_srk_record_ecc256_roundtrip(ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """Export → parse round-trip for ECC P-256 SRKRecord."""
    srk = SRKRecord.create_from_key(ecc256_pub)
    srk.update_fields()
    data = srk.export()
    srk2 = SRKRecord.parse(data)
    assert srk == srk2


def test_srk_record_ecc384_roundtrip(ecc384_pub) -> None:  # type: ignore[no-untyped-def]
    """Export → parse round-trip for ECC P-384 SRKRecord."""
    srk = SRKRecord.create_from_key(ecc384_pub)
    srk.update_fields()
    data = srk.export()
    srk2 = SRKRecord.parse(data)
    assert srk == srk2


def test_srk_record_ecc521_roundtrip(ecc521_pub) -> None:  # type: ignore[no-untyped-def]
    """Export → parse round-trip for ECC P-521 SRKRecord."""
    srk = SRKRecord.create_from_key(ecc521_pub)
    srk.update_fields()
    data = srk.export()
    srk2 = SRKRecord.parse(data)
    assert srk == srk2


def test_srk_record_rsa2048_roundtrip(rsa2048_pub) -> None:  # type: ignore[no-untyped-def]
    """Export → parse round-trip for RSA-2048 SRKRecord."""
    srk = SRKRecord.create_from_key(rsa2048_pub)
    srk.update_fields()
    data = srk.export()
    srk2 = SRKRecord.parse(data)
    assert srk.key_size == srk2.key_size


def test_srk_record_rsa4096_roundtrip(rsa4096_pub) -> None:  # type: ignore[no-untyped-def]
    """Export → parse round-trip for RSA-4096 SRKRecord."""
    srk = SRKRecord.create_from_key(rsa4096_pub)
    srk.update_fields()
    data = srk.export()
    srk2 = SRKRecord.parse(data)
    assert srk.key_size == srk2.key_size


# SRKRecord – verify()


def test_srk_record_verify_ecc_ok(ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """verify() succeeds for a valid ECC SRKRecord."""
    srk = SRKRecord.create_from_key(ecc256_pub)
    srk.update_fields()
    v = srk.verify("srk0")
    assert not v.has_errors


def test_srk_record_verify_rsa_ok(rsa2048_pub) -> None:  # type: ignore[no-untyped-def]
    """verify() succeeds for a valid RSA SRKRecord."""
    srk = SRKRecord.create_from_key(rsa2048_pub)
    srk.update_fields()
    v = srk.verify("srk0")
    assert not v.has_errors


def test_srk_record_verify_bad_length(ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """verify() detects SRK length mismatch."""
    srk = SRKRecord.create_from_key(ecc256_pub)
    srk.update_fields()
    srk.length = 999  # corrupt length
    v = srk.verify("srk0")
    assert v.has_errors


# SRKRecord – get_public_key round-trips


def test_srk_record_get_public_key_ecc(ecc384_pub) -> None:  # type: ignore[no-untyped-def]
    """get_public_key() recreates the ECC public key from stored parameters."""
    srk = SRKRecord.create_from_key(ecc384_pub)
    srk.update_fields()
    data = srk.export()
    srk2 = SRKRecord.parse(data)
    pub = srk2.get_public_key()
    assert isinstance(pub, PublicKeyEcc)


def test_srk_record_get_public_key_rsa(rsa2048_pub) -> None:  # type: ignore[no-untyped-def]
    """get_public_key() recreates the RSA public key from stored parameters."""
    srk = SRKRecord.create_from_key(rsa2048_pub)
    srk.update_fields()
    data = srk.export()
    srk2 = SRKRecord.parse(data)
    pub = srk2.get_public_key()
    assert isinstance(pub, PublicKeyRsa)


def test_srk_record_get_key_name_rsa_pss(rsa2048_pub) -> None:  # type: ignore[no-untyped-def]
    """get_key_name() returns correct name for RSA_PSS."""
    srk = SRKRecord.create_from_key(rsa2048_pub)
    assert "rsa_pss2048" in srk.get_key_name()


def test_srk_record_get_key_name_ecdsa(ecc521_pub) -> None:  # type: ignore[no-untyped-def]
    """get_key_name() returns correct name for ECDSA."""
    srk = SRKRecord.create_from_key(ecc521_pub)
    name = srk.get_key_name()
    assert "secp521r1" in name.lower() or "521" in name.lower() or "EccCurve" in name


# SRKRecord – flags


def test_srk_record_ca_flag(ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """SRK flags CA bit is set when srk_flags has it."""
    srk = SRKRecord.create_from_key(ecc256_pub, srk_flags=SRKRecord.FLAGS_CA_MASK)
    assert bool(srk.srk_flags & SRKRecord.FLAGS_CA_MASK)


def test_srk_record_ca_flag_roundtrip(ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """CA flag survives export/parse."""
    srk = SRKRecord.create_from_key(ecc256_pub, srk_flags=SRKRecord.FLAGS_CA_MASK)
    srk.update_fields()
    data = srk.export()
    srk2 = SRKRecord.parse(data)
    assert bool(srk2.srk_flags & SRKRecord.FLAGS_CA_MASK)


# SRKRecord – equality


def test_srk_record_equality(ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """Two SRKRecords from the same key are equal."""
    srk1 = SRKRecord.create_from_key(ecc256_pub)
    srk1.update_fields()
    data = srk1.export()
    srk2 = SRKRecord.parse(data)
    assert srk1 == srk2


def test_srk_record_inequality(ecc256_pub, ecc384_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKRecords from different key types are not equal."""
    srk1 = SRKRecord.create_from_key(ecc256_pub)
    srk2 = SRKRecord.create_from_key(ecc384_pub)
    assert srk1 != srk2


def test_srk_record_not_equal_other_type(ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKRecord is not equal to a non-SRKRecord object."""
    srk = SRKRecord.create_from_key(ecc256_pub)
    assert srk != "not_a_srk"


# SRKTable – repr / str / bool


def test_srk_table_repr(ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKTable __repr__ includes key count."""
    table = SRKTable()
    for _ in range(4):
        table.add_record(ecc256_pub)
    r = repr(table)
    assert "AHAB SRK TABLE" in r
    assert "4" in r


def test_srk_table_str(ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKTable __str__ includes keys count and SRK hash."""
    table = SRKTable()
    for _ in range(4):
        table.add_record(ecc256_pub)
    table.update_fields()
    s = str(table)
    assert "Keys count" in s
    assert "SRK table HASH" in s


def test_srk_table_bool_nonempty(ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKTable bool is True when records exist."""
    table = SRKTable()
    table.add_record(ecc256_pub)
    assert bool(table)


def test_srk_table_bool_empty() -> None:
    """SRKTable bool is False when empty."""
    table = SRKTable()
    assert not bool(table)


# SRKTable – verify


def test_srk_table_verify_ok(ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """verify() passes for a valid 4-record ECC SRKTable."""
    table = SRKTable()
    for _ in range(4):
        table.add_record(ecc256_pub)
    table.update_fields()
    v = table.verify()
    assert not v.has_errors


def test_srk_table_verify_wrong_count(ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """verify() fails when SRK record count != 4."""
    table = SRKTable()
    for _ in range(2):
        table.add_record(ecc256_pub)
    table.update_fields()
    v = table.verify()
    assert v.has_errors


# SRKTable – export / parse round-trip


def test_srk_table_ecc256_roundtrip(ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKTable export → parse round-trip with P-256 keys."""
    table = SRKTable()
    for _ in range(4):
        table.add_record(ecc256_pub)
    table.update_fields()
    data = table.export()
    table2 = SRKTable.parse(data)
    assert len(table2.srk_records) == 4


def test_srk_table_rsa2048_roundtrip(rsa2048_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKTable export → parse round-trip with RSA-2048 keys."""
    table = SRKTable()
    for _ in range(4):
        table.add_record(rsa2048_pub)
    table.update_fields()
    data = table.export()
    table2 = SRKTable.parse(data)
    assert len(table2.srk_records) == 4


def test_srk_table_compute_srk_hash(ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """compute_srk_hash() returns a non-empty bytes object."""
    table = SRKTable()
    for _ in range(4):
        table.add_record(ecc256_pub)
    table.update_fields()
    h = table.compute_srk_hash()
    assert isinstance(h, bytes)
    assert len(h) == 32  # SHA-256


def test_srk_table_equality(ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """Two SRKTables with identical records are equal."""
    table1 = SRKTable()
    table2 = SRKTable()
    for _ in range(4):
        table1.add_record(ecc256_pub)
        table2.add_record(ecc256_pub)
    table1.update_fields()
    table2.update_fields()
    assert table1 == table2


def test_srk_table_get_source_keys(ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """get_source_keys() returns a list of public keys."""
    table = SRKTable()
    for _ in range(4):
        table.add_record(ecc256_pub)
    keys = table.get_source_keys()
    assert len(keys) == 4
    for k in keys:
        assert isinstance(k, PublicKeyEcc)


def test_srk_table_clear(ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """clear() removes all records from SRKTable."""
    table = SRKTable()
    for _ in range(4):
        table.add_record(ecc256_pub)
    table.clear()
    assert len(table.srk_records) == 0
    assert table.length == -1


def test_srk_table_pre_parse_verify(ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """pre_parse_verify() passes for valid SRKTable binary data."""
    table = SRKTable()
    for _ in range(4):
        table.add_record(ecc256_pub)
    table.update_fields()
    data = table.export()
    v = SRKTable.pre_parse_verify(data)
    assert not v.has_errors


# SRKRecordBase – key_sizes property with invalid key_size


def test_srk_record_base_key_sizes_invalid() -> None:
    """key_sizes raises SPSDKError for an unsupported key_size value."""
    srk = SRKRecord(
        signing_algorithm=AHABSignAlgorithm.ECDSA,
        hash_type=AHABSignHashAlgorithm.SHA256,
        key_size=0xFF,  # invalid
    )
    with pytest.raises(SPSDKError):
        _ = srk.key_sizes


# SRKRecordV2 – create_from_key and round-trip


def test_srk_record_v2_create_from_ecc(ecc384_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKRecordV2 can be created from a P-384 ECC key."""
    srk = SRKRecordV2.create_from_key(ecc384_pub, srk_id=0)
    assert srk.srk_data is not None
    assert srk.signing_algorithm == AHABSignAlgorithm.ECDSA


def test_srk_record_v2_create_from_rsa(rsa2048_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKRecordV2 can be created from an RSA-2048 key."""
    srk = SRKRecordV2.create_from_key(rsa2048_pub, srk_id=1)
    assert srk.srk_data is not None
    assert srk.signing_algorithm == AHABSignAlgorithm.RSA_PSS


def test_srk_record_v2_str(ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKRecordV2 __str__ includes SRK Data Hash."""
    srk = SRKRecordV2.create_from_key(ecc256_pub, srk_id=0)
    srk.update_fields()
    s = str(srk)
    assert "SRK Data Hash" in s


def test_srk_record_v2_verify_ecc(ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKRecordV2.verify() succeeds for a valid ECC key."""
    srk = SRKRecordV2.create_from_key(ecc256_pub, srk_id=0)
    srk.update_fields()
    v = srk.verify("srk0")
    assert not v.has_errors


def test_srk_record_v2_verify_rsa(rsa2048_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKRecordV2.verify() succeeds for a valid RSA key."""
    srk = SRKRecordV2.create_from_key(rsa2048_pub, srk_id=0)
    srk.update_fields()
    v = srk.verify("srk0")
    assert not v.has_errors


def test_srk_record_v2_get_public_key_ecc(ecc384_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKRecordV2.get_public_key() recreates the ECC public key."""
    srk = SRKRecordV2.create_from_key(ecc384_pub, srk_id=0)
    srk.update_fields()
    pub = srk.get_public_key()
    assert isinstance(pub, PublicKeyEcc)


def test_srk_record_v2_get_public_key_rsa(rsa2048_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKRecordV2.get_public_key() recreates the RSA public key."""
    srk = SRKRecordV2.create_from_key(rsa2048_pub, srk_id=0)
    srk.update_fields()
    pub = srk.get_public_key()
    assert isinstance(pub, PublicKeyRsa)


def test_srk_record_v2_get_public_key_no_data() -> None:
    """SRKRecordV2.get_public_key() raises SPSDKError when srk_data is None."""
    srk = SRKRecordV2(
        signing_algorithm=AHABSignAlgorithm.ECDSA,
        hash_type=AHABSignHashAlgorithm.SHA256,
        key_size=SRKRecord.ECC_KEY_TYPE[
            __import__("spsdk.crypto.keys", fromlist=["EccCurve"]).EccCurve.SECP256R1
        ],
    )
    with pytest.raises(SPSDKError, match="missing SRK Data"):
        srk.get_public_key()


def test_srk_record_v2_compute_srk_data_hash(ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """compute_srk_data_hash() returns 64-byte hash."""
    srk = SRKRecordV2.create_from_key(ecc256_pub, srk_id=0)
    assert srk.srk_data is not None
    srk.srk_data.update_fields()
    h = srk.compute_srk_data_hash(srk.srk_data)
    assert len(h) == SRKRecordV2.CRYPTO_PARAMS_LEN


def test_srk_record_v2_srk_data_hash_property(ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """srk_data_hash property returns the crypto_params."""
    srk = SRKRecordV2.create_from_key(ecc256_pub, srk_id=0)
    srk.update_fields()
    assert srk.srk_data_hash == srk.crypto_params


# SRKData – repr / str / verify


def test_srk_data_repr(ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKData __repr__ includes key ID."""
    srk_data = SRKData.create_from_key(ecc256_pub, srk_id=2)
    r = repr(srk_data)
    assert "AHAB SRK Data" in r
    assert "2" in r


def test_srk_data_str(ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKData __str__ shows SRK ID and data length."""
    srk_data = SRKData.create_from_key(ecc256_pub, srk_id=1)
    s = str(srk_data)
    assert "SRK ID" in s
    assert "Data length" in s


def test_srk_data_verify_ok(ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKData.verify() passes for valid data."""
    srk_data = SRKData.create_from_key(ecc256_pub, srk_id=0)
    srk_data.update_fields()
    v = srk_data.verify("srk_data")
    assert not v.has_errors


def test_srk_data_create_from_ecc(ecc384_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKData.create_from_key() works for ECC P-384."""
    srk_data = SRKData.create_from_key(ecc384_pub, srk_id=0)
    assert len(srk_data.data) == 48 + 48  # X + Y for P-384


def test_srk_data_create_from_rsa(rsa2048_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKData.create_from_key() works for RSA-2048."""
    srk_data = SRKData.create_from_key(rsa2048_pub, srk_id=0)
    # RSA-2048: 256-byte modulus + e bytes
    assert len(srk_data.data) >= 256


def test_srk_data_export_parse_roundtrip(ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKData export → parse round-trip."""
    srk_data = SRKData.create_from_key(ecc256_pub, srk_id=3)
    srk_data.update_fields()
    raw = srk_data.export()
    parsed = SRKData.parse(raw)
    assert parsed.srk_id == 3
    assert parsed.data == srk_data.data


def test_srk_data_equality(ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """Two SRKData objects from same key are equal."""
    d1 = SRKData.create_from_key(ecc256_pub, srk_id=0)
    d2 = SRKData.create_from_key(ecc256_pub, srk_id=0)
    d1.update_fields()
    d2.update_fields()
    assert d1 == d2


def test_srk_data_inequality_different_srk_id(ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKData objects with different srk_id are not equal."""
    d1 = SRKData.create_from_key(ecc256_pub, srk_id=0)
    d2 = SRKData.create_from_key(ecc256_pub, srk_id=1)
    d1.update_fields()
    d2.update_fields()
    assert d1 != d2


# SRKTableV2 – repr / str / verify / roundtrip


def test_srk_table_v2_repr(ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKTableV2 repr includes key count."""
    table = SRKTableV2()
    for i in range(4):
        table.add_record(ecc256_pub, srk_id=i)
    r = repr(table)
    assert "AHAB SRK TABLE" in r


def test_srk_table_v2_verify_ok(ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKTableV2.verify() succeeds for valid 4-record table."""
    table = SRKTableV2()
    for i in range(4):
        table.add_record(ecc256_pub, srk_id=i)
        cast(SRKRecordV2, table.srk_records[i]).srk_data = SRKData.create_from_key(ecc256_pub, i)
    table.update_fields()
    v = table.verify()
    assert not v.has_errors


def test_srk_table_v2_compute_srk_hash(ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKTableV2.compute_srk_hash() returns 64-byte SHA-512 hash."""
    table = SRKTableV2()
    for i in range(4):
        table.add_record(ecc256_pub, srk_id=i)
        cast(SRKRecordV2, table.srk_records[i]).srk_data = SRKData.create_from_key(ecc256_pub, i)
    table.update_fields()
    h = table.compute_srk_hash()
    assert len(h) == 64  # SHA-512


# SRKTableArray – repr / str / verify / roundtrip


def test_srk_table_array_repr(chip_config_container, ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKTableArray repr shows table count."""
    table = SRKTableV2()
    for i in range(4):
        table.add_record(ecc256_pub, srk_id=i)
        cast(SRKRecordV2, table.srk_records[i]).srk_data = SRKData.create_from_key(ecc256_pub, i)
    arr = SRKTableArray(chip_config=chip_config_container, srk_tables=[table])
    r = repr(arr)
    assert "AHAB SRK ARRAY" in r
    assert "1" in r


def test_srk_table_array_str(chip_config_container, ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKTableArray __str__ includes length and hash info."""
    table = SRKTableV2()
    for i in range(4):
        table.add_record(ecc256_pub, srk_id=i)
        cast(SRKRecordV2, table.srk_records[i]).srk_data = SRKData.create_from_key(ecc256_pub, i)
    arr = SRKTableArray(chip_config=chip_config_container, srk_tables=[table])
    arr.update_fields()
    s = str(arr)
    assert "SRK tables count" in s
    assert "SRK_0 table HASH" in s


def test_srk_table_array_srk_count(chip_config_container, ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKTableArray.srk_count returns the number of tables."""
    table = SRKTableV2()
    for i in range(4):
        table.add_record(ecc256_pub, srk_id=i)
        cast(SRKRecordV2, table.srk_records[i]).srk_data = SRKData.create_from_key(ecc256_pub, i)
    arr = SRKTableArray(chip_config=chip_config_container, srk_tables=[table])
    assert arr.srk_count == 1


def test_srk_table_array_bool(chip_config_container, ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKTableArray bool is True when tables are present."""
    table = SRKTableV2()
    for i in range(4):
        table.add_record(ecc256_pub, srk_id=i)
        cast(SRKRecordV2, table.srk_records[i]).srk_data = SRKData.create_from_key(ecc256_pub, i)
    arr = SRKTableArray(chip_config=chip_config_container, srk_tables=[table])
    assert bool(arr)


def test_srk_table_array_bool_empty(chip_config_container) -> None:  # type: ignore[no-untyped-def]
    """SRKTableArray bool is False when empty."""
    arr = SRKTableArray(chip_config=chip_config_container)
    assert not bool(arr)


def test_srk_table_array_compute_srk_hash(chip_config_container, ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """compute_srk_hash() works for existing SRK table."""
    table = SRKTableV2()
    for i in range(4):
        table.add_record(ecc256_pub, srk_id=i)
        cast(SRKRecordV2, table.srk_records[i]).srk_data = SRKData.create_from_key(ecc256_pub, i)
    table.update_fields()
    arr = SRKTableArray(chip_config=chip_config_container, srk_tables=[table])
    h = arr.compute_srk_hash(0)
    assert len(h) == 64


def test_srk_table_array_compute_srk_hash_oob(chip_config_container, ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """compute_srk_hash() raises SPSDKValueError for out-of-range srk_id."""
    table = SRKTableV2()
    for i in range(4):
        table.add_record(ecc256_pub, srk_id=i)
        cast(SRKRecordV2, table.srk_records[i]).srk_data = SRKData.create_from_key(ecc256_pub, i)
    arr = SRKTableArray(chip_config=chip_config_container, srk_tables=[table])
    with pytest.raises(SPSDKValueError):
        arr.compute_srk_hash(5)


def test_srk_table_array_verify(chip_config_container, ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKTableArray.verify() passes for a valid single-table array."""
    table = SRKTableV2()
    for i in range(4):
        table.add_record(ecc256_pub, srk_id=i)
        cast(SRKRecordV2, table.srk_records[i]).srk_data = SRKData.create_from_key(ecc256_pub, i)
    table.update_fields()
    arr = SRKTableArray(chip_config=chip_config_container, srk_tables=[table])
    arr.update_fields()
    v = arr.verify()
    assert not v.has_errors


def test_srk_table_array_export_parse_roundtrip(chip_config_container, ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKTableArray export → parse round-trip."""
    table = SRKTableV2()
    for i in range(4):
        table.add_record(ecc256_pub, srk_id=i)
        cast(SRKRecordV2, table.srk_records[i]).srk_data = SRKData.create_from_key(ecc256_pub, i)
    table.update_fields()
    arr = SRKTableArray(chip_config=chip_config_container, srk_tables=[table])
    arr.update_fields()
    raw = arr.export()
    arr2 = SRKTableArray.parse(raw, chip_config=chip_config_container)
    assert arr2.srk_count == 1


def test_srk_table_array_pre_parse_verify(chip_config_container, ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKTableArray.pre_parse_verify() passes for valid binary."""
    table = SRKTableV2()
    for i in range(4):
        table.add_record(ecc256_pub, srk_id=i)
        cast(SRKRecordV2, table.srk_records[i]).srk_data = SRKData.create_from_key(ecc256_pub, i)
    table.update_fields()
    arr = SRKTableArray(chip_config=chip_config_container, srk_tables=[table])
    arr.update_fields()
    raw = arr.export()
    v = SRKTableArray.pre_parse_verify(raw)
    assert not v.has_errors


def test_srk_table_array_two_tables_str(chip_config_container, ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """SRKTableArray __str__ shows second hash when two tables present."""
    tables = []
    for _ in range(2):
        table = SRKTableV2()
        for i in range(4):
            table.add_record(ecc256_pub, srk_id=i)
            cast(SRKRecordV2, table.srk_records[i]).srk_data = SRKData.create_from_key(
                ecc256_pub, i
            )
        table.update_fields()
        tables.append(table)
    arr = SRKTableArray(chip_config=chip_config_container, srk_tables=tables)
    arr.update_fields()
    s = str(arr)
    assert "SRK_1 table HASH" in s


def test_srk_table_array_equality(chip_config_container, ecc256_pub) -> None:  # type: ignore[no-untyped-def]
    """Two SRKTableArrays with identical tables are equal."""

    def make_array() -> None:
        table = SRKTableV2()
        for i in range(4):
            table.add_record(ecc256_pub, srk_id=i)
            cast(SRKRecordV2, table.srk_records[i]).srk_data = SRKData.create_from_key(
                ecc256_pub, i
            )
        table.update_fields()
        arr = SRKTableArray(chip_config=chip_config_container, srk_tables=[table])
        arr.update_fields()
        return arr  # type: ignore[return-value]

    arr1 = make_array()  # type: ignore[func-returns-value]
    arr2 = make_array()  # type: ignore[func-returns-value]
    assert arr1 == arr2
