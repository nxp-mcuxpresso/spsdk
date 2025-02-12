#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import filecmp
import hashlib
import logging
import os
import shutil
from itertools import zip_longest
from typing import Optional
from unittest.mock import patch

import pytest
from click.testing import Result

from spsdk.apps import nxpcrypto
from spsdk.crypto.certificate import Certificate
from spsdk.crypto.crypto_types import SPSDKEncoding
from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.crypto.keys import (
    IS_DILITHIUM_SUPPORTED,
    IS_OSCCA_SUPPORTED,
    ECDSASignature,
    PrivateKeyRsa,
    PublicKey,
    PublicKeyRsa,
    PublicKeyDilithium,
)
from spsdk.crypto.crc import Crc, CrcAlg, from_crc_algorithm
from spsdk.exceptions import SPSDKError, SPSDKIndexError, SPSDKKeyError, SPSDKSyntaxError
from spsdk.utils.misc import Endianness, load_binary, load_text, use_working_directory, write_file
from tests.cli_runner import CliRunner
from tests.misc import GetPassMock

if IS_DILITHIUM_SUPPORTED:
    from spsdk_pqc.wrapper import KEY_INFO, DILITHIUM_LEVEL

    from spsdk.crypto.keys import PrivateKeyDilithium


def run_nxpcrypto(cli_runner: CliRunner, cmd: str, cwd: str, expected_code=0) -> Result:
    with use_working_directory(cwd):
        logging.debug(f"Running {cmd}")
        result = cli_runner.invoke(nxpcrypto.main, cmd.split(), expected_code=expected_code)
    return result


@pytest.mark.parametrize(
    "key1, key2, expected_result",
    [
        ("prk_secp256_d_3.pem", "puk_secp256_d_3.pem", 0),
        ("prk_secp256_d_5.der", "puk_secp256_d_5.der", 0),
        ("prk_secp256_d_5.der", "puk_secp256_d_5.pem", 0),
        ("prk_secp256_d_3.bin", "puk_secp256_d_5.bin", 1),
        ("prk_secp256_d_3.pem", "puk_secp256_d_5.der", 1),
        ("prk_rsa4096.pem", "puk_rsa4096.pem", 0),
    ],
)
def test_nxpcrypto_key_verify(
    cli_runner: CliRunner, data_dir: str, key1: str, key2: str, expected_result: int
):
    cmd = f"key verify -k1 {key1} -k2 {key2}"
    run_nxpcrypto(cli_runner, cmd, data_dir, expected_result)


@pytest.mark.parametrize(
    "key, transform, expected",
    [
        ("prk_secp256_d_3.bin", "-e pem", "prk_secp256_d_3.pem"),
        ("prk_secp256_d_3.pem", "-e raw", "prk_secp256_d_3.bin"),
        ("prk_secp256_d_3.bin", "-e pem --puk", "puk_secp256_d_3.pem"),
        ("puk_secp256_d_5.pem", "-e der", "puk_secp256_d_5.der"),
        ("prk_rsa4096.pem", "-e der", "prk_rsa4096.der"),
        ("prk_rsa4096.pem", "-e pem --puk", "puk_rsa4096.pem"),
    ],
)
def test_nxpcrypto_key_convert(
    cli_runner: CliRunner, data_dir: str, tmpdir: str, key: str, transform: str, expected: str
):
    src_key = f"{data_dir}/{expected}"
    dst_key = f"{tmpdir}/{expected}"
    cmd = f"key convert -i {key} {transform} -o {dst_key}"
    run_nxpcrypto(cli_runner, cmd, data_dir)

    # to validate RAW conversion we need to compare raw data as INT (there might be difference in padding)
    if "raw" in transform:
        src_num = int.from_bytes(load_binary(src_key), byteorder=Endianness.BIG.value)
        dst_num = int.from_bytes(load_binary(dst_key), byteorder=Endianness.BIG.value)
        assert src_num == dst_num
    # DER conversion is fine
    if "der" in transform:
        assert filecmp.cmp(src_key, dst_key)
    # in PEM we need to care about line-endings
    if "pem" in transform:
        src_lines = load_text(src_key).splitlines(keepends=False)
        dst_lines = load_text(dst_key).splitlines(keepends=False)
        # zip_longest ensures there will be an error if one file is longer
        for src_line, dst_line in zip_longest(src_lines, dst_lines):
            assert src_line == dst_line


@pytest.mark.parametrize(
    "key, encoding, expected",
    [
        ("prk_secp256_d_3.bin", "pem", "prk_secp256_d_3.pem"),
        ("prk_secp256_d_3.pem", "raw", "prk_secp256_d_3.bin"),
        ("prk_secp256_d_3.bin", "der", "puk_secp256_d_3.pem"),
        ("puk_secp256_d_5.pem", "der", "puk_secp256_d_5.der"),
        ("puk_secp256_d_5.bin", "der", "puk_secp256_d_5.der"),
        ("prk_rsa4096.pem", "der", "prk_rsa4096.der"),
        ("prk_rsa4096.pem", "pem", "puk_rsa4096.pem"),
    ],
)
def test_nxpcrypto_extract_puk(
    cli_runner: CliRunner, data_dir: str, tmpdir: str, key: str, encoding: str, expected: str
):
    src_key = f"{data_dir}/{expected}"
    dst_key = f"{tmpdir}/{expected}"
    cmd = f"key convert -i {key} -e {encoding} --puk -o {dst_key}"
    run_nxpcrypto(cli_runner, cmd, data_dir)

    src_key_data = load_binary(src_key)
    prk = nxpcrypto.reconstruct_key(src_key_data)
    dst_key_data = load_binary(dst_key)
    puk = nxpcrypto.reconstruct_key(dst_key_data)
    try:
        assert prk.get_public_key() == puk
    except AttributeError:  # in case input key is public
        assert prk == puk


def test_nxpcrypto_convert_rsa_raw_not_supported(cli_runner: CliRunner, data_dir: str, tmpdir: str):
    dst_key = f"{tmpdir}/prk_rsa4096.bin"
    cmd = f"key convert -i prk_rsa4096.pem -e raw -o {dst_key}"
    result = run_nxpcrypto(cli_runner, cmd, data_dir, expected_code=1)
    assert result.exc_info[0] is SPSDKError


def test_generate_rsa_key(cli_runner: CliRunner, tmpdir) -> None:
    """Test generate rsa key pair."""

    cmd = f'{os.path.join(tmpdir, "key_rsa.pem")}'
    run_nxpcrypto(cli_runner, f"key generate -k rsa2048 -o {cmd}", tmpdir)
    assert os.path.isfile(os.path.join(tmpdir, "key_rsa.pem"))
    assert os.path.isfile(os.path.join(tmpdir, "key_rsa.pub"))

    pub_key_from_file = PublicKeyRsa.load(os.path.join(tmpdir, "key_rsa.pub"))
    assert isinstance(pub_key_from_file, PublicKeyRsa)
    assert pub_key_from_file.key_size == 2048

    priv_key_from_file = PrivateKeyRsa.load(os.path.join(tmpdir, "key_rsa.pem"))
    assert priv_key_from_file.key_size == 2048


def test_generate_invalid_key(cli_runner: CliRunner, tmpdir) -> None:
    """Test generate invalid key pair."""

    cmd = f'key generate -k invalid-key-type -o {os.path.join(tmpdir, "key_invalid.pem")}'
    run_nxpcrypto(cli_runner, cmd, tmpdir, expected_code=-1)
    assert not os.path.isfile(os.path.join(tmpdir, "key_invalid.pem"))
    assert not os.path.isfile(os.path.join(tmpdir, "key_invalid.pub"))


def test_force_actual_dir(cli_runner: CliRunner, tmpdir):
    run_nxpcrypto(cli_runner, "key generate -k rsa2048 -o key", tmpdir)
    # attempt to rewrite the key should fail
    run_nxpcrypto(cli_runner, "key generate -k rsa2048 -o key", tmpdir, expected_code=1)
    # attempt to rewrite should pass due to --forces
    run_nxpcrypto(cli_runner, "key generate -k rsa2048 -o key --force", tmpdir)


@pytest.mark.parametrize(
    "key, valid",
    [
        ("secp256r1", True),
        ("secp384r1", True),
        ("secp521r1", True),
    ],
)
def test_key_types(cli_runner: CliRunner, tmpdir, key, valid):
    if valid:
        run_nxpcrypto(cli_runner, f"key generate -k {key} -o my_key_{key}.pem", tmpdir)
        assert os.path.isfile(os.path.join(tmpdir, f"my_key_{key}.pem"))
        assert os.path.isfile(os.path.join(tmpdir, f"my_key_{key}.pub"))
    else:
        run_nxpcrypto(
            cli_runner, f"key generate -k {key} -o my_key_{key}.pem", tmpdir, expected_code=-1
        )


@pytest.mark.parametrize(
    "keys, family, ref_rotkth, base64",
    [
        (
            ["ec_secp256r1_cert0.pem"],
            "mcxn9xx",
            "671e3f7108621830c08df03c339d2ce9700c0a4bd74f7bfbcc48fbe27c78bf05",
            False,
        ),
        (
            ["ec_secp256r1_cert0.pem", "ec_secp256r1_cert1.pem"],
            "mcxn9xx",
            "8ba978ef5dd132a4462d8f93abdba11c89d3f8060b3dd4ba6d6d5c9fbb7c38fa",
            False,
        ),
        (
            [
                "ec_secp256r1_cert0.pem",
                "ec_secp256r1_cert1.pem",
                "ec_secp256r1_cert2.pem",
                "ec_secp256r1_cert3.pem",
            ],
            "mcxn9xx",
            "3f1f71ccd8dfcbcff3e445c21f003a974f8c40ce9aa7d8c567416b9ab45d1655",
            False,
        ),
        (
            [
                "ec_secp256r1_cert0.pem",
                "ec_secp256r1_cert1.pem",
                "ec_secp256r1_cert2.pem",
                "ec_secp256r1_cert3.pem",
            ],
            "rw61x",
            "3f1f71ccd8dfcbcff3e445c21f003a974f8c40ce9aa7d8c567416b9ab45d1655",
            False,
        ),
        (
            [
                "ec_secp256r1_cert0.pem",
                "ec_secp256r1_cert1.pem",
                "ec_secp256r1_cert2.pem",
                "ec_secp256r1_cert3.pem",
            ],
            "kw45xx",
            "3f1f71ccd8dfcbcff3e445c21f003a974f8c40ce9aa7d8c567416b9ab45d1655",
            False,
        ),
        (
            [
                "ec_secp256r1_cert0.pem",
                "ec_secp256r1_cert1.pem",
                "ec_secp256r1_cert2.pem",
                "ec_secp256r1_cert3.pem",
            ],
            "k32w1xx",
            "3f1f71ccd8dfcbcff3e445c21f003a974f8c40ce9aa7d8c567416b9ab45d1655",
            False,
        ),
        (
            ["ec_secp256r1_cert0.pem"],
            "lpc55s0x",
            "7eb98e20a565ba54e866a3920967c3a56a1acf07043ab08fc36a90d55a6e0eb0",
            False,
        ),
        (
            ["ec_secp256r1_cert0.pem", "ec_secp256r1_cert1.pem"],
            "lpc55s0x",
            "3e3bfcd794c998eeaef6347a2a438ec36e5e5132d350d31fcbd927bfcc120c9e",
            False,
        ),
        (
            [
                "ec_secp256r1_cert0.pem",
                "ec_secp256r1_cert1.pem",
                "ec_secp256r1_cert2.pem",
                "ec_secp256r1_cert3.pem",
            ],
            "lpc55s0x",
            "3f1f71ccd8dfcbcff3e445c21f003a974f8c40ce9aa7d8c567416b9ab45d1655",
            False,
        ),
        (
            [
                "ec_secp256r1_cert0.pem",
                "ec_secp256r1_cert1.pem",
                "ec_secp256r1_cert2.pem",
                "ec_secp256r1_cert3.pem",
            ],
            "mimxrt1189",
            "34f1cd4517440f815cf57ae9f80346c74cff8804f8f5fb02b202657271e94d81",
            False,
        ),
        (
            [
                "SRK1_sha256_secp384r1_v3_ca_crt.pem",
                "SRK2_sha256_secp384r1_v3_ca_crt.pem",
                "SRK3_sha256_secp384r1_v3_ca_crt.pem",
                "SRK4_sha256_secp384r1_v3_ca_crt.pem",
            ],
            "mimxrt1176",
            "bcd8f444bd7f9ccd8048a8bcf8c2764f085058ed527c6978037a94ffb81c14e8",
            False,
        ),
        (
            [
                "ec_secp256r1_cert0.pem",
                "ec_secp256r1_cert1.pem",
                "ec_secp256r1_cert2.pem",
                "ec_secp256r1_cert3.pem",
            ],
            "mimxrt1189",
            "NPHNRRdED4Fc9Xrp+ANGx0z/iAT49fsCsgJlcnHpTYE=",
            True,
        ),
    ],
)
def test_nxpcrypto_rot_calc_hash(
    cli_runner: CliRunner,
    data_dir: str,
    tmpdir: str,
    keys: list,
    family: str,
    ref_rotkth: str,
    base64: bool,
):
    out_file = os.path.join(tmpdir, "rot_hash.bin")
    cmd = f"rot calculate-hash -f {family} -o {out_file}"
    for key in keys:
        cmd = " ".join([cmd, f"-k {key}"])
    if base64:
        cmd += " -b"
    run_nxpcrypto(cli_runner, cmd, data_dir)
    assert os.path.isfile(out_file)
    rotkth_bin = load_binary(out_file)
    rotkth = rotkth_bin.decode("utf-8") if base64 else rotkth_bin.hex()
    assert rotkth == ref_rotkth


@pytest.mark.parametrize(
    "keys, family, ref_rot",
    [
        (
            ["ec_secp256r1_cert0.pem"],
            "lpc55s0x",
            "rot_lpc550x_1_key.bin",
        ),
        (
            [
                "ec_secp256r1_cert0.pem",
                "ec_secp256r1_cert1.pem",
                "ec_secp256r1_cert2.pem",
                "ec_secp256r1_cert3.pem",
            ],
            "lpc55s0x",
            "rot_lpc550x.bin",
        ),
        (
            [
                "SRK1_sha256_secp384r1_v3_ca_crt.pem",
                "SRK2_sha256_secp384r1_v3_ca_crt.pem",
                "SRK3_sha256_secp384r1_v3_ca_crt.pem",
                "SRK4_sha256_secp384r1_v3_ca_crt.pem",
            ],
            "mimxrt1176",
            "rot_mimxrt1176.bin",
        ),
        (
            [
                "ec_secp256r1_cert0.pem",
                "ec_secp256r1_cert1.pem",
                "ec_secp256r1_cert2.pem",
                "ec_secp256r1_cert3.pem",
            ],
            "mimxrt1189",
            "rot_mimxrt1189.bin",
        ),
    ],
)
def test_nxpcrypto_rot_export(
    cli_runner: CliRunner, data_dir: str, tmpdir: str, keys: list, family: str, ref_rot: str
):
    out_file = os.path.join(tmpdir, "rot_table.bin")
    ref_file = os.path.join(data_dir, ref_rot)
    cmd = f"rot export -f {family} -o {out_file}"
    for key in keys:
        cmd = " ".join([cmd, f"-k {key}"])
    run_nxpcrypto(cli_runner, cmd, data_dir)
    assert os.path.isfile(out_file)
    assert load_binary(out_file) == load_binary(ref_file)


def test_npxcrypto_cert_get_template(cli_runner: CliRunner, tmpdir):
    """Test NXPCRYPTO CLI - Generation of template."""
    cmd = ["cert", "get-template", "--output", f"{tmpdir}/cert.yml"]
    cli_runner.invoke(nxpcrypto.main, cmd)
    assert os.path.isfile(f"{tmpdir}/cert.yml")


@pytest.mark.parametrize("password", [None, "password123"])
@pytest.mark.parametrize(
    "key_type",
    ["SECP256R1", "SECP384R1", "SECP521R1", "RSA2048", "RSA4096"],
)
@pytest.mark.parametrize("encoding", ["PEM", "DER"])
def test_nxpcrypto_cert_generate(
    cli_runner: CliRunner,
    data_dir: str,
    tmpdir,
    key_type: str,
    password: Optional[str],
    encoding: str,
):
    # Generate subject key pair
    subject_key = os.path.join(tmpdir, "subject_key.pem")
    subject_public_key = os.path.join(tmpdir, "subject_key.pub")
    cmd = ["key", "generate", "-k", key_type, "-o", subject_key, "-e", encoding]
    cli_runner.invoke(nxpcrypto.main, cmd)

    # Generate issuer key pair
    issuer_key = os.path.join(tmpdir, "issuer_key.pem")
    cmd = ["key", "generate", "-k", key_type, "-o", issuer_key, "-e", encoding]
    if password:
        cmd.extend(["--password", password])
    cli_runner.invoke(nxpcrypto.main, cmd)

    shutil.copy(os.path.join(data_dir, "cert.yaml"), tmpdir)
    crt_config = os.path.join(tmpdir, "cert.yaml")
    out_crt = os.path.join(tmpdir, "cert.crt")
    cmd = ["cert", "generate", "-c", crt_config, "-o", out_crt, "-e", encoding]

    with patch("spsdk.crypto.keys.getpass", GetPassMock(password)):
        cli_runner.invoke(nxpcrypto.main, cmd)
    assert os.path.isfile(out_crt)
    Certificate.load(out_crt)

    cmd = ["cert", "verify", "-c", out_crt, "-p", subject_public_key]
    result = cli_runner.invoke(nxpcrypto.main, cmd)
    assert "Public key in certificate matches the input" in result.output

    # Convert the certificate to DER
    cmd = ["cert", "convert", "-i", out_crt, "-e", "DER", "-o", f"{tmpdir}/cert.der"]
    result = cli_runner.invoke(nxpcrypto.main, cmd)
    assert os.path.isfile(f"{tmpdir}/cert.der")

    # Convert the certificate to PEM
    cmd = ["cert", "convert", "-i", f"{tmpdir}/cert.der", "-e", "PEM", "-o", f"{tmpdir}/cert.pem"]
    result = cli_runner.invoke(nxpcrypto.main, cmd)
    assert os.path.isfile(f"{tmpdir}/cert.pem")


SIGNATURE_NOT_MATCHING = "Signature IS NOT matching the public key"
SIGNATURE_MATCHING = "Signature IS matching the public key"


def get_key_path(data_dir: str, key_type: str):
    """Get paths to pre-generated key pairs."""
    sign_data_dir = os.path.join(data_dir, "signature_tool")
    private_ext = "pem"
    if key_type == "sm2":
        private_ext = "der"
    if key_type.startswith("dil"):
        private_ext = "bin"

    private = os.path.join(sign_data_dir, f"{key_type}.{private_ext}")
    public = os.path.join(sign_data_dir, f"{key_type}.pub")
    assert os.path.isfile(private)
    assert os.path.isfile(public)
    return private, public


def run_signature(
    cli_runner: CliRunner, data_dir: str, tmpdir: str, key_type: str, algorithm: EnumHashAlgorithm
) -> None:
    priv_key, pub_key = get_key_path(data_dir, key_type)

    input_file = os.path.join(data_dir, "data_to_sign.bin")
    output_file = os.path.join(tmpdir, f"signature_{key_type}_{algorithm}.bin")

    cmd = f"signature create -k {priv_key} -i {input_file} -o {output_file}"
    if algorithm:
        cmd += f" --algorithm {algorithm.label}"
    run_nxpcrypto(cli_runner, cmd, tmpdir)
    assert os.path.isfile(output_file)

    pub = PublicKey.load(pub_key)
    signature = load_binary(output_file)

    extra_params = {}
    if algorithm:
        extra_params["algorithm"] = algorithm
    assert pub.verify_signature(signature, load_binary(input_file), **extra_params)


@pytest.mark.parametrize(
    "key_type, algorithms",
    [
        ("secp256r1", [None, EnumHashAlgorithm.SHA256]),
        ("secp384r1", [None, EnumHashAlgorithm.SHA384]),
        ("secp521r1", [None, EnumHashAlgorithm.SHA512]),
        ("rsa2048", [None, EnumHashAlgorithm.SHA256]),
        ("rsa4096", [None, EnumHashAlgorithm.SHA256]),
    ],
)
def test_nxpcrypto_create_signature_algorithm_mandatory(
    cli_runner: CliRunner,
    data_dir: str,
    tmpdir,
    key_type: str,
    algorithms: list[Optional[EnumHashAlgorithm]],
):
    for algorithm in algorithms:
        run_signature(cli_runner, data_dir, tmpdir, key_type, algorithm)


@pytest.mark.xfail(reason="Some Linux distributions allows only certain combinations of key-hash")
@pytest.mark.parametrize(
    "key_type, algorithms",
    [
        ("secp256r1", [EnumHashAlgorithm.SHA384, EnumHashAlgorithm.SHA512]),
        ("secp384r1", [EnumHashAlgorithm.SHA256, EnumHashAlgorithm.SHA512]),
        ("secp521r1", [EnumHashAlgorithm.SHA256, EnumHashAlgorithm.SHA384]),
        ("rsa2048", [EnumHashAlgorithm.SHA384, EnumHashAlgorithm.SHA512]),
        ("rsa4096", [EnumHashAlgorithm.SHA384, EnumHashAlgorithm.SHA512]),
    ],
)
def test_nxpcrypto_create_signature_algorithm_optional(
    cli_runner: CliRunner,
    data_dir: str,
    tmpdir,
    key_type: str,
    algorithms: list[Optional[EnumHashAlgorithm]],
):
    for algorithm in algorithms:
        run_signature(cli_runner, data_dir, tmpdir, key_type, algorithm)


@pytest.mark.skipif(not IS_OSCCA_SUPPORTED, reason="OSCCA support is not installed")
def test_nxpcrypto_create_signature_algorithm_oscca(cli_runner: CliRunner, data_dir: str, tmpdir):
    input_file = os.path.join(data_dir, "data_to_sign.bin")
    output_file = os.path.join(tmpdir, "signature.bin")
    priv_key, pub_key = get_key_path(data_dir, "sm2")

    cmd = f"signature create -k {priv_key} -i {input_file} -o {output_file} -a sm3"
    run_nxpcrypto(cli_runner, cmd, tmpdir)
    assert os.path.isfile(output_file)

    pub = PublicKey.load(pub_key)
    signature = load_binary(output_file)

    assert pub.verify_signature(signature, load_binary(input_file))


@pytest.mark.skipif(not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed")
@pytest.mark.parametrize(
    "level", PrivateKeyDilithium.SUPPORTED_LEVELS if IS_DILITHIUM_SUPPORTED else []
)  # this would fail on ImportError if not handled when pqc is not installed
def test_nxpcrypto_create_signature_algorithm_dilithium(
    cli_runner: CliRunner, data_dir: str, tmpdir: str, level: int
):
    input_file = os.path.join(data_dir, "data_to_sign.bin")
    output_file = os.path.join(tmpdir, "signature.bin")
    priv_key, pub_key = get_key_path(data_dir, f"dil{level}")

    cmd = f"signature create -k {priv_key} -i {input_file} -o {output_file}"
    run_nxpcrypto(cli_runner, cmd, tmpdir)
    assert os.path.isfile(output_file)

    pub = PublicKey.load(pub_key)

    assert isinstance(pub, PublicKeyDilithium)
    signature = load_binary(output_file)

    assert len(signature) == KEY_INFO[DILITHIUM_LEVEL[level]].signature_size
    assert pub.verify_signature(signature, load_binary(input_file))


@pytest.mark.parametrize("signature_provider", [True, False])
@pytest.mark.parametrize(
    "encoding",
    [SPSDKEncoding.DER, SPSDKEncoding.NXP],
)
@pytest.mark.parametrize(
    "key_type",
    [
        "secp256r1",
        "secp384r1",
        "secp521r1",
        "rsa2048",
        "rsa4096",
        pytest.param(
            "sm2",
            marks=pytest.mark.skipif(
                not IS_OSCCA_SUPPORTED, reason="OSCCA support is not installed"
            ),
        ),
        pytest.param(
            "dil2",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        pytest.param(
            "dil3",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        pytest.param(
            "dil5",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
    ],
)
def test_nxpcrypto_signature_create_signature_encoding(
    cli_runner: CliRunner,
    data_dir: str,
    signature_provider: bool,
    key_type: str,
    encoding: SPSDKEncoding,
    tmpdir: str,
):
    priv_key, _ = get_key_path(data_dir, key_type)

    input_file = os.path.join(data_dir, "data_to_sign.bin")
    output_file = os.path.join(tmpdir, "signature.bin")
    cmd = f"signature create -i {input_file} -o {output_file} -e {encoding.value} "
    cmd += f"-sp type=file;file_path={priv_key}" if signature_provider else f"-k {priv_key}"
    run_nxpcrypto(cli_runner, cmd, tmpdir)
    assert os.path.isfile(output_file)

    signature = load_binary(output_file)
    if "secp" in key_type or "sm2" == key_type:
        assert ECDSASignature.get_encoding(signature) == encoding
    if "rsa" in key_type:
        assert len(signature) == {"rsa2048": 256, "rsa4096": 512}[key_type]
    if "dil" in key_type:
        assert (
            len(signature)
            == KEY_INFO[DILITHIUM_LEVEL[int(key_type.replace("dil", ""))]].signature_size
        )


@patch("spsdk.crypto.keys.getpass", GetPassMock("test1234"))
@pytest.mark.parametrize(
    "key_type",
    ["secp256r1", "secp384r1", "secp521r1", "rsa2048", "rsa4096"],
)
def test_nxpcrypto_create_signature_password(
    cli_runner: CliRunner, data_dir: str, key_type: str, tmpdir: str
):
    password = "test1234"
    priv_key_path = os.path.join(tmpdir, "key.pem")

    cmd = f"key generate -k {key_type} -o {priv_key_path} --password {password}"
    run_nxpcrypto(cli_runner, cmd, tmpdir)
    assert os.path.isfile(priv_key_path)

    input_file = os.path.join(data_dir, "data_to_sign.bin")
    # Password as cmd input
    out = os.path.join(tmpdir, "signature_1.bin")
    cmd = f"signature create -k {priv_key_path} -i {input_file} -o {out} --password {password}"
    run_nxpcrypto(cli_runner, cmd, tmpdir)
    assert os.path.isfile(out)

    # Password as interactive prompt
    out = os.path.join(tmpdir, "signature_2.bin")
    cmd = f"signature create -k {priv_key_path} -i {input_file} -o {out}"
    run_nxpcrypto(cli_runner, cmd, tmpdir)
    assert os.path.isfile(out)


@pytest.mark.parametrize(
    "key_type, regions, signature",
    [
        (
            "rsa2048",
            ["[:10]"],
            "76c3221ffa8f58ed3649ccbc8ce4924649c9142e08256d22d6daa39fdb72207167a44b383fabd3eac52f734db6778f0b49739b1866d2cb652c464526d8585f5ba1e199ca50d0e7c99c1c81aee105d29212a0b9b00f224839ac9d5a1a2819128f49eb6cfe44db5b471e69ff7c2289a9f85609cbc1c687b1c3dd1bf344495f12c27211a3fae7886a96ed9de37bf43522584aa719a3b7128536857449c12f3ddbfd6a7786e2047ce8b9e6446f5ffc3fd18c19278e4667e252758627631698295b50f129ae96255b3d2ae1e3b981a96f7fc7d9298290141b4db2a5fe6fb224ad54109c5d4cc6a39ed8f04fd6af2959b187d344afc186b3b7abc1954fba5c4da0ee0f",
        ),
        (
            "rsa2048",
            ["[-10:]"],
            "41bc090357946fd809e61ce2e32b19e93cb4e5317bd8b4374671ae8e5e9e90e29bb833c5ec574ab13091145fc6147784af7df4210f7acadc0a407b44fb67dcd1b402e7e166d844dfb9afb366f7828c278f006072b021faecf22fed9c0d8deaef092ec63d94d3bef63fba4c909fdc556315b583b728217967db885b5943e3db8298a9b1d7e4ee65cbc6465dd275e1dc2992eb5ec0867aa20d1668fd813e85bcaad17e255910a7a14d8e6bef069922e511eca797ceb998d1e9eb0722b9f12b2e656e10de105aaa1ab031fac69e5dbbab02dd26adb7de8fb1e8a54efafd84c00690920a5135347fb4ff9ce7b86e60469601065cf346431100fd32bd90a3d45aa76f",
        ),
        (
            "rsa2048",
            ["[5:10]", "[-5:]"],
            "3c85fb947e646655cecd6138702801e7ad43b47396ff5fc61080e89ae7eee08512d34382d1ac53f3bcd809f7ca80665863087b2a907a1d06016f27584a332e927d6b98df37ef7a9ea0400bd2dd4a7f9bad0749a61f1ee0f311fc35e55fe06a5ef662ecac88b1c0e312398367b003e403100c491b6454aa5e2eda8026eeaccf8c97f51d450601c231398ebb41af0ef33be690feb06f8130ba2f0dae284fd876466140693891d0acf7752c46aa9677a1d1458cb301ae6d4ccaf1b62c06d9309c791e5a9f8dc394ff73b5f5fd9979dc9b3d801128d8199f64ff26cac3e3635637b540871b41ed2a80002ad2d17441d794b0baf5c3ba28b02c89f3be02f37def3f10",
        ),
    ],
)
def test_nxpcrypto_create_signature_regions_rsa(
    cli_runner: CliRunner,
    data_dir: str,
    key_type: str,
    regions: list[str],
    signature: str,
    tmpdir: str,
):
    priv_key, pub_key = get_key_path(data_dir, key_type)

    input_file = os.path.join(data_dir, "data_to_sign.bin")
    out = os.path.join(tmpdir, "signature.bin")
    cmd = f"signature create -k {priv_key} -i {input_file} -o {out}"
    for region in regions:
        cmd += f" -r {region}"
    run_nxpcrypto(cli_runner, cmd, tmpdir)
    assert os.path.isfile(out)
    gen_signature = load_binary(out)
    assert gen_signature.hex() == signature

    cmd = f"signature verify -k {pub_key} -i {input_file} -s {out}"
    result = run_nxpcrypto(cli_runner, cmd, tmpdir)
    assert SIGNATURE_NOT_MATCHING in result.output

    for region in regions:
        cmd += f" -r {region}"
    result = run_nxpcrypto(cli_runner, cmd, tmpdir)
    assert SIGNATURE_MATCHING in result.output


@pytest.mark.parametrize(
    "regions, exception",
    [
        (["[:33]"], None),
        (["[-33:]"], None),
        (["[33]"], SPSDKIndexError),
        (["[:20]", "[21:25]", "[33]"], SPSDKIndexError),
        (["[:33:1:5]"], SPSDKSyntaxError),
        (["blabla"], SPSDKSyntaxError),
    ],
)
def test_nxpcrypto_create_signature_regions_rsa_invalid(
    cli_runner: CliRunner, data_dir: str, tmpdir: str, regions: list[str], exception
):
    priv_key, _ = get_key_path(data_dir, "secp521r1")
    out = os.path.join(tmpdir, "signature.bin")

    input_file = os.path.join(data_dir, "data_to_sign.bin")
    cmd = f"signature create -k {priv_key} -i {input_file} -o {out}"
    for region in regions:
        cmd += f" -r {region}"
    expected_code = 1 if exception else 0
    result = run_nxpcrypto(cli_runner, cmd, tmpdir, expected_code=expected_code)
    if exception:
        assert type(result.exception) == exception


@pytest.mark.parametrize(
    "encoding",
    [SPSDKEncoding.DER, SPSDKEncoding.NXP],
)
@pytest.mark.parametrize(
    "key_type",
    [
        "secp256r1",
        "secp384r1",
        "secp521r1",
        "rsa2048",
        "rsa4096",
        pytest.param(
            "sm2",
            marks=pytest.mark.skipif(
                not IS_OSCCA_SUPPORTED, reason="OSCCA support is not installed"
            ),
        ),
        pytest.param(
            "dil2",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        pytest.param(
            "dil3",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        pytest.param(
            "dil5",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
    ],
)
def test_nxpcrypto_verify_signature(
    cli_runner: CliRunner, data_dir: str, key_type: str, encoding: SPSDKEncoding, tmpdir: str
):
    priv_key, pub_key = get_key_path(data_dir, key_type)

    input_file = os.path.join(data_dir, "data_to_sign.bin")
    output_file = os.path.join(tmpdir, "signature.bin")
    cmd = f"signature create -k {priv_key} -i {input_file} -o {output_file} -e {encoding.value}"
    run_nxpcrypto(cli_runner, cmd, tmpdir)

    cmd = f"signature verify -k {pub_key} -i {input_file} -s {output_file}"
    result = run_nxpcrypto(cli_runner, cmd, tmpdir)
    assert SIGNATURE_MATCHING in result.output

    input_data = load_binary(input_file)
    input_data += b"0"
    modified_file = os.path.join(tmpdir, "modified_data_to_sign.bin")
    write_file(input_data, modified_file, mode="wb")

    cmd = f"signature verify -k {pub_key} -i {modified_file} -s {output_file}"
    result = run_nxpcrypto(cli_runner, cmd, tmpdir)
    assert SIGNATURE_NOT_MATCHING in result.output


def test_nxpcrypto_digest(cli_runner: CliRunner, data_dir: str, tmpdir: str):
    # Setup test environment
    input_file = os.path.join(data_dir, "data_to_digest.bin")
    output_digest_file = os.path.join(tmpdir, "output_digest.txt")
    content = b"Test data for digest"
    expected_digest = hashlib.sha256(content).hexdigest()
    write_file(expected_digest, output_digest_file)
    ssl_format = f"SHA256(/expected_digest.txt)= {expected_digest}\n"

    # Run digest command with compare from CLI
    cmd = f"digest -i {input_file} -h sha256 -c {expected_digest}"
    result = run_nxpcrypto(cli_runner, cmd, tmpdir)
    assert result.exit_code == 0, "Digest command failed"
    assert expected_digest in result.stdout

    # Run digest command with compare from CLI negative test
    cmd = f"digest -i {input_file} -h sha256 -c {expected_digest}1"
    result = run_nxpcrypto(cli_runner, cmd, tmpdir, expected_code=1)

    # Run digest command with compare from file
    cmd = f"digest -i {input_file} -h sha256 -c {output_digest_file}"
    result = run_nxpcrypto(cli_runner, cmd, tmpdir)
    assert result.exit_code == 0, "Digest command failed"

    write_file(ssl_format, output_digest_file)
    # Run digest command with compare from file SSL format
    cmd = f"digest -i {input_file} -h sha256 -c {output_digest_file}"
    result = run_nxpcrypto(cli_runner, cmd, tmpdir)
    assert result.exit_code == 0, "Digest command failed"


@pytest.mark.parametrize(
    "encoding",
    ["pem"],
)
@pytest.mark.parametrize(
    "pki_type",
    ["ahab", "hab"],
)
@pytest.mark.parametrize(
    "key_type",
    [
        "secp521r1",
        "rsa4096",
    ],
)
def test_nxpcrypto_pki_tree(
    cli_runner: CliRunner, pki_type: str, tmpdir: str, key_type: str, encoding: str
):
    cmd = f"pki-tree {pki_type} -k {key_type} -o {tmpdir}/ahab_tree_{key_type}_{encoding} -e {encoding} -ca"
    result = run_nxpcrypto(cli_runner, cmd, tmpdir)
    assert result.exit_code == 0, "PKI Tree command failed"
    assert os.path.isfile(
        f"{tmpdir}/ahab_tree_{key_type}_{encoding}/crts/CA0_{key_type}_ca_cert.{encoding}"
    )
    assert os.path.isfile(
        f"{tmpdir}/ahab_tree_{key_type}_{encoding}/keys/SRK0_{key_type}_ca_key.{encoding}"
    )


CRC_TEST_VECTORS = [
    (CrcAlg.CRC32, 127766482),
    (CrcAlg.CRC32_MPEG, 992315916),
    (CrcAlg.CRC16_XMODEM, 41226),
]


@pytest.mark.parametrize(
    "alg,ref_crc",
    CRC_TEST_VECTORS,
)
def test_nxpcrypto_crc_calculate(alg, ref_crc):
    data = bytes.fromhex("123ABC")
    crc_obj = from_crc_algorithm(alg)
    crc = crc_obj.calculate(data)
    assert crc == ref_crc


@pytest.mark.parametrize(
    "alg,ref_crc",
    CRC_TEST_VECTORS,
)
def test_nxpcrypto_crc_verify(alg, ref_crc):
    data = bytes.fromhex("123ABC")
    crc_obj = from_crc_algorithm(alg)
    is_matching = crc_obj.verify(data, ref_crc)
    assert is_matching


@pytest.mark.parametrize(
    "alg,exception",
    [
        (CrcAlg.CRC32, None),
        (CrcAlg.CRC32_MPEG, None),
        (CrcAlg.CRC16_XMODEM, None),
        ("crc32-mpeg", None),
        ("invalid", SPSDKKeyError),
    ],
)
def test_nxpcrypto_crc_from_alg(alg, exception):
    if exception:
        with pytest.raises(exception):
            from_crc_algorithm(alg)
    else:
        crc_obj = from_crc_algorithm(alg)
        assert isinstance(crc_obj, Crc)
