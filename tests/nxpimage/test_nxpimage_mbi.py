#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test MBI part of nxpimage app."""
import filecmp
import json
import os
import shutil

import pytest
import yaml

from spsdk.apps import nxpimage
from spsdk.crypto.hash import get_hash
from spsdk.crypto.keys import PrivateKeyEcc, PrivateKeyRsa, PublicKeyEcc
from spsdk.crypto.crc import CrcAlg, from_crc_algorithm
from spsdk.exceptions import SPSDKError
from spsdk.image.keystore import KeyStore
from spsdk.image.mbi.mbi import create_mbi_class, get_mbi_class
from spsdk.image.mbi.mbi_mixin import MasterBootImageManifestCrc, Mbi_MixinHmac, Mbi_MixinIvt
from spsdk.utils.crypto.cert_blocks import CertBlockV21, CertBlockVx
from spsdk.utils.database import DatabaseManager, get_db
from spsdk.utils.misc import Endianness, load_binary, load_configuration, use_working_directory
from tests.cli_runner import CliRunner

mbi_basic_tests = [
    ("mb_ram_crc.yaml", "lpc55s6x"),
    ("mb_ram_crc_s19.yaml", "lpc55s6x"),
    ("mb_ram_crc_hex.yaml", "lpc55s6x"),
    ("mb_xip_crc.yaml", "lpc55s6x"),
    ("mb_xip_crc_tz.yaml", "lpc55s6x"),
    ("mb_xip_crc_tz_no_preset.yaml", "lpc55s6x"),
    ("mb_xip_crc_hwk.yaml", "lpc55s6x"),
    ("mb_xip_crc_hwk_tz.yaml", "lpc55s6x"),
    ("mb_ram_crc.yaml", "lpc55s1x"),
    ("mb_xip_crc_tz.yaml", "lpc55s1x"),
    ("mb_xip_crc_tz_no_preset.yaml", "lpc55s1x"),
    ("mb_xip_crc_hwk.yaml", "lpc55s1x"),
    ("mb_xip_crc_hwk_tz.yaml", "lpc55s1x"),
    ("mb_ram_plain.yaml", "rt5xx"),
    ("mb_ram_crc.yaml", "rt5xx"),
    ("mb_ram_crc_tz.yaml", "rt5xx"),
    ("mb_ram_crc_tz_no_preset.yaml", "rt5xx"),
    ("mb_ram_crc_hwk.yaml", "rt5xx"),
    ("mb_ram_crc_hwk_tz.yaml", "rt5xx"),
    ("mb_xip_crc.yaml", "rt5xx"),
    ("mb_xip_crc_tz.yaml", "rt5xx"),
    ("mb_xip_crc_tz_no_preset.yaml", "rt5xx"),
    ("mb_xip_crc_hwk.yaml", "rt5xx"),
    ("mb_xip_crc_hwk_tz.yaml", "rt5xx"),
    ("mb_xip_plain.yaml", "rt5xx"),
    ("mb_ram_crc.yaml", "lpc55s3x"),
    ("mb_ram_crc_version.yaml", "lpc55s3x"),
    ("mb_xip_crc.yaml", "lpc55s3x"),
    ("mb_ext_xip_crc.yaml", "lpc55s3x"),
    ("mb_ext_xip_crc_s19.yaml", "lpc55s3x"),
    ("mb_ram_crc.yaml", "mcxn9xx"),
    ("mb_xip_crc.yaml", "mcxn9xx"),
    ("mb_xip_crc_nbu.yaml", "kw45xx"),
    ("mb_xip_crc_version.yaml", "kw45xx"),
    ("mb_xip_crc_nbu.yaml", "k32w1xx"),
    ("mb_xip_crc_version.yaml", "k32w1xx"),
    ("mb_xip_plain.yaml", "mc56f818xx"),
    ("mb_xip_plain.yaml", "mcxn9xx"),
    ("mb_xip_plain.yaml", "rt7xx"),
    ("mb_xip_crc.yaml", "rt7xx"),
    ("mb_xip_plain.yaml", "mcxc444"),
    ("mb_xip_plain_bca.yaml", "mcxc444"),
]

mbi_signed_tests = [
    ("mb_xip_256_none.yaml", "lpc55s3x", None),
    ("mb_xip_256_none_no_tz.yaml", "lpc55s3x", None),
    ("mb_xip_384_256.yaml", "lpc55s3x", None),
    ("mb_xip_384_384.yaml", "lpc55s3x", None),
    ("mb_xip_384_384_sd.yaml", "kw45xx", "sha384"),
    ("mb_xip_384_384_auto_digest.yaml", "kw45xx", "sha384"),
    ("mb_ext_xip_signed.yaml", "lpc55s3x", None),
    ("mb_xip_256_none.yaml", "mcxn9xx", None),
    ("mb_xip_256_none_no_tz.yaml", "mcxn9xx", None),
    ("mb_xip_384_256.yaml", "mcxn9xx", None),
    ("mb_xip_384_384.yaml", "mcxn9xx", None),
    ("mb_xip_384_384_recovery_crctest.yaml", "mcxn9xx", None),
    ("mb_xip_384_384_recovery.yaml", "mcxn9xx", None),
    ("mb_xip_256_none_no_tz.yaml", "rt7xx", None),
]

mbi_legacy_signed_tests = [
    ("mb_xip_signed.yaml", "lpc55s6x", 0),
    ("mb_xip_signed.yaml", "lpc55s1x", 0),
    ("mb_xip_signed_chain.yaml", "lpc55s6x", 0),
    ("mb_xip_signed_no_ks.yaml", "rt5xx", 0),
    ("mb_ram_signed_no_ks.yaml", "rt5xx", 1),
    ("mb_ram_signed_ks.yaml", "rt5xx", 2),
]

mbi_legacy_encrypted_tests = [
    ("mb_ram_encrypted_ks.yaml", "rt5xx", 2),
    ("mb_ram_encrypted_ks_binkey.yaml", "rt5xx", 2),
]


def process_config_file(config_path: str, destination: str):
    config_path.replace("\\", "/")
    config_data = load_configuration(config_path)
    for key in config_data:
        if isinstance(config_data[key], str):
            config_data[key] = config_data[key].replace("\\", "/")
    ref_binary = config_data.get("masterBootOutputFile") or config_data.get("containerOutputFile")
    new_binary = f"{destination}/{os.path.basename(ref_binary)}"
    new_config = f"{destination}/{os.path.basename(config_path)}"
    config_data["masterBootOutputFile"] = new_binary
    # It doesn't matter that there will be both keys in this temporary config
    config_data["containerOutputFile"] = new_binary
    with open(new_config, "w") as f:
        json.dump(config_data, f, indent=2)
    return ref_binary, new_binary, new_config


def get_main_root_key(config_file) -> PrivateKeyEcc:
    config_data = load_configuration(config_file)
    private_key_file = config_data.get(
        "signPrivateKey", config_data.get("mainRootCertPrivateKeyFile")
    )
    return PrivateKeyEcc.load(private_key_file.replace("\\", "/"))


def get_signing_key(config_file) -> PrivateKeyEcc:
    config_data = load_configuration(config_file)
    private_key_file = config_data.get(
        "signPrivateKey",
        config_data.get(
            "mainRootCertPrivateKeyFile",
            config_data.get("signingCertificatePrivateKeyFile"),
        ),
    )
    if not private_key_file:
        private_key_file = config_data.get("signProvider").split("=")[2]
    return PrivateKeyEcc.load(private_key_file.replace("\\", "/"))


def get_isk_key(config_file) -> PrivateKeyEcc:
    config_data = load_configuration(config_file)
    private_key_file = config_data.get(
        "signPrivateKey", config_data.get("mainRootCertPrivateKeyFile")
    )
    if not private_key_file:
        private_key_file = config_data.get("signProvider").split("=")[2]
    return PrivateKeyEcc.load(private_key_file.replace("\\", "/"))


@pytest.mark.parametrize("config_file,family", mbi_basic_tests)
def test_nxpimage_mbi_basic(cli_runner: CliRunner, nxpimage_data_dir, tmpdir, config_file, family):
    with use_working_directory(nxpimage_data_dir):
        config_file = f"{nxpimage_data_dir}/workspace/cfgs/{family}/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir)

        cmd = f"mbi export -c {new_config}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(new_binary)
        assert filecmp.cmp(new_binary, ref_binary)


@pytest.mark.parametrize("config_file,family", mbi_basic_tests)
def test_mbi_parser_basic(cli_runner: CliRunner, tmpdir, nxpimage_data_dir, family, config_file):
    # Create new MBI file
    mbi_data_dir = os.path.join(nxpimage_data_dir, "workspace")
    config_file = os.path.join(mbi_data_dir, "cfgs", family, config_file)

    ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir)

    cmd = f"mbi export -c {new_config}"
    with use_working_directory(nxpimage_data_dir):
        cli_runner.invoke(nxpimage.main, cmd.split())

    cmd = f"mbi parse -b {new_binary} -f {family} -o {tmpdir}/parsed"
    cli_runner.invoke(nxpimage.main, cmd.split())

    sub_path: str = load_configuration(config_file)["inputImageFile"]
    input_image = os.path.normpath(os.path.join(nxpimage_data_dir, sub_path.replace("\\", "/")))
    parsed_app = os.path.join(tmpdir, "parsed", "application.bin")
    assert os.path.isfile(parsed_app)
    if os.path.splitext(input_image)[1] == ".bin":
        assert filecmp.cmp(input_image, parsed_app)


@pytest.mark.parametrize("config_file,device,sign_digest", mbi_signed_tests)
def test_nxpimage_mbi_signed(
    cli_runner: CliRunner, nxpimage_data_dir, tmpdir, config_file, device, sign_digest
):
    with use_working_directory(nxpimage_data_dir):
        config_file = f"{nxpimage_data_dir}/workspace/cfgs/{device}/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir)

        cmd = f"mbi export -c {new_config}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(new_binary)

        # validate file lengths
        ref_data = load_binary(ref_binary)
        new_data = load_binary(new_binary)
        assert len(ref_data) == len(new_data)

        # validate signatures
        signing_key = get_signing_key(config_file=config_file)
        signature_length = signing_key.signature_size
        mbi_cls = get_mbi_class(load_configuration(new_config))
        parsed_mbi = mbi_cls.parse(family=device, data=new_data)
        assert hasattr(parsed_mbi, "cert_block")
        cert_block_v2: CertBlockV21 = parsed_mbi.cert_block
        cert_offset = Mbi_MixinIvt.get_cert_block_offset(new_data)

        if sign_digest:
            sign_offset = 32 if sign_digest and sign_digest == "sha256" else 48
            assert signing_key.get_public_key().verify_signature(
                new_data[-(signature_length + sign_offset) : -sign_offset],
                new_data[: -(signature_length + sign_offset)],
            )
            assert signing_key.get_public_key().verify_signature(
                ref_data[-(signature_length + sign_offset) : -sign_offset],
                ref_data[: -(signature_length + sign_offset)],
            )
            ref_data = ref_data[:-sign_offset]
            new_data = new_data[:-sign_offset]

        assert signing_key.get_public_key().verify_signature(
            ref_data[-signature_length:], ref_data[:-signature_length]
        )
        assert signing_key.get_public_key().verify_signature(
            new_data[-signature_length:], new_data[:-signature_length]
        )
        ref_data = ref_data[:-signature_length]
        new_data = new_data[:-signature_length]

        if hasattr(parsed_mbi, "manifest") and isinstance(
            parsed_mbi.manifest, MasterBootImageManifestCrc
        ):
            crc_ob = from_crc_algorithm(CrcAlg.CRC32_MPEG)
            # Check CRC
            assert (
                crc_ob.calculate(ref_data[:-4]).to_bytes(4, Endianness.LITTLE.value)
                == ref_data[-4:]
            )
            assert (
                crc_ob.calculate(new_data[:-4]).to_bytes(4, Endianness.LITTLE.value)
                == new_data[-4:]
            )
            # Remove CRC
            ref_data = ref_data[:-4]
            new_data = new_data[:-4]

        # And check the data part
        if cert_block_v2.isk_certificate:
            isk_sign_offset = (
                cert_offset
                + cert_block_v2.expected_size
                - cert_block_v2.isk_certificate.expected_size
                + cert_block_v2.isk_certificate.signature_offset
            )
            isk_end_of_signature = isk_sign_offset + len(cert_block_v2.isk_certificate.signature)
            assert ref_data[:isk_sign_offset] == new_data[:isk_sign_offset]
            assert ref_data[isk_end_of_signature:] == new_data[isk_end_of_signature:]

            # Validate ISK signature

            # with binary cert block with don't have access to root private key
            # reconstruct the root public key from cert block
            isk_key = PublicKeyEcc.recreate_from_data(cert_block_v2.root_key_record.root_public_key)
            isk_offset = (
                cert_offset
                + cert_block_v2.expected_size
                - cert_block_v2.isk_certificate.expected_size
            )
            assert isk_key.verify_signature(
                cert_block_v2.isk_certificate.signature,
                new_data[
                    cert_offset + 12 : isk_offset + cert_block_v2.isk_certificate.signature_offset
                ],
            )

        else:
            # validate data before signature
            assert ref_data[:-signature_length] == new_data[:-signature_length]


@pytest.mark.parametrize(
    "config_file,device,added_hash",
    [
        ("mb_xip.yaml", "mc56f818xx", True),
        ("mb_xip_bin_cert.yaml", "mc56f818xx", True),
        ("mb_xip_no_hash.yaml", "mc56f818xx", False),
        ("mb_xip_oem_closed.yaml", "mc56f818xx", True),
    ],
)
def test_nxpimage_mbi_signed_vx(
    cli_runner: CliRunner, nxpimage_data_dir, tmpdir, config_file, device, added_hash
):
    with use_working_directory(nxpimage_data_dir):
        config_file = f"{nxpimage_data_dir}/workspace/cfgs/{device}/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir)

        cmd = f"mbi export -c {new_config}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(new_binary)

        # validate file lengths
        ref_data = load_binary(ref_binary)
        new_data = load_binary(new_binary)
        assert len(ref_data) == len(new_data)

        # validate signatures
        signing_key = get_main_root_key(config_file=config_file)
        signature_length = signing_key.signature_size
        mbi_cls = get_mbi_class(load_configuration(new_config))
        parsed_mbi = mbi_cls.parse(family="mc56f818xx", data=new_data)
        assert hasattr(parsed_mbi, "cert_block")
        cert_block: CertBlockVx = parsed_mbi.cert_block

        SIGN_DIGEST_OFFSET = 0x360
        SIGN_DIGEST_LENGTH = 32
        BCA_OFFSET = 0x3C0
        APP_OFFSET = 0x0C00
        SIGN_OFFSET = 0x380
        IMG_FCB_OFFSET = 0x400
        IMG_FCB_SIZE = 16
        IMG_ISK_OFFSET = IMG_FCB_OFFSET + IMG_FCB_SIZE
        IMG_ISK_CERT_HASH_OFFSET = 0x04A0

        assert signing_key.get_public_key().verify_signature(
            ref_data[SIGN_OFFSET : (SIGN_OFFSET + signature_length)],
            ref_data[SIGN_DIGEST_OFFSET : (SIGN_DIGEST_OFFSET + SIGN_DIGEST_LENGTH)],
            prehashed=True,
        )
        assert signing_key.get_public_key().verify_signature(
            new_data[SIGN_OFFSET : (SIGN_OFFSET + signature_length)],
            new_data[SIGN_DIGEST_OFFSET : (SIGN_DIGEST_OFFSET + SIGN_DIGEST_LENGTH)],
            prehashed=True,
        )

        # Validate ISK signature
        isk_key = get_isk_key(config_file=config_file)

        assert isk_key.get_public_key().verify_signature(
            cert_block.isk_certificate.signature,
            new_data[IMG_ISK_OFFSET : IMG_ISK_OFFSET + cert_block.isk_certificate.SIGNATURE_OFFSET],
        )

        isk_hash = get_hash(
            new_data[
                IMG_ISK_OFFSET : IMG_ISK_OFFSET + cert_block.isk_certificate.SIGNATURE_OFFSET + 64
            ]
        )

        if added_hash:
            assert (
                isk_hash[:16] == new_data[IMG_ISK_CERT_HASH_OFFSET : IMG_ISK_CERT_HASH_OFFSET + 16]
            )

        assert new_data[:SIGN_OFFSET] == ref_data[:SIGN_OFFSET]
        assert (
            new_data[BCA_OFFSET : IMG_FCB_OFFSET + IMG_FCB_SIZE]
            == ref_data[BCA_OFFSET : IMG_FCB_OFFSET + IMG_FCB_SIZE]
        )
        assert new_data[APP_OFFSET:] == ref_data[APP_OFFSET:]


@pytest.mark.parametrize(
    "config_file,device",
    [
        ("mb_xip_crc.yaml", "mc56f817xx"),
    ],
)
def test_nxpimage_mbi_crc_vx(
    cli_runner: CliRunner,
    nxpimage_data_dir,
    tmpdir,
    config_file,
    device,
):
    with use_working_directory(nxpimage_data_dir):
        config_file = f"{nxpimage_data_dir}/workspace/cfgs/{device}/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir)

        cmd = f"mbi export -c {new_config}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(new_binary)

        ref_data = load_binary(ref_binary)
        new_data = load_binary(new_binary)
        assert ref_data == new_data

        cmd = f"mbi parse -b {new_binary} -f {device} -o {tmpdir}/parsed"
        cli_runner.invoke(nxpimage.main, cmd.split())


@pytest.mark.parametrize("config_file,family,sign_digest", mbi_signed_tests)
def test_mbi_parser_signed(
    cli_runner: CliRunner, tmpdir, nxpimage_data_dir, family, config_file, sign_digest
):
    # Create new MBI file
    mbi_data_dir = os.path.join(nxpimage_data_dir, "workspace")
    config_file = os.path.join(mbi_data_dir, "cfgs", family, config_file)

    ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir)

    cmd = f"mbi export -c {new_config}"
    with use_working_directory(nxpimage_data_dir):
        cli_runner.invoke(nxpimage.main, cmd.split())

    cmd = f"mbi parse -b {new_binary} -f {family} -o {tmpdir}/parsed"
    cli_runner.invoke(nxpimage.main, cmd.split())

    input_image = os.path.join(nxpimage_data_dir, load_configuration(config_file)["inputImageFile"])
    parsed_app = os.path.join(tmpdir, "parsed", "application.bin")
    assert os.path.isfile(parsed_app)
    if os.path.split(input_image)[1] == "bin":
        assert filecmp.cmp(input_image, parsed_app)


@pytest.mark.parametrize("config_file,family,sign_digest", mbi_signed_tests)
def test_mbi_parser_signed(
    cli_runner: CliRunner, tmpdir, nxpimage_data_dir, family, config_file, sign_digest
):
    # Create new MBI file
    mbi_data_dir = os.path.join(nxpimage_data_dir, "workspace")
    config_file = os.path.join(mbi_data_dir, "cfgs", family, config_file)

    ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir)

    cmd = f"mbi export -c {new_config}"
    with use_working_directory(nxpimage_data_dir):
        cli_runner.invoke(nxpimage.main, cmd.split())

    cmd = f"mbi parse -b {new_binary} -f {family} -o {tmpdir}/parsed"
    cli_runner.invoke(nxpimage.main, cmd.split())

    input_image = os.path.join(nxpimage_data_dir, load_configuration(config_file)["inputImageFile"])
    parsed_app = os.path.join(tmpdir, "parsed", "application.bin")
    assert os.path.isfile(parsed_app)
    if os.path.split(input_image)[1] == "bin":
        assert filecmp.cmp(input_image, parsed_app)


@pytest.mark.parametrize(
    "mbi_config_file,cert_block_config_file,device",
    [
        ("mb_xip_384_256_cert.yaml", "cert_384_256.yaml", "lpc55s3x"),
        ("mb_xip_384_384_cert.yaml", "cert_384_384.yaml", "lpc55s3x"),
    ],
)
def test_nxpimage_mbi_cert_block_signed(
    cli_runner: CliRunner,
    nxpimage_data_dir,
    tmpdir,
    mbi_config_file,
    cert_block_config_file,
    device,
):
    with use_working_directory(nxpimage_data_dir):
        cert_config_file = f"{nxpimage_data_dir}/workspace/cfgs/cert_block/{cert_block_config_file}"
        mbi_config_file = f"{nxpimage_data_dir}/workspace/cfgs/{device}/{mbi_config_file}"
        mbi_ref_binary, mbi_new_binary, mbi_new_config = process_config_file(
            mbi_config_file, tmpdir
        )
        cert_ref_binary, cert_new_binary, cert_new_config = process_config_file(
            cert_config_file, tmpdir
        )

        cmd = f"cert-block export -f {device} -c {cert_new_config}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(cert_new_binary)

        # validate cert file file lengths
        cert_ref_data = load_binary(cert_ref_binary)
        cert_new_data = load_binary(cert_new_binary)
        assert len(cert_ref_data) == len(cert_new_data)
        isk_key = get_isk_key(cert_new_config)
        length_to_compare = len(cert_new_data) - isk_key.signature_size

        assert cert_ref_data[:length_to_compare] == cert_new_data[:length_to_compare]

        cmd = f"mbi export -c {mbi_new_config}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(mbi_new_binary)

        # validate file lengths
        mbi_ref_data = load_binary(mbi_ref_binary)
        mbi_new_data = load_binary(mbi_new_binary)
        assert len(mbi_ref_data) == len(mbi_new_data)

        # validate signatures

        signing_key = get_signing_key(config_file=mbi_config_file)
        signature_length = signing_key.signature_size

        assert signing_key.get_public_key().verify_signature(
            mbi_new_data[-signature_length:], mbi_new_data[:-signature_length]
        )
        assert signing_key.get_public_key().verify_signature(
            mbi_ref_data[-signature_length:], mbi_ref_data[:-signature_length]
        )


@pytest.mark.parametrize(
    "mbi_config_file,cert_block_config_file,device",
    [
        ("mb_xip_384_256_cert_invalid.json", "cert_384_256.yaml", "lpc55s3x"),
    ],
)
def test_nxpimage_mbi_cert_block_signed_invalid(
    cli_runner: CliRunner,
    nxpimage_data_dir,
    tmpdir,
    mbi_config_file,
    cert_block_config_file,
    device,
):
    with use_working_directory(nxpimage_data_dir):
        cert_config_file = f"{nxpimage_data_dir}/workspace/cfgs/cert_block/{cert_block_config_file}"
        mbi_config_file = f"{nxpimage_data_dir}/workspace/cfgs/{device}/{mbi_config_file}"
        mbi_ref_binary, mbi_new_binary, mbi_new_config = process_config_file(
            mbi_config_file, tmpdir
        )
        cert_ref_binary, cert_new_binary, cert_new_config = process_config_file(
            cert_config_file, tmpdir
        )

        cmd = f"cert-block export -f {device} -c {cert_new_config}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(cert_new_binary)

        # validate cert file file lengths
        cert_ref_data = load_binary(cert_ref_binary)
        cert_new_data = load_binary(cert_new_binary)
        assert len(cert_ref_data) == len(cert_new_data)
        isk_key = get_isk_key(cert_new_config)
        length_to_compare = len(cert_new_data) - isk_key.signature_size

        assert cert_ref_data[:length_to_compare] == cert_new_data[:length_to_compare]

        cmd = f"mbi export -c {mbi_new_config}"
        cli_runner.invoke(nxpimage.main, cmd.split(), expected_code=-1)


# skip_hmac_keystore
# 0 indicates no hmac and no keystore present in output image
# 1 indicates hmac present but no keystore
# 2 indicates both hmac/keystore present in output image
@pytest.mark.parametrize("config_file,device,skip_hmac_keystore", mbi_legacy_signed_tests)
def test_nxpimage_mbi_legacy_signed(
    cli_runner: CliRunner, nxpimage_data_dir, tmpdir, config_file, device, skip_hmac_keystore
):
    with use_working_directory(nxpimage_data_dir):
        config_file = f"{nxpimage_data_dir}/workspace/cfgs/{device}/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir)

        cmd = f"mbi export -c {new_config}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(new_binary)

        # validate file lengths
        with open(ref_binary, "rb") as f:
            ref_data = f.read()
        with open(new_binary, "rb") as f:
            new_data = f.read()
        assert len(ref_data) == len(new_data)

        # validate signatures
        with open(new_config, "r") as f:
            config_data = json.load(f)

        signing_certificate_file_path = config_data.get(
            "signPrivateKey", config_data.get("mainRootCertPrivateKeyFile")
        )
        signing_key = PrivateKeyRsa.load(signing_certificate_file_path)
        signature_length = signing_key.signature_size
        hmac_start = 0
        hmac_end = 0
        # skip_hmac_keystore
        # 0 no hmac/keystore
        # 1 hmac present
        # 2 hmac & keystore present
        if skip_hmac_keystore:
            hmac_start = Mbi_MixinHmac.HMAC_OFFSET
            gap_len = Mbi_MixinHmac.HMAC_SIZE
            gap_len += KeyStore.KEY_STORE_SIZE if skip_hmac_keystore == 2 else 0
            hmac_end = hmac_start + gap_len

        assert signing_key.get_public_key().verify_signature(
            new_data[-signature_length:],
            new_data[:hmac_start] + new_data[hmac_end:-signature_length],
        )
        assert signing_key.get_public_key().verify_signature(
            ref_data[-signature_length:],
            ref_data[:hmac_start] + ref_data[hmac_end:-signature_length],
        )

        # validate data before signature
        assert ref_data[:-signature_length] == new_data[:-signature_length]


@pytest.mark.parametrize("config_file,family,skip_hmac_keystore", mbi_legacy_signed_tests)
def test_mbi_parser_legacy_signed(
    cli_runner: CliRunner, tmpdir, nxpimage_data_dir, family, config_file, skip_hmac_keystore
):
    # Create new MBI file
    mbi_data_dir = os.path.join(nxpimage_data_dir, "workspace")
    config_file = os.path.join(mbi_data_dir, "cfgs", family, config_file)

    ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir)

    cmd = f"mbi export -c {new_config}"
    with use_working_directory(nxpimage_data_dir):
        cli_runner.invoke(nxpimage.main, cmd.split())

    cmd = f"mbi parse -b {new_binary} -f {family} -o {tmpdir}/parsed"
    cli_runner.invoke(nxpimage.main, cmd.split())

    input_image = os.path.join(nxpimage_data_dir, load_configuration(config_file)["inputImageFile"])
    parsed_app = os.path.join(tmpdir, "parsed", "application.bin")
    assert os.path.isfile(parsed_app)
    if os.path.split(input_image)[1] == "bin":
        assert filecmp.cmp(input_image, parsed_app)


@pytest.mark.parametrize(
    "config_file,device",
    [
        ("mb_xip_signed_cert_gap.yaml", "lpc55s6x"),
    ],
)
def test_nxpimage_mbi_invalid_conf(
    cli_runner: CliRunner, nxpimage_data_dir, tmpdir, config_file, device
):
    with use_working_directory(nxpimage_data_dir):
        config_file = f"{nxpimage_data_dir}/workspace/cfgs/{device}/{config_file}"
        _, _, new_config = process_config_file(config_file, tmpdir)

        cmd = f"mbi export -c {new_config}"
        cli_runner.invoke(nxpimage.main, cmd.split(), expected_code=1)


@pytest.mark.parametrize("config_file,device,skip_hmac_keystore", mbi_legacy_encrypted_tests)
def test_nxpimage_mbi_legacy_encrypted(
    cli_runner: CliRunner, nxpimage_data_dir, tmpdir, config_file, device, skip_hmac_keystore
):
    with use_working_directory(nxpimage_data_dir):
        config_file = f"{nxpimage_data_dir}/workspace/cfgs/{device}/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir)

        cmd = f"mbi export -c {new_config}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(new_binary)

        # validate file lengths
        with open(ref_binary, "rb") as f:
            ref_data = f.read()
        with open(new_binary, "rb") as f:
            new_data = f.read()
        assert len(ref_data) == len(new_data)

        # validate signatures
        with open(new_config, "r") as f:
            config_data = json.load(f)

        signing_certificate_file_path = config_data.get(
            "signPrivateKey", config_data.get("mainRootCertPrivateKeyFile")
        )
        signing_key = PrivateKeyRsa.load(signing_certificate_file_path)

        signature_length = signing_key.signature_size
        hmac_start = 0
        hmac_end = 0
        # skip_hmac_keystore
        # 0 no hmac/keystore
        # 1 hmac present
        # 2 hmac & keystore present
        if skip_hmac_keystore:
            hmac_start = Mbi_MixinHmac.HMAC_OFFSET
            gap_len = Mbi_MixinHmac.HMAC_SIZE
            gap_len += KeyStore.KEY_STORE_SIZE if skip_hmac_keystore == 2 else 0
            hmac_end = hmac_start + gap_len

        assert signing_key.get_public_key().verify_signature(
            new_data[-signature_length:],
            new_data[:hmac_start] + new_data[hmac_end:-signature_length],
        )
        assert signing_key.get_public_key().verify_signature(
            ref_data[-signature_length:],
            ref_data[:hmac_start] + ref_data[hmac_end:-signature_length],
        )

        # validate data before signature
        assert ref_data[:-signature_length] == new_data[:-signature_length]


@pytest.mark.parametrize("config_file,family,skip_hmac_keystore", mbi_legacy_encrypted_tests)
def test_mbi_parser_legacy_encrypted(
    cli_runner: CliRunner, tmpdir, nxpimage_data_dir, family, config_file, skip_hmac_keystore
):
    # Create new MBI file
    mbi_data_dir = os.path.join(nxpimage_data_dir, "workspace")
    config_file = os.path.join(mbi_data_dir, "cfgs", family, config_file)

    ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir)

    cmd = ["mbi", "export", "-c", new_config]
    with use_working_directory(nxpimage_data_dir):
        cli_runner.invoke(nxpimage.main, cmd)

    cmd = [
        "mbi",
        "parse",
        "-b",
        new_binary,
        "-f",
        family,
        "-k",
        f"{mbi_data_dir}/keys/userkey.txt",
        "-o",
        f"{tmpdir}/parsed",
    ]
    cli_runner.invoke(nxpimage.main, cmd)

    input_image = os.path.join(nxpimage_data_dir, load_configuration(config_file)["inputImageFile"])
    parsed_app = os.path.join(tmpdir, "parsed", "application.bin")
    assert os.path.isfile(parsed_app)
    if os.path.split(input_image)[1] == "bin":
        assert filecmp.cmp(input_image, parsed_app)


def test_mbi_lpc55s3x_invalid():
    mbi = create_mbi_class("signed_xip", "lpc55s3x")(app=bytes(100), firmware_version=0)
    with pytest.raises(SPSDKError):
        mbi.validate()


@pytest.mark.parametrize(
    "family",
    [
        "lpc55s06",
        "lpc5506",
        "lpc55s16",
        "lpc5516",
        "lpc55s26",
        "lpc5528",
        "lpc55s69",
        "nhs52s04",
        "mimxrt595s",
        "mimxrt685s",
        "lpc55s36",
        "kw45b41z8",
        "k32w148",
        "lpc5536",
        "mc56f81868",
        "mwct20d2",
        "mcxn947",
        "rw612",
    ],
)
def test_mbi_get_templates(cli_runner: CliRunner, tmpdir, family):
    cmd = f"mbi get-templates -f {family} --output {tmpdir}"
    result = cli_runner.invoke(nxpimage.main, cmd.split())
    assert result.exit_code == 0
    images = get_db(family).get_dict(DatabaseManager.MBI, "images")

    for image in images:
        for config in images[image]:
            file_path = os.path.join(tmpdir, f"{family}_{image}_{config}.yaml")
            assert os.path.isfile(file_path)


@pytest.mark.parametrize(
    "family, template_name, keys_to_copy",
    [
        (
            "lpc55s3x",
            "ext_xip_signed_lpc55s3x.yaml",
            ["ec_pk_secp256r1_cert0.pem", "ec_secp256r1_cert0.pem"],
        ),
        (
            "rt5xx",
            "ext_xip_signed_rtxxxx.yaml",
            ["k0_cert0_2048.pem", "root_k0_signed_cert0_noca.der.cert"],
        ),
        (
            "rt6xx",
            "ext_xip_signed_rtxxxx.yaml",
            ["k0_cert0_2048.pem", "root_k0_signed_cert0_noca.der.cert"],
        ),
        (
            "lpc55s2x",
            "int_xip_signed_xip.yaml",
            ["k0_cert0_2048.pem", "root_k0_signed_cert0_noca.der.cert"],
        ),
        (
            "nhs52sxx",
            "int_xip_signed_xip.yaml",
            ["k0_cert0_2048.pem", "root_k0_signed_cert0_noca.der.cert"],
        ),
        (
            "kw45xx",
            "int_xip_signed_kw45xx.yaml",
            ["ec_pk_secp256r1_cert0.pem", "ec_secp256r1_cert0.pem"],
        ),
        (
            "k32w1xx",
            "int_xip_signed_kw45xx.yaml",
            ["ec_pk_secp256r1_cert0.pem", "ec_secp256r1_cert0.pem"],
        ),
        (
            "mc56f818xx",
            "mc56f818xx_int_xip_signed.yaml",
            ["ec_pk_secp256r1_cert0.pem", "ec_secp256r1_cert0.pem"],
        ),
        (
            "mc56f818xx",
            "mc56f818xx_int_xip_signed_header.yaml",
            ["ec_pk_secp256r1_cert0.pem", "ec_secp256r1_cert0.pem"],
        ),
    ],
)
def test_mbi_export_sign_provider(
    cli_runner: CliRunner, tmpdir, data_dir, family, template_name, keys_to_copy
):
    mbi_data_dir = os.path.join(data_dir, "mbi")
    config_path = os.path.join(mbi_data_dir, template_name)
    config = load_configuration(config_path)
    config["family"] = family

    for key_file_name in keys_to_copy:
        key_file_path = os.path.join(mbi_data_dir, "keys_and_certs", key_file_name)
        shutil.copyfile(key_file_path, os.path.join(tmpdir, key_file_name))
    test_app_path = os.path.join(mbi_data_dir, config["inputImageFile"])
    shutil.copyfile(test_app_path, os.path.join(tmpdir, config["inputImageFile"]))
    cert_block = os.path.join(mbi_data_dir, config["certBlock"])
    shutil.copyfile(cert_block, os.path.join(tmpdir, config["certBlock"]))
    tmp_config = os.path.join(tmpdir, "config.yaml")
    with open(tmp_config, "w") as file:
        yaml.dump(config, file)

    cmd = f"mbi export -c {tmp_config}"
    cli_runner.invoke(nxpimage.main, cmd.split())
    file_path = os.path.join(tmpdir, config["masterBootOutputFile"])
    assert os.path.isfile(file_path)


@pytest.mark.parametrize(
    "family, template_name, keys_to_copy",
    [
        (
            "lpc55s3x",
            "ext_xip_signed_lpc55s3x_invalid.yaml",
            ["ec_pk_secp256r1_cert0.pem", "ec_secp256r1_cert0.pem"],
        ),
        (
            "lpc553x",
            "ext_xip_signed_lpc55s3x_invalid.yaml",
            ["ec_pk_secp256r1_cert0.pem", "ec_secp256r1_cert0.pem"],
        ),
        (
            "rt5xx",
            "ext_xip_signed_rtxxxx_invalid.yaml",
            ["k0_cert0_2048.pem", "root_k0_signed_cert0_noca.der.cert"],
        ),
        (
            "rt6xx",
            "ext_xip_signed_rtxxxx_invalid.yaml",
            ["k0_cert0_2048.pem", "root_k0_signed_cert0_noca.der.cert"],
        ),
        (
            "lpc550x",
            "int_xip_signed_xip_invalid.yaml",
            ["k0_cert0_2048.pem", "root_k0_signed_cert0_noca.der.cert"],
        ),
        (
            "lpc551x",
            "int_xip_signed_xip_invalid.yaml",
            ["k0_cert0_2048.pem", "root_k0_signed_cert0_noca.der.cert"],
        ),
        (
            "lpc55s2x",
            "int_xip_signed_xip_invalid.yaml",
            ["k0_cert0_2048.pem", "root_k0_signed_cert0_noca.der.cert"],
        ),
        (
            "nhs52sxx",
            "int_xip_signed_xip_invalid.yaml",
            ["k0_cert0_2048.pem", "root_k0_signed_cert0_noca.der.cert"],
        ),
        (
            "kw45xx",
            "int_xip_signed_kw45xx_invalid.yaml",
            ["ec_pk_secp256r1_cert0.pem", "ec_secp256r1_cert0.pem"],
        ),
        (
            "k32w1xx",
            "int_xip_signed_kw45xx_invalid.yaml",
            ["ec_pk_secp256r1_cert0.pem", "ec_secp256r1_cert0.pem"],
        ),
    ],
)
def test_mbi_export_sign_provider_invalid_configuration(
    cli_runner: CliRunner, tmpdir, data_dir, family, template_name, keys_to_copy
):
    mbi_data_dir = os.path.join(data_dir, "mbi")
    config_path = os.path.join(mbi_data_dir, template_name)
    config = load_configuration(config_path)
    config["family"] = family

    for key_file_name in keys_to_copy:
        key_file_path = os.path.join(mbi_data_dir, "keys_and_certs", key_file_name)
        shutil.copyfile(key_file_path, os.path.join(tmpdir, key_file_name))
    test_app_path = os.path.join(mbi_data_dir, config["inputImageFile"])
    shutil.copyfile(test_app_path, os.path.join(tmpdir, config["inputImageFile"]))
    cert_block = os.path.join(mbi_data_dir, config["certBlock"])
    shutil.copyfile(cert_block, os.path.join(tmpdir, config["certBlock"]))
    tmp_config = os.path.join(tmpdir, "config.yaml")
    with open(tmp_config, "w") as file:
        yaml.dump(config, file)

    cmd = f"mbi export -c {tmp_config}"
    cli_runner.invoke(nxpimage.main, cmd.split(), expected_code=-1)


@pytest.mark.parametrize(
    "plugin,main_root_cert_id,sign_provider,exit_code",
    [
        (None, 0, "type=file;file_path=k0_cert0_2048.pem", 0),
        (None, None, "type=file;file_path=k0_cert0_2048.pem", 0),
        ("file_no_verify.py", 0, "type=file_no_verify;file_path=k0_cert0_2048.pem", 0),
        ("file_no_verify.py", None, "type=file_no_verify;file_path=k0_cert0_2048.pem", 1),
        (None, None, "type=file;file_path=k2_cert0_2048.pem", 1),
        (None, 0, "type=file;file_path=k2_cert0_2048.pem", 1),
    ],
)
def test_mbi_signature_provider(
    cli_runner: CliRunner, data_dir, tmpdir, plugin, main_root_cert_id, sign_provider, exit_code
):
    # Copy all required files
    keys_to_copy = [
        "root_k0_signed_cert0_noca.der.cert",
        "root_k1_signed_cert0_noca.der.cert",
        "k0_cert0_2048.pem",
        "k1_cert0_2048.pem",
        "k2_cert0_2048.pem",
    ]
    shutil.copyfile(
        os.path.join(data_dir, "mbi", "test_application.bin"),
        os.path.join(tmpdir, "test_application.bin"),
    )
    for key in keys_to_copy:
        shutil.copyfile(
            os.path.join(data_dir, "mbi", "keys_and_certs", key), os.path.join(tmpdir, key)
        )
    # Prepare configuration
    config_data = load_configuration(os.path.join(data_dir, "mbi", "ext_xip_signed_rt5xx.yaml"))
    if sign_provider:
        config_data["signProvider"] = sign_provider
    config_file = os.path.join(tmpdir, "ext_xip_signed_rt5xx.yaml")
    with open(config_file, "w") as fp:
        yaml.dump(config_data, fp)

    cert_config_data = load_configuration(os.path.join(data_dir, "mbi", config_data["certBlock"]))
    if sign_provider:
        cert_config_data["signProvider"] = sign_provider
    if main_root_cert_id is not None:
        cert_config_data["mainRootCertId"] = main_root_cert_id
    cert_config_file = os.path.join(tmpdir, config_data["certBlock"])
    with open(cert_config_file, "w") as fp:
        yaml.dump(cert_config_data, fp)
    cmd = f"mbi export -c {config_file}"
    if plugin:
        plugin_path = os.path.join(data_dir, "mbi", "signature_providers", plugin)
        cmd = " ".join([cmd, f"--plugin {plugin_path}"])
    cli_runner.invoke(nxpimage.main, cmd.split(), expected_code=exit_code)
