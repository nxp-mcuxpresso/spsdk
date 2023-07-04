#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test Trustzone part of nxpimage app."""
import filecmp
import json
import os
import shutil

import commentjson as json
import pytest
import yaml
from click.testing import CliRunner

from spsdk import SPSDKError
from spsdk.apps import nxpimage
from spsdk.image.exceptions import SPSDKUnsupportedImageType
from spsdk.image.keystore import KeyStore
from spsdk.image.mbi_mixin import Mbi_MixinHmac
from spsdk.image.mbimg import DEVICE_FILE, Mbi_PlainRamLpc55s3x, Mbi_PlainXipSignedLpc55s3x
from spsdk.utils.crypto.backend_internal import ECC, RSA, internal_backend
from spsdk.utils.misc import load_configuration, use_working_directory

mbi_basic_tests = [
    ("mb_ram_crc.json", "lpc55xx"),
    ("mb_ram_crc_s19.json", "lpc55xx"),
    ("mb_ram_crc_hex.json", "lpc55xx"),
    ("mb_xip_crc.json", "lpc55xx"),
    ("mb_xip_crc_tz.json", "lpc55xx"),
    ("mb_xip_crc_tz_no_preset.json", "lpc55xx"),
    ("mb_xip_crc_hwk.json", "lpc55xx"),
    ("mb_xip_crc_hwk_tz.json", "lpc55xx"),
    ("mb_ram_crc.json", "lpc55s1x"),
    ("mb_xip_crc_tz.json", "lpc55s1x"),
    ("mb_xip_crc_tz_no_preset.json", "lpc55s1x"),
    ("mb_xip_crc_hwk.json", "lpc55s1x"),
    ("mb_xip_crc_hwk_tz.json", "lpc55s1x"),
    ("mb_ram_plain.json", "rt5xx"),
    ("mb_ram_crc.json", "rt5xx"),
    ("mb_ram_crc_tz.json", "rt5xx"),
    ("mb_ram_crc_tz_no_preset.json", "rt5xx"),
    ("mb_ram_crc_hwk.json", "rt5xx"),
    ("mb_ram_crc_hwk_tz.json", "rt5xx"),
    ("mb_xip_crc.json", "rt5xx"),
    ("mb_xip_crc_tz.json", "rt5xx"),
    ("mb_xip_crc_tz_no_preset.json", "rt5xx"),
    ("mb_xip_crc_hwk.json", "rt5xx"),
    ("mb_xip_crc_hwk_tz.json", "rt5xx"),
    ("mb_ram_crc.json", "lpc55s3x"),
    ("mb_ram_crc_version.json", "lpc55s3x"),
    ("mb_xip_crc.json", "lpc55s3x"),
    ("mb_ext_xip_crc.json", "lpc55s3x"),
    ("mb_ext_xip_crc_s19.json", "lpc55s3x"),
    ("mb_ram_crc.json", "mcxn9xx"),
    ("mb_xip_crc.json", "mcxn9xx"),
]

mbi_signed_tests = [
    ("mb_xip_256_none.json", "lpc55s3x", None),
    ("mb_xip_384_256.json", "lpc55s3x", None),
    ("mb_xip_384_384.json", "lpc55s3x", None),
    ("mb_ext_xip_signed.json", "lpc55s3x", None),
    ("mb_xip_256_none.json", "mcxn9xx", None),
    ("mb_xip_384_256.json", "mcxn9xx", None),
    ("mb_xip_384_384.json", "mcxn9xx", None),
    ("mb_xip_384_384_recovery_crctest.json", "mcxn9xx", None),
    ("mb_xip_384_384_recovery.json", "mcxn9xx", None),
]

mbi_legacy_signed_tests = [
    ("mb_xip_signed.json", "lpc55xx", 0),
    ("mb_xip_signed.json", "lpc55s1x", 0),
    ("mb_xip_signed_chain.json", "lpc55xx", 0),
    ("mb_xip_signed_no_ks.json", "rt5xx", 0),
    ("mb_ram_signed_no_ks.json", "rt5xx", 1),
    ("mb_ram_signed_ks.json", "rt5xx", 2),
]

mbi_legacy_encrypted_tests = [
    ("mb_ram_encrypted_ks.json", "rt5xx", 2),
    ("mb_ram_encrypted_ks_binkey.json", "rt5xx", 2),
]


def process_config_file(config_path: str, destination: str):
    config_path.replace("\\", "/")
    with open(config_path) as f:
        config_data = json.load(f)
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


def get_signing_key(config_file) -> ECC.EccKey:
    with open(config_file) as f:
        config_data = json.load(f)
    private_key_file = (
        config_data["signingCertificatePrivateKeyFile"]
        if config_data.get("useIsk", True) or "" in config_data
        else config_data["mainRootCertPrivateKeyFile"]
    )
    with open(private_key_file.replace("\\", "/"), "rb") as f:
        siging_key = ECC.import_key(f.read())
    return siging_key


@pytest.mark.parametrize("config_file,family", mbi_basic_tests)
def test_nxpimage_mbi_basic(elftosb_data_dir, tmpdir, config_file, family):
    runner = CliRunner()
    with use_working_directory(elftosb_data_dir):
        config_file = f"{elftosb_data_dir}/workspace/cfgs/{family}/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir)

        cmd = f"mbi export {new_config}"
        result = runner.invoke(nxpimage.main, cmd.split())
        if result.exit_code != 0:
            assert isinstance(result.exception, SPSDKUnsupportedImageType)
        else:
            assert os.path.isfile(new_binary)
            assert filecmp.cmp(new_binary, ref_binary)


@pytest.mark.parametrize("config_file,family", mbi_basic_tests)
def test_mbi_parser_basic(tmpdir, elftosb_data_dir, family, config_file):
    # Create new MBI file
    mbi_data_dir = os.path.join(elftosb_data_dir, "workspace")
    config_file = os.path.join(mbi_data_dir, "cfgs", family, config_file)

    ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir)

    cmd = f"mbi export {new_config}"
    runner = CliRunner()
    with use_working_directory(elftosb_data_dir):
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0

    cmd = f"mbi parse -b {new_binary} -f {family} {tmpdir}/parsed"
    result = runner.invoke(nxpimage.main, cmd.split())

    assert result.exit_code == 0
    input_image = os.path.join(elftosb_data_dir, load_configuration(config_file)["inputImageFile"])
    parsed_app = os.path.join(tmpdir, "parsed", "application.bin")
    assert os.path.isfile(parsed_app)
    if os.path.split(input_image)[1] == "bin":
        assert filecmp.cmp(input_image, parsed_app)


@pytest.mark.parametrize("config_file,device,sign_digest", mbi_signed_tests)
def test_nxpimage_mbi_signed(elftosb_data_dir, tmpdir, config_file, device, sign_digest):
    runner = CliRunner()
    with use_working_directory(elftosb_data_dir):
        config_file = f"{elftosb_data_dir}/workspace/cfgs/{device}/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir)

        cmd = f"mbi export {new_config}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0
        assert os.path.isfile(new_binary)

        # validate file lengths
        with open(ref_binary, "rb") as f:
            ref_data = f.read()
        with open(new_binary, "rb") as f:
            new_data = f.read()
        assert len(ref_data) == len(new_data)

        # validate signatures

        signing_key = get_signing_key(config_file=config_file)
        signature_length = 2 * signing_key.pointQ.size_in_bytes()
        if sign_digest:
            sign_offset = 32 if sign_digest and sign_digest == "sha256" else 48
            assert internal_backend.ecc_verify(
                signing_key,
                new_data[-(signature_length + sign_offset) : -sign_offset],
                new_data[: -(signature_length + sign_offset)],
            )
            assert internal_backend.ecc_verify(
                signing_key,
                ref_data[-(signature_length + sign_offset) : -sign_offset],
                ref_data[: -(signature_length + sign_offset)],
            )
            # validate data before signature
            assert (
                ref_data[: -(signature_length + sign_offset)]
                == new_data[: -(signature_length + sign_offset)]
            )
            # validate signature digest
            assert (
                internal_backend.hash(new_data[:-sign_offset], sign_digest)
                == new_data[-sign_offset:]
            )
            assert (
                internal_backend.hash(ref_data[:-sign_offset], sign_digest)
                == ref_data[-sign_offset:]
            )
        else:
            assert internal_backend.ecc_verify(
                signing_key, new_data[-signature_length:], new_data[:-signature_length]
            )
            assert internal_backend.ecc_verify(
                signing_key, ref_data[-signature_length:], ref_data[:-signature_length]
            )
            # validate data before signature
            assert ref_data[:-signature_length] == new_data[:-signature_length]


@pytest.mark.parametrize("config_file,family,sign_digest", mbi_signed_tests)
def test_mbi_parser_signed(tmpdir, elftosb_data_dir, family, config_file, sign_digest):
    # Create new MBI file
    mbi_data_dir = os.path.join(elftosb_data_dir, "workspace")
    config_file = os.path.join(mbi_data_dir, "cfgs", family, config_file)

    ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir)

    cmd = f"mbi export {new_config}"
    runner = CliRunner()
    with use_working_directory(elftosb_data_dir):
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0

    cmd = f"mbi parse -b {new_binary} -f {family} {tmpdir}/parsed"
    result = runner.invoke(nxpimage.main, cmd.split())

    assert result.exit_code == 0
    input_image = os.path.join(elftosb_data_dir, load_configuration(config_file)["inputImageFile"])
    parsed_app = os.path.join(tmpdir, "parsed", "application.bin")
    assert os.path.isfile(parsed_app)
    if os.path.split(input_image)[1] == "bin":
        assert filecmp.cmp(input_image, parsed_app)


@pytest.mark.parametrize(
    "mbi_config_file,cert_block_config_file,device",
    [
        ("mb_xip_384_256_cert.json", "cert_384_256.json", "lpc55s3x"),
        ("mb_xip_384_384_cert.json", "cert_384_384.json", "lpc55s3x"),
    ],
)
def test_nxpimage_mbi_cert_block_signed(
    elftosb_data_dir, tmpdir, mbi_config_file, cert_block_config_file, device
):
    runner = CliRunner()
    with use_working_directory(elftosb_data_dir):
        cert_config_file = f"{elftosb_data_dir}/workspace/cfgs/{device}/{cert_block_config_file}"
        mbi_config_file = f"{elftosb_data_dir}/workspace/cfgs/{device}/{mbi_config_file}"
        mbi_ref_binary, mbi_new_binary, mbi_new_config = process_config_file(
            mbi_config_file, tmpdir
        )
        cert_ref_binary, cert_new_binary, cert_new_config = process_config_file(
            cert_config_file, tmpdir
        )

        cmd = f"cert-block export {cert_new_config}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0
        assert os.path.isfile(cert_new_binary)

        # validate cert file file lengths
        with open(cert_ref_binary, "rb") as f:
            cert_ref_data = f.read()
        with open(cert_new_binary, "rb") as f:
            cert_new_data = f.read()
        assert len(cert_ref_data) == len(cert_new_data)
        assert cert_ref_data == cert_new_data

        cmd = f"mbi export {mbi_new_config}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0
        assert os.path.isfile(mbi_new_binary)

        # validate file lengths
        with open(mbi_ref_binary, "rb") as f:
            mbi_ref_data = f.read()
        with open(mbi_new_binary, "rb") as f:
            mbi_new_data = f.read()
        assert len(mbi_ref_data) == len(mbi_new_data)

        # validate signatures

        signing_key = get_signing_key(config_file=mbi_config_file)
        signature_length = 2 * signing_key.pointQ.size_in_bytes()

        assert internal_backend.ecc_verify(
            signing_key, mbi_new_data[-signature_length:], mbi_new_data[:-signature_length]
        )
        assert internal_backend.ecc_verify(
            signing_key, mbi_ref_data[-signature_length:], mbi_ref_data[:-signature_length]
        )
        # validate data before signature
        assert mbi_ref_data[:-signature_length] == mbi_new_data[:-signature_length]


@pytest.mark.parametrize(
    "mbi_config_file,cert_block_config_file,device",
    [
        ("mb_xip_384_256_cert_invalid.json", "cert_384_256.json", "lpc55s3x"),
    ],
)
def test_nxpimage_mbi_cert_block_signed_invalid(
    elftosb_data_dir, tmpdir, mbi_config_file, cert_block_config_file, device
):
    runner = CliRunner()
    with use_working_directory(elftosb_data_dir):
        cert_config_file = f"{elftosb_data_dir}/workspace/cfgs/{device}/{cert_block_config_file}"
        mbi_config_file = f"{elftosb_data_dir}/workspace/cfgs/{device}/{mbi_config_file}"
        mbi_ref_binary, mbi_new_binary, mbi_new_config = process_config_file(
            mbi_config_file, tmpdir
        )
        cert_ref_binary, cert_new_binary, cert_new_config = process_config_file(
            cert_config_file, tmpdir
        )

        cmd = f"cert-block export {cert_new_config}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0
        assert os.path.isfile(cert_new_binary)

        # validate cert file file lengths
        with open(cert_ref_binary, "rb") as f:
            cert_ref_data = f.read()
        with open(cert_new_binary, "rb") as f:
            cert_new_data = f.read()
        assert len(cert_ref_data) == len(cert_new_data)
        assert cert_ref_data == cert_new_data

        cmd = f"mbi export {mbi_new_config}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code != 0


# skip_hmac_keystore
# 0 indicates no hmac and no keystore present in output image
# 1 indicates hmac present but no keystore
# 2 indicates both hmac/keystore present in output image
@pytest.mark.parametrize("config_file,device,skip_hmac_keystore", mbi_legacy_signed_tests)
def test_nxpimage_mbi_legacy_signed(
    elftosb_data_dir, tmpdir, config_file, device, skip_hmac_keystore
):
    runner = CliRunner()
    with use_working_directory(elftosb_data_dir):
        config_file = f"{elftosb_data_dir}/workspace/cfgs/{device}/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir)

        cmd = f"mbi export {new_config}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0
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

        signing_certificate_file_path = config_data["mainCertPrivateKeyFile"]
        with open(signing_certificate_file_path, "rb") as f:
            cert = f.read()
            signing_key = RSA.import_key(cert)

        modulus = signing_key.n
        exponent = signing_key.e
        signature_length = int(len(f"{modulus:x}") / 2)
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

        assert internal_backend.rsa_verify(
            modulus,
            exponent,
            new_data[-signature_length:],
            new_data[:hmac_start] + new_data[hmac_end:-signature_length],
        )
        assert internal_backend.rsa_verify(
            modulus,
            exponent,
            ref_data[-signature_length:],
            ref_data[:hmac_start] + ref_data[hmac_end:-signature_length],
        )

        # validate data before signature
        assert ref_data[:-signature_length] == new_data[:-signature_length]


@pytest.mark.parametrize("config_file,family,skip_hmac_keystore", mbi_legacy_signed_tests)
def test_mbi_parser_legacy_signed(
    tmpdir, elftosb_data_dir, family, config_file, skip_hmac_keystore
):
    # Create new MBI file
    mbi_data_dir = os.path.join(elftosb_data_dir, "workspace")
    config_file = os.path.join(mbi_data_dir, "cfgs", family, config_file)

    ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir)

    cmd = f"mbi export {new_config}"
    runner = CliRunner()
    with use_working_directory(elftosb_data_dir):
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0

    cmd = f"mbi parse -b {new_binary} -f {family} {tmpdir}/parsed"
    result = runner.invoke(nxpimage.main, cmd.split())

    assert result.exit_code == 0
    input_image = os.path.join(elftosb_data_dir, load_configuration(config_file)["inputImageFile"])
    parsed_app = os.path.join(tmpdir, "parsed", "application.bin")
    assert os.path.isfile(parsed_app)
    if os.path.split(input_image)[1] == "bin":
        assert filecmp.cmp(input_image, parsed_app)


@pytest.mark.parametrize(
    "config_file,device",
    [
        ("mb_xip_signed_cert_gap.json", "lpc55xx"),
    ],
)
def test_nxpimage_mbi_invalid_conf(elftosb_data_dir, tmpdir, config_file, device):
    runner = CliRunner()
    with use_working_directory(elftosb_data_dir):
        config_file = f"{elftosb_data_dir}/workspace/cfgs/{device}/{config_file}"
        _, _, new_config = process_config_file(config_file, tmpdir)

        cmd = f"mbi export {new_config}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 1


@pytest.mark.parametrize("config_file,device,skip_hmac_keystore", mbi_legacy_encrypted_tests)
def test_nxpimage_mbi_legacy_encrypted(
    elftosb_data_dir, tmpdir, config_file, device, skip_hmac_keystore
):
    runner = CliRunner()
    with use_working_directory(elftosb_data_dir):
        config_file = f"{elftosb_data_dir}/workspace/cfgs/{device}/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir)

        cmd = f"mbi export {new_config}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0
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

        signing_certificate_file_path = config_data["mainCertPrivateKeyFile"]
        with open(signing_certificate_file_path, "rb") as f:
            cert = f.read()
            signing_key = RSA.import_key(cert)

        modulus = signing_key.n
        exponent = signing_key.e
        signature_length = int(len(f"{modulus:x}") / 2)
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

        assert internal_backend.rsa_verify(
            modulus,
            exponent,
            new_data[-signature_length:],
            new_data[:hmac_start] + new_data[hmac_end:-signature_length],
        )
        assert internal_backend.rsa_verify(
            modulus,
            exponent,
            ref_data[-signature_length:],
            ref_data[:hmac_start] + ref_data[hmac_end:-signature_length],
        )

        # validate data before signature
        assert ref_data[:-signature_length] == new_data[:-signature_length]


@pytest.mark.parametrize("config_file,family,skip_hmac_keystore", mbi_legacy_encrypted_tests)
def test_mbi_parser_legacy_encrypted(
    tmpdir, elftosb_data_dir, family, config_file, skip_hmac_keystore
):
    # Create new MBI file
    mbi_data_dir = os.path.join(elftosb_data_dir, "workspace")
    config_file = os.path.join(mbi_data_dir, "cfgs", family, config_file)

    ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir)

    cmd = ["mbi", "export", new_config]
    runner = CliRunner()
    with use_working_directory(elftosb_data_dir):
        result = runner.invoke(nxpimage.main, cmd)
        assert result.exit_code == 0

    cmd = [
        "mbi",
        "parse",
        "-b",
        new_binary,
        "-f",
        family,
        "-k",
        f"{mbi_data_dir}/keys/userkey.txt",
        f"{tmpdir}/parsed",
    ]
    result = runner.invoke(nxpimage.main, cmd)

    assert result.exit_code == 0
    input_image = os.path.join(elftosb_data_dir, load_configuration(config_file)["inputImageFile"])
    parsed_app = os.path.join(tmpdir, "parsed", "application.bin")
    assert os.path.isfile(parsed_app)
    if os.path.split(input_image)[1] == "bin":
        assert filecmp.cmp(input_image, parsed_app)


def test_nxpimage_mbi_lower():
    mbi = Mbi_PlainRamLpc55s3x(app=bytes(100), load_addr=0, firmware_version=0)
    assert mbi.app
    assert mbi.export()


def test_mbi_lpc55s3x_invalid():
    mbi = Mbi_PlainXipSignedLpc55s3x(app=bytes(100), firmware_version=0)
    with pytest.raises(SPSDKError):
        mbi.validate()


@pytest.mark.parametrize(
    "family",
    [
        "lpc55xx",
        "lpc55s0x",
        "lpc550x",
        "lpc55s1x",
        "lpc551x",
        "lpc55s2x",
        "lpc552x",
        "lpc55s6x",
        "nhs52sxx",
        "rt5xx",
        "rt6xx",
        "lpc55s3x",
        "kw45xx",
        "k32w1xx",
        "lpc553x",
    ],
)
def test_mbi_get_templates(tmpdir, family):
    runner = CliRunner()
    cmd = f"mbi get-templates -f {family} {tmpdir}"
    result = runner.invoke(nxpimage.main, cmd.split())
    assert result.exit_code == 0
    device_data = load_configuration(path=DEVICE_FILE)
    images = device_data["devices"][family]["images"]
    for image in images:
        for config in images[image]:
            file_path = os.path.join(tmpdir, f"{family}_{image}_{config}.yaml")
            assert os.path.isfile(file_path)


@pytest.mark.parametrize(
    "family, template_name, keys_to_copy",
    [
        (
            "lpc55s3x",
            "ext_xip_signed_lpc55s3x.yml",
            ["ec_pk_secp256r1_cert0.pem", "ec_secp256r1_cert0.pem"],
        ),
        (
            "lpc553x",
            "ext_xip_signed_lpc55s3x.yml",
            ["ec_pk_secp256r1_cert0.pem", "ec_secp256r1_cert0.pem"],
        ),
        (
            "rt5xx",
            "ext_xip_signed_rtxxxx.yml",
            ["k0_cert0_2048.pem", "root_k0_signed_cert0_noca.der.cert"],
        ),
        (
            "rt6xx",
            "ext_xip_signed_rtxxxx.yml",
            ["k0_cert0_2048.pem", "root_k0_signed_cert0_noca.der.cert"],
        ),
        (
            "lpc550x",
            "int_xip_signed_xip.yml",
            ["k0_cert0_2048.pem", "root_k0_signed_cert0_noca.der.cert"],
        ),
        (
            "lpc551x",
            "int_xip_signed_xip.yml",
            ["k0_cert0_2048.pem", "root_k0_signed_cert0_noca.der.cert"],
        ),
        (
            "lpc55s2x",
            "int_xip_signed_xip.yml",
            ["k0_cert0_2048.pem", "root_k0_signed_cert0_noca.der.cert"],
        ),
        (
            "nhs52sxx",
            "int_xip_signed_xip.yml",
            ["k0_cert0_2048.pem", "root_k0_signed_cert0_noca.der.cert"],
        ),
        (
            "kw45xx",
            "int_xip_signed_kw45xx.yml",
            ["ec_pk_secp256r1_cert0.pem", "ec_secp256r1_cert0.pem"],
        ),
        (
            "k32w1xx",
            "int_xip_signed_kw45xx.yml",
            ["ec_pk_secp256r1_cert0.pem", "ec_secp256r1_cert0.pem"],
        ),
    ],
)
def test_mbi_export_sign_provider(tmpdir, data_dir, family, template_name, keys_to_copy):
    mbi_data_dir = os.path.join(data_dir, "mbi")
    config_path = os.path.join(mbi_data_dir, template_name)
    config = load_configuration(config_path)
    config["family"] = family

    for key_file_name in keys_to_copy:
        key_file_path = os.path.join(mbi_data_dir, "keys_and_certs", key_file_name)
        shutil.copyfile(key_file_path, os.path.join(tmpdir, key_file_name))
    test_app_path = os.path.join(mbi_data_dir, config["inputImageFile"])
    shutil.copyfile(test_app_path, os.path.join(tmpdir, config["inputImageFile"]))
    tmp_config = os.path.join(tmpdir, "config.yaml")
    with open(tmp_config, "w") as file:
        yaml.dump(config, file)

    runner = CliRunner()
    cmd = f"mbi export {tmp_config}"
    result = runner.invoke(nxpimage.main, cmd.split())
    assert result.exit_code == 0
    file_path = os.path.join(tmpdir, config["masterBootOutputFile"])
    assert os.path.isfile(file_path)


@pytest.mark.parametrize(
    "family, template_name, keys_to_copy",
    [
        (
            "lpc55s3x",
            "ext_xip_signed_lpc55s3x_invalid.yml",
            ["ec_pk_secp256r1_cert0.pem", "ec_secp256r1_cert0.pem"],
        ),
        (
            "lpc553x",
            "ext_xip_signed_lpc55s3x_invalid.yml",
            ["ec_pk_secp256r1_cert0.pem", "ec_secp256r1_cert0.pem"],
        ),
        (
            "rt5xx",
            "ext_xip_signed_rtxxxx_invalid.yml",
            ["k0_cert0_2048.pem", "root_k0_signed_cert0_noca.der.cert"],
        ),
        (
            "rt6xx",
            "ext_xip_signed_rtxxxx_invalid.yml",
            ["k0_cert0_2048.pem", "root_k0_signed_cert0_noca.der.cert"],
        ),
        (
            "lpc550x",
            "int_xip_signed_xip_invalid.yml",
            ["k0_cert0_2048.pem", "root_k0_signed_cert0_noca.der.cert"],
        ),
        (
            "lpc551x",
            "int_xip_signed_xip_invalid.yml",
            ["k0_cert0_2048.pem", "root_k0_signed_cert0_noca.der.cert"],
        ),
        (
            "lpc55s2x",
            "int_xip_signed_xip_invalid.yml",
            ["k0_cert0_2048.pem", "root_k0_signed_cert0_noca.der.cert"],
        ),
        (
            "nhs52sxx",
            "int_xip_signed_xip_invalid.yml",
            ["k0_cert0_2048.pem", "root_k0_signed_cert0_noca.der.cert"],
        ),
        (
            "kw45xx",
            "int_xip_signed_kw45xx_invalid.yml",
            ["ec_pk_secp256r1_cert0.pem", "ec_secp256r1_cert0.pem"],
        ),
        (
            "k32w1xx",
            "int_xip_signed_kw45xx_invalid.yml",
            ["ec_pk_secp256r1_cert0.pem", "ec_secp256r1_cert0.pem"],
        ),
    ],
)
def test_mbi_export_sign_provider_invalid_configuration(
    tmpdir, data_dir, family, template_name, keys_to_copy
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
    tmp_config = os.path.join(tmpdir, "config.yaml")
    with open(tmp_config, "w") as file:
        yaml.dump(config, file)

    runner = CliRunner()
    cmd = f"mbi export {tmp_config}"
    result = runner.invoke(nxpimage.main, cmd.split())
    assert result.exit_code != 0
