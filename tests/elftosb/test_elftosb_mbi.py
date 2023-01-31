#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test Trustzone part of elftosb app."""
import filecmp
import json
import os

import commentjson as json
import pytest
from click.testing import CliRunner

from spsdk import SPSDKError
from spsdk.apps import elftosb
from spsdk.image.exceptions import SPSDKUnsupportedImageType
from spsdk.image.keystore import KeyStore
from spsdk.image.mbi_mixin import Mbi_MixinHmac
from spsdk.image.mbimg import Mbi_PlainRamLpc55s3x, Mbi_PlainXipSignedLpc55s3x
from spsdk.utils.crypto.backend_internal import ECC, RSA, internal_backend
from spsdk.utils.misc import use_working_directory


def process_config_file(config_path: str, destination: str, family: str = None):
    with open(config_path) as f:
        config_data = json.load(f)
    for key in config_data:
        if isinstance(config_data[key], str):
            config_data[key] = config_data[key].replace("\\", "/")
    ref_binary = config_data["masterBootOutputFile"]
    new_binary = f"{destination}/{os.path.basename(ref_binary)}"
    new_config = f"{destination}/new_config.json"
    config_data["masterBootOutputFile"] = new_binary
    if family and "family" in config_data.keys():
        config_data["family"] = family
    with open(new_config, "w") as f:
        json.dump(config_data, f, indent=2)
    return ref_binary, new_binary, new_config


def get_signing_key(config_file) -> ECC.EccKey:
    with open(config_file) as f:
        config_data = json.load(f)
    private_key_file = (
        config_data["signingCertificatePrivateKeyFile"]
        if config_data["useIsk"]
        else config_data["mainRootCertPrivateKeyFile"]
    )
    with open(private_key_file.replace("\\", "/"), "rb") as f:
        siging_key = ECC.import_key(f.read())
    return siging_key


@pytest.mark.parametrize(
    "config_file,device",
    [
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
        ("mb_xip_crc_nbu.json", "kw45xx"),
        ("mb_xip_crc_version.json", "kw45xx"),
        ("mb_xip_384_384_no_signature.json", "kw45xx"),
        ("mb_xip_crc_nbu.json", "k32w1xx"),
        ("mb_xip_crc_version.json", "k32w1xx"),
        ("mb_xip_384_384_no_signature.json", "k32w1xx"),
        ("mb_ext_xip_crc_s19.json", "lpc55s3x"),
    ],
)
def test_elftosb_mbi_basic(data_dir, tmpdir, config_file, device):
    runner = CliRunner()
    with use_working_directory(data_dir):
        config_file = f"{data_dir}/workspace/cfgs/{device}/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir, device)

        cmd = f"--image-conf {new_config}"
        result = runner.invoke(elftosb.main, cmd.split())
        if result.exit_code != 0:
            assert isinstance(result.exception, SPSDKUnsupportedImageType)
        else:
            assert os.path.isfile(new_binary)
            assert filecmp.cmp(new_binary, ref_binary)


@pytest.mark.parametrize(
    "config_file,device,sign_digest",
    [
        ("mb_xip_256_none.json", "lpc55s3x", None),
        ("mb_xip_384_256.json", "lpc55s3x", None),
        ("mb_xip_384_384.json", "lpc55s3x", None),
        ("mb_ext_xip_signed.json", "lpc55s3x", None),
        ("mb_xip_256_none.json", "k32w1xx", None),
        ("mb_xip_384_256.json", "k32w1xx", None),
        ("mb_xip_384_384.json", "k32w1xx", None),
        ("mb_xip_256_none_sd.json", "k32w1xx", "sha256"),
        ("mb_xip_384_256_sd.json", "k32w1xx", "sha256"),
        ("mb_xip_384_384_sd.json", "k32w1xx", "sha384"),
        ("mb_xip_256_none.json", "kw45xx", None),
        ("mb_xip_384_256.json", "kw45xx", None),
        ("mb_xip_384_384.json", "kw45xx", None),
        ("mb_xip_256_none_sd.json", "kw45xx", "sha256"),
        ("mb_xip_384_256_sd.json", "kw45xx", "sha256"),
        ("mb_xip_384_384_sd.json", "kw45xx", "sha384"),
    ],
)
def test_elftosb_mbi_signed(data_dir, tmpdir, config_file, device, sign_digest):
    runner = CliRunner()
    with use_working_directory(data_dir):
        config_file = f"{data_dir}/workspace/cfgs/{device}/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir, device)

        cmd = f"--image-conf {new_config}"
        result = runner.invoke(elftosb.main, cmd.split())
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


# skip_hmac_keystore
# 0 indicates no hmac and no keystore present in output image
# 1 indicates hmac present but no keystore
# 2 indicates both hmac/keystore present in output image
@pytest.mark.parametrize(
    "config_file,device,skip_hmac_keystore",
    [
        ("mb_xip_signed.json", "lpc55xx", 0),
        ("mb_xip_signed.json", "lpc55s1x", 0),
        ("mb_xip_signed_chain.json", "lpc55xx", 0),
        ("mb_xip_signed_no_ks.json", "rt5xx", 0),
        ("mb_ram_signed_no_ks.json", "rt5xx", 1),
        ("mb_ram_signed_ks.json", "rt5xx", 2),
    ],
)
def test_elftosb_mbi_legacy_signed(data_dir, tmpdir, config_file, device, skip_hmac_keystore):
    runner = CliRunner()
    with use_working_directory(data_dir):
        config_file = f"{data_dir}/workspace/cfgs/{device}/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir, device)

        cmd = f"--image-conf {new_config}"
        result = runner.invoke(elftosb.main, cmd.split())
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


@pytest.mark.parametrize(
    "config_file,device",
    [
        ("mb_xip_signed_cert_gap.json", "lpc55xx"),
    ],
)
def test_elftosb_mbi_invalid_conf(data_dir, tmpdir, config_file, device):
    runner = CliRunner()
    with use_working_directory(data_dir):
        config_file = f"{data_dir}/workspace/cfgs/{device}/{config_file}"
        _, _, new_config = process_config_file(config_file, tmpdir, device)

        cmd = f"--image-conf {new_config}"
        result = runner.invoke(elftosb.main, cmd.split())
        assert result.exit_code == 1


@pytest.mark.parametrize(
    "config_file,device,skip_hmac_keystore",
    [("mb_ram_encrypted_ks.json", "rt5xx", 2), ("mb_ram_encrypted_ks_binkey.json", "rt5xx", 2)],
)
def test_elftosb_mbi_legacy_encrypted(data_dir, tmpdir, config_file, device, skip_hmac_keystore):
    runner = CliRunner()
    with use_working_directory(data_dir):
        config_file = f"{data_dir}/workspace/cfgs/{device}/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir, device)

        cmd = f"--image-conf {new_config}"
        result = runner.invoke(elftosb.main, cmd.split())
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


def test_elftosb_mbi_lower():
    mbi = Mbi_PlainRamLpc55s3x(app=bytes(100), load_addr=0, firmware_version=0)
    assert mbi.app

    mbi = Mbi_PlainRamLpc55s3x(app=bytes(100), load_addr=0, firmware_version=0)
    assert mbi.app
    assert mbi.export()


def test_mbi_lpc55s3x_invalid():
    mbi = Mbi_PlainXipSignedLpc55s3x(
        app=bytes(100),
        firmware_version=0,
    )
    with pytest.raises(SPSDKError):
        mbi.validate()

    mbi = Mbi_PlainXipSignedLpc55s3x(
        app=bytes(100),
        firmware_version=0,
    )

    with pytest.raises(SPSDKError):
        mbi.validate()
