#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test Trustzone part of elftosb app."""
import filecmp
import json
import os
import unittest.mock as mock

import commentjson as json
import pytest
from click.testing import CliRunner
from Crypto.Cipher import AES

from spsdk import SPSDKError
from spsdk.apps import elftosb
from spsdk.image import MasterBootImage, MasterBootImageN4Analog, MasterBootImageType
from spsdk.image.keystore import KeySourceType, KeyStore
from spsdk.utils.crypto.backend_internal import ECC, RSA, internal_backend
from spsdk.utils.misc import use_working_directory

devices = (
    "lpc55xx",
    "lpc55s0x",
    "lpc55s1x",
    "lpc55s3x",
)


def process_config_file(config_path: str, destination: str):
    with open(config_path) as f:
        config_data = json.load(f)
    for key in config_data:
        if isinstance(config_data[key], str):
            config_data[key] = config_data[key].replace("\\", "/")
    ref_binary = config_data["masterBootOutputFile"]
    new_binary = f"{destination}/{os.path.basename(ref_binary)}"
    new_config = f"{destination}/new_config.json"
    config_data["masterBootOutputFile"] = new_binary
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
    "config_file,device,message",
    [
        (
            "mb_ram_crc.json",
            "lpc55xx",
            (
                f'Unsupported value "RAM" of '
                f'"outputImageExecutionTarget" for selected family "lpc55xx".'
                f'Expected values for "lpc55xx" ["XIP"].'
            ),
        ),
        ("mb_xip_crc.json", "lpc55xx", ""),
        ("mb_xip_crc_tz.json", "lpc55xx", ""),
        ("mb_xip_crc_tz_no_preset.json", "lpc55xx", ""),
        (
            "mb_xip_crc_hwk.json",
            "lpc55xx",
            (
                f'Unsupported value "True" of '
                f'"enableHwUserModeKeys" for selected family "lpc55xx".'
                f'Expected values for "lpc55xx" ["False"].'
            ),
        ),
        (
            "mb_xip_crc_hwk_tz.json",
            "lpc55xx",
            (
                f'Unsupported value "True" of '
                f'"enableHwUserModeKeys" for selected family "lpc55xx".'
                f'Expected values for "lpc55xx" ["False"].'
            ),
        ),
        (
            "mb_ram_crc.json",
            "lpc55s1x",
            (
                f'Unsupported value "RAM" of '
                f'"outputImageExecutionTarget" for selected family "lpc55s1x".'
                f'Expected values for "lpc55s1x" ["XIP"].'
            ),
        ),
        ("mb_ram_crc.json", "rt5xx", ""),
        ("mb_ram_crc_tz.json", "rt5xx", ""),
        ("mb_ram_crc_tz_no_preset.json", "rt5xx", ""),
        ("mb_ram_crc_hwk.json", "rt5xx", ""),
        ("mb_ram_crc_hwk_tz.json", "rt5xx", ""),
        ("mb_xip_crc.json", "rt5xx", ""),
        ("mb_xip_crc_tz.json", "rt5xx", ""),
        ("mb_xip_crc_tz_no_preset.json", "rt5xx", ""),
        ("mb_xip_crc_hwk.json", "rt5xx", ""),
        ("mb_xip_crc_hwk_tz.json", "rt5xx", ""),
        ("mb_xip_crc_tz.json", "lpc55s1x", ""),
        ("mb_xip_crc_tz_no_preset.json", "lpc55s1x", ""),
        ("mb_xip_crc_hwk.json", "lpc55s1x", ""),
        ("mb_xip_crc_hwk_tz.json", "lpc55s1x", ""),
        ("mb_ram_crc.json", "lpc55s3x", ""),
        ("mb_ram_crc_version.json", "lpc55s3x", ""),
        ("mb_xip_crc.json", "lpc55s3x", ""),
    ],
)
def test_elftosb_mbi_basic(data_dir, tmpdir, config_file, device, message):
    runner = CliRunner()
    with use_working_directory(data_dir):
        config_file = f"{data_dir}/workspace/cfgs/{device}/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir)

        cmd = f"--image-conf {new_config}"
        result = runner.invoke(elftosb.main, cmd.split())
        if result.exit_code != 0:
            assert isinstance(result.exception, SPSDKError)
            assert result.exception.description.lower() == message.lower()
        else:
            assert os.path.isfile(new_binary)
            assert filecmp.cmp(new_binary, ref_binary)


@pytest.mark.parametrize(
    "config_file,device",
    [
        ("mb_xip_256_none.json", "lpc55s3x"),
        ("mb_xip_384_256.json", "lpc55s3x"),
        ("mb_xip_384_384.json", "lpc55s3x"),
    ],
)
def test_elftosb_mbi_signed(data_dir, tmpdir, config_file, device):
    runner = CliRunner()
    with use_working_directory(data_dir):
        config_file = f"{data_dir}/workspace/cfgs/{device}/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir)

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
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir)

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
            hmac_start = MasterBootImage.HMAC_OFFSET
            gap_len = MasterBootImage.HMAC_SIZE
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
    "config_file,device,skip_hmac_keystore",
    [("mb_ram_encrypted_ks.json", "rt5xx", 2)],
)
def test_elftosb_mbi_legacy_encrypted(data_dir, tmpdir, config_file, device, skip_hmac_keystore):
    runner = CliRunner()
    with use_working_directory(data_dir):
        config_file = f"{data_dir}/workspace/cfgs/{device}/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir)

        cmd = f"--image-conf {new_config}"
        new_defaults = list(MasterBootImage.__init__.__defaults__)
        # The last value in defaults corresponds to ctr_init_vector, which we need to mock
        new_defaults[-1] = b"\xc3\xdf\x23\x16\xfd\x40\xb1\x55\x86\xcb\x5a\xe4\x94\x83\xae\xe2"
        new_defaults = tuple(new_defaults)
        with mock.patch.object(MasterBootImage.__init__, "__defaults__", new_defaults):
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
            hmac_start = MasterBootImage.HMAC_OFFSET
            gap_len = MasterBootImage.HMAC_SIZE
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
    mbi = MasterBootImageN4Analog(
        app=bytes(100), load_addr=0, image_type=MasterBootImageType.PLAIN_IMAGE, firmware_version=0
    )
    assert mbi.data

    mbi = MasterBootImageN4Analog(app=bytes(100), load_addr=0, firmware_version=0)
    assert mbi.data
    assert mbi.info()
    assert mbi.export()


def test_mbi_n4a_invalid():
    mbi = MasterBootImageN4Analog(
        app=bytes(100),
        load_addr=0,
        image_type=MasterBootImageType.SIGNED_XIP_IMAGE,
        firmware_version=0,
    )
    mbi.cert_block = None
    with pytest.raises(SPSDKError, match="Certificate Block is not set!"):
        mbi.data
    mbi = MasterBootImageN4Analog(
        app=bytes(100),
        load_addr=0,
        image_type=MasterBootImageType.SIGNED_XIP_IMAGE,
        firmware_version=0,
    )
    mbi.manifest = None
    with pytest.raises(SPSDKError, match="MasterBootImageManifest is not set!"):
        mbi.total_len
