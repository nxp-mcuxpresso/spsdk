#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK MBI (Master Boot Image) functionality tests.

This module contains comprehensive test suite for MBI image creation, parsing,
signing, and validation across different NXP MCU families including LPC55S3x,
MCXE31, and other supported devices.
The tests cover basic MBI functionality, digital signature validation with RSA
and ECC algorithms, certificate block handling, legacy format support, template
generation, configuration validation, and signature provider integration.
"""

import filecmp
import json
import os
import shutil
from typing import Optional

import pytest
import yaml

from spsdk.apps import nxpimage
from spsdk.crypto.crc import CrcAlg, from_crc_algorithm
from spsdk.crypto.hash import get_hash
from spsdk.crypto.keys import PrivateKey, PrivateKeyEcc, PrivateKeyRsa, PublicKeyEcc
from spsdk.crypto.signature_provider import PlainFileSP, SignatureProvider, get_signature_provider
from spsdk.exceptions import SPSDKError
from spsdk.image.cert_block.cert_blocks import CertBlockV21, CertBlockVx
from spsdk.image.keystore import KeyStore
from spsdk.image.mbi.mbi import MasterBootImage
from spsdk.image.mbi.mbi_mixin import MasterBootImageManifestCrc, Mbi_MixinHmac, Mbi_MixinIvt
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision, get_db
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
    ("mb_xip_plain.yaml", "mcxe247"),
    ("mb_xip_plain.yaml", "mcxe31b"),
    ("mb_xip_plain_lc.yaml", "mcxe31b"),
    ("mb_xip_plain_lc_with_addr.yaml", "mcxe31b"),
    ("mb_xip_crc.yaml", "mcxn556s"),
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


def process_config_file(config_path: str, destination: str) -> tuple[str, str, str]:
    """Process configuration file and prepare it for image generation.

    Loads the configuration file, normalizes path separators, extracts output file information,
    and creates a new configuration file in the destination directory with updated paths.

    :param config_path: Path to the source configuration file.
    :param destination: Destination directory for the new configuration and binary files.
    :raises ValueError: When no output file is specified in configuration.
    :return: Tuple containing reference binary path, new binary path, and new config path.
    """
    config_path.replace("\\", "/")
    config_data = load_configuration(config_path)
    for key in config_data:
        if isinstance(config_data[key], str):
            config_data[key] = config_data[key].replace("\\", "/")
    ref_binary = config_data.get("masterBootOutputFile") or config_data.get("containerOutputFile")
    if ref_binary is None:
        raise ValueError("No output file specified in configuration")
    new_binary = f"{destination}/{os.path.basename(ref_binary)}"
    new_config = f"{destination}/{os.path.basename(config_path)}"
    config_data["masterBootOutputFile"] = new_binary
    # It doesn't matter that there will be both keys in this temporary config
    config_data["containerOutputFile"] = new_binary
    with open(new_config, "w") as f:
        json.dump(config_data, f, indent=2)
    return ref_binary, new_binary, new_config


def get_signer_key(config: Config) -> PrivateKeyEcc:
    """Get signer private key from configuration.

    Extracts the signer private key file path from the configuration and loads
    the corresponding ECC private key. The method handles both input file
    configuration and plain file signature provider formats.

    :param config: Configuration object containing signer information.
    :raises SPSDKError: When signer configuration is invalid or key loading fails.
    :return: Loaded ECC private key for signing operations.
    """
    try:
        private_key_file = config.get_input_file_name("signer")
    except SPSDKError:
        # let's assume plain file signature provider
        private_key_file = config.get_str("signer").split("=")[2]
    return PrivateKeyEcc.load(private_key_file)


@pytest.mark.parametrize("config_file,family", mbi_basic_tests)
def test_nxpimage_mbi_basic(
    cli_runner: CliRunner, nxpimage_data_dir: str, tmpdir: str, config_file: str, family: str
) -> None:
    """Test basic MBI export functionality using nxpimage CLI.

    This test verifies that the MBI (Master Boot Image) export command works correctly
    by comparing the generated binary output with a reference binary file.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param nxpimage_data_dir: Directory path containing test data files.
    :param tmpdir: Temporary directory path for test outputs.
    :param config_file: Configuration file name for MBI generation.
    :param family: Target MCU family name.
    :raises AssertionError: If generated binary doesn't exist or differs from reference.
    """
    with use_working_directory(nxpimage_data_dir):
        config_file = f"{nxpimage_data_dir}/workspace/cfgs/{family}/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir)

        cmd = f"mbi export -c {new_config}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(new_binary)
        assert filecmp.cmp(new_binary, ref_binary)


@pytest.mark.parametrize("config_file,family", mbi_basic_tests)
def test_mbi_parser_basic(
    cli_runner: CliRunner, tmpdir: str, nxpimage_data_dir: str, family: str, config_file: str
) -> None:
    """Test basic MBI parser functionality with export and parse operations.

    This test creates an MBI file from a configuration, exports it, then parses it back
    to verify the application binary can be correctly extracted and matches the original
    input image file.

    :param cli_runner: Click CLI test runner for invoking nxpimage commands.
    :param tmpdir: Temporary directory path for test file operations.
    :param nxpimage_data_dir: Base directory containing nxpimage test data files.
    :param family: Target MCU family name for MBI operations.
    :param config_file: Configuration file name for MBI creation.
    """
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
        if filecmp.cmp(input_image, parsed_app):
            assert True
        else:
            # There might be passing at the end of the file
            ref_data = load_binary(input_image)
            new_data = load_binary(parsed_app)
            # compare the first N bytes of reference data
            assert ref_data == new_data[: len(ref_data)]
            # remaining data must be all zeros
            assert new_data[len(ref_data) :] == bytes([0] * (len(new_data) - len(ref_data)))


def test_mbi_parser_basic_mcxe31_image_with_ivt(
    cli_runner: CliRunner, tmpdir: str, nxpimage_data_dir: str
) -> None:
    """Test MBI parser functionality with MCXE31 image containing IVT.

    This test verifies the complete workflow of exporting and parsing an MBI (Master Boot Image)
    for MCXE31B family with IVT (Image Vector Table). It creates a new MBI file from configuration,
    exports it using the CLI, parses the generated binary, and validates that the parsed
    application matches the original input image.

    :param cli_runner: Click CLI test runner for invoking nxpimage commands.
    :param tmpdir: Temporary directory path for test file operations.
    :param nxpimage_data_dir: Base directory containing test data and configuration files.
    """
    # Create new MBI file
    mbi_data_dir = os.path.join(nxpimage_data_dir, "workspace")
    config_file = os.path.join(mbi_data_dir, "cfgs", "mcxe31b", "mb_xip_plain_with_ivt.yaml")

    ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir)

    cmd = f"mbi export -c {new_config}"
    with use_working_directory(nxpimage_data_dir):
        cli_runner.invoke(nxpimage.main, cmd.split())

    cmd = f"mbi parse -b {new_binary} -f mcxe31b -o {tmpdir}/parsed"
    cli_runner.invoke(nxpimage.main, cmd.split())

    sub_path: str = load_configuration(config_file)["inputImageFile"]
    input_image = os.path.normpath(os.path.join(nxpimage_data_dir, sub_path.replace("\\", "/")))
    parsed_app = os.path.join(tmpdir, "parsed", "application.bin")
    assert os.path.isfile(parsed_app)
    # the application lies between IVT and LC config
    assert load_binary(input_image)[0x1000:-0x18] == load_binary(parsed_app)


@pytest.mark.parametrize("config_file,device,sign_digest", mbi_signed_tests)
def test_nxpimage_mbi_signed(
    cli_runner: CliRunner,
    nxpimage_data_dir: str,
    tmpdir: str,
    config_file: str,
    device: str,
    sign_digest: Optional[str],
) -> None:
    """Test nxpimage MBI signed binary generation and validation.

    This test validates the Master Boot Image (MBI) export functionality for signed binaries.
    It compares reference and newly generated binaries, verifies signatures, validates
    certificate blocks, and ensures data integrity through CRC checks.

    :param cli_runner: Click CLI test runner for command execution.
    :param nxpimage_data_dir: Directory containing test data and configuration files.
    :param tmpdir: Temporary directory for output files.
    :param config_file: Configuration file name for MBI generation.
    :param device: Target device family for MBI creation.
    :param sign_digest: Optional digest algorithm for signing (sha256 or sha384).
    """
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
        signing_key = get_signer_key(Config.create_from_file(config_file))
        signature_length = signing_key.signature_size
        mbi_cls = MasterBootImage.get_mbi_class(load_configuration(new_config))
        parsed_mbi = mbi_cls.parse(family=FamilyRevision(device), data=new_data)
        assert hasattr(parsed_mbi, "cert_block")
        cert_block_v2 = parsed_mbi.cert_block
        assert isinstance(cert_block_v2, CertBlockV21)
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


@pytest.mark.parametrize("config_file,device", [("mb_xip_signed.yaml", "mcxe31b")])
def test_nxpimage_mbi_signed_mcxe31(
    cli_runner: CliRunner, nxpimage_data_dir: str, tmpdir: str, config_file: str, device: str
) -> None:
    """Test signed MBI export and parse functionality for MCXE31 device.

    This test validates the complete workflow of exporting a signed Master Boot Image (MBI)
    and parsing it back to verify data integrity. It compares the generated binary with
    a reference binary and ensures the parsed application matches the original input.

    :param cli_runner: Click CLI test runner for invoking nxpimage commands.
    :param nxpimage_data_dir: Directory path containing test data and configuration files.
    :param tmpdir: Temporary directory path for storing generated test files.
    :param config_file: Configuration file name for MBI generation.
    :param device: Target device name for MBI configuration.
    """
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
        assert ref_data == new_data
        cmd = f"mbi parse -b {new_binary} -f {device} -o {tmpdir}/parsed"
        cli_runner.invoke(nxpimage.main, cmd.split())

        input_image = os.path.join(
            nxpimage_data_dir, load_configuration(config_file)["inputImageFile"]
        ).replace("\\", "/")
        parsed_app = os.path.join(tmpdir, "parsed", "application.bin")
        assert os.path.isfile(parsed_app)
        assert filecmp.cmp(input_image, parsed_app)


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
    cli_runner: CliRunner,
    nxpimage_data_dir: str,
    tmpdir: str,
    config_file: str,
    device: str,
    added_hash: bool,
) -> None:
    """Test MBI export functionality with signed VX certificate blocks.

    This test validates the complete MBI (Master Boot Image) export process for devices
    using VX certificate blocks with digital signatures. It verifies binary generation,
    signature validation, ISK certificate verification, and data integrity checks.

    :param cli_runner: CLI test runner for executing nxpimage commands
    :param nxpimage_data_dir: Directory containing test data and configuration files
    :param tmpdir: Temporary directory for output files
    :param config_file: Configuration file name for MBI generation
    :param device: Target device identifier for family-specific processing
    :param added_hash: Flag indicating whether ISK certificate hash should be validated
    """
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
        signature_provider: SignatureProvider = get_signature_provider(
            Config.create_from_file(config_file)
        )
        signature_length = signature_provider.signature_length
        mbi_cls = MasterBootImage.get_mbi_class(load_configuration(new_config))
        parsed_mbi = mbi_cls.parse(family=FamilyRevision(device), data=new_data)
        assert hasattr(parsed_mbi, "cert_block")
        cert_block = parsed_mbi.cert_block
        assert isinstance(cert_block, CertBlockVx)

        SIGN_DIGEST_OFFSET = 0x360
        SIGN_DIGEST_LENGTH = 32
        BCA_OFFSET = 0x3C0
        APP_OFFSET = 0x0C00
        SIGN_OFFSET = 0x380
        IMG_FCB_OFFSET = 0x400
        IMG_FCB_SIZE = 16
        IMG_ISK_OFFSET = IMG_FCB_OFFSET + IMG_FCB_SIZE
        IMG_ISK_CERT_HASH_OFFSET = 0x04A0
        assert isinstance(signature_provider, PlainFileSP)
        signing_key = PrivateKey.load(signature_provider.file_path)
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
        isk_key = get_signer_key(Config.create_from_file(config_file))

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
    cli_runner: CliRunner, nxpimage_data_dir: str, tmpdir: str, config_file: str, device: str
) -> None:
    """Test nxpimage MBI CRC functionality for various device configurations.

    This test verifies that the MBI (Master Boot Image) export and parse commands
    work correctly by comparing reference and newly generated binary files, and
    ensuring the parse operation completes successfully.

    :param cli_runner: CLI test runner instance for invoking nxpimage commands
    :param nxpimage_data_dir: Directory path containing test data and configuration files
    :param tmpdir: Temporary directory path for output files
    :param config_file: Configuration file name for the MBI export operation
    :param device: Target device name for MBI operations
    """
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
    cli_runner: CliRunner,
    tmpdir: str,
    nxpimage_data_dir: str,
    family: str,
    config_file: str,
    sign_digest: Optional[str],
) -> None:
    """Test MBI parser functionality with signed images.

    This test creates a new MBI (Master Boot Image) file using the export command,
    then parses it back and verifies that the parsed application binary matches
    the original input image when applicable.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory path for test files.
    :param nxpimage_data_dir: Base directory containing test data files.
    :param family: Target MCU family name for MBI operations.
    :param config_file: Configuration file name for MBI creation.
    :param sign_digest: Optional signing digest method for the MBI.
    """
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
    nxpimage_data_dir: str,
    tmpdir: str,
    mbi_config_file: str,
    cert_block_config_file: str,
    device: str,
) -> None:
    """Test MBI certificate block signed image generation and validation.

    This test validates the complete workflow of generating a signed MBI (Master Boot Image)
    with certificate block, comparing it against reference binaries, and verifying the
    cryptographic signatures to ensure proper signing functionality.

    :param cli_runner: CLI test runner for executing nxpimage commands
    :param nxpimage_data_dir: Directory containing test data and configuration files
    :param tmpdir: Temporary directory for output files during testing
    :param mbi_config_file: Configuration file name for MBI generation
    :param cert_block_config_file: Configuration file name for certificate block generation
    :param device: Target device name for the MBI configuration
    :raises AssertionError: When generated binaries don't match reference or signature verification fails
    """
    with use_working_directory(nxpimage_data_dir):
        cert_config_file = f"{nxpimage_data_dir}/workspace/cfgs/cert_block/{cert_block_config_file}"
        mbi_config_file = f"{nxpimage_data_dir}/workspace/cfgs/{device}/{mbi_config_file}"
        mbi_ref_binary, mbi_new_binary, mbi_new_config = process_config_file(
            mbi_config_file, tmpdir
        )
        cert_ref_binary, cert_new_binary, cert_new_config = process_config_file(
            cert_config_file, tmpdir
        )

        cmd = f"cert-block export -c {cert_new_config} -oc family={device}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(cert_new_binary)

        # validate cert file file lengths
        cert_ref_data = load_binary(cert_ref_binary)
        cert_new_data = load_binary(cert_new_binary)
        assert len(cert_ref_data) == len(cert_new_data)
        isk_key = get_signer_key(Config.create_from_file(cert_new_config))
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

        signing_key = get_signer_key(Config.create_from_file(mbi_config_file))
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
    nxpimage_data_dir: str,
    tmpdir: str,
    mbi_config_file: str,
    cert_block_config_file: str,
    device: str,
) -> None:
    """Test MBI certificate block export with signed invalid configuration.

    This test verifies that the MBI export command properly handles and rejects
    invalid signed certificate block configurations. It creates certificate blocks,
    validates their structure and content, then attempts MBI export which should
    fail with the invalid configuration.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param nxpimage_data_dir: Directory path containing test data files.
    :param tmpdir: Temporary directory path for test outputs.
    :param mbi_config_file: MBI configuration file name.
    :param cert_block_config_file: Certificate block configuration file name.
    :param device: Target device name for configuration.
    """
    with use_working_directory(nxpimage_data_dir):
        cert_config_file = f"{nxpimage_data_dir}/workspace/cfgs/cert_block/{cert_block_config_file}"
        mbi_config_file = f"{nxpimage_data_dir}/workspace/cfgs/{device}/{mbi_config_file}"
        mbi_ref_binary, mbi_new_binary, mbi_new_config = process_config_file(
            mbi_config_file, tmpdir
        )
        cert_ref_binary, cert_new_binary, cert_new_config = process_config_file(
            cert_config_file, tmpdir
        )

        cmd = f"cert-block export -c {cert_new_config} -oc family={device}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(cert_new_binary)

        # validate cert file file lengths
        cert_ref_data = load_binary(cert_ref_binary)
        cert_new_data = load_binary(cert_new_binary)
        assert len(cert_ref_data) == len(cert_new_data)
        isk_key = get_signer_key(Config.create_from_file(cert_new_config))
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
    cli_runner: CliRunner,
    nxpimage_data_dir: str,
    tmpdir: str,
    config_file: str,
    device: str,
    skip_hmac_keystore: int,
) -> None:
    """Test legacy signed MBI export functionality.

    Validates that the nxpimage MBI export command correctly generates signed MBI files
    by comparing output with reference binaries and verifying cryptographic signatures.
    The test handles different HMAC and keystore configurations.

    :param cli_runner: Click CLI test runner for command execution.
    :param nxpimage_data_dir: Directory containing test data and configuration files.
    :param tmpdir: Temporary directory for test output files.
    :param config_file: Name of the MBI configuration file to use for testing.
    :param device: Target device name for configuration selection.
    :param skip_hmac_keystore: HMAC/keystore configuration flag (0=none, 1=HMAC only, 2=HMAC+keystore).
    """
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

        signing_key = PrivateKeyRsa.load(config_data["signer"])
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
    cli_runner: CliRunner,
    tmpdir: str,
    nxpimage_data_dir: str,
    family: str,
    config_file: str,
    skip_hmac_keystore: int,
) -> None:
    """Test MBI parser functionality with legacy signed images.

    This test creates a new MBI (Master Boot Image) file using the export command,
    then parses it back and verifies that the parsed application binary matches
    the original input image when applicable.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory path for test files.
    :param nxpimage_data_dir: Base directory containing test data files.
    :param family: Target MCU family name for MBI operations.
    :param config_file: Configuration file name for MBI creation.
    :param skip_hmac_keystore: Flag to skip HMAC keystore operations.
    """
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
    cli_runner: CliRunner, nxpimage_data_dir: str, tmpdir: str, config_file: str, device: str
) -> None:
    """Test nxpimage MBI export with invalid configuration file.

    This test verifies that the nxpimage MBI export command properly handles
    invalid configuration files and returns the expected error code.

    :param cli_runner: CLI test runner for invoking commands.
    :param nxpimage_data_dir: Directory containing test data for nxpimage.
    :param tmpdir: Temporary directory for test files.
    :param config_file: Name of the configuration file to test.
    :param device: Target device name for the configuration.
    """
    with use_working_directory(nxpimage_data_dir):
        config_file = f"{nxpimage_data_dir}/workspace/cfgs/{device}/{config_file}"
        _, _, new_config = process_config_file(config_file, tmpdir)

        cmd = f"mbi export -c {new_config}"
        cli_runner.invoke(nxpimage.main, cmd.split(), expected_code=1)


@pytest.mark.parametrize("config_file,device,skip_hmac_keystore", mbi_legacy_encrypted_tests)
def test_nxpimage_mbi_legacy_encrypted(
    cli_runner: CliRunner,
    nxpimage_data_dir: str,
    tmpdir: str,
    config_file: str,
    device: str,
    skip_hmac_keystore: int,
) -> None:
    """Test nxpimage MBI legacy encrypted functionality.

    This test validates the MBI (Master Boot Image) export functionality for legacy
    encrypted images. It processes a configuration file, exports an MBI using the
    nxpimage CLI, and validates the generated binary against a reference by comparing
    file lengths, signature verification, and data integrity. The test handles
    different HMAC and keystore configurations based on the skip_hmac_keystore parameter.

    :param cli_runner: Click CLI test runner for invoking nxpimage commands.
    :param nxpimage_data_dir: Directory path containing test data files.
    :param tmpdir: Temporary directory path for output files.
    :param config_file: Configuration file name for MBI generation.
    :param device: Target device name for the test.
    :param skip_hmac_keystore: HMAC/keystore configuration flag (0=none, 1=HMAC only, 2=HMAC+keystore).
    """
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

        signing_key = PrivateKeyRsa.load(config_data["signer"])

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
    cli_runner: CliRunner,
    tmpdir: str,
    nxpimage_data_dir: str,
    family: str,
    config_file: str,
    skip_hmac_keystore: int,
) -> None:
    """Test MBI parser functionality with legacy encrypted images.

    This test verifies that the MBI parser can correctly handle legacy encrypted
    images by creating a new MBI file from configuration, then parsing it back
    and comparing the extracted application binary with the original input.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory path for test outputs.
    :param nxpimage_data_dir: Base directory containing test data files.
    :param family: Target MCU family name for MBI operations.
    :param config_file: Configuration file name for MBI creation.
    :param skip_hmac_keystore: Flag to skip HMAC keystore validation.
    """
    # Create new MBI file
    mbi_data_dir = os.path.join(nxpimage_data_dir, "workspace")
    config_file = os.path.join(mbi_data_dir, "cfgs", family, config_file)

    _, new_binary, new_config = process_config_file(config_file, tmpdir)

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


def test_mbi_lpc55s3x_invalid() -> None:
    """Test MBI validation with invalid configuration for LPC55S3X family.

    This test verifies that the MasterBootImage validation properly detects
    and raises an SPSDKError when created with invalid parameters for the
    LPC55S3X family using signed XIP configuration.

    :raises SPSDKError: Expected exception when MBI validation fails due to invalid configuration.
    """
    family = FamilyRevision("lpc55s3x")
    mbi = MasterBootImage.create_mbi_class("signed_xip", family)(
        family=family, app=bytes(100), firmware_version=0
    )
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
        "mcxe31b",
    ],
)
def test_mbi_get_templates(cli_runner: CliRunner, tmpdir: str, family: str) -> None:
    """Test MBI get-templates command functionality.

    Verifies that the MBI get-templates CLI command successfully generates
    template files for all supported image configurations of a given family.
    The test checks command execution and validates that all expected template
    files are created in the output directory.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory path for output files.
    :param family: Target MCU family name for template generation.
    """
    cmd = f"mbi get-templates -f {family} --output {tmpdir}"
    result = cli_runner.invoke(nxpimage.main, cmd.split())
    assert result.exit_code == 0
    images = get_db(FamilyRevision(family)).get_dict(DatabaseManager.MBI, "images")

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
    cli_runner: CliRunner,
    tmpdir: str,
    data_dir: str,
    family: str,
    template_name: str,
    keys_to_copy: list[str],
) -> None:
    """Test MBI export functionality with sign provider.

    This test verifies that the MBI (Master Boot Image) export command works correctly
    with a signing provider by setting up a temporary environment with configuration
    files, keys, certificates, and input images, then executing the export command
    and validating the output file is created.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory path for test files.
    :param data_dir: Base directory containing test data files.
    :param family: Target MCU family name for the MBI configuration.
    :param template_name: Name of the configuration template file to use.
    :param keys_to_copy: List of key file names to copy to temporary directory.
    """
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
    cli_runner: CliRunner,
    tmpdir: str,
    data_dir: str,
    family: str,
    template_name: str,
    keys_to_copy: list[str],
) -> None:
    """Test MBI export with invalid sign provider configuration.

    This test verifies that the MBI export command properly handles and fails
    when provided with an invalid sign provider configuration. It sets up a
    temporary environment with configuration files and required assets, then
    attempts to export an MBI image expecting the operation to fail.

    :param cli_runner: CLI test runner for executing nxpimage commands.
    :param tmpdir: Temporary directory path for test files.
    :param data_dir: Base directory containing test data files.
    :param family: Target MCU family for the MBI configuration.
    :param template_name: Name of the configuration template file to use.
    :param keys_to_copy: List of key file names to copy to temporary directory.
    """
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
    "main_root_cert_id,sign_provider,exit_code",
    [
        (0, "type=file;file_path=k0_cert0_2048.pem", 0),
        (None, "type=file;file_path=k0_cert0_2048.pem", 0),
        (None, "type=file;file_path=k2_cert0_2048.pem", 1),
        (0, "type=file;file_path=k2_cert0_2048.pem", 1),
    ],
)
def test_mbi_signature_provider(
    cli_runner: CliRunner,
    data_dir: str,
    tmpdir: str,
    main_root_cert_id: Optional[int],
    sign_provider: str,
    exit_code: int,
) -> None:
    """Test MBI signature provider functionality with different configurations.

    This test function validates the MBI (Master Boot Image) export command with various
    signature providers and certificate configurations. It sets up a temporary test
    environment by copying required keys, certificates, and application files, then
    modifies configuration files to test different signing scenarios.

    :param cli_runner: CLI test runner for executing nxpimage commands.
    :param data_dir: Directory containing test data files including keys, certificates, and configurations.
    :param tmpdir: Temporary directory for test file operations and outputs.
    :param main_root_cert_id: Optional main root certificate ID to use in certificate block configuration.
    :param sign_provider: Signature provider configuration string to test.
    :param exit_code: Expected exit code from the CLI command execution.
    """
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
        config_data["signer"] = sign_provider
    config_file = os.path.join(tmpdir, "ext_xip_signed_rt5xx.yaml")
    with open(config_file, "w") as fp:
        yaml.dump(config_data, fp)

    cert_config_data = load_configuration(os.path.join(data_dir, "mbi", config_data["certBlock"]))
    if sign_provider:
        cert_config_data["signer"] = sign_provider
    if main_root_cert_id is not None:
        cert_config_data["mainRootCertId"] = main_root_cert_id
    cert_config_file = os.path.join(tmpdir, config_data["certBlock"])
    with open(cert_config_file, "w") as fp:
        yaml.dump(cert_config_data, fp)
    cmd = f"mbi export -c {config_file}"
    cli_runner.invoke(nxpimage.main, cmd.split(), expected_code=exit_code)
