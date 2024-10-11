#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import os
from binascii import unhexlify
from itertools import zip_longest

import pytest
from test_nxpimage_sb31 import process_config_file

import spsdk.apps.nxpimage as nxpimage
from spsdk.exceptions import SPSDKError
from spsdk.sbfile.sb2.images import BootImageV21
from spsdk.utils.misc import load_configuration, use_working_directory
from tests.cli_runner import CliRunner

SB21_TEST_CONFIGURATIONS = [
    (
        "sb_sources/BD_files/real_example1.bd",
        "sb_sources/SB_files/legacy_real_example1.sb",
        [],
        "rt5xx",
    ),
    (
        "sb_sources/BD_files/real_example2.bd",
        "sb_sources/SB_files/legacy_real_example2.sb",
        [
            "sb_sources/output_images/tmdData.bin",
            "sb_sources/output_images/bootloaderImage.bin",
            "sb_sources/output_images/tmdImage.bin",
            "sb_sources/output_images/audioImage.bin",
        ],
        "rt6xx",
    ),
    (
        "sb_sources/BD_files/real_example3.bd",
        "sb_sources/SB_files/legacy_real_example3.sb",
        [],
        "rt5xx",
    ),
    (
        "sb_sources/BD_files/real_example3_test_options.bd",
        "sb_sources/SB_files/legacy_real_example3_test_options.sb",
        [],
        "rt5xx",
    ),
    (
        "sb_sources/BD_files/simpleExample_no_sha.bd",
        "sb_sources/SB_files/legacy_elftosb_no_sha.bin",
        [],
        "rt5xx",
    ),
    (
        "sb_sources/BD_files/simpleExample_sha.bd",
        "sb_sources/SB_files/legacy_elftosb_sha.bin",
        [],
        "rt5xx",
    ),
]


@pytest.mark.parametrize("use_signature_provider", [True, False])
@pytest.mark.parametrize("bd_file,legacy_sb,external,family", SB21_TEST_CONFIGURATIONS)
def test_nxpimage_sb21(
    cli_runner: CliRunner,
    use_signature_provider,
    bd_file,
    legacy_sb,
    external,
    nxpimage_data_dir,
    family,
    tmpdir,
):
    with use_working_directory(nxpimage_data_dir):
        bd_file_path = os.path.join(nxpimage_data_dir, bd_file)
        out_file_path_new = os.path.join(tmpdir, "new_elf2sb.bin")
        kek_key_path = os.path.join(nxpimage_data_dir, "sb_sources/keys/SBkek_PUF.txt")
        pkey = os.path.join(nxpimage_data_dir, "sb_sources/keys_and_certs/k0_cert0_2048.pem")
        if use_signature_provider:
            pkey = f"type=file;file_path={pkey}"
        certificate_path = os.path.join(
            nxpimage_data_dir, "sb_sources/keys_and_certs/root_k0_signed_cert0_noca.der.cert"
        )
        root_key_certificate0_path = os.path.join(
            nxpimage_data_dir, "sb_sources/keys_and_certs/root_k0_signed_cert0_noca.der.cert"
        )
        root_key_certificate1_path = os.path.join(
            nxpimage_data_dir, "sb_sources/keys_and_certs/root_k1_signed_cert0_noca.der.cert"
        )
        root_key_certificate2_path = os.path.join(
            nxpimage_data_dir, "sb_sources/keys_and_certs/root_k2_signed_cert0_noca.der.cert"
        )
        root_key_certificate3_path = os.path.join(
            nxpimage_data_dir, "sb_sources/keys_and_certs/root_k3_signed_cert0_noca.der.cert"
        )
        hash_of_hashes_output_path = os.path.join(tmpdir, "hash.bin")

        out_file_path_legacy = os.path.join(nxpimage_data_dir, legacy_sb)

        cmd = [
            "sb21",
            "export",
            "-c",
            bd_file_path,
            "-o",
            out_file_path_new,
            "-k",
            kek_key_path,
            "-s",
            pkey,
            "-S",
            certificate_path,
            "-R",
            root_key_certificate0_path,
            "-R",
            root_key_certificate1_path,
            "-R",
            root_key_certificate2_path,
            "-R",
            root_key_certificate3_path,
            "-h",
            hash_of_hashes_output_path,
        ]
        for entry in external:
            cmd.append(entry)
        cli_runner.invoke(nxpimage.main, cmd)
        assert os.path.isfile(out_file_path_new)

        with open(kek_key_path) as f:
            # transform text-based KEK into bytes
            sb_kek = unhexlify(f.read())

        # read generated secure binary image (created with new elf2sb)
        with open(out_file_path_new, "rb") as f:
            sb_file_data_new = f.read()

        sb_new = BootImageV21.parse(data=sb_file_data_new, kek=sb_kek)

        # dump the info of the secure binary image generated with new elf2sb
        # Left for debugging purposes
        # with open(os.path.join(nxpimage_data_dir, "SB_files/new_elf2sb_sb21_file.txt"), 'w') as sb_file_content:
        #     sb_file_content.write(sb_new.__str__())

        # read SB file generated using legacy elftosb
        with open(out_file_path_legacy, "rb") as f:
            sb_file_data_old = f.read()

        # we assume that SB File version is 2.1
        sb_old = BootImageV21.parse(data=sb_file_data_old, kek=sb_kek)

        # dump the info of the secure binary image generated with legacy elftosb
        # Left for debugging purposes
        # with open(os.path.join(nxpimage_data_dir, "SB_files/old_elf2sb_sb21_file.txt"), 'w') as f:
        #     f.write(str(sb_old))

        sb_new_lines = str(sb_new).split("\n")
        sb_old_lines = str(sb_old).split("\n")

        DIGEST_LINE = 4
        TIMESTAMP_LINE = 14
        # Remove lines containing digest and timestamp, as these will always differ
        # -1 for indexing starting from 0
        del sb_new_lines[DIGEST_LINE - 1]
        # -1 for indexing starting from 0, -1 for previously removed line => -2
        del sb_new_lines[TIMESTAMP_LINE - 2]

        # -1 for indexing starting from 0
        del sb_old_lines[DIGEST_LINE - 1]
        # -1 for indexing starting from 0, -1 for previously removed line => -2
        del sb_old_lines[TIMESTAMP_LINE - 2]

        for i in zip_longest(sb_new_lines, sb_old_lines, fillvalue=None):
            assert i[0] == i[1]


def test_sb_21_invalid_signature_provider(cli_runner: CliRunner, tmpdir, nxpimage_data_dir):
    with use_working_directory(nxpimage_data_dir):
        cmd = [
            "sb21",
            "export",
            "-c",
            os.path.join(nxpimage_data_dir, "sb_sources", "BD_files", "real_example1.bd"),
            "-o",
            os.path.join(tmpdir, "new_elf2sb.bin"),
            "-k",
            os.path.join(nxpimage_data_dir, "sb_sources", "keys", "SBkek_PUF.txt"),
            "-s",
            "type=invalid_sp",
            "-S",
            os.path.join(
                nxpimage_data_dir,
                "sb_sources",
                "keys_and_certs",
                "root_k0_signed_cert0_noca.der.cert",
            ),
            "-R",
            os.path.join(
                nxpimage_data_dir,
                "sb_sources",
                "keys_and_certs",
                "root_k0_signed_cert0_noca.der.cert",
            ),
            "-R",
            os.path.join(
                nxpimage_data_dir,
                "sb_sources",
                "keys_and_certs",
                "root_k1_signed_cert0_noca.der.cert",
            ),
            "-R",
            os.path.join(
                nxpimage_data_dir,
                "sb_sources",
                "keys_and_certs",
                "root_k2_signed_cert0_noca.der.cert",
            ),
            "-R",
            os.path.join(
                nxpimage_data_dir,
                "sb_sources",
                "keys_and_certs",
                "root_k3_signed_cert0_noca.der.cert",
            ),
            "-h",
            os.path.join(tmpdir, "hash.bin"),
        ]
        result = cli_runner.invoke(nxpimage.main, cmd, expected_code=1)
        assert issubclass(result.exc_info[0], SPSDKError)


def test_sb_21_invalid_parse():
    with pytest.raises(SPSDKError, match="kek cannot be empty"):
        BootImageV21.parse(data=bytes(232), kek=None)


def test_nxpimage_sbkek_cli(cli_runner: CliRunner, tmpdir):
    cmd = "sb21 get-sbkek"
    cli_runner.invoke(nxpimage.main, cmd.split())

    cmd = f"sb21 get-sbkek -o {tmpdir}"
    cli_runner.invoke(nxpimage.main, cmd.split())
    assert os.path.isfile(os.path.join(tmpdir, "sbkek.bin"))
    assert os.path.isfile(os.path.join(tmpdir, "sbkek.txt"))

    test_key = "858A4A83D07C78656165CDDD3B7AF4BB20E534392E7AF99EF7C296F95205E680"

    cmd = f"sb21 get-sbkek -k {test_key} -o {tmpdir}"
    cli_runner.invoke(nxpimage.main, cmd.split())
    assert os.path.isfile(os.path.join(tmpdir, "sbkek.bin"))
    assert os.path.isfile(os.path.join(tmpdir, "sbkek.txt"))


@pytest.mark.parametrize("use_signature_provider", [True, False])
@pytest.mark.parametrize(
    "bd_file,legacy_sb,external",
    [
        (
            "sb_sources/BD_files/real_example1_relative.bd",
            "sb_sources/SB_files/legacy_real_example1.sb",
            [],
        ),
    ],
)
def test_nxpimage_relative_path_sb21(
    cli_runner: CliRunner,
    use_signature_provider,
    bd_file,
    legacy_sb,
    external,
    nxpimage_data_dir,
    tmpdir,
):
    bd_file_path = os.path.join(nxpimage_data_dir, bd_file)
    out_file_path_new = os.path.join(tmpdir, "new_elf2sb.bin")
    kek_key_path = os.path.join(nxpimage_data_dir, "sb_sources/keys/SBkek_PUF.txt")
    pkey = os.path.join(nxpimage_data_dir, "sb_sources/keys_and_certs/k0_cert0_2048.pem")
    if use_signature_provider:
        pkey = f"type=file;file_path={pkey}"
    certificate_path = os.path.join(
        nxpimage_data_dir, "sb_sources/keys_and_certs/root_k0_signed_cert0_noca.der.cert"
    )
    root_key_certificate0_path = os.path.join(
        nxpimage_data_dir, "sb_sources/keys_and_certs/root_k0_signed_cert0_noca.der.cert"
    )
    root_key_certificate1_path = os.path.join(
        nxpimage_data_dir, "sb_sources/keys_and_certs/root_k1_signed_cert0_noca.der.cert"
    )
    root_key_certificate2_path = os.path.join(
        nxpimage_data_dir, "sb_sources/keys_and_certs/root_k2_signed_cert0_noca.der.cert"
    )
    root_key_certificate3_path = os.path.join(
        nxpimage_data_dir, "sb_sources/keys_and_certs/root_k3_signed_cert0_noca.der.cert"
    )
    hash_of_hashes_output_path = os.path.join(tmpdir, "hash.bin")

    out_file_path_legacy = os.path.join(nxpimage_data_dir, legacy_sb)

    cmd = [
        "sb21",
        "export",
        "-c",
        bd_file_path,
        "-o",
        out_file_path_new,
        "-k",
        kek_key_path,
        "-s",
        pkey,
        "-S",
        certificate_path,
        "-R",
        root_key_certificate0_path,
        "-R",
        root_key_certificate1_path,
        "-R",
        root_key_certificate2_path,
        "-R",
        root_key_certificate3_path,
        "-h",
        hash_of_hashes_output_path,
    ]
    for entry in external:
        cmd.append(entry)
    cli_runner.invoke(nxpimage.main, cmd)
    assert os.path.isfile(out_file_path_new)

    with open(kek_key_path) as f:
        # transform text-based KEK into bytes
        sb_kek = unhexlify(f.read())

    # read generated secure binary image (created with new elf2sb)
    with open(out_file_path_new, "rb") as f:
        sb_file_data_new = f.read()

    sb_new = BootImageV21.parse(data=sb_file_data_new, kek=sb_kek)

    # dump the info of the secure binary image generated with new elf2sb
    # Left for debugging purposes
    # with open(os.path.join(nxpimage_data_dir, "SB_files/new_elf2sb_sb21_file.txt"), 'w') as sb_file_content:
    #     sb_file_content.write(sb_new.__str__())

    # read SB file generated using legacy elftosb
    with open(out_file_path_legacy, "rb") as f:
        sb_file_data_old = f.read()

    # we assume that SB File version is 2.1
    sb_old = BootImageV21.parse(data=sb_file_data_old, kek=sb_kek)

    # dump the info of the secure binary image generated with legacy elftosb
    # Left for debugging purposes
    # with open(os.path.join(nxpimage_data_dir, "SB_files/old_elf2sb_sb21_file.txt"), 'w') as f:
    #     f.write(str(sb_old))

    sb_new_lines = str(sb_new).split("\n")
    sb_old_lines = str(sb_old).split("\n")

    DIGEST_LINE = 4
    TIMESTAMP_LINE = 14
    # Remove lines containing digest and timestamp, as these will always differ
    # -1 for indexing starting from 0
    del sb_new_lines[DIGEST_LINE - 1]
    # -1 for indexing starting from 0, -1 for previously removed line => -2
    del sb_new_lines[TIMESTAMP_LINE - 2]

    # -1 for indexing starting from 0
    del sb_old_lines[DIGEST_LINE - 1]
    # -1 for indexing starting from 0, -1 for previously removed line => -2
    del sb_old_lines[TIMESTAMP_LINE - 2]

    for i in zip_longest(sb_new_lines, sb_old_lines, fillvalue=None):
        assert i[0] == i[1]


@pytest.mark.parametrize(
    "family",
    [
        "lpc55s06",
        "lpc55s16",
        "lpc55s26",
        "lpc55s69",
        "mimxrt595s",
        "mimxrt685s",
    ],
)
def test_nxpimage_sb21_get_template(cli_runner: CliRunner, tmpdir, family):
    cmd = f"sb21 get-template -f {family} -o {tmpdir}/tmp.yaml"
    cli_runner.invoke(nxpimage.main, cmd.split())
    assert os.path.isfile(f"{tmpdir}/tmp.yaml")
    config = load_configuration(f"{tmpdir}/tmp.yaml")
    assert config["family"] == family


@pytest.mark.parametrize("bd_file,legacy_sb,external,family", SB21_TEST_CONFIGURATIONS)
def test_nxpimage_sb21_convert(
    cli_runner: CliRunner, bd_file, legacy_sb, external, nxpimage_data_dir, family, tmpdir
):
    with use_working_directory(nxpimage_data_dir):
        bd_file_path = os.path.join(nxpimage_data_dir, bd_file)
        out_file_path_new = os.path.join(tmpdir, "config.yaml")
        kek_key_path = os.path.join(nxpimage_data_dir, "sb_sources/keys/SBkek_PUF.txt")
        pkey = os.path.join(nxpimage_data_dir, "sb_sources/keys_and_certs/k0_cert0_2048.pem")

        certificate_path = os.path.join(
            nxpimage_data_dir, "sb_sources/keys_and_certs/root_k0_signed_cert0_noca.der.cert"
        )
        root_key_certificate0_path = os.path.join(
            nxpimage_data_dir, "sb_sources/keys_and_certs/root_k0_signed_cert0_noca.der.cert"
        )
        root_key_certificate1_path = os.path.join(
            nxpimage_data_dir, "sb_sources/keys_and_certs/root_k1_signed_cert0_noca.der.cert"
        )
        root_key_certificate2_path = os.path.join(
            nxpimage_data_dir, "sb_sources/keys_and_certs/root_k2_signed_cert0_noca.der.cert"
        )
        root_key_certificate3_path = os.path.join(
            nxpimage_data_dir, "sb_sources/keys_and_certs/root_k3_signed_cert0_noca.der.cert"
        )
        hash_of_hashes_output_path = os.path.join(tmpdir, "hash.bin")

        out_file_path_legacy = os.path.join(nxpimage_data_dir, legacy_sb)

        cmd = [
            "sb21",
            "convert",
            "-c",
            bd_file_path,
            "-o",
            out_file_path_new,
            "-k",
            kek_key_path,
            "-s",
            pkey,
            "-S",
            certificate_path,
            "-R",
            root_key_certificate0_path,
            "-R",
            root_key_certificate1_path,
            "-R",
            root_key_certificate2_path,
            "-R",
            root_key_certificate3_path,
            "-h",
            hash_of_hashes_output_path,
            "-f",
            family,
        ]
        for entry in external:
            cmd.append(entry)
        cli_runner.invoke(nxpimage.main, cmd)
        assert os.path.isfile(out_file_path_new)

        sb_file_path_new = os.path.join(tmpdir, "output.sb")

        cmd = ["sb21", "export", "-c", out_file_path_new, "-o", sb_file_path_new]

        cli_runner.invoke(nxpimage.main, cmd)
        assert os.path.isfile(sb_file_path_new)

        with open(kek_key_path) as f:
            # transform text-based KEK into bytes
            sb_kek = unhexlify(f.read())

        # read generated secure binary image (created with new elf2sb)
        with open(sb_file_path_new, "rb") as f:
            sb_file_data_new = f.read()

        sb_new = BootImageV21.parse(data=sb_file_data_new, kek=sb_kek)

        # dump the info of the secure binary image generated with new elf2sb
        # Left for debugging purposes
        # with open(os.path.join(nxpimage_data_dir, "SB_files/new_elf2sb_sb21_file.txt"), 'w') as sb_file_content:
        #     sb_file_content.write(sb_new.__str__())

        # read SB file generated using legacy elftosb
        with open(out_file_path_legacy, "rb") as f:
            sb_file_data_old = f.read()

        # we assume that SB File version is 2.1
        sb_old = BootImageV21.parse(data=sb_file_data_old, kek=sb_kek)

        # dump the info of the secure binary image generated with legacy elftosb
        # Left for debugging purposes
        # with open(os.path.join(nxpimage_data_dir, "SB_files/old_elf2sb_sb21_file.txt"), 'w') as f:
        #     f.write(str(sb_old))

        sb_new_lines = str(sb_new).split("\n")
        sb_old_lines = str(sb_old).split("\n")

        DIGEST_LINE = 4
        TIMESTAMP_LINE = 14
        # Remove lines containing digest and timestamp, as these will always differ
        # -1 for indexing starting from 0
        del sb_new_lines[DIGEST_LINE - 1]
        # -1 for indexing starting from 0, -1 for previously removed line => -2
        del sb_new_lines[TIMESTAMP_LINE - 2]

        # -1 for indexing starting from 0
        del sb_old_lines[DIGEST_LINE - 1]
        # -1 for indexing starting from 0, -1 for previously removed line => -2
        del sb_old_lines[TIMESTAMP_LINE - 2]

        for i in zip_longest(sb_new_lines, sb_old_lines, fillvalue=None):
            assert i[0] == i[1]


def test_sb_21_invalid_signature_provider(cli_runner: CliRunner, tmpdir, nxpimage_data_dir):
    with use_working_directory(nxpimage_data_dir):
        cmd = [
            "sb21",
            "export",
            "-c",
            os.path.join(nxpimage_data_dir, "sb_sources", "BD_files", "real_example1.bd"),
            "-o",
            os.path.join(tmpdir, "new_elf2sb.bin"),
            "-k",
            os.path.join(nxpimage_data_dir, "sb_sources", "keys", "SBkek_PUF.txt"),
            "-s",
            "type=invalid_sp",
            "-S",
            os.path.join(
                nxpimage_data_dir,
                "sb_sources",
                "keys_and_certs",
                "root_k0_signed_cert0_noca.der.cert",
            ),
            "-R",
            os.path.join(
                nxpimage_data_dir,
                "sb_sources",
                "keys_and_certs",
                "root_k0_signed_cert0_noca.der.cert",
            ),
            "-R",
            os.path.join(
                nxpimage_data_dir,
                "sb_sources",
                "keys_and_certs",
                "root_k1_signed_cert0_noca.der.cert",
            ),
            "-R",
            os.path.join(
                nxpimage_data_dir,
                "sb_sources",
                "keys_and_certs",
                "root_k2_signed_cert0_noca.der.cert",
            ),
            "-R",
            os.path.join(
                nxpimage_data_dir,
                "sb_sources",
                "keys_and_certs",
                "root_k3_signed_cert0_noca.der.cert",
            ),
            "-h",
            os.path.join(tmpdir, "hash.bin"),
        ]
        result = cli_runner.invoke(nxpimage.main, cmd, expected_code=1)
        assert issubclass(result.exc_info[0], SPSDKError)


def test_sb_21_invalid_parse():
    with pytest.raises(SPSDKError, match="kek cannot be empty"):
        BootImageV21.parse(data=bytes(232), kek=None)


def test_nxpimage_sbkek_cli(cli_runner: CliRunner, tmpdir):
    cmd = "sb21 get-sbkek"
    cli_runner.invoke(nxpimage.main, cmd.split())

    cmd = f"sb21 get-sbkek -o {tmpdir}"
    cli_runner.invoke(nxpimage.main, cmd.split())
    assert os.path.isfile(os.path.join(tmpdir, "sbkek.bin"))
    assert os.path.isfile(os.path.join(tmpdir, "sbkek.txt"))

    test_key = "858A4A83D07C78656165CDDD3B7AF4BB20E534392E7AF99EF7C296F95205E680"

    cmd = f"sb21 get-sbkek -k {test_key} -o {tmpdir}"
    cli_runner.invoke(nxpimage.main, cmd.split())
    assert os.path.isfile(os.path.join(tmpdir, "sbkek.bin"))
    assert os.path.isfile(os.path.join(tmpdir, "sbkek.txt"))


def test_nxpimage_parse_cli(cli_runner: CliRunner, tmpdir, nxpimage_data_dir):
    with use_working_directory(f"{nxpimage_data_dir}/sb_sources"):
        parsed_output = f"{tmpdir}/parsed_sb"
        cmd = f"sb21 parse -b SB_files/legacy_real_example1.sb -k keys/SBkek_PUF.txt -o {parsed_output}"
        cli_runner.invoke(nxpimage.main, cmd.split())

        assert os.path.isfile(os.path.join(parsed_output, "certificate_0_der.cer"))
        assert os.path.isfile(os.path.join(parsed_output, "parsed_info.txt"))
        assert os.path.isfile(os.path.join(parsed_output, "section_0_load_command_3_data.bin"))
        assert os.path.isfile(os.path.join(parsed_output, "section_0_load_command_9_data.bin"))


def test_nxpimage_parse_cli_invalid(cli_runner: CliRunner, tmpdir, nxpimage_data_dir):
    with use_working_directory(f"{nxpimage_data_dir}/sb_sources"):
        parsed_output = f"{tmpdir}/parsed_sb"
        cmd = f"sb21 parse -b SB_files/corrupted.sb -k keys/SBkek_PUF.txt -o {parsed_output}"
        cli_runner.invoke(nxpimage.main, cmd.split(), expected_code=1)


@pytest.mark.parametrize("bd_file,legacy_sb,external,family", SB21_TEST_CONFIGURATIONS)
def test_nxpimage_sb21_hex_values(bd_file, legacy_sb, external, nxpimage_data_dir, family, tmpdir):
    """Test that also hex values in configuration are accepted."""
    with use_working_directory(nxpimage_data_dir):
        parsed_config = BootImageV21.parse_sb21_config(bd_file, external_files=external)

        # update all options which may be also a hex string
        parsed_config["options"]["flags"] = hex(parsed_config["options"]["flags"])
        for key_blob in parsed_config.get("keyblobs", {}):
            if isinstance(key_blob["keyblob_content"], list):
                key_blob["keyblob_content"][0]["start"] = hex(
                    key_blob["keyblob_content"][0]["start"]
                )
                key_blob["keyblob_content"][0]["end"] = hex(key_blob["keyblob_content"][0]["end"])
            else:
                key_blob["keyblob_content"]["start"] = hex(key_blob["keyblob_content"]["start"])
                key_blob["keyblob_content"]["end"] = hex(key_blob["keyblob_content"]["end"])
        for section in parsed_config.get("sections", {}):
            for command in section.get("commands", {}):
                if "address" in command:
                    command["address"] = hex(command["address"])
                elif "pattern" in command:
                    command["pattern"] = hex(command["pattern"])
                elif "length" in command:
                    command["length"] = hex(command["length"])

        root_key_certs = [
            os.path.join(
                nxpimage_data_dir, "sb_sources/keys_and_certs/root_k0_signed_cert0_noca.der.cert"
            ),
            os.path.join(
                nxpimage_data_dir, "sb_sources/keys_and_certs/root_k1_signed_cert0_noca.der.cert"
            ),
            os.path.join(
                nxpimage_data_dir, "sb_sources/keys_and_certs/root_k2_signed_cert0_noca.der.cert"
            ),
            os.path.join(
                nxpimage_data_dir, "sb_sources/keys_and_certs/root_k3_signed_cert0_noca.der.cert"
            ),
        ]
        parsed_config["mainCertPrivateKeyFile"] = os.path.join(
            nxpimage_data_dir, "sb_sources/keys_and_certs/k0_cert0_2048.pem"
        )
        sb2 = BootImageV21.load_from_config(
            config=parsed_config,
            key_file_path=os.path.join(nxpimage_data_dir, "sb_sources/keys/SBkek_PUF.txt"),
            signing_certificate_file_paths=[
                os.path.join(
                    nxpimage_data_dir,
                    "sb_sources/keys_and_certs/root_k0_signed_cert0_noca.der.cert",
                )
            ],
            root_key_certificate_paths=root_key_certs,
            rkth_out_path=os.path.join(tmpdir, "hash.bin"),
            search_paths=[nxpimage_data_dir],
        )
        sb2.export()


@pytest.mark.parametrize("conf", ["conf1", "conf2", "conf3", "conf4", "conf5", "conf6"])
def test_nxpimage_sb21_yaml(cli_runner: CliRunner, conf, nxpimage_data_dir, tmpdir):
    KEK_PATH = os.path.join(nxpimage_data_dir, "sb_sources/keys/SBkek_PUF.txt")
    with use_working_directory(nxpimage_data_dir):
        # for conf in conf_dir:
        output_path = os.path.join(tmpdir, "output.sb")
        conf_path = os.path.join(nxpimage_data_dir, "sb_sources", "YAML_files", conf, "config.yaml")
        ref_binary, new_binary, new_config = process_config_file(conf_path, tmpdir)
        cmd = [
            "sb21",
            "export",
            "-c",
            new_config,
        ]
        cli_runner.invoke(nxpimage.main, cmd)
        assert os.path.isfile(new_binary)
        ref_path = os.path.join(nxpimage_data_dir, "sb_sources", "YAML_files", conf, ref_binary)

        with open(KEK_PATH) as f:
            # transform text-based KEK into bytes
            sb_kek = unhexlify(f.read())

        # read generated secure binary image
        with open(new_binary, "rb") as f:
            sb_file_data_new = f.read()

        sb_new = BootImageV21.parse(data=sb_file_data_new, kek=sb_kek)

        # # read reference SB file
        with open(ref_path, "rb") as f:
            sb_file_data_old = f.read()

        sb_old = BootImageV21.parse(data=sb_file_data_old, kek=sb_kek)

        sb_new_lines = str(sb_new).split("\n")
        sb_old_lines = str(sb_old).split("\n")

        DIGEST_LINE = 4
        TIMESTAMP_LINE = 14
        # Remove lines containing digest and timestamp, as these will always differ
        # -1 for indexing starting from 0
        del sb_new_lines[DIGEST_LINE - 1]
        # -1 for indexing starting from 0, -1 for previously removed line => -2
        del sb_new_lines[TIMESTAMP_LINE - 2]

        # -1 for indexing starting from 0
        del sb_old_lines[DIGEST_LINE - 1]
        # -1 for indexing starting from 0, -1 for previously removed line => -2
        del sb_old_lines[TIMESTAMP_LINE - 2]

        for i in zip_longest(sb_new_lines, sb_old_lines, fillvalue=None):
            assert i[0] == i[1]


@pytest.mark.parametrize("conf", ["advanced_params"])
def test_nxpimage_sb21_zero_padding(cli_runner: CliRunner, conf, nxpimage_data_dir, tmpdir):
    with use_working_directory(nxpimage_data_dir):
        # for conf in conf_dir:
        conf_path = os.path.join(nxpimage_data_dir, "sb_sources", "YAML_files", conf, "config.yaml")
        ref_binary, new_binary, new_config = process_config_file(conf_path, tmpdir)
        cmd = [
            "sb21",
            "export",
            "-c",
            new_config,
        ]
        cli_runner.invoke(nxpimage.main, cmd)
        assert os.path.isfile(new_binary)
        ref_path = os.path.join(nxpimage_data_dir, "sb_sources", "YAML_files", conf, ref_binary)

        # read generated secure binary image
        with open(new_binary, "rb") as f:
            sb_file_data_new = f.read()

        # # read reference SB file
        with open(ref_path, "rb") as f:
            sb_file_data_old = f.read()

        assert sb_file_data_new == sb_file_data_old
