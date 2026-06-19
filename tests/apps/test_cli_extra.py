#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Tests for CLI app commands."""

import os

import pytest

from spsdk.apps import nxpdice
from spsdk.apps import pfr as pfr_cli
from spsdk.apps.nxpimage import main as nxpimage_main
from spsdk.apps.spsdk_apps import main as spsdk_main
from tests.cli_runner import CliRunner

# Helpers

PFR_FAMILY = "lpc55s69"
PFR_AREA_CMPA = "cmpa"
PFR_AREA_CFPA = "cfpa"

MBI_FAMILY = "k32w148"

# PFR CLI tests  (spsdk/apps/pfr.py)


class TestPfrCli:
    """Tests for the pfr CLI application."""

    def test_pfr_help(self, cli_runner: CliRunner) -> None:
        """Test pfr --help."""
        result = cli_runner.invoke(pfr_cli.main, ["--help"])
        assert "Show this message and exit." in result.output

    def test_pfr_get_template_help(self, cli_runner: CliRunner) -> None:
        """Test pfr get-template --help."""
        result = cli_runner.invoke(pfr_cli.main, ["get-template", "--help"])
        assert "Show this message and exit." in result.output

    def test_pfr_get_templates_help(self, cli_runner: CliRunner) -> None:
        """Test pfr get-templates --help."""
        result = cli_runner.invoke(pfr_cli.main, ["get-templates", "--help"])
        assert "Show this message and exit." in result.output

    def test_pfr_parse_help(self, cli_runner: CliRunner) -> None:
        """Test pfr parse --help."""
        result = cli_runner.invoke(pfr_cli.main, ["parse", "--help"])
        assert "Show this message and exit." in result.output

    def test_pfr_export_help(self, cli_runner: CliRunner) -> None:
        """Test pfr export --help."""
        result = cli_runner.invoke(pfr_cli.main, ["export", "--help"])
        assert "Show this message and exit." in result.output

    def test_pfr_write_help(self, cli_runner: CliRunner) -> None:
        """Test pfr write --help."""
        result = cli_runner.invoke(pfr_cli.main, ["write", "--help"])
        assert "Show this message and exit." in result.output

    def test_pfr_read_help(self, cli_runner: CliRunner) -> None:
        """Test pfr read --help."""
        result = cli_runner.invoke(pfr_cli.main, ["read", "--help"])
        assert "Show this message and exit." in result.output

    def test_pfr_erase_cmpa_help(self, cli_runner: CliRunner) -> None:
        """Test pfr erase-cmpa --help."""
        result = cli_runner.invoke(pfr_cli.main, ["erase-cmpa", "--help"])
        assert "Show this message and exit." in result.output

    def test_pfr_get_families(self, cli_runner: CliRunner) -> None:
        """Test pfr get-families lists supported families."""
        result = cli_runner.invoke(pfr_cli.main, ["get-families"])
        assert result.output  # Should have output listing families

    def test_pfr_get_template_cmpa(self, cli_runner: CliRunner, tmp_path: str) -> None:
        """Test pfr get-template generates a CMPA template."""
        out_file = os.path.join(str(tmp_path), "cmpa_template.yaml")
        cli_runner.invoke(
            pfr_cli.main,
            ["get-template", "-f", PFR_FAMILY, "-t", PFR_AREA_CMPA, "-o", out_file],
        )
        assert os.path.isfile(out_file)

    def test_pfr_get_template_cfpa(self, cli_runner: CliRunner, tmp_path: str) -> None:
        """Test pfr get-template generates a CFPA template."""
        out_file = os.path.join(str(tmp_path), "cfpa_template.yaml")
        cli_runner.invoke(
            pfr_cli.main,
            ["get-template", "-f", PFR_FAMILY, "-t", PFR_AREA_CFPA, "-o", out_file],
        )
        assert os.path.isfile(out_file)

    def test_pfr_get_templates_creates_files(self, cli_runner: CliRunner, tmp_path: str) -> None:
        """Test pfr get-templates creates multiple template files for a family."""
        out_dir = os.path.join(str(tmp_path), "pfr_templates")
        os.makedirs(out_dir)
        cli_runner.invoke(
            pfr_cli.main,
            ["get-templates", "-f", PFR_FAMILY, "-o", out_dir],
        )
        assert any(os.listdir(out_dir))

    @pytest.mark.parametrize("area", ["cmpa", "cfpa"])
    def test_pfr_get_template_parametrized(
        self, cli_runner: CliRunner, tmp_path: str, area: str
    ) -> None:
        """Test pfr get-template for multiple PFR area types."""
        out_file = os.path.join(str(tmp_path), f"{area}_template.yaml")
        cli_runner.invoke(
            pfr_cli.main,
            ["get-template", "-f", PFR_FAMILY, "-t", area, "-o", out_file],
        )
        assert os.path.isfile(out_file)

    def test_pfr_export_missing_config_fails(self, cli_runner: CliRunner, tmp_path: str) -> None:
        """Test that pfr export fails when config file does not exist."""
        out_file = os.path.join(str(tmp_path), "out.bin")
        cli_runner.invoke(
            pfr_cli.main,
            ["export", "-c", "nonexistent_config.yaml", "-o", out_file],
            expected_code=-1,
        )

    def test_pfr_get_template_invalid_area_fails(
        self, cli_runner: CliRunner, tmp_path: str
    ) -> None:
        """Test that pfr get-template fails with an unknown area type."""
        out_file = os.path.join(str(tmp_path), "out.yaml")
        cli_runner.invoke(
            pfr_cli.main,
            ["get-template", "-f", PFR_FAMILY, "-t", "invalid_area", "-o", out_file],
            expected_code=-1,
        )


# NXPDICE CLI tests  (spsdk/apps/nxpdice.py)


class TestNxpDiceCli:
    """Tests for the nxpdice CLI application."""

    def test_nxpdice_help(self, cli_runner: CliRunner) -> None:
        """Test nxpdice --help."""
        result = cli_runner.invoke(nxpdice.main, ["--help"])
        assert "Show this message and exit." in result.output

    def test_nxpdice_get_families(self, cli_runner: CliRunner) -> None:
        """Test nxpdice get-families lists families."""
        result = cli_runner.invoke(nxpdice.main, ["get-families"])
        assert result.output

    def test_nxpdice_register_ca_puk_help(self, cli_runner: CliRunner) -> None:
        """Test nxpdice register-ca-puk --help."""
        result = cli_runner.invoke(nxpdice.main, ["register-ca-puk", "--help"])
        assert "Show this message and exit." in result.output

    def test_nxpdice_get_ca_puk_help(self, cli_runner: CliRunner) -> None:
        """Test nxpdice get-ca-puk --help."""
        result = cli_runner.invoke(nxpdice.main, ["get-ca-puk", "--help"])
        assert "Show this message and exit." in result.output

    def test_nxpdice_verify_help(self, cli_runner: CliRunner) -> None:
        """Test nxpdice verify --help."""
        result = cli_runner.invoke(nxpdice.main, ["verify", "--help"])
        assert "Show this message and exit." in result.output

    def test_nxpdice_get_response_help(self, cli_runner: CliRunner) -> None:
        """Test nxpdice get-response --help."""
        result = cli_runner.invoke(nxpdice.main, ["get-response", "--help"])
        assert "Show this message and exit." in result.output

    def test_nxpdice_create_models_help(self, cli_runner: CliRunner) -> None:
        """Test nxpdice create-models --help."""
        result = cli_runner.invoke(nxpdice.main, ["create-models", "--help"])
        assert "Show this message and exit." in result.output

    def test_nxpdice_add_device_help(self, cli_runner: CliRunner) -> None:
        """Test nxpdice add-device --help."""
        result = cli_runner.invoke(nxpdice.main, ["add-device", "--help"])
        assert "Show this message and exit." in result.output

    def test_nxpdice_print_help(self, cli_runner: CliRunner) -> None:
        """Test nxpdice print --help."""
        result = cli_runner.invoke(nxpdice.main, ["print", "--help"])
        assert "Show this message and exit." in result.output

    def test_nxpdice_verify_pg_response_help(self, cli_runner: CliRunner) -> None:
        """Test nxpdice verify-pg-response --help."""
        result = cli_runner.invoke(nxpdice.main, ["verify-pg-response", "--help"])
        assert "Show this message and exit." in result.output

    def test_nxpdice_verify_csr_help(self, cli_runner: CliRunner) -> None:
        """Test nxpdice verify-csr --help."""
        result = cli_runner.invoke(nxpdice.main, ["verify-csr", "--help"])
        assert "Show this message and exit." in result.output

    def test_nxpdice_get_fmc_config_help(self, cli_runner: CliRunner) -> None:
        """Test nxpdice get-fmc-config --help."""
        result = cli_runner.invoke(nxpdice.main, ["get-fmc-config", "--help"])
        assert "Show this message and exit." in result.output

    def test_nxpdice_get_fmc_config_generates_output(
        self, cli_runner: CliRunner, tmp_path: str
    ) -> None:
        """Test nxpdice get-fmc-config creates an output file."""
        out_file = os.path.join(str(tmp_path), "fmc_config.yaml")
        cli_runner.invoke(nxpdice.main, ["get-fmc-config", "-o", out_file])
        assert os.path.isfile(out_file)

    def test_nxpdice_get_fmc_container_help(self, cli_runner: CliRunner) -> None:
        """Test nxpdice get-fmc-container --help."""
        result = cli_runner.invoke(nxpdice.main, ["get-fmc-container", "--help"])
        assert "Show this message and exit." in result.output

    def test_nxpdice_create_models(self, cli_runner: CliRunner, tmp_path: str) -> None:
        """Test nxpdice create-models creates virtual device models."""
        # Do not pre-create the directory; create-models calls os.makedirs internally
        models_dir = os.path.join(str(tmp_path), "models")
        cli_runner.invoke(
            nxpdice.main,
            ["create-models", "-md", models_dir, "-n", "2"],
        )
        assert os.path.isdir(models_dir)

    def test_nxpdice_add_device(self, cli_runner: CliRunner, tmp_path: str) -> None:
        """Test nxpdice add-device adds a virtual device."""
        models_dir = os.path.join(str(tmp_path), "models")
        os.makedirs(models_dir)
        cli_runner.invoke(
            nxpdice.main,
            ["add-device", "-md", models_dir, "-n", "test_device"],
        )
        assert os.path.isdir(models_dir)

    def test_nxpdice_upload_ca_puk_help(self, cli_runner: CliRunner) -> None:
        """Test nxpdice upload-ca-puk --help."""
        result = cli_runner.invoke(nxpdice.main, ["upload-ca-puk", "--help"])
        assert "Show this message and exit." in result.output

    def test_nxpdice_register_version_help(self, cli_runner: CliRunner) -> None:
        """Test nxpdice register-version --help."""
        result = cli_runner.invoke(nxpdice.main, ["register-version", "--help"])
        assert "Show this message and exit." in result.output

    def test_nxpdice_make_idevid_cert_help(self, cli_runner: CliRunner) -> None:
        """Test nxpdice make-idevid-cert --help."""
        result = cli_runner.invoke(nxpdice.main, ["make-idevid-cert", "--help"])
        assert "Show this message and exit." in result.output

    def test_nxpdice_get_pg_response_help(self, cli_runner: CliRunner) -> None:
        """Test nxpdice get-pg-response --help."""
        result = cli_runner.invoke(nxpdice.main, ["get-pg-response", "--help"])
        assert "Show this message and exit." in result.output

    def test_nxpdice_print_missing_file_fails(self, cli_runner: CliRunner) -> None:
        """Test that nxpdice print fails when response file does not exist."""
        cli_runner.invoke(
            nxpdice.main,
            ["print", "-r", "nonexistent_response.bin"],
            expected_code=-1,
        )

    def test_nxpdice_verify_pg_response_missing_file_fails(
        self, cli_runner: CliRunner, tmp_path: str
    ) -> None:
        """Test that verify-pg-response fails when response file does not exist."""
        key_file = os.path.join(str(tmp_path), "key.pem")
        cli_runner.invoke(
            nxpdice.main,
            ["verify-pg-response", "-r", "nonexistent.bin", "-k", key_file],
            expected_code=-1,
        )


# NXPIMAGE utils CLI tests  (spsdk/apps/nxpimage_apps/nxpimage_utils.py)


class TestNxpimageUtilsCli:
    """Tests for the nxpimage utils CLI subcommands."""

    def test_nxpimage_utils_help(self, cli_runner: CliRunner) -> None:
        """Test nxpimage utils --help."""
        result = cli_runner.invoke(nxpimage_main, ["utils", "--help"])
        assert "Show this message and exit." in result.output

    def test_nxpimage_binary_image_help(self, cli_runner: CliRunner) -> None:
        """Test nxpimage utils binary-image --help."""
        result = cli_runner.invoke(nxpimage_main, ["utils", "binary-image", "--help"])
        assert "Show this message and exit." in result.output

    def test_nxpimage_binary_image_create_help(self, cli_runner: CliRunner) -> None:
        """Test nxpimage utils binary-image create --help."""
        result = cli_runner.invoke(nxpimage_main, ["utils", "binary-image", "create", "--help"])
        assert "Show this message and exit." in result.output

    def test_nxpimage_binary_image_create(self, cli_runner: CliRunner, tmp_path: str) -> None:
        """Test nxpimage utils binary-image create generates a binary file."""
        out_file = os.path.join(str(tmp_path), "test.bin")
        cli_runner.invoke(
            nxpimage_main,
            ["utils", "binary-image", "create", "-s", "0x100", "-o", out_file],
        )
        assert os.path.isfile(out_file)
        assert os.path.getsize(out_file) == 0x100

    def test_nxpimage_binary_image_create_pattern_ones(
        self, cli_runner: CliRunner, tmp_path: str
    ) -> None:
        """Test binary-image create with ones pattern."""
        out_file = os.path.join(str(tmp_path), "ones.bin")
        cli_runner.invoke(
            nxpimage_main,
            ["utils", "binary-image", "create", "-s", "256", "-p", "ones", "-o", out_file],
        )
        assert os.path.isfile(out_file)
        with open(out_file, "rb") as f:
            data = f.read()
        assert all(b == 0xFF for b in data)

    def test_nxpimage_binary_image_get_template(self, cli_runner: CliRunner, tmp_path: str) -> None:
        """Test nxpimage utils binary-image get-template generates template."""
        out_file = os.path.join(str(tmp_path), "binary_template.yaml")
        cli_runner.invoke(
            nxpimage_main,
            ["utils", "binary-image", "get-template", "-o", out_file],
        )
        assert os.path.isfile(out_file)

    def test_nxpimage_binary_image_info(self, cli_runner: CliRunner, tmp_path: str) -> None:
        """Test nxpimage utils binary-image info shows file information."""
        # Create a binary file first
        in_file = os.path.join(str(tmp_path), "input.bin")
        with open(in_file, "wb") as f:
            f.write(b"\x00" * 64)
        result = cli_runner.invoke(
            nxpimage_main,
            ["utils", "binary-image", "info", "-i", in_file],
        )
        assert result.output

    def test_nxpimage_binary_image_extract(self, cli_runner: CliRunner, tmp_path: str) -> None:
        """Test nxpimage utils binary-image extract extracts a chunk."""
        in_file = os.path.join(str(tmp_path), "input.bin")
        out_file = os.path.join(str(tmp_path), "extracted.bin")
        with open(in_file, "wb") as f:
            f.write(bytes(range(256)))
        cli_runner.invoke(
            nxpimage_main,
            [
                "utils",
                "binary-image",
                "extract",
                "-b",
                in_file,
                "-a",
                "0",
                "-s",
                "16",
                "-o",
                out_file,
            ],
        )
        assert os.path.isfile(out_file)
        assert os.path.getsize(out_file) == 16

    def test_nxpimage_binary_image_align(self, cli_runner: CliRunner, tmp_path: str) -> None:
        """Test nxpimage utils binary-image align pads file to alignment."""
        in_file = os.path.join(str(tmp_path), "input.bin")
        out_file = os.path.join(str(tmp_path), "aligned.bin")
        with open(in_file, "wb") as f:
            f.write(b"\xab" * 17)
        cli_runner.invoke(
            nxpimage_main,
            ["utils", "binary-image", "align", "-i", in_file, "-o", out_file, "-a", "16"],
        )
        assert os.path.isfile(out_file)
        assert os.path.getsize(out_file) % 16 == 0

    def test_nxpimage_binary_image_pad(self, cli_runner: CliRunner, tmp_path: str) -> None:
        """Test nxpimage utils binary-image pad extends file to given size."""
        in_file = os.path.join(str(tmp_path), "input.bin")
        out_file = os.path.join(str(tmp_path), "padded.bin")
        with open(in_file, "wb") as f:
            f.write(b"\xcc" * 10)
        cli_runner.invoke(
            nxpimage_main,
            ["utils", "binary-image", "pad", "-i", in_file, "-o", out_file, "-s", "64"],
        )
        assert os.path.isfile(out_file)
        assert os.path.getsize(out_file) == 64

    def test_nxpimage_binary_image_convert_help(self, cli_runner: CliRunner) -> None:
        """Test nxpimage utils binary-image convert --help."""
        result = cli_runner.invoke(nxpimage_main, ["utils", "binary-image", "convert", "--help"])
        assert "Show this message and exit." in result.output

    def test_nxpimage_convert_help(self, cli_runner: CliRunner) -> None:
        """Test nxpimage utils convert --help."""
        result = cli_runner.invoke(nxpimage_main, ["utils", "convert", "--help"])
        assert "Show this message and exit." in result.output

    def test_nxpimage_convert_bin2hex(self, cli_runner: CliRunner, tmp_path: str) -> None:
        """Test nxpimage utils convert bin2hex converts binary to hex text."""
        in_file = os.path.join(str(tmp_path), "input.bin")
        out_file = os.path.join(str(tmp_path), "output.hex")
        with open(in_file, "wb") as f:
            f.write(b"\xde\xad\xbe\xef")
        cli_runner.invoke(
            nxpimage_main,
            ["utils", "convert", "bin2hex", "-i", in_file, "-o", out_file],
        )
        assert os.path.isfile(out_file)

    def test_nxpimage_convert_bin2carr(self, cli_runner: CliRunner, tmp_path: str) -> None:
        """Test nxpimage utils convert bin2carr converts binary to C array."""
        in_file = os.path.join(str(tmp_path), "input.bin")
        out_file = os.path.join(str(tmp_path), "output.c")
        with open(in_file, "wb") as f:
            f.write(b"\xde\xad\xbe\xef")
        cli_runner.invoke(
            nxpimage_main,
            ["utils", "convert", "bin2carr", "-i", in_file, "-o", out_file],
        )
        assert os.path.isfile(out_file)

    def test_nxpimage_convert_hex2bin(self, cli_runner: CliRunner, tmp_path: str) -> None:
        """Test nxpimage utils convert hex2bin converts hex text to binary."""
        in_file = os.path.join(str(tmp_path), "input.txt")
        out_file = os.path.join(str(tmp_path), "output.bin")
        with open(in_file, "w") as f:
            f.write("DEADBEEF\n")
        cli_runner.invoke(
            nxpimage_main,
            ["utils", "convert", "hex2bin", "-i", in_file, "-o", out_file],
        )
        assert os.path.isfile(out_file)

    def test_nxpimage_binary_image_create_missing_size_fails(
        self, cli_runner: CliRunner, tmp_path: str
    ) -> None:
        """Test binary-image create fails when size is missing."""
        out_file = os.path.join(str(tmp_path), "out.bin")
        cli_runner.invoke(
            nxpimage_main,
            ["utils", "binary-image", "create", "-o", out_file],
            expected_code=-1,
        )


# SPSDK apps CLI tests  (spsdk/apps/spsdk_apps.py)


class TestSpsdkAppsCli:
    """Tests for the spsdk unified CLI application."""

    def test_spsdk_help(self, cli_runner: CliRunner) -> None:
        """Test spsdk --help."""
        result = cli_runner.invoke(spsdk_main, ["--help"])
        assert "Show this message and exit." in result.output

    def test_spsdk_version(self, cli_runner: CliRunner) -> None:
        """Test spsdk --version prints version information."""
        result = cli_runner.invoke(spsdk_main, ["--version"])
        assert result.output

    def test_spsdk_utils_help(self, cli_runner: CliRunner) -> None:
        """Test spsdk utils --help."""
        result = cli_runner.invoke(spsdk_main, ["utils", "--help"])
        assert "Show this message and exit." in result.output

    def test_spsdk_utils_clear_cache(self, cli_runner: CliRunner) -> None:
        """Test spsdk utils clear-cache executes without error."""
        cli_runner.invoke(spsdk_main, ["utils", "clear-cache"])

    def test_spsdk_utils_family_info(self, cli_runner: CliRunner) -> None:
        """Test spsdk utils family-info shows family information."""
        result = cli_runner.invoke(spsdk_main, ["utils", "family-info", "-f", "lpc55s69"])
        assert result.output

    def test_spsdk_utils_family_info_invalid_family_fails(self, cli_runner: CliRunner) -> None:
        """Test spsdk utils family-info fails with an invalid family name."""
        cli_runner.invoke(
            spsdk_main,
            ["utils", "family-info", "-f", "totally_fake_family_xyz"],
            expected_code=-1,
        )

    def test_spsdk_utils_families_mbi(self, cli_runner: CliRunner) -> None:
        """Test spsdk utils families lists families supporting mbi feature."""
        result = cli_runner.invoke(spsdk_main, ["utils", "families", "-f", "mbi"])
        assert result.output

    def test_spsdk_utils_families_pfr(self, cli_runner: CliRunner) -> None:
        """Test spsdk utils families lists families supporting pfr feature."""
        result = cli_runner.invoke(spsdk_main, ["utils", "families", "-f", "pfr"])
        assert result.output

    def test_spsdk_utils_setup_autocomplete_help(self, cli_runner: CliRunner) -> None:
        """Test spsdk utils setup-autocomplete --help."""
        result = cli_runner.invoke(spsdk_main, ["utils", "setup-autocomplete", "--help"])
        assert "Show this message and exit." in result.output

    def test_spsdk_utils_setup_autocomplete_list_tools(self, cli_runner: CliRunner) -> None:
        """Test spsdk utils setup-autocomplete --list-tools lists available tools."""
        result = cli_runner.invoke(spsdk_main, ["utils", "setup-autocomplete", "--list-tools"])
        assert result.output

    def test_spsdk_subcommands_present(self, cli_runner: CliRunner) -> None:
        """Test that key sub-commands are registered in the spsdk group."""
        result = cli_runner.invoke(spsdk_main, ["--help"])
        for tool in ("nxpimage", "pfr", "nxpdice", "blhost"):
            assert tool in result.output

    @pytest.mark.parametrize("feature", ["mbi", "pfr", "ahab"])
    def test_spsdk_utils_families_parametrized(self, cli_runner: CliRunner, feature: str) -> None:
        """Test spsdk utils families for multiple feature names."""
        result = cli_runner.invoke(spsdk_main, ["utils", "families", "-f", feature])
        assert result.output


# NXPIMAGE MBI CLI tests  (spsdk/apps/nxpimage_apps/nxpimage_mbi.py)


class TestNxpimageMbiCli:
    """Tests for nxpimage mbi subcommands."""

    def test_nxpimage_mbi_help(self, cli_runner: CliRunner) -> None:
        """Test nxpimage mbi --help."""
        result = cli_runner.invoke(nxpimage_main, ["mbi", "--help"])
        assert "Show this message and exit." in result.output

    def test_nxpimage_mbi_export_help(self, cli_runner: CliRunner) -> None:
        """Test nxpimage mbi export --help."""
        result = cli_runner.invoke(nxpimage_main, ["mbi", "export", "--help"])
        assert "Show this message and exit." in result.output

    def test_nxpimage_mbi_parse_help(self, cli_runner: CliRunner) -> None:
        """Test nxpimage mbi parse --help."""
        result = cli_runner.invoke(nxpimage_main, ["mbi", "parse", "--help"])
        assert "Show this message and exit." in result.output

    def test_nxpimage_mbi_verify_help(self, cli_runner: CliRunner) -> None:
        """Test nxpimage mbi verify --help."""
        result = cli_runner.invoke(nxpimage_main, ["mbi", "verify", "--help"])
        assert "Show this message and exit." in result.output

    def test_nxpimage_mbi_get_templates_help(self, cli_runner: CliRunner) -> None:
        """Test nxpimage mbi get-templates --help."""
        result = cli_runner.invoke(nxpimage_main, ["mbi", "get-templates", "--help"])
        assert "Show this message and exit." in result.output

    def test_nxpimage_mbi_get_templates(self, cli_runner: CliRunner, tmp_path: str) -> None:
        """Test nxpimage mbi get-templates creates YAML template files."""
        out_dir = os.path.join(str(tmp_path), "mbi_templates")
        os.makedirs(out_dir)
        cli_runner.invoke(
            nxpimage_main,
            ["mbi", "get-templates", "-f", MBI_FAMILY, "-o", out_dir],
        )
        assert any(os.listdir(out_dir))

    @pytest.mark.parametrize("family", ["k32w148", "kw45b41z5"])
    def test_nxpimage_mbi_get_templates_parametrized(
        self, cli_runner: CliRunner, tmp_path: str, family: str
    ) -> None:
        """Test nxpimage mbi get-templates for multiple MBI families."""
        out_dir = os.path.join(str(tmp_path), f"mbi_{family}")
        os.makedirs(out_dir)
        cli_runner.invoke(
            nxpimage_main,
            ["mbi", "get-templates", "-f", family, "-o", out_dir],
        )
        assert any(os.listdir(out_dir))

    def test_nxpimage_mbi_export_missing_config_fails(
        self, cli_runner: CliRunner, tmp_path: str
    ) -> None:
        """Test nxpimage mbi export fails when config file is missing."""
        cli_runner.invoke(
            nxpimage_main,
            ["mbi", "export", "-c", "nonexistent_config.yaml"],
            expected_code=-1,
        )

    def test_nxpimage_mbi_parse_missing_binary_fails(
        self, cli_runner: CliRunner, tmp_path: str
    ) -> None:
        """Test nxpimage mbi parse fails when binary file is missing."""
        out_dir = os.path.join(str(tmp_path), "parse_out")
        os.makedirs(out_dir)
        cli_runner.invoke(
            nxpimage_main,
            ["mbi", "parse", "-f", MBI_FAMILY, "-b", "nonexistent.bin", "-o", out_dir],
            expected_code=-1,
        )

    def test_nxpimage_mbi_verify_missing_binary_fails(
        self, cli_runner: CliRunner, tmp_path: str
    ) -> None:
        """Test nxpimage mbi verify fails when binary does not exist."""
        cli_runner.invoke(
            nxpimage_main,
            ["mbi", "verify", "-f", MBI_FAMILY, "-b", "nonexistent.bin"],
            expected_code=-1,
        )
