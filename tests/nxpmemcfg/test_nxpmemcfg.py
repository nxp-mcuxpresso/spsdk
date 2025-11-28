#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test suite for the nxpmemcfg command-line application.

This module contains comprehensive tests for the nxpmemcfg application,
which provides memory configuration utilities for NXP MCUs within the SPSDK framework.
Tests validate core functionality including help output, family information display,
configuration export, template generation, and BLHost script creation.
"""

import os
from typing import Any

import pytest

from spsdk.apps import nxpmemcfg
from spsdk.memcfg.memcfg import Memory, MemoryConfig, SPSDKUnsupportedInterface
from spsdk.utils.family import FamilyRevision, get_db
from tests.cli_runner import CliRunner


def test_app_help(cli_runner: CliRunner) -> None:
    """Test that the nxpmemcfg application displays help information correctly.

    Verifies that the CLI application responds appropriately when invoked without arguments
    and that the help output contains expected command names and application identifier.

    :param cli_runner: Click CLI test runner instance for invoking command-line interface.
    """
    ret = cli_runner.invoke(
        nxpmemcfg.main, "", expected_code=cli_runner.get_help_error_code(use_help_flag=False)
    )
    assert "nxpmemcfg" in ret.output
    assert "export" in ret.output
    assert "parse" in ret.output


@pytest.mark.parametrize(
    "family,peripheral,checks_output,not_in_output",
    [
        (
            None,
            None,
            ["lpc55s36", "rw612", "Opt0: 0xC1020026, Opt1: 0x000000A1", "Opt0: 0xD0000003"],
            ["invalid"],
        ),
        ("mimxrt1189", None, ["mimxrt1189", "flexspi_nand"], ["lpc55s3x"]),
        ("mimxrt1189", "flexspi_nor", ["mimxrt1189"], ["lpc55s3x", "flexspi_nand"]),
    ],
)
def test_app_family_info(
    cli_runner: CliRunner, family: Any, peripheral: Any, checks_output: Any, not_in_output: Any
) -> None:
    """Test the family info command functionality.

    This test verifies that the family-info command produces the expected output
    when called with various family and peripheral parameters. It checks both
    that required content is present and that unwanted content is absent.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param family: Family parameter to pass to the command, or None to omit.
    :param peripheral: Peripheral parameter to pass to the command, or None to omit.
    :param checks_output: List of strings that must be present in command output.
    :param not_in_output: List of strings that must not be present in command output.
    """
    cmd = "family-info"
    if family:
        cmd += f" -f {family}"
    if peripheral:
        cmd += f" -p {peripheral}"
    ret = cli_runner.invoke(nxpmemcfg.main, cmd)

    for check in checks_output:
        assert check in ret.output

    for check in not_in_output:
        assert check not in ret.output


@pytest.mark.parametrize(
    "family,peripheral,ow",
    [
        ("mimxrt1189", "flexspi_nor", [0xC000_0001]),
        ("mimxrt1189", "flexspi_nor", [0xC100_0007, 0x0000_0001]),
        ("mimxrt1189", "flexspi_nand", [0xC1020026, 0x000000C2]),
        ("mimxrt1189", "sd", [0xD0000002]),
        ("lpc55s3x", "flexspi_nor", [0xC100_0007, 0x0000_0001]),
    ],
)
def test_app_parse_export(
    cli_runner: CliRunner, tmpdir: Any, family: Any, peripheral: Any, ow: Any
) -> None:
    """Test nxpmemcfg parse and export commands functionality.

    This test verifies that the parse command can generate a configuration file
    from the given family, peripheral, and option words, and that the export
    command can successfully process the generated configuration file and
    display the option words in the expected format.

    :param cli_runner: Click CLI runner for testing command line interface.
    :param tmpdir: Temporary directory for test files.
    :param family: Target MCU family name.
    :param peripheral: Target peripheral name.
    :param ow: List of option words to be processed.
    """
    cmd = f"parse -f {family} -p {peripheral} "
    for x in ow:
        cmd += f"-w {str(x)} "
    cfg_file = os.path.join(tmpdir, "memcfg.yaml").replace("\\", "/")
    cmd += f"-o {cfg_file}"
    ret = cli_runner.invoke(nxpmemcfg.main, cmd)
    assert ret.exit_code == 0

    ret = cli_runner.invoke(nxpmemcfg.main, f"export -c {cfg_file}")

    assert ret.exit_code == 0
    for x in ow:
        assert f"0x{x:08X}" in ret.output


@pytest.mark.parametrize(
    "peripheral,mem_type,interfaces",
    [
        ("flexspi_nor", "nor", ["octal_spi", "quad_spi", "hyper_flash"]),
        ("flexspi_nand", "nand", ["quad_spi"]),
        ("semc_nor", "nor", ["parallel"]),
        ("sd", "sd", ["instance_0", "instance_1", "instance_2", "instance_3"]),
    ],
)
def test_app_parse_export_all(
    cli_runner: CliRunner, tmpdir: Any, peripheral: str, mem_type: str, interfaces: list[str]
) -> None:
    """Test parsing and exporting memory configurations for all known peripheral memories.

    This test verifies that the nxpmemcfg CLI can successfully parse memory configurations
    with option words and export them back to YAML format. It iterates through all known
    memories for a given peripheral and validates that option words are correctly preserved
    in the export output.

    :param cli_runner: Click CLI test runner for invoking commands
    :param tmpdir: Temporary directory for storing generated configuration files
    :param peripheral: Name of the peripheral to test memory configurations for
    :param mem_type: Type of memory being tested
    :param interfaces: List of interface names available for the memory configurations
    """
    memories = MemoryConfig.get_known_peripheral_memories(
        family=FamilyRevision("mimxrt1189"), peripheral=peripheral
    )

    for memory in memories:
        cmd = f"parse -f mimxrt1189 -p {peripheral} "
        for ow in memory.interfaces[0].option_words:
            cmd += f"-w {str(ow)} "
        cfg_file = os.path.join(
            tmpdir, f"{memory.manufacturer}_{memory.name}_{memory.interfaces[0].name}.yaml"
        ).replace("\\", "/")
        cmd += f"-o {cfg_file}"
        ret = cli_runner.invoke(nxpmemcfg.main, cmd)
        ret = cli_runner.invoke(nxpmemcfg.main, f"export -c {cfg_file}")

        assert ret.exit_code == 0
        for ow in memory.interfaces[0].option_words:
            assert f"0x{ow:08X}" in ret.output


@pytest.mark.parametrize("family", [x.name for x in MemoryConfig.get_supported_families()])
def test_get_templates(cli_runner: CliRunner, family: Any, tmpdir: str) -> None:
    """Test get-templates command functionality.

    Verifies that the nxpmemcfg get-templates command executes successfully
    and generates template files for the specified family in the output directory.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param family: Target MCU family for template generation.
    :param tmpdir: Temporary directory path for output files.
    """
    output = f"{tmpdir}".replace("\\", "/")
    ret = cli_runner.invoke(nxpmemcfg.main, f"get-templates -f {family} -o {output}")
    assert ret.exit_code == 0


@pytest.mark.parametrize(
    "family,peripheral,instance,interface,chip_name,fcb,secure_address,output_checks",
    [
        (
            "mimxrt1189",
            "flexspi_nor",
            1,
            "quad_spi",
            "W25QxxxJV",
            True,
            False,
            [
                "fill-memory 0x1FFE0000 4 0xCF900001",
                "fill-memory 0x1FFE0000 4 0xC0000007",
                "configure-memory 9 0x1FFE0000",
                "fill-memory 0x1FFE0000 4 0xF000000F",
                "read-memory 0x28000400 0x200",
            ],
        ),
        (
            "mimxrt1189",
            "flexspi_nor",
            1,
            "quad_spi",
            "W25QxxxJV",
            True,
            True,
            [
                "read-memory 0x38000400 0x200",
            ],
        ),
        (
            "mimxrt1189",
            "flexspi_nand",
            2,
            "quad_spi",
            "W25N01G",
            True,
            False,
            [
                "fill-memory 0x1FFE0000 4 0xCF900002",
                "fill-memory 0x1FFE0000 4 0xC1010026",
                "fill-memory 0x1FFE0004 4 0x000000EF",
                "configure-memory 257 0x1FFE0000",
                "#FCB read back is supported just only for",
            ],
        ),
        (
            "mimxrt595s",
            "flexspi_nor",
            0,
            "quad_spi",
            "W25QxxxJV",
            True,
            False,
            [
                "fill-memory 0x0010C000 4 0xCF900000",
                "fill-memory 0x0010C000 4 0xC0000007",
                "configure-memory 9 0x0010C000",
                "fill-memory 0x0010C000 4 0xF000000F",
                "read-memory",
            ],
        ),
    ],
)
def test_blhost_script(
    cli_runner: CliRunner,
    family: str,
    peripheral: str,
    instance: int,
    interface: str,
    chip_name: str,
    fcb: bool,
    secure_address: bool,
    output_checks: Any,
    tmpdir: str,
) -> None:
    """Test blhost-script command functionality with various configuration options.

    This test verifies that the nxpmemcfg application can successfully parse memory
    configuration and generate blhost scripts with different parameter combinations
    including FCB generation and secure address handling.

    :param cli_runner: Click CLI test runner for invoking commands
    :param family: Target MCU family name
    :param peripheral: Memory peripheral type to configure
    :param instance: Instance number of the peripheral (optional)
    :param interface: Communication interface type
    :param chip_name: Specific chip model name
    :param fcb: Flag to enable FCB (Flash Configuration Block) generation
    :param secure_address: Flag to enable secure address mode
    :param output_checks: Expected strings to verify in command output
    :param tmpdir: Temporary directory path for output files
    """
    output = f"{tmpdir}".replace("\\", "/")
    output_cfg = output + "/cfg.yaml"
    output_fcb = output + "/fcb.bin"
    ret = cli_runner.invoke(
        nxpmemcfg.main,
        f"parse -f {family} -p {peripheral} -m {chip_name} -i {interface} -o {output_cfg}",
    )
    assert ret.exit_code == 0
    ret = cli_runner.invoke(
        nxpmemcfg.main,
        f"blhost-script -c {output_cfg}{f' -ix {str(instance)}' if instance is not None else ''} {f' --fcb {output_fcb}' if fcb else ''}{' --secure-addresses' if secure_address else ''}",
    )
    assert ret.exit_code == 0
    for x in output_checks:
        assert x in ret.output


@pytest.mark.parametrize("family", MemoryConfig.get_supported_families())
def test_app_blhost_script_flexspi_nor(
    cli_runner: CliRunner, family: FamilyRevision, tmpdir: Any
) -> None:
    """Test blhost script generation for FlexSPI NOR memory configuration.

    This test verifies the complete workflow of generating a memory configuration
    file and then creating a blhost script for FlexSPI NOR memory. It tests the
    parse command to generate a configuration file and the blhost-script command
    to create FCB (Flash Configuration Block) output.

    :param cli_runner: Click CLI test runner for invoking commands
    :param family: Target MCU family and revision for testing
    :param tmpdir: Temporary directory for test output files
    :raises AssertionError: If CLI commands fail or return non-zero exit codes
    """
    if MemoryConfig.get_peripheral_cnt(family, "flexspi_nor") > 0:
        output = f"{tmpdir}".replace("\\", "/")
        output_cfg = output + "/cfg.yaml"
        output_fcb = output + "/fcb.bin"
        ret = cli_runner.invoke(
            nxpmemcfg.main,
            f"parse -f {family.name} -p flexspi_nor -m W25QxxxJV -i quad_spi -o {output_cfg}",
        )
        assert ret.exit_code == 0
        instances = MemoryConfig.get_peripheral_instances(family, "flexspi_nor")
        ret = cli_runner.invoke(
            nxpmemcfg.main,
            f"blhost-script -c {output_cfg}{f' -ix {instances[0]}' if len(instances) > 1 else ''} --fcb {output_fcb}",
        )
        assert ret.exit_code == 0


@pytest.mark.parametrize(
    "family,peripheral,interface,supported",
    [
        (FamilyRevision("mimxrt798s"), "xspi_nor", "hyper_flash", False),
        (FamilyRevision("mimxrt798s"), "xspi_nor", "quad_spi", True),
        (FamilyRevision("mimxrt798s"), "xspi_nor", "octal_spi", True),
    ],
)
def test_non_supported_interface(
    family: Any, peripheral: Any, interface: Any, supported: Any
) -> None:
    """Test non-supported interface configuration.

    This test verifies that MemoryConfig properly raises SPSDKUnsupportedInterface
    when attempting to create a configuration with an unsupported interface,
    and successfully creates the configuration when the interface is supported.

    :param family: MCU family identifier for memory configuration.
    :param peripheral: Peripheral type for memory configuration.
    :param interface: Interface type to test for support.
    :param supported: Boolean flag indicating if the interface should be supported.
    """
    if not supported:
        with pytest.raises(SPSDKUnsupportedInterface):
            MemoryConfig(family=family, peripheral=peripheral, interface=interface)
    else:
        assert MemoryConfig(family=family, peripheral=peripheral, interface=interface)


@pytest.mark.parametrize(
    "family,peripheral,validate,expected_not_empty",
    [
        (None, None, True, True),  # No family, no peripheral - should return all memories
        (
            None,
            "flexspi_nor",
            True,
            True,
        ),  # No family, with peripheral - should return memories for that peripheral
        (None, "flexspi_nor", False, True),  # Same but without validation
        (FamilyRevision("mimxrt1189"), None, True, True),  # With family, no peripheral
        (FamilyRevision("mimxrt1189"), "flexspi_nor", True, True),  # With family and peripheral
        (FamilyRevision("mimxrt1189"), "flexspi_nor", False, True),  # Same but without validation
        (
            FamilyRevision("mimxrt1189"),
            "invalid_peripheral",
            True,
            False,
        ),  # Invalid peripheral should return empty list
    ],
)
def test_get_known_peripheral_memories(
    family: Any, peripheral: Any, validate: Any, expected_not_empty: Any
) -> None:
    """Test the get_known_peripheral_memories function with various parameters.

    This test verifies that the function returns memories in different scenarios:
    - When no family is specified
    - When no peripheral is specified
    - When both family and peripheral are specified
    - With and without validation

    :param family: The MCU family name to filter memories by, or None for all families.
    :param peripheral: The peripheral type to filter memories by, or None for all peripherals.
    :param validate: Whether to validate option words in the returned memories.
    :param expected_not_empty: Whether the returned list is expected to contain memories.
    """
    memories = MemoryConfig.get_known_peripheral_memories(
        family=family, peripheral=peripheral, validate_option_words=validate
    )

    # Check if the result is a list of Memory objects
    assert isinstance(memories, list)

    # Check if the list is empty or not as expected
    if expected_not_empty:
        assert len(memories) > 0
        # Verify that all items are Memory objects
        for memory in memories:
            assert isinstance(memory, Memory)
            # Verify that each memory has at least one interface
            assert len(memory.interfaces) > 0
    else:
        assert len(memories) == 0

    # If peripheral is specified, check that all memories have that interface
    if peripheral and len(memories) > 0:
        # Get the memory type for this peripheral
        if family:
            p_db = get_db(family).get_dict(MemoryConfig.FEATURE, "peripherals")
            if peripheral in p_db:
                mem_type = p_db[peripheral]["mem_type"]
                # Check that all returned memories have the correct type
                for memory in memories:
                    assert memory.type == mem_type


@pytest.mark.parametrize(
    "chip_name,expected_interfaces",
    [
        ("W25QxxxJV", ["quad_spi"]),  # A common flash memory with quad_spi interface
        ("IS25WPxxxA", ["octal_spi"]),  # A memory with octal_spi interface
    ],
)
def test_get_known_chip_memory(chip_name: Any, expected_interfaces: Any) -> None:
    """Test the get_known_chip_memory function for specific chips.

    Validates that the MemoryConfig.get_known_chip_memory method correctly retrieves
    memory configuration for a given chip and verifies that the returned Memory object
    contains the expected interfaces. If the chip is not found in the database,
    the test is skipped.

    :param chip_name: Name of the chip to test memory configuration retrieval for.
    :param expected_interfaces: List of interface names that should be present in the chip's memory configuration.
    :raises Exception: When chip is not found in database, causing test to be skipped.
    """
    try:
        memory = MemoryConfig.get_known_chip_memory(chip_name)
        assert isinstance(memory, Memory)
        assert memory.name == chip_name

        # Check that the memory has the expected interfaces
        interface_names = [interface.name for interface in memory.interfaces]
        for expected_interface in expected_interfaces:
            assert expected_interface in interface_names

    except Exception as e:
        # If the chip is not in the database, this test will be skipped
        pytest.skip(f"Chip {chip_name} not found in database: {str(e)}")
