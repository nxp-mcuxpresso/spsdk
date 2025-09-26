#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Wrapper for all spsdk applications.

Its purpose is to provide easier discoverability.
New users may not be aware of all available apps.
"""
import sys
import textwrap
from typing import Any, Optional

import click
import colorama

from spsdk import __version__ as spsdk_version
from spsdk.apps.blhost import main as blhost_main
from spsdk.apps.dk6prog import main as dk6prog_main
from spsdk.apps.el2go import main as el2go_main
from spsdk.apps.lpcprog import main as lpcprog_main
from spsdk.apps.nxpcrypto import main as nxpcrypto_main
from spsdk.apps.nxpdebugmbox import main as nxpdebugmbox_main
from spsdk.apps.nxpdevhsm import main as nxpdevhsm_main
from spsdk.apps.nxpdevscan import main as nxpdevscan_main
from spsdk.apps.nxpdice import main as nxpdice_main
from spsdk.apps.nxpele import main as nxpele_main
from spsdk.apps.nxpfuses import main as nxpfuses_main
from spsdk.apps.nxpimage import main as nxpimage_main
from spsdk.apps.nxpmemcfg import main as nxpmemcfg_main
from spsdk.apps.nxpuuu import main as nxpuuu_main
from spsdk.apps.nxpwpc import main as nxpwpc_main
from spsdk.apps.pfr import main as pfr_main
from spsdk.apps.sdphost import main as sdphost_main
from spsdk.apps.sdpshost import main as sdpshost_main
from spsdk.apps.shadowregs import main as shadowregs_main
from spsdk.apps.utils.common_cli_options import CommandsTreeGroup
from spsdk.apps.utils.utils import catch_spsdk_error, make_table_from_items
from spsdk.utils.database import DatabaseManager, FeaturesEnum
from spsdk.utils.family import get_families, split_by_family_name


@click.group(name="spsdk", cls=CommandsTreeGroup)
@click.version_option(spsdk_version, "--version")
def main() -> int:
    """Main entry point for all SPSDK applications."""
    return 0


main.add_command(blhost_main, name="blhost")
main.add_command(nxpfuses_main, name="nxpfuses")
main.add_command(nxpcrypto_main, name="nxpcrypto")
main.add_command(nxpdebugmbox_main, name="nxpdebugmbox")
main.add_command(nxpdevscan_main, name="nxpdevscan")
main.add_command(nxpdevhsm_main, name="nxpdevhsm")
main.add_command(nxpele_main, name="nxpele")
main.add_command(nxpdice_main, name="nxpdice")
main.add_command(nxpimage_main, name="nxpimage")
main.add_command(nxpmemcfg_main, name="nxpmemcfg")
main.add_command(nxpuuu_main, name="nxpuuu")
main.add_command(nxpwpc_main, name="nxpwpc")
main.add_command(pfr_main, name="pfr")
main.add_command(sdphost_main, name="sdphost")
main.add_command(sdpshost_main, name="sdpshost")
main.add_command(shadowregs_main, name="shadowregs")
main.add_command(dk6prog_main, name="dk6prog")
main.add_command(el2go_main, name="el2go-host")
main.add_command(lpcprog_main, name="lpcprog")


@main.group("utils", cls=CommandsTreeGroup)
def utils_group() -> None:
    """Group of commands for working with various general utilities."""


@utils_group.command(name="clear-cache", no_args_is_help=False)
@click.pass_context
def clear_cache(ctx: click.Context) -> None:
    """Clear SPSDK cache.

    :param ctx: Click content
    """
    DatabaseManager.clear_cache()
    click.echo("SPSDK cache has been cleared.")
    ctx.exit()


def _check_auto_click_auto_import() -> tuple[Any, Any]:
    """Check if auto-click-auto is available and import required modules.

    :return: tuple of (enable_click_shell_completion, ShellType) or (None, None) if not available
    """
    try:
        from auto_click_auto import enable_click_shell_completion
        from auto_click_auto.constants import ShellType

        return enable_click_shell_completion, ShellType
    except ImportError:
        click.echo(
            colorama.Fore.RED
            + "Error: auto-click-auto is not installed. Please install it with:\n"
            + "pip install auto-click-auto"
            + colorama.Fore.RESET
        )
        return None, None


def _get_spsdk_tools() -> list[str]:
    """Get list of all SPSDK tools.

    :return: list of SPSDK tool names
    """
    return [
        "blhost",
        "nxpfuses",
        "nxpcrypto",
        "nxpdebugmbox",
        "nxpdevscan",
        "nxpdevhsm",
        "nxpele",
        "nxpdice",
        "nxpimage",
        "nxpmemcfg",
        "nxpuuu",
        "nxpwpc",
        "pfr",
        "sdphost",
        "sdpshost",
        "shadowregs",
        "dk6prog",
        "el2go-host",
        "lpcprog",
    ]


def _list_available_tools() -> None:
    """Display list of available SPSDK tools."""
    click.echo("Available SPSDK tools for autocompletion:")
    for tool in _get_spsdk_tools():
        click.echo(f"  • {tool}")


def _validate_and_get_tools(tools: tuple) -> Optional[list[str]]:
    """Validate tool names and return list of tools to setup.

    :param tools: tuple of tool names from command line
    :return: list of validated tools or None if validation fails
    """
    spsdk_tools = _get_spsdk_tools()
    tools_to_setup = list(tools) if tools else spsdk_tools

    invalid_tools = [tool for tool in tools_to_setup if tool not in spsdk_tools]
    if invalid_tools:
        click.echo(
            colorama.Fore.RED
            + f"Error: Unknown tools: {', '.join(invalid_tools)}\n"
            + "Use --list-tools to see available tools."
            + colorama.Fore.RESET
        )
        return None

    return tools_to_setup


def _get_shell_type(shell: Optional[str], ShellType: Any) -> Optional[Any]:
    """Get shell type from string.

    :param shell: Shell name string
    :param ShellType: ShellType enum class
    :return: ShellType instance or None
    """
    if not shell:
        return None

    try:
        return ShellType(shell.lower())
    except ValueError:
        click.echo(
            colorama.Fore.RED
            + f"Error: Unsupported shell '{shell}'. Supported shells: bash, zsh, fish"
            + colorama.Fore.RESET
        )
        return None


def _show_dry_run_info(shell_type: Any, tools_to_setup: list[str]) -> None:
    """Display dry run information.

    :param shell_type: Shell type or None
    :param tools_to_setup: list of tools to setup
    """
    click.echo("Dry run mode - showing what would be done:")
    click.echo(f"Shell: {shell_type.value if shell_type else 'auto-detect'}")
    click.echo(f"Tools: {', '.join(tools_to_setup)}")


def _setup_tools_completion(
    tools_to_setup: list[str], shell_type: Any, enable_click_shell_completion: Any
) -> tuple[int, list[str]]:
    """Setup completion for tools and return results.

    :param tools_to_setup: list of tools to setup
    :param shell_type: Shell type or None
    :param enable_click_shell_completion: Function to enable completion
    :return: tuple of (success_count, failed_tools)
    """
    success_count = 0
    failed_tools = []

    click.echo(f"Setting up autocompletion for {len(tools_to_setup)} tools...")

    for tool in tools_to_setup:
        try:
            enable_click_shell_completion(
                program_name=tool,
                shells={shell_type} if shell_type else None,
                verbose=False,  # We'll handle our own output
            )
            click.echo(f"  {colorama.Fore.GREEN}✓{colorama.Fore.RESET} {tool}")
            success_count += 1
        except Exception as e:
            click.echo(f"  {colorama.Fore.RED}✗{colorama.Fore.RESET} {tool}: {str(e)}")
            failed_tools.append(tool)

    return success_count, failed_tools


def _show_activation_instructions(shell_type: Any, ShellType: Any) -> None:
    """Show shell-specific activation instructions.

    :param shell_type: Shell type or None
    :param ShellType: ShellType enum class
    """
    detected_shell = shell_type.value if shell_type else "your shell"
    click.echo(f"\nTo activate completion in {detected_shell}, run:")

    if not shell_type or shell_type == ShellType.BASH:
        click.echo("  source ~/.bashrc")
    elif shell_type == ShellType.ZSH:
        click.echo("  source ~/.zshrc")
    elif shell_type == ShellType.FISH:
        click.echo("  source ~/.config/fish/config.fish")

    click.echo("\nOr start a new terminal session.")


def _show_completion_summary(
    success_count: int, failed_tools: list[str], shell_type: Any, ShellType: Any
) -> None:
    """Show completion setup summary.

    :param success_count: Number of successfully setup tools
    :param failed_tools: list of failed tools
    :param shell_type: Shell type or None
    :param ShellType: ShellType enum class
    """
    click.echo()
    if success_count > 0:
        click.echo(
            colorama.Fore.GREEN
            + f"Successfully enabled autocompletion for {success_count} tools."
            + colorama.Fore.RESET
        )
        _show_activation_instructions(shell_type, ShellType)

    if failed_tools:
        click.echo(
            colorama.Fore.YELLOW
            + f"\nWarning: Failed to enable completion for {len(failed_tools)} tools: "
            + ", ".join(failed_tools)
            + colorama.Fore.RESET
        )
        click.echo("This might be because these tools are not installed or not in your PATH.")


@utils_group.command(name="setup-autocomplete", no_args_is_help=False)
@click.option(
    "--shell",
    type=click.Choice(["bash", "zsh", "fish"], case_sensitive=False),
    help="Shell type (auto-detected if not specified)",
)
@click.option(
    "--tools",
    multiple=True,
    help="Specific tools to enable completion for (default: all tools)",
)
@click.option(
    "--list-tools",
    is_flag=True,
    help="list all available SPSDK tools and exit",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show what would be done without actually setting up completion",
)
def setup_autocomplete(shell: str, tools: tuple, list_tools: bool, dry_run: bool) -> None:
    """Setup shell autocompletion for SPSDK tools.

    This command enables tab completion for SPSDK command-line tools.
    If no shell is specified, it will attempt to auto-detect your current shell.

    Examples:
        spsdk utils setup-autocomplete --shell bash
        spsdk utils setup-autocomplete --tools nxpfuses nxpimage
        spsdk utils setup-autocomplete --list-tools
    """
    if list_tools:
        _list_available_tools()
        return

    enable_click_shell_completion, ShellType = _check_auto_click_auto_import()
    if not enable_click_shell_completion:
        return

    tools_to_setup = _validate_and_get_tools(tools)
    if tools_to_setup is None:
        return

    shell_type = _get_shell_type(shell, ShellType)
    if shell and shell_type is None:
        return

    if dry_run:
        _show_dry_run_info(shell_type, tools_to_setup)
        return

    success_count, failed_tools = _setup_tools_completion(
        tools_to_setup, shell_type, enable_click_shell_completion
    )

    _show_completion_summary(success_count, failed_tools, shell_type, ShellType)


@utils_group.command(name="family-info", no_args_is_help=True)
@click.option(
    "-f",
    "--family",
    type=click.Choice(
        choices=list(DatabaseManager().quick_info.devices.devices.keys()), case_sensitive=False
    ),
    required=True,
    help="Select the chip family.",
)
def family_info(family: str) -> None:
    """Show information of chosen family chip.

    :param family: Name of the device.
    """
    qi_family = DatabaseManager().quick_info.devices.devices[family]

    click.echo(f"Family:            {family}")
    click.echo(f"Revisions:         {qi_family.revisions}")
    click.echo(f"Purpose:           {qi_family.info.purpose}")
    click.echo(f"Web:               {qi_family.info.web}")
    if qi_family.info.spsdk_predecessor_name:
        click.echo(f"Predecessor name:  {qi_family.info.spsdk_predecessor_name}")
    click.echo(f"ISP:\n{textwrap.indent(str(qi_family.info.isp), '  ')}")
    click.echo(f"Memory map:\n{textwrap.indent(qi_family.info.memory_map.get_table(), '  ')}")

    features_raw = qi_family.get_features()
    features_desc = [
        f"{x.upper():<20}{FeaturesEnum.from_label(x).description}" for x in features_raw
    ]
    assert isinstance(features_desc, list)
    printable_list = "\n - ".join(features_desc)
    click.echo(f"The supported features for {family}:\n - {printable_list}")


@utils_group.command(name="families", no_args_is_help=True)
@click.option(
    "-f",
    "--feature",
    type=click.Choice(choices=FeaturesEnum.labels(), case_sensitive=False),
    required=True,
    help="Select the feature to print out all families that supports it.",
)
def families(feature: str) -> None:
    """Show all families that supports chosen feature.

    :param feature: Name of the feature.
    """
    families_dict = split_by_family_name(get_families(feature))
    families_with_rev = [
        f"{name}[{','.join(revisions)}]" for name, revisions in families_dict.items()
    ]
    click.echo(
        colorama.Fore.GREEN + f"The supported families for {feature}::" + colorama.Fore.RESET
    )
    for line in make_table_from_items(families_with_rev):
        click.echo(line)


@catch_spsdk_error
def safe_main() -> Any:
    """Call the main function."""
    sys.exit(main())


if __name__ == "__main__":
    safe_main()  # pylint: disable=no-value-for-parameter
