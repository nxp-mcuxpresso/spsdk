#!/usr/bin/env python
#
# Copyright 2020-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK unified command-line interface wrapper.

This module provides a centralized entry point for all SPSDK applications,
offering improved discoverability and easier access to the complete toolkit
of secure provisioning utilities across NXP MCU portfolio.
"""

import os
import sys
import textwrap
from typing import Any

import click
import colorama

# Early cache clear: handle corrupted cache before heavy imports that load database
if "clear-cache" in sys.argv:
    import shutil

    from spsdk.utils.database import get_spsdk_cache_dirname

    path = get_spsdk_cache_dirname()
    if os.path.exists(path):
        shutil.rmtree(path)
        click.echo(f"SPSDK cache has been cleared: {path}")
    else:
        click.echo(f"Cache directory '{path}' does not exist, nothing to clear.")
    sys.exit(0)

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
from spsdk.apps.nxpshe import main as nxpshe_main
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
main.add_command(nxpshe_main, name="nxpshe")
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
        "nxpshe",
        "nxpuuu",
        "nxpwpc",
        "pfr",
        "sdphost",
        "sdpshost",
        "shadowregs",
        "dk6prog",
        "el2go-host",
        "lpcprog",
        "spsdk",
    ]


def _list_available_tools() -> None:
    """Display list of available SPSDK tools."""
    click.echo("Available SPSDK tools for autocompletion:")
    for tool in _get_spsdk_tools():
        click.echo(f"  • {tool}")


# Map tool names to their Click command objects for static completion generation.
# Must stay in sync with _get_spsdk_tools().
_TOOL_COMMANDS: dict[str, click.Command] = {
    "blhost": blhost_main,
    "nxpfuses": nxpfuses_main,
    "nxpcrypto": nxpcrypto_main,
    "nxpdebugmbox": nxpdebugmbox_main,
    "nxpdevscan": nxpdevscan_main,
    "nxpdevhsm": nxpdevhsm_main,
    "nxpele": nxpele_main,
    "nxpdice": nxpdice_main,
    "nxpimage": nxpimage_main,
    "nxpmemcfg": nxpmemcfg_main,
    "nxpshe": nxpshe_main,
    "nxpuuu": nxpuuu_main,
    "nxpwpc": nxpwpc_main,
    "pfr": pfr_main,
    "sdphost": sdphost_main,
    "sdpshost": sdpshost_main,
    "shadowregs": shadowregs_main,
    "dk6prog": dk6prog_main,
    "el2go-host": el2go_main,
    "lpcprog": lpcprog_main,
    "spsdk": main,
}


def _detect_shell() -> str:
    """Detect the current shell type from the execution environment.

    Detection order:
    1. Windows platform → ``"powershell"``
    2. ``$SHELL`` environment variable → ``"zsh"`` or ``"bash"``
    3. Fallback → ``"bash"``

    :return: Detected shell name (``"powershell"``, ``"zsh"``, or ``"bash"``).
    """
    import platform

    if platform.system() == "Windows":
        return "powershell"
    shell_env = os.environ.get("SHELL", "")
    if "zsh" in shell_env:
        return "zsh"
    if "bash" in shell_env:
        return "bash"
    return "bash"


def _validate_and_get_tools(tools: tuple) -> list[str] | None:
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


def _setup_static_completion(
    tools_to_setup: list[str], shell: str, dry_run: bool
) -> tuple[int, list[str]]:
    """Generate static completion files for the requested tools.

    :param tools_to_setup: Tool names to process.
    :param shell: Target shell (``"zsh"``).
    :param dry_run: When True show what would be done without writing files.
    :return: Tuple of (success_count, failed_tools).
    """
    from spsdk.utils.autocomplete import setup_shell_completion

    success_count = 0
    failed_tools = []

    click.echo(f"Setting up {shell} autocompletion for {len(tools_to_setup)} tools...")

    for tool in tools_to_setup:
        cmd = _TOOL_COMMANDS.get(tool)
        if cmd is None:
            click.echo(
                f"  {colorama.Fore.YELLOW}?{colorama.Fore.RESET} {tool}: no Click command object found"
            )
            failed_tools.append(tool)
            continue

        ok, msg = setup_shell_completion(tool, cmd, shell=shell, dry_run=dry_run)
        if ok:
            click.echo(f"  {colorama.Fore.GREEN}✓{colorama.Fore.RESET} {tool}  {msg}")
            success_count += 1
        else:
            click.echo(f"  {colorama.Fore.RED}✗{colorama.Fore.RESET} {tool}: {msg}")
            failed_tools.append(tool)

    return success_count, failed_tools


@utils_group.command(name="setup-autocomplete", no_args_is_help=False)
@click.option(
    "--shell",
    type=click.Choice(["zsh", "bash", "powershell"], case_sensitive=False),
    default=None,
    show_default=False,
    help="Target shell for which to generate static completion files (auto-detected if not specified).",
)
@click.option(
    "--tools",
    multiple=True,
    help="Specific tools to enable completion for (default: all tools)",
)
@click.option(
    "--list-tools",
    is_flag=True,
    help="List all available SPSDK tools and exit.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show what would be done without writing any files.",
)
def setup_autocomplete(shell: str | None, tools: tuple, list_tools: bool, dry_run: bool) -> None:
    """Setup static shell autocompletion for SPSDK tools.

    Generates a pre-built completion script for each tool that loads
    instantly on TAB — no Python process is spawned during completion.

    The target shell is auto-detected from the environment (Windows →
    PowerShell; ``$SHELL`` variable → zsh/bash) but can be overridden with
    ``--shell``.

    For zsh, completion files are written to
    ``~/.config/spsdk/completions/`` and the required ``fpath`` entry is
    added to ``~/.zshrc``.

    Examples:
        spsdk utils setup-autocomplete

        spsdk utils setup-autocomplete --shell powershell

        spsdk utils setup-autocomplete --tools nxpfuses nxpimage

        spsdk utils setup-autocomplete --list-tools
    """
    if list_tools:
        _list_available_tools()
        return

    if shell is None:
        shell = _detect_shell()
        click.echo(f"Auto-detected shell: {shell}")
    shell = shell.lower()
    tools_to_setup = _validate_and_get_tools(tools)
    if tools_to_setup is None:
        return

    success_count, failed_tools = _setup_static_completion(tools_to_setup, shell, dry_run)

    click.echo()
    if success_count > 0:
        click.echo(
            colorama.Fore.GREEN
            + f"Generated static completion for {success_count} tool(s)."
            + colorama.Fore.RESET
        )
        from spsdk.utils.autocomplete import (
            get_completions_dir,
            setup_bash_profile,
            setup_powershell_profile,
            setup_zsh_profile,
        )

        completions_dir = get_completions_dir()
        if shell == "zsh":
            profile_msg = setup_zsh_profile(completions_dir, dry_run=dry_run)
            click.echo(profile_msg)
            click.echo("\nRestart your shell or run:  source ~/.zshrc")
        elif shell == "bash":
            profile_msg = setup_bash_profile(completions_dir, dry_run=dry_run)
            click.echo(profile_msg)
            click.echo("\nRestart your shell or run:  source ~/.bashrc")
        elif shell == "powershell":
            profile_msg = setup_powershell_profile(completions_dir, dry_run=dry_run)
            click.echo(profile_msg)
            click.echo("\nRestart PowerShell or run:  . $PROFILE")

    if failed_tools:
        click.echo(
            colorama.Fore.YELLOW
            + f"\nFailed to generate completion for: {', '.join(failed_tools)}"
            + colorama.Fore.RESET
        )


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
