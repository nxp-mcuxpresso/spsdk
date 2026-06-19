#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK NXP USB Device Scanner application.

This module provides a command-line utility for scanning and detecting
NXP USB devices connected to the system. It offers functionality to
identify supported NXP microcontrollers and development boards.
"""

import os
import sys
from typing import IO, TYPE_CHECKING, Optional, Sequence, Union

if TYPE_CHECKING:
    import prettytable as pt

import click
from click_option_group import MutuallyExclusiveOptionGroup, optgroup

from spsdk.apps.utils import spsdk_logger
from spsdk.apps.utils.common_cli_options import spsdk_apps_common_options, timeout_option
from spsdk.apps.utils.utils import catch_spsdk_error
from spsdk.utils import nxpdevscan
from spsdk.utils.devicedescription import (
    SDIODeviceDescription,
    SIODeviceDescription,
    UartDeviceDescription,
    USBDeviceDescription,
    UUUDeviceDescription,
)

_AnyDevice = Union[
    SDIODeviceDescription,
    USBDeviceDescription,
    UartDeviceDescription,
    SIODeviceDescription,
    UUUDeviceDescription,
]

_VERTICAL_SEP = "\x00"  # sentinel emitted by _build_vertical_lines between devices


def _fill_usb_table(table: "pt.PrettyTable", devices: Sequence[_AnyDevice]) -> None:
    """Populate a PrettyTable with USB device rows.

    :param table: PrettyTable instance to fill.
    :param devices: Sequence of USBDeviceDescription objects.
    """
    table.field_names = ["VID", "PID", "Product", "Name", "Path", "Path Hash", "Serial"]
    for dev in devices:
        assert isinstance(dev, USBDeviceDescription)
        table.add_row(
            [
                f"0x{dev.vid:04x}",
                f"0x{dev.pid:04x}",
                dev.product_string or "N/A",
                dev.name or "N/A",
                dev.path,
                dev.path_hash,
                dev.serial or "N/A",
            ]
        )


def _fill_uart_table(table: "pt.PrettyTable", devices: Sequence[_AnyDevice]) -> None:
    """Populate a PrettyTable with UART device rows.

    :param table: PrettyTable instance to fill.
    :param devices: Sequence of UartDeviceDescription objects.
    """
    table.field_names = ["Port", "Type"]
    for dev in devices:
        assert isinstance(dev, UartDeviceDescription)
        table.add_row([dev.name, dev.dev_type])


def _fill_sio_table(table: "pt.PrettyTable", devices: Sequence[_AnyDevice]) -> None:
    """Populate a PrettyTable with SIO device rows.

    :param table: PrettyTable instance to fill.
    :param devices: Sequence of SIODeviceDescription objects.
    """
    table.field_names = [
        "VID",
        "PID",
        "Manufacturer",
        "Product",
        "Path",
        "Path Hash",
        "Serial",
        "Interface #",
        "Release",
    ]
    for dev in devices:
        assert isinstance(dev, SIODeviceDescription)
        table.add_row(
            [
                f"0x{dev.vid:04x}",
                f"0x{dev.pid:04x}",
                dev.manufacturer_string or "N/A",
                dev.product_string or "N/A",
                dev.path,
                dev.path_hash or "N/A",
                dev.serial_number or "N/A",
                str(dev.interface_number),
                f"0x{dev.release_number:04x}",
            ]
        )


def _fill_uuu_table(table: "pt.PrettyTable", devices: Sequence[_AnyDevice]) -> None:
    """Populate a PrettyTable with UUU device rows.

    :param table: PrettyTable instance to fill.
    :param devices: Sequence of UUUDeviceDescription objects.
    """
    table.field_names = ["Path", "Chip", "Product", "VID", "PID", "Serial"]
    for dev in devices:
        assert isinstance(dev, UUUDeviceDescription)
        table.add_row(
            [
                dev.path,
                dev.chip,
                dev.pro,
                f"0x{dev.vid:04x}",
                f"0x{dev.pid:04x}",
                dev.serial_no or "N/A",
            ]
        )


def _fill_sdio_table(table: "pt.PrettyTable", devices: Sequence[_AnyDevice]) -> None:
    """Populate a PrettyTable with SDIO device rows.

    :param table: PrettyTable instance to fill.
    :param devices: Sequence of SDIODeviceDescription objects.
    """
    table.field_names = ["VID", "PID", "Path"]
    for dev in devices:
        assert isinstance(dev, SDIODeviceDescription)
        table.add_row([f"0x{dev.vid:04x}", f"0x{dev.pid:04x}", dev.path])


def _make_device_table(devices: Sequence[_AnyDevice]) -> "pt.PrettyTable":
    """Create and populate a borderless PrettyTable for the given device sequence.

    :param devices: Non-empty sequence of device description objects of the same type.
    :return: Filled PrettyTable instance (no borders, left-aligned).
    """
    import prettytable as pt

    first = devices[0]
    table = pt.PrettyTable()
    table.align = "l"
    table.header = True
    table.border = False
    table.hrules = pt.HRuleStyle.NONE
    table.vrules = pt.VRuleStyle.NONE

    if isinstance(first, USBDeviceDescription):
        _fill_usb_table(table, devices)
    elif isinstance(first, UartDeviceDescription):
        _fill_uart_table(table, devices)
    elif isinstance(first, SIODeviceDescription):
        _fill_sio_table(table, devices)
    elif isinstance(first, UUUDeviceDescription):
        _fill_uuu_table(table, devices)
    elif isinstance(first, SDIODeviceDescription):
        _fill_sdio_table(table, devices)

    return table


def _build_device_table_lines(
    devices: Sequence[_AnyDevice], max_width: Optional[int] = None
) -> list[str]:
    """Build plain-text table lines for the given device list.

    Returns a list of strings: the first line is the column header row and
    the remaining lines are data rows. No borders or separators are included
    so the caller can embed the lines inside a custom box.

    :param devices: Non-empty sequence of device description objects of the same type.
    :param max_width: Optional maximum width for the table content. When set,
        prettytable will truncate columns to fit within this width.
    :return: List of space-aligned plain-text lines (header first, then data rows).
    """
    table = _make_device_table(devices)
    if max_width is not None:
        table.max_table_width = max_width
    return table.get_string().splitlines()


def _build_vertical_lines(devices: Sequence[_AnyDevice]) -> list[str]:
    """Render devices as vertical key-value records (fallback for narrow terminals).

    Each device is shown as a labelled block of ``Key : Value`` pairs so the
    output is always readable regardless of terminal width.

    :param devices: Non-empty sequence of device description objects of the same type.
    :return: List of plain-text lines ready to place inside a box.
    """
    table = _make_device_table(devices)
    field_names = table.field_names
    key_w = max(len(f) for f in field_names)
    lines: list[str] = []
    for i, row in enumerate(table.rows):
        if i > 0:
            lines.append(_VERTICAL_SEP)
        for field, value in zip(field_names, row):
            lines.append(f"  {field:<{key_w}} : {value}")
    return lines


def _print_devices(output: IO[str], title: str, devices: Sequence[_AnyDevice]) -> None:
    """Print connected devices inside a unified box with colored output to stdout.

    Renders a single box containing the section title, device count, and (when
    devices are present) a space-aligned table with a column-header separator.
    Formatting is only applied when writing to stdout; plain text is used for
    file output.

    :param output: Output stream
    :param title: Title for the device group section
    :param devices: Device descriptors to display
    """
    is_stdout = hasattr(output, "name") and output.name == "<stdout>"
    if not is_stdout:
        for device in devices:
            click.echo(str(device), file=output)
            click.echo("", file=output)
        return

    count = len(devices)
    count_label = f"({count} device{'s' if count != 1 else ''})"
    full_title = f"{title}  {count_label}"

    try:
        term_columns = os.get_terminal_size().columns
        terminal_known = True
    except OSError:
        term_columns = 120
        terminal_known = False
    # The box uses 2 chars for the ║ borders, leaving this many for content.
    max_content_w = term_columns - 2

    if devices:
        if terminal_known:
            # Build the table at its natural width to see whether it fits.
            natural_lines = _build_device_table_lines(devices)
            natural_w = max((len(line) for line in natural_lines), default=0)
            if natural_w <= max_content_w:
                table_lines = natural_lines
                has_header_row = True
            else:
                # Table would overflow: fall back to vertical key-value layout.
                table_lines = _build_vertical_lines(devices)
                has_header_row = False
        else:
            # Terminal width is unknown: use vertical layout unconditionally.
            table_lines = _build_vertical_lines(devices)
            has_header_row = False
    else:
        table_lines = []
        has_header_row = False

    # inner_w = usable width between ║ and ║ (sentinels have no display width)
    content_widths = [len(line) for line in table_lines if line != _VERTICAL_SEP]
    inner_w = max(len(full_title) + 4, *content_widths, 0) + 2
    # Never let the box exceed the terminal width.
    inner_w = min(inner_w, max_content_w)
    # Safety-truncate any lines that still exceed inner_w (skip sentinels).
    table_lines = [line if line == _VERTICAL_SEP else line[:inner_w] for line in table_lines]

    def _border(left: str, fill: str, right: str) -> str:
        return click.style(left + fill * inner_w + right, fg="cyan", bold=True)

    def _cell(content: str, fg: str = "", bold: bool = False) -> str:
        styled = (
            click.style(content.ljust(inner_w), fg=fg, bold=bold) if fg else content.ljust(inner_w)
        )
        return (
            click.style("║", fg="cyan", bold=True) + styled + click.style("║", fg="cyan", bold=True)
        )

    click.echo(_border("╔", "═", "╗"), file=output)
    # Center the full title; colour title and count separately
    centered = full_title.center(inner_w)
    split_idx = centered.rfind(count_label)
    click.echo(
        click.style("║", fg="cyan", bold=True)
        + click.style(centered[:split_idx], fg="cyan", bold=True)
        + click.style(count_label, fg="green" if count else "yellow")
        + click.style(centered[split_idx + len(count_label) :], fg="cyan", bold=True)
        + click.style("║", fg="cyan", bold=True),
        file=output,
    )

    if table_lines:
        click.echo(_border("╠", "═", "╣"), file=output)
        if has_header_row:
            click.echo(_cell(table_lines[0]), file=output)
            click.echo(_border("╠", "═", "╣"), file=output)
            for line in table_lines[1:]:
                click.echo(_cell(line), file=output)
        else:
            for line in table_lines:
                if line == _VERTICAL_SEP:
                    click.echo(
                        click.style("╟", fg="cyan", bold=True)
                        + click.style("─" * inner_w, fg="cyan")
                        + click.style("╢", fg="cyan", bold=True),
                        file=output,
                    )
                else:
                    click.echo(_cell(line), file=output)

    click.echo(_border("╚", "═", "╝") + "\n", file=output)


def _display_scan_result(
    output: IO[str],
    is_stdout: bool,
    devices: Sequence[_AnyDevice],
    box_title: str,
) -> None:
    """Finalize a scan line and optionally render the device box.

    After the "Scanning …" label has been printed (without a newline), this
    helper either appends "  Nothing found" on the same line or starts a new
    line and renders the full device box.

    :param output: Output stream.
    :param is_stdout: True when output is the terminal (stdout).
    :param devices: Devices found by the preceding scan.
    :param box_title: Title string used inside the box header.
    """
    if is_stdout:
        if devices:
            click.echo("", file=output)
        else:
            click.echo(click.style("  Nothing found", fg="bright_black"), file=output)
    if devices or not is_stdout:
        _print_devices(output, box_title, devices)


@click.command(name="nxpdevscan", no_args_is_help=False)
@click.option(
    "-e",
    "--extend-vids",
    multiple=True,
    default=[],
    help="VID in hex to extend search.",
)
@click.option("-o", "--output", default="-", type=click.File("w"))
# NOTE: The MutuallyExclusiveOptionGroup doesn't work for flags, we keep it just for display purposes
@click.option(
    "-n", "--no-scan", is_flag=True, default=True, help="Do not scan UART devices by pinging them."
)
@click.option("--nxp", is_flag=True, default=True, help="Scan only NXP UART devices.")
@click.option("--uboot", is_flag=True, default=False, help="Scan for U-Boot console.")
@click.option(
    "-b",
    "--baudrate",
    type=int,
    default=None,
    help=(
        "UART baud rate to use when scanning for mboot devices. "
        "The mboot protocol supports automatic baud rate detection, "
        "so this is only needed for non-standard rates, "
        "e.g. '--baudrate 115200' for MCXE31 or other ELE-based devices."
    ),
)
@click.option(
    "-r",
    "--real-devices",
    is_flag=True,
    default=False,
    help="Check if the serial device is a real device using ioctl TIOCGSERIAL.",
)
@timeout_option(timeout=50)
@optgroup.group("Narrow down the scope of scanning", cls=MutuallyExclusiveOptionGroup)
@optgroup.option(
    "-a",
    "--all",
    "scope",
    flag_value="all",
    default=True,
    help="Search for all NXP devices (default)",
)
@optgroup.option(
    "-u",
    "--usb",
    "scope",
    flag_value="usb",
    help="Search only for USB devices",
)
@optgroup.option(
    "-sd",
    "--sdio",
    "scope",
    flag_value="sdio",
    help="Search only for SDIO devices",
)
@optgroup.option(
    "-p",
    "--port",
    "scope",
    flag_value="port",
    help="Search only for UART devices",
)
@optgroup.option(
    "-l",
    "--lpcusbsio",
    "scope",
    flag_value="lpcusbsio",
    help="Search only for USBSIO devices",
)
@optgroup.option(  # type: ignore[arg-type]
    "--uuu",
    "scope",
    flag_value="uuu",
    help="Search only for UUU devices",
)
@spsdk_apps_common_options
def main(
    extend_vids: str,
    output: IO[str],
    scope: str,
    log_level: int,
    no_scan: bool,
    nxp: bool,
    uboot: bool,
    timeout: int = 50,
    real_devices: bool = False,
    baudrate: Optional[int] = None,
) -> None:
    """Utility listing all connected NXP USB and UART devices.

    NOTE: This utility lists all NXPs USB and UART devices connected to the host.
    By default it scans UART devices by pinging them (sending the mboot or SDP command).
    This however causes that the device ISP mode is locked to UART.
    Use the -n/--no-scan option to disable this behavior.
    If you want to only scan for NXP UART devices, use the --nxp option.
    """
    spsdk_logger.install(level=log_level)
    additional_vids = [int(vid, 16) for vid in extend_vids]

    is_stdout = hasattr(output, "name") and output.name == "<stdout>"

    if scope in ["all", "sdio"] and sys.platform != "win32":
        if is_stdout:
            click.echo(
                click.style("Scanning SDIO devices...", fg="bright_black"), nl=False, file=output
            )
        nxp_sdio_devices = nxpdevscan.search_nxp_sdio_devices()
        _display_scan_result(output, is_stdout, nxp_sdio_devices, "Connected NXP SDIO Devices")

    if scope in ["all", "usb"]:
        if is_stdout:
            click.echo(
                click.style("Scanning USB devices...", fg="bright_black"), nl=False, file=output
            )
        nxp_usb_devices = nxpdevscan.search_nxp_usb_devices(additional_vids)
        _display_scan_result(output, is_stdout, nxp_usb_devices, "Connected NXP USB Devices")

    if scope in ["all", "port"]:
        if is_stdout:
            click.echo(
                click.style("Scanning UART devices...", fg="bright_black"), nl=False, file=output
            )
        nxp_uart_devices = nxpdevscan.search_nxp_uart_devices(
            no_scan, nxp, uboot, timeout, real_devices, baudrate
        )
        _display_scan_result(output, is_stdout, nxp_uart_devices, "Connected NXP UART Devices")

    if scope in ["all", "lpcusbsio"]:
        if is_stdout:
            click.echo(
                click.style("Scanning LPCUSBSIO devices...", fg="bright_black"),
                nl=False,
                file=output,
            )
        nxp_sio_devices = nxpdevscan.search_libusbsio_devices()
        _display_scan_result(output, is_stdout, nxp_sio_devices, "Connected NXP SIO Devices")

    if scope in ["all", "uuu"]:
        if is_stdout:
            click.echo(
                click.style("Scanning UUU devices...", fg="bright_black"), nl=False, file=output
            )
        nxp_uuu_devices = nxpdevscan.search_uuu_usb_devices()
        _display_scan_result(output, is_stdout, nxp_uuu_devices, "Connected NXP UUU Devices")


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()
