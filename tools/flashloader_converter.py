#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This script helps with creating a flashloader.bin for use by SPSDK."""

import os
import shutil
import subprocess
import sys
from typing import Optional

import click

THIS_DIR = os.path.dirname(os.path.abspath(__file__)).replace('\\', '/')
TARGET_DIRS = [
    os.path.normpath(os.path.join(THIS_DIR, target))
    for target in ['../examples/data', '../tests/mcu_examples/rt105x']
]


@click.command()
@click.option('-e', '--elf-file', type=click.Path(exists=True),
              help='Path to the original flashloader elf file', required=True)
@click.option('-t', '--ide-type', type=click.Choice(['mcux', 'iar', 'keil']),
              help='Type of tool to use for converting elf -> bin', required=True)
@click.option('-p', '--ide-path', type=click.Path(exists=True),
              help='Path to IDE install (root) folder', required=True)
def main(elf_file: click.File, ide_type: str, ide_path: click.Path) -> None:
    """Prepare flashloader for usage by SPSDK.

    \b
      - Convert the flashloader.elf into binary
      - Prepend binary with Image Vector Table
      - Copy result to locations required by SPSDK.
    """
    bin_file = f'{THIS_DIR}/flashloader.bin'
    cmd = get_elf_to_bin_command(ide_type, ide_path, elf_file, bin_file)
    if cmd is None:
        sys.exit(1)
    try:
        click.echo(f'Running: {cmd}')
        subprocess.call(cmd)
        click.echo('Creating ivt_flashloader')
        combine_files(
            f'{THIS_DIR}/ivt_flashloader.bin',
            f'{THIS_DIR}/preamble.bin', f'{THIS_DIR}/flashloader.bin'
        )
        for target in TARGET_DIRS:
            click.echo(f'Copying ivt_flashloader to {target}')
            shutil.copy(f'{THIS_DIR}/ivt_flashloader.bin', target)
        os.remove(f'{THIS_DIR}/flashloader.bin')
        os.remove(f'{THIS_DIR}/ivt_flashloader.bin')
    except subprocess.CalledProcessError as e:
        click.echo(f'Execution failed\n{e}')
    except OSError as e:
        click.echo(f'OS error occurred\n{e}')


def combine_files(out_file: str, *in_files: str) -> None:
    """Combine in_files into one out_file."""
    with open(out_file, 'wb') as out_file_h:
        for in_file in in_files:
            with open(in_file, 'rb') as f:
                shutil.copyfileobj(f, out_file_h)


def get_elf_to_bin_command(ide_type: str, ide_path: click.Path,
                           elf_file: click.File, bin_file: str) -> Optional[str]:
    """Geneate a command to use converting elf_file to bin_file using ide_type."""
    if ide_type == 'iar':
        tool_path = add_exe(f'{ide_path}/arm/bin/ielftool')
        if not os.path.isfile(tool_path):
            click.echo(f'IAR ELF Tool was not found: {tool_path}', err=True)
        else:
            return f'{tool_path} {elf_file} --bin {bin_file}'
    if ide_type == 'mcux':
        tool_path = add_exe(f'{ide_path}/ide/tools/bin/arm-none-eabi-objcopy')
        if not os.path.isfile(tool_path):
            click.echo(
                f'ARM Object Copy tool was not found: {tool_path}', err=True)
        else:
            return f'{tool_path} --output-target binary {elf_file} {bin_file}'
    if ide_type == 'keil':
        tool_path = add_exe(f'{ide_path}/ARM/ARMCC/bin/fromelf')
        if not os.path.isfile(tool_path):
            click.echo(
                f'ARM image conversion utility was not found: {tool_path}', err=True)
        else:
            return f'{tool_path} --bincombined {elf_file} --output {bin_file}'
    return None

def add_exe(tool_path: str) -> str:
    """Add the .exe suffix if we are on Windows."""
    path = tool_path
    path += '.exe' if sys.platform == 'win32' else ''
    return path


if __name__ == "__main__":
    sys.exit(main())  # pylint: disable=no-value-for-parameter
