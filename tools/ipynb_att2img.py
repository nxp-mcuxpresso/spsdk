#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Simple script to get the attached pictures in Jupiter notebooks to external files."""

import base64
import json
import os
from typing import Any, Optional

import click

from spsdk.utils.misc import load_text, write_file


@click.command(no_args_is_help=True)
@click.option("-f", "--filepath", "filepath", required=True)
@click.option(
    "-o",
    "--output_dir",
    "output_dir",
    default="IMG",
    help="Relative path to original file to store images",
)
def export_images(filepath: str, output_dir: str) -> None:
    """Parse JUPITER and export attached PNG pictures to external files.

    :param filepath: Path to Jupiter Notebook file.
    :param output_dir: Relative path to store exported files.
    """
    jupiter = json.loads(load_text(filepath))
    jupiter_cells: list[dict[str, Any]] = jupiter["cells"]
    img_store_path = os.path.join(os.path.dirname(filepath), output_dir)
    for c_id, cell in enumerate(jupiter_cells):
        if cell.get("cell_type") == "markdown":
            attachments: Optional[dict[str, dict[str, str]]] = cell.get("attachments")
            if attachments:
                att_solved: list[str] = []
                for k, v in attachments.items():
                    new_location = os.path.join(img_store_path, f"{c_id}_{k}")
                    # Store the picture from attachment to external PNG file
                    png = base64.decodebytes(bytes(v["image/png"], "utf-8"))
                    write_file(png, new_location, "wb")

                    # Find the places where is attachment used and rewrite it to new place
                    source: str = cell["source"]
                    for i, line in enumerate(source):
                        cell["source"][i] = line.replace(
                            f"(attachment:{k})",
                            f"({os.path.join(output_dir, f'{c_id}_{k}')})".replace("\\", "/"),
                        )
                    # cell["source"] = source
                    att_solved.append(k)
                for att in att_solved:
                    attachments.pop(att)

    write_file(json.dumps(jupiter), filepath)


if __name__ == "__main__":
    export_images()  # pylint: disable=no-value-for-parameter
