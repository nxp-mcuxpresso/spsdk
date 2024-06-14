#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
# Script for updating README.md file with the content of devices_table.inc file
import os
from generate_table import DEVICES_TABLE_FILE


def main():
    print("Updating README.md file")
    # Specify the paths of the README.md file and the devices_table.inc file
    current_dir = os.path.dirname(os.path.abspath(__file__))
    readme_path = os.path.join(current_dir, "..", "..", "README.md")
    devices_table_path = DEVICES_TABLE_FILE

    # Read the content of the devices_table.inc file
    with open(devices_table_path, "r") as devices_table_file:
        devices_table_content = devices_table_file.read()

    # Read the content of the README.md file
    with open(readme_path, "r") as readme_file:
        readme_content = readme_file.read()

    # Find the "Supported devices" section in the README.md content
    start_marker = "## Supported Devices"
    end_marker = "## Supported environments"
    start_index = readme_content.find(start_marker) + len(start_marker)
    end_index = readme_content.find(end_marker)

    # Replace the "Supported devices" section with the content of devices_table.inc
    new_readme_content = (
        readme_content[:start_index] + "\n\n" + devices_table_content + readme_content[end_index:]
    )

    # Write the updated content back to the README.md file
    with open(readme_path, "w") as readme_file:
        readme_file.write(new_readme_content)


def setup(app):
    main()


if __name__ == "__main__":
    main()
