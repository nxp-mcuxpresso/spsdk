#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This example shows how to create a simple bootable image (i.MX-RT).

After the image is created, the DCD part, application segment are added.
The basic info of the whole segment is displayed.
The image is saved to a file.
"""

import os

from spsdk.image import BootImgRT, SegDCD

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")


def main() -> None:
    """Main function."""
    # Create Boot Image instance
    img = BootImgRT(address=0x20000000, version=0x40)

    # Add DCD segment
    with open(f"{DATA_DIR}/dcd.txt", "r") as f_txt:
        img.dcd = SegDCD.parse_txt(f_txt.read())

    # Add application segment
    with open(f"{DATA_DIR}/ivt_flashloader.bin", "rb") as f_bin:
        img.add_image(data=f_bin.read())

    # Print image info
    print(img.info())

    # Save into file
    with open(f"{DATA_DIR}/flashloader.imx", "wb") as f:
        f.write(img.export())


if __name__ == "__main__":
    main()
