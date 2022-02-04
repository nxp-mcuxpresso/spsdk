#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This example shows how to create fuses file (SRK) from certificates."""

import os
import sys

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from spsdk.image import SrkItem, SrkTable

# The path to directory with certificates
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "certificates")


def main() -> None:
    """Main function."""
    cert_files = [f for f in os.listdir(DATA_DIR) if f.endswith(".pem")]
    if not cert_files:
        print(f'Add generated *.pem files into "{DATA_DIR}" directory')
        sys.exit()

    # Create SRK Table instance
    srk_table = SrkTable(version=0x40)

    for cert_file in cert_files:
        with open(f"{DATA_DIR}/{cert_file}", "rb") as f:
            certificate = x509.load_pem_x509_certificate(f.read(), default_backend())
            srk_item = SrkItem.from_certificate(certificate)
            srk_table.append(srk_item)

    with open(f"{DATA_DIR}/srk_fuses.bin", "wb") as f:
        f.write(srk_table.export_fuses())

    with open(f"{DATA_DIR}/srk_table.bin", "wb") as f:
        f.write(srk_table.export())


if __name__ == "__main__":
    main()
