#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Script setting up target (MCU) models for WPC."""

import os
import secrets
import shutil

from InquirerPy import inquirer
from ruamel.yaml import YAML

from spsdk.crypto.keys import EccCurve, PrivateKeyEcc


def main() -> None:
    """Setting up target (MCU) models for WPC."""
    model_root = inquirer.filepath(
        message="Path to root folders with target models",
        only_directories=True,
    ).execute()
    os.makedirs(model_root, exist_ok=True)
    while True:
        model_name = inquirer.text(message="Name for the device").execute()
        model_dir = os.path.join(model_root, model_name)
        if os.path.isdir(model_dir):
            overwrite = inquirer.confirm(
                message=f"Device model '{model_name}' already exists. Overwrite?",
                default=False,
            ).execute()
            if not overwrite:
                create_next = inquirer.confirm(
                    message="Create another target model?",
                    default=True,
                ).execute()
                if not create_next:
                    break
                continue
            shutil.rmtree(model_dir)
        os.makedirs(model_dir, exist_ok=True)

        prk = PrivateKeyEcc.generate_key(EccCurve.SECP256R1)
        prk.save(os.path.join(model_dir, "wpc_prk.pem"))

        with open(os.path.join(model_dir, "config.yaml"), "w") as f:
            YAML().dump(
                {
                    "uuid": secrets.token_hex(16),
                    "prk_key": "wpc_prk.pem",
                    "csr_blob": "csr_blob.bin",
                    "cert_chain": "cert_chain.bin",
                    "manufacturer_cert": "manufacturer.crt",
                    "product_unit_cert": "product_unit.crt",
                    "ca_root_hash": "ca_root_hash.txt",
                },
                f,
            )
        create_next = inquirer.confirm(
            message=f"Model '{model_name}' created. Create another target model?",
            default=True,
        ).execute()
        if not create_next:
            break


if __name__ == "__main__":
    main()
