#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Script setting up models for EL2GO mock-up."""

import os
import secrets
import shutil
import sys

from InquirerPy import inquirer
from ruamel.yaml import YAML

from spsdk.crypto.certificate import Certificate, SPSDKEncoding, generate_extensions, generate_name
from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.crypto.keys import EccCurve, PrivateKeyEcc
from spsdk.utils.misc import write_file


def generate_root(root_path: str) -> PrivateKeyEcc:
    """Generate root key for EL2GO.

    :param root_path: Root path
    :return: Private ECC key
    """
    prk = PrivateKeyEcc.generate_key(EccCurve.SECP256R1)
    prk.save(os.path.join(root_path, "wpc_root_prk.pem"))
    puk = prk.get_public_key()
    puk.save(os.path.join(root_path, "wpc_root_puk.pem"))
    crt = Certificate.generate_certificate(
        subject=generate_name({"COMMON_NAME": "WPCCA1"}),
        issuer=generate_name({"COMMON_NAME": "WPCCA1"}),
        subject_public_key=puk,
        issuer_private_key=prk,
        extensions=generate_extensions({"BASIC_CONSTRAINTS": {"ca": True, "path_length": None}}),
    )
    crt.save(os.path.join(root_path, "wpc_root.crt"), SPSDKEncoding.DER)
    crt_data = crt.export(SPSDKEncoding.DER)
    crt_hash = get_hash(crt_data, EnumHashAlgorithm.SHA256)
    write_file(crt_hash.hex(), path=os.path.join(root_path, "wpc_root_hash.txt"))
    return prk


def generate_qi_id(
    model_path: str, subject: str, policy: int, root_key: PrivateKeyEcc, extra_text: str
) -> None:
    """Generate QI ID.

    :param model_path: Filename of model
    :param subject: TODO
    :param policy: TODO
    :param root_key: TODO
    :param extra_text: TODO
    """
    prk = PrivateKeyEcc.generate_key(EccCurve.SECP256R1)
    prk.save(os.path.join(model_path, "manufacturer_prk.pem"))
    puk = prk.get_public_key()
    puk.save(os.path.join(model_path, "manufacturer_puk.pem"))
    crt = Certificate.generate_certificate(
        subject=generate_name({"COMMON_NAME": subject}),
        issuer=generate_name({"COMMON_NAME": "WPCCA1"}),
        subject_public_key=puk,
        issuer_private_key=root_key,
        extensions=generate_extensions({"WPC_QIAUTH_POLICY": {"value": policy}}),
    )
    crt.save(os.path.join(model_path, "manufacturer.crt"), SPSDKEncoding.DER)
    with open(os.path.join(model_path, "config.yaml"), "w") as f:
        YAML().dump(
            {
                "tokens": [secrets.token_hex(6), secrets.token_hex(6)],
                "manufacturer_crt": "manufacturer.crt",
                "manufacturer_prk": "manufacturer_prk.pem",
                "subject": subject,
                "policy": policy,
                "extra_text": extra_text,
                "wpc_root_hash": "../wpc_root_hash.txt",
            },
            f,
        )


def main() -> None:
    """Setting up models for EL2GO mock-up."""
    root_dir = inquirer.filepath(
        message="Path to root folder for service model",
        only_directories=True,
    ).execute()
    if os.path.isdir(root_dir):
        overwrite = inquirer.confirm(
            message="Service model folder already exists. Overwrite?",
            default=False,
        ).execute()
        if not overwrite:
            sys.exit(0)
        shutil.rmtree(root_dir)
    os.makedirs(root_dir, exist_ok=True)
    root_prk = generate_root(root_path=root_dir)

    while True:
        qi_id = inquirer.number(message="Enter new Qi ID").execute()
        model_dir = os.path.join(root_dir, qi_id)
        if os.path.isdir(model_dir):
            overwrite = inquirer.confirm(
                message=f"Qi ID '{qi_id}' already exists. Overwrite?",
                default=False,
            ).execute()
            if not overwrite:
                create_next = inquirer.confirm(
                    message="Create another Qi ID?",
                    default=True,
                ).execute()
                if not create_next:
                    break
                continue
            shutil.rmtree(model_dir)
        os.makedirs(model_dir, exist_ok=True)
        ptmc = inquirer.text(
            message="Enter 4 char PTMC (Power Transmitter Product manufacturer code)",
            default="CACA",
        ).execute()
        suffix = inquirer.text(
            message="Enter 2 char CA identifier",
            default="1A",
        ).execute()
        policy = inquirer.number(
            message="Enter Qi Auth Policy",
            default=1,
        ).execute()
        subject = f"{ptmc}-{suffix}"
        extra_text = inquirer.text(
            message="Additional text for product cert common name",
        ).execute()
        generate_qi_id(model_dir, subject, int(policy), root_prk, extra_text)

        create_next = inquirer.confirm(
            message=f"Qi ID '{qi_id}' created. Create another Qi ID?", default=True
        ).execute()
        if not create_next:
            break


if __name__ == "__main__":
    main()
