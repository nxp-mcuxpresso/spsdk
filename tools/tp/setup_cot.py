#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import os
import secrets
import sys

import click

from spsdk.crypto.certificate_management import (
    generate_certificate,
    generate_name,
    save_crypto_item,
)
from spsdk.crypto.keys_management import (
    CurveName,
    generate_ecc_private_key,
    save_ecc_private_key,
    save_ecc_public_key,
)
from spsdk.crypto.loaders import load_private_key
from spsdk.tp.adapters.model_utils import ecc_key_to_bytes
from spsdk.tp.data_container import AuthenticationType, Container, DataEntry, PayloadType
from spsdk.tp.utils import get_supported_devices
from spsdk.utils.misc import write_file


@click.group()
def main() -> None:
    """Generate PC and Target Trust Provisioning certificates for testing."""
    pass


@main.command(name="pc-cert", no_args_is_help=True)
@click.option(
    "-g",
    "--glob-key",
    type=click.Path(readable=True),
    help="Path to existing NXP_GLOB private key. If omitted, new one private key and certificate will be created.",
)
@click.option(
    "-o",
    "--output-folder",
    type=click.Path(file_okay=False),
    required=True,
    help="Path to non-existing/empty folder where to store keys and certificates.",
)
def gen_pc_cert(glob_key: str, output_folder: str) -> None:
    """Generate PC-side certificates (aka NXP_GLOB and NXP_PROD)."""
    os.makedirs(output_folder, exist_ok=True)
    if os.listdir(output_folder):
        click.echo(
            f"Folder '{output_folder}' contains files. Please use non-existing or empty folder."
        )
        click.get_current_context().exit(1)
    if glob_key:
        glob_private_key = load_private_key(glob_key)
    else:
        glob_private_key = generate_ecc_private_key(CurveName.SECP256R1)
        dest_path = os.path.join(output_folder, "nxp_glob_devattest_prk.pem")
        save_ecc_private_key(glob_private_key, dest_path)
        print(f"NXP GLOB prk saved to: {dest_path}")

        glob_public_key = glob_private_key.public_key()
        dest_path = os.path.join(output_folder, "nxp_glob_devattest_puk.pem")
        save_ecc_public_key(glob_public_key, dest_path)
        print(f"NXP GLOB puk saved to: {dest_path}")

        glob_cert = generate_certificate(
            subject=generate_name({"COMMON_NAME": "NXP GLOB TEST"}),
            issuer=generate_name({"COMMON_NAME": "NXP GLOB TEST"}),
            subject_public_key=glob_public_key,
            issuer_private_key=glob_private_key,
            if_ca=True,
        )
        dest_path = os.path.join(output_folder, "nxp_glob_devattest_cert.crt")
        save_crypto_item(glob_cert, dest_path)
        print(f"NXP GLOB crt saved to: {dest_path}")

    prod_private_key = generate_ecc_private_key(CurveName.SECP256R1)
    prod_public_key = prod_private_key.public_key()
    dest_path = os.path.join(output_folder, f"nxp_prod_devattest_prk.pem")
    save_ecc_private_key(prod_private_key, dest_path)
    print(f"NXP PROD prk saved to: {dest_path}")
    dest_path = os.path.join(output_folder, f"nxp_prod_devattest_puk.pem")
    save_ecc_public_key(prod_public_key, dest_path)
    print(f"NXP PROD puk saved to: {dest_path}")

    prod_cert = generate_certificate(
        subject=generate_name({"COMMON_NAME": "NXP PROD TEST"}),
        issuer=generate_name({"COMMON_NAME": "NXP GLOB TEST"}),
        subject_public_key=prod_public_key,
        issuer_private_key=glob_private_key,
    )
    dest_path = os.path.join(output_folder, f"nxp_prod_devattest_cert.crt")
    save_crypto_item(prod_cert, dest_path)
    print(f"NXP PROD crt saved to: {dest_path}")


@main.command(name="die-cert", no_args_is_help=True)
@click.option(
    "-u",
    "--uuid",
    help="32 char UUID (spaces are allowed). If omitted a random UUID will be generated.",
)
@click.option(
    "-e",
    "--ecid",
    help="32 char ECID (spaces are allowed). If omitted a random ECID will be generated.",
)
@click.option("-f", "--family", type=click.Choice(get_supported_devices()), required=True)
@click.option(
    "-p",
    "--prod-key",
    required=True,
    type=click.Path(readable=True),
    help="Path to existing NXP_PROD private key.",
)
@click.option(
    "-o",
    "--output-folder",
    required=True,
    type=click.Path(file_okay=False),
    help="Path to non-existing/empty folder where to store keys and certificates.",
)
def gen_die_cert(uuid: str, ecid: str, family: str, prod_key: str, output_folder: str) -> None:
    """Generate target/die certificate (aka nxp_die_devattest_id_cert)."""
    if not uuid:
        uuid = secrets.token_hex(16)
    if not ecid:
        ecid = secrets.token_hex(16)

    uuid = uuid.replace(" ", "")
    ecid = ecid.replace(" ", "")

    if len(uuid) != 32:
        click.echo(f"UUID is {len(uuid)} chars long. UUID must be 32chars (16B).")
        click.get_current_context().exit(1)
    if len(ecid) != 32:
        click.echo(f"ECID is {len(ecid)} chars long. ECID must be 32chars (16B).")
        click.get_current_context().exit(1)

    os.makedirs(output_folder, exist_ok=True)
    if os.listdir(output_folder):
        click.echo(
            f"Folder {output_folder} contains files. please use non-existing or empty folder."
        )
        click.get_current_context().exit(1)
    prod_private_key = load_private_key(prod_key)

    id_auth_private_key = generate_ecc_private_key(CurveName.SECP256R1)
    save_ecc_private_key(
        id_auth_private_key, os.path.join(output_folder, "nxp_die_id_auth_prk.pem")
    )
    id_auth_public_key = id_auth_private_key.public_key()
    save_ecc_public_key(id_auth_public_key, os.path.join(output_folder, "nxp_die_id_auth_puk.pem"))

    die_cert = Container()
    die_cert.add_entry(
        DataEntry(
            payload_type=PayloadType.NXP_DIE_ID_AUTH_PUK,
            payload=ecc_key_to_bytes(id_auth_public_key),
        )
    )
    if family == "lpc55s3x":
        id_attest_private_key = generate_ecc_private_key(CurveName.SECP256R1)
        save_ecc_private_key(
            id_attest_private_key, os.path.join(output_folder, "nxp_die_id_attest_prk.pem")
        )
        id_attest_public_key = id_attest_private_key.public_key()
        save_ecc_public_key(
            id_attest_public_key, os.path.join(output_folder, "nxp_die_id_attest_puk.pem")
        )
        die_cert.add_entry(
            DataEntry(
                payload_type=PayloadType.NXP_DIE_ATTEST_AUTH_PUK,
                payload=ecc_key_to_bytes(id_attest_public_key),
            )
        )
    die_cert.add_entry(
        DataEntry(
            payload_type=PayloadType.NXP_DIE_ECID_ID_UID,
            payload=bytes.fromhex(ecid),
        )
    )
    die_cert.add_entry(
        DataEntry(
            payload_type=PayloadType.NXP_DIE_RFC4122v4_ID_UUID,
            payload=bytes.fromhex(uuid),
        )
    )
    die_cert.add_auth_entry(
        auth_type=AuthenticationType.ECDSA_256,
        key=prod_private_key,  # type: ignore
    )
    print(die_cert)
    dest_path = os.path.join(output_folder, "nxp_die_devattest_id_cert.bin")
    write_file(die_cert.export(), dest_path, mode="wb")
    print(f"DIE ID cert saved to: {dest_path}")


@main.command(name="card")
@click.option(
    "-o",
    "--output-folder",
    type=click.Path(file_okay=False),
    required=True,
    help="Path to non-existing/empty folder where to store smart card keys.",
)
def card(output_folder: str) -> None:
    """Generate public/private key for Smart Card."""
    os.makedirs(output_folder, exist_ok=True)
    if os.listdir(output_folder):
        click.echo(
            f"Folder {output_folder} contains files. please use non-existing or empty folder."
        )
        click.get_current_context().exit(1)
    card_prk = generate_ecc_private_key(CurveName.SECP256R1)
    dest_path = os.path.join(output_folder, "nxp_prod_card_auth_prk.pem")
    save_ecc_private_key(card_prk, dest_path)
    print(f"CARD prk saved to: {dest_path}")

    card_puk = card_prk.public_key()
    dest_path = os.path.join(output_folder, "nxp_prod_card_auth_puk.pem")
    save_ecc_public_key(card_puk, dest_path)
    print(f"CARD puk saved to: {dest_path}")


if __name__ == "__main__":
    sys.exit(main())
