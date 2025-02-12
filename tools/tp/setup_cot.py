#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Script to Generate PC-side certificates (aka NXP_GLOB and NXP_PROD)."""
import os
import secrets
import sys

import click

from spsdk.apps.utils.common_cli_options import spsdk_family_option
from spsdk.crypto.certificate import Certificate, generate_extensions, generate_name
from spsdk.crypto.crypto_types import SPSDKEncoding
from spsdk.crypto.keys import EccCurve, PrivateKeyEcc
from spsdk.tp.data_container import AuthenticationType, Container, DataEntry, PayloadType
from spsdk.tp.utils import get_supported_devices
from spsdk.utils.misc import write_file


@click.group(name="setup-cot", no_args_is_help=True)
def main() -> int:
    """Generate PC and Target Trust Provisioning certificates for testing."""
    return 0


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
        glob_private_key = PrivateKeyEcc.load(glob_key)
    else:
        glob_private_key = PrivateKeyEcc.generate_key(EccCurve.SECP256R1)
        dest_path = os.path.join(output_folder, "nxp_glob_devattest_prk.pem")
        glob_private_key.save(dest_path)
        print(f"NXP GLOB prk saved to: {dest_path}")

        glob_public_key = glob_private_key.get_public_key()
        dest_path = os.path.join(output_folder, "nxp_glob_devattest_puk.pem")
        glob_public_key.save(dest_path)
        print(f"NXP GLOB puk saved to: {dest_path}")

        glob_cert = Certificate.generate_certificate(
            subject=generate_name({"COMMON_NAME": "NXP GLOB TEST"}),
            issuer=generate_name({"COMMON_NAME": "NXP GLOB TEST"}),
            subject_public_key=glob_public_key,
            issuer_private_key=glob_private_key,
            extensions=generate_extensions(
                {"BASIC_CONSTRAINTS": {"ca": True, "path_length": None}}
            ),
        )
        dest_path = os.path.join(output_folder, "nxp_glob_devattest_cert.crt")
        glob_cert.save(dest_path)
        print(f"NXP GLOB crt saved to: {dest_path}")

    prod_private_key = PrivateKeyEcc.generate_key(EccCurve.SECP256R1)
    prod_public_key = prod_private_key.get_public_key()
    dest_path = os.path.join(output_folder, "nxp_prod_devattest_prk.pem")
    prod_private_key.save(dest_path)
    print(f"NXP PROD prk saved to: {dest_path}")
    dest_path = os.path.join(output_folder, "nxp_prod_devattest_puk.pem")
    prod_public_key.save(dest_path)
    print(f"NXP PROD puk saved to: {dest_path}")

    prod_cert = Certificate.generate_certificate(
        subject=generate_name({"COMMON_NAME": "NXP PROD TEST"}),
        issuer=generate_name({"COMMON_NAME": "NXP GLOB TEST"}),
        subject_public_key=prod_public_key,
        issuer_private_key=glob_private_key,
    )
    dest_path = os.path.join(output_folder, "nxp_prod_devattest_cert.crt")
    prod_cert.save(dest_path)
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
@spsdk_family_option(get_supported_devices())
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
    prod_private_key = PrivateKeyEcc.load(prod_key)

    id_auth_private_key = PrivateKeyEcc.generate_key(EccCurve.SECP256R1)
    id_auth_private_key.save(os.path.join(output_folder, "nxp_die_id_auth_prk.pem"))
    id_auth_public_key = id_auth_private_key.get_public_key()
    id_auth_public_key.save(os.path.join(output_folder, "nxp_die_id_auth_puk.pem"))

    die_cert = Container()
    die_cert.add_entry(
        DataEntry(
            payload_type=PayloadType.NXP_DIE_ID_AUTH_PUK.tag,
            payload=id_auth_public_key.export(SPSDKEncoding.NXP),
        )
    )
    if family == "lpc55s3x":
        id_attest_private_key = PrivateKeyEcc.generate_key(EccCurve.SECP256R1)
        id_attest_private_key.save(os.path.join(output_folder, "nxp_die_id_attest_prk.pem"))
        id_attest_public_key = id_attest_private_key.get_public_key()
        id_attest_public_key.save(os.path.join(output_folder, "nxp_die_id_attest_puk.pem"))
        die_cert.add_entry(
            DataEntry(
                payload_type=PayloadType.NXP_DIE_ATTEST_AUTH_PUK.tag,
                payload=id_attest_public_key.export(SPSDKEncoding.NXP),
            )
        )
    die_cert.add_entry(
        DataEntry(
            payload_type=PayloadType.NXP_DIE_ECID_ID_UID.tag,
            payload=bytes.fromhex(ecid),
        )
    )
    die_cert.add_entry(
        DataEntry(
            payload_type=PayloadType.NXP_DIE_RFC4122v4_ID_UUID.tag,
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
    card_prk = PrivateKeyEcc.generate_key(EccCurve.SECP256R1)
    dest_path = os.path.join(output_folder, "nxp_prod_card_auth_prk.pem")
    card_prk.save(dest_path)
    print(f"CARD prk saved to: {dest_path}")

    card_puk = card_prk.get_public_key()
    dest_path = os.path.join(output_folder, "nxp_prod_card_auth_puk.pem")
    card_puk.save(dest_path)
    print(f"CARD puk saved to: {dest_path}")


if __name__ == "__main__":
    sys.exit(main())
