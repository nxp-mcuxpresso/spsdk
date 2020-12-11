#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Console script for Elf2SB."""
import sys

import click
import commentjson as json
from click_option_group import RequiredMutuallyExclusiveOptionGroup, optgroup
from Crypto.PublicKey import ECC

from spsdk import __version__ as spsdk_version
from spsdk.apps import elftosb_helper
from spsdk.apps.utils import catch_spsdk_error
from spsdk.crypto import (
    load_private_key, load_certificate, SignatureProvider,
    EllipticCurvePrivateKeyWithSerialization
)
from spsdk.image import MasterBootImageN4Analog, MasterBootImageType, TrustZone
from spsdk.utils.misc import load_binary, load_file, write_file
from spsdk.utils.crypto import CertBlockV3

SUPPORTED_FAMILIES = ['lpc55s3x']


def generate_trustzone_binary(tzm_conf: click.File) -> None:
    """Generate TrustZone binary from json configuration file."""
    config_data = json.load(tzm_conf)
    config = elftosb_helper.TrustZoneConfig(config_data)
    trustzone = TrustZone.custom(family=config.family, revision=config.revision, customizations=config.presets)
    tz_data = trustzone.export()
    with open(config.output_file, 'wb') as f:
        f.write(tz_data)


def _get_trustzone(config: elftosb_helper.MasterBootImageConfig) -> TrustZone:
    """Create appropriate TrustZone instance."""
    if not config.trustzone_preset_file:
        return TrustZone.disabled()
    try:
        tz_config_data = json.loads(load_file(config.trustzone_preset_file))
        tz_config = elftosb_helper.TrustZoneConfig(tz_config_data)
        return TrustZone.custom(
            family=tz_config.family, revision=tz_config.revision, customizations=tz_config.presets
        )
    except ValueError:
        tz_raw_data = load_binary(config.trustzone_preset_file)
        return TrustZone.from_binary(
            family=config.family, revision=config.revision, raw_data=tz_raw_data
        )


def _get_master_boot_image_type(config: elftosb_helper.MasterBootImageConfig) -> MasterBootImageType:
    """Get appropriate MasterBootImage type."""
    sb3_image_types = {
        "crc-ram-False": MasterBootImageType.CRC_RAM_IMAGE,
        "crc-xip-False": MasterBootImageType.CRC_XIP_IMAGE,
        "signed-xip-False": MasterBootImageType.SIGNED_XIP_IMAGE,
        "signed-xip-True": MasterBootImageType.SIGNED_XIP_NXP_IMAGE
    }
    image_type = f"{config.output_image_auth_type}-{config.output_image_exec_target}-{config.use_isk}"
    return sb3_image_types[image_type]


def generate_master_boot_image(image_conf: click.File) -> None:
    """Generate MasterBootImage from json configuration file."""
    config_data = json.load(image_conf)
    config = elftosb_helper.MasterBootImageConfig(config_data)
    app = load_binary(config.input_image_file)
    load_addr = config.output_image_exec_address
    trustzone = _get_trustzone(config)
    image_type = _get_master_boot_image_type(config)
    dual_boot_version = config.dual_boot_version
    firmware_version = config.firmware_version

    cert_block = None
    signature_provider = None
    if MasterBootImageType.is_signed(image_type):
        cert_config = elftosb_helper.CertificateBlockConfig(config_data)
        root_certs = [
            load_binary(cert_file) for cert_file in cert_config.root_certs  # type: ignore
        ]
        user_data = None
        if cert_config.isk_sign_data_path:
            user_data = load_binary(cert_config.isk_sign_data_path)
        isk_private_key = None
        if cert_config.isk_private_key_file:
            isk_private_key = load_private_key(cert_config.isk_private_key_file)
            assert isinstance(isk_private_key, EllipticCurvePrivateKeyWithSerialization)

        isk_cert = None
        if cert_config.isk_certificate:
            cert_data = load_binary(cert_config.isk_certificate)
            isk_cert = ECC.import_key(cert_data)

        ca_flag = not cert_config.use_isk
        cert_block = CertBlockV3(
            root_certs=root_certs, ca_flag=ca_flag,
            used_root_cert=cert_config.main_root_cert_id, constraints=cert_config.isk_constraint,
            isk_private_key=isk_private_key, isk_cert=isk_cert,  # type: ignore
            user_data=user_data
        )
        if cert_config.use_isk:
            signing_private_key_path = cert_config.isk_private_key_file
        else:
            signing_private_key_path = cert_config.main_root_private_key_file
        signature_provider = SignatureProvider.create(f'type=file;file_path={signing_private_key_path}')

    assert config.master_boot_output_file
    mbi = MasterBootImageN4Analog(
        app=app, load_addr=load_addr, image_type=image_type,
        trust_zone=trustzone, dual_boot_version=dual_boot_version,
        firmware_version=firmware_version,
        cert_block=cert_block,
        signature_provider=signature_provider
    )
    mbi_data = mbi.export()

    write_file(mbi_data, config.master_boot_output_file, mode='wb')


def generate_secure_binary(container_conf: click.File) -> None:
    """Geneate SecureBinary image from json configuration file."""
    raise NotImplementedError()


@click.command()
@click.option('-f', '--chip-family', default='lpc55s3x',
              help="Select the chip family (default is lpc55s3x Niobe4Analog)")
@optgroup.group('Configuration file type', cls=RequiredMutuallyExclusiveOptionGroup)
@optgroup.option('-J', '--image-conf', type=click.File('r'),
                 help="Json image configuration file to produce master boot image")
@optgroup.option('-j', '--container-conf', type=click.File('r'),
                 help="json container configuration file to produce secure binary")
@optgroup.option('-T', '--tzm-conf', type=click.File('r'),
                 help="json trust zone configuration file to produce trust zone binary")
@click.version_option(spsdk_version, '-v', '--version')
@click.help_option('--help')
def main(chip_family: str, image_conf: click.File, container_conf: click.File, tzm_conf: click.File) -> None:
    """Tool for generating TrustZone, MasterBootImage and SecureBinary images."""
    if chip_family not in SUPPORTED_FAMILIES:
        click.echo(f"Family '{chip_family}' is not supported")
        sys.exit(1)

    if image_conf:
        generate_master_boot_image(image_conf)
    if container_conf:
        generate_secure_binary(container_conf)
    if tzm_conf:
        generate_trustzone_binary(tzm_conf)


@catch_spsdk_error
def safe_main() -> int:
    """Call the main function."""
    sys.exit(main())  # pragma: no cover  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()  # pragma: no cover
