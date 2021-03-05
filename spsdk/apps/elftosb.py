#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Console script for Elf2SB."""
import sys
from datetime import datetime

import click
import commentjson as json
from click_option_group import RequiredMutuallyExclusiveOptionGroup, optgroup

from spsdk import __version__ as spsdk_version
from spsdk.apps import elftosb_helper
from spsdk.apps.utils import catch_spsdk_error
from spsdk.crypto import SignatureProvider
from spsdk.image import MasterBootImageN4Analog, MasterBootImageType, TrustZone
from spsdk.sbfile.sb31.images import (SecureBinary31Commands,
                                      SecureBinary31Header)
from spsdk.utils.crypto import CertBlockV31
from spsdk.utils.crypto.backend_internal import internal_backend
from spsdk.utils.misc import load_binary, load_text, write_file

SUPPORTED_FAMILIES = ['lpc55s3x']


def generate_trustzone_binary(tzm_conf: click.File) -> None:
    """Generate TrustZone binary from json configuration file."""
    config_data = json.load(tzm_conf)
    config = elftosb_helper.TrustZoneConfig(config_data)
    trustzone = TrustZone.custom(family=config.family, revision=config.revision, customizations=config.presets)
    tz_data = trustzone.export()
    write_file(tz_data, config.output_file, mode="wb")


def _get_trustzone(config: elftosb_helper.MasterBootImageConfig) -> TrustZone:
    """Create appropriate TrustZone instance."""
    if not config.trustzone_preset_file:
        return TrustZone.disabled()
    try:
        tz_config_data = json.loads(load_text(config.trustzone_preset_file))
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


def _get_cert_block_v31(config: elftosb_helper.CertificateBlockConfig) -> CertBlockV31:
    root_certs = [
        load_binary(cert_file) for cert_file in config.root_certs  # type: ignore
    ]
    user_data = None
    if config.use_isk and config.isk_sign_data_path:
        user_data = load_binary(config.isk_sign_data_path)
    isk_private_key = None
    if config.use_isk:
        assert config.main_root_private_key_file
        isk_private_key = load_binary(config.main_root_private_key_file)
    isk_cert = None
    if config.use_isk:
        assert config.isk_certificate
        isk_cert = load_binary(config.isk_certificate)

    cert_block = CertBlockV31(
        root_certs=root_certs,
        used_root_cert=config.main_root_cert_id,
        user_data=user_data,
        constraints=config.isk_constraint,
        isk_cert=isk_cert, ca_flag=not config.use_isk,
        isk_private_key=isk_private_key,
    )
    return cert_block


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
        cert_block = _get_cert_block_v31(cert_config)
        if cert_config.use_isk:
            signing_private_key_path = cert_config.isk_private_key_file
        else:
            signing_private_key_path = cert_config.main_root_private_key_file
        signature_provider = SignatureProvider.create(f'type=file;file_path={signing_private_key_path}')

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
    config_data = json.load(container_conf)
    config = elftosb_helper.SB31Config(config_data)
    timestamp = config.timestamp
    if timestamp is None:
        # in our case, timestamp is the number of seconds since "Jan 1, 2000"
        timestamp = int((datetime.now() - datetime(2000, 1, 1)).total_seconds())
    if isinstance(timestamp, str):
        timestamp = int(timestamp, 0)

    final_data = bytes()
    assert isinstance(config.main_curve_name, str)
# COMMANDS
    pck = None
    if config.is_encrypted:
        assert isinstance(config.container_keyblob_enc_key_path, str)
        pck = bytes.fromhex(load_text(config.container_keyblob_enc_key_path))
    sb_cmd_block = SecureBinary31Commands(
        curve_name=config.main_curve_name, is_encrypted=config.is_encrypted,
        kdk_access_rights=config.kdk_access_rights,
        pck=pck, timestamp=timestamp,
    )
    commands = elftosb_helper.get_cmd_from_json(config)
    sb_cmd_block.set_commands(commands)

    commands_data = sb_cmd_block.export()

# CERTIFICATE BLOCK
    cert_block = _get_cert_block_v31(config)
    data_cb = cert_block.export()

# SB FILE HEADER
    sb_header = SecureBinary31Header(
        firmware_version=config.firmware_version, description=config.description,
        curve_name=config.main_curve_name, timestamp=timestamp, is_nxp_container=config.is_nxp_container
    )
    sb_header.block_count = sb_cmd_block.block_count
    sb_header.image_total_length += len(sb_cmd_block.final_hash) + len(data_cb)
    # TODO: use proper signature len calculation
    sb_header.image_total_length += 2 * len(sb_cmd_block.final_hash)
    sb_header_data = sb_header.export()
    final_data += sb_header_data

# HASH OF PREVIOUS BLOCK
    final_data += sb_cmd_block.final_hash
    final_data += data_cb

# SIGNATURE
    assert isinstance(config.main_signing_key, str)
    private_key_data = load_binary(config.main_signing_key)
    data_to_sign = final_data
    signature = internal_backend.ecc_sign(private_key_data, data_to_sign)
    assert internal_backend.ecc_verify(private_key_data, signature, data_to_sign)
    final_data += signature
    final_data += commands_data

    write_file(final_data, config.container_output, mode='wb')


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
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pragma: no cover  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()  # pragma: no cover
