#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for parsing original elf2sb configuration files."""
# pylint: disable=too-few-public-methods,too-many-instance-attributes

class RootOfTrustInfo:
    """Filters out Root Of Trust information given to elf2sb application."""

    def __init__(self, data: dict) -> None:
        """Create object out of data loaded from elf2sb configuration file."""
        self.config_data = data
        self.private_key = data["mainCertPrivateKeyFile"]
        self.public_keys = [data.get(f"rootCertificate{idx}File") for idx in range(4)]
        # filter out None and empty values
        self.public_keys = list(filter(None, self.public_keys))
        self.public_key_index = self.config_data["mainCertChainId"]


class TrustZoneConfig:
    """Configuration object specific for TrustZone."""

    def __init__(self, config_data: dict) -> None:
        """Initialize TrustZoneConfig from json config data."""
        self.family = config_data['family']
        self.revision = config_data.get('revision')
        self.output_file = config_data['tzpOutputFile']
        self.presets = config_data['trustZonePreset']


class CertificateBlockConfig:
    """Configuration object for Certificate block."""

    def __init__(self, config_data: dict) -> None:
        """Initialize CertificateBlockConfig from json config data."""
        self.root_certificate_0_file = config_data.get('rootCertificate0File')
        self.root_certificate_1_file = config_data.get('rootCertificate1File')
        self.root_certificate_2_file = config_data.get('rootCertificate2File')
        self.root_certificate_3_file = config_data.get('rootCertificate3File')
        self.root_certs = [
            self.root_certificate_0_file, self.root_certificate_1_file,
            self.root_certificate_2_file, self.root_certificate_3_file
        ]
        self.root_certs = [item for item in self.root_certs if item]
        self.root_certificate_curve = config_data.get('rootCertificateEllipticCurve')
        self.main_root_cert_id = config_data.get('mainRootCertId', 0)
        self.main_root_private_key_file = config_data.get('mainRootCertPrivateKeyFile')
        self.use_isk = config_data.get('useIsk', False)
        self.isk_certificate = config_data.get('signingCertificateFile')
        self.isk_private_key_file = config_data.get('signingCertificatePrivateKeyFile')
        self.isk_constraint = int(config_data.get('signingCertificateConstraint', '0'), 0)
        self.isk_certificate_curve = config_data.get('iskCertificateEllipticCurve')
        self.isk_sign_data_path = config_data.get('signCertData')


class MasterBootImageConfig(CertificateBlockConfig):
    """Configuration object for MasterBootImage."""

    def __init__(self, config_data: dict) -> None:
        """Initialize MasterBootImageConfig from json config data."""
        super().__init__(config_data)
        self.family = config_data['family']
        self.revision = config_data.get('revision')
        self.input_image_file = config_data['inputImageFile']
        self.output_image_exec_address = int(config_data['outputImageExecutionAddress'], 0)
        self.output_image_exec_target = config_data.get('outputImageExecutionTarget')
        self.output_image_auth_type = config_data.get('outputImageAuthenticationType')
        self.output_image_subtype = config_data.get('outputImageSubtype', 'default')
        self.trustzone_preset_file = config_data.get('trustZonePresetFile')
        self.is_dual_boot = config_data.get('isDualBootImageVersion', False)
        self.dual_boot_version = config_data.get('dualBootImageVersion')
        if self.is_dual_boot:
            assert self.dual_boot_version
            self.dual_boot_version = int(self.dual_boot_version, 0)
        self.firmware_version = int(config_data.get('firmwareVersion', '1'), 0)
        self.master_boot_output_file = config_data.get('masterBootOutputFile')


class SB31Config(CertificateBlockConfig):
    """Configuration object for SecureBinary image."""

    def __init__(self, config_data: dict) -> None:
        """Initialize SB31Config from json config data."""
        super().__init__(config_data)
        self.family = config_data['family']
        self.revision = config_data.get('revision')
        self.container_keyblob_enc_key_path = config_data.get('containerKeyBlobEncryptionKey')
        self.is_nxp_container = config_data.get('isNxpContainer', False)
        self.description = config_data.get('description')
        self.kdk_access_rights = config_data.get('kdkAccessRights', 0)
        self.container_configuration_word = config_data.get('containerConfigurationWord', 0)
        self.firmware_version = config_data.get('firmwareVersion')
        self.sb3_block_output = config_data.get('sb3BlockOutput', False)
        self.commands = config_data.get('commands')
