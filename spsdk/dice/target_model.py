#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK DICE target model implementation.

This module provides the ModelDICETarget class for simulating DICE (Device Identifier
Composition Engine) operations on target devices within the SPSDK framework.
"""

import logging
import os

from spsdk.crypto.keys import PrivateKeyEcc, PublicKeyEcc
from spsdk.dice.models import DICEResponse, DICETarget
from spsdk.utils.misc import load_configuration

logger = logging.getLogger(__name__)


class ModelDICETarget(DICETarget):
    """SPSDK DICE Target Model for MCU simulation.

    This class provides a file-based implementation of DICE (Device Identifier
    Composition Engine) target operations using local workspace files. It simulates
    MCU behavior by loading configuration and cryptographic keys from a structured
    directory layout, enabling DICE protocol testing and development without
    physical hardware.
    """

    def __init__(self, models_dir: str, port: str) -> None:
        """Initialize the MCU model.

        :param models_dir: Path to root of the MCU model workspace directory.
        :param port: Name of the device within workspace.
        """
        super().__init__()
        self.port = port
        self.models_dir = models_dir
        self.config = load_configuration(os.path.join(models_dir, "config.yaml"))
        if port:
            self.device_config = load_configuration(os.path.join(models_dir, port, "config.yaml"))

    def get_ca_puk(self, rkth: bytes, mldsa: bool = False) -> bytes:
        """Generate and return NXP_CUST_DICE_CA_PUK from the target.

        The method loads the DICE CA public key from a file specified in the device
        configuration or falls back to the general configuration. The key is loaded
        as an ECC public key and exported in its standard format.

        :param rkth: Root Key Table Hash bytes.
        :param mldsa: Flag indicating whether to use ML-DSA algorithm, defaults to False.
        :return: Exported public key bytes in standard format.
        """
        logger.info("Generating NXP_CUST_DICE_CA_PUK")
        puk_file_name = self.device_config.get("dice_ca_puk")
        if puk_file_name:
            puk_file = os.path.join(self.models_dir, self.port, puk_file_name)
        else:
            puk_file_name = self.config["dice_ca_puk"]
            puk_file = os.path.join(self.models_dir, puk_file_name)
        puk = PublicKeyEcc.load(file_path=puk_file)
        return puk.export()

    def get_dice_response(self, challenge: bytes) -> bytes:
        """Generate and return DICE response to challenge on the target.

        Creates a DICE (Device Identifier Composition Engine) response by loading the required
        private keys, constructing the response with device configuration parameters, and
        signing it with both CA and DIE private keys.

        :param challenge: Challenge bytes to be included in the DICE response.
        :return: Exported DICE response data as bytes.
        :raises RuntimeError: If DICE response verification fails after signing.
        """
        logger.info("Generating DICE Response")

        ca_prk_name = self.device_config.get("dice_ca_prk")
        if ca_prk_name:
            ca_prk_file = os.path.join(self.models_dir, self.port, ca_prk_name)
        else:
            ca_prk_name = self.config["dice_ca_prk"]
            ca_prk_file = os.path.join(self.models_dir, ca_prk_name)
        ca_prk = PrivateKeyEcc.load(file_path=ca_prk_file)

        die_prk_name = self.device_config["die_prk"]
        die_prk_file = os.path.join(self.models_dir, self.port, die_prk_name)
        die_prk = PrivateKeyEcc.load(file_path=die_prk_file)

        version = self.device_config.get("version") or self.config["version"]
        response = DICEResponse(
            die_puk=die_prk.get_public_key(),
            rtf=self.device_config.get("rtf") or self.config["rtf"],
            had=self.device_config.get("had") or self.config["had"],
            uuid=self.device_config["uuid"],
            version=int(version),
            challenge=self.device_config.get("challenge") or challenge,
        )

        response.sign(ca_prk=ca_prk, die_prk=die_prk)
        if not response.verify(ca_puk=ca_prk.get_public_key()):
            raise RuntimeError("DICE response verification failed")
        data = response.export()
        return data
