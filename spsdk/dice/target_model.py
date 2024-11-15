#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""MCU model covering DICE operations."""

import logging
import os

from spsdk.crypto.keys import PrivateKeyEcc, PublicKeyEcc
from spsdk.dice.models import DICEResponse, DICETarget
from spsdk.utils.misc import load_configuration

logger = logging.getLogger(__name__)


class ModelDICETarget(DICETarget):
    """Model of a MCU using local workspace files."""

    def __init__(self, models_dir: str, port: str) -> None:
        """Initialize the MCU model.

        :param workspace: Path to root of the MCU model workspace
        :param port: Name of the device within workspace
        """
        super().__init__()
        self.port = port
        self.models_dir = models_dir
        self.config = load_configuration(os.path.join(models_dir, "config.yaml"))
        if port:
            self.device_config = load_configuration(os.path.join(models_dir, port, "config.yaml"))

    def get_ca_puk(self, rkth: bytes) -> bytes:
        """Generate and return NXP_CUST_DICE_CA_PUK from the target."""
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
        """Generate and return DICE response to challenge on the target."""
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
