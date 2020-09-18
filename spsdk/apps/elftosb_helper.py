#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for parsing original elf2sb configuration files."""

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
