#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Utilities used by adapters."""

from typing import List

from spsdk.crypto.certificate_management import X509NameConfig


def sanitize_common_name(name_config: X509NameConfig) -> None:
    """Adjust the COMMON_NAME for TrustProvisioning purposes.

    Base common name will be AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-BB
    AA will be eventually replaced by UUID
    BB will be the certificate index (0-3)
    If the common name already contains some string, it will be used as a prefix
    """
    if isinstance(name_config, dict):
        subject_cn = name_config.get("COMMON_NAME") or ""
        assert isinstance(subject_cn, str)
        name_config["COMMON_NAME"] = subject_cn + 16 * "AA" + "-" + "BB"

    if isinstance(name_config, list):

        def find_item_index(config: List, item_key: str) -> int:
            for i, item in enumerate(config):
                assert isinstance(item, dict)
                if item_key in item:
                    return i
            return -1

        subject_cn_idx = find_item_index(name_config, "COMMON_NAME")
        subject_cn = name_config[subject_cn_idx].get("COMMON_NAME") or ""
        subject_cn = subject_cn + 16 * "AA" + "-" + "BB"
        if subject_cn_idx == -1:
            name_config.append({"COMMON_NAME": subject_cn})
        else:
            name_config[subject_cn_idx] = {"COMMON_NAME": subject_cn}
