#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module holding all supported Payload types."""

from spsdk.utils.spsdk_enum import SpsdkEnum


class PayloadType(SpsdkEnum):
    """Enumeration of all supported Payload types."""

    # fmt: off
    NXP_EPH_CHALLENGE_DATA_RND  = (0x2000, "NXP_EPH_CHALLENGE_DATA_RND", "Trust Provisioning initial challenge")
    NXP_EPH_DEVICE_KA_PUK       = (0x20A0, "NXP_EPH_DEVICE_KA_PUK", "Public key for Ephemeral key exchange")
    NXP_EPH_CARD_KA_PUK         = (0x20A2, "NXP_EPH_CARD_KA_PUK", "Public key for Ephemeral key exchange")

    TP_WRAP_DATA_IV             = (0x2001, "TP_WRAP_DATA_IV", "TP_WRAP_DATA_IV")
    TP_WRAP_DATA_TAG            = (0x2002, "TP_WRAP_DATA_TAG", "TP_WRAP_DATA_TAG")
    TP_WRAP_DATA_CIPHERTEXT     = (0xFF00, "TP_WRAP_DATA_CIPHERTEXT", "TP_WRAP_DATA_CIPHERTEXT")

    OEM_DIE_DEVATTEST_ID_PUK    = (0x20C0, "OEM_DIE_DEVATTEST_ID_PUK", "Public Key for OEM certificate creation")
    OEM_DIE_DEVATTEST_ID_CERT   = (0x20C5, "OEM_DIE_DEVATTEST_ID_CERT", "OEM DIE x509 certificate destination entry")
    OEM_DIE_DEVATTEST_ID_CERT_STD_E = (0x20C7, "OEM_DIE_DEVATTEST_ID_CERT", "OEM DIE x509 certificate standard entry")
    OEM_DIE_DEVATTEST_ID_PRK    = (0x20C6, "OEM_DIE_DEVATTEST_ID_PRK", "Private Key for singing OEM certificate")

    CUST_PROD_SB_KEK_SK         = (0x20C1, "CUST_PROD_SB_KEK_SK", "CUST_PROD_SB_KEK_SK")
    CUST_PROD_USER_KEK_SK       = (0x20C2, "CUST_PROD_SB_KEK_SK", "CUST_PROD_SB_KEK_SK")

    CUST_PROD_CFPA_DATA_SECRET  = (0x20C3, "CUST_PROD_CFPA_DATA_SECRET", "CUST_PROD_CFPA_DATA_SECRET")
    CUST_PROD_CMPA_DATA_SECRET  = (0x20C4, "CUST_PROD_CMPA_DATA_SECRET", "CUST_PROD_CMPA_DATA_SECRET")

    CUST_PROD_PROV_DATA         = (0x20C8, "CUST_PROD_PROV_DATA", "CUST_PROD_PROV_DATA")

    OEM_PROD_COUNTER            = (0x20D1, "CUST_PROD_COUNTER", "CUST_PROD_COUNTER")

    OEM_TP_LOG_HASH             = (0x20D2, "OEM_TP_LOG_HASH", "OEM_TP_LOG_HASH")
    OEM_TP_LOG_SIGN             = (0x20D3, "OEM_TP_LOG_SIGN", "OEM_TP_LOG_SIGN")
    OEM_TP_LOG_PRK              = (0x20D4, "OEM_TP_LOG_PRK", "OEM_TP_LOG_PRK")

    NXP_DIE_ID_AUTH_PUK         = (0x9966, "NXP_DIE_ID_AUTH_PUK", "NXP_DIE_ID_AUTH_PUK")
    NXP_DIE_ATTEST_AUTH_PUK     = (0x9999, "NXP_DIE_ATTEST_AUTH_PUK", "NXP_DIE_ATTEST_AUTH_PUK")
    NXP_DIE_ID_AUTH_CERT        = (0xF0F0, "NXP_DIE_ID_AUTH_CERT", "NXP_DIE_ID_AUTH_CERT")
    NXP_DIE_ECID_ID_UID         = (0x0F0F, "NXP_DIE_ECID_ID_UID", "NXP_DIE_ECID_ID_UID")
    NXP_DIE_RFC4122v4_ID_UUID   = (0x9696, "NXP_DIE_RFC4122v4_ID_UUID", "NXP_DIE_RFC4122v4_ID_UUID")

    WPC_DIE_ID_AUTH_PUK         = (0xABAB, "WPC_DIE_ID_PUK", "Public key for WPC Qi Authentication")
    WPC_RSID                    = (0x9797, "WPC_RSID", "RSID for WPC Qi Certificate identification")
