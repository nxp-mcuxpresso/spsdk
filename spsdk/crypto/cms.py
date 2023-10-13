#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""ASN1Crypto implementation for CMS signature container."""


# Used security modules
from datetime import datetime

from spsdk.crypto.certificate import Certificate
from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.crypto.keys import PrivateKey, PrivateKeyEcc, PrivateKeyRsa
from spsdk.crypto.types import SPSDKEncoding
from spsdk.exceptions import SPSDKError


def cms_sign(
    zulu: datetime, data: bytes, certificate: Certificate, signing_key: PrivateKey
) -> bytes:
    """Sign provided data and return CMS signature.

    :param zulu: current UTC time+date
    :param data: to be signed
    :param certificate: Certificate with issuer information
    :param signing_key: Signing key
    :return: CMS signature (binary)
    :raises SPSDKError: If certificate is not present
    :raises SPSDKError: If private key is not present
    :raises SPSDKError: If incorrect time-zone"
    """
    # Lazy imports are used here to save some time during SPSDK startup
    from asn1crypto import cms, util, x509

    if certificate is None:
        raise SPSDKError("Certificate is not present")
    if signing_key is None:
        raise SPSDKError("Private key is not present")
    if not isinstance(signing_key, (PrivateKeyEcc, PrivateKeyRsa)):
        raise SPSDKError(f"Unsupported private key type {type(signing_key)}.")

    # signed data (main section)
    signed_data = cms.SignedData()
    signed_data["version"] = "v1"
    signed_data["encap_content_info"] = util.OrderedDict([("content_type", "data")])
    signed_data["digest_algorithms"] = [
        util.OrderedDict([("algorithm", "sha256"), ("parameters", None)])
    ]

    # signer info sub-section
    signer_info = cms.SignerInfo()
    signer_info["version"] = "v1"
    signer_info["digest_algorithm"] = util.OrderedDict(
        [("algorithm", "sha256"), ("parameters", None)]
    )
    signer_info["signature_algorithm"] = (
        util.OrderedDict([("algorithm", "rsassa_pkcs1v15"), ("parameters", b"")])
        if isinstance(signing_key, PrivateKeyRsa)
        else util.OrderedDict([("algorithm", "sha256_ecdsa")])
    )
    # signed identifier: issuer amd serial number

    asn1_cert = x509.Certificate.load(certificate.export(SPSDKEncoding.DER))
    signer_info["sid"] = cms.SignerIdentifier(
        {
            "issuer_and_serial_number": cms.IssuerAndSerialNumber(
                {
                    "issuer": asn1_cert.issuer,
                    "serial_number": asn1_cert.serial_number,
                }
            )
        }
    )
    # signed attributes
    signed_attrs = cms.CMSAttributes()
    signed_attrs.append(
        cms.CMSAttribute(
            {
                "type": "content_type",
                "values": [cms.ContentType("data")],
            }
        )
    )

    # check time-zone is assigned (expected UTC+0)
    if not zulu.tzinfo:
        raise SPSDKError("Incorrect time-zone")
    signed_attrs.append(
        cms.CMSAttribute(
            {
                "type": "signing_time",
                "values": [cms.Time(name="utc_time", value=zulu.strftime("%y%m%d%H%M%SZ"))],
            }
        )
    )
    signed_attrs.append(
        cms.CMSAttribute(
            {
                "type": "message_digest",
                "values": [cms.OctetString(get_hash(data))],  # digest
            }
        )
    )
    signer_info["signed_attrs"] = signed_attrs

    # create signature
    data_to_sign = signed_attrs.dump()
    signature = (
        signing_key.sign(data_to_sign)
        if isinstance(signing_key, PrivateKeyRsa)
        else signing_key.sign(data_to_sign, algorithm=EnumHashAlgorithm.SHA256, der_format=True)
    )

    signer_info["signature"] = signature
    # Adding SignerInfo object to SignedData object
    signed_data["signer_infos"] = [signer_info]

    # content info
    content_info = cms.ContentInfo()
    content_info["content_type"] = "signed_data"
    content_info["content"] = signed_data

    return content_info.dump()
