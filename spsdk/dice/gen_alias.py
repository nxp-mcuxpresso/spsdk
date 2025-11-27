#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK DICE alias certificate generation utilities.

This module provides functionality for generating FMC (First Mutable Code) certificate
templates and handling DICE (Device Identifier Composition Engine) alias certificates
in SPSDK context.
"""

import logging
import math
import struct
from typing import Optional

from cryptography import x509
from typing_extensions import Literal

from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.crypto.keys import EccCurve, PrivateKey, PrivateKeyEcc, PrivateKeyMLDSA, SPSDKEncoding
from spsdk.dice import tcg_asn
from spsdk.dice.cust_exts import (
    CUST_TCB,
    FMC_TCB,
    NXP_TCB,
    TCBInfoTable,
    TCGDiceMultiTcbInfo,
    TCGDiceUeid,
)
from spsdk.dice.data_container import DataEntry, PayloadType, TPDataContainer
from spsdk.exceptions import SPSDKValueError
from spsdk.utils.config import Config
from spsdk.utils.misc import load_binary, write_file

logger = logging.getLogger(__name__)


def to_be_bytes(number: int, length: Optional[int] = None) -> bytes:
    """Convert number into big-endian bytes with given length.

    :param number: Integer number to convert to bytes.
    :param length: Target byte length. If None, calculated from number bit length.
    :return: Big-endian byte representation of the number.
    """
    if length is None:
        length = math.ceil(number.bit_length() / 8)
    return number.to_bytes(length, "big")


def get_mode(config: Config) -> Literal["ecdsa", "mldsa"]:
    """Get cryptographic mode from configuration.

    Extracts the cryptographic algorithm mode (ECDSA or ML-DSA) from the provided
    configuration object with ECDSA as the default fallback.

    :param config: Configuration object containing mode settings.
    :raises SPSDKValueError: When mode is not 'ecdsa' or 'mldsa'.
    :return: The cryptographic mode, either 'ecdsa' or 'mldsa'.
    """
    mode: Literal["ecdsa", "mldsa"] = config.get_str("mode", "ecdsa")  # type: ignore[assignment]
    if mode not in ["ecdsa", "mldsa"]:
        raise SPSDKValueError("Mode must be either 'ecdsa' or 'mldsa'")
    return mode


def get_printable_string(data: bytes) -> bytes:
    """Get ASN.1 printable string from data.

    Converts input data to hexadecimal representation and wraps it in ASN.1 printable string format
    with proper tag and length encoding.

    :param data: Input bytes to be converted to ASN.1 printable string format.
    :return: ASN.1 encoded printable string with tag 0x13, length, and hex-encoded data.
    """
    ps = data.hex().encode("utf-8")
    return bytes([0x13, len(ps)]) + ps


SERIAL_NUMBER = 20 * b"\x11"
ISSUER_SERIAL_NUMBER = 32 * b"\x22"
SUBJECT_SERIAL_NUMBER = 32 * b"\x33"
SUBJECT_KEY_ID = 20 * b"\x44"
AUTHORITY_KEY_ID = 20 * b"\x55"
UUID = 16 * b"\x66"
FMC_FWID = 48 * b"\x77"
CUST_FWID = 48 * b"\x88"
NXP_FWID = 48 * b"\x99"


def generate_fmc(config: Config) -> None:
    """Generate FMC certificate template in form of a TP container.

    Creates a DICE FMC (First Mutable Code) certificate template with configurable TCB
    (Trusted Computing Base) information tables and packages it into a TP container format.
    The method supports both ECDSA and ML-DSA signature algorithms and generates the
    necessary descriptors for certificate field offsets.

    :param config: Configuration object containing certificate parameters, key settings,
        output paths, and TCB table configuration options.
    :raises SPSDKError: When certificate generation or file operations fail.
    """
    mode = get_mode(config)
    if config.get("template_key"):
        issuer_private_key = PrivateKey.load(config.get_input_file_name("template_key"))
    else:
        if mode == "ecdsa":
            issuer_private_key = PrivateKeyEcc.generate_key(curve_name=EccCurve.SECP384R1)
        else:
            issuer_private_key = PrivateKeyMLDSA.generate_key(level=5)

    subject_public_key = issuer_private_key.get_public_key()

    issuer = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COMMON_NAME, config.get_str("issuer_name")),
            x509.NameAttribute(x509.NameOID.SERIAL_NUMBER, ISSUER_SERIAL_NUMBER.hex()),
        ]
    )
    subject = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COMMON_NAME, config.get_str("subject_name")),
            x509.NameAttribute(x509.NameOID.SERIAL_NUMBER, SUBJECT_SERIAL_NUMBER.hex()),
        ]
    )

    multi_info_tables: list[TCBInfoTable] = [
        FMC_TCB(
            svn=0x01AABBCCDD,
            fwid_hashes=[FMC_FWID],
        ),
    ]
    if config.get_bool("include_cust_table", default=False):
        multi_info_tables.append(
            CUST_TCB(
                svn=config.get_int("cust_svn"),
                fwid_hashes=[CUST_FWID],
                flags=0x00ABCDEF01,
                mask=0x00FEDCBA98,
            ),
        )
    if config.get_bool("include_nxp_table", default=False):
        multi_info_tables.append(
            NXP_TCB(
                svn=0x0111223344,
                fwid_hashes=[NXP_FWID],
            ),
        )

    tbs = tcg_asn.TBSCertificate.create(
        serial=int.from_bytes(SERIAL_NUMBER, byteorder="big"),
        subject=subject,
        public_key=subject_public_key,
        issuer=issuer,
        critical_extensions=[
            x509.BasicConstraints(ca=True, path_length=5),
            x509.KeyUsage(
                key_cert_sign=True,
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
        ],
        extensions=[
            x509.SubjectKeyIdentifier(digest=SUBJECT_KEY_ID),
            x509.AuthorityKeyIdentifier(
                key_identifier=AUTHORITY_KEY_ID,
                authority_cert_issuer=None,
                authority_cert_serial_number=None,
            ),
            TCGDiceUeid(UUID),
            TCGDiceMultiTcbInfo(multi_info_tables),
        ],
    )

    tbs_data = tbs.encode()

    cert = tcg_asn.Certificate.create(tbs_certificate=tbs, signing_key=issuer_private_key)
    cert_data = cert.encode()

    if config.get("template_output"):
        write_file(cert_data, config.get_output_file_name("template_output"), mode="wb")

    tbs_offset = cert_data.find(tbs_data)
    serial_offset = cert_data.find(bytes([0x02, len(SERIAL_NUMBER)]) + SERIAL_NUMBER)
    issuer_sn_offset = cert_data.find(get_printable_string(ISSUER_SERIAL_NUMBER))
    subject_sn_offset = cert_data.find(get_printable_string(SUBJECT_SERIAL_NUMBER))
    puk_data_offset = cert_data.find(subject_public_key.export(SPSDKEncoding.DER))
    puk_offset = cert_data.find(subject_public_key.export(SPSDKEncoding.NXP))
    puk_offset -= 4 if mode == "ecdsa" else 5
    # the OID for private key (signature) is present in the certificate twice
    # here we need to fetch the 2nd occurrence, which is always after the PUK
    signature_offset = cert_data.find(tcg_asn.get_oid_for_key(issuer_private_key), puk_offset)
    signature_offset += len(tcg_asn.get_oid_for_key(issuer_private_key))
    subject_key_id = cert_data.find(bytes([0x04, len(SUBJECT_KEY_ID)]) + SUBJECT_KEY_ID)
    authority_key_id = cert_data.find(bytes([0x80, len(AUTHORITY_KEY_ID)]) + AUTHORITY_KEY_ID)
    tcb_ueid_offset = cert_data.find(bytes([0x04, len(UUID)]) + UUID)
    multi_info_tables_count = len(multi_info_tables)
    logger.info(f"{tbs_offset = }")
    logger.info(f"{serial_offset = }")
    logger.info(f"{issuer_sn_offset = }")
    logger.info(f"{subject_sn_offset = }")
    logger.info(f"{puk_data_offset = }")
    logger.info(f"{puk_offset = }")
    logger.info(f"{signature_offset = }")
    logger.info(f"{subject_key_id = }")
    logger.info(f"{authority_key_id = }")
    logger.info(f"{tcb_ueid_offset = }")
    logger.info(f"{multi_info_tables_count = }")

    descriptor = struct.pack(
        "<11I",
        tbs_offset,
        serial_offset,
        issuer_sn_offset,
        subject_sn_offset,
        puk_data_offset,
        puk_offset,
        signature_offset,
        subject_key_id,
        authority_key_id,
        tcb_ueid_offset,
        multi_info_tables_count,
    )

    for tcb_table in multi_info_tables:
        logger.info(f"Processing {tcb_table.table_name}")
        table_data = struct.pack(
            "<BHBHH",  # cspell:ignore BHBHH
            0x01,
            11 * 4,
            0x29,
            tcb_table.descriptor_flags,
            tcb_table.descriptor_type,
        )
        svn_data = to_be_bytes(tcb_table.svn)
        need_padding = svn_data[0] >= 0x80
        svn_offset = cert_data.find(svn_data) - (3 if need_padding else 2)
        fwid_offset = cert_data.find(tcb_table.fwid_hashes[0]) - 2
        logger.info(f"{svn_offset = }")
        logger.info(f"{fwid_offset = }")
        if isinstance(tcb_table, CUST_TCB):
            flags_offset = cert_data.find(to_be_bytes(tcb_table.flags, 5)) - 2
            mask_offset = cert_data.find(to_be_bytes(tcb_table.mask, 5)) - 2
            logger.info(f"{flags_offset = }")
            logger.info(f"{mask_offset = }")
        else:
            flags_offset = 0
            mask_offset = 0
        reserved = 5 * [0]
        table_data += struct.pack(
            "<9L", svn_offset, fwid_offset, flags_offset, mask_offset, *reserved
        )

        descriptor += table_data

    descriptor = struct.pack("<BHB", 0x01, len(descriptor), 0x2F) + descriptor

    if config.get("descriptor_output"):
        write_file(descriptor, config.get_output_file_name("descriptor_output"), mode="wb")

    template_tag = (
        PayloadType.DICE_FCM_ECDSA_CERT_TEMPLATE.tag
        if mode == "ecdsa"
        else PayloadType.DICE_FCM_MLDSA_CERT_TEMPLATE.tag
    )

    cont = TPDataContainer()
    cont.add_entry(
        DataEntry(payload=descriptor, payload_type=PayloadType.DICE_FCM_CERT_DESCRIPTOR.tag)
    )
    cont.add_entry(
        DataEntry(payload=cert_data, payload_type=template_tag),
    )
    logger.debug(cont)
    cont_data = cont.export()

    write_file(cont_data, config.get_output_file_name("container_output"), mode="wb")

    cont_hash = get_hash(cont.export(), EnumHashAlgorithm.SHA384)
    logger.info(f"TP Container hash: {cont_hash.hex()}")


def make_container(config: Config) -> None:
    """Make FMC certificate template container from existing template and descriptor file.

    Creates a TPDataContainer with certificate descriptor and template entries based on the
    specified cryptographic mode (ECDSA or MLDSA). The container is exported and saved to
    the configured output path.

    :param config: Configuration object containing input/output file paths and mode settings.
    :raises SPSDKError: If input files cannot be loaded or output file cannot be written.
    :raises SPSDKValueError: If configuration contains invalid mode or missing file paths.
    """
    mode = get_mode(config)

    template = config.get_input_file_name("template_output")
    template_data = load_binary(template)

    descriptor = config.get_input_file_name("descriptor_output")
    descriptor_data = load_binary(descriptor)

    template_tag = (
        PayloadType.DICE_FCM_ECDSA_CERT_TEMPLATE.tag
        if mode == "ecdsa"
        else PayloadType.DICE_FCM_MLDSA_CERT_TEMPLATE.tag
    )
    container_path = config.get_output_file_name("container_output")
    container = TPDataContainer()
    container.add_entry(
        DataEntry(payload=descriptor_data, payload_type=PayloadType.DICE_FCM_CERT_DESCRIPTOR.tag)
    )
    container.add_entry(
        DataEntry(payload=template_data, payload_type=template_tag),
    )
    write_file(container.export(), container_path, mode="wb")
    print(f"TP Container saved to: {container_path}")
