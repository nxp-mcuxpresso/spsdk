#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Tests for certificate management (generating certificate, CSR, validating certificate, chains)
"""
import os
from os import path

import pytest
import yaml

from spsdk.apps.nxpcertgen import main
from spsdk.crypto.certificate import (
    Certificate,
    SPSDKExtensionOID,
    SPSDKNameOID,
    generate_extensions,
    generate_name,
    validate_ca_flag_in_cert_chain,
    validate_certificate_chain,
)
from spsdk.crypto.crypto_types import SPSDKEncoding
from spsdk.crypto.keys import PrivateKeyRsa, PublicKey
from spsdk.exceptions import SPSDKError
from spsdk.utils.misc import load_binary, use_working_directory
from tests.cli_runner import CliRunner


def get_certificate(data_dir, cert_file_name: str) -> Certificate:
    cert = Certificate.load(path.join(data_dir, cert_file_name))
    return cert


def get_certificates(data_dir, cert_file_names: list[str]) -> list[Certificate]:
    cert_list = [get_certificate(data_dir, cert_name) for cert_name in cert_file_names]
    return cert_list


def keys_generation(data_dir):
    priv_key = PrivateKeyRsa()
    pub_key = priv_key.get_public_key()
    priv_key.save(path.join(data_dir, "priv.pem"))
    pub_key.save(path.join(data_dir, "pub.pem"))


@pytest.mark.parametrize(
    "file_name, expect_cer",
    [
        ("priv.pem", False),
        ("ca.pem", True),
        ("pub.pem", False),
        ("CA1_key.der", False),
        ("ca1_crt.der", True),
        ("ca_key.pem", False),
        ("NXPEnterpriseCA4.crt", True),
        ("NXPInternalPolicyCAG2.crt", True),
        ("NXPROOTCAG2.crt", True),
    ],
)
def test_is_cert(data_dir, file_name, expect_cer):
    cert_path = path.join(data_dir, file_name)
    if expect_cer:
        Certificate.load(cert_path)
    else:
        with pytest.raises(SPSDKError):
            Certificate.load(cert_path)


@pytest.mark.parametrize(
    "file_name, password, expect_priv_key",
    [("CA1_sha256_2048_65537_v3_ca_key.pem", "test", True), ("ca.pem", "test", False)],
)
def test_is_key_priv(data_dir, file_name, password, expect_priv_key):
    key_path = path.join(data_dir, file_name)
    if expect_priv_key:
        PrivateKeyRsa.load(key_path, password=password)
    else:
        with pytest.raises(SPSDKError):
            PrivateKeyRsa.load(key_path, password=password)


@pytest.mark.parametrize(
    "file_name,  expect_pub_key",
    [
        ("ca.pem", False),
        ("pub.pem", True),
        ("priv.pem", False),
        ("ca1_crt.der", False),
        ("ca_key.pem", False),
        ("NXPEnterpriseCA4.crt", False),
        ("NXPInternalPolicyCAG2.crt", False),
        ("NXPROOTCAG2.crt", False),
    ],
)
def test_is_key_pub(data_dir, file_name, expect_pub_key):
    key_path = path.join(data_dir, file_name)
    if expect_pub_key:
        PublicKey.load(key_path)
    else:
        with pytest.raises(SPSDKError):
            PublicKey.load(key_path)


@pytest.mark.parametrize(
    "file_name, expected_encoding",
    [
        ("ca.pem", SPSDKEncoding.PEM),
        ("pub.pem", SPSDKEncoding.PEM),
        ("priv.pem", SPSDKEncoding.PEM),
        ("CA1_key.der", SPSDKEncoding.DER),
        ("ca1_crt.der", SPSDKEncoding.DER),
        ("ca_key.pem", SPSDKEncoding.PEM),
        ("NXPEnterpriseCA4.crt", SPSDKEncoding.PEM),
        ("NXPInternalPolicyCAG2.crt", SPSDKEncoding.PEM),
        ("NXPROOTCAG2.crt", SPSDKEncoding.PEM),
    ],
)
def test_get_encoding_type(data_dir, file_name, expected_encoding):
    file = path.join(data_dir, file_name)
    assert SPSDKEncoding.get_file_encodings(load_binary(file)) == expected_encoding


def test_validate_cert(data_dir):
    nxp_ca = get_certificate(data_dir, "NXPROOTCAG2.crt")
    nxp_international = get_certificate(data_dir, "NXPInternalPolicyCAG2.crt")
    nxp_enterprise = get_certificate(data_dir, "NXPEnterpriseCA4.crt")
    satyr = get_certificate(data_dir, "satyr.crt")

    assert nxp_international.validate_subject(nxp_enterprise)
    assert nxp_ca.validate_subject(nxp_international)
    assert nxp_enterprise.validate_subject(satyr)


def test_validate_invalid_cert(data_dir):
    nxp_ca = get_certificate(data_dir, "NXPROOTCAG2.crt")
    nxp_international = get_certificate(data_dir, "NXPInternalPolicyCAG2.crt")
    nxp_enterprise = get_certificate(data_dir, "NXPEnterpriseCA4.crt")
    satyr = get_certificate(data_dir, "satyr.crt")

    assert not nxp_ca.validate_subject(satyr)
    assert not nxp_ca.validate_subject(nxp_enterprise)
    assert not nxp_international.validate_subject(satyr)


def test_certificate_chain_verification(data_dir):
    chain = ["satyr.crt", "NXPEnterpriseCA4.crt", "NXPInternalPolicyCAG2.crt", "NXPROOTCAG2.crt"]
    chain_cert = [
        get_certificate(data_dir, file_name) for file_name in chain if file_name.startswith("NXP")
    ]
    assert all(validate_certificate_chain(chain_cert))

    list_cert_files = ["img.pem", "srk.pem", "ca.pem"]
    chain_prov = get_certificates(data_dir, list_cert_files)
    assert all(validate_certificate_chain(chain_prov))


def test_certificate_chain_verification_error(data_dir):
    chain = ["ca.pem", "NXPInternalPolicyCAG2.crt", "NXPEnterpriseCA4.crt", "NXPROOTCAG2.crt"]
    chain_cert = get_certificates(data_dir, chain)
    assert not all(validate_certificate_chain(chain_cert))

    list_cert_files = ["satyr.crt", "img.pem", "srk.pem"]
    chain_prov = get_certificates(data_dir, list_cert_files)
    assert not all(validate_certificate_chain(chain_prov))


def test_is_ca_flag_set(data_dir):
    ca_certificate = get_certificate(data_dir, "ca.pem")
    assert ca_certificate.ca
    no_ca_certificate = get_certificate(data_dir, "img.pem")
    assert not no_ca_certificate.ca


def test_validate_ca_flag_in_cert_chain(data_dir):
    chain = ["ca.pem", "srk.pem"]
    chain_cert = get_certificates(data_dir, chain)
    assert validate_ca_flag_in_cert_chain(chain_cert)
    invalid_chain = ["img.pem", "srk.pem"]
    chain_cert_invalid = get_certificates(data_dir, invalid_chain)
    assert not validate_ca_flag_in_cert_chain(chain_cert_invalid)


def test_certificate_generation(tmpdir):
    ca_priv_key = PrivateKeyRsa.generate_key()
    ca_priv_key.save(path.join(tmpdir, "ca_private_key.pem"))
    ca_pub_key = ca_priv_key.get_public_key()
    ca_pub_key.save(path.join(tmpdir, "ca_pub_key.pem"))
    assert path.isfile(path.join(tmpdir, "ca_private_key.pem"))
    assert path.isfile(path.join(tmpdir, "ca_pub_key.pem"))

    data = yaml.safe_load(
        """
        COMMON_NAME: xyz
        DOMAIN_COMPONENT: [com, nxp, wbi]
        ORGANIZATIONAL_UNIT_NAME: [NXP, CZ, Managed Users, Developers]
        """
    )
    subject = issuer = generate_name(data)
    ca_cert = Certificate.generate_certificate(
        subject,
        issuer,
        ca_pub_key,
        ca_priv_key,
        extensions=generate_extensions(
            {"BASIC_CONSTRAINTS": {"ca": True, "path_length": 3}},
        ),
    )
    ca_cert.save(path.join(tmpdir, "ca_cert.pem"))
    assert path.isfile(path.join(tmpdir, "ca_cert.pem"))

    data = yaml.safe_load(
        """
        - COMMON_NAME: ccccc
        - DOMAIN_COMPONENT: [com, nxp, wbi]
        - ORGANIZATIONAL_UNIT_NAME: NXP
        - ORGANIZATIONAL_UNIT_NAME: CZ
        - ORGANIZATIONAL_UNIT_NAME: Managed Users
        - ORGANIZATIONAL_UNIT_NAME: Developers
        """
    )
    subject = issuer = generate_name(data)
    ca_cert1 = Certificate.generate_certificate(
        subject,
        issuer,
        ca_pub_key,
        ca_priv_key,
        extensions=generate_extensions(
            {"BASIC_CONSTRAINTS": {"ca": True, "path_length": 3}},
        ),
    )
    ca_cert1.save(path.join(tmpdir, "ca_cert_1.pem"))
    assert path.isfile(path.join(tmpdir, "ca_cert_1.pem"))


def test_certificate_generation_invalid():
    with pytest.raises(SPSDKError, match="Invalid value of certificate attribute: COMM"):
        generate_name({"COMM": "first"})


@pytest.mark.parametrize("json, encoding", [(True, "PEM"), (False, "Der")])
def test_certificate_generation_cli(cli_runner: CliRunner, tmpdir, data_dir, json, encoding):
    with use_working_directory(data_dir):
        cert_path = os.path.join(tmpdir, "cert.crt")
        cmd = [
            "generate",
            "-c",
            os.path.join(data_dir, f"certgen_config.{'json' if json else 'yaml'}"),
            "-o",
            cert_path,
            "-e",
            encoding,
        ]
        cli_runner.invoke(main, cmd)
        assert os.path.isfile(cert_path)

    generated_cert = Certificate.load(cert_path)
    assert (
        generated_cert.issuer.get_attributes_for_oid(SPSDKNameOID.COMMON_NAME).pop(0).value == "ONE"
    )
    assert (
        generated_cert.subject.get_attributes_for_oid(SPSDKNameOID.COMMON_NAME).pop(0).value
        == "TWO"
    )
    assert generated_cert.extensions.get_extension_for_oid(
        SPSDKExtensionOID.BASIC_CONSTRAINTS
    ).value.ca
    assert generated_cert.serial_number == 777


def test_invalid_certificate_chain():
    with pytest.raises(SPSDKError):
        validate_certificate_chain(chain_list=[])


def test_generate_template(cli_runner: CliRunner, tmpdir):
    template = "template.yaml"
    with use_working_directory(tmpdir):
        cli_runner.invoke(main, f"get-template -o {template}")
        assert os.path.isfile(template)
        with open(template) as f:
            data = yaml.safe_load(f)
        # there should be at least 5 items in the template
        assert len(data) > 5


def test_certificate_generation_with_encrypted_private_key(cli_runner: CliRunner, tmpdir, data_dir):
    with use_working_directory(data_dir):
        cert_path = os.path.join(tmpdir, "cert.crt")
        cmd = [
            "generate",
            "-c",
            os.path.join(data_dir, f"certgen_config.yaml"),
            "-o",
            cert_path,
        ]
        cli_runner.invoke(main, cmd)
        assert os.path.isfile(cert_path)
