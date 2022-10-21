#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Tests for certificate management (generating certificate, CSR, validating certificate, chains)
"""
import os
from os import path
from typing import List

import pytest
import yaml
from click.testing import CliRunner

from spsdk import SPSDKError
from spsdk.apps.nxpcertgen import main
from spsdk.crypto import (
    Certificate,
    Encoding,
    ExtensionOID,
    NameOID,
    generate_certificate,
    generate_rsa_private_key,
    generate_rsa_public_key,
    is_ca_flag_set,
    load_certificate,
    load_private_key,
    load_public_key,
    save_crypto_item,
    save_rsa_private_key,
    save_rsa_public_key,
    validate_ca_flag_in_cert_chain,
    validate_certificate,
    validate_certificate_chain,
)
from spsdk.crypto.certificate_management import generate_name
from spsdk.crypto.loaders import _get_encoding_type
from spsdk.utils.misc import load_binary, use_working_directory


def get_certificate(data_dir, cert_file_name: str) -> Certificate:
    cert = load_certificate(path.join(data_dir, cert_file_name))
    return cert


def get_certificates(data_dir, cert_file_names: List[str]) -> List[Certificate]:
    cert_list = [get_certificate(data_dir, cert_name) for cert_name in cert_file_names]
    return cert_list


def keys_generation(data_dir):
    priv_key = generate_rsa_private_key()
    pub_key = generate_rsa_public_key(priv_key)
    save_rsa_private_key(priv_key, path.join(data_dir, "priv.pem"))
    save_rsa_public_key(pub_key, path.join(data_dir, "pub.pem"))


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
        load_certificate(cert_path)
    else:
        with pytest.raises(SPSDKError):
            load_certificate(cert_path)


@pytest.mark.parametrize(
    "file_name, password, expect_priv_key",
    [("CA1_sha256_2048_65537_v3_ca_key.pem", b"test", True), ("ca.pem", b"test", False)],
)
def test_is_key_priv(data_dir, file_name, password, expect_priv_key):
    key_path = path.join(data_dir, file_name)
    if expect_priv_key:
        load_private_key(key_path, password)
    else:
        with pytest.raises(SPSDKError):
            load_private_key(key_path, password)


@pytest.mark.parametrize(
    "file_name,  expect_pub_key",
    [
        ("ca.pem", False),
        ("pub.pem", True),
        ("priv.pem", False),
        ("CA1_key.der", False),
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
        load_public_key(key_path)
    else:
        with pytest.raises(SPSDKError):
            load_public_key(key_path)


@pytest.mark.parametrize(
    "file_name, expected_encoding",
    [
        ("ca.pem", Encoding.PEM),
        ("pub.pem", Encoding.PEM),
        ("priv.pem", Encoding.PEM),
        ("CA1_key.der", Encoding.DER),
        ("ca1_crt.der", Encoding.DER),
        ("ca_key.pem", Encoding.PEM),
        ("NXPEnterpriseCA4.crt", Encoding.PEM),
        ("NXPInternalPolicyCAG2.crt", Encoding.PEM),
        ("NXPROOTCAG2.crt", Encoding.PEM),
    ],
)
def test_get_encoding_type(data_dir, file_name, expected_encoding):
    file = path.join(data_dir, file_name)
    assert _get_encoding_type(load_binary(file)) == expected_encoding


def test_validate_cert(data_dir):
    nxp_ca = get_certificate(data_dir, "NXPROOTCAG2.crt")
    nxp_international = get_certificate(data_dir, "NXPInternalPolicyCAG2.crt")
    nxp_enterprise = get_certificate(data_dir, "NXPEnterpriseCA4.crt")
    satyr = get_certificate(data_dir, "satyr.crt")

    assert validate_certificate(nxp_enterprise, nxp_international)
    assert validate_certificate(nxp_international, nxp_ca)
    assert validate_certificate(satyr, nxp_enterprise)


def test_validate_invalid_cert(data_dir):
    nxp_ca = get_certificate(data_dir, "NXPROOTCAG2.crt")
    nxp_international = get_certificate(data_dir, "NXPInternalPolicyCAG2.crt")
    nxp_enterprise = get_certificate(data_dir, "NXPEnterpriseCA4.crt")
    satyr = get_certificate(data_dir, "satyr.crt")

    assert not validate_certificate(satyr, nxp_ca)
    assert not validate_certificate(nxp_enterprise, nxp_ca)
    assert not validate_certificate(satyr, nxp_international)


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
    assert is_ca_flag_set(ca_certificate)
    no_ca_certificate = get_certificate(data_dir, "img.pem")
    assert not is_ca_flag_set(no_ca_certificate)


def test_validate_ca_flag_in_cert_chain(data_dir):
    chain = ["ca.pem", "srk.pem"]
    chain_cert = get_certificates(data_dir, chain)
    assert validate_ca_flag_in_cert_chain(chain_cert)
    invalid_chain = ["img.pem", "srk.pem"]
    chain_cert_invalid = get_certificates(data_dir, invalid_chain)
    assert not validate_ca_flag_in_cert_chain(chain_cert_invalid)


def test_certificate_generation(tmpdir):
    ca_priv_key = generate_rsa_private_key()
    save_rsa_private_key(ca_priv_key, path.join(tmpdir, "ca_private_key.pem"))
    ca_pub_key = generate_rsa_public_key(ca_priv_key)
    save_rsa_public_key(ca_pub_key, path.join(tmpdir, "ca_pub_key.pem"))
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
    ca_cert = generate_certificate(subject, issuer, ca_pub_key, ca_priv_key, if_ca=True)
    save_crypto_item(ca_cert, path.join(tmpdir, "ca_cert.pem"))
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
    ca_cert = generate_certificate(subject, issuer, ca_pub_key, ca_priv_key, if_ca=True)
    save_crypto_item(ca_cert, path.join(tmpdir, "ca_cert_1.pem"))
    assert path.isfile(path.join(tmpdir, "ca_cert_1.pem"))


def test_certificate_generation_invalid():
    with pytest.raises(SPSDKError, match="Invalid value of certificate attribute: COMM"):
        generate_name({"COMM": "first"})


@pytest.mark.parametrize("json, encoding", [(True, "PEM"), (False, "Der")])
def test_certificate_generation_cli(tmpdir, data_dir, json, encoding):
    with use_working_directory(data_dir):
        cert_path = os.path.join(tmpdir, "cert.crt")
        if json:
            cmd = f'generate -j {os.path.join(data_dir, "certgen_config.json")} -o {cert_path}'
        else:
            cmd = f'generate -c {os.path.join(data_dir, "certgen_config.yaml")} -o {cert_path} -e {encoding}'
        runner = CliRunner()
        result = runner.invoke(main, cmd.split())
        assert result.exit_code == 0
        assert os.path.isfile(cert_path)

    generated_cert = load_certificate(cert_path)
    assert isinstance(generated_cert, Certificate)
    assert generated_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME).pop(0).value == "ONE"
    assert generated_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME).pop(0).value == "TWO"
    assert generated_cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca
    assert generated_cert.serial_number == 777


def test_invalid_certificate_chain():
    with pytest.raises(SPSDKError):
        validate_certificate_chain(chain_list=[])


def test_generate_template(tmpdir):
    template = "template.yaml"
    with use_working_directory(tmpdir):
        runner = CliRunner()
        result = runner.invoke(main, f"get-template {template}")
        assert result.exit_code == 0
        assert os.path.isfile(template)
        with open(template) as f:
            data = yaml.safe_load(f)
        # there should be at least 5 items in the template
        assert len(data) > 5
