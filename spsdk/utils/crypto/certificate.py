#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Internal representation of a Certificate."""

from datetime import datetime
from typing import Dict, Set

from asn1crypto import x509
from oscrypto.asymmetric import load_public_key, rsa_pkcs1v15_verify
from oscrypto.errors import SignatureError

from .backend_internal import internal_backend
from .common import crypto_backend


class Certificate:
    """Internally used representation of a Certificate."""

    @property
    def version(self) -> str:
        """Version of the Certificate."""
        return self._cert.native["tbs_certificate"]["version"]

    @property
    def ca(self) -> bool:  # pylint: disable=invalid-name
        """Certification Authority flag."""
        return self._cert.ca

    @property
    def self_signed(self) -> str:
        """Indication whether the Certificate is self-signed.

        A unicode string of "no" or "maybe". The "maybe" result will
        be returned if the certificate issuer and subject are the same.
        If a key identifier and authority key identifier are present,
        they will need to match otherwise "no" will be returned.

        To verify is a certificate is truly self-signed, the signature
        will need to be verified. See the certvalidator package for
        one possible solution.
        """
        return self._cert.self_signed

    @property
    def self_issued(self) -> bool:
        """Is the Certificate self-issued (subject and issuer are the same)."""
        return self._cert.self_issued

    @property
    def serial_number(self) -> int:
        """Serial number of the Certificate."""
        return self._cert.serial_number

    @property
    def hash_algo(self) -> str:
        """HASH algorithm used in the Certificate."""
        return self._cert.hash_algo

    @property
    def public_key_modulus(self) -> int:
        """Modulus of the public key of the certificate."""
        return self._cert.public_key.native["public_key"]["modulus"]

    @property
    def public_key_exponent(self) -> int:
        """Exponent of the public key of the certificate."""
        return self._cert.public_key.native["public_key"]["public_exponent"]

    @property
    def public_key_hash(self) -> bytes:
        """32 bytes hash (SHA-256) of public key (modulus and exponent)."""
        modulus = self._cert.public_key.native["public_key"]["modulus"]
        exponent = self._cert.public_key.native["public_key"]["public_exponent"]
        modulus_len = (modulus.bit_length() + 7) // 8
        exponent_len = (exponent.bit_length() + 7) // 8
        return crypto_backend().hash(
            modulus.to_bytes(modulus_len, "big") + exponent.to_bytes(exponent_len, "big")
        )

    @property
    def public_key_usage(self) -> Set[str]:
        """Usage of the Certificate."""
        return self._cert.key_usage_value.native

    @property
    def signature_algo(self) -> str:
        """Certificate signature algorithm."""
        return self._cert.signature_algo

    @property
    def signature(self) -> bytes:
        """Certificate signature."""
        return self._cert.signature

    @property
    def max_path_length(self) -> int:
        """Maximum length of derived Certificate chain."""
        if not self.ca:
            return 0
        return self._cert.basic_constraints_value["path_len_constraint"].native

    @property
    def issuer(self) -> Dict[str, str]:
        """Certificate issuer."""
        return self._cert.issuer.native

    @property
    def not_valid_before(self) -> datetime:
        """Begging of the Certificate valid period."""
        return self._cert.not_valid_before

    @property
    def not_valid_after(self) -> datetime:
        """End of the Certificate valid period."""
        return self._cert.not_valid_after

    @property
    def raw_size(self) -> int:
        """Size of the Certificate data (aligned to 4 bytes)."""
        size = len(self._data)
        if size % 4:
            size += 4 - (size % 4)
        return size

    def __init__(self, certificate: bytes) -> None:
        """Initialize the Certificate object.

        :param certificate: Certificate bytes (read from file)
        """
        self._cert = x509.Certificate.load(certificate)
        self._data = certificate

    def _get_issuer_info(self, key: str, format_str: str) -> str:
        """Return selected issuer info in specified format.

        :param key: of the info to be returned
        :param format_str: formatting string, e.g. "Value: {}\n"
        :return: formatted info; empty string if the info is not available (as most of the info are optional)
        """
        value = self.issuer.get(key, None)
        if not value:
            return ""

        return format_str.format(value)

    def info(self) -> str:
        """Text information about the Certificate."""
        not_valid_before = self.not_valid_before.strftime("%d.%m.%Y (%H:%M:%S)")
        not_valid_after = self.not_valid_after.strftime("%d.%m.%Y (%H:%M:%S)")
        nfo = ""
        nfo += f"  Certification Authority:    {'YES' if self.ca else 'NO'}\n"
        if self.ca:
            nfo += f"  Max Path Length:            {self.max_path_length}\n"
        nfo += f"  Serial Number:              {hex(self.serial_number)}\n"
        nfo += f"  Validity Range:             {not_valid_before} - {not_valid_after}\n"
        nfo += f"  Signature Algorithm:        {self.signature_algo}\n"
        nfo += f"  Self Issued:                {'YES' if self.self_issued else 'NO'}\n"
        nfo += self._get_issuer_info("country_name", "  Issuer Country Name:        {}\n")
        nfo += self._get_issuer_info("state_or_province_name", "  Issuer State/Province Name: {}\n")
        nfo += self._get_issuer_info("locality_name", "  Issuer Locality Name:       {}\n")
        nfo += self._get_issuer_info("organization_name", "  Issuer Organization Name:   {}\n")
        nfo += self._get_issuer_info(
            "organizational_unit_name", "  Issuer Organ. Unit Name:    {}\n"
        )
        nfo += self._get_issuer_info("common_name", "  Issuer Common Name:         {}\n")
        nfo += self._get_issuer_info("email_address", "  Issuer Email Address:       {}\n")
        return nfo

    def export(self) -> bytes:
        """Serialized Certificate data."""
        raw_data = self._data
        if len(raw_data) % 4:
            raw_data += b"\x00" * (4 - (len(raw_data) % 4))
        return raw_data

    def verify(self, public_key_modulus: int, public_key_exponent: int) -> bool:
        """Use given public key to verify the certificate is signed.

        :param public_key_modulus: modulus of the public key to be verified
        :param public_key_exponent: exponent of the public key to be verified
        :return: True if verification pass; False otherwise
        """
        public_key = internal_backend.rsa_public_key(public_key_modulus, public_key_exponent)
        key_object = load_public_key(public_key.export_key())
        try:
            rsa_pkcs1v15_verify(
                key_object,
                self._cert["signature_value"].native,
                self._cert["tbs_certificate"].dump(),
                self.hash_algo,
            )
        except SignatureError:
            return False
        return True

    def dump(self, force: bool = False) -> bytes:
        """Encodes the value using DER.

        :param force:
            If the encoded contents already exist, clear them and regenerate
            to ensure they are in DER format instead of BER format

        :return: A byte string of the DER-encoded value
        """
        return self._cert.dump(force)
