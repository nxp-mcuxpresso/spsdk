#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module with Debug Authentication Response (DAR) Packet."""

from struct import pack
from typing import Type

from spsdk import crypto
from spsdk.crypto.signature_provider import PlainFileSP
from spsdk.dat import DebugAuthenticationChallenge, DebugCredential
from spsdk.dat.utils import ecc_public_numbers_to_bytes
from spsdk.utils.crypto.backend_internal import internal_backend


class DebugAuthenticateResponse:
    """Class for DAR packet."""

    def __init__(self, debug_credential: DebugCredential, auth_beacon: int,
                 dac: DebugAuthenticationChallenge, path_dck_private: str) -> None:
        """Initialize the DebugAuthenticateResponse object.

        :param debug_credential:the path, where the dc is store
        :param auth_beacon: authentication beacon value
        :param dac: the path, where the dac is store
        :param path_dck_private: the path, where the dck private key is store
        """
        self.debug_credential = debug_credential
        self.auth_beacon = auth_beacon
        self.dac = dac
        self.dck_priv = path_dck_private
        self.is_n4analog = self.debug_credential.socc == 0x04
        self.sig_provider = PlainFileSP(path_dck_private)

    def info(self) -> str:
        """String representation of DebugAuthenticateResponse."""
        # pylint: disable=bad-whitespace
        msg = f"DAC:\n{self.dac.info()}\n"
        msg += f"DC:\n{self.debug_credential.info()}\n"
        msg += f"Authentication Beacon: {self.auth_beacon}\n"
        return msg

    def _get_data_for_signature(self) -> bytes:
        """Collects the data for signature in bytes format."""
        data = self._get_common_data()
        data += self.dac.challenge
        return data

    def _get_signature(self) -> bytes:
        assert self.sig_provider, f"Signature provider is not set"
        signature = self.sig_provider.sign(self._get_data_for_signature())
        assert signature
        return signature

    def export(self) -> bytes:
        """Export to binary form (serialization).

        :return: the exported bytes from object
        """
        data = self._get_common_data()
        data += self._get_signature()
        return data

    def _get_common_data(self) -> bytes:
        """Collects dc, auth_beacon and in case of n4analog devices - UUID."""
        data = self.debug_credential.export()
        data += pack("<L", self.auth_beacon)
        if self.is_n4analog:
            data += pack("<16s", self.debug_credential.uuid)
        return data

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> 'DebugAuthenticateResponse':
        """Parse the DAR.

        :param data: Raw data as bytes
        :param offset: Offset of input data
        :return: DebugAuthenticateResponse object
        """
        raise NotImplementedError

    @classmethod
    def _get_class(cls, version: str, socc: int) -> 'Type[DebugAuthenticateResponse]':
        if socc == 4:
            return _n4analog_version_mapping[version]
        return _version_mapping[version]

    @classmethod
    def create(cls, version: str, socc: int, dc: DebugCredential,
               auth_beacon: int, dac: DebugAuthenticationChallenge, dck: str) -> 'DebugAuthenticateResponse':
        """Create a dar object out of input parameters.

        :param version: protocol version
        :param socc: SoC Class
        :param dc: debug credential object
        :param auth_beacon: authentication beacon value
        :param dac: DebugAuthenticationChallenge object
        :param dck: string containing path to dck key
        :return: DAR object
        """
        klass = DebugAuthenticateResponse._get_class(version=version, socc=socc)
        dar_obj = klass(debug_credential=dc, auth_beacon=auth_beacon, dac=dac, path_dck_private=dck)
        return dar_obj


class DebugAuthenticateResponseRSA(DebugAuthenticateResponse):
    """Class for RSA specifics of DAR packet."""

    def _get_signature(self) -> bytes:
        """Create signature for RSA.

        :return: signature in bytes format
        """
        key = crypto.load_private_key(file_path=self.dck_priv)
        key_bytes = key.private_bytes(
            encoding=crypto.Encoding.PEM,
            format=crypto.serialization.PrivateFormat.PKCS8,
            encryption_algorithm=crypto.serialization.NoEncryption()
        )
        return internal_backend.rsa_sign(key_bytes, self._get_data_for_signature())


class DebugAuthenticateResponseECC(DebugAuthenticateResponse):
    """Class for ECC specific of DAR."""

    def _get_signature(self) -> bytes:
        """Sign the DAR data using SignatureProvider."""
        signature = super()._get_signature()
        r, s = crypto.utils_cryptography.decode_dss_signature(signature)
        public_numbers = crypto.EllipticCurvePublicNumbers(r, s, crypto.ec.SECP256R1())
        signature = ecc_public_numbers_to_bytes(public_numbers=public_numbers, length=66)
        return signature


class DebugAuthenticateResponseN4A_256(DebugAuthenticateResponse):
    """Class for N4A specific of DAR."""

    def _get_signature(self) -> bytes:
        """Sign the DAR data using SignatureProvider."""
        signature = super()._get_signature()
        r, s = crypto.utils_cryptography.decode_dss_signature(signature)
        public_numbers = crypto.EllipticCurvePublicNumbers(r, s, crypto.ec.SECP256R1())
        return ecc_public_numbers_to_bytes(public_numbers=public_numbers,
                                           length=32)


class DebugAuthenticateResponseN4A_384(DebugAuthenticateResponse):
    """Class for N4A specific of DAR."""

    def _get_signature(self) -> bytes:
        """Sign the DAR data using SignatureProvider."""
        signature = super()._get_signature()
        r, s = crypto.utils_cryptography.decode_dss_signature(signature)
        public_numbers = crypto.EllipticCurvePublicNumbers(r, s, crypto.ec.SECP384R1())
        return ecc_public_numbers_to_bytes(public_numbers=public_numbers,
                                           length=48)


_version_mapping = {
    '1.0': DebugAuthenticateResponseRSA,
    '1.1': DebugAuthenticateResponseRSA,
    '2.0': DebugAuthenticateResponseECC,
    '2.1': DebugAuthenticateResponseECC,
    '2.2': DebugAuthenticateResponseECC,
}

_n4analog_version_mapping = {
    '2.0': DebugAuthenticateResponseN4A_256,
    '2.1': DebugAuthenticateResponseN4A_384
}
