#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module with Debug Authentication Response (DAR) Packet."""

from struct import pack, unpack_from
from typing import Union

from spsdk import crypto
from spsdk.crypto import utils_cryptography
from spsdk.dat import DebugAuthenticationChallenge, DebugCredential
from spsdk.dat.utils import ecc_public_numbers_to_bytes
from spsdk.utils.crypto.backend_internal import internal_backend


class DebugAuthenticateResponse:
    """Class for DAR packet."""

    def __init__(self, debug_credential: DebugCredential, auth_beacon: int,
                 dac: Union[bytes, DebugAuthenticationChallenge], path_dck_private: str) -> None:
        """Initialize the DebugAuthenticateResponse object.

        :param debug_credential:the path, where the dc is store
        :param auth_beacon: authentication beacon value
        :param dac: the path, where the dac is store
        :param path_dck_private: the path, where the dck private key is store
        """
        self.debug_credential = debug_credential
        self.auth_beacon = auth_beacon
        self.dac = dac if isinstance(dac, DebugAuthenticationChallenge) else DebugAuthenticationChallenge.parse(dac)
        self.dck_priv = path_dck_private

    def info(self) -> str:
        """String representation of DebugAuthenticateResponse."""
        msg  = f"DAC:\n{self.dac.info()}\n"  # pylint: disable=bad-whitespace
        msg += f"DC:\n{self.debug_credential.info()}\n"  # pylint: disable=bad-whitespace
        msg += f"Authentication Beacon  : {self.auth_beacon}\n"
        return msg

    def _get_data_for_signature(self) -> bytes:
        """Collects the data for signature in bytes format."""
        dc = self.debug_credential.export()
        ab = pack("<L", self.auth_beacon)
        return dc + ab + self.dac.challenge

    def _get_signature(self) -> bytes:
        raise NotImplementedError('Derived class has to implement this method.')

    def export(self) -> bytes:
        """Export to binary form (serialization).

        :return: the exported bytes from object
        """
        data = self.debug_credential.export()
        data += pack("<L", self.auth_beacon)
        data += self._get_signature()
        return data

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> 'DebugAuthenticateResponse':
        """Parse the debug credential.

        :param data: Raw data as bytes
        :param offset: Offset of input data
        :return: DebugCredential object
        """
        raise NotImplementedError


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
    """Class for ECC specifics of DAR packet."""

    def _get_signature(self) -> bytes:
        """Create signature for ECC.

        :return: signature in bytes format
        """
        key = crypto.load_private_key(self.dck_priv)
        assert isinstance(key, crypto.EllipticCurvePrivateKeyWithSerialization)
        signature = key.sign(self._get_data_for_signature(), crypto.ec.ECDSA(crypto.hashes.SHA256()))
        r, s = utils_cryptography.decode_dss_signature(signature)
        public_numbers = crypto.EllipticCurvePublicNumbers(r, s, key.curve)
        return ecc_public_numbers_to_bytes(public_numbers=public_numbers)
