#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module with Debug Authentication Response (DAR) Packet."""

from struct import pack
from typing import Type

from typing_extensions import Self

from spsdk.crypto.signature_provider import InteractivePlainFileSP
from spsdk.dat.dac_packet import DebugAuthenticationChallenge
from spsdk.dat.debug_credential import DebugCredential
from spsdk.exceptions import SPSDKError


class DebugAuthenticateResponse:
    """Class for DAR packet."""

    def __init__(
        self,
        debug_credential: DebugCredential,
        auth_beacon: int,
        dac: DebugAuthenticationChallenge,
        path_dck_private: str,
    ) -> None:
        """Initialize the DebugAuthenticateResponse object.

        :param debug_credential: the path, where the dc is store
        :param auth_beacon: authentication beacon value
        :param dac: the path, where the dac is store
        :param path_dck_private: the path, where the dck private key is store
        """
        self.debug_credential = debug_credential
        self.auth_beacon = auth_beacon
        self.dac = dac
        self.dck_priv = path_dck_private
        self.sig_provider = InteractivePlainFileSP(path_dck_private)

    def __repr__(self) -> str:
        return f"DAR v{self.dac.version}, SOCC: {DebugCredential.get_socc_description(self.dac.version, self.dac.socc)}"

    def __str__(self) -> str:
        """String representation of DebugAuthenticateResponse."""
        msg = f"DAC:\n{str(self.dac)}\n"
        msg += f"DC:\n{str(self.debug_credential)}\n"
        msg += f"Authentication Beacon: {self.auth_beacon}\n"
        return msg

    def _get_data_for_signature(self) -> bytes:
        """Collects the data for signature in bytes format."""
        data = self._get_common_data()
        data += self.dac.challenge
        return data

    def _get_signature(self) -> bytes:
        if not self.sig_provider:
            raise SPSDKError("Signature provider is not set")
        signature = self.sig_provider.sign(self._get_data_for_signature())
        if not signature:
            raise SPSDKError("Signature is not present")
        return signature

    def export(self) -> bytes:
        """Export to binary form (serialization).

        :return: the exported bytes from object
        """
        data = self._get_common_data()
        data += self._get_signature()
        return data

    def _get_common_data(self) -> bytes:
        """Collects dc, auth_beacon."""
        data = self.debug_credential.export()
        data += pack("<L", self.auth_beacon)
        return data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse the DAR.

        :param data: Raw data as bytes
        :return: DebugAuthenticateResponse object
        :raises NotImplementedError: Derived class has to implement this method
        """
        raise NotImplementedError("Derived class has to implement this method.")

    @staticmethod
    def _get_class(version: str) -> "Type[DebugAuthenticateResponse]":
        """Get the right Debug Authentication Response class by the protocol version.

        :param version: DAT protocol version
        """
        return _version_mapping[version]

    @classmethod
    def create(
        cls,
        version: str,
        dc: DebugCredential,
        auth_beacon: int,
        dac: DebugAuthenticationChallenge,
        dck: str,
    ) -> "DebugAuthenticateResponse":
        """Create a dar object out of input parameters.

        :param version: protocol version
        :param dc: debug credential object
        :param auth_beacon: authentication beacon value
        :param dac: DebugAuthenticationChallenge object
        :param dck: string containing path to dck key
        :return: DAR object
        """
        klass = DebugAuthenticateResponse._get_class(version=version)
        dar_obj = klass(debug_credential=dc, auth_beacon=auth_beacon, dac=dac, path_dck_private=dck)
        return dar_obj


class DebugAuthenticateResponseRSA(DebugAuthenticateResponse):
    """Class for RSA specifics of DAR packet."""


class DebugAuthenticateResponseECC(DebugAuthenticateResponse):
    """Class for ECC specific of DAR."""

    KEY_LENGTH = 0
    CURVE = "secp256r1"

    def _get_common_data(self) -> bytes:
        """Collects dc, auth_beacon and UUID."""
        data = self.debug_credential.export()
        data += pack("<L", self.auth_beacon)
        data += pack("<16s", self.dac.uuid)
        return data


class DebugAuthenticateResponseECC_256(DebugAuthenticateResponseECC):
    """Class for LPC55S3x specific of DAR, 256 bits sized keys."""

    KEY_LENGTH = 32
    CURVE = "secp256r1"


class DebugAuthenticateResponseECC_384(DebugAuthenticateResponseECC):
    """Class for LPC55S3x specific of DAR, 384 bits sized keys."""

    KEY_LENGTH = 48
    CURVE = "secp384r1"


class DebugAuthenticateResponseECC_521(DebugAuthenticateResponseECC):
    """Class for LPC55S3x specific of DAR, 521 bits sized keys."""

    KEY_LENGTH = 66
    CURVE = "secp521r1"


_version_mapping = {
    "1.0": DebugAuthenticateResponseRSA,
    "1.1": DebugAuthenticateResponseRSA,
    "2.0": DebugAuthenticateResponseECC_256,
    "2.1": DebugAuthenticateResponseECC_384,
    "2.2": DebugAuthenticateResponseECC_521,
}
