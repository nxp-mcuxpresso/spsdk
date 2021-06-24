#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SignatureProvider is an Interface for all potential signature providers.

Each concrete signature provider needs to implement:
- sign(data: bytes) -> bytes
- into() -> str
"""

import abc
from typing import Dict, List, Optional

from spsdk import crypto


class SignatureProvider(abc.ABC):
    """Abstract class (Interface) for all signature providers."""

    # Subclasses override the following signature provider type
    sp_type = "INVALID"

    @abc.abstractmethod
    def sign(self, data: bytes) -> Optional[bytes]:
        """Return signature for data."""

    @abc.abstractmethod
    def info(self) -> str:
        """Provide information about the Signature provide."""

    @staticmethod
    def _convert_params(params: str) -> Dict[str, str]:
        """Coverts creation params from string into dictionary.

        e.g.: "type=file;file_path=some_path" -> {'type': 'file', 'file_path': 'some_path'}
        """
        result = dict([tuple(p.split("=")) for p in params.split(";")])  # type: ignore  #oh dear Mypy
        return result

    @classmethod
    def get_types(cls) -> List[str]:
        """Returns a list of all available signature provider types."""
        return [sub_class.sp_type for sub_class in cls.__subclasses__()]

    @classmethod
    def create(cls, create_params: str) -> Optional["SignatureProvider"]:
        """Creates an concrete instance of signature provider."""
        params = cls._convert_params(create_params)
        for (
            klass
        ) in cls.__subclasses__():  # pragma: no branch  # there always be at least one subclass
            if klass.sp_type == params["type"]:
                del params["type"]
                return klass(**params)  # type: ignore  #oh dear Mypy
        return None


class PlainFileSP(SignatureProvider):
    """PlainFileSP is a SignatureProvider implementation that uses plain local files."""

    sp_type = "file"

    def __init__(
        self,
        file_path: str,
        password: str = "",
        encoding: str = "PEM",
        hash_alg: str = None,
    ) -> None:
        """Initialize the plain file signature provider.

        :param file_path: Path to private file
        :param password: Password in case of encrypted private file, defaults to ''
        :param encoding: Private file encoding, defaults to 'PEM'
        :param hash_alg: Hash for the signature, defaults to 'sha256'
        """
        self.file_path = file_path
        self.private_key = crypto.load_private_key(file_path)
        hash_size = self.private_key.key_size
        if isinstance(self.private_key, crypto.RSAPrivateKeyWithSerialization):
            hash_size = 256  # hash_size //= 8
        hash_alg_name = hash_alg or f"sha{hash_size}"
        self.hash_alg = getattr(crypto.hashes, hash_alg_name.upper())()

    def info(self) -> str:
        """Return basic into about the signature provider."""
        msg = "Plain File Signature Provider\n"
        msg += f"Key path: {self.file_path}\n"
        return msg

    def sign(self, data: bytes) -> Optional[bytes]:
        """Return the signature for data."""
        if isinstance(self.private_key, crypto.RSAPrivateKey):
            return self._rsa_sign(data)
        if isinstance(self.private_key, crypto.EllipticCurvePrivateKey):
            return self._ecc_sign(data)
        return None

    def _rsa_sign(self, data: bytes) -> Optional[bytes]:
        """Return RSA signature."""
        assert isinstance(self.private_key, crypto.RSAPrivateKey)
        signature = self.private_key.sign(
            data=data, padding=crypto.padding.PKCS1v15(), algorithm=self.hash_alg
        )
        return signature

    def _ecc_sign(self, data: bytes) -> Optional[bytes]:
        """Return ECC signature."""
        assert isinstance(self.private_key, crypto.EllipticCurvePrivateKey)
        signature = self.private_key.sign(
            data=data, signature_algorithm=crypto.ec.ECDSA(self.hash_alg)
        )
        return signature
