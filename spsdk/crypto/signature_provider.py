#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SignatureProvider is an Interface for all potential signature providers.

Each concrete signature provider needs to implement:
- sign(data: bytes) -> bytes
- into() -> str
"""

import abc
import logging
from typing import Any, Dict, List, Optional, Union

from Crypto.PublicKey import ECC

from spsdk import crypto
from spsdk.exceptions import SPSDKError, SPSDKUnsupportedOperation, SPSDKValueError
from spsdk.utils.crypto.backend_internal import internal_backend
from spsdk.utils.crypto.common import crypto_backend
from spsdk.utils.misc import find_file

logger = logging.getLogger(__name__)


class SignatureProvider(abc.ABC):
    """Abstract class (Interface) for all signature providers."""

    # Subclasses override the following signature provider type
    sp_type = "INVALID"

    @abc.abstractmethod
    def sign(self, data: bytes) -> bytes:
        """Return signature for data."""

    @property
    @abc.abstractmethod
    def signature_length(self) -> int:
        """Return length of the signature."""

    def verify_public_key(self, public_key: bytes) -> bool:
        """Verify if given public key matches private key."""
        raise SPSDKUnsupportedOperation("Verify method is not supported.")

    def info(self) -> str:
        """Provide information about the Signature provider."""
        return self.__class__.__name__

    @staticmethod
    def convert_params(params: str) -> Dict[str, str]:
        """Coverts creation params from string into dictionary.

        e.g.: "type=file;file_path=some_path" -> {'type': 'file', 'file_path': 'some_path'}
        """
        try:
            result = dict([tuple(p.split("=")) for p in params.split(";")])  # type: ignore  #oh dear Mypy
        except ValueError as e:
            raise SPSDKValueError(
                "Parameter must meet following pattern: type=file;file_path=some_path"
            ) from e
        return result

    @classmethod
    def get_types(cls) -> List[str]:
        """Returns a list of all available signature provider types."""
        return [sub_class.sp_type for sub_class in cls.__subclasses__()]

    @classmethod
    def create(cls, params: Union[str, dict]) -> Optional["SignatureProvider"]:
        """Creates an concrete instance of signature provider."""
        if isinstance(params, str):
            params = cls.convert_params(params)
        for (
            klass
        ) in cls.__subclasses__():  # pragma: no branch  # there always be at least one subclass
            if klass.sp_type == params["type"]:
                del params["type"]
                unused_params = set(params) - set(klass.__init__.__code__.co_varnames)
                for unused_param in unused_params:
                    if unused_param != "search_paths":
                        logger.warning(
                            f"Removing unused parameter for {klass.sp_type} signature provider: {unused_param}"
                        )
                    del params[unused_param]
                return klass(**params)  # type: ignore  #oh dear Mypy
        return None


class PlainFileSP(SignatureProvider):
    """PlainFileSP is a SignatureProvider implementation that uses plain local files."""

    sp_type = "file"

    def __init__(
        self,
        file_path: str,
        password: str = "",  # pylint: disable=unused-argument
        encoding: str = "PEM",  # pylint: disable=unused-argument
        hash_alg: Optional[str] = None,
        search_paths: Optional[List[str]] = None,
        mode: Optional[str] = None,
    ) -> None:
        """Initialize the plain file signature provider.

        :param file_path: Path to private file
        :param password: Password in case of encrypted private file, defaults to ''
        :param encoding: Private file encoding, defaults to 'PEM'
        :param hash_alg: Hash for the signature, defaults to 'sha256'
        :param mode: Optionally there could be specified mode of signature algorithm.
            For example to switch EC signature to deterministic mode 'deterministic-rfc6979' must be used
        :raises SPSDKError: Invalid Private Key
        """
        self.file_path = find_file(file_path=file_path, search_paths=search_paths)
        self.private_key = crypto.load_private_key(self.file_path)
        assert isinstance(self.private_key, crypto._PrivateKeyTuple)
        if hash_alg:
            hash_alg_name = hash_alg
        else:
            if isinstance(self.private_key, crypto.RSAPrivateKey):
                hash_alg_name = "sha256"

            elif isinstance(self.private_key, crypto.EllipticCurvePrivateKey):
                # key_size <= 256       =>  SHA256
                # 256 < key_size <= 384 =>  SHA384
                # 384 < key_size        =>  SHA512
                if self.private_key.key_size <= 256:
                    hash_size = 256
                elif 256 < self.private_key.key_size <= 384:
                    hash_size = 384
                else:
                    hash_size = 512
                hash_alg_name = f"sha{hash_size}"
            else:
                raise SPSDKError(
                    f"Unsupported private key by signature provider: {str(self.private_key)}"
                )
        self.mode = mode
        self.hash_alg = getattr(crypto.hashes, hash_alg_name.upper())()

    @property
    def signature_length(self) -> int:
        """Return length of the signature."""
        sig_len = self.private_key.key_size // 8
        if isinstance(self.private_key, crypto.EllipticCurvePrivateKey):
            sig_len *= 2
        return sig_len

    def verify_public_key(self, public_key: bytes) -> bool:
        """Verify if given public key matches private key."""
        crypto_public_key = crypto.loaders.load_public_key_from_data(public_key)
        assert isinstance(crypto_public_key, crypto._PublicKeyTuple)
        data = bytes()
        if isinstance(crypto_public_key, crypto.RSAPublicKey):
            signature = self._rsa_sign(data)
            is_matching = crypto_backend().rsa_verify(
                pub_key_mod=crypto_public_key.public_numbers().n,
                pub_key_exp=crypto_public_key.public_numbers().e,
                signature=signature,
                data=data,
            )
            return is_matching
        else:  # public_key can be only one of RSAPublicKey | EllipticCurvePublicKey type
            signature = self._ecc_sign(data)
            is_matching = crypto_backend().ecc_verify(
                public_key=public_key, signature=signature, data=data
            )
            return is_matching

    def info(self) -> str:
        """Return basic into about the signature provider."""
        msg = super().info()
        msg += f"\nKey path: {self.file_path}\n"
        return msg

    def sign(self, data: bytes) -> bytes:
        """Return the signature for data."""
        if isinstance(self.private_key, crypto.RSAPrivateKey):
            return self._rsa_sign(data)
        else:  # self.private_key can be only one of RSAPrivateKey | RSAPublicKey type
            return self._ecc_sign(data)

    def _rsa_sign(self, data: bytes) -> bytes:
        """Return RSA signature."""
        assert isinstance(self.private_key, crypto.RSAPrivateKey)
        signature = self.private_key.sign(
            data=data, padding=crypto.padding.PKCS1v15(), algorithm=self.hash_alg
        )
        return signature

    def _ecc_sign(self, data: bytes) -> bytes:
        """Return ECC signature."""
        assert isinstance(self.private_key, crypto.EllipticCurvePrivateKey)
        if self.mode and self.mode == "deterministic-rfc6979":
            private_key_bytes = self.private_key.private_bytes(
                encoding=crypto.Encoding.PEM,
                format=crypto.serialization.PrivateFormat.PKCS8,
                encryption_algorithm=crypto.serialization.NoEncryption(),
            )
            crypto_dome_key = ECC.import_key(private_key_bytes)
            signature = internal_backend.ecc_sign(crypto_dome_key, data)
        else:
            signature = self.private_key.sign(
                data=data, signature_algorithm=crypto.ec.ECDSA(self.hash_alg)
            )
        return signature


def get_signature_provider(
    sp_cfg: Optional[str], local_file_key: Optional[str], **kwargs: Any
) -> SignatureProvider:
    """Get the signature provider from configuration.

    :param sp_cfg: Configuration of signature provider.
    :param local_file_key: Optional backward compatibility
        option to specify just path to local private key.
    :param kwargs: Additional parameters, that could be accepted by Signature providers.
    :return: Signature Provider instance.
    :raises SPSDKError: Invalid input configuration.
    """
    if sp_cfg:
        params: Dict[str, Union[str, List[str]]] = {}
        params.update(SignatureProvider.convert_params(sp_cfg))
        for k, v in kwargs.items():
            if not k in params:
                params[k] = v
        signature_provider = SignatureProvider.create(params=params)
    elif local_file_key:
        signature_provider = PlainFileSP(
            file_path=local_file_key,
            search_paths=kwargs.get("search_paths"),
            mode=kwargs.get("mode"),
        )
    else:
        raise SPSDKValueError("No signature provider configuration is provided")

    if not signature_provider:
        raise SPSDKError(f"Cannot create signature provider from: {sp_cfg or local_file_key}")

    return signature_provider
