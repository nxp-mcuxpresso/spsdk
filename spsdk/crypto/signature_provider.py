#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SignatureProvider is an Interface for all potential signature providers.

Each concrete signature provider needs to implement:
- sign(data: bytes) -> bytes
- signature_length -> int
- into() -> str
"""

import abc
import logging
import os
from typing import Any, Optional, Union, cast

from cryptography.hazmat.primitives.hashes import HashAlgorithm

from spsdk.crypto.crypto_types import SPSDKEncoding
from spsdk.crypto.exceptions import SPSDKKeysNotMatchingError
from spsdk.crypto.hash import EnumHashAlgorithm, get_hash, get_hash_algorithm
from spsdk.crypto.keys import (
    ECDSASignature,
    PrivateKey,
    PrivateKeyEcc,
    PrivateKeyRsa,
    PrivateKeySM2,
    PublicKey,
    SPSDKKeyPassphraseMissing,
    prompt_for_passphrase,
)
from spsdk.exceptions import SPSDKError, SPSDKUnsupportedOperation, SPSDKValueError
from spsdk.utils.config import Config
from spsdk.utils.http_client import HTTPClientBase
from spsdk.utils.misc import find_file, load_secret
from spsdk.utils.service_provider import ServiceProvider

logger = logging.getLogger(__name__)


class SignatureProvider(ServiceProvider):
    """Abstract class (Interface) for all signature providers."""

    # Subclasses override the following signature provider type
    identifier = "INVALID"
    reserved_keys = ["type", "identifier", "search_paths"]
    legacy_identifier_name = "sp_type"
    plugin_identifier = "spsdk.sp"

    @abc.abstractmethod
    def sign(self, data: bytes) -> bytes:
        """Return signature for data."""

    @property
    @abc.abstractmethod
    def signature_length(self) -> int:
        """Return length of the signature."""

    def verify_public_key(self, public_key: PublicKey) -> bool:
        """Verify if given public key matches private key."""
        raise SPSDKUnsupportedOperation("Verify method is not supported.")

    def try_to_verify_public_key(self, public_key: Union[PublicKey, bytes]) -> None:
        """Verify public key by signature provider if verify method is implemented.

        :param public_key: Public key to be verified. If used as bytes, it can be in PEM/DER/NXP format
        :raises SPSDKUnsupportedOperation: The verify_public_key method si not implemented
        :raises SPSDKError: The verification of key-pair integrity failed
        """
        try:
            if isinstance(public_key, bytes):
                public_key = PublicKey.parse(public_key)
            result = self.verify_public_key(public_key)
            if not result:
                raise SPSDKKeysNotMatchingError(
                    "Signature verification failed, public key does not match to private key"
                )
            logger.debug("The verification of private key pair integrity has been successful.")
        except SPSDKUnsupportedOperation:
            logger.warning("Signature provider could not verify the integrity of private key pair.")

    def get_signature(self, data: bytes, encoding: Optional[SPSDKEncoding] = None) -> bytes:
        """Get signature. In case of ECC signature, the NXP format(r+s) is used.

        :param data: Data to be signed.
        :param encoding: Encoding type of output signature.
        :return: Signature of the data
        """
        signature = self.sign(data)
        try:
            ecdsa_sig = ECDSASignature.parse(signature)
            signature = ecdsa_sig.export(encoding or SPSDKEncoding.NXP)
        except SPSDKValueError:
            pass  # Not an ECC signature
        if len(signature) != self.signature_length:
            logger.warning(
                f"Signature has unexpected length: {len(signature)}. Expected length: {self.signature_length}"
            )
        return signature


class PlainFileSP(SignatureProvider):
    """PlainFileSP is a SignatureProvider implementation that uses plain local files."""

    identifier = "file"

    def __init__(
        self,
        file_path: str,
        password: Optional[str] = None,
        hash_alg: Optional[EnumHashAlgorithm] = None,
        search_paths: Optional[list[str]] = None,
        **kwargs: Union[str, int, bool, EnumHashAlgorithm],
    ) -> None:
        """Initialize the plain file signature provider.

        :param file_path: Path to private file
        :param password: Password in case of encrypted private file, defaults to None
        :param hash_alg: Hash for the signature, defaults to None
        :param search_paths: List of paths where to search for the file, defaults to None
        :raises SPSDKError: Invalid Private Key
        """
        password = load_secret(password, search_paths) if password else None
        self.sign_kwargs = kwargs
        self.file_path = find_file(file_path=file_path, search_paths=search_paths)
        self.private_key = PrivateKey.load(self.file_path, password=password)
        self.hash_alg = hash_alg

    @property
    def hash_alg(self) -> Optional[EnumHashAlgorithm]:
        """Hash algorithm property."""
        return self._hash_alg

    @hash_alg.setter
    def hash_alg(self, hash_alg: Optional[EnumHashAlgorithm]) -> None:
        """Hash algorithm property setter."""
        self._hash_alg = hash_alg
        if hash_alg:
            self.sign_kwargs["algorithm"] = hash_alg

    def _get_hash_algorithm(self, hash_alg: Optional[EnumHashAlgorithm] = None) -> HashAlgorithm:
        if hash_alg:
            hash_alg_name = hash_alg
        else:
            if isinstance(self.private_key, PrivateKeyRsa):
                hash_alg_name = EnumHashAlgorithm.SHA256

            elif isinstance(self.private_key, PrivateKeyEcc):
                # key_size <= 256       =>  SHA256
                # 256 < key_size <= 384 =>  SHA384
                # 384 < key_size        =>  SHA512
                if self.private_key.key_size <= 256:
                    hash_size = 256
                elif 256 < self.private_key.key_size <= 384:
                    hash_size = 384
                else:
                    hash_size = 512
                hash_alg_name = EnumHashAlgorithm.from_label(f"sha{hash_size}")

            elif isinstance(self.private_key, PrivateKeySM2):
                hash_alg_name = EnumHashAlgorithm.SM3
            else:
                raise SPSDKError(
                    f"Unsupported private key by signature provider: {str(self.private_key)}"
                )
        return get_hash_algorithm(hash_alg_name)

    @property
    def signature_length(self) -> int:
        """Return length of the signature."""
        return self.private_key.signature_size

    def verify_public_key(self, public_key: PublicKey) -> bool:
        """Verify if given public key matches private key."""
        return self.private_key.verify_public_key(public_key)

    def info(self) -> str:
        """Return basic into about the signature provider."""
        msg = super().info()
        msg += f"\nKey path: {self.file_path}\n"
        return msg

    def sign(self, data: bytes) -> bytes:
        """Return the signature for data."""
        return self.private_key.sign(data, **self.sign_kwargs)


class InteractivePlainFileSP(PlainFileSP):
    """SignatureProvider implementation that uses plain local file in an "interactive" mode.

    If the private key is encrypted, the user will be prompted for password
    """

    identifier = "interactive_file"

    def __init__(
        self,
        file_path: str,
        hash_alg: Optional[EnumHashAlgorithm] = None,
        search_paths: Optional[list[str]] = None,
        **kwargs: Union[str, int, bool],
    ) -> None:
        """Initialize the interactive plain file signature provider.

        :param file_path: Path to private file
        :param hash_alg: Hash for the signature, defaults to sha256
        :param search_paths: List of paths where to search for the file, defaults to None
        :raises SPSDKError: Invalid Private Key
        """
        try:
            super().__init__(
                file_path=file_path,
                password=cast(Optional[str], kwargs.pop("password", None)),
                hash_alg=hash_alg,
                search_paths=search_paths,
                **kwargs,
            )
        except SPSDKKeyPassphraseMissing:
            password = prompt_for_passphrase()
            super().__init__(
                file_path=file_path,
                password=password,
                hash_alg=hash_alg,
                search_paths=search_paths,
                **kwargs,
            )


class HttpProxySP(HTTPClientBase, SignatureProvider):
    """Signature Provider implementation that delegates all operations to a proxy server."""

    identifier = "proxy"
    reserved_keys = ["type", "search_paths", "data"]
    api_version = "2.0"

    def __init__(
        self,
        host: str = "localhost",
        port: str = "8000",
        url_prefix: str = "api",
        timeout: int = 60,
        prehash: Optional[str] = None,
        **kwargs: Union[str, int, bool],
    ) -> None:
        """Initialize Http Proxy Signature Provider.

        :param host: Hostname (IP address) of the proxy server, defaults to "localhost"
        :param port: Port of the proxy server, defaults to "8000"
        :param url_prefix: REST API prefix, defaults to "api"
        :param timeout: REST API timeout in seconds, defaults to 60
        :param prehash: Name of the hashing algorithm to pre-hash data before sending to signing service
        """
        super().__init__(
            host=host,
            port=int(port),
            url_prefix=url_prefix,
            timeout=timeout,
            use_ssl=False,
            raise_exceptions=True,
            **kwargs,
        )
        self.prehash = prehash

    def sign(self, data: bytes) -> bytes:
        """Return signature for data."""
        if self.prehash:
            data = get_hash(data=data, algorithm=EnumHashAlgorithm.from_label(self.prehash))
        response = self._handle_request(
            method=self.Method.GET,
            url="/sign",
            json_data={
                "data": data.hex(),
                "prehashed": self.prehash,
            },
        )
        response_data = self._check_response(response=response, names_types=[("data", str)])
        return bytes.fromhex(response_data["data"])

    @property
    def signature_length(self) -> int:
        """Return length of the signature."""
        response = self._handle_request(method=self.Method.GET, url="/signature_length")
        response_data = self._check_response(response=response, names_types=[("data", int)])
        return int(response_data["data"])

    def verify_public_key(self, public_key: PublicKey) -> bool:
        """Verify if given public key matches private key."""
        response = self._handle_request(
            method=self.Method.GET,
            url="/verify_public_key",
            json_data={
                "data": public_key.export(encoding=SPSDKEncoding.PEM).decode("utf-8"),
                "encoding": "pem",
            },
        )
        response_data = self._check_response(response=response, names_types=[("data", bool)])
        return response_data["data"]


def get_signature_provider(config: Config, key: str = "signer", **kwargs: Any) -> SignatureProvider:
    """Get the signature provider instance from configuration.

    This function creates a signature provider based on provided configuration.
    If the key parameter refers to a configuration string, it will use that
    to create the signature provider. If it refers to a file path, it will
    create an InteractivePlainFileSP with that file.

    :param config: Configuration object that contains signature provider settings.
    :param key: Config key under which the signature provider configuration is stored.
                Defaults to "signer".
    :param kwargs: Additional parameters that will be passed to the signature provider.
    :return: Instantiated Signature Provider.
    :raises SPSDKValueError: If signature provider configuration is missing.
    :raises SPSDKError: If signature provider could not be created from the configuration.
    """
    if key not in config:
        raise SPSDKValueError(f"Signature provider configuration '{key}' is missing")
    try:
        params: dict[str, Union[str, list[str]]] = {"search_paths": config.search_paths}
        params.update(SignatureProvider.convert_params(config.get_str(key)))

        for k, v in kwargs.items():
            if k not in params:
                params[k] = v
        signature_provider = SignatureProvider.create(params=params)
        if not signature_provider:
            raise SPSDKError(
                f"Signature provider could not be created from config {config.get_str(key)}."
            )
    except SPSDKValueError:
        signature_provider = InteractivePlainFileSP(
            file_path=config.get_input_file_name(key),
            **kwargs,
        )
    return signature_provider


def get_signature_provider_from_config_str(config_str: str, **kwargs: Any) -> SignatureProvider:
    """Create a signature provider from a configuration string.

    :param config_str: Configuration string for signature provider
    :param kwargs: Additional parameters that will be passed to the signature provider.
    """
    config = Config({"signer": config_str})
    config.search_paths.append(os.getcwd())
    return get_signature_provider(config, **kwargs)


def try_to_verify_public_key(signature_provider: SignatureProvider, public_key_data: bytes) -> None:
    """Verify public key by signature provider if verify method is implemented."""
    logger.warning(
        "Function `try_to_verify_public_key` is deprecated and will be removed. "
        "Please use `SignatureProvider.try_to_verify_public_key` instead."
    )
    signature_provider.try_to_verify_public_key(public_key_data)
