#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK signature provider interface and implementations.

This module provides a unified interface for various signature providers used in SPSDK,
including file-based, interactive, and HTTP proxy signature providers. It enables
flexible signature generation across different deployment scenarios from development
to production environments.
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
    """Abstract base class for cryptographic signature providers in SPSDK.

    This class defines the interface for all signature providers that handle cryptographic
    signing operations across NXP MCU portfolio. Signature providers abstract the underlying
    signing mechanisms (hardware tokens, files, remote services) and provide unified API
    for generating digital signatures.

    :cvar identifier: Unique identifier for the signature provider type.
    :cvar reserved_keys: Configuration keys reserved by the base class.
    :cvar legacy_identifier_name: Legacy name for backward compatibility.
    :cvar plugin_identifier: Plugin system identifier for dynamic loading.
    """

    # Subclasses override the following signature provider type
    identifier = "INVALID"
    reserved_keys = ["type", "identifier", "search_paths"]
    legacy_identifier_name = "sp_type"
    plugin_identifier = "spsdk.sp"

    @abc.abstractmethod
    def sign(self, data: bytes) -> bytes:
        """Sign data using the configured signature provider.

        :param data: Data to be signed.
        :return: Digital signature of the input data.
        """

    @property
    @abc.abstractmethod
    def signature_length(self) -> int:
        """Get the length of the signature in bytes.

        :return: Length of the signature in bytes.
        """

    def verify_public_key(self, public_key: PublicKey) -> bool:
        """Verify if given public key matches private key.

        :param public_key: Public key to verify against the private key.
        :raises SPSDKUnsupportedOperation: Verify method is not supported.
        """
        raise SPSDKUnsupportedOperation("Verify method is not supported.")

    def try_to_verify_public_key(self, public_key: Union[PublicKey, bytes]) -> None:
        """Verify public key by signature provider if verify method is implemented.

        The method attempts to verify that the provided public key corresponds to the private key
        held by the signature provider. If the public key is provided as bytes, it will be parsed
        automatically. The verification is optional and depends on provider implementation.

        :param public_key: Public key to be verified. If used as bytes, it can be in PEM/DER/NXP
            format
        :raises SPSDKUnsupportedOperation: The verify_public_key method is not implemented
        :raises SPSDKKeysNotMatchingError: The verification of key-pair integrity failed
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
        """Get signature with optional encoding format.

        In case of ECC signature, the NXP format (r+s) is used by default. The method
        automatically detects ECC signatures and applies the specified encoding format.
        Non-ECC signatures are returned as-is.

        :param data: Data to be signed.
        :param encoding: Encoding type of output signature, defaults to NXP format for ECC.
        :return: Signature of the data in the specified encoding format.
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
    """File-based signature provider for local cryptographic operations.

    This signature provider implementation loads private keys from local files
    and performs cryptographic signing operations. It supports encrypted private
    keys with password protection and automatic hash algorithm selection based
    on key type and size.

    :cvar identifier: Provider identifier used for configuration and registration.
    """

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

        :param file_path: Path to private key file.
        :param password: Password for encrypted private key file, defaults to None.
        :param hash_alg: Hash algorithm for the signature, defaults to None.
        :param search_paths: List of paths where to search for the file, defaults to None.
        :param kwargs: Additional keyword arguments for signing operation.
        :raises SPSDKError: Invalid private key or file not found.
        """
        password = load_secret(password, search_paths) if password else None
        self.sign_kwargs = kwargs
        self.file_path = find_file(file_path=file_path, search_paths=search_paths)
        self.private_key = PrivateKey.load(self.file_path, password=password)
        self.hash_alg = hash_alg

    @property
    def hash_alg(self) -> Optional[EnumHashAlgorithm]:
        """Get hash algorithm used by the signature provider.

        :return: Hash algorithm enumeration value, None if not set.
        """
        return self._hash_alg

    @hash_alg.setter
    def hash_alg(self, hash_alg: Optional[EnumHashAlgorithm]) -> None:
        """Set hash algorithm for signature operations.

        Updates the internal hash algorithm and configures the signing parameters
        accordingly. If hash algorithm is provided, it will be set in the sign_kwargs
        dictionary for use in signature operations.

        :param hash_alg: Hash algorithm to use for signing operations, or None to clear.
        """
        self._hash_alg = hash_alg
        if hash_alg:
            self.sign_kwargs["algorithm"] = hash_alg

    def _get_hash_algorithm(self, hash_alg: Optional[EnumHashAlgorithm] = None) -> HashAlgorithm:
        """Get appropriate hash algorithm for the private key type.

        Determines the hash algorithm based on the provided parameter or automatically
        selects one based on the private key type and size. For RSA keys, SHA256 is used.
        For ECC keys, the algorithm is chosen based on key size (SHA256 for â¤256 bits,
        SHA384 for 256-384 bits, SHA512 for >384 bits). For SM2 keys, SM3 is used.

        :param hash_alg: Specific hash algorithm to use, if None auto-detection is applied.
        :raises SPSDKError: Unsupported private key type.
        :return: Hash algorithm instance for the given or detected algorithm.
        """
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
        """Get signature length in bytes.

        :return: Length of the signature in bytes.
        """
        return self.private_key.signature_size

    def verify_public_key(self, public_key: PublicKey) -> bool:
        """Verify if given public key matches private key.

        :param public_key: Public key to verify against the private key.
        :return: True if public key matches private key, False otherwise.
        """
        return self.private_key.verify_public_key(public_key)

    def info(self) -> str:
        """Return basic information about the signature provider.

        The method extends the parent class info with additional details about
        the key file path used by this signature provider.

        :return: Formatted string containing signature provider information including key path.
        """
        msg = super().info()
        msg += f"\nKey path: {self.file_path}\n"
        return msg

    def sign(self, data: bytes) -> bytes:
        """Sign data using the private key.

        :param data: Data to be signed.
        :return: Digital signature of the input data.
        """
        return self.private_key.sign(data, **self.sign_kwargs)


class InteractivePlainFileSP(PlainFileSP):
    """Interactive signature provider for encrypted private key files.

    This signature provider extends PlainFileSP to handle encrypted private keys
    by automatically prompting the user for a password when the key requires
    decryption. It provides a seamless interactive experience for signature
    operations with password-protected keys.

    :cvar identifier: Provider identifier for registration and lookup.
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

        This provider automatically prompts for password if the private key file
        requires one and no password was provided in the initial attempt.

        :param file_path: Path to private key file.
        :param hash_alg: Hash algorithm for the signature, defaults to sha256.
        :param search_paths: List of paths where to search for the file, defaults to None.
        :param kwargs: Additional keyword arguments including optional password.
        :raises SPSDKError: Invalid private key or initialization failure.
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
    """HTTP Proxy Signature Provider for remote cryptographic operations.

    This class implements a signature provider that delegates cryptographic signing
    operations to a remote proxy server via HTTP REST API. It supports optional
    data pre-hashing before transmission and provides a secure way to perform
    signing operations without direct access to private keys.

    :cvar identifier: Provider type identifier for configuration.
    :cvar reserved_keys: Configuration keys reserved by the framework.
    :cvar api_version: Supported API version for proxy communication.
    """

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
        :param kwargs: Additional keyword arguments passed to parent class
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
        """Sign data using the signature provider.

        The method optionally pre-hashes the input data if prehash algorithm is configured,
        then sends a signing request to the remote signature service.

        :param data: Data to be signed.
        :return: Digital signature of the input data.
        :raises SPSDKError: If the signing request fails or response is invalid.
        """
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
        """Get signature length from remote signature provider.

        Retrieves the length of signatures that will be produced by the remote
        signature provider service.

        :raises SPSDKError: Communication with signature provider failed.
        :raises SPSDKValueError: Invalid response from signature provider.
        :return: Length of the signature in bytes.
        """
        response = self._handle_request(method=self.Method.GET, url="/signature_length")
        response_data = self._check_response(response=response, names_types=[("data", int)])
        return int(response_data["data"])

    def verify_public_key(self, public_key: PublicKey) -> bool:
        """Verify if given public key matches private key.

        This method sends a request to verify that the provided public key corresponds
        to the private key held by the signature provider.

        :param public_key: The public key to verify against the private key.
        :return: True if the public key matches the private key, False otherwise.
        """
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
    """Get signature provider instance from configuration.

    Creates a signature provider based on provided configuration. If the key parameter
    refers to a configuration string, it will use that to create the signature provider.
    If it refers to a file path, it will create an InteractivePlainFileSP with that file.

    :param config: Configuration object that contains signature provider settings.
    :param key: Config key under which the signature provider configuration is stored,
                defaults to "signer".
    :param kwargs: Additional parameters that will be passed to the signature provider.
    :raises SPSDKValueError: If signature provider configuration is missing.
    :raises SPSDKError: If signature provider could not be created from the configuration.
    :return: Instantiated signature provider.
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

    The method creates a Config object from the provided string, sets the current working
    directory as search path, and returns the corresponding signature provider.

    :param config_str: Configuration string for signature provider
    :param kwargs: Additional parameters that will be passed to the signature provider
    :return: Configured signature provider instance
    """
    config = Config({"signer": config_str})
    config.search_paths.append(os.getcwd())
    return get_signature_provider(config, **kwargs)


def try_to_verify_public_key(signature_provider: SignatureProvider, public_key_data: bytes) -> None:
    """Verify public key by signature provider if verify method is implemented.

    This function is deprecated and will be removed in future versions.
    Use SignatureProvider.try_to_verify_public_key method instead.

    :param signature_provider: The signature provider instance to use for verification.
    :param public_key_data: Public key data in bytes format to be verified.
    """
    logger.warning(
        "Function `try_to_verify_public_key` is deprecated and will be removed. "
        "Please use `SignatureProvider.try_to_verify_public_key` instead."
    )
    signature_provider.try_to_verify_public_key(public_key_data)
