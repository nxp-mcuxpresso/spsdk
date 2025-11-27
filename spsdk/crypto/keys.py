#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK cryptographic key management and operations.

This module provides comprehensive functionality for handling cryptographic keys
including RSA and ECC key types. It supports key generation, loading, saving,
and cryptographic operations like signing and verification across the SPSDK
ecosystem.
"""

import abc
import getpass
import math
from enum import Enum
from typing import Any, Callable, Optional, Union, cast

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from cryptography.hazmat.primitives.serialization import (
    load_der_private_key as crypto_load_der_private_key,
)
from cryptography.hazmat.primitives.serialization import (
    load_der_public_key as crypto_load_der_public_key,
)
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key as crypto_load_pem_private_key,
)
from cryptography.hazmat.primitives.serialization import (
    load_pem_public_key as crypto_load_pem_public_key,
)
from typing_extensions import Self

from spsdk import SPSDK_INTERACTIVE_DISABLED
from spsdk.crypto.crypto_types import SPSDKEncoding
from spsdk.crypto.dilithium import IS_DILITHIUM_SUPPORTED
from spsdk.crypto.hash import EnumHashAlgorithm, get_hash, get_hash_algorithm, hashes
from spsdk.crypto.oscca import IS_OSCCA_SUPPORTED
from spsdk.crypto.rng import rand_below, random_hex
from spsdk.exceptions import (
    SPSDKError,
    SPSDKNotImplementedError,
    SPSDKUnsupportedOperation,
    SPSDKValueError,
)
from spsdk.utils.abstract import BaseClass
from spsdk.utils.misc import Endianness, load_binary, write_file

if IS_OSCCA_SUPPORTED:
    from gmssl import sm2  # pylint: disable=import-error

    from spsdk.crypto.oscca import SM2Encoder, SM2PrivateKey, SM2PublicKey, sanitize_pem

if IS_DILITHIUM_SUPPORTED:
    # pylint: disable=import-error
    import spsdk_pqc.wrapper
    from spsdk_pqc import (
        DilithiumPrivateKey,
        DilithiumPublicKey,
        MLDSAPrivateKey,
        MLDSAPublicKey,
        PQCAlgorithm,
        PQCError,
    )

    if hasattr(spsdk_pqc.wrapper, "DISABLE_DIL_MLDSA_PUBLIC_KEY_MISMATCH_WARNING"):
        spsdk_pqc.wrapper.DISABLE_DIL_MLDSA_PUBLIC_KEY_MISMATCH_WARNING = True


def _load_pem_private_key(data: bytes, password: Optional[bytes]) -> Any:
    """Load PEM private key from binary data.

    The method attempts to load a private key using multiple algorithms including
    standard cryptographic algorithms, SM2 (if OSCCA support is available), and
    post-quantum algorithms like Dilithium and ML-DSA (if supported).

    :param data: Binary data containing the PEM-encoded private key.
    :param password: Optional password for encrypted private keys.
    :raises SPSDKError: If the key cannot be decoded with any supported algorithm.
    :return: Loaded private key object (type depends on the key algorithm).
    """
    last_error: Exception
    try:
        return _crypto_load_private_key(SPSDKEncoding.PEM, data, password)
    except (UnsupportedAlgorithm, ValueError) as exc:
        last_error = exc
    if IS_OSCCA_SUPPORTED:
        try:
            key_data = sanitize_pem(data)
            key_set = SM2Encoder().decode_private_key(data=key_data)
            return sm2.CryptSM2(private_key=key_set.private, public_key=key_set.public)
        except SPSDKError as exc:
            last_error = exc
    if IS_DILITHIUM_SUPPORTED:
        try:
            return DilithiumPrivateKey.parse(data=data)
        except PQCError as exc:
            last_error = exc
        try:
            return MLDSAPrivateKey.parse(data=data)
        except PQCError as exc:
            last_error = exc

    raise SPSDKError(f"Cannot load PEM private key: {last_error}")


def _load_der_private_key(data: bytes, password: Optional[bytes]) -> Any:
    """Load DER private key from binary data.

    The method attempts to load a DER-encoded private key using multiple algorithms
    including standard cryptographic keys, SM2 (if OSCCA support is available),
    and post-quantum algorithms like Dilithium and ML-DSA (if supported).

    :param data: DER-encoded private key binary data.
    :param password: Optional password for encrypted private keys.
    :raises SPSDKError: If the key cannot be decoded with any supported algorithm.
    :return: Loaded private key object (type varies based on key algorithm).
    """
    last_error: Exception
    try:
        return _crypto_load_private_key(SPSDKEncoding.DER, data, password)
    except (UnsupportedAlgorithm, ValueError) as exc:
        last_error = exc
    if IS_OSCCA_SUPPORTED:
        try:
            key_set = SM2Encoder().decode_private_key(data=data)
            return sm2.CryptSM2(private_key=key_set.private, public_key=key_set.public)
        except SPSDKError as exc:
            last_error = exc
    if IS_DILITHIUM_SUPPORTED:
        try:
            return DilithiumPrivateKey.parse(data=data)
        except PQCError as exc:
            last_error = exc
        try:
            return MLDSAPrivateKey.parse(data=data)
        except PQCError as exc:
            last_error = exc

    raise SPSDKError(f"Cannot load DER private key: {last_error}")


def _crypto_load_private_key(
    encoding: SPSDKEncoding, data: bytes, password: Optional[bytes]
) -> Union[ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey]:
    """Load private key from encoded data.

    The method supports both DER and PEM encoding formats and handles encrypted
    private keys with optional password protection.

    :param encoding: Encoding format of the input key data (DER or PEM).
    :param data: Raw key data in bytes.
    :param password: Optional password for encrypted private keys.
    :raises SPSDKValueError: Unsupported encoding format provided.
    :raises SPSDKWrongKeyPassphrase: Private key is encrypted and passphrase is incorrect.
    :raises SPSDKKeyPassphraseMissing: Private key is encrypted and passphrase is missing.
    :return: Loaded private key object (ECC or RSA).
    """
    if encoding not in [SPSDKEncoding.DER, SPSDKEncoding.PEM]:
        raise SPSDKValueError(f"Unsupported encoding: {encoding}")
    crypto_load_function = {
        SPSDKEncoding.DER: crypto_load_der_private_key,
        SPSDKEncoding.PEM: crypto_load_pem_private_key,
    }[encoding]
    try:
        private_key = crypto_load_function(data, password)
        assert isinstance(private_key, (ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey))
        return private_key
    except ValueError as exc:
        if "Incorrect password" in exc.args[0]:
            raise SPSDKWrongKeyPassphrase("Provided password was incorrect.") from exc
        raise exc
    except TypeError as exc:
        if "Password was not given but private key is encrypted" in str(exc):
            raise SPSDKKeyPassphraseMissing(str(exc)) from exc
        raise exc


def _load_pem_public_key(data: bytes) -> Any:
    """Load PEM public key from byte data.

    Attempts to load a PEM-formatted public key using multiple cryptographic libraries
    including standard cryptography, SM2 (if OSCCA support is enabled), and post-quantum
    algorithms like Dilithium and ML-DSA (if available).

    :param data: PEM-formatted public key data as bytes
    :raises SPSDKError: If the key cannot be decoded by any supported method
    :return: Public key object (type varies based on key algorithm)
    """
    last_error: Exception
    try:
        return crypto_load_pem_public_key(data)
    except (UnsupportedAlgorithm, ValueError) as exc:
        last_error = exc
    if IS_OSCCA_SUPPORTED:
        try:
            key_data = sanitize_pem(data)
            public_key = SM2Encoder().decode_public_key(data=key_data)
            return sm2.CryptSM2(private_key=None, public_key=public_key.public)
        except SPSDKError as exc:
            last_error = exc
    if IS_DILITHIUM_SUPPORTED:
        try:
            return DilithiumPublicKey.parse(data=data)
        except PQCError as exc:
            last_error = exc
        try:
            return MLDSAPublicKey.parse(data=data)
        except PQCError as exc:
            last_error = exc

    raise SPSDKError(f"Cannot load PEM public key: {last_error}")


def _load_der_public_key(data: bytes) -> Any:
    """Load DER public key from binary data.

    Attempts to decode the provided DER-encoded public key data using multiple algorithms
    including standard cryptographic keys, SM2 (if OSCCA support is available), and
    post-quantum algorithms like Dilithium and ML-DSA (if supported).

    :param data: DER-encoded public key binary data
    :raises SPSDKError: If the key cannot be decoded with any supported algorithm
    :return: Decoded public key object (type varies based on key algorithm)
    """
    last_error: Exception
    try:
        return crypto_load_der_public_key(data)
    except (UnsupportedAlgorithm, ValueError) as exc:
        last_error = exc
    if IS_OSCCA_SUPPORTED:
        try:
            public_key = SM2Encoder().decode_public_key(data=data)
            return sm2.CryptSM2(private_key=None, public_key=public_key.public)
        except SPSDKError as exc:
            last_error = exc
    if IS_DILITHIUM_SUPPORTED:
        try:
            return DilithiumPublicKey.parse(data=data)
        except PQCError as exc:
            last_error = exc
        try:
            return MLDSAPublicKey.parse(data=data)
        except PQCError as exc:
            last_error = exc

    raise SPSDKError(f"Cannot load DER public key: {last_error}")


class SPSDKInvalidKeyType(SPSDKError):
    """SPSDK exception for invalid cryptographic key types.

    This exception is raised when an unsupported or invalid key type is
    encountered during cryptographic operations in SPSDK.
    """


class SPSDKKeyPassphraseMissing(SPSDKError):
    """SPSDK exception for missing private key passphrase.

    This exception is raised when a passphrase is required to decrypt a private key
    but none has been provided during cryptographic operations.
    """


class SPSDKWrongKeyPassphrase(SPSDKError):
    """SPSDK exception for incorrect private key passphrase.

    This exception is raised when an incorrect or invalid passphrase is provided
    for decrypting a private key during cryptographic operations.
    """


class PrivateKey(BaseClass, abc.ABC):
    """SPSDK Private Key abstract base class.

    This abstract class defines the interface for private key operations in SPSDK,
    providing cryptographic functionality for signing operations and key management
    across different key types and algorithms.
    """

    key: Any

    @classmethod
    @abc.abstractmethod
    def generate_key(cls) -> Self:
        """Generate SPSDK Key (private key).

        :return: SPSDK private key instance.
        """

    @property
    @abc.abstractmethod
    def default_hash_algorithm(self) -> EnumHashAlgorithm:
        """Get default hash algorithm for signing and verifying operations.

        :return: Default hash algorithm enumeration value.
        """

    @property
    @abc.abstractmethod
    def signature_size(self) -> int:
        """Get the size of signature data in bytes.

        :return: Size of signature data in bytes.
        """

    @property
    @abc.abstractmethod
    def key_size(self) -> int:
        """Get key size in bits.

        :return: Key size in bits.
        """

    @abc.abstractmethod
    def get_public_key(self) -> "PublicKey":
        """Get public key from the private key.

        :return: Public key object derived from this private key.
        """

    @abc.abstractmethod
    def verify_public_key(self, public_key: "PublicKey") -> bool:
        """Verify that the given public key forms a cryptographic pair with this private key.

        This method checks if the provided public key corresponds to this private key
        by verifying their mathematical relationship in the cryptographic key pair.

        :param public_key: Public key to verify against this private key.
        :return: True if the keys form a valid pair, False otherwise.
        """

    def __eq__(self, obj: Any) -> bool:
        """Check object equality.

        Compares this object with another object by checking if they are of the same class
        and have identical public keys.

        :param obj: Object to compare with this instance.
        :return: True if objects are equal, False otherwise.
        """
        return isinstance(obj, self.__class__) and self.get_public_key() == obj.get_public_key()

    def save(
        self,
        file_path: str,
        password: Optional[str] = None,
        encoding: SPSDKEncoding = SPSDKEncoding.PEM,
    ) -> None:
        """Save the Private key to the given file.

        :param file_path: Path to the file where the key will be stored.
        :param password: Password to encrypt private key; None to store without password.
        :param encoding: Encoding type for the saved key, default is PEM.
        :raises SPSDKError: If the file cannot be written or key export fails.
        """
        write_file(self.export(password=password, encoding=encoding), file_path, mode="wb")

    @classmethod
    def load(cls, file_path: str, password: Optional[str] = None) -> Self:
        """Load the Private key from the given file.

        :param file_path: Path to the file where the key is stored.
        :param password: Password to private key; None to load without password.
        :raises SPSDKError: If the file cannot be loaded or parsed.
        :return: Loaded private key instance.
        """
        data = load_binary(file_path)
        return cls.parse(data=data, password=password)

    @abc.abstractmethod
    def sign(self, data: bytes, **kwargs: Any) -> bytes:
        """Sign input data with the cryptographic key.

        This method performs cryptographic signing of the provided data using the
        underlying key material and algorithm.

        :param data: Input data to be signed.
        :param kwargs: Additional keyword arguments specific to the key type and signing algorithm.
        :return: Digital signature of the input data.
        """

    @abc.abstractmethod
    def export(
        self,
        password: Optional[str] = None,
        encoding: SPSDKEncoding = SPSDKEncoding.DER,
    ) -> bytes:
        """Export key into bytes in requested format.

        :param password: Password to private key; None to store without password.
        :param encoding: Encoding type, default is DER.
        :return: Byte representation of key.
        """

    @classmethod
    def parse(cls, data: bytes, password: Optional[str] = None) -> Self:
        """Parse private key from bytes array.

        The method supports multiple encodings (PEM, DER) and various key types including
        RSA, ECC, SM2, Dilithium, and ML-DSA private keys.

        :param data: Raw key data to be parsed.
        :param password: Password for encrypted private key; None for unencrypted keys.
        :return: Recreated private key object.
        :raises SPSDKError: Invalid key data or unsupported key type.
        """
        try:
            private_key = {
                SPSDKEncoding.PEM: _load_pem_private_key,
                SPSDKEncoding.DER: _load_der_private_key,
            }[SPSDKEncoding.get_file_encodings(data)](
                data, password.encode("utf-8") if password else None
            )
            if isinstance(private_key, (ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey)):
                return cls.create(private_key)
            if IS_OSCCA_SUPPORTED and isinstance(private_key, sm2.CryptSM2):
                return cls.create(private_key)
            if IS_DILITHIUM_SUPPORTED and isinstance(private_key, DilithiumPrivateKey):
                return cls.create(private_key)
            if IS_DILITHIUM_SUPPORTED and isinstance(private_key, MLDSAPrivateKey):
                return cls.create(private_key)
        except (ValueError, SPSDKInvalidKeyType) as exc:
            raise SPSDKError(f"Cannot load private key: ({str(exc)})") from exc
        raise SPSDKError(f"Unsupported private key: ({str(private_key)})")

    @classmethod
    def create(cls, key: Any) -> Self:
        """Create Private Key object from supported cryptographic key types.

        This factory method creates an appropriate SPSDK private key wrapper based on the
        input key type. It supports ECC, RSA, SM2 (if OSCCA is available), and post-quantum
        Dilithium/ML-DSA keys (if Dilithium support is available).

        :param key: A cryptographic private key object (ECC, RSA, SM2, Dilithium, or ML-DSA).
        :raises SPSDKInvalidKeyType: Unsupported private key type provided.
        :return: SPSDK Private Key object wrapping the input key.
        """
        SUPPORTED_KEYS = {
            PrivateKeyEcc: ec.EllipticCurvePrivateKey,
            PrivateKeyRsa: rsa.RSAPrivateKey,
        }
        if IS_OSCCA_SUPPORTED:
            SUPPORTED_KEYS[PrivateKeySM2] = sm2.CryptSM2

        if IS_DILITHIUM_SUPPORTED:
            SUPPORTED_KEYS[PrivateKeyDilithium] = DilithiumPrivateKey
            SUPPORTED_KEYS[PrivateKeyMLDSA] = MLDSAPrivateKey

        for k, v in SUPPORTED_KEYS.items():
            if isinstance(key, v):
                return k(key)

        raise SPSDKInvalidKeyType(f"Unsupported key type: {str(key)}")


class PublicKey(BaseClass, abc.ABC):
    """SPSDK Public Key abstraction for cryptographic operations.

    This abstract base class provides a unified interface for public key operations
    across different cryptographic algorithms and key types. It handles key loading,
    saving, signature verification, and key format conversions while maintaining
    consistency across the SPSDK cryptographic framework.

    :cvar RECOMMENDED_ENCODING: Default encoding format for key serialization.
    """

    key: Any
    RECOMMENDED_ENCODING = SPSDKEncoding.PEM

    @property
    @abc.abstractmethod
    def default_hash_algorithm(self) -> EnumHashAlgorithm:
        """Get default hash algorithm for signing/verifying.

        :return: Default hash algorithm enumeration value.
        """

    @property
    @abc.abstractmethod
    def signature_size(self) -> int:
        """Get the size of signature data in bytes.

        :return: Size of signature data in bytes.
        """

    @property
    @abc.abstractmethod
    def public_numbers(self) -> Any:
        """Get the public numbers of the cryptographic key.

        Returns the public key numbers which contain the mathematical components
        that make up the public portion of the key.

        :return: Public key numbers object containing the key's mathematical components.
        """

    def save(self, file_path: str, encoding: SPSDKEncoding = SPSDKEncoding.PEM) -> None:
        """Save the public key to the file.

        :param file_path: Path to the file where the key will be stored.
        :param encoding: Encoding type for the key export, defaults to PEM.
        :raises SPSDKError: If the file cannot be written or export fails.
        """
        write_file(data=self.export(encoding=encoding), path=file_path, mode="wb")

    @classmethod
    def load(cls, file_path: str) -> Self:
        """Load the Public key from the given file.

        The method loads binary data from the specified file path and parses it to create
        a public key instance.

        :param file_path: Path to the file where the key is stored.
        :raises SPSDKError: If the file cannot be loaded or parsed.
        :return: Public key instance created from the file data.
        """
        data = load_binary(file_path)
        return cls.parse(data=data)

    @abc.abstractmethod
    def verify_signature(
        self,
        signature: bytes,
        data: bytes,
        algorithm: Optional[EnumHashAlgorithm] = None,
        **kwargs: Any,
    ) -> bool:
        """Verify signature against input data using cryptographic algorithm.

        The method validates the provided signature against the input data using the specified
        or automatically selected hash algorithm.

        :param signature: The signature bytes to verify against the data.
        :param data: Input data bytes that were signed.
        :param algorithm: Hash algorithm to use for verification, defaults to automatic selection.
        :param kwargs: Additional keyword arguments specific to the key type.
        :return: True if signature is valid, False otherwise.
        """

    @abc.abstractmethod
    def export(self, encoding: SPSDKEncoding = SPSDKEncoding.NXP) -> bytes:
        """Export key into bytes to requested format.

        :param encoding: Encoding type for the exported key data, defaults to NXP format.
        :return: Byte representation of the key in specified encoding format.
        """

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse public key from bytes array.

        Attempts to parse public key data from various formats including PEM, DER,
        ECC, RSA, Dilithium, ML-DSA, and NXP OTPS formats.

        :param data: Raw bytes containing public key data in supported format.
        :return: Parsed public key object.
        :raises SPSDKError: Unable to parse public key data from any supported format.
        """
        encoding = SPSDKEncoding.get_file_encodings(data)
        if encoding == SPSDKEncoding.PEM:
            return cls.create(_load_pem_public_key(data))

        try:
            return cls.create(_load_der_public_key(data))
        except SPSDKError:
            pass

        try:
            return cast(Self, PublicKeyEcc.recreate_from_data(data))
        except SPSDKError:
            pass

        try:
            return cast(Self, PublicKeyRsa.recreate_from_data(data))
        except SPSDKError:
            pass

        if IS_DILITHIUM_SUPPORTED:
            try:
                return cast(Self, PublicKeyDilithium.parse(data=data))
            except (SPSDKError, ValueError):
                pass
            try:
                return cast(Self, PublicKeyMLDSA.parse(data=data))
            except (SPSDKError, ValueError):
                pass

        # No need for explicit SM2, because SM2.recreate_from_data uses PEM/DER
        # There's no NXP encoding format for SM2

        # attempt to parse OTPS format as the last resort
        from spsdk.crypto._otps_puk import nxp_otps_extract_puk

        try:
            puk_data = nxp_otps_extract_puk(data)
            return cls.parse(data=puk_data)
        except SPSDKError:
            pass

        raise SPSDKError("Unable to parse public key data.")

    def key_hash(self, algorithm: EnumHashAlgorithm = EnumHashAlgorithm.SHA256) -> bytes:
        """Get key hash.

        Computes hash of the exported key data using the specified hash algorithm.

        :param algorithm: Hash algorithm to use for key hashing, defaults to SHA256.
        :return: Hash of the key data as bytes.
        """
        return get_hash(self.export(), algorithm)

    def __eq__(self, obj: Any) -> bool:
        """Check object equality.

        Compare this object with another object to determine if they are equal.
        Two objects are considered equal if they are instances of the same class
        and have identical public_numbers attributes.

        :param obj: Object to compare with this instance.
        :return: True if objects are equal, False otherwise.
        """
        return isinstance(obj, self.__class__) and self.public_numbers == obj.public_numbers

    @classmethod
    def create(cls, key: Any) -> Self:
        """Create Public Key object from supported key types.

        This factory method creates an appropriate SPSDK Public Key wrapper object based on the
        type of the input key. It supports various key types including ECC, RSA, SM2 (if OSCCA
        is supported), and post-quantum algorithms like Dilithium and ML-DSA (if available).

        :param key: A supported public key object (ECC, RSA, SM2, Dilithium, or ML-DSA).
        :raises SPSDKInvalidKeyType: Unsupported public key type provided.
        :return: SPSDK Public Key object wrapping the input key.
        """
        SUPPORTED_KEYS = {
            PublicKeyEcc: ec.EllipticCurvePublicKey,
            PublicKeyRsa: rsa.RSAPublicKey,
        }
        if IS_OSCCA_SUPPORTED:
            SUPPORTED_KEYS[PublicKeySM2] = sm2.CryptSM2

        if IS_DILITHIUM_SUPPORTED:
            SUPPORTED_KEYS[PublicKeyDilithium] = DilithiumPublicKey
            SUPPORTED_KEYS[PublicKeyMLDSA] = MLDSAPublicKey

        for k, v in SUPPORTED_KEYS.items():
            if isinstance(key, v):
                return k(key)

        raise SPSDKInvalidKeyType(f"Unsupported key type: {str(key)}")


class NonSupportingPublicKey(PublicKey):
    """Placeholder class for unsupported public key types.

    This class serves as a fallback implementation that raises an exception
    when instantiated, indicating that the specific key type is not supported
    by the SPSDK crypto module.
    """

    def __init__(self) -> None:
        """Initialize unsupported key type constructor.

        This constructor is designed to immediately raise an exception to indicate
        that the specific key type is not supported or implemented in the current
        version of SPSDK.

        :raises SPSDKNotImplementedError: The key type is not supported or implemented.
        """
        raise SPSDKNotImplementedError("The key is not supported.")


class NonSupportingPrivateKey(PrivateKey):
    """Placeholder class for unsupported private key types.

    This class serves as a fallback implementation that raises an exception
    when instantiated, indicating that the specific private key type is not
    supported by the SPSDK crypto module.
    """

    def __init__(self) -> None:
        """Initialize unsupported key type constructor.

        This constructor is designed to immediately raise an exception to indicate
        that the specific key type is not supported or implemented in the current
        version of SPSDK.

        :raises SPSDKNotImplementedError: The key type is not supported or implemented.
        """
        raise SPSDKNotImplementedError("The key is not supported.")


# ===================================================================================================
# ===================================================================================================
#
#                                      RSA Keys
#
# ===================================================================================================
# ===================================================================================================


class PrivateKeyRsa(PrivateKey):
    """SPSDK RSA Private Key implementation.

    This class provides RSA private key functionality for cryptographic operations
    including key generation, signing, and public key derivation. It supports
    standard RSA key sizes and integrates with SPSDK's cryptographic framework.

    :cvar SUPPORTED_KEY_SIZES: List of supported RSA key sizes in bits.
    """

    SUPPORTED_KEY_SIZES = [2048, 3072, 4096]

    key: rsa.RSAPrivateKey

    def __init__(self, key: rsa.RSAPrivateKey) -> None:
        """Create SPSDK RSA private key wrapper.

        Initialize the SPSDK key object with an RSA private key for cryptographic operations.

        :param key: RSA private key instance to be wrapped by SPSDK key object.
        """
        self.key = key

    @classmethod
    def generate_key(cls, key_size: int = 2048, exponent: int = 65537) -> Self:
        """Generate SPSDK RSA private key.

        This method creates a new RSA private key with specified parameters for use in
        SPSDK cryptographic operations.

        :param key_size: Key size in bits, must be >= 512.
        :param exponent: Public exponent, must be >= 3 and odd.
        :return: New SPSDK private key instance.
        """
        return cls(
            rsa.generate_private_key(
                public_exponent=exponent,
                key_size=key_size,
            )
        )

    @property
    def default_hash_algorithm(self) -> EnumHashAlgorithm:
        """Get default hash algorithm for signing/verifying operations.

        :return: Default hash algorithm enumeration value (SHA256).
        """
        return EnumHashAlgorithm.SHA256

    @property
    def signature_size(self) -> int:
        """Get the size of signature data in bytes.

        :return: Size of signature data in bytes.
        """
        return self.key.key_size // 8

    @property
    def key_size(self) -> int:
        """Key size in bits.

        :return: Key size in bits.
        """
        return self.key.key_size

    def get_public_key(self) -> "PublicKeyRsa":
        """Get public key from RSA private key.

        Extracts the public key component from the RSA private key instance.

        :return: RSA public key object.
        """
        return PublicKeyRsa(self.key.public_key())

    def verify_public_key(self, public_key: PublicKey) -> bool:
        """Verify that the given public key matches this private key.

        This method compares the provided public key with the public key derived
        from this private key to determine if they form a valid key pair.

        :param public_key: Public key to verify against this private key
        :return: True if the keys form a valid pair, False otherwise
        """
        return self.get_public_key() == public_key

    def export(
        self,
        password: Optional[str] = None,
        encoding: SPSDKEncoding = SPSDKEncoding.DER,
    ) -> bytes:
        """Export the Private key to the bytes in requested encoding.

        :param password: Password to private key; None to store without password.
        :param encoding: Encoding type, default is DER.
        :return: Private key in bytes.
        """
        enc = (
            BestAvailableEncryption(password=password.encode("utf-8"))
            if password
            else NoEncryption()
        )
        return self.key.private_bytes(
            SPSDKEncoding.get_cryptography_encodings(encoding), PrivateFormat.PKCS8, enc
        )

    def sign(
        self,
        data: bytes,
        algorithm: Optional[EnumHashAlgorithm] = None,
        pss_padding: bool = False,
        prehashed: bool = False,
        **kwargs: Any,
    ) -> bytes:
        """Sign input data with the private key.

        The method supports both PKCS#1 v1.5 and PSS padding schemes for RSA keys.
        It can handle both raw data and pre-hashed data depending on the prehashed parameter.

        :param data: Input data to be signed.
        :param algorithm: Hash algorithm to use for signing, defaults to key's default algorithm.
        :param pss_padding: Whether to use RSA-PSS padding scheme instead of PKCS#1 v1.5.
        :param prehashed: Whether the input data is already hashed.
        :param kwargs: Additional unused parameters for compatibility.
        :return: Digital signature as bytes.
        """
        hash_alg = get_hash_algorithm(algorithm or self.default_hash_algorithm)
        pad = (
            padding.PSS(mgf=padding.MGF1(algorithm=hash_alg), salt_length=padding.PSS.DIGEST_LENGTH)
            if pss_padding
            else padding.PKCS1v15()
        )
        sign_alg = utils.Prehashed(hash_alg) if prehashed else hash_alg
        assert isinstance(sign_alg, (utils.Prehashed, hashes.HashAlgorithm))
        signature = self.key.sign(data=data, padding=pad, algorithm=sign_alg)
        return signature

    @classmethod
    def parse(cls, data: bytes, password: Optional[str] = None) -> Self:
        """Parse RSA private key from bytes array.

        The method parses binary data to recreate an RSA private key object with optional
        password protection support.

        :param data: Binary data containing the RSA private key to be parsed.
        :param password: Password for encrypted private key; None for unencrypted keys.
        :raises SPSDKInvalidKeyType: When the data cannot be parsed as RSA private key.
        :return: Recreated RSA private key object.
        """
        key = super().parse(data=data, password=password)
        if isinstance(key, PrivateKeyRsa):
            return key

        raise SPSDKInvalidKeyType("Can't parse Rsa private key from given data")

    def __repr__(self) -> str:
        """Return string representation of the RSA private key.

        :return: String containing key type and size information.
        """
        return f"RSA{self.key_size} Private Key"

    def __str__(self) -> str:
        """Get string representation of the RSA private key.

        Returns a formatted string containing the key size and private exponent value
        in hexadecimal format for debugging and logging purposes.

        :return: String representation showing RSA key size and private exponent.
        """
        ret = f"RSA{self.key_size} Private key: \nd({hex(self.key.private_numbers().d)})"
        return ret


class PublicKeyRsa(PublicKey):
    """SPSDK RSA Public Key implementation.

    This class provides RSA public key operations for cryptographic functions
    including signature verification and key property access. It wraps the
    cryptography library's RSA public key with SPSDK-specific functionality.
    """

    key: rsa.RSAPublicKey

    def __init__(self, key: rsa.RSAPublicKey) -> None:
        """Create SPSDK Public Key.

        :param key: RSA public key object to be wrapped by SPSDK.
        :raises SPSDKError: If the provided key is invalid or unsupported.
        """
        self.key = key

    @property
    def default_hash_algorithm(self) -> EnumHashAlgorithm:
        """Get default hash algorithm for signing and verifying operations.

        :return: Default hash algorithm enumeration value (SHA256).
        """
        return EnumHashAlgorithm.SHA256

    @property
    def signature_size(self) -> int:
        """Get the size of signature data in bytes.

        :return: Size of signature data in bytes.
        """
        return self.key.key_size // 8

    @property
    def key_size(self) -> int:
        """Key size in bits.

        :return: Key size in bits.
        """
        return self.key.key_size

    @property
    def public_numbers(self) -> rsa.RSAPublicNumbers:
        """Public numbers of key.

        :return: Public numbers
        """
        return self.key.public_numbers()

    @property
    def e(self) -> int:
        """Get the public exponent E of the RSA key.

        The public exponent E is a component of the RSA public key used in cryptographic
        operations for encryption and signature verification.

        :return: The public exponent E as an integer.
        """
        return self.public_numbers.e

    @property
    def n(self) -> int:
        """Get the RSA public key modulus N.

        The modulus N is one of the two components of an RSA public key, representing the product
        of two prime numbers used in RSA encryption and signature operations.

        :return: The RSA public key modulus as an integer.
        """
        return self.public_numbers.n

    def export(
        self,
        encoding: SPSDKEncoding = SPSDKEncoding.NXP,
        exp_length: Optional[int] = None,
        modulus_length: Optional[int] = None,
    ) -> bytes:
        """Export the public key to bytes in specified format.

        The method supports both NXP proprietary format (modulus + exponent) and standard DER format.
        For NXP encoding, the output contains modulus followed by exponent in big-endian byte order.

        :param encoding: Encoding format for the exported key, defaults to NXP format.
        :param exp_length: Optional specific exponent length in bytes for NXP format.
        :param modulus_length: Optional specific modulus length in bytes for NXP format.
        :return: Public key exported as bytes in the specified format.
        """
        if encoding == SPSDKEncoding.NXP:
            exp_rotk = self.e
            mod_rotk = self.n
            exp_length = exp_length or math.ceil(exp_rotk.bit_length() / 8)
            modulus_length = modulus_length or math.ceil(mod_rotk.bit_length() / 8)
            exp_rotk_bytes = exp_rotk.to_bytes(exp_length, Endianness.BIG.value)
            mod_rotk_bytes = mod_rotk.to_bytes(modulus_length, Endianness.BIG.value)
            return mod_rotk_bytes + exp_rotk_bytes

        return self.key.public_bytes(
            SPSDKEncoding.get_cryptography_encodings(encoding), PublicFormat.PKCS1
        )

    def verify_signature(
        self,
        signature: bytes,
        data: bytes,
        algorithm: Optional[EnumHashAlgorithm] = None,
        pss_padding: bool = False,
        prehashed: bool = False,
        **kwargs: Any,
    ) -> bool:
        """Verify signature against provided data using RSA cryptographic verification.

        The method supports both PKCS#1 v1.5 and PSS padding schemes, with configurable
        hash algorithms and pre-hashed data verification.

        :param signature: The signature bytes to verify against the data.
        :param data: Input data bytes to verify signature against.
        :param algorithm: Hash algorithm to use for verification, defaults to key's default.
        :param pss_padding: Use RSA-PSS padding scheme instead of PKCS#1 v1.5.
        :param prehashed: Indicates if data is already hashed and ready for verification.
        :param kwargs: Additional unused parameters for compatibility.
        :return: True if signature is valid, False otherwise.
        """
        hash_alg = get_hash_algorithm(algorithm or self.default_hash_algorithm)
        pad = (
            padding.PSS(mgf=padding.MGF1(algorithm=hash_alg), salt_length=padding.PSS.DIGEST_LENGTH)
            if pss_padding
            else padding.PKCS1v15()
        )
        sign_alg = utils.Prehashed(hash_alg) if prehashed else hash_alg
        assert isinstance(sign_alg, (utils.Prehashed, hashes.HashAlgorithm))
        try:
            self.key.verify(
                signature=signature,
                data=data,
                padding=pad,
                algorithm=sign_alg,
            )
        except InvalidSignature:
            return False

        return True

    def __eq__(self, obj: Any) -> bool:
        """Check object equality.

        Compare this object with another object to determine if they are equal.
        Two objects are considered equal if they are instances of the same class
        and have identical public_numbers attributes.

        :param obj: Object to compare with this instance.
        :return: True if objects are equal, False otherwise.
        """
        return isinstance(obj, self.__class__) and self.public_numbers == obj.public_numbers

    def __repr__(self) -> str:
        """Return string representation of the RSA public key.

        Provides a human-readable string format showing the key type and size
        for debugging and logging purposes.

        :return: String representation in format "RSA{key_size} Public Key".
        """
        return f"RSA{self.key_size} Public Key"

    def __str__(self) -> str:
        """Get string representation of RSA public key.

        Returns a formatted string containing the RSA key size, exponent (e), and modulus (n)
        in hexadecimal format.

        :return: String representation showing RSA key size and key components.
        """
        ret = f"RSA{self.key_size} Public key: \ne({hex(self.e)}) \nn({hex(self.n)})"
        return ret

    @classmethod
    def recreate(cls, exponent: int, modulus: int) -> Self:
        """Recreate RSA public key from exponent and modulus.

        :param exponent: Exponent of RSA key.
        :param modulus: Modulus of RSA key.
        :return: RSA public key instance.
        """
        public_numbers = rsa.RSAPublicNumbers(e=exponent, n=modulus)
        return cls(public_numbers.public_key())

    @classmethod
    def recreate_from_data(cls, data: bytes) -> Self:
        """Recreate RSA public key from exponent and modulus in data blob.

        :param data: Data blob containing exponent and modulus in bytes (Big Endian format).
        :return: RSA public key instance.
        """
        return cls(cls.recreate_public_numbers(data).public_key())

    @staticmethod
    def recreate_public_numbers(data: bytes) -> rsa.RSAPublicNumbers:
        """Recreate RSA public numbers from raw key data.

        The method attempts to parse the input data as an RSA public key by trying different
        supported key sizes and extracting the modulus (n) and exponent (e) components.

        :param data: Raw key data containing modulus and exponent in big-endian format.
        :raises SPSDKError: Unrecognized data format or unsupported key size.
        :return: RSA public numbers object containing the extracted key components.
        """
        data_len = len(data)
        for key_size in PrivateKeyRsa.SUPPORTED_KEY_SIZES:
            key_size_bytes = key_size // 8
            if key_size_bytes + 3 <= data_len <= key_size_bytes + 4:
                n = int.from_bytes(data[:key_size_bytes], Endianness.BIG.value)
                e = int.from_bytes(data[key_size_bytes:], Endianness.BIG.value)
                return rsa.RSAPublicNumbers(e=e, n=n)

        raise SPSDKError(f"Unsupported RSA key to recreate with data size {data_len}")

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse RSA public key from bytes array.

        Attempts to parse the data using the parent class method first. If that fails,
        tries to recreate the RSA public key using RSA-specific parsing methods.

        :param data: Raw bytes data containing the RSA public key information.
        :raises SPSDKInvalidKeyType: When the data cannot be parsed as RSA public key.
        :return: Recreated RSA public key instance.
        """
        try:
            key = super().parse(data=data)
            if isinstance(key, PublicKeyRsa):
                return key
        except SPSDKError:
            public_numbers = PublicKeyRsa.recreate_public_numbers(data)
            return PublicKeyRsa(public_numbers.public_key())  # type:ignore

        raise SPSDKInvalidKeyType("Can't parse RSA public key from given data")


# ===================================================================================================
# ===================================================================================================
#
#                                      Elliptic Curves Keys
#
# ===================================================================================================
# ===================================================================================================


class EccCurve(str, Enum):
    """Enumeration of supported elliptic curve cryptographic key types.

    This enumeration defines the elliptic curve types that are supported
    by SPSDK cryptographic operations for ECC key generation and processing.
    """

    SECP256R1 = "secp256r1"
    SECP384R1 = "secp384r1"
    SECP521R1 = "secp521r1"


class SPSDKUnsupportedEccCurve(SPSDKValueError):
    """SPSDK exception for unsupported ECC curve operations.

    This exception is raised when an operation is attempted with an ECC curve
    that is not supported by the SPSDK cryptographic functionality.
    """


class KeyEccCommon:
    """SPSDK Common ECC Key Handler.

    This class provides common functionality for Elliptic Curve Cryptography (ECC) keys,
    supporting both private and public key operations. It offers standardized access to
    key properties, signature operations, and curve management across different ECC
    curve types used in SPSDK cryptographic operations.
    """

    key: Union[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]

    @property
    def default_hash_algorithm(self) -> EnumHashAlgorithm:
        """Get default hash algorithm for signing/verifying operations.

        Determines the appropriate hash algorithm based on the key size of the cryptographic key.
        The mapping follows standard practices: 256-bit keys use SHA256, 384-bit keys use SHA384,
        and 521-bit keys use SHA512.

        :return: Hash algorithm enum value corresponding to the key size.
        :raises KeyError: If the key size is not supported (not 256, 384, or 521 bits).
        """
        return {
            256: EnumHashAlgorithm.SHA256,
            384: EnumHashAlgorithm.SHA384,
            521: EnumHashAlgorithm.SHA512,
        }[self.key.key_size]

    @property
    def coordinate_size(self) -> int:
        """Get the coordinate size in bytes.

        The coordinate size is calculated based on the key size, representing
        the number of bytes needed to store one coordinate of the key.

        :return: Size of coordinate in bytes.
        """
        return math.ceil(self.key.key_size / 8)

    @property
    def signature_size(self) -> int:
        """Get the size of signature data in bytes.

        :return: Size of signature data, calculated as coordinate size multiplied by 2.
        """
        return self.coordinate_size * 2

    @property
    def curve(self) -> EccCurve:
        """Get the elliptic curve type of the key.

        :return: The elliptic curve type used by this key.
        """
        return EccCurve(self.key.curve.name)

    @property
    def key_size(self) -> int:
        """Get the key size in bits.

        :return: Size of the key in bits.
        """
        return self.key.key_size

    @staticmethod
    def _get_ec_curve_object(name: EccCurve) -> ec.EllipticCurve:
        """Get the EC curve object by its name.

        :param name: Name of EC curve.
        :return: EC curve object.
        :raises SPSDKValueError: Invalid EC curve name.
        """
        # pylint: disable=protected-access
        for key_object in ec._CURVE_TYPES:
            if key_object.lower() == name.lower():
                curve_object = ec._CURVE_TYPES[key_object]
                if callable(curve_object):
                    return curve_object()
                return curve_object

        raise SPSDKValueError(f"The EC curve with name '{name}' is not supported.")

    @staticmethod
    def serialize_signature(signature: bytes, coordinate_length: int) -> bytes:
        """Re-format ECC ANS.1 DER signature into the format used by ROM code.

        Converts an ASN.1 DER encoded ECDSA signature into a concatenated format where
        the r and s coordinates are represented as fixed-length byte arrays.

        :param signature: ASN.1 DER encoded ECDSA signature bytes.
        :param coordinate_length: Length in bytes for each coordinate (r and s).
        :return: Concatenated r and s coordinates as fixed-length byte arrays.
        """
        r, s = utils.decode_dss_signature(signature)

        r_bytes = r.to_bytes(coordinate_length, Endianness.BIG.value)
        s_bytes = s.to_bytes(coordinate_length, Endianness.BIG.value)
        return r_bytes + s_bytes


class PrivateKeyEcc(KeyEccCommon, PrivateKey):
    """SPSDK ECC Private Key implementation.

    This class provides elliptic curve cryptography private key operations for SPSDK,
    including key generation, ECDH key exchange, digital signatures, and public key
    derivation. It wraps cryptographic operations for secure provisioning workflows.
    """

    key: ec.EllipticCurvePrivateKey

    def __init__(self, key: ec.EllipticCurvePrivateKey) -> None:
        """Create SPSDK ECC Private Key.

        Initialize an SPSDK ECC private key wrapper with the provided cryptographic key.

        :param key: ECC private key object from cryptography library.
        :raises TypeError: If the provided key is not an ECC private key.
        """
        self.key = key

    @classmethod
    def generate_key(cls, curve_name: EccCurve = EccCurve.SECP256R1) -> Self:
        """Generate SPSDK Key (private key).

        Creates a new private key using the specified elliptic curve for cryptographic operations.

        :param curve_name: Name of the elliptic curve to use for key generation, defaults to SECP256R1
        :return: SPSDK private key instance
        """
        curve_obj = cls._get_ec_curve_object(curve_name)
        prv = ec.generate_private_key(curve_obj)
        return cls(prv)

    def exchange(self, peer_public_key: "PublicKeyEcc") -> bytes:
        """Exchange key using ECDH algorithm with provided peer public key.

        :param peer_public_key: Peer public key for ECDH key exchange.
        :return: Shared secret key as bytes.
        """
        return self.key.exchange(algorithm=ec.ECDH(), peer_public_key=peer_public_key.key)

    def get_public_key(self) -> "PublicKeyEcc":
        """Get public key from private key.

        Extracts the corresponding public key from this private key instance.

        :return: Public key derived from this private key.
        """
        return PublicKeyEcc(self.key.public_key())

    def verify_public_key(self, public_key: PublicKey) -> bool:
        """Verify that the given public key matches this private key.

        This method compares the provided public key with the public key derived
        from this private key to determine if they form a valid key pair.

        :param public_key: Public key to verify against this private key
        :return: True if the keys form a valid pair, False otherwise
        """
        return self.get_public_key() == public_key

    def export(
        self,
        password: Optional[str] = None,
        encoding: SPSDKEncoding = SPSDKEncoding.DER,
    ) -> bytes:
        """Export the Private key to the bytes in requested format.

        The method supports multiple encoding formats including DER, PEM, and NXP-specific format.
        For NXP encoding, only the raw private scalar 'd' is exported.

        :param password: Password to encrypt the private key; None to store without password.
        :param encoding: Encoding type for the exported key, default is DER.
        :return: Private key in bytes format.
        """
        if encoding == SPSDKEncoding.NXP:
            # Export raw private scalar 'd' only in NXP format
            return self.d.to_bytes(self.coordinate_size, Endianness.BIG.value)

        return self.key.private_bytes(
            encoding=SPSDKEncoding.get_cryptography_encodings(encoding),
            format=PrivateFormat.PKCS8,
            encryption_algorithm=(
                BestAvailableEncryption(password.encode("utf-8")) if password else NoEncryption()
            ),
        )

    def sign(
        self,
        data: bytes,
        algorithm: Optional[EnumHashAlgorithm] = None,
        der_format: bool = False,
        prehashed: bool = False,
        **kwargs: Any,
    ) -> bytes:
        """Sign input data with the private key using ECDSA algorithm.

        The method supports both raw data and pre-hashed input data signing.
        Output format can be either DER or serialized signature format.

        :param data: Input data to be signed or pre-hashed value if prehashed is True.
        :param algorithm: Hash algorithm to use for signing, defaults to key's default algorithm.
        :param der_format: If True, return signature in DER format, otherwise use serialized format.
        :param prehashed: If True, treat input data as already hashed value.
        :param kwargs: Additional unused arguments for compatibility.
        :return: Digital signature as bytes in specified format.
        """
        hash_name = algorithm or self.default_hash_algorithm
        if prehashed:
            signature_algorithm = ec.ECDSA(utils.Prehashed(get_hash_algorithm(hash_name)))
        else:
            signature_algorithm = ec.ECDSA(get_hash_algorithm(hash_name))
        signature = self.key.sign(data, signature_algorithm)

        if der_format:
            return signature

        return self.serialize_signature(signature, self.coordinate_size)

    @property
    def d(self) -> int:
        """Get the private number D from the RSA key.

        :return: The private value D component of the RSA private key.
        """
        return self.key.private_numbers().private_value

    @classmethod
    def parse(cls, data: bytes, password: Optional[str] = None) -> Self:
        """Parse ECC private key object from bytes array.

        The method parses the provided byte data to recreate an ECC private key object.
        It validates that the parsed key is specifically an ECC private key type.

        :param data: Raw byte data containing the key information to be parsed.
        :param password: Optional password for encrypted private key; None for unencrypted keys.
        :raises SPSDKInvalidKeyType: When the data cannot be parsed as an ECC private key.
        :return: Recreated ECC private key object.
        """
        key = super().parse(data=data, password=password)
        if isinstance(key, PrivateKeyEcc):
            return key

        raise SPSDKInvalidKeyType("Can't parse Ecc private key from given data")

    @classmethod
    def recreate(cls, d: int, curve: EccCurve) -> Self:
        """Recreate ECC private key from private key number.

        :param d: Private number D.
        :param curve: ECC curve.
        :return: ECC private key.
        """
        key = ec.derive_private_key(d, cls._get_ec_curve_object(curve))
        return cls(key)

    def __repr__(self) -> str:
        """Return string representation of the ECC private key.

        :return: String representation showing the curve type and key type.
        """
        return f"ECC {self.curve} Private Key"

    def __str__(self) -> str:
        """Get string representation of the ECC private key.

        Returns a formatted string containing the curve type and private key value
        in hexadecimal format.

        :return: String representation showing curve and private key value.
        """
        return f"ECC ({self.curve}) Private key: \nd({hex(self.d)})"


class PublicKeyEcc(KeyEccCommon, PublicKey):
    """SPSDK ECC Public Key implementation.

    This class provides functionality for handling Elliptic Curve Cryptography (ECC) public keys
    within the SPSDK framework. It supports key export in various formats, signature verification,
    and coordinate extraction for cryptographic operations across NXP MCU portfolio.
    """

    key: ec.EllipticCurvePublicKey

    def __init__(self, key: ec.EllipticCurvePublicKey) -> None:
        """Create SPSDK Public Key.

        :param key: Elliptic curve public key instance.
        :raises SPSDKError: Invalid key provided.
        """
        self.key = key

    def export(self, encoding: SPSDKEncoding = SPSDKEncoding.NXP) -> bytes:
        """Export the public key to bytes in requested format.

        The method supports NXP encoding (concatenated x and y coordinates) and standard
        cryptographic encodings through the cryptography library.

        :param encoding: Encoding type for the exported key, defaults to SPSDKEncoding.NXP
        :return: Public key exported as bytes in the specified format
        """
        if encoding == SPSDKEncoding.NXP:
            x_bytes = self.x.to_bytes(self.coordinate_size, Endianness.BIG.value)
            y_bytes = self.y.to_bytes(self.coordinate_size, Endianness.BIG.value)
            return x_bytes + y_bytes

        return self.key.public_bytes(
            SPSDKEncoding.get_cryptography_encodings(encoding),
            PublicFormat.SubjectPublicKeyInfo,
        )

    def verify_signature(
        self,
        signature: bytes,
        data: bytes,
        algorithm: Optional[EnumHashAlgorithm] = None,
        prehashed: bool = False,
        **kwargs: Any,
    ) -> bool:
        """Verify signature against input data using ECDSA algorithm.

        The method supports both raw signature format (r||s coordinates) and DER-encoded
        signatures. It automatically converts raw signatures to DER format for verification.

        :param signature: The signature bytes to verify against the data.
        :param data: Input data that was signed.
        :param algorithm: Hash algorithm to use for verification. If None, uses default.
        :param prehashed: Whether the input data is already hashed.
        :param kwargs: Additional unused arguments for compatibility.
        :return: True if signature is valid, False otherwise.
        """
        coordinate_size = math.ceil(self.key.key_size / 8)
        hash_name = algorithm or self.default_hash_algorithm

        if prehashed:
            signature_algorithm = ec.ECDSA(utils.Prehashed(get_hash_algorithm(hash_name)))
        else:
            signature_algorithm = ec.ECDSA(get_hash_algorithm(hash_name))

        if len(signature) == self.signature_size:
            der_signature = utils.encode_dss_signature(
                int.from_bytes(signature[:coordinate_size], byteorder=Endianness.BIG.value),
                int.from_bytes(signature[coordinate_size:], byteorder=Endianness.BIG.value),
            )
        else:
            der_signature = signature
        try:
            # pylint: disable=no-value-for-parameter    # pylint is mixing RSA and ECC verify methods
            self.key.verify(der_signature, data, signature_algorithm)
            return True
        except InvalidSignature:
            return False

    @property
    def public_numbers(self) -> ec.EllipticCurvePublicNumbers:
        """Get public numbers of the elliptic curve key.

        :return: Public numbers containing the x and y coordinates of the public key point.
        """
        return self.key.public_numbers()

    @property
    def x(self) -> int:
        """Get the X coordinate of the public key point.

        :return: X coordinate value of the elliptic curve public key point.
        """
        return self.public_numbers.x

    @property
    def y(self) -> int:
        """Get the Y coordinate of the public key point.

        :return: Y coordinate value of the elliptic curve public key point.
        """
        return self.public_numbers.y

    @classmethod
    def recreate(cls, coor_x: int, coor_y: int, curve: EccCurve) -> Self:
        """Recreate ECC public key from coordinates.

        :param coor_x: X coordinate of point on curve.
        :param coor_y: Y coordinate of point on curve.
        :param curve: ECC curve.
        :raises SPSDKValueError: Invalid coordinates or curve parameters.
        :return: ECC public key.
        """
        try:
            pub_numbers = ec.EllipticCurvePublicNumbers(
                x=coor_x, y=coor_y, curve=PrivateKeyEcc._get_ec_curve_object(curve)
            )
            key = pub_numbers.public_key()
        except ValueError as exc:
            raise SPSDKValueError(f"Cannot recreate the public key: {str(exc)}") from exc
        return cls(key)

    @classmethod
    def recreate_from_data(cls, data: bytes, curve: Optional[EccCurve] = None) -> Self:
        """Recreate ECC public key from coordinates in data blob.

        The method supports both raw binary format (X,Y coordinates in Big Endian) and DER format.
        If curve is not specified, the method will attempt to determine it from data length.

        :param data: Data blob of coordinates in bytes (X,Y in Big Endian) or DER format.
        :param curve: ECC curve, if None the curve will be auto-detected from data length.
        :raises SPSDKUnsupportedEccCurve: When curve cannot be determined from data length.
        :return: ECC public key instance.
        """

        def get_curve(data_length: int, curve: Optional[EccCurve] = None) -> tuple[EccCurve, bool]:
            """Determine ECC curve and encoding format from signature data length.

            Analyzes the provided data length to identify the matching ECC curve and whether
            the data uses DER encoding format. If a specific curve is provided, only that
            curve is checked; otherwise, all available curves are tested.

            :param data_length: Length of the signature data in bytes.
            :param curve: Optional specific ECC curve to check, defaults to None.
            :return: Tuple containing the matching ECC curve and boolean indicating if DER
                encoded (True for DER, False for raw binary).
            :raises SPSDKUnsupportedEccCurve: When no curve matches the provided data length.
            """
            curve_list = [curve] if curve else list(EccCurve)
            for cur in curve_list:
                curve_obj = KeyEccCommon._get_ec_curve_object(EccCurve(cur))
                curve_sign_size = math.ceil(curve_obj.key_size / 8) * 2
                # Check raw binary format
                if curve_sign_size == data_length:
                    return (cur, False)
                # Check DER binary format
                curve_sign_size += 7
                if curve_sign_size <= data_length <= curve_sign_size + 2:
                    return (cur, True)
            raise SPSDKUnsupportedEccCurve(f"Cannot recreate ECC curve with {data_length} length")

        data_length = len(data)
        (curve, der_format) = get_curve(data_length, curve)

        if der_format:
            der = _load_der_public_key(data)
            assert isinstance(der, ec.EllipticCurvePublicKey)
            return cls(der)

        coordinate_length = data_length // 2
        coor_x = int.from_bytes(data[:coordinate_length], byteorder=Endianness.BIG.value)
        coor_y = int.from_bytes(data[coordinate_length:], byteorder=Endianness.BIG.value)
        return cls.recreate(coor_x=coor_x, coor_y=coor_y, curve=curve)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse ECC public key object from bytes array.

        Attempts to parse the data using the parent class method first. If that fails
        or doesn't return a PublicKeyEcc instance, falls back to recreating the key
        from the raw data.

        :param data: Raw bytes data containing the ECC public key information.
        :raises SPSDKInvalidKeyType: When the data cannot be parsed as an ECC public key.
        :return: Recreated ECC public key object.
        """
        try:
            key = super().parse(data=data)
            if isinstance(key, PublicKeyEcc):
                return key
        except SPSDKError:
            return cls.recreate_from_data(data=data)

        raise SPSDKInvalidKeyType("Can't parse ECC public key from given data")

    def __repr__(self) -> str:
        """Return string representation of the ECC public key.

        Provides a human-readable string format showing the curve type and key nature.

        :return: String representation in format "ECC {curve} Public Key".
        """
        return f"ECC {self.curve} Public Key"

    def __str__(self) -> str:
        """Get string representation of the ECC public key.

        Returns a formatted string containing the curve type and the x, y coordinates
        of the public key in hexadecimal format.

        :return: String representation with curve type and coordinates.
        """
        return f"ECC ({self.curve}) Public key: \nx({hex(self.x)}) \ny({hex(self.y)})"


# ===================================================================================================
# ===================================================================================================
#
#                                      SM2 Key
#
# ===================================================================================================
# ===================================================================================================
if IS_OSCCA_SUPPORTED:

    class PrivateKeySM2(PrivateKey):
        """SPSDK SM2 Private Key implementation.

        This class provides SM2 elliptic curve private key operations for cryptographic
        functions including key generation, signing, and public key derivation. SM2 is
        a Chinese national standard for elliptic curve cryptography.
        """

        key: sm2.CryptSM2

        def __init__(self, key: sm2.CryptSM2) -> None:
            """Create SPSDK Key with SM2 cryptographic key.

            :param key: SM2 cryptographic key instance to be wrapped by SPSDK Key.
            :raises SPSDKInvalidKeyType: If the provided key is not of SM2 type.
            """
            if not isinstance(key, sm2.CryptSM2):
                raise SPSDKInvalidKeyType("The input key is not SM2 type")
            self.key = key

        @classmethod
        def generate_key(cls) -> Self:
            """Generate SM2 cryptographic key pair.

            Creates a new SM2 private key with corresponding public key using secure random generation.
            The method ensures the generated public key meets SM2 format requirements.

            :return: New SM2 key instance with generated private and public key pair.
            """
            key = sm2.CryptSM2(None, "None")
            n = int(key.ecc_table["n"], base=16)
            prk = rand_below(n)
            while True:
                puk = key._kg(prk, key.ecc_table["g"])
                if puk[:2] != "04":  # PUK cannot start with 04
                    break
            key.private_key = f"{prk:064x}"
            key.public_key = puk

            return cls(key)

        def get_public_key(self) -> "PublicKeySM2":
            """Get public key from private key.

            Extracts the public key component from the SM2 private key and wraps it
            in a PublicKeySM2 object for cryptographic operations.

            :return: Public key object containing the SM2 public key.
            """
            return PublicKeySM2(sm2.CryptSM2(private_key=None, public_key=self.key.public_key))

        def verify_public_key(self, public_key: PublicKey) -> bool:
            """Verify that the given public key corresponds to this private key.

            This method checks if the provided public key forms a valid cryptographic
            key pair with the current private key by comparing it with the derived
            public key.

            :param public_key: Public key to verify against this private key.
            :return: True if the keys form a valid pair, False otherwise.
            """
            return self.get_public_key() == public_key

        def sign(
            self,
            data: bytes,
            salt: Optional[str] = None,
            use_ber: bool = False,
            **kwargs: Any,
        ) -> bytes:
            """Sign data using SM2 algorithm with SM3 hash.

            The method uses SM3 hash function to process the input data and generates
            a digital signature using the SM2 elliptic curve cryptography algorithm.

            :param data: Data to sign.
            :param salt: Salt for signature generation, defaults to None. If not specified a random string will be used.
            :param use_ber: Encode signature into BER format, defaults to False.
            :param kwargs: Sink for unused arguments.
            :raises SPSDKError: Signature can't be created.
            :return: SM2 signature in raw or BER format.
            """
            data_hash = bytes.fromhex(self.key._sm3_z(data))
            if salt is None:
                salt = random_hex(self.key.para_len // 2)
            signature_str = self.key.sign(data=data_hash, K=salt)
            if not signature_str:
                raise SPSDKError("Can't sign data")
            signature = bytes.fromhex(signature_str)
            if use_ber:
                ber_signature = SM2Encoder().encode_signature(signature)
                return ber_signature
            return signature

        def export(
            self,
            password: Optional[str] = None,
            encoding: SPSDKEncoding = SPSDKEncoding.DER,
        ) -> bytes:
            """Export SM2 private key to bytes format supported by NXP.

            The method exports the SM2 private key using DER encoding, which is the only
            supported encoding format for SM2 keys in NXP systems.

            :param password: Password for key encryption (currently not used for SM2 keys).
            :param encoding: Encoding format for the exported key, only DER is supported.
            :raises SPSDKNotImplementedError: When encoding other than DER is requested.
            :return: SM2 private key encoded as bytes in DER format.
            """
            if encoding != SPSDKEncoding.DER:
                raise SPSDKNotImplementedError("Only DER encoding is supported for SM2 keys export")
            keys = SM2PrivateKey(self.key.private_key, self.key.public_key)
            return SM2Encoder().encode_private_key(keys)

        def __repr__(self) -> str:
            """Return string representation of SM2 private key.

            :return: String identifier for SM2 private key object.
            """
            return "SM2 Private Key"

        def __str__(self) -> str:
            """Get string representation of the SM2Key object.

            Returns a formatted string containing the private and public key information
            for debugging and logging purposes.

            :return: String representation showing private and public key details.
            """
            return f"SM2Key(private_key={self.key.private_key}, public_key='{self.key.public_key}')"

        @property
        def key_size(self) -> int:
            """Get the size of the key in bits.

            :return: Size of the key in bits.
            """
            return self.key.para_len

        @property
        def default_hash_algorithm(self) -> EnumHashAlgorithm:
            """Get default hash algorithm for signing and verifying operations.

            Returns the SM3 hash algorithm as the default choice for cryptographic
            operations with this key type.

            :return: SM3 hash algorithm enum value.
            """
            return EnumHashAlgorithm.SM3

        @property
        def signature_size(self) -> int:
            """Get the signature size in bytes.

            :return: Size of the signature in bytes (always 64 for this implementation).
            """
            return 64

        def save(
            self,
            file_path: str,
            password: Optional[str] = None,
            encoding: SPSDKEncoding = SPSDKEncoding.PEM,
        ) -> None:
            """Save the Private key to the given file.

            Saves the private key to a file in DER encoding format regardless of the encoding
            parameter specified.

            :param file_path: Path where the private key file will be saved.
            :param password: Optional password for encrypting the private key file.
            :param encoding: Encoding format (parameter ignored, always saves as DER).
            """
            return super().save(file_path, password, encoding=SPSDKEncoding.DER)

    class PublicKeySM2(PublicKey):
        """SM2 Public Key implementation for SPSDK cryptographic operations.

        This class provides SM2 elliptic curve public key functionality including signature
        verification and key export operations. SM2 is a Chinese national standard for
        elliptic curve cryptography.

        :cvar RECOMMENDED_ENCODING: Default encoding format for SM2 key export operations.
        """

        RECOMMENDED_ENCODING = SPSDKEncoding.DER
        key: sm2.CryptSM2

        def __init__(self, key: sm2.CryptSM2) -> None:
            """Create SPSDK Public Key from SM2 cryptographic key.

            :param key: SM2 cryptographic key instance to wrap.
            :raises SPSDKInvalidKeyType: If the provided key is not an SM2 type.
            """
            if not isinstance(key, sm2.CryptSM2):
                raise SPSDKInvalidKeyType("The input key is not SM2 type")
            self.key = key

        def verify_signature(
            self,
            signature: bytes,
            data: bytes,
            algorithm: Optional[EnumHashAlgorithm] = None,
            **kwargs: Any,
        ) -> bool:
            """Verify SM2 signature against provided data.

            The method supports both BER-formatted signatures (starting with 0x30) and raw format
            signatures (r || s concatenated). The data is hashed using SM3 algorithm before
            verification.

            :param signature: SM2 signature to verify in BER or raw format.
            :param data: Original data that was signed.
            :param algorithm: Hash algorithm parameter for compatibility with abstract class.
            :param kwargs: Additional unused arguments.
            :raises SPSDKError: Invalid signature format or verification failure.
            :return: True if signature is valid, False otherwise.
            """
            # Check if the signature is BER formatted
            if len(signature) > 64 and signature[0] == 0x30:
                signature = SM2Encoder().decode_signature(signature)
            # Otherwise the signature is in raw format r || s
            data_hash = bytes.fromhex(self.key._sm3_z(data))
            return self.key.verify(Sign=signature.hex(), data=data_hash)

        def export(self, encoding: SPSDKEncoding = SPSDKEncoding.DER) -> bytes:
            """Convert key into bytes supported by NXP.

            Exports the SM2 key in the specified encoding format. Currently only DER encoding
            is supported for SM2 keys.

            :param encoding: The encoding format to use for export.
            :raises SPSDKNotImplementedError: If encoding other than DER is requested.
            :return: Byte representation of the SM2 public key in DER format.
            """
            if encoding != SPSDKEncoding.DER:
                raise SPSDKNotImplementedError("Only DER encoding is supported for SM2 keys export")
            keys = SM2PublicKey(self.key.public_key)
            return SM2Encoder().encode_public_key(keys)

        @property
        def default_hash_algorithm(self) -> EnumHashAlgorithm:
            """Get default hash algorithm for signing and verifying operations.

            Returns the SM3 hash algorithm as the default choice for cryptographic
            operations with this key type.

            :return: SM3 hash algorithm enum value.
            """
            return EnumHashAlgorithm.SM3

        @property
        def signature_size(self) -> int:
            """Get the signature size in bytes.

            :return: Size of the signature in bytes (always 64 for this implementation).
            """
            return 64

        @property
        def public_numbers(self) -> str:
            """Get the public numbers of the cryptographic key.

            :return: Public numbers representation of the key.
            """
            return self.key.public_key

        @classmethod
        def recreate(cls, data: bytes) -> Self:
            """Recreate SM2 public key from data.

            :param data: Raw bytes containing the SM2 public key data to be reconstructed.
            :return: New SPSDK SM2 public key instance created from the provided data.
            """
            return cls(sm2.CryptSM2(private_key=None, public_key=data.hex()))

        @classmethod
        def recreate_from_data(cls, data: bytes) -> Self:
            """Recreate SM2 public key from data.

            The method creates a new SM2 public key instance from PEM or DER encoded key data.
            It sanitizes the input data and decodes it using SM2Encoder.

            :param data: PEM or DER encoded key data as bytes.
            :return: New SM2 public key instance.
            """
            key_data = sanitize_pem(data)
            public_key = SM2Encoder().decode_public_key(data=key_data)
            return cls(sm2.CryptSM2(private_key=None, public_key=public_key.public))

        def __repr__(self) -> str:
            """Return string representation of SM2 public key.

            :return: String identifier for SM2 public key object.
            """
            return "SM2 Public Key"

        def __str__(self) -> str:
            """Get string representation of SM2 public key.

            :return: String representation containing the public key numbers.
            """
            ret = f"SM2 Public Key <{self.public_numbers}>"
            return ret

        def save(self, file_path: str, encoding: SPSDKEncoding = SPSDKEncoding.PEM) -> None:
            """Save the Private key to the given file.

            :param file_path: Path to the file where the private key will be saved.
            :param encoding: Encoding format for the key (defaults to PEM, but saves as DER).
            """
            return super().save(file_path, encoding=SPSDKEncoding.DER)

else:
    # In case the OSCCA is not installed, do this to avoid import errors
    PrivateKeySM2 = NonSupportingPrivateKey  # type: ignore
    PublicKeySM2 = NonSupportingPublicKey  # type: ignore


class ECDSASignature:
    """ECDSA Signature representation and manipulation.

    This class provides functionality for handling ECDSA signatures including parsing
    from different formats (DER, NXP), exporting to various encodings, and managing
    signature components (r, s values) along with their associated ECC curve parameters.

    :cvar COORDINATE_LENGTHS: Mapping of ECC curves to their coordinate byte lengths.
    """

    COORDINATE_LENGTHS = {EccCurve.SECP256R1: 32, EccCurve.SECP384R1: 48, EccCurve.SECP521R1: 66}

    def __init__(self, r: int, s: int, ecc_curve: EccCurve) -> None:
        """Initialize ECDSA signature with r and s values.

        Creates an ECDSA signature object containing the mathematical components
        of the signature along with the associated elliptic curve parameters.

        :param r: The r component of the ECDSA signature (x-coordinate of random point).
        :param s: The s component of the ECDSA signature (calculated signature value).
        :param ecc_curve: The elliptic curve used for the signature generation.
        """
        self.r = r
        self.s = s
        self.ecc_curve = ecc_curve

    @classmethod
    def parse(cls, signature: bytes) -> Self:
        """Parse signature in DER or NXP format.

        The method automatically detects the encoding format and creates an instance with the parsed
        signature components (r, s) and the appropriate ECC curve.

        :param signature: Binary signature data in either DER or NXP format.
        :raises SPSDKValueError: Invalid signature encoding format.
        :return: New instance with parsed signature components.
        """
        encoding = cls.get_encoding(signature)
        if encoding == SPSDKEncoding.DER:
            r, s = utils.decode_dss_signature(signature)
            ecc_curve = cls.get_ecc_curve(len(signature))
            return cls(r, s, ecc_curve)
        if encoding == SPSDKEncoding.NXP:
            r = int.from_bytes(signature[: len(signature) // 2], Endianness.BIG.value)
            s = int.from_bytes(signature[len(signature) // 2 :], Endianness.BIG.value)
            ecc_curve = cls.get_ecc_curve(len(signature))
            return cls(r, s, ecc_curve)
        raise SPSDKValueError(f"Invalid signature encoding {encoding.value}")

    def export(self, encoding: SPSDKEncoding = SPSDKEncoding.NXP) -> bytes:
        """Export signature in DER or NXP format.

        The method converts the signature's r and s coordinates into the specified encoding format.
        For NXP encoding, it concatenates the r and s values as big-endian bytes. For DER encoding,
        it uses the standard ASN.1 DER format for DSS signatures.

        :param encoding: Signature encoding format (NXP or DER).
        :raises SPSDKValueError: Invalid signature encoding format.
        :return: Signature as bytes in the specified encoding format.
        """
        if encoding == SPSDKEncoding.NXP:
            r_bytes = self.r.to_bytes(self.COORDINATE_LENGTHS[self.ecc_curve], Endianness.BIG.value)
            s_bytes = self.s.to_bytes(self.COORDINATE_LENGTHS[self.ecc_curve], Endianness.BIG.value)
            return r_bytes + s_bytes
        if encoding == SPSDKEncoding.DER:
            return utils.encode_dss_signature(self.r, self.s)
        raise SPSDKValueError(f"Invalid signature encoding {encoding.value}")

    @classmethod
    def get_encoding(cls, signature: bytes) -> SPSDKEncoding:
        """Get encoding of signature.

        Detects the encoding format of a given signature by analyzing its length and structure.
        The method first checks for NXP format based on signature length, then attempts to
        decode as DER format.

        :param signature: The signature bytes to analyze for encoding detection.
        :raises SPSDKValueError: When signature doesn't match any supported encoding format.
        :return: The detected encoding format (NXP or DER).
        """
        signature_length = len(signature)
        # Try detect the NXP format by data length
        if signature_length // 2 in cls.COORDINATE_LENGTHS.values():
            return SPSDKEncoding.NXP
        # Try detect the DER format by decode of header
        try:
            utils.decode_dss_signature(signature)
            return SPSDKEncoding.DER
        except ValueError:
            pass
        raise SPSDKValueError(
            f"The given signature with length {signature_length} does not match any encoding"
        )

    @classmethod
    def get_ecc_curve(cls, signature_length: int) -> EccCurve:
        """Get the Elliptic Curve based on signature length.

        The method determines the appropriate ECC curve by matching the signature length
        against known coordinate lengths. It supports both exact matches and ranges
        for DER-encoded signatures.

        :param signature_length: Length of the signature in bytes
        :return: The corresponding ECC curve
        :raises SPSDKValueError: If signature length doesn't match any known ECC curve
        """
        for curve, coord_len in cls.COORDINATE_LENGTHS.items():
            if signature_length == coord_len * 2:
                return curve
            if signature_length in range(coord_len * 2 + 3, coord_len * 2 + 9):
                return curve
        raise SPSDKValueError(
            f"The given signature with length {signature_length} does not match any ecc curve"
        )


if IS_DILITHIUM_SUPPORTED:
    # ===================================================================================================
    # ===================================================================================================
    #
    #                                      Dilithium Key
    #
    # ===================================================================================================
    # ===================================================================================================
    class PQCKey:
        """Post-Quantum Cryptography key wrapper for SPSDK operations.

        This class provides a unified interface for working with post-quantum cryptographic keys,
        supporting both Dilithium and ML-DSA key types. It handles key operations including
        signature verification and provides access to key properties and metadata.

        :cvar SUPPORTED_LEVELS: List of supported security levels for PQC algorithms.
        :cvar RECOMMENDED_ENCODING: Preferred encoding format for key serialization.
        """

        SUPPORTED_LEVELS = [2, 3, 5]
        RECOMMENDED_ENCODING = SPSDKEncoding.PEM
        key: Union[DilithiumPrivateKey, DilithiumPublicKey, MLDSAPublicKey, MLDSAPublicKey]

        def __init__(
            self,
            key: Union[DilithiumPrivateKey, DilithiumPublicKey, MLDSAPublicKey, MLDSAPublicKey],
        ):
            """Initialize PQC key.

            :param key: The post-quantum cryptography key object to initialize with.
            :raises TypeError: If the provided key is not a supported PQC key type.
            """
            self.key = key

        @property
        def default_hash_algorithm(self) -> EnumHashAlgorithm:
            """Get default hash algorithm for signing and verifying operations.

            :return: Default hash algorithm enumeration value (SHA384).
            """
            return EnumHashAlgorithm.SHA384

        @property
        def signature_size(self) -> int:
            """Get the size of signature data in bytes.

            :return: Size of the signature in bytes.
            """
            return self.key.signature_size

        @property
        def public_numbers(self) -> bytes:
            """Get public numbers of the cryptographic key.

            Returns the public data portion of the key as raw bytes, which contains
            the public key material that can be shared openly.

            :return: Raw bytes containing the public key data.
            """
            return self.key.public_data

        @property
        def key_size(self) -> int:
            """Get the key size in bytes.

            :return: Size of the key in bytes.
            """
            return self.key.key_size

        @property
        def level(self) -> int:
            """Get Key level.

            :return: The level of the key.
            """
            return self.key.level

        def __str__(self) -> str:
            """Return string representation of the object.

            This method provides a string representation by delegating to the repr() method,
            ensuring consistent string formatting across different contexts.

            :return: String representation of the object.
            """
            return repr(self)

        def verify_signature(
            self,
            signature: bytes,
            data: bytes,
            algorithm: Optional[EnumHashAlgorithm] = None,
            prehashed: bool = False,
            **kwargs: Any,
        ) -> bool:
            """Verify signature against input data using the public key.

            The method supports both raw data and pre-hashed data verification. When prehashed
            is False, the data will be hashed using the specified or default algorithm before
            verification.

            :param signature: The signature bytes to verify against the data.
            :param data: Input data to verify or pre-hashed data if prehashed is True.
            :param algorithm: Hash algorithm to use, defaults to key's default algorithm.
            :param prehashed: Whether the input data is already hashed.
            :param kwargs: Additional keyword arguments for specific key types.
            :return: True if signature is valid, False otherwise.
            """
            if prehashed:
                data_to_sign = data
            else:
                data_to_sign = get_hash(data, algorithm or self.default_hash_algorithm)
            return self.key.verify(data=data_to_sign, signature=signature)

    class PQCPublicKey(PQCKey, PublicKey):
        """Post-Quantum Cryptography public key wrapper.

        This class provides a unified interface for handling PQC public keys,
        supporting both Dilithium and ML-DSA algorithms. It manages key export
        operations and provides comparison functionality for PQC public keys.
        """

        key: Union[DilithiumPublicKey, MLDSAPublicKey]

        def export(self, encoding: SPSDKEncoding = SPSDKEncoding.NXP) -> bytes:
            """Export key into bytes to requested format.

            The method supports multiple encoding formats including NXP proprietary format and PEM format.

            :param encoding: Encoding type for key export, defaults to SPSDKEncoding.NXP.
            :return: Byte representation of the exported key.
            """
            if encoding == SPSDKEncoding.NXP:
                return self.key.public_data
            return self.key.export(pem=encoding == SPSDKEncoding.PEM)

        def __repr__(self) -> str:
            """Return string representation of the public key.

            :return: String containing the algorithm type and key designation.
            """
            return f"{self.key.algorithm.value} Public key"

        def __eq__(self, obj: Any) -> bool:
            """Check equality between PQC public keys.

            Compares two PQC public keys by their public data content. Since Dilithium and MLDSA
            public keys cannot be distinguished by type, the comparison is based on the actual
            public key data rather than the specific key type.

            :param obj: Object to compare with this PQC public key.
            :return: True if both objects are PQC public keys with identical public data,
                     False otherwise.
            """
            # since we can't distinguish between Dilithium and MLDSA public keys
            # we compare the public data directly and don't care about the specific type
            # this shall be rectified soon to avoid problems in the future
            if not isinstance(obj, PQCPublicKey):
                return False
            return self.key.public_data == obj.key.public_data

    class PQCPrivateKey(PQCKey, PrivateKey):
        """SPSDK Post-Quantum Cryptography private key wrapper.

        This class provides a unified interface for PQC private key operations including
        digital signing and key export functionality. It wraps underlying PQC private key
        implementations (Dilithium, ML-DSA) and provides standardized methods for
        cryptographic operations across different PQC algorithms.
        """

        key: Union[DilithiumPrivateKey, MLDSAPrivateKey]

        def sign(
            self,
            data: bytes,
            algorithm: Optional[EnumHashAlgorithm] = None,
            prehashed: bool = False,
            **kwargs: Any,
        ) -> bytes:
            """Sign input data with the private key.

            The method supports both raw data signing and pre-hashed data signing based on the
            prehashed parameter. When prehashed is False, the data is hashed using the specified
            or default algorithm before signing.

            :param data: Input data to be signed or pre-hashed data if prehashed is True.
            :param algorithm: Hash algorithm to use for data hashing, uses default if None.
            :param prehashed: If True, treats input data as already hashed.
            :param kwargs: Additional keyword arguments for specific key implementations.
            :return: Digital signature as bytes.
            """
            if prehashed:
                data_to_sign = data
            else:
                data_to_sign = get_hash(data, algorithm or self.default_hash_algorithm)
            return self.key.sign(data=data_to_sign)

        def export(
            self, password: Optional[str] = None, encoding: SPSDKEncoding = SPSDKEncoding.DER
        ) -> bytes:
            """Export key into bytes to requested format.

            :param password: Password to private key; None to store without password.
            :param encoding: Encoding type, defaults to DER.
            :return: Byte representation of key.
            """
            if encoding == SPSDKEncoding.NXP:
                return self.key.private_data + (self.key.public_data or bytes())
            return self.key.export(pem=encoding == SPSDKEncoding.PEM)

        def __repr__(self) -> str:
            """Return string representation of the private key.

            :return: String describing the algorithm type and key nature.
            """
            return f"{self.key.algorithm.value} Private key"

        def __eq__(self, obj: Any) -> bool:
            """Check equality of two private key objects.

            Compares this private key instance with another object by checking if the other
            object is of the same class and has identical private key data.

            :param obj: Object to compare with this private key instance.
            :return: True if objects are equal private keys, False otherwise.
            """
            return isinstance(obj, self.__class__) and self.key.private_data == obj.key.private_data

    class PublicKeyDilithium(PQCPublicKey):
        """Dilithium Public Key implementation for post-quantum cryptography.

        This class provides a wrapper for Dilithium public keys, enabling parsing
        and handling of Dilithium public key data within the SPSDK framework.
        Dilithium is a post-quantum digital signature algorithm designed to be
        secure against quantum computer attacks.
        """

        key: DilithiumPublicKey

        @classmethod
        def parse(cls, data: bytes) -> Self:
            """Parse Dilithium public key object from bytes array.

            :param data: Raw bytes data containing the Dilithium public key to be parsed.
            :raises SPSDKInvalidKeyType: Invalid or corrupted Dilithium public key data.
            :return: Recreated Dilithium public key object.
            """
            try:
                return cls(DilithiumPublicKey.parse(data=data))
            except PQCError as e:
                raise SPSDKInvalidKeyType(f"Can't parse Dilithium Public from data: {e}") from e

    class PrivateKeyDilithium(PQCPrivateKey):
        """SPSDK Dilithium private key implementation for post-quantum cryptography.

        This class provides a wrapper around Dilithium private keys, enabling generation,
        parsing, and cryptographic operations with post-quantum security.
        """

        key: DilithiumPrivateKey

        @classmethod
        def generate_key(
            cls, level: Optional[int] = None, algorithm: Optional[PQCAlgorithm] = None
        ) -> Self:
            """Generate SPSDK Key (private key).

            One of 'level' or 'algorithm' must be specified.

            :param level: NIST claim level, defaults to None
            :param algorithm: Exact PQC algorithm to use, defaults to None
            :raises SPSDKError: Could not create Dilithium key
            :return: Dilithium Private key
            """
            try:
                return cls(DilithiumPrivateKey(level=level, algorithm=algorithm))
            except PQCError as e:
                raise SPSDKError(f"Could not create Dilithium key: {e}") from e

        def get_public_key(self) -> PublicKeyDilithium:
            """Get the public key from the Dilithium private key.

            Extracts and returns the public key portion from this Dilithium private key instance.

            :raises SPSDKUnsupportedOperation: When the Dilithium key doesn't have public portion.
            :return: Public key instance containing the Dilithium public key data.
            """
            if self.key.public_data is None:
                raise SPSDKUnsupportedOperation("Dilithium key doesn't have public portion")
            return PublicKeyDilithium(DilithiumPublicKey(public_data=self.key.public_data))

        def verify_public_key(self, public_key: PublicKey) -> bool:
            """Verify that the provided public key matches this key's public key.

            This method checks if the given public key is of the correct Dilithium type and
            compares the public key data to determine if they are identical.

            :param public_key: The public key to verify against this key.
            :raises SPSDKInvalidKeyType: If the public key is not a Dilithium public key.
            :return: True if the public keys match, False otherwise.
            """
            if not isinstance(public_key, PublicKeyDilithium):
                raise SPSDKInvalidKeyType("Public key type is not a Dilithium public key")
            return self.key.public_data == public_key.key.public_data

        @classmethod
        def parse(cls, data: bytes, password: Optional[str] = None) -> Self:
            """Parse object from bytes array.

            :param data: Data to be parsed.
            :param password: Password in case of encrypted key.
            :raises SPSDKError: Could not parse key.
            :return: Recreated key.
            """
            try:
                return cls(DilithiumPrivateKey.parse(data=data))
            except PQCError as e:
                raise SPSDKError(f"Could not parse key: {e}") from e

    class PublicKeyMLDSA(PQCPublicKey):
        """ML-DSA (Module-Lattice-Based Digital Signature Algorithm) public key implementation.

        This class provides a wrapper for ML-DSA public keys, offering parsing capabilities
        and integration with the SPSDK cryptographic framework. ML-DSA is a post-quantum
        cryptographic signature algorithm designed to be secure against quantum attacks.
        """

        key: MLDSAPublicKey

        @classmethod
        def parse(cls, data: bytes) -> Self:
            """Parse MLDSA public key object from bytes array.

            :param data: Raw bytes data containing the MLDSA public key to be parsed.
            :raises SPSDKError: If the key data cannot be parsed or is invalid.
            :return: Recreated MLDSA public key instance.
            """
            try:
                return cls(MLDSAPublicKey.parse(data=data))
            except PQCError as e:
                raise SPSDKError(f"Could not parse key: {e}") from e

    class PrivateKeyMLDSA(PQCPrivateKey):
        """ML-DSA Private Key for post-quantum cryptographic operations.

        This class provides a wrapper around ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
        private keys, enabling key generation, public key derivation, verification, and serialization
        operations within the SPSDK framework.
        """

        key: MLDSAPrivateKey

        @classmethod
        def generate_key(
            cls, level: Optional[int] = None, algorithm: Optional[PQCAlgorithm] = None
        ) -> Self:
            """Generate SPSDK Key (private key).

            One of 'level' or 'algorithm' must be specified.

            :param level: NIST claim level, defaults to None
            :param algorithm: Exact PQC algorithm to use, defaults to None
            :raises SPSDKError: Could not create Dilithium key
            :return: ML-DSA Private key
            """
            try:
                key = MLDSAPrivateKey(level=level, algorithm=algorithm)
            except PQCError as e:
                raise SPSDKError(f"Could not create Dilithium key: {e}") from e
            return cls(key)

        def get_public_key(self) -> PublicKeyMLDSA:
            """Get the public key from the Dilithium private key.

            Extracts and returns the public key portion of the ML-DSA (Dilithium) key pair.

            :raises SPSDKUnsupportedOperation: When the Dilithium key doesn't have a public portion.
            :return: The public key as PublicKeyMLDSA instance.
            """
            if self.key.public_data is None:
                raise SPSDKUnsupportedOperation("Dilithium key doesn't have public portion")
            return PublicKeyMLDSA(MLDSAPublicKey(public_data=self.key.public_data))

        def verify_public_key(self, public_key: PublicKey) -> bool:
            """Verify that the provided public key matches this private key.

            The method checks if the public key is of the correct type (Dilithium/ML-DSA) and
            compares the public data to ensure it corresponds to this private key.

            :param public_key: The public key to verify against this private key.
            :raises SPSDKInvalidKeyType: If the public key is not a Dilithium public key.
            :return: True if the public key matches this private key, False otherwise.
            """
            if not isinstance(public_key, PublicKeyMLDSA):
                raise SPSDKInvalidKeyType("Public key type is not a Dilithium public key")
            return self.key.public_data == public_key.key.public_data

        @classmethod
        def parse(cls, data: bytes, password: Optional[str] = None) -> Self:
            """Parse MLDSA private key object from bytes array.

            :param data: Raw bytes data containing the MLDSA private key to be parsed.
            :param password: Optional password for encrypted key decryption.
            :raises SPSDKError: When the key parsing fails or data is invalid.
            :return: Recreated MLDSA private key object.
            """
            try:
                return cls(MLDSAPrivateKey.parse(data=data))
            except PQCError as e:
                raise SPSDKError(f"Could not parse key: {e}") from e

else:
    PrivateKeyDilithium = NonSupportingPrivateKey  # type: ignore
    PublicKeyDilithium = NonSupportingPublicKey  # type: ignore
    PrivateKeyMLDSA = NonSupportingPrivateKey  # type: ignore
    PublicKeyMLDSA = NonSupportingPublicKey  # type: ignore

# # ===================================================================================================
# # ===================================================================================================
# #
# #                                     General section
# #
# # ===================================================================================================
# # ===================================================================================================

GeneratorParams = dict[str, Union[int, str, bool]]
KeyGeneratorInfo = dict[str, tuple[Callable[..., PrivateKey], GeneratorParams]]


def get_supported_keys_generators(basic: bool = False) -> KeyGeneratorInfo:
    """Get supported key generators dictionary.

    Returns a dictionary mapping key type names to their corresponding generator functions
    and parameters. Supports RSA, ECC, and optionally SM2, Dilithium, and ML-DSA key types
    based on system capabilities.

    :param basic: If True, return only RSA and ECC key generators, defaults to False
    :return: Dictionary mapping key type names to tuples of (generator_function, parameters)
    """
    ret: KeyGeneratorInfo = {
        # RSA keys
        "rsa2048": (PrivateKeyRsa.generate_key, {"key_size": 2048}),
        "rsa3072": (PrivateKeyRsa.generate_key, {"key_size": 3072}),
        "rsa4096": (PrivateKeyRsa.generate_key, {"key_size": 4096}),
        # ECC keys
        "secp256r1": (PrivateKeyEcc.generate_key, {"curve_name": "secp256r1"}),
        "secp384r1": (PrivateKeyEcc.generate_key, {"curve_name": "secp384r1"}),
        "secp521r1": (PrivateKeyEcc.generate_key, {"curve_name": "secp521r1"}),
    }
    if basic:
        return ret

    if IS_OSCCA_SUPPORTED:
        ret["sm2"] = (PrivateKeySM2.generate_key, {})

    if IS_DILITHIUM_SUPPORTED:
        ret["dil2"] = (PrivateKeyDilithium.generate_key, {"level": 2})
        ret["dil3"] = (PrivateKeyDilithium.generate_key, {"level": 3})
        ret["dil5"] = (PrivateKeyDilithium.generate_key, {"level": 5})
        ret["mldsa44"] = (PrivateKeyMLDSA.generate_key, {"level": 2})
        ret["mldsa65"] = (PrivateKeyMLDSA.generate_key, {"level": 3})
        ret["mldsa87"] = (PrivateKeyMLDSA.generate_key, {"level": 5})

    return ret


def get_ecc_curve(key_length: int) -> EccCurve:
    """Get ECC curve based on key length.

    Determines the appropriate elliptic curve cryptography curve type based on the
    provided key length in bytes. Supports SECP256R1, SECP384R1, and SECP521R1 curves.

    :param key_length: Length of ECC key in bytes
    :return: Corresponding ECC curve type
    :raises SPSDKError: When key length doesn't correspond to any supported curve
    """
    if key_length <= 32 or key_length == 64:
        return EccCurve.SECP256R1
    if key_length <= 48 or key_length == 96:
        return EccCurve.SECP384R1
    if key_length <= 66:
        return EccCurve.SECP521R1
    raise SPSDKError(f"Not sure what curve corresponds to {key_length} data")


def prompt_for_passphrase() -> str:
    """Prompt interactively for private key passphrase.

    This function displays a secure password prompt to the user and waits for input.
    The entered passphrase is hidden from display for security purposes.

    :raises SPSDKError: When interactive mode is disabled via SPSDK_INTERACTIVE_DISABLED
                       environment variable.
    :return: The passphrase entered by the user.
    """
    if SPSDK_INTERACTIVE_DISABLED:
        raise SPSDKError(
            "Prompting for passphrase failed. The interactive mode is turned off."
            "You can change it setting the 'SPSDK_INTERACTIVE_DISABLED' environment variable"
        )
    password = getpass.getpass(prompt="Private key is encrypted. Enter password: ", stream=None)
    return password
