#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for key generation and saving keys to file."""

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
    """Load PEM Private key.

    :param data: key data
    :param password: optional password
    :raises SPSDKError: if the key cannot be decoded
    :return: Key
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
    """Load DER Private key.

    :param data: key data
    :param password: optional password
    :raises SPSDKError: if the key cannot be decoded
    :return: Key
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
    """Load Private key.

    :param encoding: Encoding of input data
    :param data: Key data
    :param password: Optional password
    :raises SPSDKValueError: Unsupported encoding
    :raises SPSDKWrongKeyPassphrase: Private key is encrypted and passphrase is incorrect
    :raises SPSDKKeyPassphraseMissing: Private key is encrypted and passphrase is missing
    :return: Key
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
    """Load PEM Public key.

    :param data: key data
    :raises SPSDKError: if the key cannot be decoded
    :return: PublicKey
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
    """Load DER Public key.

    :param data: key data
    :raises SPSDKError: if the key cannot be decoded
    :return: PublicKey
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
            return DilithiumPublicKey(public_data=data)
        except PQCError as exc:
            last_error = exc
        try:
            return MLDSAPublicKey(public_data=data)
        except PQCError as exc:
            last_error = exc

    raise SPSDKError(f"Cannot load DER public key: {last_error}")


class SPSDKInvalidKeyType(SPSDKError):
    """Invalid Key Type."""


class SPSDKKeyPassphraseMissing(SPSDKError):
    """Passphrase for decryption of private key is missing."""


class SPSDKWrongKeyPassphrase(SPSDKError):
    """Passphrase for decryption of private key is wrong."""


class PrivateKey(BaseClass, abc.ABC):
    """SPSDK Private Key."""

    key: Any

    @classmethod
    @abc.abstractmethod
    def generate_key(cls) -> Self:
        """Generate SPSDK Key (private key).

        :return: SPSDK private key
        """

    @property
    @abc.abstractmethod
    def default_hash_algorithm(self) -> EnumHashAlgorithm:
        """Default hash algorithm for signing/verifying."""

    @property
    @abc.abstractmethod
    def signature_size(self) -> int:
        """Size of signature data."""

    @property
    @abc.abstractmethod
    def key_size(self) -> int:
        """Key size in bits.

        :return: Key Size
        """

    @abc.abstractmethod
    def get_public_key(self) -> "PublicKey":
        """Generate public key.

        :return: Public key
        """

    @abc.abstractmethod
    def verify_public_key(self, public_key: "PublicKey") -> bool:
        """Verify public key.

        :param public_key: Public key to verify
        :return: True if is in pair, False otherwise
        """

    def __eq__(self, obj: Any) -> bool:
        """Check object equality."""
        return isinstance(obj, self.__class__) and self.get_public_key() == obj.get_public_key()

    def save(
        self,
        file_path: str,
        password: Optional[str] = None,
        encoding: SPSDKEncoding = SPSDKEncoding.PEM,
    ) -> None:
        """Save the Private key to the given file.

        :param file_path: path to the file, where the key will be stored
        :param password: password to private key; None to store without password
        :param encoding: encoding type, default is PEM
        """
        write_file(self.export(password=password, encoding=encoding), file_path, mode="wb")

    @classmethod
    def load(cls, file_path: str, password: Optional[str] = None) -> Self:
        """Load the Private key from the given file.

        :param file_path: path to the file, where the key is stored
        :param password: password to private key; None to load without password
        """
        data = load_binary(file_path)
        return cls.parse(data=data, password=password)

    @abc.abstractmethod
    def sign(self, data: bytes, **kwargs: Any) -> bytes:
        """Sign input data.

        :param data: Input data
        :param kwargs: Keyword arguments for specific type of key
        :return: Signed data
        """

    @abc.abstractmethod
    def export(
        self,
        password: Optional[str] = None,
        encoding: SPSDKEncoding = SPSDKEncoding.DER,
    ) -> bytes:
        """Export key into bytes in requested format.

        :param password: password to private key; None to store without password
        :param encoding: encoding type, default is DER
        :return: Byte representation of key
        """

    @classmethod
    def parse(cls, data: bytes, password: Optional[str] = None) -> Self:
        """Deserialize object from bytes array.

        :param data: Data to be parsed
        :param password: password to private key; None to store without password
        :returns: Recreated key
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
        """Create Private Key object.

        :param key: Supported private key.
        :raises SPSDKInvalidKeyType: Unsupported private key given
        :return: SPSDK Private Kye object
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
    """SPSDK Public Key."""

    key: Any
    RECOMMENDED_ENCODING = SPSDKEncoding.PEM

    @property
    @abc.abstractmethod
    def default_hash_algorithm(self) -> EnumHashAlgorithm:
        """Default hash algorithm for signing/verifying."""

    @property
    @abc.abstractmethod
    def signature_size(self) -> int:
        """Size of signature data."""

    @property
    @abc.abstractmethod
    def public_numbers(self) -> Any:
        """Public numbers."""

    def save(self, file_path: str, encoding: SPSDKEncoding = SPSDKEncoding.PEM) -> None:
        """Save the public key to the file.

        :param file_path: path to the file, where the key will be stored
        :param encoding: encoding type, default is PEM
        """
        write_file(data=self.export(encoding=encoding), path=file_path, mode="wb")

    @classmethod
    def load(cls, file_path: str) -> Self:
        """Load the Public key from the given file.

        :param file_path: path to the file, where the key is stored
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
        """Verify input data.

        :param signature: The signature of input data
        :param data: Input data
        :param algorithm: Used algorithm, defaults, automatic selection - None
        :param kwargs: Keyword arguments for specific type of key
        :return: True if signature is valid, False otherwise
        """

    @abc.abstractmethod
    def export(self, encoding: SPSDKEncoding = SPSDKEncoding.NXP) -> bytes:
        """Export key into bytes to requested format.

        :param encoding: encoding type, default is NXP
        :return: Byte representation of key
        """

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Deserialize object from bytes array.

        :param data: Data to be parsed
        :returns: Recreated key
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

        :param algorithm: Used hash algorithm, defaults to sha256
        :return: Key Hash
        """
        return get_hash(self.export(), algorithm)

    def __eq__(self, obj: Any) -> bool:
        """Check object equality."""
        return isinstance(obj, self.__class__) and self.public_numbers == obj.public_numbers

    @classmethod
    def create(cls, key: Any) -> Self:
        """Create Public Key object.

        :param key: Supported public key.
        :raises SPSDKInvalidKeyType: Unsupported public key given
        :return: SPSDK Public Kye object
        """
        SUPPORTED_KEYS = {
            PublicKeyEcc: ec.EllipticCurvePublicKey,
            PublicKeyRsa: rsa.RSAPublicKey,
        }
        if IS_OSCCA_SUPPORTED:
            SUPPORTED_KEYS[PublicKeySM2] = sm2.CryptSM2

        if IS_DILITHIUM_SUPPORTED:
            SUPPORTED_KEYS[PublicKeyDilithium] = DilithiumPublicKey

        for k, v in SUPPORTED_KEYS.items():
            if isinstance(key, v):
                return k(key)

        raise SPSDKInvalidKeyType(f"Unsupported key type: {str(key)}")


class NonSupportingPublicKey(PublicKey):
    """Just for non supported keys."""

    def __init__(self) -> None:
        """Just constructor to inform about not supported key type.

        :raises SPSDKNotImplementedError: Key is not implemented exception.
        """
        raise SPSDKNotImplementedError("The key is not supported.")


class NonSupportingPrivateKey(PrivateKey):
    """Just for non supported keys."""

    def __init__(self) -> None:
        """Just constructor to inform about not supported key type.

        :raises SPSDKNotImplementedError: Key is not implemented exception.
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
    """SPSDK Private Key."""

    SUPPORTED_KEY_SIZES = [2048, 3072, 4096]

    key: rsa.RSAPrivateKey

    def __init__(self, key: rsa.RSAPrivateKey) -> None:
        """Create SPSDK Key.

        :param key: Only RSA key is accepted
        """
        self.key = key

    @classmethod
    def generate_key(cls, key_size: int = 2048, exponent: int = 65537) -> Self:
        """Generate SPSDK Key (private key).

        :param key_size: key size in bits; must be >= 512
        :param exponent: public exponent; must be >= 3 and odd
        :return: SPSDK private key
        """
        return cls(
            rsa.generate_private_key(
                public_exponent=exponent,
                key_size=key_size,
            )
        )

    @property
    def default_hash_algorithm(self) -> EnumHashAlgorithm:
        """Default hash algorithm for signing/verifying."""
        return EnumHashAlgorithm.SHA256

    @property
    def signature_size(self) -> int:
        """Size of signature data."""
        return self.key.key_size // 8

    @property
    def key_size(self) -> int:
        """Key size in bits.

        :return: Key Size
        """
        return self.key.key_size

    def get_public_key(self) -> "PublicKeyRsa":
        """Generate public key.

        :return: Public key
        """
        return PublicKeyRsa(self.key.public_key())

    def verify_public_key(self, public_key: PublicKey) -> bool:
        """Verify public key.

        :param public_key: Public key to verify
        :return: True if is in pair, False otherwise
        """
        return self.get_public_key() == public_key

    def export(
        self,
        password: Optional[str] = None,
        encoding: SPSDKEncoding = SPSDKEncoding.DER,
    ) -> bytes:
        """Export the Private key to the bytes in requested encoding.

        :param password: password to private key; None to store without password
        :param encoding: encoding type, default is DER
        :returns: Private key in bytes
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
        """Sign input data.

        :param data: Input data
        :param algorithm: Used algorithm
        :param pss_padding: Use RSA-PSS signing scheme
        :param prehashed: Data for signing is already pre-hashed
        :param kwargs: Sink for unused parameters
        :return: Signed data
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
        """Deserialize object from bytes array.

        :param data: Data to be parsed
        :param password: password to private key; None to store without password
        :returns: Recreated key
        """
        key = super().parse(data=data, password=password)
        if isinstance(key, PrivateKeyRsa):
            return key

        raise SPSDKInvalidKeyType("Can't parse Rsa private key from given data")

    def __repr__(self) -> str:
        return f"RSA{self.key_size} Private Key"

    def __str__(self) -> str:
        """Object description in string format."""
        ret = f"RSA{self.key_size} Private key: \nd({hex(self.key.private_numbers().d)})"
        return ret


class PublicKeyRsa(PublicKey):
    """SPSDK Public Key."""

    key: rsa.RSAPublicKey

    def __init__(self, key: rsa.RSAPublicKey) -> None:
        """Create SPSDK Public Key.

        :param key: SPSDK Public Key data or file path
        """
        self.key = key

    @property
    def default_hash_algorithm(self) -> EnumHashAlgorithm:
        """Default hash algorithm for signing/verifying."""
        return EnumHashAlgorithm.SHA256

    @property
    def signature_size(self) -> int:
        """Size of signature data."""
        return self.key.key_size // 8

    @property
    def key_size(self) -> int:
        """Key size in bits.

        :return: Key Size
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
        """Public number E.

        :return: E
        """
        return self.public_numbers.e

    @property
    def n(self) -> int:
        """Public number N.

        :return: N
        """
        return self.public_numbers.n

    def export(
        self,
        encoding: SPSDKEncoding = SPSDKEncoding.NXP,
        exp_length: Optional[int] = None,
        modulus_length: Optional[int] = None,
    ) -> bytes:
        """Save the public key to the bytes in NXP or DER format.

        :param encoding: encoding type, default is NXP
        :param exp_length: Optional specific exponent length in bytes
        :param modulus_length: Optional specific modulus length in bytes
        :returns: Public key in bytes
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
        """Verify input data.

        :param signature: The signature of input data
        :param data: Input data
        :param algorithm: Used algorithm
        :param pss_padding: Use RSA-PSS signing scheme
        :param prehashed: Data for signing is already pre-hashed
        :param kwargs: Sink for unused parameters
        :return: True if signature is valid, False otherwise
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
        """Check object equality."""
        return isinstance(obj, self.__class__) and self.public_numbers == obj.public_numbers

    def __repr__(self) -> str:
        return f"RSA{self.key_size} Public Key"

    def __str__(self) -> str:
        """Object description in string format."""
        ret = f"RSA{self.key_size} Public key: \ne({hex(self.e)}) \nn({hex(self.n)})"
        return ret

    @classmethod
    def recreate(cls, exponent: int, modulus: int) -> Self:
        """Recreate RSA public key from Exponent and modulus.

        :param exponent: Exponent of RSA key.
        :param modulus: Modulus of RSA key.
        :return: RSA public key.
        """
        public_numbers = rsa.RSAPublicNumbers(e=exponent, n=modulus)
        return cls(public_numbers.public_key())

    @classmethod
    def recreate_from_data(cls, data: bytes) -> Self:
        """Recreate RSA public key from exponent and modulus in data blob.

        :param data: Data blob of exponent and modulus in bytes (in Big Endian)
        :return: RSA public key.
        """
        return cls(cls.recreate_public_numbers(data).public_key())

    @staticmethod
    def recreate_public_numbers(data: bytes) -> rsa.RSAPublicNumbers:
        """Recreate public numbers from data.

        :param data: Dat with raw key.
        :raises SPSDKError: Un recognized data.
        :return: RAS public numbers.
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
        """Deserialize object from bytes array.

        :param data: Data to be parsed
        :returns: Recreated key
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
    """Supported ecc key types."""

    SECP256R1 = "secp256r1"
    SECP384R1 = "secp384r1"
    SECP521R1 = "secp521r1"


class SPSDKUnsupportedEccCurve(SPSDKValueError):
    """Unsupported Ecc curve error."""


class KeyEccCommon:
    """SPSDK Common Key."""

    key: Union[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]

    @property
    def default_hash_algorithm(self) -> EnumHashAlgorithm:
        """Default hash algorithm for signing/verifying."""
        return {
            256: EnumHashAlgorithm.SHA256,
            384: EnumHashAlgorithm.SHA384,
            521: EnumHashAlgorithm.SHA512,
        }[self.key.key_size]

    @property
    def coordinate_size(self) -> int:
        """Size of signature data."""
        return math.ceil(self.key.key_size / 8)

    @property
    def signature_size(self) -> int:
        """Size of signature data."""
        return self.coordinate_size * 2

    @property
    def curve(self) -> EccCurve:
        """Curve type."""
        return EccCurve(self.key.curve.name)

    @property
    def key_size(self) -> int:
        """Key size in bits."""
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
        """Re-format ECC ANS.1 DER signature into the format used by ROM code."""
        r, s = utils.decode_dss_signature(signature)

        r_bytes = r.to_bytes(coordinate_length, Endianness.BIG.value)
        s_bytes = s.to_bytes(coordinate_length, Endianness.BIG.value)
        return r_bytes + s_bytes


class PrivateKeyEcc(KeyEccCommon, PrivateKey):
    """SPSDK Private Key."""

    key: ec.EllipticCurvePrivateKey

    def __init__(self, key: ec.EllipticCurvePrivateKey) -> None:
        """Create SPSDK Ecc Private Key.

        :param key: Only Ecc key is accepted
        """
        self.key = key

    @classmethod
    def generate_key(cls, curve_name: EccCurve = EccCurve.SECP256R1) -> Self:
        """Generate SPSDK Key (private key).

        :param curve_name: Name of curve
        :return: SPSDK private key
        """
        curve_obj = cls._get_ec_curve_object(curve_name)
        prv = ec.generate_private_key(curve_obj)
        return cls(prv)

    def exchange(self, peer_public_key: "PublicKeyEcc") -> bytes:
        """Exchange key using ECDH algorithm with provided peer public key.

        :param peer_public_key: Peer public key
        :return: Shared key
        """
        return self.key.exchange(algorithm=ec.ECDH(), peer_public_key=peer_public_key.key)

    def get_public_key(self) -> "PublicKeyEcc":
        """Generate public key.

        :return: Public key
        """
        return PublicKeyEcc(self.key.public_key())

    def verify_public_key(self, public_key: PublicKey) -> bool:
        """Verify public key.

        :param public_key: Public key to verify
        :return: True if is in pair, False otherwise
        """
        return self.get_public_key() == public_key

    def export(
        self,
        password: Optional[str] = None,
        encoding: SPSDKEncoding = SPSDKEncoding.DER,
    ) -> bytes:
        """Export the Private key to the bytes in requested format.

        :param password: password to private key; None to store without password
        :param encoding: encoding type, default is DER
        :returns: Private key in bytes
        """
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
        """Sign input data.

        :param data: Input data
        :param algorithm: Used algorithm
        :param der_format: Use DER format as a output
        :param prehashed: Use pre hashed value as input
        :param kwargs: Sink for unused arguments
        :return: Signed data
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
        """Private number D."""
        return self.key.private_numbers().private_value

    @classmethod
    def parse(cls, data: bytes, password: Optional[str] = None) -> Self:
        """Deserialize object from bytes array.

        :param data: Data to be parsed
        :param password: password to private key; None to store without password
        :returns: Recreated key
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
        return f"ECC {self.curve} Private Key"

    def __str__(self) -> str:
        """Object description in string format."""
        return f"ECC ({self.curve}) Private key: \nd({hex(self.d)})"


class PublicKeyEcc(KeyEccCommon, PublicKey):
    """SPSDK Public Key."""

    key: ec.EllipticCurvePublicKey

    def __init__(self, key: ec.EllipticCurvePublicKey) -> None:
        """Create SPSDK Public Key.

        :param key: SPSDK Public Key data or file path
        """
        self.key = key

    def export(self, encoding: SPSDKEncoding = SPSDKEncoding.NXP) -> bytes:
        """Export the public key to the bytes in requested format.

        :param encoding: encoding type, default is NXP
        :returns: Public key in bytes
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
        """Verify input data.

        :param signature: The signature of input data
        :param data: Input data
        :param algorithm: Used algorithm
        :param prehashed: Use pre hashed value as input
        :param kwargs: Sink for unused arguments
        :return: True if signature is valid, False otherwise
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
        """Public numbers of key.

        :return: Public numbers
        """
        return self.key.public_numbers()

    @property
    def x(self) -> int:
        """Public number X.

        :return: X
        """
        return self.public_numbers.x

    @property
    def y(self) -> int:
        """Public number Y.

        :return: Y
        """
        return self.public_numbers.y

    @classmethod
    def recreate(cls, coor_x: int, coor_y: int, curve: EccCurve) -> Self:
        """Recreate ECC public key from coordinates.

        :param coor_x: X coordinate of point on curve.
        :param coor_y: Y coordinate of point on curve.
        :param curve: ECC curve.
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

        :param data: Data blob of coordinates in bytes (X,Y in Big Endian)
        :param curve: ECC curve.
        :return: ECC public key.
        """

        def get_curve(data_length: int, curve: Optional[EccCurve] = None) -> tuple[EccCurve, bool]:
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
        """Deserialize object from bytes array.

        :param data: Data to be parsed
        :returns: Recreated key
        """
        try:
            key = super().parse(data=data)
            if isinstance(key, PublicKeyEcc):
                return key
        except SPSDKError:
            return cls.recreate_from_data(data=data)

        raise SPSDKInvalidKeyType("Can't parse ECC public key from given data")

    def __repr__(self) -> str:
        return f"ECC {self.curve} Public Key"

    def __str__(self) -> str:
        """Object description in string format."""
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
        """SPSDK SM2 Private Key."""

        key: sm2.CryptSM2

        def __init__(self, key: sm2.CryptSM2) -> None:
            """Create SPSDK Key.

            :param key: Only SM2 key is accepted
            """
            if not isinstance(key, sm2.CryptSM2):
                raise SPSDKInvalidKeyType("The input key is not SM2 type")
            self.key = key

        @classmethod
        def generate_key(cls) -> Self:
            """Generate SM2 Key (private key).

            :return: SM2 private key
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
            """Generate public key.

            :return: Public key
            """
            return PublicKeySM2(sm2.CryptSM2(private_key=None, public_key=self.key.public_key))

        def verify_public_key(self, public_key: PublicKey) -> bool:
            """Verify public key.

            :param public_key: Public key to verify
            :return: True if is in pair, False otherwise
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

            :param data: Data to sign.
            :param salt: Salt for signature generation, defaults to None. If not specified a random string will be used.
            :param use_ber: Encode signature into BER format, defaults to True
            :param kwargs: Sink for unused arguments
            :raises SPSDKError: Signature can't be created.
            :return: SM2 signature.
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
            """Convert key into bytes supported by NXP."""
            if encoding != SPSDKEncoding.DER:
                raise SPSDKNotImplementedError("Only DER encoding is supported for SM2 keys export")
            keys = SM2PrivateKey(self.key.private_key, self.key.public_key)
            return SM2Encoder().encode_private_key(keys)

        def __repr__(self) -> str:
            return "SM2 Private Key"

        def __str__(self) -> str:
            """Object description in string format."""
            return f"SM2Key(private_key={self.key.private_key}, public_key='{self.key.public_key}')"

        @property
        def key_size(self) -> int:
            """Size of the key in bits."""
            return self.key.para_len

        @property
        def default_hash_algorithm(self) -> EnumHashAlgorithm:
            """Default hash algorithm for signing/verifying."""
            return EnumHashAlgorithm.SM3

        @property
        def signature_size(self) -> int:
            """Signature size."""
            return 64

        def save(
            self,
            file_path: str,
            password: Optional[str] = None,
            encoding: SPSDKEncoding = SPSDKEncoding.PEM,
        ) -> None:
            """Save the Private key to the given file."""
            return super().save(file_path, password, encoding=SPSDKEncoding.DER)

    class PublicKeySM2(PublicKey):
        """SM2 Public Key."""

        RECOMMENDED_ENCODING = SPSDKEncoding.DER
        key: sm2.CryptSM2

        def __init__(self, key: sm2.CryptSM2) -> None:
            """Create SPSDK Public Key.

            :param key: SPSDK Public Key data or file path
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
            """Verify signature.

            :param signature: SM2 signature to verify
            :param data: Signed data
            :param algorithm: Just to keep compatibility with abstract class
            :param kwargs: Sink for unused arguments
            :raises SPSDKError: Invalid signature
            """
            # Check if the signature is BER formatted
            if len(signature) > 64 and signature[0] == 0x30:
                signature = SM2Encoder().decode_signature(signature)
            # Otherwise the signature is in raw format r || s
            data_hash = bytes.fromhex(self.key._sm3_z(data))
            return self.key.verify(Sign=signature.hex(), data=data_hash)

        def export(self, encoding: SPSDKEncoding = SPSDKEncoding.DER) -> bytes:
            """Convert key into bytes supported by NXP.

            :return: Byte representation of key
            """
            if encoding != SPSDKEncoding.DER:
                raise SPSDKNotImplementedError("Only DER encoding is supported for SM2 keys export")
            keys = SM2PublicKey(self.key.public_key)
            return SM2Encoder().encode_public_key(keys)

        @property
        def default_hash_algorithm(self) -> EnumHashAlgorithm:
            """Default hash algorithm for signing/verifying."""
            return EnumHashAlgorithm.SM3

        @property
        def signature_size(self) -> int:
            """Signature size."""
            return 64

        @property
        def public_numbers(self) -> str:
            """Public numbers of key.

            :return: Public numbers
            """
            return self.key.public_key

        @classmethod
        def recreate(cls, data: bytes) -> Self:
            """Recreate SM2 public key from data.

            :param data: public key data
            :return: SPSDK public key.
            """
            return cls(sm2.CryptSM2(private_key=None, public_key=data.hex()))

        @classmethod
        def recreate_from_data(cls, data: bytes) -> Self:
            """Recreate SM2 public key from data.

            :param data: PEM or DER encoded key.
            :return: SM2 public key.
            """
            key_data = sanitize_pem(data)
            public_key = SM2Encoder().decode_public_key(data=key_data)
            return cls(sm2.CryptSM2(private_key=None, public_key=public_key.public))

        def __repr__(self) -> str:
            return "SM2 Public Key"

        def __str__(self) -> str:
            """Object description in string format."""
            ret = f"SM2 Public Key <{self.public_numbers}>"
            return ret

        def save(self, file_path: str, encoding: SPSDKEncoding = SPSDKEncoding.PEM) -> None:
            """Save the Private key to the given file."""
            return super().save(file_path, encoding=SPSDKEncoding.DER)

else:
    # In case the OSCCA is not installed, do this to avoid import errors
    PrivateKeySM2 = NonSupportingPrivateKey  # type: ignore
    PublicKeySM2 = NonSupportingPublicKey  # type: ignore


class ECDSASignature:
    """ECDSA Signature."""

    COORDINATE_LENGTHS = {EccCurve.SECP256R1: 32, EccCurve.SECP384R1: 48, EccCurve.SECP521R1: 66}

    def __init__(self, r: int, s: int, ecc_curve: EccCurve) -> None:
        """ECDSA Signature constructor.

        :param r: r value of signature
        :param s: s value of signature
        :param ecc_curve: ECC Curve enum
        """
        self.r = r
        self.s = s
        self.ecc_curve = ecc_curve

    @classmethod
    def parse(cls, signature: bytes) -> Self:
        """Parse signature in DER or NXP format.

        :param signature: Signature binary
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

        :param encoding: Signature encoding
        :return: Signature as bytes
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

        :param signature: Signature
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
        """Get the Elliptic Curve of signature.

        :param signature_length: Signature length
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
        """Generic base class for all PQC keys."""

        SUPPORTED_LEVELS = [2, 3, 5]
        RECOMMENDED_ENCODING = SPSDKEncoding.PEM
        key: Union[DilithiumPrivateKey, DilithiumPublicKey, MLDSAPublicKey, MLDSAPublicKey]

        def __init__(
            self,
            key: Union[DilithiumPrivateKey, DilithiumPublicKey, MLDSAPublicKey, MLDSAPublicKey],
        ):
            """Initialize PQC key."""
            self.key = key

        @property
        def default_hash_algorithm(self) -> EnumHashAlgorithm:
            """Default hash algorithm for signing/verifying."""
            return EnumHashAlgorithm.SHA384

        @property
        def signature_size(self) -> int:
            """Size of signature data."""
            return self.key.signature_size

        @property
        def public_numbers(self) -> bytes:
            """Public numbers of key."""
            return self.key.public_data

        @property
        def key_size(self) -> int:
            """Key size in bytes."""
            return self.key.key_size

        @property
        def level(self) -> int:
            """Get Key level."""
            return self.key.level

        def __str__(self) -> str:
            return repr(self)

        def verify_signature(
            self,
            signature: bytes,
            data: bytes,
            algorithm: Optional[EnumHashAlgorithm] = None,
            prehashed: bool = False,
            **kwargs: Any,
        ) -> bool:
            """Verify input data.

            :param signature: The signature of input data
            :param data: Input data
            :param algorithm: Used algorithm, defaults, automatic selection - None
            :param prehashed: Use pre hashed value as input
            :param kwargs: Keyword arguments for specific type of key
            :return: True if signature is valid, False otherwise
            """
            if prehashed:
                data_to_sign = data
            else:
                data_to_sign = get_hash(data, algorithm or self.default_hash_algorithm)
            return self.key.verify(data=data_to_sign, signature=signature)

    class PQCPublicKey(PQCKey, PublicKey):
        """Generic base class for PQC public keys."""

        key: Union[DilithiumPublicKey, MLDSAPublicKey]

        def export(self, encoding: SPSDKEncoding = SPSDKEncoding.NXP) -> bytes:
            """Export key into bytes to requested format.

            :param encoding: encoding type, default is NXP
            :return: Byte representation of key
            """
            if encoding == SPSDKEncoding.NXP:
                return self.key.public_data
            return self.key.export(pem=encoding == SPSDKEncoding.PEM)

        def __repr__(self) -> str:
            return f"{self.key.algorithm.value} Public key"

    class PQCPrivateKey(PQCKey, PrivateKey):
        """Generic base class for PQC private keys."""

        key: Union[DilithiumPrivateKey, MLDSAPrivateKey]

        def sign(
            self,
            data: bytes,
            algorithm: Optional[EnumHashAlgorithm] = None,
            prehashed: bool = False,
            **kwargs: Any,
        ) -> bytes:
            """Sign input data.

            :param data: Input data
            :param algorithm: Used algorithm
            :param prehashed: Use pre hashed value as input
            :param kwargs: Keyword arguments for specific type of key
            :return: Signed data
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

            :param encoding: encoding type, default is NXP
            :param password: password to private key; None to store without password
            :return: Byte representation of key
            """
            if encoding == SPSDKEncoding.NXP:
                return self.key.private_data + (self.key.public_data or bytes())
            return self.key.export(pem=encoding == SPSDKEncoding.PEM)

        def __repr__(self) -> str:
            return f"{self.key.algorithm.value} Private key"

    class PublicKeyDilithium(PQCPublicKey):
        """Dilithium Public Key."""

        key: DilithiumPublicKey

        @classmethod
        def parse(cls, data: bytes) -> Self:
            """Deserialize object from bytes array.

            :param data: Data to be parsed
            :returns: Recreated key
            """
            try:
                return cls(DilithiumPublicKey.parse(data=data))
            except PQCError as e:
                raise SPSDKInvalidKeyType(f"Can't parse Dilithium Public from data: {e}") from e

    class PrivateKeyDilithium(PQCPrivateKey):
        """Dilithium Private Key."""

        key: DilithiumPrivateKey

        @classmethod
        def generate_key(
            cls, level: Optional[int] = None, algorithm: Optional[PQCAlgorithm] = None
        ) -> Self:
            """Generate SPSDK Key (private key).

            One of 'level' or 'algorithm' must be specified.

            :param level: NIST claim level, defaults to None
            :param algorithm: Exact PQC algorithm to use , defaults to None
            :return: Dilithium Private key
            """
            try:
                return cls(DilithiumPrivateKey(level=level, algorithm=algorithm))
            except PQCError as e:
                raise SPSDKError(f"Could not create Dilithium key: {e}") from e

        def get_public_key(self) -> PublicKeyDilithium:
            """Generate public key."""
            if self.key.public_data is None:
                raise SPSDKUnsupportedOperation("Dilithium key doesn't have public portion")
            return PublicKeyDilithium(DilithiumPublicKey(public_data=self.key.public_data))

        def verify_public_key(self, public_key: PublicKey) -> bool:
            """Verify public key."""
            if not isinstance(public_key, PublicKeyDilithium):
                raise SPSDKInvalidKeyType("Public key type is not a Dilithium public key")
            return self.key.public_data == public_key.key.public_data

        @classmethod
        def parse(cls, data: bytes, password: Optional[str] = None) -> Self:
            """Deserialize object from bytes array.

            :param data: Data to be parsed
            :param password: Password in case of encrypted key
            :returns: Recreated key
            """
            try:
                return cls(DilithiumPrivateKey.parse(data=data))
            except PQCError as e:
                raise SPSDKError(f"Could not parse key: {e}") from e

    class PublicKeyMLDSA(PQCPublicKey):
        """ML-DSA Public key."""

        key: MLDSAPublicKey

        @classmethod
        def parse(cls, data: bytes) -> Self:
            """Deserialize object from bytes array.

            :param data: Data to be parsed
            :returns: Recreated key
            """
            try:
                return cls(MLDSAPublicKey.parse(data=data))
            except PQCError as e:
                raise SPSDKError(f"Could not parse key: {e}") from e

    class PrivateKeyMLDSA(PQCPrivateKey):
        """ML-DSA Private Key."""

        key: MLDSAPrivateKey

        @classmethod
        def generate_key(
            cls, level: Optional[int] = None, algorithm: Optional[PQCAlgorithm] = None
        ) -> Self:
            """Generate SPSDK Key (private key).

            One of 'level' or 'algorithm' must be specified.

            :param level: NIST claim level, defaults to None
            :param algorithm: Exact PQC algorithm to use , defaults to None
            :return: ML-DSA Private key
            """
            try:
                key = MLDSAPrivateKey(level=level, algorithm=algorithm)
            except PQCError as e:
                raise SPSDKError(f"Could not create Dilithium key: {e}") from e
            return cls(key)

        def get_public_key(self) -> PublicKeyMLDSA:
            """Generate public key."""
            if self.key.public_data is None:
                raise SPSDKUnsupportedOperation("Dilithium key doesn't have public portion")
            return PublicKeyMLDSA(MLDSAPublicKey(public_data=self.key.public_data))

        def verify_public_key(self, public_key: PublicKey) -> bool:
            """Verify public key."""
            if not isinstance(public_key, PublicKeyMLDSA):
                raise SPSDKInvalidKeyType("Public key type is not a Dilithium public key")
            return self.key.public_data == public_key.key.public_data

        @classmethod
        def parse(cls, data: bytes, password: Optional[str] = None) -> Self:
            """Deserialize object from bytes array.

            :param data: Data to be parsed
            :param password: Password in case of encrypted key
            :returns: Recreated key
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
    """Generate list with list of supported key types.

    :param basic: Return only the RSA and ECC keys generators
    :return: `KeyGeneratorInfo` dictionary of supported key types.
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
    """Get curve name for Crypto library.

    :param key_length: Length of ecc key in bytes
    """
    if key_length <= 32 or key_length == 64:
        return EccCurve.SECP256R1
    if key_length <= 48 or key_length == 96:
        return EccCurve.SECP384R1
    if key_length <= 66:
        return EccCurve.SECP521R1
    raise SPSDKError(f"Not sure what curve corresponds to {key_length} data")


def prompt_for_passphrase() -> str:
    """Prompt interactively for private key passphrase."""
    if SPSDK_INTERACTIVE_DISABLED:
        raise SPSDKError(
            "Prompting for passphrase failed. The interactive mode is turned off."
            "You can change it setting the 'SPSDK_INTERACTIVE_DISABLED' environment variable"
        )
    password = getpass.getpass(prompt="Private key is encrypted. Enter password: ", stream=None)
    return password
