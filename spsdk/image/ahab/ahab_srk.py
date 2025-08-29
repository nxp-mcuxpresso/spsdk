#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Implementation of AHAB container SRK (Super Root Keys) support.

This module provides classes and functionality for creating, parsing, verifying and exporting
Super Root Keys used in AHAB (Advanced High Assurance Boot) secure boot implementations.
The module supports multiple cryptographic algorithms including RSA, ECDSA, SM2, and
post-quantum cryptography (Dilithium/ML-DSA).

The main classes are:
- SRKRecordBase: Base class for SRK records
- SRKRecord: Class for SRK records version 1
- SRKRecordV2: Enhanced version supporting post-quantum cryptography
- SRKData: Class for storing key data
- SRKTable: Class representing a table of SRK records
- SRKTableV2: Enhanced SRK table supporting PQC keys
- SRKTableArray: Class managing multiple SRK tables
"""


import logging
import math
import os
from struct import pack, unpack
from typing import Any, Optional, Sequence, cast

from typing_extensions import Self, TypeAlias

from spsdk.crypto.dilithium import IS_DILITHIUM_SUPPORTED
from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.crypto.keys import (
    IS_OSCCA_SUPPORTED,
    EccCurve,
    PublicKey,
    PublicKeyDilithium,
    PublicKeyEcc,
    PublicKeyMLDSA,
    PublicKeyRsa,
    PublicKeySM2,
)
from spsdk.crypto.utils import extract_public_key
from spsdk.exceptions import (
    SPSDKError,
    SPSDKLengthError,
    SPSDKUnsupportedOperation,
    SPSDKValueError,
)
from spsdk.image.ahab.ahab_abstract_interfaces import (
    HeaderContainer,
    HeaderContainerData,
    HeaderContainerInverted,
)
from spsdk.image.ahab.ahab_data import (
    LITTLE_ENDIAN,
    RESERVED,
    UINT8,
    UINT16,
    AhabChipContainerConfig,
    AHABSignAlgorithm,
    AHABSignAlgorithmV1,
    AHABSignAlgorithmV2,
    AHABSignHashAlgorithm,
    AHABSignHashAlgorithmV1,
    AHABSignHashAlgorithmV2,
    AHABTags,
)
from spsdk.utils.config import Config
from spsdk.utils.misc import (
    Endianness,
    bytes_to_print,
    extend_block,
    find_file,
    value_to_bytes,
    write_file,
)
from spsdk.utils.verifier import Verifier, VerifierResult

logger = logging.getLogger(__name__)


def get_key_by_val(dictionary: dict, val: Any) -> Any:
    """Get Dictionary key by its value or default.

    :param dictionary: Dictionary to search in.
    :param val: Value to search
    :raises SPSDKValueError: In case that dictionary doesn't contains the value.
    :return: Key.
    """
    for key, value in dictionary.items():
        if value == val:
            return key
    raise SPSDKValueError(
        f"The requested value [{val}] in dictionary [{dictionary}] is not available."
    )


class SRKRecordBase(HeaderContainerInverted):
    """Class representing SRK (Super Root Key) record as part of SRK table in the AHAB container.

    The class holds information about RSA/ECDSA signing algorithms.

    SRK Record::

        +-----+---------------------------------------------------------------+
        |Off  |    Byte 3    |    Byte 2      |    Byte 1    |     Byte 0     |
        +-----+---------------------------------------------------------------+
        |0x00 |    Tag       |         Length of SRK         | Signing Algo   |
        +-----+---------------------------------------------------------------+
        |0x04 |    Hash Algo | Key Size/Curve |    Not Used  |   SRK Flags    |
        +-----+---------------------------------------------------------------+
        |0x08 | RSA modulus len / ECDSA X len | RSA exponent len / ECDSA Y len|
        |     |                Dilithium Raw keys length                      |
        +-----+---------------------------------------------------------------+
        |0x0C |                 SRK record general data                       |
        +-----+---------------------------------------------------------------+

    """

    SIGN_ALGORITHM_ENUM = AHABSignAlgorithmV2
    HASH_ALGORITHM_ENUM = AHABSignHashAlgorithmV2

    TAG = AHABTags.SRK_RECORD.tag
    VERSION = SIGN_ALGORITHM_ENUM.tags()
    ECC_KEY_TYPE = {EccCurve.SECP521R1: 0x3, EccCurve.SECP384R1: 0x2, EccCurve.SECP256R1: 0x1}
    RSA_KEY_TYPE = {2048: 0x5, 3072: 0x6, 4096: 0x7}
    SM2_KEY_TYPE = 0x8
    DILITHIUM_KEY_TYPE = {3: 0x9, 5: 0xA}
    MLDSA_KEY_TYPE = {65: 0x9, 87: 0xA}

    # Dictionary of key sizes for different algorithms.
    KEY_SIZES = {
        0x1: (32, 32),  # PRIME256V1: (32, 32) bytes for X and Y coordinates
        0x2: (48, 48),  # SEC384R1: (48, 48) bytes for X and Y coordinates
        0x3: (66, 66),  # SEC521R1: (66, 66) bytes for X and Y coordinates
        0x5: (256, 4),  # RSA2048: (256, 4) bytes for modulus and exponent
        0x6: (384, 4),  # RSA3072: (384, 4) bytes for modulus and exponent
        0x7: (512, 4),  # RSA4096: (512, 4) bytes for modulus and exponent
        0x8: (32, 32),  # SM2: (32, 32) bytes for X and Y coordinates
        0x9: (1952, 0),  # Dilithium 3 / ML-DSA-65: (1952, 0) bytes for raw key data
        0xA: (2592, 0),  # Dilithium 5 / ML-DSA-87: (2592, 0) bytes for raw key data
    }

    FLAGS_CA_MASK = 0x80
    DIFF_ATTRIBUTES_VALUES = ["version", "hash_algorithm", "key_size", "srk_flags", "crypto_params"]

    def __init__(
        self,
        src_key: Optional[PublicKey] = None,
        signing_algorithm: AHABSignAlgorithm = SIGN_ALGORITHM_ENUM.RSA_PSS,
        hash_type: AHABSignHashAlgorithm = HASH_ALGORITHM_ENUM.SHA256,
        key_size: int = 0,
        srk_flags: int = 0,
        crypto_params: bytes = b"",
        legacy_rsa_exponent_size: bool = False,
    ):
        """Class object initializer.

        :param src_key: Optional source public key used to create the SRKRecord
        :param signing_algorithm: signing algorithm type.
        :param hash_type: hash algorithm type.
        :param key_size: key (curve) size.
        :param srk_flags: flags.
        :param crypto_params: RSA modulus (big endian) or ECDSA X (big endian) or Hash of SRK data.
        :param legacy_rsa_exponent_size: Use legacy 4-byte RSA exponent size for backward compatibility.
        """
        super().__init__(
            tag=self.TAG,
            length=-1,
            version=signing_algorithm.tag,
        )
        self.src_key = src_key
        self.hash_algorithm = hash_type
        self.key_size = key_size
        self.srk_flags = srk_flags
        self.crypto_params = crypto_params
        self.legacy_rsa_exponent_size = legacy_rsa_exponent_size
        self._param_lengths: Optional[tuple[int, int]] = None

    @property
    def key_sizes(self) -> tuple[int, int]:
        """Get the key parameter sizes for the current key.

        This property determines the sizes of the key parameters based on the key_size attribute.
        For RSA keys, it calculates the actual exponent size if a source key is available.

        The returned tuple contains:

        - For RSA keys: (modulus_size, exponent_size) in bytes
        - For ECDSA keys: (x_coordinate_size, y_coordinate_size) in bytes
        - For SM2 keys: (x_coordinate_size, y_coordinate_size) in bytes
        - For Dilithium/ML-DSA keys: (raw_key_size, 0) in bytes

        :raises SPSDKError: If the key_size value is not supported
        :return: Tuple containing the sizes of the two key parameters in bytes
        """
        # If we have parsed parameter lengths, use them
        if self._param_lengths:
            return self._param_lengths

        if self.key_size not in self.KEY_SIZES:
            raise SPSDKError(f"Key size value is not supported: {self.key_size}")

        key_sizes = self.KEY_SIZES[self.key_size]
        key_size_0 = key_sizes[0]
        key_size_1 = key_sizes[1]

        # For RSA keys, check if we need to use actual exponent size
        if self.signing_algorithm in [
            self.SIGN_ALGORITHM_ENUM.RSA,
            self.SIGN_ALGORITHM_ENUM.RSA_PSS,
        ]:
            if self.legacy_rsa_exponent_size:
                # Use legacy 4-byte exponent size
                key_size_1 = key_sizes[1]  # This is already 4 from KEY_SIZES
            elif self.src_key:
                assert isinstance(self.src_key, PublicKeyRsa)
                key_size_1 = math.ceil(int(self.src_key.e).bit_length() / 8)
                # Warn user about potential compatibility issues
                if key_size_1 != 4:
                    logger.info(
                        f"RSA exponent size is {key_size_1} bytes (not the legacy 4 bytes). "
                        f"If you previously used older SPSDK versions and need backward compatibility, "
                        f"consider using the 'rsa_exponent_legacy_size: true' option in your SRK configuration."
                    )

                # Ensure even with src_key, the exponent size is within bounds
                if key_size_1 > 65535:
                    logger.warning(
                        f"RSA exponent size {key_size_1} exceeds maximum allowed value of 65535, "
                        f"using default size {key_sizes[1]}"
                    )
                    key_size_1 = key_sizes[1]
            else:
                # Calculate actual exponent size with bounds checking
                if self.crypto_params and len(self.crypto_params) > key_size_0:
                    key_size_1 = len(self.crypto_params) - key_size_0
                    # Ensure the exponent size is within valid bounds (1-65535)
                    if key_size_1 <= 0 or key_size_1 > 65535:
                        logger.warning(
                            f"Invalid calculated exponent size {key_size_1}, "
                            f"using default size {key_sizes[1]}"
                        )
                        key_size_1 = key_sizes[1]
                else:
                    # Use default if crypto_params is too short or empty
                    key_size_1 = key_sizes[1]

        # For non-RSA keys or if we don't have crypto_params yet, use the default sizes
        self._param_lengths = (key_size_0, key_size_1)
        return self._param_lengths

    @property
    def parameter_lengths(self) -> bytes:
        """Parameter lengths field.

        :return: Created parameter lengths field from the key parameter
        """
        key_sizes = self.key_sizes
        return pack(LITTLE_ENDIAN + UINT16 + UINT16, key_sizes[0], key_sizes[1])

    @classmethod
    def _crypto_params_length(cls, parameter_lengths: bytes) -> int:
        """Decode crypto parameters length.

        :return: Length of crypto parameters.
        """
        len1, len2 = unpack(LITTLE_ENDIAN + UINT16 + UINT16, parameter_lengths[:4])
        return len1 + len2

    @property
    def signing_algorithm(self) -> AHABSignAlgorithm:
        """Return the signing algorithm used by this SRK record.

        Converts the internal version tag into the corresponding AHABSignAlgorithm enum value.

        :return: The signing algorithm as an AHABSignAlgorithm enum value
        """
        return self.SIGN_ALGORITHM_ENUM.from_tag(self.version)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, type(self)):
            if (
                super().__eq__(other)  # pylint: disable=too-many-boolean-expressions
                and self.hash_algorithm == other.hash_algorithm
                and self.key_size == other.key_size
                and self.srk_flags == other.srk_flags
                and self.crypto_params == other.crypto_params
            ):
                return True

        return False

    def __len__(self) -> int:
        return super().__len__() + len(self.crypto_params)

    def __repr__(self) -> str:
        return f"AHAB SRK record, key: {self.get_key_name()}"

    def __str__(self) -> str:
        return (
            "AHAB SRK Record:\n"
            f"  Key:                {self.get_key_name()}\n"
            f"  SRK flags:          {hex(self.srk_flags)}\n"
            f"  Crypto param value: {bytes_to_print(self.crypto_params)}\n"
        )

    @classmethod
    def format(cls) -> str:
        """Format of binary representation."""
        return (
            super().format()
            + UINT8  # Hash Algorithm
            + UINT8  # Key Size / Curve
            + UINT8  # Not Used
            + UINT8  # SRK Flags
            + "4s"  # crypto_params_len
        )

    def update_fields(self) -> None:
        """Update all fields depended on input values."""
        if self.length <= 0:
            self.length = len(self)

    def export(self) -> bytes:
        """Export one SRK record, little big endian format.

        The crypto parameters (X/Y for ECDSA or modulus/exponent) are kept in
        big endian form.

        :return: bytes representing container content.
        """
        return (
            pack(
                self.format(),
                self.tag,
                self.length,
                self.version,
                self.hash_algorithm.tag,
                self.key_size,
                RESERVED,
                self.srk_flags,
                self.parameter_lengths,
            )
            + self.crypto_params
        )

    def _verify(self, name: str) -> Verifier:
        """Verify object data.

        :return: Verifier object with loaded all valid verification records
        """

        def verify_flags() -> Verifier:
            ver_flags = Verifier("Flags")
            ver_flags.add_record_bit_range("Range", self.srk_flags, 8)
            ver_flags.add_record(
                "CA flag", VerifierResult.SUCCEEDED, bool(self.srk_flags & self.FLAGS_CA_MASK)
            )
            return ver_flags

        def verify_key_size() -> None:
            if self.signing_algorithm in (
                self.SIGN_ALGORITHM_ENUM.RSA,
                self.SIGN_ALGORITHM_ENUM.RSA_PSS,
            ):  # Signing algorithm RSA
                if self.key_size not in self.RSA_KEY_TYPE.values():
                    ret.add_record(
                        "Key size",
                        VerifierResult.ERROR,
                        f"Invalid Key size in match to RSA signing algorithm: {self.key_size}",
                    )
            elif (
                self.signing_algorithm == self.SIGN_ALGORITHM_ENUM.ECDSA
            ):  # Signing algorithm ECDSA
                if self.key_size not in self.ECC_KEY_TYPE.values():
                    ret.add_record(
                        "Key size",
                        VerifierResult.ERROR,
                        f"Invalid Key size in match to ECDSA signing algorithm: {self.key_size}",
                    )
            elif self.signing_algorithm == self.SIGN_ALGORITHM_ENUM.SM2:  # Signing algorithm SM2
                if self.key_size != self.SM2_KEY_TYPE:
                    ret.add_record(
                        "Key size",
                        VerifierResult.ERROR,
                        f"Invalid Key size in match to SM2 signing algorithm: {self.key_size}",
                    )
            else:
                ret.add_record("Key size", VerifierResult.SUCCEEDED, self.key_size)

        ret = Verifier(name, description="")
        key_sizes = self.key_sizes
        ret.add_child(self.verify_parsed_header())
        ret.add_child(self.verify_header())
        ret.add_record_enum("Signing algorithm", self.signing_algorithm, self.SIGN_ALGORITHM_ENUM)
        ret.add_child(verify_flags())
        ret.add_record_enum("Signing hash algorithm", self.hash_algorithm, self.HASH_ALGORITHM_ENUM)
        ret.add_record_range("Crypto parameter 1 length", key_sizes[0], 32, 2592)
        ret.add_record_range("Crypto parameter 2 length", key_sizes[1], 0, 66)
        verify_key_size()
        return ret

    def verify(self, name: str) -> Verifier:
        """Verify object data.

        :return: Verifier object with loaded all valid verification records
        """
        ret = self._verify(name)
        key_sizes = self.key_sizes

        computed_length = self.fixed_length() + key_sizes[0] + key_sizes[1]

        if self.length != computed_length:
            ret.add_record(
                "SRK Length",
                VerifierResult.ERROR,
                f"Length of SRK:{self.length}" f", Required Length of SRK:{computed_length}",
            )

        return ret

    @classmethod
    def create_from_key(
        cls,
        public_key: PublicKey,
        srk_flags: int = 0,
        srk_id: int = 0,
        hash_algorithm: Optional[AHABSignHashAlgorithm] = None,
        legacy_rsa_exponent_size: bool = False,
    ) -> Self:
        """Create instance from key data.

        :param public_key: Loaded public key.
        :param srk_flags: SRK flags for key.
        :param srk_id: Index of key in SRK table
        :param hash_algorithm: Optional hash algorithm to use, if None default will be selected based on key type
        :param legacy_rsa_exponent_size: Use legacy 4-byte RSA exponent size for backward compatibility.
        :raises SPSDKValueError: Unsupported keys size is detected.
        :raises SPSDKUnsupportedOperation: Unsupported public key
        """
        if hasattr(public_key, "ca"):
            srk_flags |= cls.FLAGS_CA_MASK

        if isinstance(public_key, PublicKeyRsa):
            par_n: int = public_key.public_numbers.n
            par_e: int = public_key.public_numbers.e
            key_size = cls.RSA_KEY_TYPE[public_key.key_size]

            # Determine exponent size based on legacy mode
            if legacy_rsa_exponent_size:
                actual_e_size = 4  # Use legacy 4-byte size
                logger.info("Using legacy 4-byte RSA exponent size for backward compatibility")
            else:
                actual_e_size = math.ceil(par_e.bit_length() / 8)
                if actual_e_size != 4:
                    logger.info(
                        f"RSA exponent size is {actual_e_size} bytes (not the legacy 4 bytes). "
                        f"If you previously used older SPSDK versions and need backward compatibility, "
                        f"consider using the 'rsa_exponent_legacy_size: true' option in your configuration."
                    )
            return cls(
                src_key=public_key,
                signing_algorithm=cls.SIGN_ALGORITHM_ENUM.RSA_PSS,
                hash_type=hash_algorithm or cls.HASH_ALGORITHM_ENUM.SHA256,
                key_size=key_size,
                srk_flags=srk_flags,
                crypto_params=par_n.to_bytes(
                    length=cls.KEY_SIZES[key_size][0], byteorder=Endianness.BIG.value
                )
                + par_e.to_bytes(length=actual_e_size, byteorder=Endianness.BIG.value),
                legacy_rsa_exponent_size=legacy_rsa_exponent_size,
            )

        if isinstance(public_key, PublicKeyEcc):
            par_x: int = public_key.x
            par_y: int = public_key.y
            key_size = cls.ECC_KEY_TYPE[public_key.curve]

            if public_key.key_size not in [256, 384, 521]:
                raise SPSDKValueError(
                    f"Unsupported ECC key for AHAB container: {public_key.key_size}"
                )
            if hash_algorithm:
                hash_type = hash_algorithm
            else:
                hash_type = {
                    256: cls.HASH_ALGORITHM_ENUM.SHA256,
                    384: cls.HASH_ALGORITHM_ENUM.SHA384,
                    521: cls.HASH_ALGORITHM_ENUM.SHA512,
                }[public_key.key_size]

            return cls(
                signing_algorithm=cls.SIGN_ALGORITHM_ENUM.ECDSA,
                hash_type=hash_type,
                key_size=key_size,
                srk_flags=srk_flags,
                crypto_params=par_x.to_bytes(
                    length=cls.KEY_SIZES[key_size][0], byteorder=Endianness.BIG.value
                )
                + par_y.to_bytes(length=cls.KEY_SIZES[key_size][1], byteorder=Endianness.BIG.value),
            )

        if IS_OSCCA_SUPPORTED and isinstance(public_key, PublicKeySM2):
            param1: bytes = value_to_bytes("0x" + public_key.public_numbers[:64], byte_cnt=32)
            param2: bytes = value_to_bytes("0x" + public_key.public_numbers[64:], byte_cnt=32)
            if len(param1 + param2) != 64:
                raise SPSDKValueError("Invalid length of the SM2 key")
            key_size = cls.SM2_KEY_TYPE
            return cls(
                src_key=public_key,
                signing_algorithm=cls.SIGN_ALGORITHM_ENUM.SM2,
                hash_type=hash_algorithm or cls.HASH_ALGORITHM_ENUM.SM3,
                key_size=key_size,
                srk_flags=srk_flags,
                crypto_params=param1 + param2,
            )

        raise SPSDKUnsupportedOperation(f"Unsupported public key type: {type(public_key)}")

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse input binary chunk to the container object.

        :param data: Binary data with SRK record block to parse.
        :raises SPSDKLengthError: Invalid length of SRK record data block.
        :return: SRK record recreated from the binary data.
        """
        cls.check_container_head(data).validate()
        (
            _,  # tag
            container_length,
            signing_algo,
            hash_algo,
            key_size_curve,
            _,  # reserved
            srk_flags,
            parameters_len_raw,
        ) = unpack(cls.format(), data[: cls.fixed_length()])

        # Although we know from the total length, that we have enough bytes,
        # the crypto param lengths may be set improperly and we may get into trouble
        # while parsing. So we need to check the lengths as well.
        parameters_sizes = unpack(LITTLE_ENDIAN + UINT16 + UINT16, parameters_len_raw)
        parameters_len = cls._crypto_params_length(parameters_len_raw)
        cnt_len_computed = parameters_len + cls.fixed_length()
        if parameters_len + cls.fixed_length() > container_length:
            raise SPSDKLengthError(
                "Parsing error of SRK Record data."
                "SRK record lengths mismatch. Sum of lengths declared in container "
                f"({cnt_len_computed} (= {cls.fixed_length()} + "
                f"{parameters_len})) doesn't match total length declared in container ({container_length})!"
            )
        crypto_params = data[cls.fixed_length() : cls.fixed_length() + parameters_len]

        # For RSA keys, determine the actual exponent size

        if signing_algo in [cls.SIGN_ALGORITHM_ENUM.RSA, cls.SIGN_ALGORITHM_ENUM.RSA_PSS]:
            modulus_size = cls.KEY_SIZES[key_size_curve][0]
            # The exponent starts after the modulus
            exponent_data = crypto_params[modulus_size:]
            # Find the actual exponent size by removing any trailing zeros
            actual_exponent_size = len(exponent_data)

            # Create the SRK record with the actual exponent
            srk_rec = cls(
                signing_algorithm=cls.SIGN_ALGORITHM_ENUM.from_tag(signing_algo),
                hash_type=cls.HASH_ALGORITHM_ENUM.from_tag(hash_algo),
                key_size=key_size_curve,
                srk_flags=srk_flags,
                crypto_params=crypto_params[: modulus_size + actual_exponent_size],
            )
        else:
            # For non-RSA keys, use the existing approach
            srk_rec = cls(
                signing_algorithm=cls.SIGN_ALGORITHM_ENUM.from_tag(signing_algo),
                hash_type=cls.HASH_ALGORITHM_ENUM.from_tag(hash_algo),
                key_size=key_size_curve,
                srk_flags=srk_flags,
                crypto_params=crypto_params,
            )

        srk_rec.length = container_length
        srk_rec._param_lengths = parameters_sizes
        srk_rec._parsed_header = HeaderContainerData.parse(binary=data, inverted=True)
        return srk_rec

    def get_key_name(self) -> str:
        """Get text key name in SRK record.

        :return: Key name.
        """
        if self.signing_algorithm == self.SIGN_ALGORITHM_ENUM.RSA:
            return f"rsa{get_key_by_val(self.RSA_KEY_TYPE, self.key_size)}"
        if self.signing_algorithm == self.SIGN_ALGORITHM_ENUM.RSA_PSS:
            return f"rsa_pss{get_key_by_val(self.RSA_KEY_TYPE, self.key_size)}"
        if self.signing_algorithm == self.SIGN_ALGORITHM_ENUM.ECDSA:
            return get_key_by_val(self.ECC_KEY_TYPE, self.key_size)
        if self.signing_algorithm == self.SIGN_ALGORITHM_ENUM.SM2:
            return "sm2"
        if self.SIGN_ALGORITHM_ENUM == AHABSignAlgorithmV2:
            if self.signing_algorithm == self.SIGN_ALGORITHM_ENUM.DILITHIUM:
                return f"dilithium{get_key_by_val(self.DILITHIUM_KEY_TYPE, self.key_size)}"
            if self.signing_algorithm == self.SIGN_ALGORITHM_ENUM.ML_DSA:
                return f"mldsa{get_key_by_val(self.MLDSA_KEY_TYPE, self.key_size)}"

        return "Unknown Key name!"

    def get_public_key(self) -> PublicKey:
        """Recreate the SRK public key.

        :raises SPSDKError: Unsupported public key
        """
        raise NotImplementedError()


class SRKRecord(SRKRecordBase):
    """Class representing SRK (Super Root Key) record as part of SRK table in the AHAB container.

    The class holds information about RSA/ECDSA signing algorithms.

    SRK Record::

        +-----+---------------------------------------------------------------+
        |Off  |    Byte 3    |    Byte 2      |    Byte 1    |     Byte 0     |
        +-----+---------------------------------------------------------------+
        |0x00 |    Tag       |         Length of SRK         | Signing Algo   |
        +-----+---------------------------------------------------------------+
        |0x04 |    Hash Algo | Key Size/Curve |    Not Used  |   SRK Flags    |
        +-----+---------------------------------------------------------------+
        |0x08 | RSA modulus len / ECDSA X len | RSA exponent len / ECDSA Y len|
        +-----+---------------------------------------------------------------+
        |0x0C | RSA modulus (big endian) / ECDSA X (big endian)               |
        +-----+---------------------------------------------------------------+
        |...  | RSA exponent (big endian) / ECDSA Y (big endian)              |
        +-----+---------------------------------------------------------------+

    """

    SIGN_ALGORITHM_ENUM: TypeAlias = AHABSignAlgorithmV1
    HASH_ALGORITHM_ENUM: TypeAlias = AHABSignHashAlgorithmV1

    def __eq__(self, other: object) -> bool:
        if isinstance(other, type(self)):
            if (
                super().__eq__(other)
                and self.crypto_param1 == other.crypto_param1
                and self.crypto_param2 == other.crypto_param2
            ):
                return True

        return False

    def __str__(self) -> str:
        return super().__str__() + (
            f"  Param 1 value:      {bytes_to_print(self.crypto_param1)})\n"
            f"  Param 2 value:      {bytes_to_print(self.crypto_param2)})\n"
        )

    @property
    def crypto_param1(self) -> bytes:
        """Crypto parameter number 1."""
        return self.crypto_params[: self.KEY_SIZES[self.key_size][0]]

    @property
    def crypto_param2(self) -> bytes:
        """Crypto parameter number 2."""
        return self.crypto_params[self.KEY_SIZES[self.key_size][0] :]

    def verify(self, name: str) -> Verifier:
        """Verify object data.

        :return: Verifier object with loaded all valid verification records
        """

        def verify_param_lengths() -> None:
            key_sizes = self.key_sizes
            if self.crypto_param1 is None:
                ret.add_record("Crypto parameter 1", VerifierResult.ERROR, "Not exists")

            elif len(self.crypto_param1) != key_sizes[0]:
                ret.add_record(
                    "Crypto parameter 1",
                    VerifierResult.ERROR,
                    f"Invalid length: {len(self.crypto_param1)} != {key_sizes[0]}",
                )
            else:
                ret.add_record(
                    "Crypto parameter 1", VerifierResult.SUCCEEDED, self.crypto_param1.hex()
                )

            if self.crypto_param2 is None:
                ret.add_record("Crypto parameter 2", VerifierResult.ERROR, "Not exists")
            elif len(self.crypto_param2) != key_sizes[1]:
                ret.add_record(
                    "Crypto parameter 2",
                    VerifierResult.ERROR,
                    f"Invalid length: {len(self.crypto_param2)} != {key_sizes[1]}",
                )
            else:
                ret.add_record(
                    "Crypto parameter 2", VerifierResult.SUCCEEDED, self.crypto_param2.hex()
                )

        ret = super().verify(name)
        verify_param_lengths()

        try:
            public_key = self.get_public_key()
            ret.add_record("Restore public key", VerifierResult.SUCCEEDED, str(public_key))
        except SPSDKError as exc:
            ret.add_record("Restore public key", VerifierResult.WARNING, str(exc.description))

        return ret

    def get_public_key(self) -> PublicKey:
        """Recreate the SRK public key.

        :raises SPSDKError: Unsupported public key
        """
        par1 = int.from_bytes(self.crypto_param1, Endianness.BIG.value)
        par2 = int.from_bytes(self.crypto_param2, Endianness.BIG.value)

        if self.signing_algorithm in [
            self.SIGN_ALGORITHM_ENUM.RSA,
            self.SIGN_ALGORITHM_ENUM.RSA_PSS,
        ]:
            # RSA Key to store
            return PublicKeyRsa.recreate(modulus=par1, exponent=par2)

        if self.signing_algorithm == self.SIGN_ALGORITHM_ENUM.ECDSA:
            # ECDSA Key to store
            curve = get_key_by_val(self.ECC_KEY_TYPE, self.key_size)
            return PublicKeyEcc.recreate(par1, par2, curve=curve)

        if self.signing_algorithm == self.SIGN_ALGORITHM_ENUM.SM2 and IS_OSCCA_SUPPORTED:
            return PublicKeySM2.recreate(self.crypto_param1 + self.crypto_param2)

        raise SPSDKUnsupportedOperation("Unsupported public key type")


class SRKRecordV2(SRKRecordBase):
    """Class representing SRK (Super Root Key) record Version 2 as part of SRK table in the AHAB container.

    The class holds information about RSA/ECDSA/Dilithium signing algorithms.

    SRK Record V2::

        +-----+---------------------------------------------------------------+
        |Off  |    Byte 3    |    Byte 2      |    Byte 1    |     Byte 0     |
        +-----+---------------------------------------------------------------+
        |0x00 |    Tag       |         Length of SRK         | Signing Algo   |
        +-----+---------------------------------------------------------------+
        |0x04 |    Hash Algo | Key Size/Curve |    Not Used  |   SRK Flags    |
        +-----+---------------------------------------------------------------+
        |0x08 | RSA modulus len / ECDSA X len | RSA exponent len / ECDSA Y len|
        |     |                Dilithium Raw keys length                      |
        +-----+---------------------------------------------------------------+
        |0x0C |           Hash of public Key (SRK data) 512 Bits              |
        |0x4B |                                                               |
        +-----+---------------------------------------------------------------+

    """

    CRYPTO_PARAMS_LEN = 64
    DIFF_ATTRIBUTES_OBJECTS = ["srk_data"]

    def __init__(
        self,
        src_key: Optional[PublicKey] = None,
        signing_algorithm: AHABSignAlgorithmV2 = AHABSignAlgorithmV2.RSA_PSS,
        hash_type: AHABSignHashAlgorithmV2 = AHABSignHashAlgorithmV2.SHA256,
        key_size: int = 0,
        srk_flags: int = 0,
        crypto_params: bytes = b"",
        legacy_rsa_exponent_size: bool = False,
    ):
        """Class object initializer.

        :param src_key: Optional source public key used to create the SRKRecord
        :param signing_algorithm: signing algorithm type.
        :param hash_type: hash algorithm type.
        :param key_size: key (curve) size.
        :param srk_flags: flags.
        :param crypto_params: RSA modulus (big endian) or ECDSA X (big endian) or Hash of SRK data.
        """
        super().__init__(
            src_key,
            signing_algorithm,
            hash_type,
            key_size,
            srk_flags,
            crypto_params,
            legacy_rsa_exponent_size,
        )
        self.srk_data: Optional[SRKData] = None

    def __eq__(self, other: object) -> bool:
        if isinstance(other, type(self)):
            if super().__eq__(other) and self.crypto_params == other.crypto_params:
                return True

        return False

    def __str__(self) -> str:
        return super().__str__() + f"  SRK Data Hash:      {bytes_to_print(self.crypto_params)}\n"

    @property
    def srk_data_hash(self) -> bytes:
        """SRK Data Hash value."""
        return self.crypto_params

    @classmethod
    def _crypto_params_length(cls, parameter_lengths: bytes) -> int:
        """Decode crypto parameters length.

        :return: Length of crypto parameters.
        """
        # In case of SRK record version 2 the is fixed value of SRK Data container HASH of 512 bits
        return cls.CRYPTO_PARAMS_LEN

    def compute_srk_data_hash(self, srk_data: "SRKData") -> bytes:
        """Compute Hash of SRK data.

        :param srk_data: SRK data block.
        :return: Hash extended to 512 bits of SRK Data.
        """
        return extend_block(
            get_hash(
                data=srk_data.export(),
                algorithm=EnumHashAlgorithm.from_label(self.hash_algorithm.label),
            ),
            length=self.CRYPTO_PARAMS_LEN,
            padding=RESERVED,
        )

    def update_fields(self) -> None:
        """Update all fields depended on input values."""
        # Compute hash block if empty
        if self.srk_data:
            self.srk_data.update_fields()
            if not self.crypto_params:
                self.crypto_params = self.compute_srk_data_hash(self.srk_data)

        super().update_fields()

    def verify(self, name: str) -> Verifier:
        """Verify object data.

        :return: Verifier object with loaded all valid verification records
        """

        def verify_param_lengths() -> None:
            assert isinstance(self.srk_data, SRKData)
            key_sizes = self.key_sizes

            if self.signing_algorithm in [
                self.SIGN_ALGORITHM_ENUM.RSA,
                self.SIGN_ALGORITHM_ENUM.RSA_PSS,
            ]:
                # For RSA keys, use actual sizes
                modulus_size = key_sizes[0]
                crypto_param1 = self.srk_data.data[:modulus_size]
                crypto_param2 = self.srk_data.data[modulus_size:]

                if len(crypto_param1) != modulus_size:
                    ret.add_record(
                        "SRK Data Crypto parameter 1",
                        VerifierResult.ERROR,
                        f"Invalid length: {len(crypto_param1)} != {modulus_size}",
                    )
                else:
                    ret.add_record(
                        "SRK Data Crypto parameter 1",
                        VerifierResult.SUCCEEDED,
                        bytes_to_print(crypto_param1),
                    )

                if crypto_param2:
                    # For RSA keys, get the actual exponent
                    actual_e_size = len(crypto_param2)
                    ret.add_record_range(
                        "Crypto parameter 2", min_val=1, max_val=65535, value=actual_e_size
                    )
                else:
                    ret.add_record(
                        "SRK Data Crypto parameter 2", VerifierResult.ERROR, "Not exists"
                    )
            else:
                # For non-RSA keys, use fixed sizes
                crypto_param1 = self.srk_data.data[: key_sizes[0]]
                crypto_param2 = self.srk_data.data[key_sizes[0] :]

                if crypto_param1 is None:
                    ret.add_record(
                        "SRK Data Crypto parameter 1", VerifierResult.ERROR, "Not exists"
                    )
                elif len(crypto_param1) != key_sizes[0]:
                    ret.add_record(
                        "SRK Data Crypto parameter 1",
                        VerifierResult.ERROR,
                        f"Invalid length: {len(crypto_param1)} != {key_sizes[0]}",
                    )
                else:
                    ret.add_record(
                        "SRK Data Crypto parameter 1",
                        VerifierResult.SUCCEEDED,
                        bytes_to_print(crypto_param1),
                    )

                if key_sizes[1]:
                    if crypto_param2 is None:
                        ret.add_record(
                            "SRK Data Crypto parameter 2", VerifierResult.ERROR, "Not exists"
                        )
                    elif len(crypto_param2) != key_sizes[1]:
                        ret.add_record(
                            "SRK Data Crypto parameter 2",
                            VerifierResult.ERROR,
                            f"Invalid length: {len(crypto_param2)} != {key_sizes[1]}",
                        )
                    else:
                        ret.add_record(
                            "SRK Data Crypto parameter 2",
                            VerifierResult.SUCCEEDED,
                            bytes_to_print(crypto_param2),
                        )

        ret = self._verify(name)
        ret.add_record_range(
            "SRK Data Hash Length",
            len(self.crypto_params),
            self.CRYPTO_PARAMS_LEN,
            self.CRYPTO_PARAMS_LEN,
        )
        if self.srk_data:
            verify_param_lengths()
            ret.add_record(
                "SRK Data Hash",
                self.srk_data_hash == self.compute_srk_data_hash(self.srk_data),
                self.srk_data_hash.hex(),
            )
            try:
                public_key = self.get_public_key()
                ret.add_record("Restore public key", VerifierResult.SUCCEEDED, str(public_key))
            except SPSDKUnsupportedOperation as exc:
                ret.add_record("Restore public key", VerifierResult.WARNING, str(exc.description))
            except SPSDKError as exc:
                ret.add_record("Restore public key", VerifierResult.ERROR, str(exc.description))

        return ret

    @classmethod
    def create_from_key(
        cls,
        public_key: PublicKey,
        srk_flags: int = 0,
        srk_id: int = 0,
        hash_algorithm: Optional[AHABSignHashAlgorithm] = None,
        legacy_rsa_exponent_size: bool = False,
    ) -> Self:
        """Create instance from key data.

        :param public_key: Loaded public key.
        :param srk_flags: SRK flags for key.
        :param srk_id: Index of key in SRK table
        :param hash_algorithm: Optional hash algorithm to use, if None default will be selected based on key type
        :param legacy_rsa_exponent_size: Use legacy 4-byte RSA exponent size for backward compatibility.
        :raises SPSDKValueError: Unsupported keys size is detected.
        :raises SPSDKUnsupportedOperation: Unsupported key type or operation.
        """
        if hash_algorithm:
            assert isinstance(
                hash_algorithm, AHABSignHashAlgorithmV2
            ), "Invalid hash algorithm type"

        signing_algorithm = None
        hash_type = cls.HASH_ALGORITHM_ENUM.SHA256
        key_size = 0

        if hasattr(public_key, "ca"):
            srk_flags |= cls.FLAGS_CA_MASK

        if isinstance(public_key, PublicKeyRsa):
            signing_algorithm = cls.SIGN_ALGORITHM_ENUM.RSA_PSS
            hash_type = hash_algorithm or cls.HASH_ALGORITHM_ENUM.SHA256
            key_size = cls.RSA_KEY_TYPE[public_key.key_size]

        elif isinstance(public_key, PublicKeyEcc):
            signing_algorithm = cls.SIGN_ALGORITHM_ENUM.ECDSA
            key_size = cls.ECC_KEY_TYPE[public_key.curve]

            if public_key.key_size not in [256, 384, 521]:
                raise SPSDKValueError(
                    f"Unsupported ECC key for AHAB container: {public_key.key_size}"
                )
            if hash_algorithm:
                hash_type = hash_algorithm
            else:
                hash_type = {
                    256: cls.HASH_ALGORITHM_ENUM.SHA256,
                    384: cls.HASH_ALGORITHM_ENUM.SHA384,
                    521: cls.HASH_ALGORITHM_ENUM.SHA512,
                }[public_key.key_size]

        elif IS_OSCCA_SUPPORTED and isinstance(public_key, PublicKeySM2):
            signing_algorithm = cls.SIGN_ALGORITHM_ENUM.SM2
            hash_type = hash_algorithm or cls.HASH_ALGORITHM_ENUM.SM3
            key_size = cls.SM2_KEY_TYPE

        elif IS_DILITHIUM_SUPPORTED and isinstance(public_key, PublicKeyDilithium):
            signing_algorithm = cls.SIGN_ALGORITHM_ENUM.DILITHIUM
            key_size = cls.DILITHIUM_KEY_TYPE[public_key.level]
            if hash_algorithm:
                hash_type = hash_algorithm
            else:
                hash_type = {
                    3: cls.HASH_ALGORITHM_ENUM.SHA384,
                    5: cls.HASH_ALGORITHM_ENUM.SHA512,
                }[public_key.level]
        elif IS_DILITHIUM_SUPPORTED and isinstance(public_key, PublicKeyMLDSA):
            signing_algorithm = cls.SIGN_ALGORITHM_ENUM.ML_DSA
            try:
                key_size = cls.DILITHIUM_KEY_TYPE[public_key.level]
            except KeyError as exc:
                raise SPSDKUnsupportedOperation(
                    f"Unsupported ML-DSA key level: {public_key.level}"
                ) from exc
            if hash_algorithm:
                hash_type = hash_algorithm
            else:
                hash_type = {
                    3: cls.HASH_ALGORITHM_ENUM.SHA384,
                    5: cls.HASH_ALGORITHM_ENUM.SHA512,
                }[public_key.level]

        else:
            raise SPSDKValueError("Unsupported public key by AHAB SPSDK support.")

        ret = cls(
            src_key=public_key,
            signing_algorithm=signing_algorithm,
            hash_type=hash_type,
            key_size=key_size,
            srk_flags=srk_flags,
            legacy_rsa_exponent_size=legacy_rsa_exponent_size,
        )
        ret.srk_data = SRKData.create_from_key(
            public_key=public_key, srk_id=srk_id, legacy_rsa_exponent_size=legacy_rsa_exponent_size
        )

        return ret

    def get_public_key(self) -> PublicKey:
        """Recreate the SRK public key.

        :raises SPSDKError: Unsupported public key
        """
        if self.srk_data is None:
            raise SPSDKError("Cannot recreate public key due missing SRK Data")

        if self.signing_algorithm in [
            self.SIGN_ALGORITHM_ENUM.RSA,
            self.SIGN_ALGORITHM_ENUM.RSA_PSS,
        ]:
            # For RSA keys, we need to use the actual key sizes, not the default
            modulus_size = self.KEY_SIZES[self.key_size][0]
            crypto_param1 = self.srk_data.data[:modulus_size]
            crypto_param2 = self.srk_data.data[modulus_size:]

            par1 = int.from_bytes(crypto_param1, Endianness.BIG.value)
            par2 = int.from_bytes(crypto_param2, Endianness.BIG.value)

            return PublicKeyRsa.recreate(modulus=par1, exponent=par2)

        # For non-RSA keys, use the fixed sizes from KEY_SIZES
        crypto_param1 = self.srk_data.data[: self.KEY_SIZES[self.key_size][0]]
        crypto_param2 = self.srk_data.data[self.KEY_SIZES[self.key_size][0] :]
        par1 = int.from_bytes(crypto_param1, Endianness.BIG.value)
        par2 = int.from_bytes(crypto_param2, Endianness.BIG.value)

        if self.signing_algorithm == self.SIGN_ALGORITHM_ENUM.ECDSA:
            # ECDSA Key to store
            curve = get_key_by_val(self.ECC_KEY_TYPE, self.key_size)
            return PublicKeyEcc.recreate(par1, par2, curve=curve)

        if self.signing_algorithm == self.SIGN_ALGORITHM_ENUM.SM2 and IS_OSCCA_SUPPORTED:
            return PublicKeySM2.recreate(self.srk_data.data)

        if self.signing_algorithm == self.SIGN_ALGORITHM_ENUM.DILITHIUM and IS_DILITHIUM_SUPPORTED:
            return PublicKeyDilithium.parse(self.srk_data.data)
        if self.signing_algorithm == self.SIGN_ALGORITHM_ENUM.ML_DSA and IS_DILITHIUM_SUPPORTED:
            return PublicKeyMLDSA.parse(self.srk_data.data)

        if self.signing_algorithm == self.SIGN_ALGORITHM_ENUM.ML_DSA and IS_DILITHIUM_SUPPORTED:
            return PublicKeyMLDSA.parse(self.srk_data.data)

        if self.signing_algorithm == self.SIGN_ALGORITHM_ENUM.ML_DSA and IS_DILITHIUM_SUPPORTED:
            return PublicKeyMLDSA.parse(self.srk_data.data)

        if self.signing_algorithm == self.SIGN_ALGORITHM_ENUM.ML_DSA and IS_DILITHIUM_SUPPORTED:
            return PublicKeyMLDSA.parse(self.srk_data.data)

        raise SPSDKUnsupportedOperation("Unsupported public key type")


class SRKData(HeaderContainer):
    """Class representing SRK (Super Root Key) data as part of SRK table in the AHAB container.

    The class holds information about RSA/ECDSA/Dilithium signing algorithms.

    SRK Data::

        +-----+---------------------------------------------------------------+
        |Off  |    Byte 3    |    Byte 2      |    Byte 1    |     Byte 0     |
        +-----+---------------------------------------------------------------+
        |0x00 |    Tag       |      Length of SRK Data       |   Version      |
        +-----+---------------------------------------------------------------+
        |0x04 |                 Not Used                     |  SRK Record #  |
        +-----+---------------------------------------------------------------+
        |0x08 | Key data: Format depends on key type                          |
        |     | RSA modulus (big endian), RSA exponent (big endian)           |
        |     | ECDSA X (big endian), ECDSA Y (big endian)                    |
        |...  | Dilithium Raw key (Big endian)                                |
        +-----+---------------------------------------------------------------+

    """

    TAG = AHABTags.SRK_DATA.tag
    VERSION = 0
    DIFF_ATTRIBUTES_VALUES = ["srk_id", "data"]

    def __init__(self, srk_id: int, src_key: Optional[PublicKey] = None, data: bytes = b""):
        """Class object initializer.

        :param srk_id: Index of SRK record in SRK table to identified SRK Data
        :param src_key: Optional source public key used to create the SRKData
        :param data: RSA modulus (big endian) or ECDSA X (big endian) or Dilithium Raw data
        """
        super().__init__(
            tag=self.TAG,
            length=-1,
            version=self.VERSION,
        )
        self.srk_id = srk_id
        self.src_key = src_key
        self.data = data

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SRKData):
            return super().__eq__(other) and self.data == other.data and self.srk_id == other.srk_id
        return False

    def __len__(self) -> int:
        return super().__len__() + len(self.data)

    def __repr__(self) -> str:
        return f"AHAB SRK Data, key ID: {self.srk_id}"

    def __str__(self) -> str:
        return (
            "AHAB SRK Data:\n"
            f"  SRK ID:             {self.srk_id}\n"
            f"  Data length:        {len(self.data)}\n"
            f"  Data:               {self.data.hex()}\n"
        )

    @classmethod
    def format(cls) -> str:
        """Format of binary representation."""
        return super().format() + UINT16 + UINT8 + UINT8  # Reserved - Reserved - SRK ID

    def update_fields(self) -> None:
        """Update all fields depended on input values."""
        if self.length <= 0:
            self.length = len(self)

    def export(self) -> bytes:
        """Export one SRK data.

        The crypto parameters (X/Y for ECDSA or modulus/exponent for RSA or Raw data for Dilithium) are kept in
        big endian form.

        :return: bytes representing container content.
        """
        return (
            pack(
                self.format(),
                self.version,
                self.length,
                self.tag,
                self.srk_id,
                RESERVED,
                RESERVED,
            )
            + self.data
        )

    def verify(self, name: str) -> Verifier:
        """Verify object data.

        :return: Verifier object with loaded all valid verification records
        """
        ret = Verifier(name, description="")
        ret.add_child(self.verify_parsed_header())
        ret.add_child(self.verify_header())
        ret.add_record_range("SRK ID", self.srk_id, min_val=0, max_val=3)
        if self.data is None:
            ret.add_record("Data", VerifierResult.ERROR, "Not exists")
        else:
            ret.add_record("Data", VerifierResult.SUCCEEDED, self.data.hex())

        return ret

    @classmethod
    def create_from_key(
        cls, public_key: PublicKey, srk_id: int, legacy_rsa_exponent_size: bool = False
    ) -> Self:
        """Create instance from public key.

        :param public_key: Loaded public key.
        :param srk_id: SRK Identification 0-3.
        :param legacy_rsa_exponent_size: Use legacy 4-byte RSA exponent size for backward compatibility.
        :raises SPSDKValueError: Unsupported keys size is detected.
        """
        if isinstance(public_key, PublicKeyRsa):
            par_n: int = public_key.public_numbers.n
            par_e: int = public_key.public_numbers.e
            key_size = SRKRecordV2.RSA_KEY_TYPE[public_key.key_size]
            if legacy_rsa_exponent_size:
                actual_e_size = 4
                logger.info("Using legacy 4-byte RSA exponent size for SRK data")
            else:
                actual_e_size = math.ceil(par_e.bit_length() / 8)
            data = par_n.to_bytes(
                length=SRKRecordV2.KEY_SIZES[key_size][0], byteorder=Endianness.BIG.value
            ) + par_e.to_bytes(length=actual_e_size, byteorder=Endianness.BIG.value)
            return cls(src_key=public_key, srk_id=srk_id, data=data)

        if isinstance(public_key, PublicKeyEcc):
            par_x: int = public_key.x
            par_y: int = public_key.y
            key_size = SRKRecordV2.ECC_KEY_TYPE[public_key.curve]

            if public_key.key_size not in [256, 384, 521]:
                raise SPSDKValueError(
                    f"Unsupported ECC key for AHAB container: {public_key.key_size}"
                )
            data = par_x.to_bytes(
                length=SRKRecordV2.KEY_SIZES[key_size][0], byteorder=Endianness.BIG.value
            ) + par_y.to_bytes(
                length=SRKRecordV2.KEY_SIZES[key_size][1], byteorder=Endianness.BIG.value
            )
            return cls(src_key=public_key, srk_id=srk_id, data=data)

        if isinstance(public_key, PublicKeySM2):
            data = value_to_bytes(
                "0x" + public_key.public_numbers[:64], byte_cnt=32
            ) + value_to_bytes("0x" + public_key.public_numbers[64:], byte_cnt=32)
            if len(data) != 64:
                raise SPSDKValueError("Invalid length of the SM2 key")

            return cls(src_key=public_key, srk_id=srk_id, data=data)

        if isinstance(public_key, (PublicKeyDilithium, PublicKeyMLDSA)):
            data = public_key.public_numbers
            return cls(src_key=public_key, srk_id=srk_id, data=data)

        raise SPSDKValueError(f"Unsupported public key for SRK data: {type(public_key)}")

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse input binary chunk to the container object.

        :param data: Binary data with SRK record block to parse.
        :raises SPSDKLengthError: Invalid length of SRK record data block.
        :return: SRK record recreated from the binary data.
        """
        cls.check_container_head(data).validate()
        (_, container_length, _, srk_id, _, _) = unpack(  # version  # tag  # Reserved  # Reserved
            cls.format(), data[: cls.fixed_length()]
        )

        data_length = container_length - cls.fixed_length()
        data = data[cls.fixed_length() : cls.fixed_length() + data_length]

        srk_rec = cls(src_key=None, srk_id=srk_id, data=data)
        srk_rec.length = container_length
        srk_rec._parsed_header = HeaderContainerData.parse(binary=data)
        return srk_rec


class SRKTable(HeaderContainerInverted):
    """Class representing SRK (Super Root Key) table in the AHAB container as part of signature block.

    SRK Table::

        +-----+---------------------------------------------------------------+
        |Off  |    Byte 3    |    Byte 2      |    Byte 1    |     Byte 0     |
        +-----+---------------------------------------------------------------+
        |0x00 |   Version    |         Length of SRK Table   |      Tag       |
        +-----+---------------------------------------------------------------+
        |0x04 |    SRK Record 1                                               |
        +-----+---------------------------------------------------------------+
        |...  |    SRK Record 2                                               |
        +-----+---------------------------------------------------------------+
        |...  |    SRK Record 3                                               |
        +-----+---------------------------------------------------------------+
        |...  |    SRK Record 4                                               |
        +-----+---------------------------------------------------------------+

    """

    TAG = AHABTags.SRK_TABLE.tag
    VERSION = 0x42
    SRK_HASH_ALGORITHM = EnumHashAlgorithm.SHA256
    SRK_RECORDS_CNT = 4
    SRK_RECORD = SRKRecord
    DIFF_ATTRIBUTES_OBJECTS = ["srk_records"]

    def __init__(self, srk_records: Optional[Sequence[SRKRecordBase]] = None) -> None:
        """Class object initializer.

        :param srk_records: list of SRK Record objects.
        """
        super().__init__(tag=self.TAG, length=-1, version=self.VERSION)
        self.srk_records: list[SRKRecordBase] = list(srk_records) if srk_records else []

    def __repr__(self) -> str:
        return f"AHAB SRK TABLE, keys count: {len(self.srk_records)}"

    def __str__(self) -> str:
        return (
            "AHAB SRK table:\n"
            f"  Keys count:         {len(self.srk_records)}\n"
            f"  Length:             {self.length}\n"
            f"SRK table HASH:       {self.compute_srk_hash().hex()}"
        )

    def clear(self) -> None:
        """Clear the SRK Table Object."""
        self.srk_records.clear()
        self.length = -1

    def add_record(
        self,
        public_key: PublicKey,
        srk_flags: int = 0,
        srk_id: int = 0,
        hash_algorithm: Optional[AHABSignHashAlgorithm] = None,
        legacy_rsa_exponent_size: bool = False,
    ) -> None:
        """Add SRK table record.

        :param public_key: Loaded public key.
        :param srk_flags: SRK flags for key.
        :param srk_id: Index of key in SRK table
        :param hash_algorithm: Optional hash algorithm to use
        :param legacy_rsa_exponent_size: Use legacy 4-byte RSA exponent size for backward compatibility.
        """
        self.srk_records.append(
            self.SRK_RECORD.create_from_key(
                public_key=public_key,
                srk_flags=srk_flags,
                srk_id=srk_id,
                hash_algorithm=hash_algorithm,
                legacy_rsa_exponent_size=legacy_rsa_exponent_size,
            )
        )

    def __eq__(self, other: object) -> bool:
        """Compares for equality with other SRK Table objects.

        :param other: object to compare with.
        :return: True on match, False otherwise.
        """
        if isinstance(other, SRKTable):
            if super().__eq__(other) and self.srk_records == other.srk_records:
                return True

        return False

    def __bool__(self) -> bool:
        """Check existence."""
        return bool(len(self.srk_records))

    def __len__(self) -> int:
        records_len = 0
        for record in self.srk_records:
            records_len += len(record)
        return super().__len__() + records_len

    @property
    def srk_count(self) -> int:
        """Get count of used signatures in container."""
        return 1

    def update_fields(self) -> None:
        """Update all fields depended on input values."""
        for rec in self.srk_records:
            rec.update_fields()
        if self.length <= 0:
            self.length = len(self)

    def compute_srk_hash(self, srk_id: int = 0) -> bytes:
        """Computes a SHA256 out of all SRK records.

        :param srk_id: ID of SRK table in case of using multiple Signatures, default is 0.
        :return: SHA256 computed over SRK records.
        """
        return get_hash(data=self.export(), algorithm=self.SRK_HASH_ALGORITHM)

    def get_source_keys(self) -> list[PublicKey]:
        """Return list of source public keys.

        Either from the src_key field or recreate them.
        :return: List of public keys.
        """
        ret = []
        for srk in self.srk_records:
            if srk.src_key:
                # return src key if available
                ret.append(srk.src_key)
            else:
                # recreate the key
                ret.append(srk.get_public_key())
        return ret

    def export(self) -> bytes:
        """Export SRK table data as bytes.

        :return: Bytes representation of SRK table.
        """
        data = pack(self.format(), self.tag, self.length, self.version)

        for srk_record in self.srk_records:
            data += srk_record.export()

        return data

    def verify(self) -> Verifier:
        """Verify SRK table data."""

        def verify_count_of_records() -> None:
            if self.srk_records is None:
                ret.add_record("Count", VerifierResult.ERROR, "Not exists records")
            elif len(self.srk_records) != self.SRK_RECORDS_CNT:
                ret.add_record(
                    "Count",
                    VerifierResult.ERROR,
                    f"Invalid {len(self.srk_records)} != {self.SRK_RECORDS_CNT}",
                )
            else:
                ret.add_record("Count", VerifierResult.SUCCEEDED, self.SRK_RECORDS_CNT)

        ret = Verifier("SRK table", description="")
        ret.add_child(self.verify_parsed_header())
        ret.add_child(self.verify_header())
        verify_count_of_records()

        # Validate individual SRK records
        for i, srk_rec in enumerate(self.srk_records):
            ret.add_child(srk_rec.verify(f"SRK record[{i}]"))

        # Check if all SRK records has same type
        srk_records_info = [
            (x.version, x.hash_algorithm.tag, x.key_size, x.length, x.srk_flags)
            for x in self.srk_records
        ]

        messages = ["Signing algorithm", "Hash algorithm", "Key Size", "Length", "Flags"]
        for i in range(len(srk_records_info[0])):
            values = [record[i] for record in srk_records_info]
            if len(set(values)) == 1:
                ret.add_record(messages[i], VerifierResult.SUCCEEDED, "Is same in all SRK records")
            else:
                ret.add_record(messages[i], VerifierResult.ERROR, "Is not same in all SRK records")

        ret.add_record_bytes("SRK Hash", self.compute_srk_hash())

        return ret

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse input binary chunk to the container object.

        :param data: Binary data with SRK table block to parse.
        :raises SPSDKLengthError: Invalid length of SRK table data block.
        :return: Object recreated from the binary data.
        """
        cls.check_container_head(data).validate()
        srk_rec_offset = cls.fixed_length()
        _, container_length, _ = unpack(cls.format(), data[:srk_rec_offset])
        if ((container_length - srk_rec_offset) % cls.SRK_RECORDS_CNT) != 0:
            raise SPSDKLengthError("SRK table: Invalid length of SRK records data.")
        srk_rec_size = math.ceil((container_length - srk_rec_offset) / cls.SRK_RECORDS_CNT)

        # try to parse records
        srk_records = []
        for _ in range(cls.SRK_RECORDS_CNT):
            srk_record = cls.SRK_RECORD.parse(data[srk_rec_offset:])
            srk_rec_offset += srk_rec_size
            srk_records.append(srk_record)

        srk_table = cls(srk_records=srk_records)
        srk_table.length = container_length
        srk_table._parsed_header = HeaderContainerData.parse(binary=data, inverted=True)
        return srk_table

    @classmethod
    def pre_parse_verify(cls, data: bytes) -> Verifier:
        """Pre-Parse verify of AHAB SRK table Block.

        :param data: Binary data with SRK table block to pre-parse.
        :return: Verifier of pre-parsed binary data.
        """
        ret = cls.check_container_head(data)
        if ret.has_errors:
            return ret
        srk_rec_offset = SRKTable.fixed_length()
        _, container_length, _ = unpack(SRKTable.format(), data[:srk_rec_offset])
        ret.add_record(
            "SRK Table length alignment",
            ((container_length - srk_rec_offset) % SRKTable.SRK_RECORDS_CNT) == 0,
        )
        if ret.has_errors:
            return ret
        srk_rec_size = math.ceil((container_length - srk_rec_offset) / SRKTable.SRK_RECORDS_CNT)

        # try to pre-parse records
        for _ in range(SRKTable.SRK_RECORDS_CNT):
            ret.add_child(cls.SRK_RECORD.check_container_head(data[srk_rec_offset:]))
            srk_rec_offset += srk_rec_size
        return ret

    def get_config(self, data_path: str, index: int) -> Config:
        """Create configuration of the AHAB Image SRK Table.

        :param data_path: Path to store the data files of configuration.
        :param index: Container Index.
        :return: Configuration dictionary.
        """
        ret_cfg = Config()
        cfg_srk_records = []

        ret_cfg["flag_ca"] = bool(self.srk_records[0].srk_flags & self.SRK_RECORD.FLAGS_CA_MASK)

        for ix_srk, srk in enumerate(self.srk_records):
            filename = f"container{index}_srk_public_key{ix_srk}_{srk.get_key_name()}.pem"
            public_key = srk.get_public_key()
            write_file(
                data=public_key.export(public_key.RECOMMENDED_ENCODING),
                path=os.path.join(data_path, filename),
                mode="wb",
            )
            cfg_srk_records.append(filename)

        ret_cfg["srk_array"] = cfg_srk_records
        return ret_cfg

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Converts the configuration option into an AHAB image object.

        "config" content of container configurations.

        :param config: array of AHAB containers configuration dictionaries.
        :return: SRK Table object.
        """
        srk_table = cls()
        flags = 0
        # Allow user to provide flag_ca in configuration
        flag_ca = config.get("flag_ca", False)
        if flag_ca:
            flags |= cls.SRK_RECORD.FLAGS_CA_MASK

        # Get hash algorithm if specified
        hash_algorithm = None
        hash_algo_str = config.get("hash_algorithm")
        if hash_algo_str and hash_algo_str != "default":
            hash_algorithm = cls.SRK_RECORD.HASH_ALGORITHM_ENUM.from_label(hash_algo_str)

        # Get the legacy RSA exponent size option from config
        legacy_rsa_exponent_size = config.get("rsa_exponent_legacy_size", False)

        srk_list = config.get_list("srk_array")
        for srk_key in srk_list:
            assert isinstance(srk_key, str)
            srk_key_path = find_file(srk_key, search_paths=config.search_paths)
            pub_key = extract_public_key(srk_key_path)
            if hasattr(pub_key, "ca"):
                flags |= cls.SRK_RECORD.FLAGS_CA_MASK
            srk_table.add_record(
                pub_key,
                srk_flags=flags,
                hash_algorithm=hash_algorithm,
                legacy_rsa_exponent_size=legacy_rsa_exponent_size,
            )
        return srk_table


class SRKTableV2(SRKTable):
    """Class representing SRK (Super Root Key) table in the AHAB container.

    This is a new type of SRK Table that supports PQC keys and is part of SRK table array.


    SRK Table::

        +-----+---------------------------------------------------------------+
        |Off  |    Byte 3    |    Byte 2      |    Byte 1    |     Byte 0     |
        +-----+---------------------------------------------------------------+
        |0x00 |   Version    |         Length of SRK Table   |      Tag       |
        +-----+---------------------------------------------------------------+
        |0x04 |    SRK Record 1                                               |
        +-----+---------------------------------------------------------------+
        |...  |    SRK Record 2                                               |
        +-----+---------------------------------------------------------------+
        |...  |    SRK Record 3                                               |
        +-----+---------------------------------------------------------------+
        |...  |    SRK Record 4                                               |
        +-----+---------------------------------------------------------------+

    """

    VERSION = 0x43
    SRK_RECORD: TypeAlias = SRKRecordV2
    SRK_HASH_ALGORITHM = EnumHashAlgorithm.SHA512

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Converts the configuration option into an AHAB image object.

        "config" content of container configurations.

        :param config: array of AHAB containers configuration dictionaries.
        :return: SRK Table object.
        """
        srk_table = cls()
        flags = 0
        flag_ca = config.get("flag_ca", False)
        if flag_ca:
            flags |= cls.SRK_RECORD.FLAGS_CA_MASK

        # Get hash algorithm if specified
        hash_algorithm = None
        hash_algo_str = config.get("hash_algorithm")
        if hash_algo_str and hash_algo_str != "default":
            hash_algorithm = cls.SRK_RECORD.HASH_ALGORITHM_ENUM.from_label(hash_algo_str)

        # Get the legacy RSA exponent size option from config
        legacy_rsa_exponent_size = config.get("rsa_exponent_legacy_size", False)

        srk_list = config.get_list("srk_array")
        for ix, srk_key in enumerate(srk_list):
            assert isinstance(srk_key, str)
            srk_key_path = find_file(srk_key, search_paths=config.search_paths)
            pub_key = extract_public_key(srk_key_path)
            if hasattr(pub_key, "ca"):
                flags |= cls.SRK_RECORD.FLAGS_CA_MASK
            srk_table.add_record(
                pub_key,
                srk_flags=flags,
                srk_id=ix,
                hash_algorithm=hash_algorithm,
                legacy_rsa_exponent_size=legacy_rsa_exponent_size,
            )
            cast(SRKRecordV2, srk_table.srk_records[ix]).srk_data = SRKData.create_from_key(
                pub_key, ix
            )
        return srk_table

    def get_config(self, data_path: str, index: int, srk_table_index: int = 0) -> Config:
        """Create configuration of the AHAB Image SRK Table.

        :param data_path: Path to store the data files of configuration.
        :param index: Container Index.
        :param srk_table_index: SRK table index, default is 0.
        :return: Configuration dictionary.
        """
        ret_cfg = Config()
        cfg_srk_records = []

        ret_cfg["flag_ca"] = bool(self.srk_records[0].srk_flags & self.SRK_RECORD.FLAGS_CA_MASK)

        for ix_srk, srk in enumerate(self.srk_records):
            cfg_val = "Cannot re-create due missing SRK_DATA container."
            assert isinstance(srk, SRKRecordV2)
            if srk.srk_data:
                cfg_val = f"container{index}_srk_public_key{ix_srk}_{srk.get_key_name()}.pem"
                public_key = srk.get_public_key()
                write_file(
                    data=public_key.export(public_key.RECOMMENDED_ENCODING),
                    path=os.path.join(data_path, f"SRK_{srk_table_index}", cfg_val),
                    mode="wb",
                )
                cfg_val = f"SRK_{srk_table_index}/" + cfg_val
            cfg_srk_records.append(cfg_val)

        ret_cfg["srk_array"] = cfg_srk_records
        return ret_cfg


class SRKTableArray(HeaderContainer):
    """Class representing SRK (Super Root Key) table array in the AHAB container as part of signature block.

    SRK Table::

        +-----+---------------------------------------------------------------+
        |Off  |    Byte 3    |    Byte 2      |    Byte 1    |     Byte 0     |
        +-----+---------------------------------------------------------------+
        |0x00 |    Tag       |         Length of SRK Table   |     Version    |
        +-----+---------------------------------------------------------------+
        |0x00 |                   Reserved                   | # of SRK Tables|
        +-----+---------------------------------------------------------------+
        |0x04 |    SRK Table 0                                                |
        +-----+---------------------------------------------------------------+
        |...  |    SRK Data 0                                                 |
        +-----+---------------------------------------------------------------+
        |...  |    SRK Table 1 (Optional)                                     |
        +-----+---------------------------------------------------------------+
        |...  |    SRK Data 1 (Optional)                                      |
        +-----+---------------------------------------------------------------+

    """

    TAG = AHABTags.SRK_TABLE_ARRAY.tag
    VERSION = 0x00
    SRK_TABLE_MIN_CNT = 1
    SRK_TABLE_MAX_CNT = 2
    DIFF_ATTRIBUTES_OBJECTS = ["_srk_tables"]

    def __init__(
        self, chip_config: AhabChipContainerConfig, srk_tables: Optional[list[SRKTableV2]] = None
    ) -> None:
        """Class object initializer.

        :param chip_config: AHAB container chip configuration.
        :param srk_tables: list of SRK Tables V2 objects.
        """
        super().__init__(tag=self.TAG, length=-1, version=self.VERSION)
        self._srk_tables: list[SRKTableV2] = srk_tables or []
        self.chip_config = chip_config

    def __repr__(self) -> str:
        return f"AHAB SRK ARRAY, tables count: {len(self._srk_tables)}"

    def __str__(self) -> str:
        ret = (
            "AHAB SRK table array:\n"
            f"  SRK tables count:   {len(self._srk_tables)}\n"
            f"  Length:             {self.length}\n"
            f"SRK_0 table HASH:       {self.compute_srk_hash(0).hex()}"
        )
        if len(self._srk_tables) > 1:
            ret += f"\nSRK_1 table HASH:       {self.compute_srk_hash(1).hex()}"

        return ret

    def __eq__(self, other: object) -> bool:
        """Compares for equality with other SRK Table array objects.

        :param other: object to compare with.
        :return: True on match, False otherwise.
        """
        if isinstance(other, SRKTableArray):
            if super().__eq__(other) and self._srk_tables == other._srk_tables:
                return True

        return False

    def __bool__(self) -> bool:
        """Check existence."""
        return bool(self.srk_count)

    def __len__(self) -> int:
        tables_len = 0
        for table in self._srk_tables:
            tables_len += len(table)
            tables_len += len(
                cast(
                    SRKRecordV2, table.srk_records[self.chip_config.used_srk_id]
                ).srk_data  # type:ignore
            )

        return super().__len__() + tables_len

    @classmethod
    def format(cls) -> str:
        """Format of binary representation."""
        return super().format() + UINT8 + UINT16 + UINT8

    @property
    def srk_count(self) -> int:
        """Get count of used signatures in container."""
        return len(self._srk_tables)

    def update_fields(self) -> None:
        """Update all fields depended on input values."""
        for rec in self._srk_tables:
            rec.update_fields()
        if self.length <= 0:
            self.length = len(self)

    def compute_srk_hash(self, srk_id: int = 0) -> bytes:
        """Computes a SHA512 out of all SRK tables.

        :param srk_id: ID of SRK table in case of using multiple Signatures, default is 0.
        :return: SHA512 computed over SRK table.
        """
        if srk_id >= len(self._srk_tables):
            raise SPSDKValueError(f"The SRK ID({srk_id}) is out of range.")
        data = self._srk_tables[srk_id].export()
        return get_hash(data=data, algorithm=EnumHashAlgorithm.SHA512)

    def export(self) -> bytes:
        """Export SRK table array to bytes.

        :return: Bytes representation of SRK table array
        """
        data = pack(
            self.format(),
            self.version,
            self.length,
            self.tag,
            len(self._srk_tables),
            RESERVED,
            RESERVED,
        )

        for srk_table in self._srk_tables:
            data += srk_table.export()
            srk_record = cast(SRKRecordV2, srk_table.srk_records[self.chip_config.used_srk_id])
            assert isinstance(srk_record.srk_data, SRKData)
            data += srk_record.srk_data.export()

        return data

    def verify(self) -> Verifier:
        """Verify SRK table array data."""
        ret = Verifier("SRK table", description="")
        ret.add_child(self.verify_parsed_header())
        ret.add_child(self.verify_header())
        ret.add_record_range(
            "Tables count", len(self._srk_tables), self.SRK_TABLE_MIN_CNT, self.SRK_TABLE_MAX_CNT
        )

        # Validate individual SRK tables
        for i, srk_table in enumerate(self._srk_tables):
            ret.add_child(srk_table.verify(), prefix_name=f"SRK table[{i}] ")
            if i == self.chip_config.used_srk_id:
                srk_record = cast(SRKRecordV2, srk_table.srk_records[i])
                ret.add_record(f"SRK Data{i} exists", bool(srk_record.srk_data))

        return ret

    # pylint: disable=arguments-differ
    @classmethod
    def parse(cls, data: bytes, chip_config: AhabChipContainerConfig) -> Self:  # type: ignore[override]
        """Parse input binary chunk to the container object.

        :param data: Binary data with SRK table array block to parse.
        :param chip_config: AHAB container chip configuration.
        :return: Object recreated from the binary data.
        """
        SRKTableArray.check_container_head(data).validate()
        srk_tab_arr_header_size = SRKTableArray.fixed_length()
        _, container_length, _, tables_cnt, _, _ = unpack(
            cls.format(), data[:srk_tab_arr_header_size]
        )

        # try to parse tables and data
        header_offset = srk_tab_arr_header_size
        srk_tables: list[SRKTableV2] = []
        for i in range(tables_cnt):
            # Check the SRK table header
            srk_tables.append(SRKTableV2.parse(data[header_offset:]))
            header_offset += len(srk_tables[i])
            srk_data = SRKData.parse(data[header_offset:])
            srk_record = cast(SRKRecordV2, srk_tables[i].srk_records[srk_data.srk_id])
            srk_record.srk_data = srk_data
            header_offset += len(srk_data)

        srk_table_array = cls(chip_config=chip_config, srk_tables=srk_tables)
        srk_table_array.length = container_length
        srk_table_array._parsed_header = HeaderContainerData.parse(binary=data)
        return srk_table_array

    @classmethod
    def pre_parse_verify(cls, data: bytes) -> Verifier:
        """Pre-Parse verify of AHAB SRK table array Block.

        :param data: Binary data with SRK table block to pre-parse.
        :return: Verifier of pre-parsed binary data.
        """
        ret = cls.check_container_head(data)
        if ret.has_errors:
            return ret
        srk_tab_arr_header_size = cls.fixed_length()
        _, _, _, _, _, tables_cnt = unpack(cls.format(), data[:srk_tab_arr_header_size])
        header_offset = srk_tab_arr_header_size
        for _ in range(tables_cnt):
            # Check the SRK table header
            ret.add_child(SRKTableV2.pre_parse_verify(data[header_offset:]))
            if ret.has_errors:
                return ret
            _, srk_table_length, _ = SRKTableV2.parse_head(data[header_offset:])
            header_offset += srk_table_length
            # Check the SRK table header
            srk_data_tag, srk_data_length, srk_data_version = SRKData.parse_head(
                data[header_offset:]
            )
            ret.add_child(SRKData._verify_header(srk_data_tag, srk_data_length, srk_data_version))
            if ret.has_errors:
                return ret
            header_offset += srk_data_length

        return ret

    def get_config(self, data_path: str, index: int) -> Config:
        """Create configuration of the AHAB Image SRK Table.

        :param data_path: Path to store the data files of configuration.
        :param index: Container Index.
        :return: Configuration dictionary.
        """
        ret_cfg = Config()

        if len(self._srk_tables) > 0:
            ret_cfg = self._srk_tables[0].get_config(data_path, index, 0)
        if len(self._srk_tables) > 1:
            ret_cfg["srk_table_#2"] = self._srk_tables[1].get_config(data_path, index, 1)

        return ret_cfg

    @classmethod
    def load_from_config(cls, config: Config, chip_config: AhabChipContainerConfig) -> Self:
        """Converts the configuration option into an AHAB image object.

        "config" content of container configurations.

        :param config: array of AHAB containers configuration dictionaries.
        :param chip_config: AHAB container chip configuration.
        :return: SRK Table array object.
        """
        srk_table_array: list[SRKTableV2] = []
        srk_table_array.append(SRKTableV2.load_from_config(config))
        if "srk_table_#2" in config:
            srk_table_array.append(SRKTableV2.load_from_config(config.get_config("srk_table_#2")))

        return cls(chip_config=chip_config, srk_tables=srk_table_array)
