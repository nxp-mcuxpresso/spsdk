#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Implementation of AHAB container SRK (Super Root Keys) support."""

import logging
import math
import os
from struct import pack, unpack
from typing import Any, Optional, Union, cast

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
    KEY_SIZES = {
        0x1: (32, 32),  # PRIME256V1
        0x2: (48, 48),  # SEC384R1
        0x3: (66, 66),  # SEC521R1
        0x5: (256, 4),  # RSA2048
        0x6: (384, 4),  # RSA3072
        0x7: (512, 4),  # RSA4096
        0x8: (32, 32),  # SM2
        0x9: (1952, 0),  # Dilithium 3 / ML-DSA-65
        0xA: (2592, 0),  # Dilithium 5 / ML-DSA-87
    }

    FLAGS_CA_MASK = 0x80

    def __init__(
        self,
        src_key: Optional[PublicKey] = None,
        signing_algorithm: AHABSignAlgorithm = SIGN_ALGORITHM_ENUM.RSA_PSS,
        hash_type: AHABSignHashAlgorithm = HASH_ALGORITHM_ENUM.SHA256,
        key_size: int = 0,
        srk_flags: int = 0,
        crypto_params: bytes = b"",
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
            tag=self.TAG,
            length=-1,
            version=signing_algorithm.tag,
        )
        self.src_key = src_key
        self.hash_algorithm = hash_type
        self.key_size = key_size
        self.srk_flags = srk_flags
        self.crypto_params = crypto_params

    @property
    def parameter_lengths(self) -> bytes:
        """Parameter lengths field.

        :return: Created parameter lengths field from the key parameter
        """
        if self.key_size not in self.KEY_SIZES:
            raise SPSDKError(f"Key size value is not supported: {self.key_size}")
        key_sizes = self.KEY_SIZES[self.key_size]
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
        """Get signing algorithm."""
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
            f"  Crypto param value: {self.crypto_params.hex()})\n"
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
        ret.add_child(self.verify_parsed_header())
        ret.add_child(self.verify_header())
        ret.add_record_enum("Signing algorithm", self.signing_algorithm, self.SIGN_ALGORITHM_ENUM)
        ret.add_child(verify_flags())
        ret.add_record_enum("Signing hash algorithm", self.hash_algorithm, self.HASH_ALGORITHM_ENUM)
        verify_key_size()
        return ret

    def verify(self, name: str) -> Verifier:
        """Verify object data.

        :return: Verifier object with loaded all valid verification records
        """
        ret = self._verify(name)
        computed_length = (
            self.fixed_length()
            + self.KEY_SIZES[self.key_size][0]
            + self.KEY_SIZES[self.key_size][1]
        )
        if self.length != computed_length:
            ret.add_record(
                "SRK Length",
                VerifierResult.ERROR,
                f"Length of SRK:{self.length}" f", Required Length of SRK:{computed_length}",
            )

        return ret

    @classmethod
    def create_from_key(cls, public_key: PublicKey, srk_flags: int = 0) -> Self:
        """Create instance from key data.

        :param public_key: Loaded public key.
        :param srk_flags: SRK flags for key.
        :raises SPSDKValueError: Unsupported keys size is detected.
        :raises SPSDKUnsupportedOperation: Unsupported public key
        """
        if hasattr(public_key, "ca"):
            srk_flags |= cls.FLAGS_CA_MASK

        if isinstance(public_key, PublicKeyRsa):
            par_n: int = public_key.public_numbers.n
            par_e: int = public_key.public_numbers.e
            key_size = cls.RSA_KEY_TYPE[public_key.key_size]
            return cls(
                src_key=public_key,
                signing_algorithm=cls.SIGN_ALGORITHM_ENUM.RSA_PSS,
                hash_type=cls.HASH_ALGORITHM_ENUM.SHA256,
                key_size=key_size,
                srk_flags=srk_flags,
                crypto_params=par_n.to_bytes(
                    length=cls.KEY_SIZES[key_size][0], byteorder=Endianness.BIG.value
                )
                + par_e.to_bytes(length=cls.KEY_SIZES[key_size][1], byteorder=Endianness.BIG.value),
            )

        if isinstance(public_key, PublicKeyEcc):
            par_x: int = public_key.x
            par_y: int = public_key.y
            key_size = cls.ECC_KEY_TYPE[public_key.curve]

            if public_key.key_size not in [256, 384, 521]:
                raise SPSDKValueError(
                    f"Unsupported ECC key for AHAB container: {public_key.key_size}"
                )
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
                hash_type=cls.HASH_ALGORITHM_ENUM.SM3,
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

        srk_rec = cls(
            signing_algorithm=cls.SIGN_ALGORITHM_ENUM.from_tag(signing_algo),
            hash_type=cls.HASH_ALGORITHM_ENUM.from_tag(hash_algo),
            key_size=key_size_curve,
            srk_flags=srk_flags,
            crypto_params=crypto_params,
        )
        srk_rec.length = container_length
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
        if (
            self.SIGN_ALGORITHM_ENUM == AHABSignAlgorithmV2
            and self.signing_algorithm == self.SIGN_ALGORITHM_ENUM.DILITHIUM
        ):
            return f"dilithium{get_key_by_val(self.DILITHIUM_KEY_TYPE, self.key_size)}"
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
            f"  Param 1 value:      {self.crypto_param1.hex()})\n"
            f"  Param 2 value:      {self.crypto_param2.hex()})\n"
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
            if self.crypto_param1 is None:
                ret.add_record("Crypto parameter 1", VerifierResult.ERROR, "Not exists")

            elif len(self.crypto_param1) != self.KEY_SIZES[self.key_size][0]:
                ret.add_record(
                    "Crypto parameter 1",
                    VerifierResult.ERROR,
                    f"Invalid length: {len(self.crypto_param1)} != {self.KEY_SIZES[self.key_size][0]}",
                )
            else:
                ret.add_record(
                    "Crypto parameter 1", VerifierResult.SUCCEEDED, self.crypto_param1.hex()
                )

            if self.crypto_param2 is None:
                ret.add_record("Crypto parameter 2", VerifierResult.ERROR, "Not exists")

            elif len(self.crypto_param2) != self.KEY_SIZES[self.key_size][1]:
                ret.add_record(
                    "Crypto parameter 2",
                    VerifierResult.ERROR,
                    f"Invalid length: {len(self.crypto_param2)} != {self.KEY_SIZES[self.key_size][1]}",
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

    def __init__(
        self,
        src_key: Optional[PublicKey] = None,
        signing_algorithm: AHABSignAlgorithmV2 = AHABSignAlgorithmV2.RSA_PSS,
        hash_type: AHABSignHashAlgorithmV2 = AHABSignHashAlgorithmV2.SHA256,
        key_size: int = 0,
        srk_flags: int = 0,
        crypto_params: bytes = b"",
    ):
        """Class object initializer.

        :param src_key: Optional source public key used to create the SRKRecord
        :param signing_algorithm: signing algorithm type.
        :param hash_type: hash algorithm type.
        :param key_size: key (curve) size.
        :param srk_flags: flags.
        :param crypto_params: RSA modulus (big endian) or ECDSA X (big endian) or Hash of SRK data.
        """
        super().__init__(src_key, signing_algorithm, hash_type, key_size, srk_flags, crypto_params)
        self.srk_data: Optional[SRKData] = None

    def __eq__(self, other: object) -> bool:
        if isinstance(other, type(self)):
            if super().__eq__(other) and self.crypto_params == other.crypto_params:
                return True

        return False

    def __str__(self) -> str:
        return super().__str__() + f"  SRK Data Hash:      {self.crypto_params.hex()})\n"

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
            crypto_param1 = self.srk_data.data[: self.KEY_SIZES[self.key_size][0]]
            crypto_param2 = self.srk_data.data[self.KEY_SIZES[self.key_size][0] :]
            if crypto_param1 is None:
                ret.add_record("SRK Data Crypto parameter 1", VerifierResult.ERROR, "Not exists")

            elif len(crypto_param1) != self.KEY_SIZES[self.key_size][0]:
                ret.add_record(
                    "SRK Data Crypto parameter 1",
                    VerifierResult.ERROR,
                    f"Invalid length: {len(crypto_param1)} != {self.KEY_SIZES[self.key_size][0]}",
                )
            else:
                ret.add_record(
                    "SRK Data Crypto parameter 1",
                    VerifierResult.SUCCEEDED,
                    bytes_to_print(crypto_param1),
                )

            if self.KEY_SIZES[self.key_size][1]:
                if crypto_param2 is None:
                    ret.add_record(
                        "SRK Data Crypto parameter 2", VerifierResult.ERROR, "Not exists"
                    )

                elif len(crypto_param2) != self.KEY_SIZES[self.key_size][0]:
                    ret.add_record(
                        "SRK Data Crypto parameter 2",
                        VerifierResult.ERROR,
                        f"Invalid length: {len(crypto_param2)} != {self.KEY_SIZES[self.key_size][0]}",
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
    def create_from_key(cls, public_key: PublicKey, srk_flags: int = 0, srk_id: int = 0) -> Self:
        """Create instance from key data.

        :param public_key: Loaded public key.
        :param srk_flags: SRK flags for key.
        :param srk_id: Index of key in SRK table
        :raises SPSDKValueError: Unsupported keys size is detected.
        """
        signing_algorithm = None
        hash_type = cls.HASH_ALGORITHM_ENUM.SHA256
        key_size = 0

        if hasattr(public_key, "ca"):
            srk_flags |= cls.FLAGS_CA_MASK

        if isinstance(public_key, PublicKeyRsa):
            signing_algorithm = cls.SIGN_ALGORITHM_ENUM.RSA_PSS
            hash_type = cls.HASH_ALGORITHM_ENUM.SHA256
            key_size = cls.RSA_KEY_TYPE[public_key.key_size]

        elif isinstance(public_key, PublicKeyEcc):
            signing_algorithm = cls.SIGN_ALGORITHM_ENUM.ECDSA
            key_size = cls.ECC_KEY_TYPE[public_key.curve]

            if public_key.key_size not in [256, 384, 521]:
                raise SPSDKValueError(
                    f"Unsupported ECC key for AHAB container: {public_key.key_size}"
                )
            hash_type = {
                256: cls.HASH_ALGORITHM_ENUM.SHA256,
                384: cls.HASH_ALGORITHM_ENUM.SHA384,
                521: cls.HASH_ALGORITHM_ENUM.SHA512,
            }[public_key.key_size]

        elif IS_OSCCA_SUPPORTED and isinstance(public_key, PublicKeySM2):
            signing_algorithm = cls.SIGN_ALGORITHM_ENUM.SM2
            hash_type = cls.HASH_ALGORITHM_ENUM.SM3
            key_size = cls.SM2_KEY_TYPE

        elif IS_DILITHIUM_SUPPORTED and isinstance(public_key, PublicKeyDilithium):
            signing_algorithm = cls.SIGN_ALGORITHM_ENUM.DILITHIUM
            key_size = cls.DILITHIUM_KEY_TYPE[public_key.level]
            hash_type = {
                3: cls.HASH_ALGORITHM_ENUM.SHA384,
                5: cls.HASH_ALGORITHM_ENUM.SHA512,
            }[public_key.level]
        elif IS_DILITHIUM_SUPPORTED and isinstance(public_key, PublicKeyMLDSA):
            signing_algorithm = cls.SIGN_ALGORITHM_ENUM.ML_DSA
            key_size = cls.DILITHIUM_KEY_TYPE[public_key.level]
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
        )
        ret.srk_data = SRKData.create_from_key(public_key=public_key, srk_id=srk_id)

        return ret

    def get_public_key(self) -> PublicKey:
        """Recreate the SRK public key.

        :raises SPSDKError: Unsupported public key
        """
        # assert isinstance(self.SIGN_ALGORITHM_ENUM, AHABSignAlgorithmV2)

        if self.srk_data is None:
            raise SPSDKError("Cannot recreate public key due missing SRK Data")
        crypto_param1 = self.srk_data.data[: self.KEY_SIZES[self.key_size][0]]
        crypto_param2 = self.srk_data.data[self.KEY_SIZES[self.key_size][0] :]
        par1 = int.from_bytes(crypto_param1, Endianness.BIG.value)
        par2 = int.from_bytes(crypto_param2, Endianness.BIG.value)

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
            return PublicKeySM2.recreate(self.srk_data.data)

        if self.signing_algorithm == self.SIGN_ALGORITHM_ENUM.DILITHIUM and IS_DILITHIUM_SUPPORTED:
            return PublicKeyDilithium.parse(self.srk_data.data)

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
    def create_from_key(cls, public_key: PublicKey, srk_id: int) -> Self:
        """Create instance from public key.

        :param public_key: Loaded public key.
        :param srk_id: SRK Identification 0-3.
        :raises SPSDKValueError: Unsupported keys size is detected.
        """
        if isinstance(public_key, PublicKeyRsa):
            par_n: int = public_key.public_numbers.n
            par_e: int = public_key.public_numbers.e
            key_size = SRKRecordV2.RSA_KEY_TYPE[public_key.key_size]
            data = par_n.to_bytes(
                length=SRKRecordV2.KEY_SIZES[key_size][0], byteorder=Endianness.BIG.value
            ) + par_e.to_bytes(
                length=SRKRecordV2.KEY_SIZES[key_size][1], byteorder=Endianness.BIG.value
            )
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

        if isinstance(public_key, PublicKeyDilithium):
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

    def __init__(
        self, srk_records: Optional[Union[list[SRKRecord], list[SRKRecordV2]]] = None
    ) -> None:
        """Class object initializer.

        :param srk_records: list of SRK Record objects.
        """
        super().__init__(tag=self.TAG, length=-1, version=self.VERSION)

        self.srk_records = srk_records or []

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

    def add_record(self, public_key: PublicKey, srk_flags: int = 0) -> None:
        """Add SRK table record.

        :param public_key: Loaded public key.
        :param srk_flags: SRK flags for key.
        """
        self.srk_records.append(
            self.SRK_RECORD.create_from_key(  # type:ignore
                public_key=public_key, srk_flags=srk_flags
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
        """Serializes container object into bytes in little endian.

        :return: bytes representing container content.
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

    def create_config(self, index: int, data_path: str) -> dict[str, Any]:
        """Create configuration of the AHAB Image SRK Table.

        :param index: Container Index.
        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        ret_cfg: dict[str, Union[list, bool]] = {}
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
    def load_from_config(
        cls, config: dict[str, Any], search_paths: Optional[list[str]] = None
    ) -> "SRKTable":
        """Converts the configuration option into an AHAB image object.

        "config" content of container configurations.

        :param config: array of AHAB containers configuration dictionaries.
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: SRK Table object.
        """
        srk_table = SRKTable()
        flags = 0
        # Allow user to provide flag_ca in configuration
        flag_ca = config.get("flag_ca", False)
        if flag_ca:
            flags |= cls.SRK_RECORD.FLAGS_CA_MASK
        srk_list = config.get("srk_array")
        assert isinstance(srk_list, list)
        for srk_key in srk_list:
            assert isinstance(srk_key, str)
            srk_key_path = find_file(srk_key, search_paths=search_paths)
            pub_key = extract_public_key(srk_key_path)
            if hasattr(pub_key, "ca"):
                flags |= cls.SRK_RECORD.FLAGS_CA_MASK
            srk_table.add_record(pub_key, srk_flags=flags)
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
    def load_from_config(
        cls, config: dict[str, Any], search_paths: Optional[list[str]] = None
    ) -> Self:
        """Converts the configuration option into an AHAB image object.

        "config" content of container configurations.

        :param config: array of AHAB containers configuration dictionaries.
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: SRK Table object.
        """
        srk_table = cls()
        flags = 0
        flag_ca = config.get("flag_ca", False)
        if flag_ca:
            flags |= cls.SRK_RECORD.FLAGS_CA_MASK
        srk_list = config.get("srk_array")
        assert isinstance(srk_list, list)
        for ix, srk_key in enumerate(srk_list):
            assert isinstance(srk_key, str)
            srk_key_path = find_file(srk_key, search_paths=search_paths)
            pub_key = extract_public_key(srk_key_path)
            if hasattr(pub_key, "ca"):
                flags |= cls.SRK_RECORD.FLAGS_CA_MASK
            srk_table.add_record(pub_key, srk_flags=flags)
            cast(SRKRecordV2, srk_table.srk_records[ix]).srk_data = SRKData.create_from_key(
                pub_key, ix
            )
        return srk_table

    def create_config(self, index: int, data_path: str, srk_table_index: int = 0) -> dict[str, Any]:
        """Create configuration of the AHAB Image SRK Table.

        :param index: Container Index.
        :param data_path: Path to store the data files of configuration.
        :param srk_table_index: SRK table index, default is 0.
        :return: Configuration dictionary.
        """
        ret_cfg: dict[str, Union[list, bool]] = {}
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
            ret += f"SRK_1 table HASH:       {self.compute_srk_hash(1).hex()}"

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
        if srk_id > len(self._srk_tables):
            raise SPSDKValueError(f"The SRK ID({srk_id}) is out of range.")
        data = self._srk_tables[srk_id].export()
        return get_hash(data=data, algorithm=EnumHashAlgorithm.SHA512)

    def export(self) -> bytes:
        """Serializes container object into bytes in little endian.

        :return: bytes representing container content.
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

    def create_config(self, index: int, data_path: str) -> dict[str, Any]:
        """Create configuration of the AHAB Image SRK Table.

        :param index: Container Index.
        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        ret_cfg: dict[str, Any] = {}

        if len(self._srk_tables) > 0:
            ret_cfg = self._srk_tables[0].create_config(index, data_path, 0)
        if len(self._srk_tables) > 1:
            ret_cfg["srk_table_#2"] = self._srk_tables[1].create_config(index, data_path, 1)

        return ret_cfg

    @classmethod
    def load_from_config(
        cls,
        config: dict[str, Any],
        chip_config: AhabChipContainerConfig,
        search_paths: Optional[list[str]] = None,
    ) -> Self:
        """Converts the configuration option into an AHAB image object.

        "config" content of container configurations.

        :param config: array of AHAB containers configuration dictionaries.
        :param chip_config: AHAB container chip configuration.
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: SRK Table array object.
        """
        srk_table_array: list[SRKTableV2] = []
        srk_table_array.append(SRKTableV2.load_from_config(config, search_paths))
        if "srk_table_#2" in config:
            srk_table_array.append(
                SRKTableV2.load_from_config(config["srk_table_#2"], search_paths)
            )

        return cls(chip_config=chip_config, srk_tables=srk_table_array)
