#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Implementation of AHAB container SRK (Super Root Keys) support."""

import logging
import math
import os
from struct import pack, unpack
from typing import Any, Dict, List, Optional, Union

from typing_extensions import Self

from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.crypto.keys import (
    IS_OSCCA_SUPPORTED,
    EccCurve,
    PublicKey,
    PublicKeyEcc,
    PublicKeyRsa,
    PublicKeySM2,
)
from spsdk.crypto.utils import extract_public_key
from spsdk.exceptions import SPSDKError, SPSDKLengthError, SPSDKValueError
from spsdk.image.ahab.ahab_abstract_interfaces import HeaderContainerData, HeaderContainerInversed
from spsdk.image.ahab.ahab_data import (
    RESERVED,
    UINT8,
    UINT16,
    AHABSignAlgorithm,
    AHABSignHashAlgorithm,
    AHABTags,
)
from spsdk.utils.misc import Endianness, find_file, value_to_bytes, write_file
from spsdk.utils.verifier import Verifier, VerifierResult

logger = logging.getLogger(__name__)


def get_key_by_val(dictionary: Dict, val: Any) -> Any:
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


class SRKRecord(HeaderContainerInversed):
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

    TAG = AHABTags.SRK_RECORD.tag
    VERSION = AHABSignAlgorithm.tags()
    ECC_KEY_TYPE = {EccCurve.SECP521R1: 0x3, EccCurve.SECP384R1: 0x2, EccCurve.SECP256R1: 0x1}
    RSA_KEY_TYPE = {2048: 0x5, 3072: 0x6, 4096: 0x7}
    SM2_KEY_TYPE = 0x8
    KEY_SIZES = {
        0x1: (32, 32),  # PRIME256V1
        0x2: (48, 48),  # SEC384R1
        0x3: (66, 66),  # SEC521R1
        0x5: (256, 4),  # RSA2048
        0x6: (384, 4),  # RSA3072
        0x7: (512, 4),  # RSA4096
        0x8: (32, 32),  # SM2
    }

    FLAGS_CA_MASK = 0x80

    def __init__(
        self,
        src_key: Optional[PublicKey] = None,
        signing_algorithm: AHABSignAlgorithm = AHABSignAlgorithm.RSA_PSS,
        hash_type: AHABSignHashAlgorithm = AHABSignHashAlgorithm.SHA256,
        key_size: int = 0,
        srk_flags: int = 0,
        crypto_param1: bytes = b"",
        crypto_param2: bytes = b"",
    ):
        """Class object initializer.

        :param src_key: Optional source public key used to create the SRKRecord
        :param signing_algorithm: signing algorithm type.
        :param hash_type: hash algorithm type.
        :param key_size: key (curve) size.
        :param srk_flags: flags.
        :param crypto_param1: RSA modulus (big endian) or ECDSA X (big endian)
        :param crypto_param2: RSA exponent (big endian) or ECDSA Y (big endian)
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
        self.crypto_param1 = crypto_param1
        self.crypto_param2 = crypto_param2

    @property
    def signing_algorithm(self) -> AHABSignAlgorithm:
        """Get signing algorithm."""
        return AHABSignAlgorithm.from_tag(self.version)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SRKRecord):
            if (
                super().__eq__(other)  # pylint: disable=too-many-boolean-expressions
                and self.hash_algorithm == other.hash_algorithm
                and self.key_size == other.key_size
                and self.srk_flags == other.srk_flags
                and self.crypto_param1 == other.crypto_param1
                and self.crypto_param2 == other.crypto_param2
            ):
                return True

        return False

    def __len__(self) -> int:
        return super().__len__() + len(self.crypto_param1) + len(self.crypto_param2)

    def __repr__(self) -> str:
        return f"AHAB SRK record, key: {self.get_key_name()}"

    def __str__(self) -> str:
        return (
            "AHAB SRK Record:\n"
            f"  Key:                {self.get_key_name()}\n"
            f"  SRK flags:          {hex(self.srk_flags)}\n"
            f"  Param 1 value:      {self.crypto_param1.hex()})\n"
            f"  Param 2 value:      {self.crypto_param2.hex()})\n"
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
            + UINT16  # crypto_param2_len
            + UINT16  # crypto_param1_len
        )

    def update_fields(self) -> None:
        """Update all fields depended on input values."""
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
                len(self.crypto_param1),
                len(self.crypto_param2),
            )
            + self.crypto_param1
            + self.crypto_param2
        )

    def verify(self, name: str) -> Verifier:
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
                AHABSignAlgorithm.RSA,
                AHABSignAlgorithm.RSA_PSS,
            ):  # Signing algorithm RSA
                if self.key_size not in self.RSA_KEY_TYPE.values():
                    ret.add_record(
                        "Key size",
                        VerifierResult.ERROR,
                        f"Invalid Key size in match to RSA signing algorithm: {self.key_size}",
                    )
            elif self.signing_algorithm == AHABSignAlgorithm.ECDSA:  # Signing algorithm ECDSA
                if self.key_size not in self.ECC_KEY_TYPE.values():
                    ret.add_record(
                        "Key size",
                        VerifierResult.ERROR,
                        f"Invalid Key size in match to ECDSA signing algorithm: {self.key_size}",
                    )
            elif self.signing_algorithm == AHABSignAlgorithm.SM2:  # Signing algorithm SM2
                if self.key_size != self.SM2_KEY_TYPE:
                    ret.add_record(
                        "Key size",
                        VerifierResult.ERROR,
                        f"Invalid Key size in match to SM2 signing algorithm: {self.key_size}",
                    )
            else:
                ret.add_record("Key size", VerifierResult.SUCCEEDED, self.key_size)

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

            elif len(self.crypto_param2) != self.KEY_SIZES[self.key_size][0]:
                ret.add_record(
                    "Crypto parameter 2",
                    VerifierResult.ERROR,
                    f"Invalid length: {len(self.crypto_param2)} != {self.KEY_SIZES[self.key_size][0]}",
                )
            else:
                ret.add_record(
                    "Crypto parameter 2", VerifierResult.SUCCEEDED, self.crypto_param2.hex()
                )

        ret = Verifier(name, description="")
        ret.add_child(self.verify_parsed_header())
        ret.add_child(self.verify_header())
        ret.add_record_enum("Signing algorithm", self.signing_algorithm, AHABSignAlgorithm)
        ret.add_child(verify_flags())
        ret.add_record_enum("Signing hash algorithm", self.hash_algorithm, AHABSignHashAlgorithm)
        verify_key_size()
        verify_param_lengths()

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

        try:
            public_key = self.get_public_key()
            ret.add_record("Restore public key", VerifierResult.SUCCEEDED, str(public_key))
        except SPSDKError as exc:
            ret.add_record("Restore public key", VerifierResult.ERROR, str(exc.description))

        return ret

    @staticmethod
    def create_from_key(public_key: PublicKey, srk_flags: int = 0) -> "SRKRecord":
        """Create instance from key data.

        :param public_key: Loaded public key.
        :param srk_flags: SRK flags for key.
        :raises SPSDKValueError: Unsupported keys size is detected.
        """
        if isinstance(public_key, PublicKeyRsa):
            par_n: int = public_key.public_numbers.n
            par_e: int = public_key.public_numbers.e
            key_size = SRKRecord.RSA_KEY_TYPE[public_key.key_size]
            return SRKRecord(
                src_key=public_key,
                signing_algorithm=AHABSignAlgorithm.RSA_PSS,
                hash_type=AHABSignHashAlgorithm.SHA256,
                key_size=key_size,
                srk_flags=srk_flags,
                crypto_param1=par_n.to_bytes(
                    length=SRKRecord.KEY_SIZES[key_size][0], byteorder=Endianness.BIG.value
                ),
                crypto_param2=par_e.to_bytes(
                    length=SRKRecord.KEY_SIZES[key_size][1], byteorder=Endianness.BIG.value
                ),
            )

        if isinstance(public_key, PublicKeyEcc):
            par_x: int = public_key.x
            par_y: int = public_key.y
            key_size = SRKRecord.ECC_KEY_TYPE[public_key.curve]

            if not public_key.key_size in [256, 384, 521]:
                raise SPSDKValueError(
                    f"Unsupported ECC key for AHAB container: {public_key.key_size}"
                )
            hash_type = {
                256: AHABSignHashAlgorithm.SHA256,
                384: AHABSignHashAlgorithm.SHA384,
                521: AHABSignHashAlgorithm.SHA512,
            }[public_key.key_size]

            return SRKRecord(
                signing_algorithm=AHABSignAlgorithm.ECDSA,
                hash_type=hash_type,
                key_size=key_size,
                srk_flags=srk_flags,
                crypto_param1=par_x.to_bytes(
                    length=SRKRecord.KEY_SIZES[key_size][0], byteorder=Endianness.BIG.value
                ),
                crypto_param2=par_y.to_bytes(
                    length=SRKRecord.KEY_SIZES[key_size][1], byteorder=Endianness.BIG.value
                ),
            )

        assert isinstance(public_key, PublicKeySM2), "Unsupported public key for SRK record"
        param1: bytes = value_to_bytes("0x" + public_key.public_numbers[:64], byte_cnt=32)
        param2: bytes = value_to_bytes("0x" + public_key.public_numbers[64:], byte_cnt=32)
        assert len(param1 + param2) == 64, "Invalid length of the SM2 key"
        key_size = SRKRecord.SM2_KEY_TYPE
        return SRKRecord(
            src_key=public_key,
            signing_algorithm=AHABSignAlgorithm.SM2,
            hash_type=AHABSignHashAlgorithm.SM3,
            key_size=key_size,
            srk_flags=srk_flags,
            crypto_param1=param1,
            crypto_param2=param2,
        )

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse input binary chunk to the container object.

        :param data: Binary data with SRK record block to parse.
        :raises SPSDKLengthError: Invalid length of SRK record data block.
        :return: SRK record recreated from the binary data.
        """
        SRKRecord.check_container_head(data).validate()
        (
            _,  # tag
            container_length,
            signing_algo,
            hash_algo,
            key_size_curve,
            _,  # reserved
            srk_flags,
            crypto_param1_len,
            crypto_param2_len,
        ) = unpack(SRKRecord.format(), data[: SRKRecord.fixed_length()])

        # Although we know from the total length, that we have enough bytes,
        # the crypto param lengths may be set improperly and we may get into trouble
        # while parsing. So we need to check the lengths as well.
        param_length = SRKRecord.fixed_length() + crypto_param1_len + crypto_param2_len
        if container_length < param_length:
            raise SPSDKLengthError(
                "Parsing error of SRK Record data."
                "SRK record lengths mismatch. Sum of lengths declared in container "
                f"({param_length} (= {SRKRecord.fixed_length()} + {crypto_param1_len} + "
                f"{crypto_param2_len})) doesn't match total length declared in container ({container_length})!"
            )
        crypto_param1 = data[
            SRKRecord.fixed_length() : SRKRecord.fixed_length() + crypto_param1_len
        ]
        crypto_param2 = data[
            SRKRecord.fixed_length()
            + crypto_param1_len : SRKRecord.fixed_length()
            + crypto_param1_len
            + crypto_param2_len
        ]

        srk_rec = cls(
            signing_algorithm=AHABSignAlgorithm.from_tag(signing_algo),
            hash_type=AHABSignHashAlgorithm.from_tag(hash_algo),
            key_size=key_size_curve,
            srk_flags=srk_flags,
            crypto_param1=crypto_param1,
            crypto_param2=crypto_param2,
        )
        srk_rec._parsed_header = HeaderContainerData.parse(binary=data, inverted=True)
        return srk_rec

    def get_key_name(self) -> str:
        """Get text key name in SRK record.

        :return: Key name.
        """
        if self.signing_algorithm == AHABSignAlgorithm.RSA:
            return f"rsa{get_key_by_val(self.RSA_KEY_TYPE, self.key_size)}"
        if self.signing_algorithm == AHABSignAlgorithm.RSA_PSS:
            return f"rsa_pss{get_key_by_val(self.RSA_KEY_TYPE, self.key_size)}"
        if self.signing_algorithm == AHABSignAlgorithm.ECDSA:
            return get_key_by_val(self.ECC_KEY_TYPE, self.key_size)
        if self.signing_algorithm == AHABSignAlgorithm.SM2:
            return "sm2"
        return "Unknown Key name!"

    def get_public_key(self) -> PublicKey:
        """Recreate the SRK public key.

        :raises SPSDKError: Unsupported public key
        """
        par1 = int.from_bytes(self.crypto_param1, Endianness.BIG.value)
        par2 = int.from_bytes(self.crypto_param2, Endianness.BIG.value)

        if self.signing_algorithm in [AHABSignAlgorithm.RSA, AHABSignAlgorithm.RSA_PSS]:
            # RSA Key to store
            return PublicKeyRsa.recreate(modulus=par1, exponent=par2)

        if self.signing_algorithm == AHABSignAlgorithm.ECDSA:
            # ECDSA Key to store
            curve = get_key_by_val(self.ECC_KEY_TYPE, self.key_size)
            return PublicKeyEcc.recreate(par1, par2, curve=curve)

        if self.signing_algorithm == AHABSignAlgorithm.SM2 and IS_OSCCA_SUPPORTED:
            return PublicKeySM2.recreate(self.crypto_param1 + self.crypto_param2)

        raise SPSDKError(f"Unsupported public key type:{self.signing_algorithm.label}")


class SRKTable(HeaderContainerInversed):
    """Class representing SRK (Super Root Key) table in the AHAB container as part of signature block.

    SRK Table::

        +-----+---------------------------------------------------------------+
        |Off  |    Byte 3    |    Byte 2      |    Byte 1    |     Byte 0     |
        +-----+---------------------------------------------------------------+
        |0x00 |    Tag       |         Length of SRK Table   |     Version    |
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
    SRK_RECORDS_CNT = 4
    SUPPORTED_HASHES = ["sha256", "sha384", "sha512", "sm3"]

    def __init__(self, srk_records: Optional[List[SRKRecord]] = None) -> None:
        """Class object initializer.

        :param srk_records: list of SRKRecord objects.
        """
        super().__init__(tag=self.TAG, length=-1, version=self.VERSION)
        self._srk_records: List[SRKRecord] = srk_records or []
        self.length = len(self)

    def __repr__(self) -> str:
        return f"AHAB SRK TABLE, keys count: {len(self._srk_records)}"

    def __str__(self) -> str:
        return (
            "AHAB SRK table:\n"
            f"  Keys count:         {len(self._srk_records)}\n"
            f"  Length:             {self.length}\n"
            f"SRK table HASH:       {self.compute_srk_hash().hex()}"
        )

    def clear(self) -> None:
        """Clear the SRK Table Object."""
        self._srk_records.clear()
        self.length = -1

    def add_record(self, public_key: PublicKey, srk_flags: int = 0) -> None:
        """Add SRK table record.

        :param public_key: Loaded public key.
        :param srk_flags: SRK flags for key.
        """
        self._srk_records.append(
            SRKRecord.create_from_key(public_key=public_key, srk_flags=srk_flags)
        )
        self.length = len(self)

    def __eq__(self, other: object) -> bool:
        """Compares for equality with other SRK Table objects.

        :param other: object to compare with.
        :return: True on match, False otherwise.
        """
        if isinstance(other, SRKTable):
            if super().__eq__(other) and self._srk_records == other._srk_records:
                return True

        return False

    def __len__(self) -> int:
        records_len = 0
        for record in self._srk_records:
            records_len += len(record)
        return super().__len__() + records_len

    def update_fields(self) -> None:
        """Update all fields depended on input values."""
        for rec in self._srk_records:
            rec.update_fields()
        self.length = len(self)

    def compute_srk_hash(self) -> bytes:
        """Computes a SHA256 out of all SRK records.

        :return: SHA256 computed over SRK records.
        """
        return get_hash(data=self.export(), algorithm=EnumHashAlgorithm.SHA256)

    def get_source_keys(self) -> List[PublicKey]:
        """Return list of source public keys.

        Either from the src_key field or recreate them.
        :return: List of public keys.
        """
        ret = []
        for srk in self._srk_records:
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

        for srk_record in self._srk_records:
            data += srk_record.export()

        return data

    def verify(self) -> Verifier:
        """Verify SRK table data."""

        def verify_count_of_records() -> None:
            if self._srk_records is None:
                ret.add_record("Count", VerifierResult.ERROR, "Not exists records")
            elif len(self._srk_records) != self.SRK_RECORDS_CNT:
                ret.add_record(
                    "Count",
                    VerifierResult.ERROR,
                    f"Invalid {len(self._srk_records)} != {self.SRK_RECORDS_CNT}",
                )
            else:
                ret.add_record("Count", VerifierResult.SUCCEEDED, self.SRK_RECORDS_CNT)

        ret = Verifier("SRK table", description="")
        ret.add_child(self.verify_parsed_header())
        ret.add_child(self.verify_header())
        verify_count_of_records()

        # Validate individual SRK records
        for i, srk_rec in enumerate(self._srk_records):
            ret.add_child(srk_rec.verify(f"SRK record[{i}]"))

        # Check if all SRK records has same type
        srk_records_info = [
            (x.version, x.hash_algorithm.tag, x.key_size, x.length, x.srk_flags)
            for x in self._srk_records
        ]

        messages = ["Signing algorithm", "Hash algorithm", "Key Size", "Length", "Flags"]
        for i in range(4):
            if not all(srk_records_info[0][i] == x[i] for x in srk_records_info):
                ret.add_record(messages[i], VerifierResult.ERROR, "Is not same in all SRK records")
            else:
                ret.add_record(messages[i], VerifierResult.SUCCEEDED, "Is same in all SRK records")

        if self._srk_records[0].hash_algorithm.label.lower() not in self.SUPPORTED_HASHES:
            ret.add_record(
                "Supported hash",
                VerifierResult.ERROR,
                "SRK records haven't supported hash algorithm on this device:"
                f" Used:{self._srk_records[0].hash_algorithm.label} is not member of"
                f" {self.SUPPORTED_HASHES}",
            )
        else:
            ret.add_record(
                "Supported hash",
                VerifierResult.SUCCEEDED,
                f"{self._srk_records[0].hash_algorithm.label} is supported",
            )
        return ret

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse input binary chunk to the container object.

        :param data: Binary data with SRK table block to parse.
        :raises SPSDKLengthError: Invalid length of SRK table data block.
        :return: Object recreated from the binary data.
        """
        SRKTable.check_container_head(data).validate()
        srk_rec_offset = SRKTable.fixed_length()
        _, container_length, _ = unpack(SRKTable.format(), data[:srk_rec_offset])
        if ((container_length - srk_rec_offset) % SRKTable.SRK_RECORDS_CNT) != 0:
            raise SPSDKLengthError("SRK table: Invalid length of SRK records data.")
        srk_rec_size = math.ceil((container_length - srk_rec_offset) / SRKTable.SRK_RECORDS_CNT)

        # try to parse records
        srk_records: List[SRKRecord] = []
        for _ in range(SRKTable.SRK_RECORDS_CNT):
            srk_record = SRKRecord.parse(data[srk_rec_offset:])
            srk_rec_offset += srk_rec_size
            srk_records.append(srk_record)

        srk_table = cls(srk_records=srk_records)
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
            ret.add_child(SRKRecord.check_container_head(data[srk_rec_offset:]))
            srk_rec_offset += srk_rec_size
        return ret

    def create_config(self, index: int, data_path: str) -> Dict[str, Any]:
        """Create configuration of the AHAB Image SRK Table.

        :param index: Container Index.
        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        ret_cfg: Dict[str, Union[List, bool]] = {}
        cfg_srks = []

        ret_cfg["flag_ca"] = bool(self._srk_records[0].srk_flags & SRKRecord.FLAGS_CA_MASK)

        for ix_srk, srk in enumerate(self._srk_records):
            filename = f"container{index}_srk_public_key{ix_srk}_{srk.get_key_name()}.pem"
            public_key = srk.get_public_key()
            write_file(
                data=public_key.export(public_key.RECOMMENDED_ENCODING),
                path=os.path.join(data_path, filename),
                mode="wb",
            )
            cfg_srks.append(filename)

        ret_cfg["srk_array"] = cfg_srks
        return ret_cfg

    @staticmethod
    def load_from_config(
        config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> "SRKTable":
        """Converts the configuration option into an AHAB image object.

        "config" content of container configurations.

        :param config: array of AHAB containers configuration dictionaries.
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: SRK Table object.
        """
        srk_table = SRKTable()
        flags = 0
        flag_ca = config.get("flag_ca", False)
        if flag_ca:
            flags |= SRKRecord.FLAGS_CA_MASK
        srk_list = config.get("srk_array")
        assert isinstance(srk_list, list)
        for srk_key in srk_list:
            assert isinstance(srk_key, str)
            srk_key_path = find_file(srk_key, search_paths=search_paths)
            srk_table.add_record(extract_public_key(srk_key_path), srk_flags=flags)
        return srk_table
