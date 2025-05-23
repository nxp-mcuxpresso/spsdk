#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module with DebugCredential class."""

import abc
import logging
import math
from struct import pack
from typing import Type

from typing_extensions import Self

from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.crypto.keys import PublicKeyEcc, PublicKeyRsa
from spsdk.crypto.utils import extract_public_key
from spsdk.exceptions import SPSDKError, SPSDKNotImplementedError, SPSDKTypeError, SPSDKValueError
from spsdk.image.ahab.ahab_srk import SRKRecord, SRKTable
from spsdk.image.cert_block.cert_blocks import CertBlock, CertBlockV1, CertBlockV21
from spsdk.utils.config import Config
from spsdk.utils.misc import Endianness

logger = logging.getLogger(__name__)


class RotMeta:
    """RoT meta base class."""

    @classmethod
    @abc.abstractmethod
    def load_from_config(cls, config: Config) -> Self:
        """Creates the RoT meta from configuration.

        :return: RotMeta object
        """

    @classmethod
    def load_from_cert_block(cls, cert_block: CertBlock) -> Self:
        """Creates the RoT meta from configuration."""
        raise SPSDKError(f"The {cls.__name__} does not support loading from certificate block.")

    @classmethod
    @abc.abstractmethod
    def parse(cls, data: bytes) -> Self:
        """Parse the object from binary data.

        :param data: Raw data as bytes
        :return: RotMeta object
        """

    @abc.abstractmethod
    def export(self) -> bytes:
        """Export to binary form.

        :return: binary representation of the object
        """

    @abc.abstractmethod
    def calculate_hash(self) -> bytes:
        """Get Root Of Trust Keys Hash.

        :return: RoTKH in bytes
        """

    @abc.abstractmethod
    def __str__(self) -> str:
        """Object description in string format."""

    def __len__(self) -> int:
        """Length of exported data."""
        return len(self.export())


class RotMetaRSA(RotMeta):
    """RSA RoT meta object."""

    def __init__(self, rot_items: list[bytes]) -> None:
        """Class object initializer.

        :param rot_items: List of public key hashes
        """
        self.rot_items = rot_items

    def __str__(self) -> str:
        msg = "RSA RoT meta"
        msg += f"Number of RoT items   : {len(self.rot_items)}\n"
        return msg

    def __eq__(self, obj: object) -> bool:
        """Check object equality.

        :param other: object to compare with.
        :return: True if matches, False otherwise.
        """
        return isinstance(obj, RotMetaRSA) and self.rot_items == obj.rot_items

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Creates the RoT meta from configuration.

        :return: RotMetaRSA object
        """
        rot_pub_keys = config.get_list("rot_meta")
        if len(rot_pub_keys) > 4:
            raise SPSDKValueError("The maximum number of rot public keys is 4.")
        rot_items = []
        for rot_key in rot_pub_keys:
            rot = extract_public_key(
                file_path=rot_key, password=None, search_paths=config.search_paths
            )
            assert isinstance(rot, PublicKeyRsa)
            data = rot.export(exp_length=3)
            rot_item = get_hash(data)
            rot_items.append(rot_item)
        return cls(rot_items)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse the object from binary data.

        :param data: Raw data as bytes
        :return: RotMetaRSA object
        """
        if len(data) < 128:
            raise SPSDKValueError("The provided data must be 128 bytes long.")
        rot_items = []
        for index in range(0, 4):
            rot_item = data[index * 32 : (index + 1) * 32]
            if int.from_bytes(rot_item, Endianness.LITTLE.value):
                rot_items.append(rot_item)
        return cls(rot_items)

    def export(self) -> bytes:
        """Export to binary form.

        :return: binary representation of the object
        """
        rot_meta = bytearray(128)
        for index, rot_item in enumerate(self.rot_items):
            rot_meta[index * 32 : (index + 1) * 32] = rot_item
        return bytes(rot_meta)

    def calculate_hash(self) -> bytes:
        """Get Root Of Trust Keys Hash.

        :return: RoTKH in bytes
        """
        return get_hash(data=self.export())

    @classmethod
    def load_from_cert_block(cls, cert_block: CertBlock) -> Self:
        """Creates the RoT meta from certificate block.

        :param cert_block: Certificate block to extract Root of Trust metadata from
        :return: RotMetaRSA object
        """
        if not isinstance(cert_block, CertBlockV1):
            raise SPSDKTypeError(
                f"Invalid certificate block type. Only {CertBlockV1.__name__} is supported."
            )

        rot_items = [bytes(rkh) for rkh in cert_block.rkh]
        if not rot_items:
            raise SPSDKValueError("Certificate block has no root key hashes")

        return cls(rot_items)


class RotMetaFlags:
    """Rot meta flags."""

    def __init__(self, used_root_cert: int, cnt_root_cert: int) -> None:
        """Class object initializer.

        :param used_root_cert: Index of used root certificate
        :param cnt_root_cert: Number of certificates in the RoT meta
        """
        self.used_root_cert = used_root_cert
        self.cnt_root_cert = cnt_root_cert
        self.validate()

    def validate(self) -> None:
        """Validate the flags."""
        if self.cnt_root_cert > 4:
            raise SPSDKValueError("The maximum number of certificates is 4")
        if self.used_root_cert + 1 > self.cnt_root_cert:
            raise SPSDKValueError(
                f"Used root certificate {self.used_root_cert} must be in range 0-{self.cnt_root_cert-1}."
            )

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse flags from binary data.

        :param data: Raw data as bytes
        :returns: The RotMetaFlags object
        """
        if len(data) != 4:
            raise SPSDKValueError("Invalid data flags length to parse")
        flags = int.from_bytes(data, "little")
        if not flags & (1 << 31):
            raise SPSDKValueError("Invalid flags format to parse")
        used_root_cert = (flags >> 8) & 0x0F
        cnt_root_cert = (flags >> 4) & 0x0F
        return cls(used_root_cert, cnt_root_cert)

    def export(self) -> bytes:
        """Export to binary form.

        :return: binary representation of the object
        """
        flags = 0
        flags |= 1 << 31
        flags |= self.used_root_cert << 8
        flags |= self.cnt_root_cert << 4
        return pack("<L", flags)

    def __str__(self) -> str:
        msg = f"Used root cert index: {self.used_root_cert}\n"
        msg = f"Number of records in flags: {self.cnt_root_cert}\n"
        return msg

    def __eq__(self, obj: object) -> bool:
        """Check object equality.

        :param other: object to compare with.
        :return: True if matches, False otherwise.
        """
        return (
            isinstance(obj, RotMetaFlags)
            and self.used_root_cert == obj.used_root_cert
            and self.cnt_root_cert == obj.cnt_root_cert
        )

    def __len__(self) -> int:
        return len(self.export())


class RotMetaEcc(RotMeta):
    """ECC RoT meta object."""

    HASH_SIZES = {32: 256, 48: 384, 66: 512}
    HASH_SIZE = 0  # to be overridden by derived class

    def __init__(self, flags: RotMetaFlags, rot_items: list[bytes]) -> None:
        """Class object initializer.

        :param flags: RotMetaFlags object
        :param rot_items: List of public key hashes
        """
        self.flags = flags
        self.rot_items = rot_items

    def __eq__(self, obj: object) -> bool:
        """Check object equality.

        :param other: object to compare with.
        :return: True if matches, False otherwise.
        """
        return (
            isinstance(obj, RotMetaEcc)
            and self.flags == obj.flags
            and self.rot_items == obj.rot_items
        )

    def __str__(self) -> str:
        msg = str(self.flags)
        if self.flags.cnt_root_cert == 1:
            msg += "CRTK table not present \n"
        else:
            msg += f"CRTK table has {self.flags.cnt_root_cert} entries\n"
        return msg

    @property
    def key_size(self) -> int:
        """Key size property."""
        return self.HASH_SIZES[(len(self) - len(self.flags)) // self.flags.cnt_root_cert]

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Creates the RoT meta from configuration.

        :return: RotMetaEcc object
        """
        rot_pub_keys = cls._load_public_keys(config)
        hash_size = cls._get_hash_size(config)
        klass = cls._get_subclass(hash_size)
        rot_items: list[bytes] = []
        if len(rot_pub_keys) > 1:
            for pub_key in rot_pub_keys:
                data = pub_key.export()
                rot_items.append(
                    get_hash(
                        data=data,
                        algorithm=EnumHashAlgorithm.from_label(f"sha{cls.HASH_SIZES[hash_size]}"),
                    )
                )
        flags = RotMetaFlags(config.get_int("rot_id"), len(rot_pub_keys))
        return klass(flags, rot_items)  # type: ignore

    def export(self) -> bytes:
        """Export to binary form.

        :return: binary representation of the object
        """
        return self.flags.export() + self.export_crtk_table()

    def export_crtk_table(self) -> bytes:
        """Export CRTK table into binary form."""
        ctrk_table = b""
        if len(self.rot_items) > 1:
            for rot_item in self.rot_items:
                ctrk_table += rot_item
        return ctrk_table

    def calculate_hash(self) -> bytes:
        """Get CRKT table Hash.

        :return: CRKT table hash in bytes
        """
        crkt_table = self.export_crtk_table()
        if not crkt_table:
            raise SPSDKError("Hash cannot be calculated as crkt table is empty")
        return get_hash(
            data=crkt_table,
            algorithm=EnumHashAlgorithm.from_label(f"sha{self.key_size}"),
        )

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse the object from binary data.

        :param data: Raw data as bytes
        :return: RotMetaEcc object
        """
        if not cls.HASH_SIZE:
            raise SPSDKValueError("Hash size not defined.")
        flags = RotMetaFlags.parse(data[:4])
        crt_table = data[4:]
        rot_items = []
        if flags.cnt_root_cert > 1:
            for rot_item_idx in range(0, flags.cnt_root_cert):
                rot_item = crt_table[
                    rot_item_idx * cls.HASH_SIZE : (rot_item_idx + 1) * cls.HASH_SIZE
                ]
                rot_items.append(rot_item)
        return cls(flags, rot_items)

    @classmethod
    def _load_public_keys(cls, config: Config) -> list[PublicKeyEcc]:
        """Load public keys from configuration."""
        pub_key_paths = config.get_list("rot_meta")
        if len(pub_key_paths) < 1:
            raise SPSDKValueError("At least one public key must be specified.")
        pub_keys: list[PublicKeyEcc] = []
        for pub_key_path in pub_key_paths:
            pub_key = extract_public_key(
                file_path=pub_key_path, password=None, search_paths=config.search_paths
            )
            if not isinstance(pub_key, PublicKeyEcc):
                raise SPSDKTypeError("Public key must be of ECC type.")
            pub_keys.append(pub_key)
        return pub_keys

    @classmethod
    def _get_hash_size(cls, config: Config) -> int:
        hash_size = None
        pub_key_paths = config.get_list("rot_meta")
        for pub_key_path in pub_key_paths:
            pub_key = extract_public_key(
                file_path=pub_key_path, password=None, search_paths=config.search_paths
            )
            assert isinstance(pub_key, PublicKeyEcc)
            if not hash_size:
                hash_size = math.ceil(pub_key.key_size / 8)
            if hash_size != math.ceil(pub_key.key_size / 8):
                raise SPSDKValueError("All public keys must be of a same length")
        if not hash_size:
            raise SPSDKError("Hash size could not be determined.")
        return hash_size

    @classmethod
    def _get_subclass(cls, hash_size: int) -> Type["RotMetaEcc"]:
        """Get the subclass with given hash algorithm."""
        subclasses: list[Type[RotMetaEcc]] = cls._build_subclasses()
        for subclass in subclasses:
            if subclass.HASH_SIZE == hash_size:
                return subclass
        raise SPSDKValueError(f"The subclass with hash length {hash_size} does not exist.")

    @classmethod
    def _build_subclasses(cls) -> list[Type["RotMetaEcc"]]:
        """Dynamically build list of classes based on hash algorithm."""
        rot_meta_types = []
        for hash_size, hash_algo in cls.HASH_SIZES.items():
            subclass = type(f"RotMetaEcc{hash_algo}", (RotMetaEcc,), {"HASH_SIZE": hash_size})
            rot_meta_types.append(subclass)
        return rot_meta_types

    @classmethod
    def load_from_cert_block(cls, cert_block: CertBlock) -> Self:
        """Creates the RoT meta from certificate block.

        :param cert_block: Certificate block to extract Root of Trust metadata from
        :return: RotMetaEdgeLockEnclave object
        :raises SPSDKTypeError: When an unsupported certificate block type is provided
        """
        if not isinstance(cert_block, CertBlockV21):
            raise SPSDKTypeError(
                f"Invalid certificate block type. Only {CertBlockV21.__name__} is supported."
            )
        # Get the right subclass based on hash size
        subclass = cls._get_subclass(len(cert_block.root_key_record._rkht.rkh_list[0]))
        flags = RotMetaFlags(
            cert_block.root_key_record.used_root_cert,
            cert_block.root_key_record.number_of_certificates,
        )

        return subclass(flags, cert_block.root_key_record._rkht.rkh_list)  # type: ignore


class RotMetaEdgeLockEnclave(RotMeta):
    """ELE RoT meta object."""

    def __init__(self, flags: RotMetaFlags, srk_table: SRKTable) -> None:
        """Class object initializer.

        :param flags: RotMetaFlags object
        :param srk_table: SRKTable object
        """
        self.flags = flags
        self.srk_table = srk_table

    def __eq__(self, obj: object) -> bool:
        """Check object equality.

        :param other: object to compare with.
        :return: True if matches, False otherwise.
        """
        return (
            isinstance(obj, RotMetaEdgeLockEnclave)
            and self.flags == obj.flags
            and self.srk_table == obj.srk_table
        )

    def __str__(self) -> str:
        msg = str(self.flags)
        if self.flags.cnt_root_cert != 4:
            msg += "Invalid count of SRK records \n"
        else:
            msg += f"SRK table has {self.flags.cnt_root_cert} entries\n"
        return msg

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse the object from binary data.

        :param data: Raw data as bytes
        :return: RotMetaEdgeLockEnclave object
        """
        flags = RotMetaFlags.parse(data[:4])
        srk_table = SRKTable.parse(data[4:])
        srk_table.verify().validate()
        return cls(flags, srk_table)

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Creates the RoT meta from configuration.

        :return: RotMetaEdgeLockEnclave object
        """
        rot_pub_keys = config.get_list("rot_meta")
        flags = RotMetaFlags(config.get_int("rot_id"), len(rot_pub_keys))
        if len(rot_pub_keys) != 4:
            raise SPSDKValueError("Invalid count of Super Root keys.")
        flag_ca = config.get("flag_ca", False)
        srk_flags = 0
        if flag_ca:
            srk_flags |= SRKRecord.FLAGS_CA_MASK

        srk_table = SRKTable(
            [
                SRKRecord.create_from_key(
                    extract_public_key(x, search_paths=config.search_paths), srk_flags=srk_flags
                )
                for x in rot_pub_keys
            ]
        )
        srk_table.update_fields()
        srk_table.verify().validate()
        return cls(flags, srk_table)

    def export(self) -> bytes:
        """Export to binary form.

        :return: binary representation of the object
        """
        return self.flags.export() + self.srk_table.export()

    def calculate_hash(self) -> bytes:
        """Get SRK table hash.

        :return: SRK table hash in bytes
        """
        self.srk_table.update_fields()
        return self.srk_table.compute_srk_hash()


class RotMetaDummy(RotMeta):
    """RoT meta dummy class."""

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Creates the RoT meta from configuration."""
        raise SPSDKNotImplementedError()

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse the object from binary data."""
        raise SPSDKNotImplementedError()

    def export(self) -> bytes:
        """Export to binary form."""
        raise SPSDKNotImplementedError()

    def calculate_hash(self) -> bytes:
        """Get Root Of Trust Keys Hash."""
        raise SPSDKNotImplementedError()

    def __str__(self) -> str:
        """Object description in string format."""
        return "Dummy RoT Meta class"

    def __len__(self) -> int:
        """Length of exported data."""
        return 0
