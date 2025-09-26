#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""TLV."""

import logging
from inspect import isclass
from typing import Any, Optional, Type

from typing_extensions import Self
from x690.types import TypeClass, TypeNature, X690Type, decode

from spsdk.crypto.cmac import cmac
from spsdk.crypto.crypto_types import SPSDKEncoding
from spsdk.crypto.hkdf import hkdf
from spsdk.crypto.keys import PrivateKeyEcc
from spsdk.crypto.symmetric import aes_cbc_encrypt, aes_key_wrap
from spsdk.exceptions import (
    SPSDKError,
    SPSDKNotImplementedError,
    SPSDKParsingError,
    SPSDKValueError,
)
from spsdk.image.ahab.ahab_data import (
    RESERVED,
    KeyAlgorithm,
    KeyImportSigningAlgorithm,
    KeyType,
    KeyUsage,
    LifeCycle,
    LifeTime,
    WrappingAlgorithm,
)
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, SpsdkEnum, get_schema_file
from spsdk.utils.family import FamilyRevision, update_validation_schema_family
from spsdk.utils.schema_validator import CommentedConfig
from spsdk.utils.verifier import Verifier

logger = logging.getLogger(__name__)


class TLV(FeatureBaseClass):
    """`Tag-Length-Value` (TLV) base class for AHAB image processing."""

    NAME = "TLV_BLOB"
    FEATURE = DatabaseManager.TLV_BLOB

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse object from bytes array."""
        raise SPSDKNotImplementedError("'parse' must be implemented in child class")

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get list of validation schemas.

        :param family: Family for which the validation schema should be generated.
        :return: Validation list of schemas.
        """
        sch = get_schema_file(DatabaseManager.TLV_BLOB)
        sch_family = get_schema_file("general")["family"]
        update_validation_schema_family(
            sch_family["properties"], cls.get_supported_families(), family
        )
        return [sch["output_file"], sch_family, sch["tlv"]]

    @classmethod
    def get_config_template(cls, family: FamilyRevision) -> str:
        """Get AHAB configuration template.

        :param family: Family for which the template should be generated.
        :return: Dictionary of individual templates (key is name of template, value is template itself).
        """
        val_schemas = cls.get_validation_schemas(family=family)
        return CommentedConfig(
            f"TLV Configuration template for {family}.", val_schemas
        ).get_template()

    @classmethod
    def get_tlv_class(cls, name: str) -> Type[Self]:
        """Get the dedicated class for TLV."""
        for var in globals():
            obj = globals()[var]
            if isclass(obj) and issubclass(obj, TLV) and obj is not TLV:
                assert issubclass(obj, TLV)  # pylint: disable=assert-instance
                if TLVTypes.from_label(name) == obj.NAME:
                    return obj  # type: ignore

        raise SPSDKValueError(f"TLV {name} is not supported.")

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Converts the configuration option into an TLV object.

        "config" content of container configurations.

        :param config: Message configuration dictionaries.
        :return: TLV object.
        """
        family = config.get_family()
        command = config.get_dict("command")
        if len(command) != 1:
            raise SPSDKError(f"Invalid config field command: {command}")
        msg_cls = cls.get_tlv_class(list(command.keys())[0])
        return msg_cls._load_from_config(config, family)

    @classmethod
    def _load_from_config(cls, config: Config, family: FamilyRevision) -> Self:
        """Converts the configuration option into an message object.

        "config" content of container configurations.

        :param config: Message configuration dictionaries.
        :param family: Family revision for message configuration.
        :raises SPSDKError: Invalid configuration detected.
        :return: Message object.
        """
        raise SPSDKNotImplementedError("'_load_from_config' must be implemented in child class")

    def __str__(self) -> str:
        """String representation of the KeyImportTLV object.

        :return: Formatted string with key import details.
        """
        return "TLV"

    def __repr__(self) -> str:
        return "TLV"


class TLVTypes(SpsdkEnum):
    """TLV Types."""

    KEY_IMPORT = (
        0,
        "KEY_IMPORT",
        "TLV for Key Import",
    )


class KeyImportTLV(TLV):
    """Key import request message class representation."""

    NAME = "KEY_IMPORT"
    HEADER_MAGIC = "edgelockenclaveimport"

    def __init__(
        self,
        family: FamilyRevision,
        key_id: int = 0,
        permitted_algorithm: KeyAlgorithm = KeyAlgorithm.SHA256,
        key_usage: Optional[list[KeyUsage]] = None,
        key_type: KeyType = KeyType.AES,
        key_size_bits: int = 0,
        key_lifetime: LifeTime = LifeTime.ELE_KEY_IMPORT_PERMANENT,
        key_lifecycle: LifeCycle = LifeCycle.OPEN,
        oem_import_mk_sk_key_id: int = 0,
        wrapping_algorithm: WrappingAlgorithm = WrappingAlgorithm.RFC3394,
        iv: Optional[bytes] = None,
        signing_algorithm: KeyImportSigningAlgorithm = KeyImportSigningAlgorithm.CMAC,
        wrapped_private_key: bytes = bytes(),
        signature: bytes = bytes(),
    ) -> None:
        """Key exchange signed message class init.

        :param family: Family revision
        :param cert_ver: Certificate version, defaults to 0
        :param permissions: Certificate permission, to be used in future
            The stated permission must allow the operation requested by the signed message
            , defaults to 0
        :param issue_date: Issue date, defaults to None (Current date will be applied)
        :param unique_id: UUID of device, defaults to None
        :param unique_id_len: UUID length - 64 or 128 bits, defaults to 64 bits (8 bytes)
        :param key_id: Key ID where to store the derived key. It must be the key store ID
            related to the key management handle set in the command API, defaults to 0
        :param permitted_algorithm: Algorithm used by the key import process:

         **Hash Algorithms:**
            | MD5                    0x02000003
            | SHA1                   0x02000005
            | SHA224                 0x02000008
            | SHA256                 0x02000009
            | SHA384                 0x0200000A
            | SHA512                 0x0200000B
            | SHA3_224               0x02000010
            | SHA3_256               0x02000011
            | SHA3_384               0x02000012
            | SHA3_512               0x02000013
            | SHAKE256               0x02000015

            **MAC Algorithms:**
            | HMAC SHA256            0x03800009
            | HMAC SHA384            0x0380000A
            | CMAC                   0x03C00200

            **Cipher Algorithms:**
            | ECB NO PADDING         0x04404400
            | CBC NO PADDING         0x04404000
            | CTR                    0x04C01000
            | CFB                    0x04C01100
            | OFB                    0x04C01200
            | ALL CIPHER             0x84C0FF00

            **AEAD Algorithms:**
            | CCM                    0x05500100
            | GCM                    0x05500200
            | CHACHA20_POLY1305      0x05100500
            | ALL AEAD               0x8550FF00

            **Signature Algorithms:**
            | ECDSA SHA224           0x06000608
            | ECDSA SHA256           0x06000609
            | ECDSA SHA384           0x0600060A
            | ECDSA SHA512           0x0600060B
            | RSA PKCS1 V1.5 SHA224  0x06000208
            | RSA PKCS1 V1.5 SHA256  0x06000209
            | RSA PKCS1 V1.5 SHA384  0x0600020A
            | RSA PKCS1 V1.5 SHA512  0x0600020B
            | RSA PKCS1 V1.5 SHA ANY 0x060002FF
            | RSA PKCS1 PSS MGF1 SHA224 0x06000308
            | RSA PKCS1 PSS MGF1 SHA256 0x06000309
            | RSA PKCS1 PSS MGF1 SHA384 0x0600030A
            | RSA PKCS1 PSS MGF1 SHA512 0x0600030B
            | RSA PKCS1 PSS MGF1 SHA ANY 0x060003FF
            | RSA PKCS1 ALL          0x8600FF00
            | ED25519PH              0x0600090B
            | ED448PH                0x06000915
            | PURE EDDSA             0x06000800
            | ALL EDDSA              0x86000800

            **Key Exchange Algorithms:**
            | ECDH HKDF SHA256 KEY IMPORT 0x09020109
            | ECDH HKDF SHA384 KEY IMPORT 0x0902010A
            | ECDH HKDF SHA ANY KEY IMPORT 0x090201FF
            | ECDH HKDF SHA256       0x89020109
            | ECDH HKDF SHA384       0x8902010A
            | ECDH HKDF SHA ANY      0x890201FF


        :param key_usage: Imported key usage attribute.

            | Cache  0x00000004  Permission to cache the key in the ELE internal secure memory.
            |                     This usage is set by default by ELE FW for all keys generated or imported.
            | Encrypt  0x00000100  Permission to encrypt a message with the key. It could be cipher
            |                     encryption, AEAD encryption or asymmetric encryption operation.
            | Decrypt  0x00000200  Permission to decrypt a message with the key. It could be
            |                     cipher decryption, AEAD decryption or asymmetric decryption operation.
            | Sign message  0x00000400  Permission to sign a message with the key. It could be
            |                     a MAC generation or an asymmetric message signature operation.
            | Verify message  0x00000800  Permission to verify a message signature with the key.
            |                     It could be a MAC verification or an asymmetric message signature
            |                     verification operation.
            | Sign hash  0x00001000  Permission to sign a hashed message with the key
            |                     with an asymmetric signature operation. Setting this permission automatically
            |                     sets the Sign Message usage.
            | Verify hash  0x00002000  Permission to verify a hashed message signature with
            |                     the key with an asymmetric signature verification operation.
            |                     Setting this permission automatically sets the Verify Message usage.
            | Derive  0x00004000  Permission to derive other keys from this key.
            | , defaults to 0

        :param key_type:

            +-------------------+-------+------------------+
            |Key type           | Value | Key size in bits |
            +===================+=======+==================+
            |   AES             |0x2400 | 128/192/256      |
            +-------------------+-------+------------------+
            |  HMAC             |0x1100 | 224/256/384/512  |
            +-------------------+-------+------------------+
            | OEM_IMPORT_MK_SK* |0x9200 | 128/192/256      |
            +-------------------+-------+------------------+

            , defaults to AES

        :param key_size_bits:  Derived key size bits attribute, defaults to 0
        :param key_lifetime: Imported key lifetime attribute

            | ELE_KEY_IMPORT_VOLATILE           0xC0020000  Standard volatile key.
            | ELE_KEY_IMPORT_PERSISTENT         0xC0020001  Standard persistent key.
            | ELE_KEY_IMPORT_PERMANENT          0xC00200FF  Standard permanent key., defaults to PERSISTENT

        :param key_lifecycle: Imported key lifecycle attribute

            | CURRENT  0x00  Key is usable in current lifecycle.
            | OPEN  0x01  Key is usable in open lifecycle.
            | CLOSED  0x02  Key is usable in closed lifecycle.
            | CLOSED and LOCKED  0x04  Key is usable in closed and locked lifecycle.
            | , defaults to OPEN

        :param oem_import_mk_sk_key_id: Identifier in the ELE key storage of the OEM_IMPORT_MK_SK key to use
            to encrypt and sign the imported key, defaults to 0
        :param wrapping_algorithm: Wrapping algorithm of the key blob. This field is
            required to distinguish between different flavors of wrapping algorithms.

            Possible values are:
            - 0x01: RFC3394 wrapping
            - 0x02: AES CBC wrapping

        :param iv: IV to use for CBC wrapping. Not used if 'wrapping algorithm' not equal 0x02.
        :param signing_algorithm: Algorithm used to sign the blob itself. Field “Signature” of this blob.
            It must be: 0x01 (CMAC).
        :param wrapped_private_key: Private key data in encrypted format as defined by the 'Wrapping Algorithm'.
            Key used to do the encryption must be OEM_IMPORT_WRAP_SK derived from OEM_IMPORT_MK_SK.
        :param signature: Signature of all previous fields of this blob including
            the signature tag (0x5E) and signature length fields. Key used to do the signature must be
            OEM_IMPORT_CMAC_SK derived from OEM_IMPORT_MK_SK.


        """
        self.family = family
        self.reserved = RESERVED
        self.key_id = key_id
        self.permitted_algorithm = permitted_algorithm
        self.key_usage: list[KeyUsage] = key_usage or []
        self.key_type = key_type
        self.key_size_bits = key_size_bits
        self.key_lifetime = key_lifetime
        self.key_lifecycle = key_lifecycle
        self.oem_import_mk_sk_key_id = oem_import_mk_sk_key_id
        self.wrapping_algorithm = wrapping_algorithm
        self.iv = iv or bytes(16)
        self.signing_algorithm = signing_algorithm
        self.wrapped_private_key = wrapped_private_key
        self.signature = signature

    @property
    def payload_len(self) -> int:
        """Message payload length in bytes."""
        return len(self.export())

    def wrap_and_sign(
        self, private_key: bytes, oem_import_mk_sk_key: bytes, srkh: Optional[bytes] = None
    ) -> None:
        """Get wrapped key and sign whole Import Key message.

        :param private_key: Unwrapped private key
        :param oem_import_mk_sk_key: OEM_IMPORT_MK_SK_KEY
        :param srkh: Optionally SRKH if Salt flags requires it in Key Exchange commands, defaults to None
        """
        oem_import_wrap_sk = hkdf(
            salt=srkh or bytes(32),
            ikm=oem_import_mk_sk_key,
            info="oemelefwkeyimportwrap256".encode(),
            length=32,
        )
        oem_import_cmac_sk = hkdf(
            salt=srkh or bytes(32),
            ikm=oem_import_mk_sk_key,
            info="oemelefwkeyimportcmac256".encode(),
            length=32,
        )
        logger.info(f"Derived OEM_IMPORT_WRAP_SK: {oem_import_wrap_sk.hex()}")
        logger.info(f"Derived OEM_IMPORT_CMAC_SK: {oem_import_cmac_sk.hex()}")
        if self.wrapping_algorithm == WrappingAlgorithm.RFC3394:
            self.wrapped_private_key = aes_key_wrap(kek=oem_import_wrap_sk, key_to_wrap=private_key)
        elif self.wrapping_algorithm == WrappingAlgorithm.AES_CBC:
            self.wrapped_private_key = aes_cbc_encrypt(
                key=oem_import_wrap_sk, plain_data=private_key, iv_data=self.iv
            )
        else:
            raise SPSDKError(f"Invalid wrapping algorithm: {self.wrapping_algorithm}")

        self.signature = cmac(key=oem_import_cmac_sk, data=self.export()[:-16])

    class Ki(X690Type[bytes]):
        """Key Import base field type."""

        TAG = 0x00
        TYPECLASS = TypeClass.APPLICATION
        NATURE = [TypeNature.PRIMITIVE]

    class KiMagic(Ki):
        """TLV record - Magic header."""

        TAG = 0x00

    class KiKeyId(Ki):
        """TLV record - Key ID."""

        TAG = 0x01

    class KiKeyAlgorithm(Ki):
        """TLV record - Key algorithm."""

        TAG = 0x02

    class KiKeyUsage(Ki):
        """TLV record - Key usage."""

        TAG = 0x03

    class KiKeyType(Ki):
        """TLV record - Key type."""

        TAG = 0x04

    class KiKeyBitsSize(Ki):
        """TLV record - Key size."""

        TAG = 0x05

    class KiKeyLifeTime(Ki):
        """TLV record - Key life time."""

        TAG = 0x06

    class KiKeyLifeCycle(Ki):
        """TLV record - Key life cycle."""

        TAG = 0x07

    class KiImportMkSkKeyId(Ki):
        """TLV record - Import MK SK KEY id."""

        TAG = 0x10

    class KiWrappingAlgorithm(Ki):
        """TLV record - Key wrapping algorithm."""

        TAG = 0x11

    class KiIv(Ki):
        """TLV record - Optional Initial vector."""

        TAG = 0x12

    class KiSigningAlgorithm(Ki):
        """TLV record - Key signing algorithm."""

        TAG = 0x14

    class KiEncryptedPrk(Ki):
        """TLV record - Key wrapped data."""

        TAG = 0x15

    class KiSignature(Ki):
        """TLV record - Signature."""

        TAG = 0x1E

    def export(self) -> bytes:
        """Exports message payload to bytes array.

        :return: Bytes representation of message payload.
        """
        key_usage = 0
        for usage in self.key_usage:
            key_usage |= usage.tag

        ret = bytes()
        ret += bytes(self.KiMagic(self.HEADER_MAGIC.encode()))
        ret += bytes(self.KiKeyId(self.key_id.to_bytes(4, "big")))
        ret += bytes(self.KiKeyAlgorithm(self.permitted_algorithm.tag.to_bytes(4, "big")))
        ret += bytes(self.KiKeyUsage(key_usage.to_bytes(4, "big")))
        ret += bytes(self.KiKeyType(self.key_type.tag.to_bytes(2, "big")))
        ret += bytes(self.KiKeyBitsSize(self.key_size_bits.to_bytes(4, "big")))
        ret += bytes(self.KiKeyLifeTime(self.key_lifetime.tag.to_bytes(4, "big")))
        ret += bytes(self.KiKeyLifeCycle(self.key_lifecycle.tag.to_bytes(4, "big")))
        ret += bytes(self.KiImportMkSkKeyId(self.oem_import_mk_sk_key_id.to_bytes(4, "big")))
        ret += bytes(self.KiWrappingAlgorithm(self.wrapping_algorithm.tag.to_bytes(4, "big")))
        if self.wrapping_algorithm == WrappingAlgorithm.AES_CBC:
            ret += bytes(self.KiIv(self.iv))
        ret += bytes(self.KiSigningAlgorithm(self.signing_algorithm.tag.to_bytes(4, "big")))
        ret += bytes(self.KiEncryptedPrk(self.wrapped_private_key))
        ret += bytes(self.KiSignature(self.signature))

        return ret

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse object from bytes array.

        :param data: Binary data with Payload to parse.
        :return: New instance with parsed data.
        """
        # Create a new instance with default values
        instance = cls(
            family=FamilyRevision("mx93"),  # Will be set properly if needed
            key_id=0,
            permitted_algorithm=KeyAlgorithm.SHA256,
            key_usage=[],
            key_type=KeyType.AES,
            key_size_bits=0,
            key_lifetime=LifeTime.ELE_KEY_IMPORT_PERMANENT,
            key_lifecycle=LifeCycle.OPEN,
            oem_import_mk_sk_key_id=0,
            wrapping_algorithm=WrappingAlgorithm.RFC3394,
            iv=None,
            signing_algorithm=KeyImportSigningAlgorithm.CMAC,
            wrapped_private_key=bytes(),
            signature=bytes(),
        )

        tlv_magic, nxt = decode(data=data, enforce_type=instance.KiMagic)
        if tlv_magic.value.decode() != instance.HEADER_MAGIC:
            raise SPSDKParsingError("This is not Import Key datablob, magic value is invalid.")
        tlv_key_id, nxt = decode(data=data, start_index=nxt, enforce_type=instance.KiKeyId)
        tlv_permitted_algorithm, nxt = decode(
            data=data, start_index=nxt, enforce_type=instance.KiKeyAlgorithm
        )
        tlv_key_usage, nxt = decode(data=data, start_index=nxt, enforce_type=instance.KiKeyUsage)
        tlv_key_type, nxt = decode(data=data, start_index=nxt, enforce_type=instance.KiKeyType)
        tlv_key_size_bits, nxt = decode(
            data=data, start_index=nxt, enforce_type=instance.KiKeyBitsSize
        )
        tlv_key_lifetime, nxt = decode(
            data=data, start_index=nxt, enforce_type=instance.KiKeyLifeTime
        )
        tlv_key_lifecycle, nxt = decode(
            data=data, start_index=nxt, enforce_type=instance.KiKeyLifeCycle
        )
        tlv_oem_import_mk_sk_key_id, nxt = decode(
            data=data, start_index=nxt, enforce_type=instance.KiImportMkSkKeyId
        )
        tlv_wrapping_algorithm, nxt = decode(
            data=data, start_index=nxt, enforce_type=instance.KiWrappingAlgorithm
        )
        wrapping_algorithm = WrappingAlgorithm.from_tag(
            int.from_bytes(tlv_wrapping_algorithm.value, "big")
        )
        if wrapping_algorithm == WrappingAlgorithm.AES_CBC:
            tlv_iv, nxt = decode(data=data, start_index=nxt, enforce_type=instance.KiIv)
        else:
            tlv_iv = None
        tlv_signing_algorithm, nxt = decode(
            data=data, start_index=nxt, enforce_type=instance.KiSigningAlgorithm
        )
        tlv_wrapped_private_key, nxt = decode(
            data=data, start_index=nxt, enforce_type=instance.KiEncryptedPrk
        )
        tlv_signature, nxt = decode(data=data, start_index=nxt, enforce_type=instance.KiSignature)

        # Set parsed values on the instance
        instance.key_id = int.from_bytes(tlv_key_id.value, "big")
        instance.permitted_algorithm = KeyAlgorithm.from_tag(
            int.from_bytes(tlv_permitted_algorithm.value, "big")
        )
        key_usage = int.from_bytes(tlv_key_usage.value, "big")
        instance.key_usage.clear()
        for tag in KeyUsage.tags():
            if tag & key_usage:
                instance.key_usage.append(KeyUsage.from_tag(tag))
        instance.key_type = KeyType.from_tag(int.from_bytes(tlv_key_type.value, "big"))
        instance.key_size_bits = int.from_bytes(tlv_key_size_bits.value, "big")
        instance.key_lifetime = LifeTime.from_tag(int.from_bytes(tlv_key_lifetime.value, "big"))
        instance.key_lifecycle = LifeCycle.from_tag(int.from_bytes(tlv_key_lifecycle.value, "big"))
        instance.oem_import_mk_sk_key_id = int.from_bytes(tlv_oem_import_mk_sk_key_id.value, "big")
        instance.wrapping_algorithm = WrappingAlgorithm.from_tag(
            int.from_bytes(tlv_wrapping_algorithm.value, "big")
        )
        instance.iv = tlv_iv.value if tlv_iv else bytes(16)
        instance.signing_algorithm = KeyImportSigningAlgorithm.from_tag(
            int.from_bytes(tlv_signing_algorithm.value, "big")
        )
        instance.wrapped_private_key = tlv_wrapped_private_key.value
        instance.signature = tlv_signature.value

        return instance

    def verify(self) -> Verifier:
        """Verify message properties."""
        ret = Verifier("TLV blob")
        ret.add_record_range("Key ID", self.key_id)
        ret.add_record_enum("Key import algorithm", self.permitted_algorithm, KeyAlgorithm)
        for key_usage in self.key_usage:
            ret.add_record_enum(f"Key usage [{key_usage.label}]", key_usage, KeyUsage)
        ret.add_record_enum("Key type", self.key_type, KeyType)
        ret.add_record_range("Key bit size", self.key_size_bits)
        ret.add_record_enum("Key life time", self.key_lifetime, LifeTime)
        ret.add_record_enum("Key life cycle", self.key_lifecycle, LifeCycle)
        ret.add_record_range("OEM import MK SK key ID", self.oem_import_mk_sk_key_id)
        ret.add_record_enum("Key wrapping algorithm", self.wrapping_algorithm, WrappingAlgorithm)
        ret.add_record_bytes("Initial Vector", self.iv, min_length=16, max_length=16)
        ret.add_record_enum(
            "Key signing algorithm", self.signing_algorithm, KeyImportSigningAlgorithm
        )
        ret.add_record_bytes("Import key wrapped data", self.wrapped_private_key, min_length=4)
        ret.add_record_bytes("Signature", self.signature, min_length=16, max_length=16)

        return ret

    def __str__(self) -> str:
        ret = super().__str__() + "\n"
        ret += f"  Key ID value: 0x{self.key_id:08X}, {self.key_id}\n"
        ret += f"  Key import algorithm value: {self.permitted_algorithm.label}\n"
        ret += f"  Key usage value: {[x.label for x in self.key_usage]}\n"
        ret += f"  Key type value: {self.key_type.label}\n"
        ret += f"  Key bit size value: 0x{self.key_size_bits:08X}, {self.key_size_bits}\n"
        ret += f"  Key life time value: {self.key_lifetime.label}\n"
        ret += f"  Key life cycle value: {self.key_lifecycle.label}\n"
        ret += (
            f"  OEM Import MK SK key ID value: 0x{self.oem_import_mk_sk_key_id:08X},"
            f" {self.oem_import_mk_sk_key_id}\n"
        )
        ret += f"  Key wrapping algorithm: {self.wrapping_algorithm.label}\n"
        ret += f"  Initial vector value: {self.iv.hex()}\n"
        ret += f"  Key signing algorithm: {self.signing_algorithm.label}\n"
        ret += f"  Import key wrapped data: {self.wrapped_private_key.hex()}\n"
        ret += f"  Signature: {self.signature.hex()}"
        return ret

    @classmethod
    def _load_from_config(cls, config: Config, family: FamilyRevision) -> Self:
        """Converts the configuration option into an message object.

        "config" content of container configurations.

        :param config: Message configuration dictionaries.
        :param family: Family revision context.
        :param base_cls: Base message class for configuration loading.
        :raises SPSDKError: Invalid configuration detected.
        :return: Message object.
        """
        command = config.get_config("command")
        if len(command) != 1:
            raise SPSDKError(f"Invalid config field command: {command}")
        command_name = list(command.keys())[0]
        if TLVTypes.from_label(command_name) != cls.NAME:
            raise SPSDKError("Invalid configuration for Key Import Request command.")

        key_import = command.get_config("KEY_IMPORT")

        key_id = key_import.get_int("key_id", 0)
        key_algorithm = KeyAlgorithm.from_attr(key_import.get_str("permitted_algorithm", "SHA256"))
        key_usage = [KeyUsage.from_attr(x) for x in key_import.get_list("key_usage", [])]
        key_type = KeyType.from_attr(key_import.get_str("key_type", "AES"))
        key_size_bits = key_import.get_int("key_size_bits", 128)
        key_lifetime = LifeTime.from_attr(
            key_import.get_str("key_lifetime", "ELE_KEY_IMPORT_PERMANENT")
        )
        key_lifecycle = LifeCycle.from_attr(key_import.get_str("key_lifecycle", "OPEN"))
        oem_mk_sk_key_id = key_import.get_int("oem_mk_sk_key_id", 0)
        key_wrapping_algorithm = WrappingAlgorithm.from_attr(
            key_import.get_str("key_wrapping_algorithm", "RFC3394")
        )
        if key_wrapping_algorithm == WrappingAlgorithm.AES_CBC:
            iv = key_import.load_symmetric_key(key="iv", expected_size=16, default=bytes(16))
        else:
            iv = None
        signing_algorithm = KeyImportSigningAlgorithm.from_attr(
            key_import.get_str("signing_algorithm", "CMAC")
        )

        ret = cls(
            family=family,
            key_id=key_id,
            permitted_algorithm=key_algorithm,
            key_usage=key_usage,
            key_type=key_type,
            key_size_bits=key_size_bits,
            key_lifetime=key_lifetime,
            key_lifecycle=key_lifecycle,
            oem_import_mk_sk_key_id=oem_mk_sk_key_id,
            wrapping_algorithm=key_wrapping_algorithm,
            iv=iv,
            signing_algorithm=signing_algorithm,
            wrapped_private_key=bytes(4),
            signature=bytes(16),
        )

        if "import_key" in key_import and "oem_import_mk_sk_key" in key_import:
            logger.info(
                "The Import key Signed message created with raw key and OEM_IMPORT_MK_SK key."
            )
            if key_type == KeyType.ECC:
                import_key = PrivateKeyEcc.load(
                    key_import.get_input_file_name("import_key")
                ).export(encoding=SPSDKEncoding.NXP)
            else:
                import_key = key_import.load_symmetric_key(
                    "import_key", expected_size=key_size_bits // 8
                )
            oem_import_mk_sk_key = key_import.load_symmetric_key(
                "oem_import_mk_sk_key", expected_size=32
            )
            srkh = (
                key_import.load_symmetric_key("srkh", expected_size=32)
                if "srkh" in key_import
                else None
            )
            ret.wrap_and_sign(
                private_key=import_key,
                oem_import_mk_sk_key=oem_import_mk_sk_key,
                srkh=srkh,
            )
        elif "wrapped_key" in key_import and "signature" in key_import:
            logger.info(
                "The Import key Signed message created with already wrapped key and signature."
            )
            ret.wrapped_private_key = key_import.get_bytes("wrapped_key", bytes(4))
            ret.signature = key_import.load_symmetric_key(
                "signature", expected_size=16, default=bytes(16)
            )

        else:
            raise SPSDKValueError("Invalid IMPORT KEY configuration.")

        return ret

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the Key Import TLV.

        :param data_path: Path where to store the data files.
        :return: Configuration dictionary.
        """
        # Create the base configuration structure
        config_dict = {
            "family": self.family.name,
            "revision": self.family.revision,
            "output": "parsed_tlv.bin",
            "command": {
                "KEY_IMPORT": {
                    "key_id": f"0x{self.key_id:08X}",
                    "permitted_algorithm": self.permitted_algorithm.label,
                    "key_usage": [x.label for x in self.key_usage],
                    "key_type": self.key_type.label,
                    "key_size_bits": self.key_size_bits,
                    "key_lifetime": self.key_lifetime.label,
                    "key_lifecycle": self.key_lifecycle.label,
                    "oem_mk_sk_key_id": f"0x{self.oem_import_mk_sk_key_id:08X}",
                    "key_wrapping_algorithm": self.wrapping_algorithm.label,
                    "signing_algorithm": self.signing_algorithm.label,
                    "wrapped_key": "0x" + self.wrapped_private_key.hex(),
                    "signature": "0x" + self.signature.hex(),
                    "iv": "0x" + self.iv.hex() if self.iv else None,
                }
            },
        }

        # Create Config object from dictionary
        cfg = Config(config_dict)
        return cfg
