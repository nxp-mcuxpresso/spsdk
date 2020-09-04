#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module with Debugcredential class."""

import binascii
from struct import pack, unpack_from
from typing import List, Type

from spsdk import crypto
from spsdk.dat.utils import ecc_public_numbers_to_bytes, ecc_key_to_bytes, rsa_key_to_bytes
from spsdk.utils.crypto.backend_internal import internal_backend
from spsdk.crypto import utils_cryptography


class DebugCredential:
    """Base class for DebugCredential."""

    FORMAT = 'INVALID_FORMAT'
    FORMAT_NO_SIG = 'INVALID_FORMAT'

    def __init__(self, version: str, socc: int, uuid: str, rot_meta: bytes, dck_pub: bytes,
                 cc_socu: int, cc_vu: int, cc_beacon: int, rot_pub: bytes, signature: bytes = None) -> None:
        """Initialize the DebugCredential object.

        :param version: The string representing version: for RSA: 1.0, for ECC: 2.0, 2.1, 2.2
        :param socc: The SoC Class that this credential applies to
        :param uuid: The string representing the unique device identifier
        :param rot_meta: Metadata for Root of Trust
        :param dck_pub: Internal binary representation of Debug Credential public key
        :param cc_socu: The Credential Constraint value that the vendor has associated with this credential.
        :param cc_vu: The Vendor Usage constraint value that the vendor has associated with this credential.
        :param cc_beacon: The non-zero Credential Beacon value, which is bound to a DC
        :param rot_pub: Internal binary representation of RoT public key
        :param signature: Debug Credential signature
        """
        self.version = version
        self.socc = socc
        self.uuid = uuid
        self.rot_meta = rot_meta
        self.dck_pub = dck_pub
        self.cc_socu = cc_socu
        self.cc_vu = cc_vu
        self.cc_beacon = cc_beacon
        self.rot_pub = rot_pub
        self.signature = signature

    def export(self) -> bytes:
        """Export to binary form (serialization).

        :return: binary representation of the debug credential
        """
        data = pack(
            self.FORMAT,
            *[int(v) for v in self.version.split('.')],
            self.socc, bytes.fromhex(self.uuid), self.rot_meta, self.dck_pub, self.cc_socu,
            self.cc_vu, self.cc_beacon, self.rot_pub, self.signature
        )
        return data

    def info(self) -> str:
        """String representation of DebugCredential.

        :return: binary representation of the debug credential
        """
        msg = f"Version : {self.version}\n"
        msg += f"SOCC    : {self.socc}\n"
        msg += f"UUID    : {self.uuid}\n"
        msg += f"CC_SOCC : {hex(self.cc_socu)}\n"
        msg += f"CC_VU   : {hex(self.cc_vu)}\n"
        msg += f"BEACON  : {self.cc_beacon}\n"
        return msg

    def _get_data_to_sign(self) -> bytes:
        data = pack(
            self.FORMAT_NO_SIG,
            *[int(v) for v in self.version.split('.')],
            self.socc, bytes.fromhex(self.uuid), self.rot_meta, self.dck_pub,
            self.cc_socu, self.cc_vu, self.cc_beacon, self.rot_pub
        )
        return data

    @staticmethod
    def _get_signature(data: bytes, rotk_priv_path: str) -> bytes:
        """Creates a cryptographic signature over the data.

        :return: binary representing the signature
        """
        raise NotImplementedError('Derived class has to implement this method.')

    @staticmethod
    def _get_rot_meta(rot_pub_keys: List[str]) -> bytes:
        """Creates the RoT meta-data required by the device to corroborate.

        :return: binary representing the rot-meta data
        """
        raise NotImplementedError('Derived class has to implement this method.')

    @staticmethod
    def _get_dck(dck_key_path: str) -> bytes:
        """Loads the Debugger Public Key (DCK).

        :return: binary representing the DCK key
        """
        raise NotImplementedError('Derived class has to implement this method.')

    @staticmethod
    def _get_rotk(rotk_priv_key: str, rot_pub_keys: List[str]) -> bytes:
        """Loads the vendor RoT private key.

        Derive from it and gets public key as bytes used by the device
        to verify the signature of this DC.

        :return: binary representing the rotk public key
        """
        raise NotImplementedError('Derived class has to implement this method.')

    @classmethod
    def __get_class(cls, version: str) -> 'Type[DebugCredential]':
        return _version_mapping[version]

    @classmethod
    def from_yaml_config(cls, version: str, yaml_config: dict) -> 'DebugCredential':
        """Create a debugcredential object out of yaml configuration.

        :return: DebugCredential object
        """
        klass = DebugCredential.__get_class(version=version)
        dc_obj = klass(
            version=version, socc=yaml_config['socc'], uuid=yaml_config['uuid'],
            rot_meta=klass._get_rot_meta(yaml_config['rot_meta']),
            dck_pub=klass._get_dck(yaml_config['dck']),
            cc_socu=yaml_config['cc_socu'],
            cc_vu=yaml_config['cc_vu'], cc_beacon=yaml_config['cc_beacon'],
            rot_pub=klass._get_rotk(yaml_config['rotk'], yaml_config['rot_meta'])
        )
        # calculate signature
        dc_obj.signature = dc_obj._get_signature(dc_obj._get_data_to_sign(), yaml_config['rotk'])
        return dc_obj

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> 'DebugCredential':
        """Parse the debug credential.

        :param data: Raw data as bytes
        :param offset: Offset of input data
        :return: DebugCredential object
        """
        version = "{}.{}".format(*unpack_from("<2H", data, offset))
        klass = cls.__get_class(version)
        _, _, socc, uuid, *rest = unpack_from(klass.FORMAT, data, offset)
        return klass(version, socc, uuid.hex().upper(), *rest)


class DebugCredentialRSA(DebugCredential):
    """Class for RSA specific of DebugCredential."""

    FORMAT_NO_SIG = "<2HL16s128s260s3L260s"
    FORMAT = "<2HL16s128s260s3L260s256s"

    @staticmethod
    def _get_signature(data: bytes, rotk_priv_path: str) -> bytes:
        """Creates a rsa signature over the data.

        :return: binary representing the signature
        """
        priv_rotk = crypto.load_private_key(file_path=rotk_priv_path). \
            private_bytes(encoding=crypto.Encoding.PEM,
                          format=crypto.serialization.PrivateFormat.PKCS8,
                          encryption_algorithm=crypto.serialization.NoEncryption())
        return internal_backend.rsa_sign(priv_rotk, data)

    @staticmethod
    def _get_rot_meta(rot_pub_keys: List[str]) -> bytes:
        """Creates the RoT meta-data required by the device to corroborate.

        The meta-data is created by getting the public numbers (modulus and exponent)
        from each of the RoT public keys, hashing them and combing together.

        :return: binary representing the rot-meta data
        """
        rot_meta = bytearray(128)
        for index, rot_key in enumerate(rot_pub_keys):
            rot = crypto.load_public_key(file_path=rot_key)
            assert isinstance(rot, crypto.RSAPublicKey)
            data = rsa_key_to_bytes(
                key=rot, exp_length=3, modulus_length=None)
            result = internal_backend.hash(data)
            rot_meta[index * 32:(index + 1) * 32] = result
        return bytes(rot_meta)

    @staticmethod
    def _get_dck(dck_key_path: str) -> bytes:
        """Loads the Debugger Public Key (DCK).

        :return: binary representing the DCK key
        """
        dck_key = crypto.load_public_key(file_path=dck_key_path)
        assert isinstance(dck_key, crypto.RSAPublicKey)
        return rsa_key_to_bytes(key=dck_key, exp_length=4)

    @staticmethod
    def _get_rotk(rotk_priv_key: str, _rot_pub_keys: List[str]) -> bytes:
        """Loads the vendor RoT private key.

         It corresponds to the (default) position zero RoT key in the rot_meta list of public keys.
         Derive public key from RoT private keys and converts it to the bytes.

        :return: binary representing the rotk public key
        """
        priv_key_rotk = crypto.load_private_key(file_path=rotk_priv_key)
        pub_key_rotk = priv_key_rotk.public_key()
        assert isinstance(pub_key_rotk, crypto.RSAPublicKey)
        return rsa_key_to_bytes(key=pub_key_rotk, exp_length=4)


class DebugCredentialECC(DebugCredential):
    """Class for ECC specific of DebugCredential."""

    FORMAT_NO_SIG = "<2HL16s528s132s3L4s"
    FORMAT = "<2HL16s528s132s3L4s132s"

    @staticmethod
    def _get_signature(data: bytes, rotk_priv_path: str) -> bytes:
        """Creates a cryptographic signature over the data.

        :return: binary representing the signature
        """
        priv_rotk = crypto.load_private_key(file_path=rotk_priv_path)
        assert isinstance(priv_rotk, crypto.EllipticCurvePrivateKeyWithSerialization)
        signature = priv_rotk.sign(data, crypto.ec.ECDSA(crypto.hashes.SHA256()))
        r, s = utils_cryptography.decode_dss_signature(signature)
        public_numbers = crypto.EllipticCurvePublicNumbers(r, s, priv_rotk.curve)
        return ecc_public_numbers_to_bytes(public_numbers=public_numbers)

    @staticmethod
    def _get_rot_meta(rot_pub_keys: List[str]) -> bytes:
        """Creates the RoT meta-data required by the device to corroborate.

        The meta-data is created by getting the public numbers (modulus and exponent)
        from each of the RoT public keys, hashing them and combing together.

        :return: binary representing the rot-meta data
        """
        rot_meta = bytearray(528)
        for index, rot_key in enumerate(rot_pub_keys):
            rot = crypto.load_public_key(file_path=rot_key)
            assert isinstance(rot, crypto.EllipticCurvePublicKey)
            data = ecc_key_to_bytes(key=rot, length=66)
            rot_meta[index * 132:(index + 1) * 132] = data
        return bytes(rot_meta)

    @staticmethod
    def _get_dck(dck_key_path: str) -> bytes:
        """Loads the Debugger Public Key (DCK).

        :return: binary representing the DCK key
        """
        dck_key = crypto.load_public_key(file_path=dck_key_path)
        assert isinstance(dck_key, crypto.EllipticCurvePublicKey)
        return ecc_key_to_bytes(key=dck_key, length=66)

    @staticmethod
    def _get_rotk(rotk_priv_key: str, rot_pub_keys: List[str]) -> bytes:
        """Creates RoTKey_Pub (2 element 16-bit array (little endian).

        CTRKtable index (RoT meta-data) of the public key used by the vendor to sign the DC.
        Curve identifier:
        - Secp256r1: 0x0001
        - Secp384r1: 0x0002
        - Secp521r1: 0x0003

        :return: binary representation
        """
        priv_loaded = crypto.load_private_key(rotk_priv_key)
        pub_from_priv = priv_loaded.public_key()
        pub_numbers = pub_from_priv.public_numbers()
        rot_pub_numbers = [crypto.load_public_key(k).public_numbers() for k in rot_pub_keys]
        key_index = rot_pub_numbers.index(pub_numbers)
        assert key_index is not None, "ROTK private key does not correspond to any of RotMeta public keys."
        curve_index = {
            256: 1, 384: 2, 521: 3
        }[pub_from_priv.key_size]
        return pack('<2H', key_index, curve_index)


class DebugCredentialRSA2048(DebugCredentialRSA):
    """DebugCredential class for RSA 2048."""

    FORMAT = "<2HL16s128s260s3L260s256s"
    FORMAT_NO_SIG = "<2HL16s128s260s3L260s"


class DebugCredentialRSA4096(DebugCredentialRSA):
    """DebugCredential class for RSA 4096."""
    FORMAT = "<2HL16s128s514s3L514s512s"
    FORMAT_NO_SIG = "<2HL16s128s514s3L514s"


class DebugCredentialECC256(DebugCredentialECC):
    """DebugCredential class for ECC 256."""
    pass


class DebugCredentialECC384(DebugCredentialECC):
    """DebugCredential class for ECC 384."""
    pass


class DebugCredentialECC521(DebugCredentialECC):
    """DebugCredential class for ECC 521."""
    pass


_version_mapping = {
    '1.0': DebugCredentialRSA2048,
    '1.1': DebugCredentialRSA4096,
    '2.0': DebugCredentialECC256,
    '2.1': DebugCredentialECC384,
    '2.2': DebugCredentialECC521,
}
