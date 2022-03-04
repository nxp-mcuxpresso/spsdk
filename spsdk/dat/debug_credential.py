#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module with Debugcredential class."""

from struct import calcsize, pack, unpack_from
from typing import Any, List, Type

from spsdk import SPSDKError, crypto
from spsdk.crypto import SignatureProvider
from spsdk.crypto.loaders import extract_public_key
from spsdk.dat.utils import ecc_key_to_bytes, ecc_public_numbers_to_bytes, rsa_key_to_bytes
from spsdk.utils.crypto.backend_internal import internal_backend


class DebugCredential:
    """Base class for DebugCredential."""

    # Subclasses override the following invalid class member values
    FORMAT = "INVALID_FORMAT"
    FORMAT_NO_SIG = "INVALID_FORMAT"
    VERSION = "0.0"
    HASH_LENGTH = 32

    def __init__(
        self,
        socc: int,
        uuid: bytes,
        rot_meta: bytes,
        dck_pub: bytes,
        cc_socu: int,
        cc_vu: int,
        cc_beacon: int,
        rot_pub: bytes,
        signature: bytes = None,
        signature_provider: SignatureProvider = None,
    ) -> None:
        """Initialize the DebugCredential object.

        :param socc: The SoC Class that this credential applies to
        :param uuid: The bytes of the unique device identifier
        :param rot_meta: Metadata for Root of Trust
        :param dck_pub: Internal binary representation of Debug Credential public key
        :param cc_socu: The Credential Constraint value that the vendor has associated with this credential.
        :param cc_vu: The Vendor Usage constraint value that the vendor has associated with this credential.
        :param cc_beacon: The non-zero Credential Beacon value, which is bound to a DC
        :param rot_pub: Internal binary representation of RoT public key
        :param signature: Debug Credential signature
        :param signature_provider: external signature provider
        """
        self.socc = socc
        self.uuid = uuid
        self.rot_meta = rot_meta
        self.dck_pub = dck_pub
        self.cc_socu = cc_socu
        self.cc_vu = cc_vu
        self.cc_beacon = cc_beacon
        self.rot_pub = rot_pub
        self.signature = signature
        self.signature_provider = signature_provider

    def export(self) -> bytes:
        """Export to binary form (serialization).

        :return: binary representation of the debug credential
        :raises SPSDKError: When Debug Credential Signature is not set, call the .sign method first
        """
        # make sure user called .sign before
        if not self.signature:
            raise SPSDKError("Debug Credential Signature is not set, call the .sign method first")
        data = pack(
            self.FORMAT,
            *[int(v) for v in self.VERSION.split(".")],
            self.socc,
            self.uuid,
            self.rot_meta,
            self.dck_pub,
            self.cc_socu,
            self.cc_vu,
            self.cc_beacon,
            self.rot_pub,
            self.signature,
        )
        return data

    def info(self) -> str:
        """String representation of DebugCredential.

        :return: binary representation of the debug credential
        """
        msg = f"Version : {self.VERSION}\n"
        msg += f"SOCC    : {self.socc}\n"
        msg += f"UUID    : {self.uuid.hex().upper()}\n"
        msg += f"CC_SOCC : {hex(self.cc_socu)}\n"
        msg += f"CC_VU   : {hex(self.cc_vu)}\n"
        msg += f"BEACON  : {self.cc_beacon}\n"
        return msg

    def sign(self) -> None:
        """Sign the DC data using SignatureProvider."""
        if not self.signature_provider:
            raise SPSDKError("Debug Credential Signature provider is not set")
        signature = self.signature_provider.sign(self._get_data_to_sign())
        if not signature:
            raise SPSDKError("Debug Credential Signature provider didn't return any signature")
        self.signature = signature

    def _get_data_to_sign(self) -> bytes:
        """Collects data meant for signing."""
        data = pack(
            self.FORMAT_NO_SIG,
            *[int(v) for v in self.VERSION.split(".")],
            self.socc,
            self.uuid,
            self.rot_meta,
            self.dck_pub,
            self.cc_socu,
            self.cc_vu,
            self.cc_beacon,
            self.rot_pub,
        )
        return data

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, DebugCredential) and vars(self) == vars(other)

    @staticmethod
    def _get_rot_meta(used_root_cert: int, rot_pub_keys: List[str]) -> bytes:
        """Creates the RoT meta-data required by the device to corroborate.

        :return: binary representing the rot-meta data
        :raises NotImplementedError: Derived class has to implement this method
        """
        raise NotImplementedError("Derived class has to implement this method.")

    @staticmethod
    def _get_dck(dck_key_path: str) -> bytes:
        """Loads the Debugger Public Key (DCK).

        :return: binary representing the DCK key
        :raises NotImplementedError: Derived class has to implement this method
        """
        raise NotImplementedError("Derived class has to implement this method.")

    @staticmethod
    def _get_rot_pub(rot_pub_id: int, rot_pub_keys: List[str]) -> bytes:
        """Loads the vendor RoT Public key that corresponds to the private key used for singing.

        :return: binary representing the rotk public key
        :raises NotImplementedError: Derived class has to implement this method
        """
        raise NotImplementedError("Derived class has to implement this method.")

    @classmethod
    def _get_class(cls, version: str, socc: int) -> "Type[DebugCredential]":
        if socc == 4:
            return _lpc55s3x_version_mapping[version]
        return _version_mapping[version]

    @classmethod
    def create_from_yaml_config(cls, version: str, yaml_config: dict) -> "DebugCredential":
        """Create a debugcredential object out of yaml configuration.

        :return: DebugCredential object
        """
        socc = yaml_config["socc"]
        klass = DebugCredential._get_class(version=version, socc=socc)
        dc_obj = klass(
            socc=yaml_config["socc"],
            uuid=bytes.fromhex(yaml_config["uuid"]),
            rot_meta=klass._get_rot_meta(  # pylint: disable=protected-access
                used_root_cert=yaml_config["rot_id"],
                rot_pub_keys=yaml_config["rot_meta"],
            ),
            dck_pub=klass._get_dck(yaml_config["dck"]),  # pylint: disable=protected-access
            cc_socu=yaml_config["cc_socu"],
            cc_vu=yaml_config["cc_vu"],
            cc_beacon=yaml_config["cc_beacon"],
            rot_pub=klass._get_rot_pub(  # pylint: disable=protected-access
                yaml_config["rot_id"], yaml_config["rot_meta"]
            ),
            signature_provider=SignatureProvider.create(
                # if the yaml_config doesn't contain 'sign_provider' assume file-type
                yaml_config.get("sign_provider")
                or f'type=file;file_path={yaml_config["rotk"]}'
            ),
        )
        return dc_obj

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "DebugCredential":
        """Parse the debug credential.

        :param data: Raw data as bytes
        :param offset: Offset of input data
        :return: DebugCredential object
        """
        ver = unpack_from("<2H", data, offset)
        version = f"{ver[0]}.{ver[1]}"
        socc = unpack_from("<L", data, offset + 4)
        klass = cls._get_class(version, socc[0])
        return klass.get_instance_from_challenge(data[offset:])

    @classmethod
    def get_instance_from_challenge(cls, data: bytes) -> "DebugCredential":
        """Returns instance of class from DAP authentication challenge data.

        :return: Instance of this class.
        """
        _, _, *rest = unpack_from(cls.FORMAT, data, 0)
        return cls(*rest)


class DebugCredentialRSA(DebugCredential):
    """Class for RSA specific of DebugCredential."""

    FORMAT_NO_SIG = "<2HL16s128s260s3L260s"
    FORMAT = FORMAT_NO_SIG + "256s"

    @staticmethod
    def _get_rot_meta(used_root_cert: int, rot_pub_keys: List[str]) -> bytes:
        """Creates the RoT meta-data required by the device to corroborate.

        The meta-data is created by getting the public numbers (modulus and exponent)
        from each of the RoT public keys, hashing them and combing together.

        :return: binary representing the rot-meta data
        """
        rot_meta = bytearray(128)
        for index, rot_key in enumerate(rot_pub_keys):
            rot = extract_public_key(file_path=rot_key, password=None)
            assert isinstance(rot, crypto.RSAPublicKey)
            data = rsa_key_to_bytes(key=rot, exp_length=3, modulus_length=None)
            result = internal_backend.hash(data)
            rot_meta[index * 32 : (index + 1) * 32] = result
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
    def _get_rot_pub(rot_pub_id: int, rot_pub_keys: List[str]) -> bytes:
        """Loads the vendor RoT private key.

         It corresponds to the (default) position zero RoT key in the rot_meta list of public keys.
         Derive public key from RoT private keys and converts it to the bytes.

        :return: binary representing the rotk public key
        """
        pub_key_path = rot_pub_keys[rot_pub_id]
        pub_key = extract_public_key(file_path=pub_key_path, password=None)
        assert isinstance(pub_key, crypto.RSAPublicKey)
        return rsa_key_to_bytes(key=pub_key, exp_length=4)


class DebugCredentialECC(DebugCredential):
    """Class for ECC specific of DebugCredential."""

    FORMAT_NO_SIG = "<2HL16s528s132s3L4s"
    FORMAT = FORMAT_NO_SIG + "132s"
    CURVE: Any = crypto.ec.SECP256R1()
    CORD_LENGTH = 66

    def sign(self) -> None:
        """Sign the DC data using SignatureProvider."""
        super().sign()
        if not self.signature:
            raise SPSDKError("Debug Credential Signature is not set in base class")
        r, s = crypto.utils_cryptography.decode_dss_signature(self.signature)
        public_numbers = crypto.EllipticCurvePublicNumbers(r, s, self.CURVE)
        self.signature = ecc_public_numbers_to_bytes(
            public_numbers=public_numbers, length=self.CORD_LENGTH
        )

    @staticmethod
    def _get_rot_meta(used_root_cert: int, rot_pub_keys: List[str]) -> bytes:
        """Creates the RoT meta-data required by the device to corroborate.

        The meta-data is created by getting the public numbers (modulus and exponent)
        from each of the RoT public keys, hashing them and combing together.

        :return: binary representing the rot-meta data
        """
        rot_meta = bytearray(528)
        for index, rot_key in enumerate(rot_pub_keys):
            rot = extract_public_key(file_path=rot_key, password=None)
            assert isinstance(rot, crypto.EllipticCurvePublicKey)
            data = ecc_key_to_bytes(key=rot, length=66)
            rot_meta[index * 132 : (index + 1) * 132] = data
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
    def _get_rot_pub(rot_pub_id: int, rot_pub_keys: List[str]) -> bytes:
        """Creates RoTKey_Pub (2 element 16-bit array (little endian).

        CTRK table index (RoT meta-data) of the public key used by the vendor to sign the DC.
        Curve identifier:
        - Secp256r1: 0x0001
        - Secp384r1: 0x0002
        - Secp521r1: 0x0003

        :return: binary representation
        """
        pub_key_path = rot_pub_keys[rot_pub_id]
        pub_key = extract_public_key(file_path=pub_key_path, password=None)
        assert isinstance(pub_key, crypto.EllipticCurvePublicKey)
        curve_index = {256: 1, 384: 2, 521: 3}[pub_key.curve.key_size]
        return pack("<2H", rot_pub_id, curve_index)


class DebugCredentialRSA2048(DebugCredentialRSA):
    """DebugCredential class for RSA 2048."""

    FORMAT_NO_SIG = "<2HL16s128s260s3L260s"
    FORMAT = FORMAT_NO_SIG + "256s"
    VERSION = "1.0"


class DebugCredentialRSA4096(DebugCredentialRSA):
    """DebugCredential class for RSA 4096."""

    FORMAT_NO_SIG = "<2HL16s128s516s3L516s"
    FORMAT = FORMAT_NO_SIG + "512s"
    VERSION = "1.1"


class DebugCredentialECC256(DebugCredentialECC):
    """DebugCredential class for ECC 256."""

    VERSION = "2.0"
    CURVE = crypto.ec.SECP256R1()


class DebugCredentialECC384(DebugCredentialECC):
    """DebugCredential class for ECC 384."""

    VERSION = "2.1"
    CURVE = crypto.ec.SECP384R1()


class DebugCredentialECC521(DebugCredentialECC):
    """DebugCredential class for ECC 521."""

    VERSION = "2.2"
    CURVE = crypto.ec.SECP521R1()


class Lpc55s3xMixin(DebugCredentialECC):
    """LPC55s3x Class."""

    HASH_LENGTH = 0
    KEY_LENGTH = 0
    CORD_LENGTH = 0

    @staticmethod
    def _get_rot_meta(used_root_cert: int, rot_pub_keys: List[str]) -> bytes:
        """Creates the RoT meta-data required by the device to corroborate.

        :return: binary representing the rot-meta data
        """
        ctrk_hash_table = Lpc55s3xMixin.create_ctrk_table(rot_pub_keys)
        flags = Lpc55s3xMixin.calculate_flags(used_root_cert, rot_pub_keys)
        return flags + ctrk_hash_table

    @staticmethod
    def _get_dck(dck_key_path: str) -> bytes:
        """Loads the Debugger Public Key (DCK).

        :return: binary representing the DCK key
        """
        dck_key = crypto.load_public_key(file_path=dck_key_path)
        length = dck_key.key_size // 8
        assert isinstance(dck_key, crypto.EllipticCurvePublicKey)
        data = ecc_key_to_bytes(dck_key, length=length)
        return data

    @staticmethod
    def _get_rot_pub(rot_pub_id: int, rot_pub_keys: List[str]) -> bytes:
        """Loads the vendor RoT Public key that corresponds to the private key used for singing.

        :return: binary representing the rotk public key
        """
        root_key = rot_pub_keys[rot_pub_id]
        root_public_key = extract_public_key(file_path=root_key, password=None)
        length = root_public_key.key_size // 8
        assert isinstance(root_public_key, crypto.EllipticCurvePublicKey)
        data = ecc_key_to_bytes(root_public_key, length=length)
        return data

    def info(self) -> str:
        """String representation of DebugCredential.

        :return: binary representation of the debug credential
        """
        msg = f"Version : {self.VERSION}\n"
        msg += f"SOCC    : {self.socc}\n"
        msg += f"UUID    : {self.uuid.hex().upper()}\n"
        msg += f"CC_SOCC : {hex(self.cc_socu)}\n"
        msg += f"CC_VU   : {hex(self.cc_vu)}\n"
        msg += f"BEACON  : {self.cc_beacon}\n"
        ctrk_records_num = self.rot_meta[0] >> 4
        if ctrk_records_num == 1:
            msg += "CRTK table not present \n"
        else:
            msg += f"CRTK table has {ctrk_records_num} entries\n"
            # Compute and show RKTH HASH
            key_length = 256 if (len(self.rot_meta) - 4) == 32 else 384
            ctrk_hash = internal_backend.hash(data=self.rot_meta[4:], algorithm=f"sha{key_length}")
            msg += f"CRTK Hash: {ctrk_hash.hex()}"
        return msg

    @property
    def FORMAT(self) -> str:  # type: ignore # pylint: disable=invalid-name
        """Formatting string."""
        return f"<2HL16s3L{len(self.rot_meta)}s{self.HASH_LENGTH * 2}s{self.HASH_LENGTH * 2}s{self.HASH_LENGTH * 2}s"

    @property
    def FORMAT_NO_SIG(self) -> str:  # type: ignore # pylint: disable=invalid-name
        """Formatting string without signature."""
        return f"<2HL16s3L{len(self.rot_meta)}s{self.HASH_LENGTH * 2}s{self.HASH_LENGTH * 2}s"

    @staticmethod
    def create_ctrk_table(rot_pub_keys: List[str]) -> bytes:
        """Creates ctrk table."""
        if len(rot_pub_keys) == 1:
            return bytes()
        ctrk_table = bytes()
        for pub_key_path in rot_pub_keys:
            pub_key = extract_public_key(file_path=pub_key_path, password=None)
            assert isinstance(pub_key, crypto.EllipticCurvePublicKey)
            key_length = pub_key.key_size
            data = ecc_key_to_bytes(key=pub_key, length=key_length // 8)
            ctrk_hash = internal_backend.hash(data=data, algorithm=f"sha{key_length}")
            ctrk_table += ctrk_hash
        return ctrk_table

    @staticmethod
    def calculate_flags(used_root_cert: int, rot_pub_keys: List[str]) -> bytes:
        """Calculates flags in rotmeta."""
        flags = 0
        flags |= 1 << 31
        flags |= used_root_cert << 8
        flags |= len(rot_pub_keys) << 4
        return pack("<L", flags)

    def export(self) -> bytes:
        """Export to binary form (serialization)."""
        data = pack(
            self.FORMAT,
            *[int(v) for v in self.VERSION.split(".")],
            self.socc,
            self.uuid,
            self.cc_socu,
            self.cc_vu,
            self.cc_beacon,
            self.rot_meta,
            self.rot_pub,
            self.dck_pub,
            self.signature,
        )
        return data

    def _get_data_to_sign(self) -> bytes:
        """Collects data meant for signing."""
        data = pack(
            self.FORMAT_NO_SIG,
            *[int(v) for v in self.VERSION.split(".")],
            self.socc,
            self.uuid,
            self.cc_socu,
            self.cc_vu,
            self.cc_beacon,
            self.rot_meta,
            self.rot_pub,
            self.dck_pub,
        )
        return data

    def __eq__(self, other: Any) -> bool:
        self_vars = vars(self)
        del self_vars["signature_provider"]
        other_vars = vars(other)
        del other_vars["signature_provider"]
        return isinstance(other, DebugCredential) and other_vars == self_vars

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "DebugCredential":
        """Parse the debug credential.

        :param data: Raw data as bytes
        :param offset: Offset of input data
        :return: DebugCredential object
        :raises SPSDKError: When flag is invalid
        """
        format_head = "<2HL16s4L"
        (
            version_major,  # pylint: disable=unused-variable
            version_minor,  # pylint: disable=unused-variable
            socc,
            uuid,
            cc_socu,
            cc_vu,
            beacon,
            flags,
        ) = unpack_from(format_head, data)
        if not flags & 0x8000_0000:
            raise SPSDKError("Invalid flag")
        records_num = (flags & 0xF0) >> 4
        rot_meta_len = 4
        ctrk_hash_table = bytes()
        if records_num > 1:
            rot_meta_len += records_num * cls.HASH_LENGTH
            ctrk_format = f"<{records_num * cls.HASH_LENGTH}s"
            ctrk_hash_table = unpack_from(ctrk_format, data, offset=offset + calcsize(format_head))[
                0
            ]
        rot_meta = pack("<L", flags) + ctrk_hash_table
        format_tail = f"<{cls.HASH_LENGTH * 2}s{cls.HASH_LENGTH * 2}s{cls.HASH_LENGTH * 2}s"
        rot_pub, dck_pub, signature = unpack_from(
            format_tail, data, offset + calcsize(format_head) + len(rot_meta) - 4
        )

        return cls(
            socc=socc,
            uuid=uuid,
            rot_meta=rot_meta,
            dck_pub=dck_pub,
            cc_socu=cc_socu,
            cc_vu=cc_vu,
            cc_beacon=beacon,
            rot_pub=rot_pub,
            signature=signature,
        )

    @classmethod
    def get_instance_from_challenge(cls, data: bytes) -> "DebugCredential":
        """Returns instance of class from DAP authentication challenge data.

        :return: Instance of this class.
        """
        return cls.parse(data, 0)


class DebugCredentialECC256Lpc55s3x(Lpc55s3xMixin):
    """DebugCredential class for LPC55s3x for version 2.0 (p256)."""

    HASH_LENGTH = 32
    CORD_LENGTH = 32
    KEY_LENGTH = 256
    VERSION = "2.0"


class DebugCredentialECC384Lpc55s3x(Lpc55s3xMixin):
    """DebugCredential class for LPC55s3x for version 2.1 (p384)."""

    HASH_LENGTH = 48
    CORD_LENGTH = 48
    KEY_LENGTH = 384
    VERSION = "2.1"


_version_mapping = {
    "1.0": DebugCredentialRSA2048,
    "1.1": DebugCredentialRSA4096,
    "2.0": DebugCredentialECC256,
    "2.1": DebugCredentialECC384,
    "2.2": DebugCredentialECC521,
}

_lpc55s3x_version_mapping = {
    "2.0": DebugCredentialECC256Lpc55s3x,
    "2.1": DebugCredentialECC384Lpc55s3x,
}
