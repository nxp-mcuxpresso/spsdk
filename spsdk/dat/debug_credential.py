#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module with DebugCredential class."""

import math
from struct import calcsize, pack, unpack_from
from typing import Any, List, Optional, Type

from spsdk import SPSDKError, crypto
from spsdk.crypto.loaders import extract_public_key
from spsdk.crypto.signature_provider import SignatureProvider, get_signature_provider
from spsdk.dat.utils import ecc_key_to_bytes, ecc_public_numbers_to_bytes, rsa_key_to_bytes
from spsdk.exceptions import SPSDKValueError
from spsdk.image.ahab.ahab_container import SRKRecord, SRKTable
from spsdk.utils.crypto.backend_internal import internal_backend
from spsdk.utils.misc import find_file


class DebugCredential:
    """Base class for DebugCredential."""

    # Subclasses override the following invalid class member values
    FORMAT = "INVALID_FORMAT"
    FORMAT_NO_SIG = "INVALID_FORMAT"
    SOCC_FORMAT = ""
    VERSION = "0.0"
    HASH_LENGTH = 32

    SOCC_LIST = {
        0x0000: "i.MXRT595, i.MXRT685",
        0x0001: "LPC550x, LPC55s0x, LPC551x, LPC55s1x, LPC552x, LPC55s2x, LPC55s6",
        0x0004: "LPC55s3",
        0x0005: "KW45xx/K32W1xx",
        0x5254049C: "i.MXRT118x",
    }

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
        signature: Optional[bytes] = None,
        signature_provider: Optional[SignatureProvider] = None,
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

    @staticmethod
    def get_socc_description(version: str, socc: int) -> str:
        """Get SOCC family name description.

        :param version: Protocol version
        :param socc: SOCC number
        :return: SOCC string representation
        """
        cls = DebugCredential._get_class(version, socc)
        return f"{socc:{cls.SOCC_FORMAT}}, " + cls.SOCC_LIST.get(socc, "Unknown SOCC")

    def info(self) -> str:
        """String representation of DebugCredential.

        :return: binary representation of the debug credential
        """
        msg = f"Version : {self.VERSION}\n"
        msg += f"SOCC    : {self.get_socc_description(self.VERSION, self.socc)}\n"
        msg += f"UUID    : {self.uuid.hex().upper()}\n"
        msg += f"CC_SOCC : {hex(self.cc_socu)}\n"
        msg += f"CC_VU   : {hex(self.cc_vu)}\n"
        msg += f"BEACON  : {self.cc_beacon}\n"
        msg += f"RoTKH   : {self.get_rotkh().hex()}\n"
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

    @classmethod
    def _get_rot_meta(cls, used_root_cert: int, rot_pub_keys: List[str]) -> bytes:
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

    def get_rotkh(self) -> bytes:
        """Get Root Of Trust Keys Hash.

        :return: RoTKH in bytes
        :raises NotImplementedError: Derived class has to implement this method
        """
        raise NotImplementedError("Derived class has to implement this method.")

    @classmethod
    def _get_class(cls, version: str, socc: int) -> "Type[DebugCredential]":
        if socc in [0x5254049C]:
            return _edge_lock_version_mapping[version]
        return _version_mapping[version]

    @classmethod
    def create_from_yaml_config(
        cls, version: str, yaml_config: dict, search_paths: Optional[List[str]] = None
    ) -> "DebugCredential":
        """Create a debug credential object out of yaml configuration.

        :param version: Debug Authentication protocol version.
        :param yaml_config: Debug credential file configuration.
        :param search_paths: List of paths where to search for the file, defaults to None

        :return: DebugCredential object
        """
        socc = yaml_config["socc"]
        klass = DebugCredential._get_class(version=version, socc=socc)
        # Fix the file paths by search paths
        for i, rot in enumerate(yaml_config["rot_meta"]):
            yaml_config["rot_meta"][i] = find_file(rot, search_paths=search_paths)
        if "rotk" in yaml_config.keys():
            yaml_config["rotk"] = find_file(yaml_config["rotk"], search_paths=search_paths)
        yaml_config["dck"] = find_file(yaml_config["dck"], search_paths=search_paths)
        signature_provider = get_signature_provider(
            sp_cfg=yaml_config.get("sign_provider"),
            local_file_key=yaml_config.get("rotk"),
            search_paths=search_paths,
        )
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
            signature_provider=signature_provider,
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

    @classmethod
    def _get_rot_meta(cls, used_root_cert: int, rot_pub_keys: List[str]) -> bytes:
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
        dck_key = extract_public_key(file_path=dck_key_path)
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

    def get_rotkh(self) -> bytes:
        """Get Root Of Trust Keys Hash.

        :return: RoTKH in bytes
        """
        return internal_backend.hash(data=self.rot_meta[:])


class DebugCredentialECC(DebugCredential):
    """Class for ECC specific of DebugCredential."""

    HASH_LENGTH = 0
    KEY_LENGTH = 0
    CORD_LENGTH = 0
    HASH_SIZES = {32: 256, 48: 384, 66: 512}
    CURVE: crypto.ec.EllipticCurve = crypto.ec.SECP256R1()

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

    @classmethod
    def _get_rot_meta(cls, used_root_cert: int, rot_pub_keys: List[str]) -> bytes:
        """Creates the RoT meta-data required by the device to corroborate.

        :return: binary representing the rot-meta data
        """
        ctrk_hash_table = DebugCredentialECC.create_ctrk_table(rot_pub_keys)
        flags = DebugCredentialECC.calculate_flags(used_root_cert, rot_pub_keys)
        return flags + ctrk_hash_table

    @staticmethod
    def _get_dck(dck_key_path: str) -> bytes:
        """Loads the Debugger Public Key (DCK).

        :return: binary representing the DCK key
        """
        dck_key = extract_public_key(file_path=dck_key_path)
        length = math.ceil(dck_key.key_size / 8)
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
        length = math.ceil(root_public_key.key_size / 8)
        assert isinstance(root_public_key, crypto.EllipticCurvePublicKey)
        data = ecc_key_to_bytes(root_public_key, length=length)
        return data

    def info(self) -> str:
        """String representation of DebugCredential.

        :return: binary representation of the debug credential
        """
        msg = f"Version : {self.VERSION}\n"
        msg += f"SOCC    : {self.get_socc_description(self.VERSION, self.socc)}\n"
        msg += f"UUID    : {self.uuid.hex().upper()}\n"
        msg += f"CC_SOCC : {hex(self.cc_socu)}\n"
        msg += f"CC_VU   : {hex(self.cc_vu)}\n"
        msg += f"BEACON  : {self.cc_beacon}\n"
        ctrk_records_num = self.rot_meta[0] >> 4
        if ctrk_records_num == 1:
            msg += "CRTK table not present \n"
        else:
            msg += f"CRTK table has {ctrk_records_num} entries\n"
            msg += f"CRTK Hash: {self.get_rotkh().hex()}"
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
            hash_size = DebugCredentialECC.HASH_SIZES[math.ceil(pub_key.key_size / 8)]
            data = ecc_key_to_bytes(key=pub_key, length=math.ceil(pub_key.key_size / 8))
            ctrk_hash = internal_backend.hash(data=data, algorithm=f"sha{hash_size}")
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

    def get_rotkh(self) -> bytes:
        """Get Root Of Trust Keys Hash.

        :return: RoTKH in bytes
        """
        srk_records_num = self.rot_meta[0] >> 4
        if srk_records_num == 1:
            return b""
        key_length = 256 if ((len(self.rot_meta) - 4) // srk_records_num) == 32 else 384
        return internal_backend.hash(data=self.rot_meta[4:], algorithm=f"sha{key_length}")

    @classmethod
    def get_instance_from_challenge(cls, data: bytes) -> "DebugCredential":
        """Returns instance of class from DAP authentication challenge data.

        :return: Instance of this class.
        """
        return cls.parse(data, 0)


class DebugCredentialEdgeLockEnclave(DebugCredentialECC):
    """EdgeLock Class."""

    HASH_LENGTH = 0
    KEY_LENGTH = 0
    CORD_LENGTH = 0
    SOCC_FORMAT = "08X"

    @classmethod
    def _get_rot_meta(cls, used_root_cert: int, rot_pub_keys: List[str]) -> bytes:
        """Creates the RoT meta-data required by the device to corroborate.

        :return: binary representing the rot-meta data
        """
        srk_hash_table = DebugCredentialEdgeLockEnclave.create_srk_table(rot_pub_keys)
        flags = DebugCredentialECC.calculate_flags(used_root_cert, rot_pub_keys)
        return flags + srk_hash_table

    @staticmethod
    def _get_dck(dck_key_path: str) -> bytes:
        """Loads the Debugger Public Key (DCK).

        :return: binary representing the DCK key
        """
        dck_key = extract_public_key(file_path=dck_key_path)
        length = math.ceil(dck_key.key_size / 8)
        assert isinstance(dck_key, crypto.EllipticCurvePublicKey)
        data = ecc_key_to_bytes(dck_key, length=length)
        return data

    @staticmethod
    def _get_rot_pub(rot_pub_id: int, rot_pub_keys: List[str]) -> bytes:
        """Loads the vendor RoT Public key that corresponds to the private key used for singing.

        :return: binary representing the rotk public key
        """
        return DebugCredentialECC._get_rot_pub(rot_pub_id=rot_pub_id, rot_pub_keys=rot_pub_keys)

    def get_rotkh(self) -> bytes:
        """Get Root Of Trust Keys Hash.

        :return: RoTKH in bytes
        """
        srk = SRKTable.parse(self.rot_meta[4:])
        srk.update_fields()
        return srk.compute_srk_hash()

    def info(self) -> str:
        """String representation of DebugCredential.

        :return: binary representation of the debug credential
        """
        msg = f"Version : {self.VERSION}\n"
        msg += f"SOCC    : {self.get_socc_description(self.VERSION, self.socc)}\n"
        msg += f"UUID    : {self.uuid.hex().upper()}\n"
        msg += f"CC_SOCC : {hex(self.cc_socu)}\n"
        msg += f"CC_VU   : {hex(self.cc_vu)}\n"
        msg += f"BEACON  : {self.cc_beacon}\n"
        srk_records_num = self.rot_meta[0] >> 4
        if srk_records_num != 4:
            msg += "Invalid count of SRK records \n"
        else:
            msg += f"SRK table has {srk_records_num} entries\n"
            msg += f"SRK Hash: {self.get_rotkh().hex()}"
        return msg

    @property
    def FORMAT(self) -> str:  # type: ignore # pylint: disable=invalid-name
        """Formatting string."""
        return f"<2HL16s3L{len(self.rot_meta)}s{self.HASH_LENGTH * 2}s{self.HASH_LENGTH * 2}s"

    @property
    def FORMAT_NO_SIG(self) -> str:  # type: ignore # pylint: disable=invalid-name
        """Formatting string without signature."""
        return f"<2HL16s3L{len(self.rot_meta)}s{self.HASH_LENGTH * 2}s"

    @staticmethod
    def create_srk_table(rot_pub_keys: List[str]) -> bytes:
        """Creates ctrk table."""
        if len(rot_pub_keys) != 4:
            raise SPSDKValueError("Invalid count of Super Root keys!")

        srk_table = SRKTable(
            [SRKRecord.create_from_key(extract_public_key(x)) for x in rot_pub_keys]
        )
        srk_table.update_fields()
        srk_table.validate({})
        return srk_table.export()

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

        srk_table = SRKTable.parse(data, offset=offset + calcsize(format_head))
        srk_table.update_fields()
        srk_table.validate({})
        rot_meta = int.to_bytes(flags, 4, "little") + srk_table.export()
        format_tail = f"<{cls.HASH_LENGTH * 2}s{cls.HASH_LENGTH * 2}s"
        dck_pub, signature = unpack_from(
            format_tail, data, offset + calcsize(format_head) + len(srk_table)
        )

        return cls(
            socc=socc,
            uuid=uuid,
            rot_meta=rot_meta,
            dck_pub=dck_pub,
            rot_pub=bytes(),
            cc_socu=cc_socu,
            cc_vu=cc_vu,
            cc_beacon=beacon,
            signature=signature,
        )

    @classmethod
    def get_instance_from_challenge(cls, data: bytes) -> "DebugCredential":
        """Returns instance of class from DAP authentication challenge data.

        :return: Instance of this class.
        """
        return cls.parse(data, 0)


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
    """DebugCredential class for LPC55s3x for version 2.0 (p256)."""

    VERSION = "2.0"
    CURVE = crypto.ec.SECP256R1()
    HASH_LENGTH = 32
    CORD_LENGTH = 32
    KEY_LENGTH = 256


class DebugCredentialECC384(DebugCredentialECC):
    """DebugCredential class for LPC55s3x for version 2.1 (p384)."""

    VERSION = "2.1"
    CURVE = crypto.ec.SECP384R1()
    HASH_LENGTH = 48
    CORD_LENGTH = 48
    KEY_LENGTH = 384


class DebugCredentialECC521(DebugCredentialECC):
    """DebugCredential class for LPC55s3x for version 2.1 (p384)."""

    VERSION = "2.2"
    CURVE = crypto.ec.SECP521R1()
    HASH_LENGTH = 66
    CORD_LENGTH = 66
    KEY_LENGTH = 521


class DebugCredentialEdgeLockEnclaveECC256(DebugCredentialEdgeLockEnclave):
    """Debug Credential class for device using EdgeLock peripheral for ECC256 keys."""

    VERSION = "2.0"
    CURVE = crypto.ec.SECP256R1()
    HASH_LENGTH = 32
    CORD_LENGTH = 32
    KEY_LENGTH = 256


class DebugCredentialEdgeLockEnclaveECC384(DebugCredentialEdgeLockEnclave):
    """Debug Credential class for device using EdgeLock peripheral for ECC384 keys."""

    VERSION = "2.1"
    CURVE = crypto.ec.SECP384R1()
    HASH_LENGTH = 48
    CORD_LENGTH = 48
    KEY_LENGTH = 384


class DebugCredentialEdgeLockEnclaveECC521(DebugCredentialEdgeLockEnclave):
    """Debug Credential class for device using EdgeLock peripheral for ECC521 keys."""

    VERSION = "2.2"
    CURVE = crypto.ec.SECP521R1()
    HASH_LENGTH = 66
    CORD_LENGTH = 66
    KEY_LENGTH = 521


_version_mapping = {
    "1.0": DebugCredentialRSA2048,
    "1.1": DebugCredentialRSA4096,
    "2.0": DebugCredentialECC256,
    "2.1": DebugCredentialECC384,
    "2.2": DebugCredentialECC521,
}


_edge_lock_version_mapping = {
    "2.0": DebugCredentialEdgeLockEnclaveECC256,
    "2.1": DebugCredentialEdgeLockEnclaveECC384,
    "2.2": DebugCredentialEdgeLockEnclaveECC521,
}
