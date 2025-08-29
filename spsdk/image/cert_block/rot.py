#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""The module provides support for RoT hash calculation ."""


from abc import abstractmethod
from typing import Optional, Sequence, Type, Union

from spsdk.crypto.certificate import Certificate
from spsdk.crypto.keys import PrivateKey, PublicKey
from spsdk.exceptions import SPSDKError
from spsdk.image.ahab.ahab_srk import SRKRecord, SRKRecordV2
from spsdk.image.ahab.ahab_srk import SRKTable as AhabSrkTable
from spsdk.image.ahab.ahab_srk import SRKTableV2 as AhabSrkTableV2
from spsdk.image.cert_block.rkht import RKHT, RKHTv1, RKHTv21
from spsdk.image.hab.hab_srk import SrkItem as HabSrkItem
from spsdk.image.hab.hab_srk import SrkTable as HabSrkTable
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision, get_db, get_families
from spsdk.utils.misc import load_binary


class Rot:
    """Root of Trust object providing an abstraction over the RoT hash calculation for multiple device families."""

    def __init__(
        self,
        family: FamilyRevision,
        keys_or_certs: Sequence[Union[str, bytes, bytearray, PublicKey, PrivateKey, Certificate]],
        password: Optional[str] = None,
        search_paths: Optional[list[str]] = None,
    ) -> None:
        """Root of Trust initialization."""
        self.rot_obj = self.get_rot_class(family)(
            keys_or_certs=keys_or_certs, password=password, search_paths=search_paths
        )

    def calculate_hash(self) -> bytes:
        """Calculate RoT hash."""
        return self.rot_obj.calculate_hash()

    def export(self) -> bytes:
        """Export RoT."""
        return self.rot_obj.export()

    def __str__(self) -> str:
        return str(self.rot_obj)

    @classmethod
    def get_supported_families(cls) -> list[FamilyRevision]:
        """Get all supported families."""
        return get_families(DatabaseManager.CERT_BLOCK)

    @classmethod
    def get_rot_class(cls, family: FamilyRevision) -> Type["RotBase"]:
        """Get RoT class."""
        db = get_db(family)
        rot_type = db.get_str(DatabaseManager.CERT_BLOCK, "rot_type")
        return RotBase.get_rot_class(rot_type)


class RotBase:
    """Root of Trust base class."""

    rot_type: Optional[str] = None
    _registry: dict[str, Type["RotBase"]] = {}

    def __init__(
        self,
        keys_or_certs: Sequence[Union[str, bytes, bytearray, PublicKey, PrivateKey, Certificate]],
        password: Optional[str] = None,
        search_paths: Optional[list[str]] = None,
    ) -> None:
        """Rot initialization."""
        self.keys_or_certs = keys_or_certs
        self.password = password
        self.search_paths = search_paths

    @classmethod
    def register(cls, rot_class: Type["RotBase"]) -> Type["RotBase"]:
        """Register a ROT implementation class."""
        if rot_class.rot_type:
            cls._registry[rot_class.rot_type] = rot_class
        return rot_class

    @classmethod
    def get_rot_class(cls, rot_type: str) -> Type["RotBase"]:
        """Get ROT implementation by type."""
        if rot_type not in cls._registry:
            raise SPSDKError(f"A ROT type {rot_type} does not exist.")
        return cls._registry[rot_type]

    @abstractmethod
    def calculate_hash(
        self,
    ) -> bytes:
        """Calculate ROT hash."""

    @abstractmethod
    def export(self) -> bytes:
        """Calculate ROT table."""

    @abstractmethod
    def __str__(self) -> str:
        """Return string representation of the RoT object."""


@RotBase.register
class RotCertBlockv1(RotBase):
    """Root of Trust for certificate block v1 class."""

    rot_type = "cert_block_1"

    def __init__(
        self,
        keys_or_certs: Sequence[Union[str, bytes, bytearray, PublicKey, PrivateKey, Certificate]],
        password: Optional[str] = None,
        search_paths: Optional[list[str]] = None,
    ) -> None:
        """Rot cert block v1 initialization."""
        super().__init__(keys_or_certs, password, search_paths)
        self.rkht = RKHTv1.from_keys(self.keys_or_certs, self.password, self.search_paths)

    def calculate_hash(
        self,
    ) -> bytes:
        """Calculate RoT hash."""
        return self.rkht.rkth()

    def export(self) -> bytes:
        """Export RoT."""
        return self.rkht.export()

    def __str__(self) -> str:
        return str(self.rkht)


@RotBase.register
class RotCertBlockv21(RotBase):
    """Root of Trust for certificate block v21 class."""

    rot_type = "cert_block_21"

    def __init__(
        self,
        keys_or_certs: Sequence[Union[str, bytes, bytearray, PublicKey, PrivateKey, Certificate]],
        password: Optional[str] = None,
        search_paths: Optional[list[str]] = None,
    ) -> None:
        """Rot cert block v21 initialization."""
        super().__init__(keys_or_certs, password, search_paths)
        self.rkht = RKHTv21.from_keys(self.keys_or_certs, self.password, self.search_paths)

    def calculate_hash(
        self,
    ) -> bytes:
        """Calculate ROT hash."""
        return self.rkht.rkth()

    def export(self) -> bytes:
        """Export RoT."""
        return self.rkht.export()

    def __str__(self) -> str:
        return str(self.rkht)


@RotBase.register
class RotSrkTableAhab(RotBase):
    """Root of Trust for AHAB SrkTable class."""

    rot_type = "srk_table_ahab"

    def __init__(
        self,
        keys_or_certs: Sequence[Union[str, bytes, bytearray, PublicKey, PrivateKey, Certificate]],
        password: Optional[str] = None,
        search_paths: Optional[list[str]] = None,
    ) -> None:
        """AHAB SRK table initialization."""
        super().__init__(keys_or_certs, password, search_paths)
        self.srk = AhabSrkTable(
            [
                SRKRecord.create_from_key(RKHT.convert_key(key, password, search_paths))
                for key in keys_or_certs
            ]
        )
        self.srk.update_fields()
        verifier = self.srk.verify()
        if verifier.has_errors:  # Check for errors
            raise SPSDKError(verifier.draw())

    def calculate_hash(self) -> bytes:
        """Calculate ROT hash."""
        return self.srk.compute_srk_hash()

    def export(self) -> bytes:
        """Export RoT."""
        return self.srk.export()

    def __str__(self) -> str:
        return str(self.srk)


@RotBase.register
class RotSrkTableAhabV2(RotBase):
    """Root of Trust for AHAB SrkTable version 2 class."""

    rot_type = "srk_table_ahab_v2"

    def __init__(
        self,
        keys_or_certs: Sequence[Union[str, bytes, bytearray, PublicKey, PrivateKey, Certificate]],
        password: Optional[str] = None,
        search_paths: Optional[list[str]] = None,
    ) -> None:
        """AHAB SRK table initialization."""
        super().__init__(keys_or_certs, password, search_paths)
        self.srk = AhabSrkTableV2(
            [
                SRKRecordV2.create_from_key(
                    RKHT.convert_key(key, password, search_paths), srk_id=key_id
                )
                for key_id, key in enumerate(keys_or_certs)
            ]
        )
        self.srk.update_fields()
        verifier = self.srk.verify()
        if verifier.has_errors:  # Check for errors
            raise SPSDKError(verifier.draw())

    def calculate_hash(self) -> bytes:
        """Calculate ROT hash."""
        return self.srk.compute_srk_hash()

    def export(self) -> bytes:
        """Export RoT."""
        return self.srk.export()

    def __str__(self) -> str:
        return str(self.srk)


@RotBase.register
class RotSrkTableAhabV2_48Bytes(RotSrkTableAhabV2):
    """Root of Trust for AHAB SrkTable version 2 class with hash shortened to 48 bytes."""

    rot_type = "srk_table_ahab_v2_48_bytes"

    def calculate_hash(self) -> bytes:
        """Calculate ROT hash."""
        return super().calculate_hash()[:48]


@RotBase.register
class RotSrkTableHab(RotBase):
    """Root of Trust for HAB SrkTable class."""

    rot_type = "srk_table_hab"

    def __init__(
        self,
        keys_or_certs: Sequence[Union[str, bytes, bytearray, PublicKey, PrivateKey, Certificate]],
        password: Optional[str] = None,
        search_paths: Optional[list[str]] = None,
    ) -> None:
        """HAB SRK table initialization."""
        super().__init__(keys_or_certs, password, search_paths)
        self.srk = HabSrkTable()
        for certificate in keys_or_certs:
            if isinstance(certificate, (str, bytes, bytearray)):
                try:
                    certificate = self._load_certificate(certificate, search_paths)
                except SPSDKError as exc:
                    raise SPSDKError(
                        "Unable to load certificate. Certificate must be provided for HAB RoT calculation."
                    ) from exc
            if not isinstance(certificate, Certificate):
                raise SPSDKError("Certificate must be provided for HAB RoT calculation.")
            item = HabSrkItem.from_certificate(certificate)
            self.srk.append(item)

    def calculate_hash(self) -> bytes:
        """Calculate ROT hash."""
        return self.srk.export_fuses()

    def export(self) -> bytes:
        """Export RoT."""
        return self.srk.export()

    @classmethod
    def _load_certificate(
        cls,
        certificate: Union[str, bytes, bytearray],
        search_paths: Optional[list[str]] = None,
    ) -> Certificate:
        """Load certificate if certificate provided, or extract public key if private/public key is provided."""
        if isinstance(certificate, str):
            certificate = load_binary(certificate, search_paths)
        try:
            return Certificate.parse(certificate)
        except SPSDKError as exc:
            raise SPSDKError("Unable to load certificate.") from exc

    def __str__(self) -> str:
        return str(self.srk)
