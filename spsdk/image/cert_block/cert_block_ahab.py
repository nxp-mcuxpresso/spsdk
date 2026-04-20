#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Certificate Block management and processing utilities.

This module provides comprehensive functionality for handling various types of
certificate blocks used in NXP secure boot and authentication processes.
It supports multiple certificate block versions and formats including V1, V2.1,
Vx, and AHAB certificate blocks with their respective headers and structures.
"""

import logging
from typing import Any, Optional

from typing_extensions import Self

from spsdk.crypto.keys import PublicKey
from spsdk.exceptions import SPSDKError
from spsdk.image.ahab.ahab_certificate import AhabCertificate, get_ahab_certificate_class
from spsdk.image.cert_block.cert_blocks import CertBlock
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision, get_db, get_families
from spsdk.utils.verifier import Verifier

logger = logging.getLogger(__name__)


class CertBlockAhab(CertBlock):
    """Certificate block implementation using AHAB Certificate format.

    This class provides certificate block functionality based on AHAB (Advanced High
    Assurance Boot) certificates, supporting SRK-based certificate blocks with AHAB v2
    48-byte format for compatible chip families.

    :cvar SUB_FEATURE: Identifier for SRK-based certificate block type.
    """

    SUB_FEATURE = "based_on_srk"

    def __init__(  # type: ignore[no-untyped-def]
        self, family: FamilyRevision, ahab_certificate: Optional[AhabCertificate] = None, **kwargs
    ) -> None:
        """Initialize AHAB-based certificate block.

        Creates a new AHAB certificate block instance either from an existing AHAB certificate
        or by creating a new one using the provided arguments.

        :param family: Chip family and revision information.
        :param ahab_certificate: Optional existing AHAB Certificate instance to use.
        :param kwargs: Additional keyword arguments for AHAB certificate creation when
            ahab_certificate is not provided.
        """
        super().__init__(family)

        if ahab_certificate:
            self._ahab_certificate = ahab_certificate
        else:
            # Create AHAB certificate with provided arguments
            ahab_cert_class = get_ahab_certificate_class(family)
            self._ahab_certificate = ahab_cert_class(family=family, **kwargs)

    @property
    def ahab_certificate(self) -> AhabCertificate:
        """Get the underlying AHAB certificate.

        :return: The AHAB certificate instance associated with this certificate block.
        """
        return self._ahab_certificate

    @property
    def expected_size(self) -> int:
        """Get expected size of binary block.

        :return: Size of the AHAB certificate in bytes.
        """
        return len(self._ahab_certificate)

    @property
    def signature_size(self) -> int:
        """Get the total size of signatures in bytes.

        Calculates the combined size of both public key signatures (key 0 and key 1)
        from the AHAB certificate. If a public key is not available or causes an error,
        its signature size is treated as 0.

        :return: Total signature size in bytes from both public keys.
        """
        sign0_size = 0
        sign1_size = 0
        try:
            if self._ahab_certificate.public_key_0:
                sign0_size = self._ahab_certificate.public_key_0.get_public_key().signature_size
        except SPSDKError:
            pass

        try:
            if self._ahab_certificate.public_key_1:
                sign1_size = self._ahab_certificate.public_key_1.get_public_key().signature_size
        except SPSDKError:
            pass

        return sign0_size + sign1_size

    def export(self) -> bytes:
        """Export certificate block as bytes.

        Updates the internal AHAB certificate fields and exports the complete
        certificate block data in binary format.

        :return: Binary representation of the certificate block.
        """
        self._ahab_certificate.update_fields()
        return self._ahab_certificate.export()

    def get_root_public_key(self) -> PublicKey:
        """Get the root public key from the certificate block.

        Extracts and returns the first public key from the AHAB certificate, which serves as the root
        public key for certificate validation.

        :raises SPSDKError: No public key available in AHAB certificate.
        :return: Public key object from the first public key in AHAB certificate.
        """
        if not self._ahab_certificate.public_key_0:
            raise SPSDKError("No public key available in AHAB certificate")
        return self._ahab_certificate.public_key_0.get_public_key()

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision = FamilyRevision("Unknown")) -> Self:
        """Parse Certificate block from binary data.

        Creates a CertBlockAhab instance by parsing the provided binary data and extracting
        the AHAB certificate information specific to the given chip family.

        :param data: Binary data of certification block
        :param family: Chip family revision information
        :return: CertBlockAhab instance
        """
        ahab_cert_class = get_ahab_certificate_class(family)
        ahab_certificate = ahab_cert_class.parse(data, family)

        return cls(family=family, ahab_certificate=ahab_certificate)

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Create the list of validation schemas for the specified family.

        The method retrieves the appropriate AHAB certificate class for the given family
        and delegates the schema creation to that class.

        :param family: Family revision to get validation schemas for.
        :return: List of validation schemas for the specified family.
        """
        ahab_cert_class = get_ahab_certificate_class(family)
        return ahab_cert_class.get_validation_schemas(family)

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Create an instance of CertBlockAhab from configuration.

        Loads family revision and AHAB certificate from the provided configuration
        and constructs a new CertBlockAhab instance.

        :param config: Input standard configuration containing family and certificate data.
        :return: Instance of CertBlockAhab with loaded family and certificate.
        """
        family = FamilyRevision.load_from_config(config)
        ahab_cert_class = get_ahab_certificate_class(family)
        ahab_certificate = ahab_cert_class.load_from_config(config)

        return cls(family=family, ahab_certificate=ahab_certificate)

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of Certificate Block from object.

        :param data_path: Output folder to store possible files.
        :return: Configuration dictionary.
        """
        return self._ahab_certificate.get_config(data_path=data_path)

    @classmethod
    def get_supported_families(cls, include_predecessors: bool = False) -> list[FamilyRevision]:
        """Get supported families for this certificate block.

        Returns families that have cert_block configuration with:
        - sub_features: [based_on_srk]
        - rot_type: "srk_table_ahab_v2_48_bytes"

        :param include_predecessors: Whether to include predecessor family revisions in the search.
        :return: List of supported family revisions that meet the configuration requirements.
        """
        supported_families = get_families(
            feature=cls.FEATURE,
            sub_feature=cls.SUB_FEATURE,
            include_predecessors=include_predecessors,
        )
        supported_families_final: list[FamilyRevision] = []
        for family_rev in supported_families:
            db = get_db(family_rev)
            cert_block_config = db.get_str(cls.FEATURE, "rot_type", "None")
            # Check for specific configuration requirements
            if cert_block_config == "srk_table_ahab_v2_48_bytes":
                supported_families_final.append(family_rev)

        return supported_families_final

    def __repr__(self) -> str:
        """Return string representation of CertBlockAhab instance.

        :return: String containing class name and target family.
        """
        return f"CertBlockAhab for {self.family}"

    def __str__(self) -> str:
        """Get string representation of AHAB Certificate Block.

        :return: Formatted string containing AHAB certificate block information.
        """
        return f"AHAB Certificate Block:\n{str(self._ahab_certificate)}"

    def verify(self) -> Verifier:
        """Verify the certificate block.

        :return: Verifier object for certificate block verification.
        """
        return self._ahab_certificate.verify()
