#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK WPC (Wireless Power Consortium) implementation utilities.

This module provides core functionality for WPC certificate management,
target communication, and certificate service operations. It includes
base classes, error handling, and utility functions for ASN.1 encoding
used throughout the WPC implementation.
"""

import inspect
import logging
import struct
from abc import abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional, Type

from typing_extensions import Self

from spsdk.crypto.certificate import Certificate, WPCQiAuthPolicy, WPCQiAuthRSID, x509
from spsdk.crypto.crypto_types import Encoding, SPSDKEncoding
from spsdk.crypto.hash import hashes
from spsdk.crypto.keys import EccCurve, PrivateKeyEcc, PublicKeyEcc
from spsdk.exceptions import SPSDKError, SPSDKNotImplementedError
from spsdk.utils.abstract_features import FeatureBaseClassComm
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, get_db, update_validation_schema_family
from spsdk.utils.misc import load_binary, write_file
from spsdk.utils.plugins import PluginsManager

logger = logging.getLogger(__name__)


class SPSDKWPCError(SPSDKError):
    """WPC (Wireless Power Consortium) specific error exception.

    This exception is raised when errors occur during WPC operations, providing
    specific error handling for wireless power consortium related functionality
    within the SPSDK framework.
    """


class WPCIdType(Enum):
    """WPC ID type enumeration for target device identification.

    This enumeration defines the different types of WPC (Wireless Power Consortium)
    identifiers that can be provided by target devices during secure provisioning
    operations.
    """

    UUID = "uuid"
    RSID = "rsid"
    STATIC_CSR = "static_csr"
    COMPUTED_CSR = "computed_csr"


class ConfigCheckScope(Enum):
    """Configuration check scope enumeration for WPC operations.

    This enumeration defines the different scopes available when validating
    WPC configuration files, allowing for targeted validation of specific
    configuration sections or comprehensive full validation.
    """

    SERVICE = "service_config"
    TARGET = "target_config"
    FULL = "full_config"


@dataclass
class CSRBlob:
    """Custom Certificate Signing Request binary data container.

    This class represents a parsed CSR (Certificate Signing Request) blob containing
    UUID, public key data, and signature. It provides functionality to parse binary
    CSR data, extract public keys, and verify the integrity of the CSR blob through
    signature validation.
    """

    uuid: bytes
    puk_data: bytes
    signature: bytes

    @classmethod
    def parse(cls, data: bytes) -> "CSRBlob":
        """Parse CSR blob data from binary format.

        Parses binary data containing UUID, public key, and signature components
        in big-endian format to create a CSRBlob instance.

        :param data: Binary data containing packed UUID (8 bytes), public key (64 bytes),
                     and signature (64 bytes) in big-endian format.
        :return: CSRBlob instance with parsed UUID, public key data, and signature.
        """
        uuid, puk, sign = struct.unpack_from(">8s64s64s", data)
        return CSRBlob(uuid=uuid, puk_data=puk, signature=sign)

    def get_puk(self) -> PublicKeyEcc:
        """Get public key from stored public key data.

        Extracts the x and y coordinates from the stored public key data and
        recreates the ECC public key object.

        :return: Recreated ECC public key object.
        """
        x, y = self.puk_data[:32], self.puk_data[32:]
        return PublicKeyEcc.recreate_from_data(x + y)

    def verify(self) -> bool:
        """Verify CSR blob signature.

        This method extracts the public key from the CSR blob and uses it to verify
        the signature against the concatenated UUID and public key data.

        :return: True if signature verification succeeds, False otherwise.
        """
        puk = self.get_puk()
        return puk.verify_signature(self.signature, self.uuid + self.puk_data)


@dataclass
class WPCCertChain:
    """WPC Certificate Chain for Qi wireless charging authentication.

    This class represents a complete WPC (Wireless Power Consortium) certificate chain
    used in Qi wireless charging authentication, containing the root CA hash,
    manufacturer certificate, and product unit certificate with their respective
    WPC-specific extensions.
    """

    root_ca_hash: bytes
    manufacturer_cert: Certificate
    product_unit_cert: Certificate

    def __post_init__(self) -> None:
        """Post-initialization validation of WPC certificates.

        Validates that the manufacturer certificate contains the required WPC Qi-Auth Policy
        extension and the product unit certificate contains the required WPC Qi-Auth RSID
        extension.

        :raises SPSDKWPCError: If manufacturer certificate is missing WPC Qi-Auth Policy
            extension or product unit certificate is missing WPC Qi-Auth RSID extension.
        """
        try:
            self.manufacturer_cert.extensions.get_extension_for_oid(WPCQiAuthPolicy.oid)
        except x509.ExtensionNotFound as e:
            raise SPSDKWPCError(
                "Manufacturer certificate doesn't contain WPC Qi-Auth Policy extension"
            ) from e
        try:
            self.product_unit_cert.extensions.get_extension_for_oid(WPCQiAuthRSID.oid)
        except x509.ExtensionNotFound as e:
            raise SPSDKWPCError(
                "Product unit certificate doesn't contain the WPC Qi-Auth RSID extension"
            ) from e

    def get_puk_offset(self, pu_cert_only: bool = False) -> int:
        """Get offset to the Product Unit Certificate public key.

        :param pu_cert_only: Get the offset relative to start of the Product Unit Certificate,
            defaults to False.
        :return: Offset to the Product Unit Certificate public key.
        """
        pu_puk = self.product_unit_cert.get_public_key()
        puk_x = pu_puk.export()
        if pu_cert_only:
            return self.product_unit_cert.export(SPSDKEncoding.DER).index(puk_x)
        data = self.export()
        return data.index(puk_x)

    def get_rsid_offset(self, pu_cert_only: bool = False) -> int:
        """Get offset to the Revocation Sequential Identifier.

        :param pu_cert_only: Get the offset relative to Product Unit Certificate, defaults to False
        :return: Offset to the Revocation ID.
        """
        rsid = self.get_rsid()
        if pu_cert_only:
            return self.product_unit_cert.export(SPSDKEncoding.DER).index(rsid)
        return self.export().index(rsid)

    def get_rsid(self) -> bytes:
        """Get the Revocation Sequential Identifier.

        Extracts the RSID from the product unit certificate extension and validates its length.
        The RSID is used for certificate revocation tracking in WPC authentication.

        :raises SPSDKWPCError: Invalid RSID length (expected 9 bytes).
        :return: The 9-byte RSID extracted from the certificate extension.
        """
        ext = self.product_unit_cert.cert.extensions.get_extension_for_oid(WPCQiAuthRSID.oid)
        rsid = ext.value.public_bytes()
        if len(rsid) == 11:
            rsid = rsid[2:]
        if len(rsid) != 9:
            raise SPSDKWPCError(f"Invalid RSID length. Expected 9B, got {len(rsid)}")
        return rsid

    def export(self) -> bytes:
        """Export WPC Certificate Chain into bytes.

        The method concatenates the root CA hash with manufacturer and product unit
        certificates in DER encoding format, then prepends the total length as a
        2-byte big-endian value.

        :return: Byte representation of the WPC certificate chain with length prefix.
        """
        data = (
            self.root_ca_hash
            + self.manufacturer_cert.export(encoding=SPSDKEncoding.DER)
            + self.product_unit_cert.export(encoding=SPSDKEncoding.DER)
        )
        return (len(data) + 2).to_bytes(length=2, byteorder="big") + data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse binary data into WPC Certificate Chain object.

        The method parses the binary representation of a WPC certificate chain,
        extracting the root CA hash, manufacturer certificate, and product unit certificate.

        :param data: Binary data containing the WPC certificate chain.
        :raises SPSDKWPCError: When the data length doesn't match expected length.
        :return: Parsed WPC Certificate Chain object.
        """
        expected_length = int.from_bytes(data[:2], byteorder="big")
        if len(data) != expected_length:
            raise SPSDKWPCError(
                f"Expected length of WPC Cert Chain data is {expected_length} not {len(data)}"
            )
        root_ca_hash = data[2:34]
        manufacturer_cert_start = 34
        manufacturer_cert_len = asn1_to_length(
            data[manufacturer_cert_start : manufacturer_cert_start + 6]
        )
        manufacturer_cert = Certificate.parse(
            data[manufacturer_cert_start : manufacturer_cert_start + manufacturer_cert_len]
        )
        product_unit_cert_start = 34 + manufacturer_cert_len
        product_unit_cert_len = asn1_to_length(
            data[product_unit_cert_start : product_unit_cert_start + 6]
        )
        product_unit_cert = Certificate.parse(
            data[product_unit_cert_start : product_unit_cert_start + product_unit_cert_len]
        )
        return cls(
            root_ca_hash=root_ca_hash,
            manufacturer_cert=manufacturer_cert,
            product_unit_cert=product_unit_cert,
        )

    @classmethod
    def load(cls, path: str) -> Self:
        """Load WPC Certificate Chain from a file.

        :param path: Path to the file containing WPC Certificate Chain data.
        :raises SPSDKError: If the file cannot be loaded or parsed.
        :return: WPC Certificate Chain object.
        """
        data = load_binary(path=path)
        return cls.parse(data=data)

    def save(
        self,
        chain_path: Optional[str] = None,
        root_hash_path: Optional[str] = None,
        manufacturer_path: Optional[str] = None,
        product_unit_path: Optional[str] = None,
    ) -> None:
        """Save WPC Certificate Chain into file(s).

        The method allows saving the complete certificate chain or individual components
        (root hash, manufacturer certificate, product unit certificate) to separate files.
        At least one path parameter must be provided to perform any save operation.

        :param chain_path: Path where to store the whole certificate chain in binary format.
        :param root_hash_path: Path where to store only the WPC Root Certificate hash as hex string.
        :param manufacturer_path: Path where to store only the Manufacturer Certificate in DER format.
        :param product_unit_path: Path where to store only the Product Unit Certificate in DER format.
        """
        if chain_path:
            write_file(data=self.export(), path=chain_path, mode="wb")
        if root_hash_path:
            write_file(data=self.root_ca_hash.hex(), path=root_hash_path, mode="w")
        if manufacturer_path:
            write_file(
                data=self.manufacturer_cert.export(SPSDKEncoding.DER),
                path=manufacturer_path,
                mode="wb",
            )
        if product_unit_path:
            write_file(
                data=self.product_unit_cert.export(SPSDKEncoding.DER),
                path=product_unit_path,
                mode="wb",
            )


class BaseWPCClass(FeatureBaseClassComm):
    """Base abstract class for WPC (Wireless Power Consortium) Service and Target implementations.

    This class provides the foundation for WPC operations across NXP MCU portfolio,
    handling device identification, family-specific configurations, and database
    management for wireless power charging functionality.

    :cvar FEATURE: Feature identifier for WPC operations.
    :cvar legacy_identifier_name: Legacy attribute name for backward compatibility.
    """

    identifier: str
    CONFIG_PARAMS: str
    legacy_identifier_name = "NAME"
    FEATURE = "wpc"

    def __init_subclass__(cls) -> None:
        """Initialize subclass with identifier validation and legacy support.

        Validates that non-abstract subclasses have an 'identifier' attribute set.
        Handles legacy identifier names by converting them to the standard 'identifier'
        attribute and logging a deprecation warning.

        :raises SPSDKError: When identifier is not set for non-abstract subclass.
        """
        if not inspect.isabstract(cls) and hasattr(cls, cls.legacy_identifier_name):
            identifier = getattr(cls, cls.legacy_identifier_name)
            logger.warning(
                (
                    f"Class {cls.__name__} uses legacy identifier '{cls.legacy_identifier_name} = \"{identifier}\"', "
                    f"please use 'identifier = \"{identifier}\"' instead"
                )
            )
            setattr(cls, "identifier", identifier)

        if not inspect.isabstract(cls) and not hasattr(cls, "identifier"):
            raise SPSDKError(f"{cls.__name__}.identifier is not set")
        return super().__init_subclass__()

    def __init__(self, family: FamilyRevision) -> None:
        """Initialize WPC target.

        :param family: Target family name and revision information
        :raises SPSDKWPCError: Family is not supported as WPC target
        """
        self.family = family
        self.db = get_db(family)
        self.wpc_id_type = WPCIdType(self.db.get_str(DatabaseManager.WPC, "id_type"))

    def __repr__(self) -> str:
        """Get string representation of WPC object.

        :return: String containing WPC identifier and target family.
        """
        return f"WPC {self.identifier} for {self.family}."

    def __str__(self) -> str:
        """Get string representation of the object.

        :return: String representation of the object.
        """
        ret = self.__repr__()
        return ret

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the Feature.

        :param data_path: Path to directory containing configuration data files.
        :raises SPSDKNotImplementedError: Method not implemented in base class.
        """
        raise SPSDKNotImplementedError()

    @classmethod
    def get_providers(cls) -> dict[str, Type[Self]]:
        """Get available WPC Service/Target Providers.

        This method dynamically loads and registers WPC (Wireless Power Consortium) service and target
        providers from both built-in modules and entry points. It ensures that all available providers
        are properly registered with the plugin manager.

        :return: Dictionary mapping provider identifiers to their corresponding class types.
        """
        # explicit import so PyInstaller will pickup the files
        # import is not top-level to prevent problems with cyclic import
        from spsdk.wpc import service_el2go, target_mboot, target_model

        manager = PluginsManager()

        manager.register(service_el2go)
        manager.register(target_mboot)
        manager.register(target_model)

        if "spsdk.wpc.service" not in manager.plugins:
            manager.load_from_entrypoints("spsdk.wpc.service")
        return {sc.identifier: sc for sc in cls.__subclasses__()}


class WPCCertificateService(BaseWPCClass):
    """WPC Certificate Service base class.

    This abstract base class defines the interface for service adapters that provide
    WPC (Wireless Power Consortium) Certificate Chains. Implementations of this class
    handle the retrieval and management of WPC certificates required for wireless
    power transfer authentication.

    :cvar CONFIG_PARAMS: Configuration parameter key for service settings.
    """

    CONFIG_PARAMS = "service_parameters"

    @abstractmethod
    def get_wpc_cert(self, wpc_id_data: bytes) -> WPCCertChain:
        """Obtain the WPC Certificate Chain.

        :param wpc_id_data: WPC ID provided by the target device.
        :return: WPC Certificate Chain containing the device certificates.
        """


class WPCTarget(BaseWPCClass):
    """WPC Target adapter base class.

    This abstract base class provides the foundation for implementing adapters that
    establish connections to target devices for Wireless Power Consortium (WPC)
    operations. It defines the interface for WPC ID retrieval, certificate chain
    insertion, and cryptographic signing operations on target hardware.

    :cvar CONFIG_PARAMS: Configuration parameter key for target-specific settings.
    """

    CONFIG_PARAMS = "target_parameters"

    @abstractmethod
    def get_low_level_wpc_id(self) -> bytes:
        """Get the lower-level WPC ID from the target.

        :return: The lower-level WPC ID as bytes.
        """

    @abstractmethod
    def wpc_insert_cert(self, cert_chain: WPCCertChain) -> bool:
        """Insert the WPC Certificate Chain into the target.

        This method handles the insertion of a complete WPC certificate chain into the target
        device, ensuring proper validation and secure provisioning.

        :param cert_chain: Certificate chain to insert into the target
        :raises SPSDKWPCError: Error during certificate chain insertion
        :return: True if operation finishes successfully
        """

    def sign(self, data: bytes) -> bytes:
        """Sign data by the target.

        :param data: Data to be signed.
        :raises NotImplementedError: Method must be implemented by subclass.
        :return: Signed data.
        """
        raise NotImplementedError()

    def get_wpc_id(self) -> bytes:
        """Get the WPC ID from the target.

        Retrieves and processes the WPC (Wireless Power Consortium) ID based on the configured
        ID type. For COMPUTED_CSR type, generates a certificate signing request with the target's
        public key and signature. For RSID type, returns the raw ID data.

        :raises SPSDKWPCError: When WPC ID contains all zeros.
        :raises NotImplementedError: When WPC ID type is not supported.
        :return: WPC ID as PEM-encoded CSR bytes for COMPUTED_CSR type or raw bytes for RSID type.
        """
        logger.info("Getting WPC ID")
        wpc_id_data = self.get_low_level_wpc_id()

        if wpc_id_data.count(0) == len(wpc_id_data):
            raise SPSDKWPCError("WPC ID is all zeros.")

        if self.wpc_id_type == WPCIdType.COMPUTED_CSR:
            logger.info("Computing CSR")
            csr = CSRBlob.parse(data=wpc_id_data)

            fake_prk = PrivateKeyEcc.generate_key(EccCurve.SECP256R1)

            builder = x509.CertificateSigningRequestBuilder()
            builder = builder.subject_name(
                x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, csr.uuid.hex())])
            )
            req = builder.sign(fake_prk.key, hashes.SHA256())
            req_puk = PublicKeyEcc(req.public_key())  # type: ignore[arg-type]

            tbs_data = bytearray(req.tbs_certrequest_bytes)
            puk_offset = tbs_data.index(req_puk.export())
            tbs_data[puk_offset : puk_offset + 64] = csr.get_puk().export()
            raw_signature = self.sign(data=tbs_data)

            csr2_data = bytes(tbs_data)
            # ASN1 blob for signature algorithm
            csr2_data += bytes.fromhex("30 0A 06 08 2A 86 48 CE 3D 04 03 02")
            csr2_data += b"\03" + (len(raw_signature) + 1).to_bytes(1, byteorder="big") + b"\x00"
            csr2_data += raw_signature
            csr2_data = b"\x30" + length_to_asn1(len(csr2_data)) + csr2_data

            csr2 = x509.load_der_x509_csr(data=csr2_data)
            csr2_pem_data = csr2.public_bytes(Encoding.PEM)
            return csr2_pem_data

        if self.wpc_id_type == WPCIdType.RSID:
            return wpc_id_data

        raise NotImplementedError()


class WPC(FeatureBaseClassComm):
    """WPC (Wireless Power Consortium) certificate and provisioning manager.

    This class provides a unified interface for managing WPC certificate services and targets
    across NXP MCU portfolio. It handles WPC-specific operations including certificate
    validation, configuration management, and target provisioning for wireless power applications.

    :cvar FEATURE: Feature identifier for WPC operations.
    :cvar SERVICES: Available WPC certificate service providers.
    :cvar TARGETS: Available WPC target providers.
    """

    FEATURE = "wpc"
    SERVICES = WPCCertificateService.get_providers()
    TARGETS = WPCTarget.get_providers()

    def __init__(
        self,
        family: FamilyRevision,
        service: Optional[WPCCertificateService] = None,
        target: Optional[WPCTarget] = None,
    ) -> None:
        """Initialize WPC target.

        :param family: Target family name
        :param service: Optional WPC certificate service instance
        :param target: Optional WPC target instance
        :raises SPSDKWPCError: Family is not supported as WPC target
        """
        self.family = family
        self.service = service
        self.target = target
        self.db = get_db(family)
        self.wpc_id_type = WPCIdType(self.db.get_str(DatabaseManager.WPC, "id_type"))

    def __repr__(self) -> str:
        """Get string representation of WPC container object.

        :return: String representation containing the target family name.
        """
        return f"WPC container for {self.family}."

    def __str__(self) -> str:
        """Get string representation of the object.

        Provides a detailed string representation including service and target
        identifiers when available.

        :return: Formatted string with object representation, service, and target information.
        """
        ret = self.__repr__()
        ret += "\n Service: "
        ret += self.service.identifier if self.service else "None"
        ret += "\n Target:  "
        ret += self.target.identifier if self.target else "None"
        return ret

    @classmethod
    def get_validation_schemas(
        cls,
        family: FamilyRevision,
        service: Optional[Type[WPCCertificateService]] = None,
        target: Optional[Type[WPCTarget]] = None,
    ) -> list[dict[str, Any]]:
        """Create the list of validation schemas for WPC configuration.

        The method builds validation schemas by starting with basic schemas and then
        conditionally adding service and target specific schemas based on the provided
        parameters. Each schema is updated with family-specific information and
        appropriate enumeration values.

        :param family: The MCU/MPU/MPU family revision to generate schemas for.
        :param service: Optional WPC certificate service class to include in schemas.
        :param target: Optional WPC target class to include in schemas.
        :return: List of validation schema dictionaries for WPC configuration.
        """
        sch = cls.get_validation_schemas_basic()
        update_validation_schema_family(sch[0]["properties"], cls.get_supported_families(), family)

        if service:
            service_sch = get_schema_file(DatabaseManager.WPC)["service_config"]
            service_schema = service.get_validation_schemas(family)
            service_sch["properties"]["service_type"]["template_value"] = service.identifier
            service_sch["properties"]["service_type"]["enum"] = list(cls.SERVICES.keys())
            service_sch["properties"]["service_parameters"].update(service_schema[0])
            sch.append(service_sch)
        if target:
            target_sch = get_schema_file(DatabaseManager.WPC)["target_config"]
            target_schema = target.get_validation_schemas(family)
            target_sch["properties"]["target_type"]["template_value"] = target.identifier
            target_sch["properties"]["target_type"]["enum"] = list(cls.TARGETS.keys())
            target_sch["properties"]["target_parameters"].update(target_schema[0])
            sch.append(target_sch)
        return sch

    @classmethod
    def get_validation_schemas_from_cfg(cls, config: Config) -> list[dict[str, Any]]:
        """Get validation schemas based on configuration.

        If the class doesn't behave generally, just override this implementation.

        :param config: Valid configuration object containing family, service and target settings.
        :raises SPSDKWPCError: When specified service_type or target_type is not supported.
        :return: List of validation schema dictionaries for the configured WPC setup.
        """
        config.check(cls.get_validation_schemas_basic())
        family = FamilyRevision.load_from_config(config)
        service = None
        target = None
        if "service_type" in config:
            service_type = config.get_str("service_type")
            if service_type not in cls.SERVICES:
                raise SPSDKWPCError(f"WPC service {service_type} is not supported.")
            service = cls.SERVICES[service_type]
        if "target_type" in config:
            target_type = config.get_str("target_type")
            if target_type not in cls.TARGETS:
                raise SPSDKWPCError(f"WPC service {target_type} is not supported.")
            target = cls.TARGETS[target_type]
        return cls.get_validation_schemas(family=family, service=service, target=target)

    def _get_validation_schemas(self) -> list[dict[str, Any]]:
        """Get the list of validation schemas for the current configuration.

        The method retrieves validation schemas based on the family, service type, and target type
        of the current WPC instance. It dynamically determines the service and target types from
        the configured instances.

        :return: List of validation schemas as dictionaries.
        """
        return self.get_validation_schemas(
            self.family,
            service=type(self.service) if self.service else None,
            target=type(self.target) if self.target else None,
        )

    @classmethod
    def get_config_template(
        cls,
        family: FamilyRevision,
        service: Optional[Type[WPCCertificateService]] = None,
        target: Optional[Type[WPCTarget]] = None,
    ) -> str:
        """Get WPC configuration template for specified family and components.

        Generates a configuration template based on the provided family revision and optional
        WPC service and target components. The template includes validation schemas for the
        specified configuration.

        :param family: Family revision for which the template should be generated.
        :param service: Optional WPC certificate service class to include in template.
        :param target: Optional WPC target class to include in template.
        :return: Configuration template as string representation.
        """
        schemas = cls.get_validation_schemas(family, service, target)
        return cls._get_config_template(family, schemas)

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the Feature.

        :param data_path: Path to directory containing configuration data files.
        :raises SPSDKNotImplementedError: Method not implemented in base class.
        """
        raise SPSDKNotImplementedError()

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load feature object from configuration.

        The method creates a feature object by loading family revision and optionally
        service and target components based on the configuration settings.

        :param config: Configuration dictionary containing feature settings.
        :return: Initialized feature object with loaded components.
        """
        family = FamilyRevision.load_from_config(config)
        service = None
        target = None
        if "service_type" in config:
            service_cls = cls.SERVICES[config.get_str("service_type")]
            service = service_cls.load_from_config(config)
        if "target_type" in config:
            target_cls = cls.TARGETS[config.get_str("target_type")]
            target = target_cls.load_from_config(config)
        return cls(family=family, service=service, target=target)

    @classmethod
    def check_wpc_top_level_config(
        cls,
        config: Config,
        scope: ConfigCheckScope = ConfigCheckScope.FULL,
    ) -> None:
        """Check top layer of config data.

        Validates the configuration data against appropriate schemas based on the specified scope.
        The method performs basic validation and additional target/service-specific validation
        depending on the scope parameter.

        :param config: Configuration data from config file
        :param scope: Scope of the config file check
        :raises SPSDKError: Configuration contains invalid data or some data is missing
        """
        config.check(cls.get_validation_schemas_basic())

        if scope == ConfigCheckScope.TARGET or scope == ConfigCheckScope.FULL:
            config.check([get_schema_file(DatabaseManager.WPC)["target_config"]])
        if scope == ConfigCheckScope.SERVICE or scope == ConfigCheckScope.FULL:
            config.check([get_schema_file(DatabaseManager.WPC)["service_config"]])


def asn1_to_length(data: bytes) -> int:
    """Get length of a ASN.1 Sequence.

    Parses ASN.1 DER encoded data to extract the total length of the sequence,
    including the tag and length octets.

    :param data: ASN.1 DER encoded bytes starting with sequence tag (0x30).
    :raises SPSDKWPCError: If data doesn't start with ASN.1 sequence tag (0x30).
    :return: Total length of the ASN.1 sequence including tag and length octets.
    """
    if data[0] != 0x30:
        raise SPSDKWPCError(f"Expecting the data to start with 0x30 not {data[0]}")
    if data[1] < 0x80:
        return data[1] + 2
    length = data[1] - 0x80
    return int.from_bytes(data[2 : 2 + length], byteorder="big") + length + 2


def length_to_asn1(length: int) -> bytes:
    """Encode a number into ASN.1 DER length format.

    Converts an integer length value into the proper ASN.1 Distinguished Encoding Rules
    (DER) length encoding format. For lengths < 128, uses short form (single byte).
    For lengths >= 128, uses long form with length-of-length prefix.

    :param length: The length value to encode into ASN.1 format.
    :raises ValueError: If length is negative.
    :return: ASN.1 DER encoded length as bytes.
    """
    if length < 0x80:
        return length.to_bytes(1, byteorder="big")
    byte_length = (length.bit_length() + 7) // 8
    return (0x80 + byte_length).to_bytes(1, byteorder="big") + length.to_bytes(
        byte_length, byteorder="big"
    )
