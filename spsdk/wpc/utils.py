#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""General utilities and classes used for WPC."""

import logging
import os
import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Type

from typing_extensions import Self

from spsdk.crypto.certificate import Certificate, WPCQiAuthPolicy, WPCQiAuthRSID, x509
from spsdk.crypto.hash import hashes
from spsdk.crypto.keys import EccCurve, PrivateKeyEcc, PublicKeyEcc
from spsdk.crypto.types import Encoding, SPSDKEncoding
from spsdk.exceptions import SPSDKError
from spsdk.utils.database import DatabaseManager, get_db, get_families, get_schema_file
from spsdk.utils.misc import load_binary, write_file
from spsdk.utils.plugins import PluginsManager
from spsdk.utils.schema_validator import CommentedConfig, check_config

logger = logging.getLogger(__name__)


class SPSDKWPCError(SPSDKError):
    """Generic WPC Error."""


class WPCIdType(Enum):
    """Enumeration of different types of WPC ID provided by the target."""

    UUID = "uuid"
    STATIC_CSR = "static_csr"
    COMPUTED_CSR = "computed_csr"


@dataclass
class CSRBlob:
    """Custom Certificate Singing Request binary."""

    uuid: bytes
    puk_data: bytes
    signature: bytes

    @classmethod
    def parse(cls, data: bytes) -> "CSRBlob":
        """Parse data."""
        uuid, puk, sign = struct.unpack_from(">8s64s64s", data)
        return CSRBlob(uuid=uuid, puk_data=puk, signature=sign)

    def get_puk(self) -> PublicKeyEcc:
        """Get public key."""
        x, y = self.puk_data[:32], self.puk_data[32:]
        return PublicKeyEcc.recreate_from_data(x + y)

    def verify(self) -> bool:
        """Verify CSR blob signature."""
        puk = self.get_puk()
        return puk.verify_signature(self.signature, self.uuid + self.puk_data)


@dataclass
class WPCCertChain:
    """WPC Certificate Chain."""

    root_ca_hash: bytes
    manufacturer_cert: Certificate
    product_unit_cert: Certificate

    def __post_init__(self) -> None:
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

        :param pu_cert_only: Get the offset relative to start of the Product Unit Certificate, defaults to False
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
        """Get the Revocation Sequential Identifier."""
        ext = self.product_unit_cert.cert.extensions.get_extension_for_oid(WPCQiAuthRSID.oid)
        return ext.value.public_bytes()[2:]

    def export(self) -> bytes:
        """Export WPC Certificate Chain into bytes."""
        data = (
            self.root_ca_hash
            + self.manufacturer_cert.export(encoding=SPSDKEncoding.DER)
            + self.product_unit_cert.export(encoding=SPSDKEncoding.DER)
        )
        return (len(data) + 2).to_bytes(length=2, byteorder="big") + data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse data into WPC Certificate Chain object."""
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

        :param path: Path to a file
        :return: WPC Certificate Chain object
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

        :param chain_path: Path where to store the whole chain, defaults to None
        :param root_hash_path: Path where to store only the WPC Root Cert hash, defaults to None
        :param manufacturer_path: Path where to store only the Manufacturer Certificate, defaults to None
        :param product_unit_path: Path where to store only the Product Unit Certificate, defaults to None
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


class BaseWPCClass(ABC):
    """Base abstract class for both WPC Service and Target."""

    NAME: str
    CONFIG_PARAMS: str

    @classmethod
    def get_validation_schema(cls) -> dict:
        """Get JSON schema for validating configuration data."""
        # need to use raise here since we're not instantiating an object
        raise NotImplementedError()

    @classmethod
    def get_supported_families(cls) -> List[str]:
        """Get family names supported by WPCTarget."""
        return get_families(DatabaseManager.WPC)

    @classmethod
    def get_providers(cls) -> Dict[str, Type[Self]]:
        """Get available WPC Service/Target Providers."""
        import_providers_and_plugins()
        return {sc.NAME: sc for sc in cls.__subclasses__()}

    @classmethod
    def validate_config(cls, config_data: dict, search_paths: Optional[List[str]] = None) -> None:
        """Validate configuration data using JSON schema specific to this class.

        :param config_data: Configuration data
        :param search_paths: Paths where to look for files referenced in config data, defaults to None
        """
        schema = cls.get_validation_schema()
        check_config(config=config_data, schemas=[schema], search_paths=search_paths)

    @classmethod
    def from_config(cls, config_data: dict, search_paths: Optional[List[str]] = None) -> Self:
        """Create instance of this class based on configuration data.

        __init__ method of this class will be called with data from config_data.
        To limit the scope of data, set cls.CONFIG_PARAMS (key in config data).

        :param config_data: Configuration data
        :param search_paths: Paths where to look for files referenced in config data, defaults to None
        :return: Instance of this class
        """
        if cls.CONFIG_PARAMS in config_data:
            config_data = config_data[cls.CONFIG_PARAMS]
        cls.validate_config(config_data=config_data, search_paths=search_paths)
        return cls(**config_data)


class WPCCertificateService(BaseWPCClass):
    """Base class for service adapters providing the WPC Certificate Chain."""

    CONFIG_PARAMS = "service_parameters"

    @abstractmethod
    def get_wpc_cert(
        self, wpc_id_data: str, wpc_id_type: Optional[WPCIdType] = None
    ) -> WPCCertChain:
        """Obtain the WPC Certificate Chain.

        :param wpc_id_data: WPC ID provided by the target
        :param wpc_id_type: WPC ID type, defaults to None
        :return: WPC Certificate Chain
        """


class WPCTarget(BaseWPCClass):
    """Base class for adapters providing connection to a target."""

    CONFIG_PARAMS = "target_parameters"

    def __init__(self, family: str) -> None:
        """Initialize WPC target.

        :param family: Target family name
        :raises SPSDKWPCError: Family is not supported as WPC target
        """
        if family not in WPCTarget.get_supported_families():
            raise SPSDKWPCError(f"Family '{family}' is not supported")
        self.family = family
        self.wpc_id_type = WPCIdType(get_db(device=family).get_str(DatabaseManager.WPC, "id_type"))

    @abstractmethod
    def get_low_level_wpc_id(self) -> bytes:
        """Get the lower-level WPC ID from the target."""

    @abstractmethod
    def wpc_insert_cert(self, cert_chain: WPCCertChain) -> bool:
        """Insert the WPC Certificate Chain into the target.

        :param cert_chain: Certificate chain to insert into the target
        :raises SPSDKWPCError: Error during certificate chain insertion
        :return: True if operation finishes successfully
        """

    def sign(self, data: bytes) -> bytes:
        """Sign data by the target."""
        raise NotImplementedError()

    def get_wpc_id(self) -> str:
        """Get the WPC ID from the target."""
        logger.info("Getting WPC ID")
        wpc_id_data = self.get_low_level_wpc_id()
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
            return csr2_pem_data.decode("utf-8")

        raise NotImplementedError()


def asn1_to_length(data: bytes) -> int:
    """Get length of a ASN.1 Sequence."""
    if data[0] != 0x30:
        raise SPSDKWPCError(f"Expecting the data to start with 0x30 not {data[0]}")
    if data[1] < 0x80:
        return data[1] + 2
    length = data[1] - 0x80
    return int.from_bytes(data[2 : 2 + length], byteorder="big") + length + 2


def length_to_asn1(length: int) -> bytes:
    """Encode a number into ASN.1 format."""
    if length < 0x80:
        return length.to_bytes(1, byteorder="big")
    byte_length = (length.bit_length() + 7) // 8
    return (0x80 + byte_length).to_bytes(1, byteorder="big") + length.to_bytes(
        byte_length, byteorder="big"
    )


def check_main_config(config_data: dict, search_paths: Optional[List[str]] = None) -> None:
    """Check top layer of config data.

    :param config_data: Configuration data from config file
    :param search_paths: List of paths where to look for files and directories in config data, defaults to None
    :raises SPSDKError: Configuration contains invalid data or some data is missing
    """
    schema = get_schema_file(DatabaseManager.WPC)["full_config"]
    check_config(config=config_data, schemas=[schema], search_paths=search_paths)


def generate_template_config(
    family: str, service: Type[WPCCertificateService], target: Type[WPCTarget]
) -> str:
    """Generate configuration YAML template.

    :param family: Name of the target family
    :param service: WPC Service adapter class
    :param target: WPC Target adapter class
    :return: Configuration template in YAML format
    """
    overall_schema = get_schema_file(DatabaseManager.WPC)["full_config"]
    service_schema = service.get_validation_schema()
    if "family" in service_schema["properties"]:
        service_schema["properties"]["family"]["template_value"] = family
        service_schema["properties"]["family"]["enum"] = service.get_supported_families()
    target_schema = target.get_validation_schema()
    if "family" in target_schema["properties"]:
        target_schema["properties"]["family"]["template_value"] = family
        target_schema["properties"]["family"]["enum"] = target.get_supported_families()

    overall_schema["properties"]["service_type"]["template_value"] = service.NAME
    overall_schema["properties"]["service_parameters"].update(service_schema)
    overall_schema["properties"]["target_type"]["template_value"] = target.NAME
    overall_schema["properties"]["target_parameters"].update(target_schema)
    yaml_data = CommentedConfig(
        main_title="WPC Certificate injection configuration",
        schemas=[overall_schema],
    ).get_template()

    return yaml_data


def import_providers_and_plugins() -> None:
    """Dynamically import built-in WPC Service/Target providers and plugins."""
    this_dir = os.path.normpath(os.path.join(__file__, ".."))
    manager = PluginsManager()

    def import_builtin_provider(module_name: str) -> None:
        file = os.path.join(this_dir, f"{module_name}.py")
        name = f"spsdk.wpc.{module_name}"
        if name not in manager.plugins:
            manager.load_from_source_file(source_file=file, module_name=name)

    import_builtin_provider("service_el2go")
    import_builtin_provider("target_model")
    import_builtin_provider("target_mboot")

    if "spsdk.wpc.service" not in manager.plugins:
        manager.load_from_entrypoints("spsdk.wpc.service")
