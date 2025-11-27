#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK DICE utilities for device identity and certificate operations.

This module provides utility functions and classes for DICE (Device Identifier
Composition Engine) operations, including ECC key management, X.509 certificate
handling, device support queries, and hardware attestation functionality.
"""

import logging
import secrets
from typing import Callable, Optional, Union

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.crypto.keys import (
    PrivateKey,
    PrivateKeyEcc,
    PrivateKeyMLDSA,
    PublicKey,
    PublicKeyDilithium,
    PublicKeyEcc,
    PublicKeyMLDSA,
    SPSDKEncoding,
)
from spsdk.dice.data_container import PayloadType, TPDataContainer
from spsdk.dice.exceptions import SPSDKDICEError, SPSDKError
from spsdk.dice.tcg_asn import Certificate, TBSCertificate
from spsdk.mboot import McuBoot
from spsdk.mboot.protocol.base import MbootProtocolBase
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision, get_db, get_families
from spsdk.utils.registers import Register, Registers, RegsBitField
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)


def get_supported_devices() -> list[FamilyRevision]:
    """Get list of devices supported by DICE.

    :return: List of family revisions that support DICE functionality.
    """
    return get_families(DatabaseManager.DICE)


def reconstruct_ecc_key(puk_data: Union[str, bytes]) -> ec.EllipticCurvePublicKey:
    """Reconstruct ECC public key from raw X,Y coordinates.

    Converts raw byte data containing X and Y coordinates of an elliptic curve point
    into a proper ECC public key object using the SECP256R1 curve.

    :param puk_data: Raw X,Y coordinates as hex string or bytes (64 bytes total).
    :return: ECC public key object reconstructed from the coordinates.
    """
    if isinstance(puk_data, str):
        puk_bytes = bytes.fromhex(puk_data)
    else:
        puk_bytes = puk_data
    x = int.from_bytes(puk_bytes[:32], byteorder="big")
    y = int.from_bytes(puk_bytes[32:], byteorder="big")
    numbers = ec.EllipticCurvePublicNumbers(x=x, y=y, curve=ec.SECP256R1())
    return numbers.public_key()


def serialize_ecc_key(key: ec.EllipticCurvePublicKey) -> str:
    """Serialize ECC public key into PEM-formatted string.

    :param key: ECC public key to serialize.
    :return: PEM-encoded public key as string.
    """
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


HADDifferences = list[Union[tuple[RegsBitField, RegsBitField], tuple[Register, Register]]]


class HADDiff:
    """HAD (Hardware Attestation Data) difference analyzer for DICE operations.

    This class provides functionality to compare HAD data values and identify
    differences between expected and actual hardware configurations. It supports
    both full comparison and critical-only analysis based on family-specific
    register definitions.
    """

    def __init__(self, family: FamilyRevision) -> None:
        """Initialize the HADDiff instance.

        :param family: Selected family for HAD data parsing
        :raises SPSDKDICEError: Unsupported family
        """
        self.family = family
        database = get_db(self.family)
        self.had_length = database.get_int(DatabaseManager.DICE, "had_length")
        self.critical_registers = database.get_list(DatabaseManager.DICE, "critical_had_members")

    def get_diff(
        self, expected: Union[str, bytes], actual: Union[str, bytes], critical_only: bool = False
    ) -> HADDifferences:
        """Compare provided HAD data and return registers/bitfields containing different values.

        The method accepts HAD data in string (hex) or bytes format and compares them to identify
        differences. When critical_only is enabled, only differences in critical registers are returned.

        :param expected: Expected HAD data as hex string or bytes
        :param actual: Actual HAD data as hex string or bytes
        :param critical_only: Return only differences of critical HAD registers, defaults to False
        :raises SPSDKDICEError: Invalid data length
        :return: List of registers/bitfields with mismatching values
        """
        expected_data = bytes.fromhex(expected) if isinstance(expected, str) else expected
        actual_data = bytes.fromhex(actual) if isinstance(actual, str) else actual

        if len(expected_data) != self.had_length:
            raise SPSDKDICEError(
                f"Expected HAD length must be {self.had_length}; got {len(expected_data)}"
            )
        if len(actual_data) != self.had_length:
            raise SPSDKDICEError(
                f"Actual HAD length must be {self.had_length}; got {len(actual_data)}"
            )

        expected_regs = self._setup_regs(data=expected_data)
        actual_regs = self._setup_regs(data=actual_data)

        differences = expected_regs.get_diff(actual_regs)
        if not critical_only:
            return differences

        critical_differences: HADDifferences = []
        for d1, d2 in differences:
            if isinstance(d1, Register) and isinstance(d2, Register):
                if d1.name in self.critical_registers:
                    critical_differences.append((d1, d2))
            else:
                assert isinstance(d1, RegsBitField) and isinstance(d2, RegsBitField)
                if d1.parent.name in self.critical_registers:
                    critical_differences.append((d1, d2))
        return critical_differences

    def _setup_regs(self, data: bytes) -> Registers:
        """Setup registers for DICE operations.

        Parse binary data into a Registers object configured for the specific MCU family
        and DICE feature set.

        :param data: Binary data to be parsed into registers.
        :return: Configured Registers object with parsed DICE data.
        """
        registers = Registers(family=self.family, feature="dice")
        registers.parse(binary=data)
        return registers


class ProveGenuinity:
    """SPSDK Proof of Genuinity operations manager.

    This class provides functionality for device authenticity verification through cryptographic
    proof of genuinity operations. It supports ECDSA and Hybrid modes for generating and
    verifying genuinity responses, certificate creation, and validation operations.
    """

    class Mode(SpsdkEnum):
        """Enumeration of predefined modes for genuinity proof operations.

        This class defines the available modes that can be used when performing
        genuinity proof operations in DICE (Device Identifier Composition Engine)
        functionality, including ECDSA and Hybrid modes.
        """

        ECDSA = (0, "ECDSA")
        HYBRID = (1, "Hybrid")

    @staticmethod
    def get_response(
        family: FamilyRevision,
        interface: MbootProtocolBase,
        challenge: Optional[bytes] = None,
        mode: Optional[Mode] = Mode.ECDSA,
    ) -> bytes:
        """Generate a response for genuinity proof.

        This method communicates with the device to perform genuinity verification by sending
        a challenge and receiving a cryptographic response that proves device authenticity.

        :param family: Device family revision for database configuration lookup
        :param interface: McuBoot interface for communication with the target device
        :param challenge: Optional 16-byte challenge for response generation, random if None
        :param mode: Mode of genuinity proof operation (ECDSA or Hybrid)
        :raises SPSDKError: Invalid challenge length, communication failure, or operation error
        :return: Response bytes containing the genuinity proof data
        """
        database = get_db(family)
        buffer_address = database.get_int(DatabaseManager.DICE, "buffer_address")
        buffer_size = database.get_int(DatabaseManager.DICE, "buffer_size")

        challenge_bytes = challenge or secrets.token_bytes(16)
        if len(challenge_bytes) != 16:
            raise SPSDKError(f"Challenge must be 16 bytes long, got {len(challenge_bytes)} bytes")

        with McuBoot(interface=interface) as mboot:
            if not mboot.write_memory(buffer_address, challenge_bytes):
                raise SPSDKError(f"Setting of challenge failed. Error code: {mboot.status_string}")

            op = (
                mboot.tp_prove_genuinity
                if mode == ProveGenuinity.Mode.ECDSA
                else mboot.tp_prove_genuinity_hybrid
            )
            tp_response_length = op(buffer_address, buffer_size)
            if tp_response_length is None:
                raise SPSDKError(
                    f"Executing Prove Genuinity failed. Error code: {mboot.status_string}"
                )

            ret = mboot.read_memory(buffer_address, tp_response_length)
            if not ret:
                raise SPSDKError(
                    f"Reading of Trusted provisioning failed. Error code: {mboot.status_string}"
                )

            return ret

    @staticmethod
    def verify_response(
        response: bytes,
        keys: list[bytes],
        challenge: Optional[bytes] = None,
        strict: bool = False,
        print_fn: Callable[[str], None] = print,
    ) -> bool:
        """Verify Prove-Genuinity response from device.

        Validates the authenticity of a device response by verifying signatures using product keys
        and DevID keys, optionally checking challenge match and enforcing strict payload validation.

        :param response: Raw response data from device to verify.
        :param keys: List of product public keys for certificate validation.
        :param challenge: Optional challenge bytes to verify against response challenge.
        :param strict: Enable strict validation of all required payload entries.
        :param print_fn: Function to use for printing status messages.
        :return: True if all validations pass, False otherwise.
        """
        strict_result = True
        logger.debug("Loading product key(s)")
        prod_keys = [PublicKey.parse(key) for key in keys]
        print_fn(f"{len(prod_keys)} Product key(s) loaded")

        logger.debug("Parsing response container")
        outer_container = TPDataContainer.parse(data=response)
        print_fn("Response container parsed")

        if strict:
            strict_result &= ProveGenuinity._check_entry(
                outer_container, PayloadType.CHALLENGE, "Challenge", 16, print_fn
            )
            strict_result &= ProveGenuinity._check_entry(
                outer_container, PayloadType.PLATFORM_DATA, "Platform Data", 16, print_fn
            )
            strict_result &= ProveGenuinity._check_entry(
                outer_container, PayloadType.ROM_PATCH_HASH, "IFR1 ROM Patch hash", 48, print_fn
            )

        logger.debug("Extracting auth certificate")
        cert_data = outer_container.get_entry(PayloadType.NXP_DIE_ID_AUTH_CERT).payload
        print_fn("Authentication certificate extracted")

        logger.debug("Parsing authentication certificate")
        cert_container = TPDataContainer.parse(data=cert_data)
        print_fn("Authentication certificate parsed")

        if strict:
            strict_result &= ProveGenuinity._check_entry(
                cert_container, PayloadType.NXP_DIE_ECID_ID_UID, "ECID", 16, print_fn
            )
            strict_result &= ProveGenuinity._check_entry(
                cert_container, PayloadType.NXP_DIE_RFC4122v4_ID_UUID, "UUID", 16, print_fn
            )

        logger.debug("Verifying authentication certificate signature(s)")
        cert_sign_ok = cert_container.validate(keys=prod_keys)  # type: ignore[arg-type]
        if cert_sign_ok:
            print_fn("Authentication certificate signature(s) validation passed")
        else:
            logger.error("Authentication certificate signature(s) validation FAILED")

        logger.debug("Extracting DevID public keys")
        puk_entries = cert_container.get_entries(PayloadType.NXP_DIE_ID_AUTH_PUK)
        logger.debug("Loading DevID public keys")
        dev_keys = [PublicKey.parse(puk.payload) for puk in puk_entries]
        print_fn(f"{len(dev_keys)} DevID public key(s) loaded")

        response_sign_ok = outer_container.validate(keys=dev_keys)  # type: ignore[arg-type]
        if response_sign_ok:
            print_fn("Response signature validation passed")
        else:
            logger.error("Response signature validation FAILED")

        # Optional challenge verification if provided
        if challenge is not None:
            challenge_entry = outer_container.get_entry(PayloadType.CHALLENGE)
            challenge_ok = challenge_entry.payload == challenge
            if challenge_ok:
                print_fn("Challenge verification passed")
            else:
                logger.error("Challenge verification FAILED")
        else:
            challenge_ok = True

        return cert_sign_ok and response_sign_ok and challenge_ok and strict_result

    @staticmethod
    def _check_entry(
        container: TPDataContainer,
        payload_type: PayloadType,
        name: str,
        length: int,
        print_fn: Callable[[str], None],
    ) -> bool:
        """Helper method to validate container entries.

        Validates that a container entry exists and has the expected payload length.
        Prints validation results and error messages using the provided print function.

        :param container: The TPDataContainer to validate entries from.
        :param payload_type: Type of payload entry to retrieve and validate.
        :param name: Human-readable name of the entry for error messages.
        :param length: Expected length of the entry payload in bytes.
        :param print_fn: Function to use for printing validation results and errors.
        :return: True if entry validation passes, False if length mismatch occurs.
        """
        result = True
        entry = container.get_entry(payload_type)
        print_fn("------------")
        print_fn(f"{name} entry")
        print_fn(str(entry))
        if len(entry.payload) != length:
            result = False
            print_fn(f"{name} entry length mismatch: expected {length}, got {len(entry.payload)}")
        return result

    @staticmethod
    def verify_csr(
        csr_data: bytes,
        prod_keys: list[bytes],
        dice_ca_keys: list[bytes],
        challenge: Optional[bytes] = None,
        extract_alias_keys: bool = False,
        strict: bool = False,
        print_fn: Callable[[str], None] = print,
    ) -> tuple[bool, list[PublicKey]]:
        """Verify Certificate Signing Request (CSR) data.

        This method validates a DICE CSR by verifying signatures at multiple levels:
        authentication certificate, prove genuinity container, and CSR container itself.
        Optionally extracts DICE alias keys and performs strict validation checks.

        :param csr_data: Raw CSR data bytes to be verified.
        :param prod_keys: List of production public keys for certificate validation.
        :param dice_ca_keys: List of DICE CA public keys for CSR validation.
        :param challenge: Optional challenge bytes to verify against CSR challenge.
        :param extract_alias_keys: Whether to extract DICE alias keys from CSR.
        :param strict: Whether to perform strict validation of required entries.
        :param print_fn: Function to use for printing status messages.
        :return: Tuple of verification result (bool) and list of extracted alias keys.
        """
        strict_result = True
        logger.debug("Loading product key(s)")
        prod_keys_parsed = [PublicKey.parse(key) for key in prod_keys]
        print_fn(f"{len(prod_keys_parsed)} Product key(s) loaded")

        logger.debug("Parsing CSR container")
        csr_container = TPDataContainer.parse(data=csr_data)
        print_fn("CSR container parsed")

        logger.debug("Extracting Prove Genuinity container")
        prove_container_data = csr_container.get_entry(PayloadType.NXP_DIE_ID_AUTH_CERT).payload
        prove_container = TPDataContainer.parse(prove_container_data)
        print_fn("Prove Genuinity container extracted and parsed")

        if strict:
            strict_result &= ProveGenuinity._check_entry(
                prove_container, PayloadType.CHALLENGE, "Challenge", 16, print_fn
            )
            strict_result &= ProveGenuinity._check_entry(
                prove_container, PayloadType.PLATFORM_DATA, "Platform Data", 16, print_fn
            )
            strict_result &= ProveGenuinity._check_entry(
                prove_container, PayloadType.ROM_PATCH_HASH, "IFR1 ROM Patch hash", 48, print_fn
            )

        logger.debug("Extracting authentication certificate")
        cert_data = prove_container.get_entry(PayloadType.NXP_DIE_ID_AUTH_CERT).payload
        cert_container = TPDataContainer.parse(data=cert_data)
        print_fn("Authentication certificate extracted and parsed")

        if strict:
            strict_result &= ProveGenuinity._check_entry(
                cert_container, PayloadType.NXP_DIE_ECID_ID_UID, "ECID", 16, print_fn
            )
            strict_result &= ProveGenuinity._check_entry(
                cert_container, PayloadType.NXP_DIE_RFC4122v4_ID_UUID, "UUID", 16, print_fn
            )

        logger.debug("Verifying authentication certificate signature(s)")
        cert_sign_ok = cert_container.validate(keys=prod_keys_parsed)  # type: ignore[arg-type]
        if cert_sign_ok:
            print_fn("Authentication certificate signature(s) validation passed")
        else:
            print_fn("Authentication certificate signature(s) validation FAILED")

        logger.debug("Extracting DICE DevID public keys")
        puk_entries = cert_container.get_entries(PayloadType.NXP_DIE_ID_AUTH_PUK)
        logger.debug("Loading DICE DevID public keys")
        dice_device_id_keys = [PublicKey.parse(puk.payload) for puk in puk_entries]

        prove_sign_ok = prove_container.validate(keys=dice_device_id_keys)  # type: ignore[arg-type]
        if prove_sign_ok:
            print_fn("Prove Genuinity container signature(s) validation passed")
        else:
            logger.error("Prove Genuinity container signature(s) validation FAILED")

        csr_sign_ok = csr_container.validate(keys=dice_ca_keys)  # type: ignore[arg-type]
        if csr_sign_ok:
            print_fn("CSR container signature(s) validation passed")
        else:
            logger.error("CSR container signature(s) validation FAILED")

        if challenge is not None:
            challenge_entry = csr_container.get_entry(PayloadType.CHALLENGE)
            challenge_ok = challenge_entry.payload == challenge
            if challenge_ok:
                print_fn("Challenge verification passed")
            else:
                logger.error("Challenge verification FAILED")
        else:
            challenge_ok = True

        if extract_alias_keys:
            logger.debug("Extracting DICE DevID public keys from CSR")
            csr_puk_entries = csr_container.get_entries(PayloadType.DICE_ALIAS_KEY)
            dice_alias_keys = [PublicKey.parse(puk.payload) for puk in csr_puk_entries]
            print_fn(f"{len(dice_alias_keys)} DevID public key(s) loaded from CSR")

            # dirty hack to make the second key MLDSA instead of Dilithium
            if len(dice_alias_keys) == 2:
                dice_alias_keys[1] = PublicKeyMLDSA.parse(csr_puk_entries[1].payload)
        else:
            dice_alias_keys = []

        verification_result = (
            cert_sign_ok and prove_sign_ok and csr_sign_ok and challenge_ok and strict_result
        )
        return verification_result, dice_alias_keys

    @classmethod
    def create_cert(
        cls,
        response: bytes,
        ca_prk: bytes,
        subject_common_name: Optional[str] = None,
        ca_puk: Optional[bytes] = None,
        ca_name: Optional[str] = None,
        use_full_der_for_serial: bool = False,
    ) -> bytes:
        """Create IDevID certificate from PG response data.

        This method parses the response data to extract device public keys and creates
        X.509 certificates signed by the provided CA private key. It supports both
        ECC and ML-DSA key types and ensures type compatibility between device and CA keys.

        :param response: Raw response data containing device authentication information.
        :param ca_prk: CA private key in bytes format for signing the certificate.
        :param subject_common_name: Optional common name for certificate subject.
        :param ca_puk: Optional CA public key in bytes format.
        :param ca_name: Optional CA name for certificate issuer.
        :param use_full_der_for_serial: Whether to use full DER encoding for serial number.
        :raises SPSDKError: When no type match found between device keys and CA key.
        :return: Encoded certificate data in bytes format.
        """
        out_container = TPDataContainer.parse(data=response)
        cert_data = out_container.get_entry(PayloadType.NXP_DIE_ID_AUTH_CERT).payload
        cert_container = TPDataContainer.parse(data=cert_data)
        puk_entries = cert_container.get_entries(PayloadType.NXP_DIE_ID_AUTH_PUK)
        ca_prk_key = PrivateKey.parse(ca_prk)
        if ca_puk and ca_name:
            ca_puk_key = PublicKey.parse(ca_puk)
        dev_keys = [PublicKey.parse(puk.payload) for puk in puk_entries]

        for i, dev_key in enumerate(dev_keys):
            if isinstance(dev_key, (PublicKeyDilithium, PublicKeyMLDSA)):
                dev_keys[i] = PublicKeyMLDSA.parse(dev_key.key.public_data)

        print(f"{ca_prk_key = }")
        print(f"{dev_keys = }")

        for dev_key in dev_keys:
            if isinstance(dev_key, PublicKeyMLDSA) and not isinstance(ca_prk_key, PrivateKeyMLDSA):
                continue
            if isinstance(dev_key, PublicKeyEcc) and not isinstance(ca_prk_key, PrivateKeyEcc):
                continue

            subject_name, subject_key_hash = get_x509_name(
                subject_common_name or "NXP DICE 2.0 - IDevID", dev_key, use_full_der_for_serial
            )
            if ca_puk and ca_name:
                issuer_name = x509.Name(
                    [
                        x509.NameAttribute(x509.NameOID.COMMON_NAME, ca_name),
                    ]
                )
            else:
                issuer_name = None

            serial_bytes = bytearray(subject_key_hash)[:20]
            serial_bytes[0] = (serial_bytes[0] | 0x04) & ~0x80

            extensions = [
                x509.BasicConstraints(ca=True, path_length=1),
                x509.KeyUsage(
                    key_cert_sign=True,
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                x509.SubjectKeyIdentifier(digest=subject_key_hash[:20]),
            ]
            if ca_puk and ca_name:
                extensions.append(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_puk_key.key),
                )

            tbs = TBSCertificate.create(
                serial=int.from_bytes(serial_bytes, byteorder="big"),
                subject=subject_name,
                issuer=issuer_name,
                public_key=dev_key,
                extensions=extensions,
            )
            cert = Certificate.create(tbs_certificate=tbs, signing_key=ca_prk_key)
            cert_data = cert.encode()
            return cert_data

        raise SPSDKError(f"Could not found a type match between {dev_keys} and {ca_prk_key}")


def get_x509_name(
    name: str, public_key: PublicKey, use_full_der_for_serial: bool = False
) -> tuple[x509.Name, bytes]:
    """Create X.509 Name object with consistent attributes and key hash.

    The method generates an X.509 Name with common name and serial number attributes.
    The serial number is derived from the public key hash. Additionally returns
    a truncated key hash for certificate identification purposes.

    :param name: Common name to be used in the X.509 Name object.
    :param public_key: Public key used for generating the serial number hash.
    :param use_full_der_for_serial: Whether to use full DER encoding for serial
        generation, defaults to False.
    :return: Tuple containing the X.509 Name object and 20-byte key hash.
    """
    if use_full_der_for_serial:
        key_data = public_key.export(SPSDKEncoding.DER)
    else:
        key_data = public_key.export(SPSDKEncoding.NXP)
        if isinstance(public_key, PublicKeyEcc):
            key_data = b"\x04" + key_data
    key_hash = get_hash(key_data, EnumHashAlgorithm.SHA256)
    x509_name = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COMMON_NAME, name),
            x509.NameAttribute(x509.NameOID.SERIAL_NUMBER, key_hash.hex()),
        ]
    )
    return (x509_name, key_hash[:20])
