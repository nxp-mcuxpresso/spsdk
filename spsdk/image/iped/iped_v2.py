#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
# cSpell: words BHBBB

"""SPSDK IPED V2 table creator.

The module serializes family-specific IPED configuration formats used by boot ROM/ELE handoff:
XSPI register images and tagged ROM/Sentinel configuration blobs. IPED/PRINCE data encryption
uses SPSDK's built-in PRINCE models, with optional native acceleration for supported legacy
models.
"""

import inspect
import logging
import os
from copy import deepcopy
from dataclasses import dataclass
from functools import lru_cache
from struct import pack, unpack_from
from typing import Any

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from typing_extensions import Self

from spsdk.exceptions import SPSDKError, SPSDKKeyError, SPSDKValueError
from spsdk.image.ahab.ahab_data import KeyblobLifeCycle
from spsdk.image.iped.prince import PrinceError, PrinceV2Cipher
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.binary_image import BinaryImage
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, get_db, update_validation_schema_family
from spsdk.utils.misc import Endianness, align_block, file_extension, value_to_int
from spsdk.utils.spsdk_enum import SpsdkEnum
from spsdk.utils.verifier import Verifier, VerifierResult

logger = logging.getLogger(__name__)

ROM_CONFIG_HEADER_SIZE = 0x10
ROM_CONFIG_REGION_SIZE = 0x20
ROM_CONFIG_HEADER_TAG = 0x4C
ROM_CONFIG_REGION_TAG = 0x43


def _uses_rom_config_blob(family: FamilyRevision | None) -> bool:
    """Return whether the family uses a ROM/Sentinel tagged IPED configuration blob."""
    if family is None:
        return False
    return get_db(family).get_bool(DatabaseManager.IPED, "rom_config_blob", False)


def _uses_prince_v2_model(family: FamilyRevision | None) -> bool:
    """Return whether the family uses the configurable Python PRINCE V2 model."""
    if family is None:
        return False
    return get_db(family).get_bool(DatabaseManager.IPED, "prince_v2_model", False)


def _get_default_backend_device(family: FamilyRevision) -> str:
    """Get the default device identifier for the family-specific encryption model."""
    configured_device = get_db(family).get_str(DatabaseManager.IPED, "backend_device", "")
    return configured_device or family.name.lower()


def _get_default_backend_instance(family: FamilyRevision) -> str:
    """Get the default instance identifier for the family-specific encryption model."""
    return get_db(family).get_str(DatabaseManager.IPED, "backend_instance", "xspi0")


def _get_derivation_lifecycles(family: FamilyRevision) -> list[str]:
    """Get supported derivation lifecycles from device database."""
    return [
        str(label).lower()
        for label in get_db(family).get_list(DatabaseManager.IPED, "derivation_lifecycles", [])
    ]


def _get_derivation_instance_map(family: FamilyRevision) -> dict[str, int]:
    """Get derivation instance constants from device database."""
    db_map = get_db(family).get_dict(DatabaseManager.IPED, "derivation_instance_map", {})
    return {str(name).lower(): value_to_int(value) for name, value in db_map.items()}


def _load_word_list(config: Config, key: str, expected_count: int) -> list[int]:
    """Load a fixed-size list of 32-bit words from configuration.

    :param config: Source configuration.
    :param key: Configuration key.
    :param expected_count: Expected number of 32-bit words.
    :raises SPSDKValueError: If count or value widths are invalid.
    :return: Parsed list of 32-bit words.
    """
    raw_value = config.get(key)
    if isinstance(raw_value, list):
        values = config.get_list(key)
        if len(values) != expected_count:
            raise SPSDKValueError(f"IPED {key} must contain exactly {expected_count} 32-bit words.")
        words = [value_to_int(value) for value in values]
    else:
        key_bytes = config.load_symmetric_key(
            key=key, expected_size=expected_count * 4, name=f"IPED {key}"
        )
        words = [
            int.from_bytes(key_bytes[offset : offset + 4], "little")
            for offset in range(0, len(key_bytes), 4)
        ]
    for index, word in enumerate(words):
        _check_u32(word, f"{key}[{index}]")
    return words


def _words_to_bytes_le(words: list[int]) -> bytes:
    """Convert list of 32-bit words into little-endian bytes."""
    return b"".join(word.to_bytes(4, "little") for word in words)


def _derive_master_key(
    product_string: str,
    cust_mk_sk: bytes,
    lifecycle: str,
    supported_lifecycles: list[str],
    srkh_classic: bytes,
    srkh_pqc: bytes,
) -> bytes:
    """Derive external memory master key from fuse material.

    :param product_string: Product string used by AHAB offline keyblob derivation.
    :param cust_mk_sk: 256-bit CUST_MK_SK key value.
    :param lifecycle: Device lifecycle label.
    :param supported_lifecycles: Supported lifecycle labels from device database.
    :param srkh_classic: 512-bit classical SRKH bytes.
    :param srkh_pqc: 512-bit PQC SRKH bytes.
    :raises SPSDKValueError: If lifecycle is unsupported.
    :return: 32-byte derived external memory master key.
    """
    lifecycle_l = lifecycle.lower()
    try:
        lifecycle_state = KeyblobLifeCycle.from_label(lifecycle_l)
    except SPSDKKeyError as exc:
        raise SPSDKValueError(
            f"Unsupported lifecycle '{lifecycle}'. " f"Use one of: {supported_lifecycles}"
        ) from exc
    if lifecycle_state.label.lower() not in supported_lifecycles:
        raise SPSDKValueError(
            f"Unsupported lifecycle '{lifecycle}'. " f"Use one of: {supported_lifecycles}"
        )

    derivation_data = b"\x64"
    derivation_data += product_string.encode("ascii")
    derivation_data += srkh_classic
    derivation_data += srkh_pqc
    derivation_data += lifecycle_state.tag.to_bytes(4, "little")
    derivation_data += bytes(12)
    derivation_data += (0x100).to_bytes(4, "big")

    mac = b""
    for index in range(1, 3):
        cmac_ctx = cmac.CMAC(algorithms.AES(cust_mk_sk))
        cmac_ctx.update(derivation_data + index.to_bytes(4, "big"))
        mac += cmac_ctx.finalize()
    return mac


def _derive_iped_key(
    master_key: bytes, label: int, instance: str, mode: int, instance_map: dict[str, int]
) -> bytes:
    """Derive one IPED key (IV or MEM key).

    :param master_key: 32-byte derived external memory master key.
    :param label: Derivation label (0x65 for IV key, 0x66 for MEM key).
    :param instance: XSPI instance (`xspi0` or `xspi1`).
    :param mode: IPED mode tag value.
    :param instance_map: Instance constants from device database.
    :raises SPSDKValueError: If instance is unsupported.
    :return: 16-byte derived key.
    """
    instance_l = instance.lower()
    if instance_l not in instance_map:
        raise SPSDKValueError(
            f"Unsupported instance '{instance}'. " f"Use one of: {sorted(instance_map.keys())}"
        )

    derivation_data = label.to_bytes(1, "little")
    derivation_data += instance_map[instance_l].to_bytes(4, "little")
    derivation_data += mode.to_bytes(1, "little")
    derivation_data += bytes(18)
    derivation_data += (0x80).to_bytes(4, "big")
    derivation_data += (0x01).to_bytes(4, "big")

    cmac_ctx = cmac.CMAC(algorithms.AES(master_key))
    cmac_ctx.update(derivation_data)
    return cmac_ctx.finalize()


def _generate_iv(iv_key: bytes, fw_version: int, nonce: int) -> list[int]:
    """Generate 64-bit IV from derived IV key, FW version, and nonce.

    :param iv_key: 16-byte IV derivation key.
    :param fw_version: 32-bit firmware version.
    :param nonce: 64-bit nonce value.
    :return: Two 32-bit IV words in big-endian word order.
    """
    plaintext = nonce.to_bytes(8, "little")
    plaintext += fw_version.to_bytes(4, "little")
    plaintext += bytes(4)
    encryptor = Cipher(algorithms.AES(iv_key), modes.ECB()).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    iv_msb = int.from_bytes(ciphertext[0:4], "big")
    iv_lsb = int.from_bytes(ciphertext[4:8], "big")
    return [iv_msb, iv_lsb]


@dataclass(frozen=True)
class _KeyDerivationContext:
    """Prepared key-derivation context for IPED table generation."""

    device: str
    instance: str
    fw_version: int
    mem_enc_key: bytes
    master_key: bytes
    instance_map: dict[str, int]


def _load_key_derivation_context(
    config: Config, family: FamilyRevision
) -> _KeyDerivationContext | None:
    """Load optional key derivation settings from configuration.

    Supports both top-level fields and nested ``key_derivation`` object.

    :param config: IPED V2 configuration.
    :param family: Target family.
    :raises SPSDKValueError: If derivation settings are partially configured or invalid.
    :return: Parsed derivation context, or ``None`` when derivation is not requested.
    """
    derivation_config = (
        config.get_config("key_derivation") if "key_derivation" in config else config
    )
    required_fields = ("cust_mk_sk", "srkh", "pqc_srkh", "lifecycle")
    present_fields = [field for field in required_fields if field in derivation_config]
    if not present_fields:
        return None
    missing_fields = [field for field in required_fields if field not in derivation_config]
    if missing_fields:
        raise SPSDKValueError(
            "Key derivation is partially configured. Missing fields: " + ", ".join(missing_fields)
        )

    default_device = _get_default_backend_device(family)
    if "device" in config:
        default_device = config.get_str("device").lower()
    device = derivation_config.get_str("device", default_device).lower()

    default_instance = _get_default_backend_instance(family)
    if "instance" in config:
        default_instance = config.get_str("instance").lower()
    instance = derivation_config.get_str("instance", default_instance).lower()

    default_fw_version = config.get_int("fw_version", 0)
    fw_version = derivation_config.get_int("fw_version", default_fw_version)
    _check_u32(fw_version, "fw_version")

    cust_mk_sk = _words_to_bytes_le(_load_word_list(derivation_config, "cust_mk_sk", 8))
    srkh = _words_to_bytes_le(_load_word_list(derivation_config, "srkh", 16))
    pqc_srkh = _words_to_bytes_le(_load_word_list(derivation_config, "pqc_srkh", 16))
    lifecycle = derivation_config.get_str("lifecycle")
    supported_lifecycles = _get_derivation_lifecycles(family)
    if not supported_lifecycles:
        raise SPSDKValueError("Missing IPED derivation lifecycles in device database.")
    instance_map = _get_derivation_instance_map(family)
    if not instance_map:
        raise SPSDKValueError("Missing IPED derivation instance map in device database.")

    product_string = get_db(family).get_str(DatabaseManager.AHAB, "offline_keyblob_constant")
    if not product_string:
        raise SPSDKValueError("Missing offline keyblob product string.")
    master_key = _derive_master_key(
        product_string, cust_mk_sk, lifecycle, supported_lifecycles, srkh, pqc_srkh
    )
    mem_enc_key = _derive_iped_key(master_key, 0x66, instance, IpedMode.CTR.tag, instance_map)
    return _KeyDerivationContext(
        device=device,
        instance=instance,
        fw_version=fw_version,
        mem_enc_key=mem_enc_key,
        master_key=master_key,
        instance_map=instance_map,
    )


class IpedMode(SpsdkEnum):
    """IPED context mode."""

    CTR = (0, "ctr", "CTR mode")
    GCM = (1, "gcm", "GCM mode")
    XEX = (2, "xex", "XEX mode")
    BYPASS = (3, "bypass", "Bypass mode")


def _check_u32(value: int, name: str) -> None:
    """Check that value fits into an unsigned 32-bit register field.

    :param value: Value to check.
    :param name: Value name for error reporting.
    :raises SPSDKValueError: If value is outside of unsigned 32-bit range.
    """
    if value < 0 or value > 0xFFFFFFFF:
        raise SPSDKValueError(f"{name} must fit into 32 bits.")


def _words_from_config(config: Config, key: str, default: list[int] | None = None) -> list[int]:
    """Load two 32-bit words from configuration.

    :param config: Source configuration.
    :param key: Configuration key.
    :param default: Default two words if the key is missing.
    :raises SPSDKValueError: If the value does not represent exactly two words.
    :return: List of two 32-bit words.
    """
    value = config.get(key)
    if value is None:
        return default[:] if default is not None else [0, 0]
    if isinstance(value, list):
        if len(value) != 2:
            raise SPSDKValueError(f"IPED {key} must contain exactly two 32-bit words.")
        words = [value_to_int(word) for word in value]
    else:
        data = config.load_symmetric_key(key, expected_size=8, name=f"IPED {key}")
        words = [
            int.from_bytes(data[0:4], byteorder=Endianness.BIG.value),
            int.from_bytes(data[4:8], byteorder=Endianness.BIG.value),
        ]
    for index, word in enumerate(words):
        _check_u32(word, f"{key}[{index}]")
    return words


def _words_to_hex(words: list[int]) -> str:
    """Convert two 32-bit words into one 8-byte hexadecimal value.

    :param words: Two 32-bit words.
    :return: Hexadecimal string.
    """
    if len(words) != 2:
        raise SPSDKValueError("IPED value must contain exactly two 32-bit words.")
    return f"0x{value_to_int(words[0]):08x}{value_to_int(words[1]):08x}"


def _words_to_int(words: list[int]) -> int:
    """Convert two 32-bit words into one 64-bit integer.

    :param words: Two 32-bit words.
    :return: 64-bit integer.
    """
    if len(words) != 2:
        raise SPSDKValueError("IPED value must contain exactly two 32-bit words.")
    return (value_to_int(words[0]) << 32) | value_to_int(words[1])


def _load_iped_key(config: Config) -> bytes | None:
    """Load optional 128-bit effective IPED encryption key from configuration.

    :param config: Context configuration.
    :return: Effective IPED key or None if the key is not configured.
    """
    if config.get("key") is None:
        return None
    return config.load_symmetric_key("key", expected_size=16, name="IPED encryption key")


@lru_cache(maxsize=1)
def _load_iped_backend() -> tuple[type[Any], type[Exception]]:
    """Load IPED encryption backend.

    Uses SPSDK pure-Python ``PrinceCipher`` by default and prefers optional native
    ``spsdk-iped`` when available and verified against reference vectors.

    :return: Tuple with backend class and backend exception type.
    """
    from spsdk.image.iped.prince import PrinceCipher

    try:
        from spsdk_iped import (
            IPED as NativeIped,  # type: ignore[import-not-found] # pylint: disable=import-outside-toplevel,import-error
        )
        from spsdk_iped import (
            IPEDError as NativeIpedError,  # type: ignore[import-not-found] # pylint: disable=import-outside-toplevel,import-error
        )
    except ImportError:
        logger.debug("Using SPSDK Python PRINCE backend (native spsdk-iped not installed)")
        return PrinceCipher, PrinceError

    ctr_plain = (0x0CF16D721BCADFCB).to_bytes(8, "big")
    ctr_expected = (0xCEDB66D149075929).to_bytes(8, "big")
    gcm_plain = b"".join(
        block.to_bytes(8, "big")
        for block in [
            0x8A64EC141794252F,
            0xDE143CBCDE2BBEBC,
            0xB30C0C6618836731,
            0xE218FAC40858B510,
        ]
    )
    gcm_expected = b"".join(
        block.to_bytes(8, "big")
        for block in [
            0x6FD8089AD7A48DF6,
            0xC90DBE898F02BA55,
            0xF5F7A65030D0693B,
            0xAD103E34E80016FC,
        ]
    )
    try:
        ctr_backend = NativeIped(
            key=0x01,
            address=0x80003000,
            iv=0x79EAFAB3A72412A1,
            double_encrypt=True,
            use_gcm=False,
        )
        if ctr_backend.encrypt(ctr_plain) != ctr_expected:
            raise SPSDKError("CTR reference vector mismatch")

        gcm_backend = NativeIped(
            key=0x9DC81A3B3AEF4775297C23529ACCCE35,
            address=0x80003000,
            iv=0xC5FFB28BBB2F7876,
            aad=0x0D11BB1AA784324F,
            use_gcm=True,
        )
        if gcm_backend.encrypt(gcm_plain) != gcm_expected:
            raise SPSDKError("GCM reference vector mismatch")
        if int(gcm_backend.tag) != 0xE38CA1F93131FC30:
            raise SPSDKError("GCM reference tag mismatch")

        logger.debug("Using native C++ PRINCE backend (spsdk-iped)")
        return NativeIped, NativeIpedError
    except (AttributeError, TypeError, ValueError, SPSDKError, NativeIpedError) as exc:
        logger.warning(
            f"Native spsdk-iped backend verification failed, using Python backend: {exc}"
        )
        return PrinceCipher, PrinceError


class IpedContext:
    """One IPED context register record."""

    FORMAT = "<8I"
    SIZE = 0x20
    ADDRESS_ALIGNMENT = 0x100
    FREEZE_MASK = 0x3
    KEY_SIZE = 16
    ENCRYPTION_BLOCK_SIZE = 8
    GCM_BLOCKS_PER_TAG = 4
    GCM_CHUNK_SIZE = ENCRYPTION_BLOCK_SIZE * GCM_BLOCKS_PER_TAG

    def __init__(
        self,
        start_address: int,
        end_address: int,
        mode: IpedMode = IpedMode.CTR,
        iv: list[int] | None = None,
        aad: list[int] | None = None,
        nonce: int | None = None,
        region_id: int | None = None,
        freeze: int = 0,
        address_alignment: int = ADDRESS_ALIGNMENT,
        key: bytes | None = None,
    ) -> None:
        """Initialize IPED context.

        :param start_address: Start address of the IPED region.
        :param end_address: End address of the IPED region.
        :param mode: IPED context mode.
        :param iv: Two 32-bit IV words.
        :param aad: Two 32-bit AAD words.
        :param nonce: Optional 64-bit nonce used by ROM key derivation.
        :param region_id: Optional hardware context identifier.
        :param freeze: Two-bit context freeze value.
        :param address_alignment: Required region address alignment.
        :param key: Optional 128-bit effective IPED encryption key for data blobs.
        :raises SPSDKValueError: If the context parameters are invalid.
        """
        self.start_address = value_to_int(start_address)
        self.end_address = value_to_int(end_address)
        self.mode = mode
        self.iv = iv[:] if iv else [0, 0]
        self.aad = aad[:] if aad else [0, 0]
        self.nonce = value_to_int(nonce) if nonce is not None else None
        self.region_id = value_to_int(region_id) if region_id is not None else None
        self.freeze = value_to_int(freeze)
        self.address_alignment = value_to_int(address_alignment)
        self.key = key
        self.validate()

    def validate(self) -> None:
        """Validate IPED context fields.

        :raises SPSDKValueError: If the context fields are invalid.
        """
        _check_u32(self.start_address, "start_address")
        _check_u32(self.end_address, "end_address")
        if self.end_address < self.start_address:
            raise SPSDKValueError("IPED context end_address must be greater than start_address.")
        if self.address_alignment <= 0:
            raise SPSDKValueError("IPED address alignment must be positive.")
        if self.start_address % self.address_alignment:
            raise SPSDKValueError(
                f"IPED context start_address must be aligned to {hex(self.address_alignment)}."
            )
        if self.end_address % self.address_alignment:
            raise SPSDKValueError(
                f"IPED context end_address must be aligned to {hex(self.address_alignment)}."
            )
        if self.freeze & ~self.FREEZE_MASK:
            raise SPSDKValueError(
                f"IPED context freeze value exceeds mask {hex(self.FREEZE_MASK)}."
            )
        if self.nonce is not None and (self.nonce < 0 or self.nonce > 0xFFFFFFFFFFFFFFFF):
            raise SPSDKValueError("IPED context nonce must fit into 64 bits.")
        if self.region_id is not None and not 0 <= self.region_id < IpedV2.CONTEXT_COUNT:
            raise SPSDKValueError(
                f"IPED region_id must be between 0 and {IpedV2.CONTEXT_COUNT - 1}."
            )
        for field_name, words in (("iv", self.iv), ("aad", self.aad)):
            if len(words) != 2:
                raise SPSDKValueError(f"IPED context {field_name} must contain two words.")
            for index, word in enumerate(words):
                _check_u32(value_to_int(word), f"{field_name}[{index}]")
        if self.key is not None and len(self.key) != self.KEY_SIZE:
            raise SPSDKValueError(f"IPED context key must be {self.KEY_SIZE} bytes long.")

    @property
    def start_register(self) -> int:
        """Get serialized START register value.

        :return: START register value with mode bits.
        """
        return self.start_address | self.mode.tag

    def export(self) -> bytes:
        """Export context into the XSPI IPED register-image layout.

        :return: Serialized context bytes.
        """
        return pack(
            self.FORMAT,
            self.iv[0],
            self.iv[1],
            self.start_register,
            self.end_address,
            self.aad[0],
            self.aad[1],
            0,
            0,
        )

    def matches_range(self, start_address: int, end_address: int) -> bool:
        """Check if the context fully contains an address range.

        :param start_address: Start address of the range.
        :param end_address: Exclusive end address of the range.
        :return: True if the range fits into the context.
        """
        return self.start_address <= start_address and end_address <= self.end_address

    def encrypted_data_size(self, data_size: int, interleaved_gcm_tags: bool = False) -> int:
        """Calculate encrypted output size for the given plaintext size.

        :param data_size: Plaintext size in bytes.
        :param interleaved_gcm_tags: Include per-chunk GCM tag expansion in output size.
        :return: Resulting encrypted size in bytes.
        """
        if self.mode == IpedMode.GCM and interleaved_gcm_tags:
            aligned_size = (
                (data_size + self.GCM_CHUNK_SIZE - 1) // self.GCM_CHUNK_SIZE
            ) * self.GCM_CHUNK_SIZE
            tag_count = aligned_size // self.GCM_CHUNK_SIZE
            return aligned_size + tag_count * self.ENCRYPTION_BLOCK_SIZE
        return (
            (data_size + self.ENCRYPTION_BLOCK_SIZE - 1) // self.ENCRYPTION_BLOCK_SIZE
        ) * self.ENCRYPTION_BLOCK_SIZE

    @staticmethod
    def _get_backend_capabilities(backend_cls: type[Any]) -> tuple[set[str], bool]:
        """Inspect backend constructor capabilities.

        :param backend_cls: Backend class to inspect.
        :return: Tuple of supported parameter names and kwargs support flag.
        """
        try:
            signature = inspect.signature(backend_cls)
            parameters = signature.parameters
            params = set(parameters.keys())
            supports_kwargs = any(
                parameter.kind == inspect.Parameter.VAR_KEYWORD for parameter in parameters.values()
            )
            return params, supports_kwargs
        except (TypeError, ValueError):
            return {"key", "address", "iv", "use_gcm", "aad", "double_encrypt"}, False

    @staticmethod
    def _supports_backend_arg(params: set[str], supports_kwargs: bool, arg_name: str) -> bool:
        """Return whether backend supports a constructor argument.

        :param params: Explicitly supported constructor parameters.
        :param supports_kwargs: True if backend accepts arbitrary kwargs.
        :param arg_name: Argument name to check.
        :return: True if argument is accepted.
        """
        return supports_kwargs or arg_name in params

    @classmethod
    def _validate_backend_mode_support(
        cls, mode: IpedMode, params: set[str], supports_kwargs: bool
    ) -> None:
        """Validate that backend supports required mode controls.

        :param mode: Requested IPED mode.
        :param params: Explicitly supported constructor parameters.
        :param supports_kwargs: True if backend accepts arbitrary kwargs.
        :raises SPSDKError: If selected mode is not supported.
        """
        supports_mode = cls._supports_backend_arg(params, supports_kwargs, "mode")
        supports_gcm_switch = cls._supports_backend_arg(params, supports_kwargs, "use_gcm")

        if mode == IpedMode.XEX and not supports_mode:
            raise SPSDKError(
                "IPED XEX data encryption requires a backend with explicit mode support."
            )
        if mode == IpedMode.GCM and not supports_mode and not supports_gcm_switch:
            raise SPSDKError("IPED GCM data encryption is not supported by the active backend.")

    @classmethod
    def _build_backend_kwargs(
        cls,
        key: bytes,
        address: int,
        iv: int,
        mode: IpedMode,
        aad: int,
        double_encryption: bool,
        device: str | None,
        instance: str | None,
        context_nr: int | None,
        params: set[str],
        supports_kwargs: bool,
    ) -> dict[str, Any]:
        """Build backend constructor keyword arguments.

        :return: Keyword arguments compatible with backend constructor.
        """
        kwargs: dict[str, Any] = {
            "key": key,
            "address": address,
            "iv": iv,
            "double_encrypt": double_encryption,
        }
        optional_args: dict[str, Any] = {
            "mode": mode.tag,
            "use_gcm": mode == IpedMode.GCM,
            "aad": aad,
            "device": device,
            "instance": instance,
        }
        for arg_name, arg_value in optional_args.items():
            if cls._supports_backend_arg(params, supports_kwargs, arg_name):
                kwargs[arg_name] = arg_value
        if context_nr is not None and cls._supports_backend_arg(
            params, supports_kwargs, "context_nr"
        ):
            kwargs["context_nr"] = context_nr
        return kwargs

    @classmethod
    def _create_backend(
        cls,
        backend_cls: type[Any],
        key: bytes,
        address: int,
        iv: int,
        mode: IpedMode,
        aad: int,
        double_encryption: bool,
        family: FamilyRevision | None,
        device: str | None,
        instance: str | None,
        context_nr: int | None,
    ) -> Any:
        """Create IPED backend instance while handling backend API differences."""
        if _uses_prince_v2_model(family):
            if family is None or instance is None or context_nr is None:
                raise SPSDKError("PRINCE V2 model requires family, instance, and context number.")
            model = get_db(family).get_dict(DatabaseManager.IPED, ["prince_v2_models", instance])
            context_keys = model.get("context_keys")
            context_ivs = model.get("context_ivs")
            if not isinstance(context_keys, list) or not isinstance(context_ivs, list):
                raise SPSDKError(
                    f"Missing PRINCE V2 context keys or IVs for instance '{instance}'."
                )
            if context_nr >= len(context_keys) or context_nr >= len(context_ivs):
                raise SPSDKError(
                    f"PRINCE V2 context {context_nr} is not available for instance '{instance}'."
                )
            effective_key = (
                int.from_bytes(key, "big") ^ value_to_int(context_keys[context_nr])
            ).to_bytes(cls.KEY_SIZE, "big")
            effective_iv = iv ^ value_to_int(context_ivs[context_nr])
            return PrinceV2Cipher(
                key=effective_key,
                address=address,
                iv=effective_iv,
                sbox_t0=value_to_int(model["sbox_t0"]),
                sbox_t1=value_to_int(model["sbox_t1"]),
                inverse_sbox_t0=value_to_int(model["inverse_sbox_t0"]),
                inverse_sbox_t1=value_to_int(model["inverse_sbox_t1"]),
                duplicate_address=bool(model.get("duplicate_address", False)),
                use_gcm=mode == IpedMode.GCM,
                aad=aad,
                double_encrypt=double_encryption,
            )

        params, supports_kwargs = cls._get_backend_capabilities(backend_cls)
        cls._validate_backend_mode_support(mode, params, supports_kwargs)
        kwargs = cls._build_backend_kwargs(
            key=key,
            address=address,
            iv=iv,
            mode=mode,
            aad=aad,
            double_encryption=double_encryption,
            device=device,
            instance=instance,
            context_nr=context_nr,
            params=params,
            supports_kwargs=supports_kwargs,
        )
        return backend_cls(**kwargs)

    def encrypt_data(
        self,
        data: bytes,
        address: int,
        double_encryption: bool,
        family: FamilyRevision | None = None,
        device: str | None = None,
        instance: str | None = None,
        context_nr: int | None = None,
        interleaved_gcm_tags: bool = False,
    ) -> bytes:
        """Encrypt data using this IPED context.

        :param data: Plain data to encrypt.
        :param address: Absolute address where data will be stored.
        :param double_encryption: Enable double encryption in the IPED backend.
        :param family: Target family.
        :param device: Optional encryption model device identifier.
        :param instance: Optional encryption model instance identifier.
        :param context_nr: Optional encryption model context index.
        :param interleaved_gcm_tags: Emit per-chunk GCM tags in output stream.
        :raises SPSDKError: If encryption cannot be performed.
        :return: Encrypted data aligned to IPED block size (and GCM-tagged for GCM mode).
        """
        if self.mode == IpedMode.BYPASS:
            return align_block(data, self.ENCRYPTION_BLOCK_SIZE)
        if self.mode == IpedMode.XEX:
            raise SPSDKError(
                "IPED XEX data encryption is not supported by the active PRINCE backend."
            )
        if self.key is None:
            raise SPSDKError(
                f"IPED context {hex(self.start_address)}-{hex(self.end_address)} has no key "
                "configured for data encryption."
            )

        backend_cls, backend_error = (
            (PrinceV2Cipher, PrinceError) if _uses_prince_v2_model(family) else _load_iped_backend()
        )
        iv = _words_to_int(self.iv)
        aad = _words_to_int(self.aad)
        try:
            if self.mode == IpedMode.GCM and interleaved_gcm_tags:
                data = align_block(data, self.GCM_CHUNK_SIZE)
                encrypted = bytearray()
                chunk_address = address
                for offset in range(0, len(data), self.GCM_CHUNK_SIZE):
                    backend = self._create_backend(
                        backend_cls=backend_cls,
                        key=self.key,
                        address=chunk_address,
                        iv=iv,
                        mode=self.mode,
                        aad=aad,
                        double_encryption=double_encryption,
                        family=family,
                        device=device,
                        instance=instance,
                        context_nr=context_nr,
                    )
                    chunk_data = data[offset : offset + self.GCM_CHUNK_SIZE]
                    encrypted.extend(bytes(backend.encrypt(data=chunk_data)))
                    if not hasattr(backend, "tag"):
                        raise SPSDKError(
                            "Active IPED backend does not expose GCM authentication tag."
                        )
                    encrypted.extend(int(backend.tag).to_bytes(8, "big"))
                    chunk_address += self.GCM_CHUNK_SIZE + self.ENCRYPTION_BLOCK_SIZE
                return bytes(encrypted)

            data = align_block(data, self.ENCRYPTION_BLOCK_SIZE)
            backend = self._create_backend(
                backend_cls=backend_cls,
                key=self.key,
                address=address,
                iv=iv,
                mode=self.mode,
                aad=aad,
                double_encryption=double_encryption,
                family=family,
                device=device,
                instance=instance,
                context_nr=context_nr,
            )
            encrypted = backend.encrypt(data=data)
        except (backend_error, OSError, TypeError, ValueError) as exc:
            raise SPSDKError(f"IPED data encryption failed: {exc}") from exc
        return bytes(encrypted)

    @classmethod
    def parse(
        cls,
        data: bytes,
        offset: int = 0,
        address_alignment: int = ADDRESS_ALIGNMENT,
        freeze: int = 0,
    ) -> Self:
        """Parse IPED context from the XSPI IPED register-image layout.

        :param data: Binary data containing the context record.
        :param offset: Offset of the context record in the binary data.
        :param address_alignment: Required region address alignment.
        :param freeze: Two-bit context freeze value from IPEDCTXCTRL.
        :raises SPSDKValueError: If the context record is invalid.
        :return: Parsed IPED context object.
        """
        if len(data) < offset + cls.SIZE:
            raise SPSDKValueError("IPED context data is too short.")
        iv0, iv1, start_register, end_address, aad0, aad1, reserved0, reserved1 = unpack_from(
            cls.FORMAT, data, offset
        )
        if reserved0 or reserved1:
            raise SPSDKValueError("IPED context reserved words must be zero.")
        return cls(
            start_address=start_register & ~0x3,
            end_address=end_address,
            mode=IpedMode.from_tag(start_register & 0x3),
            iv=[iv0, iv1],
            aad=[aad0, aad1],
            freeze=freeze,
            address_alignment=address_alignment,
        )

    @classmethod
    def load_from_config(
        cls,
        config: Config,
        address_alignment: int,
        default_iv: list[int] | None = None,
        default_key: bytes | None = None,
    ) -> Self:
        """Load IPED context from configuration.

        :param config: Context configuration.
        :param address_alignment: Required region address alignment.
        :param default_iv: Optional default IV words used when context IV is not configured.
        :param default_key: Optional default encryption key used when key is not configured.
        :return: IPED context object.
        """
        key = default_key if default_key is not None else _load_iped_key(config)
        iv = default_iv[:] if default_iv is not None else _words_from_config(config, "iv")
        return cls(
            start_address=config.get_int("start_address"),
            end_address=config.get_int("end_address"),
            mode=IpedMode.from_label(config.get_str("mode", IpedMode.CTR.label)),
            iv=iv,
            aad=_words_from_config(config, "aad"),
            nonce=(config.get_int("nonce") if config.get("nonce") is not None else None),
            region_id=(
                config.get_int("region_id") if config.get("region_id") is not None else None
            ),
            freeze=config.get_int("freeze", 0),
            address_alignment=address_alignment,
            key=key,
        )

    def get_config(self) -> dict[str, str | int]:
        """Get context configuration.

        :return: Configuration dictionary.
        """
        config: dict[str, str | int] = {
            "start_address": hex(self.start_address),
            "end_address": hex(self.end_address),
            "mode": self.mode.label,
            "iv": _words_to_hex(self.iv),
            "aad": _words_to_hex(self.aad),
            "freeze": self.freeze,
        }
        if self.region_id is not None:
            config["region_id"] = self.region_id
        if self.nonce is not None:
            config["nonce"] = hex(self.nonce)
        return config


class IpedV2(FeatureBaseClass):
    """IPED V2 table creator.

    The family database selects either a direct XSPI register image or a tagged ROM/Sentinel
    configuration blob. Register images contain 16 context slots followed by IPEDCTRL and
    IPEDCTXCTRL words; ROM blobs contain a header and one descriptor per protected region.

    The boolean control flags map to IPEDCTRL bits. The IP path is the memory controller
    command interface, while the AHB path is the memory-mapped XIP bus. Enable only the
    read/write flags that match the configured context modes and intended access path.
    """

    FEATURE = DatabaseManager.IPED

    CONTEXT_COUNT = 16
    RAW_TABLE_SIZE = CONTEXT_COUNT * IpedContext.SIZE + 0x10

    IPEDCTRL_CONFIG = 1 << 0
    IPEDCTRL_IPED_EN = 1 << 1
    IPEDCTRL_IPWR_EN = 1 << 2
    IPEDCTRL_AHBWR_EN = 1 << 3
    IPEDCTRL_AHBRD_EN = 1 << 4
    IPEDCTRL_IPGCMWR = 1 << 6
    IPEDCTRL_AHGCMWR = 1 << 7
    IPEDCTRL_AHBGCMRD = 1 << 8
    IPEDCTRL_IPED_PROTECT = 1 << 9
    IPEDCTRL_IPED_XEX_EN = 1 << 11
    IPEDCTRL_IPSXEXWE = 1 << 12
    IPEDCTRL_AHBXEXWE = 1 << 13
    IPEDCTRL_AHBXEXRE = 1 << 14

    def __init__(
        self,
        family: FamilyRevision,
        contexts: list[IpedContext] | None = None,
        table_size: int | None = None,
        control_word: int | None = None,
        context_control: list[int] | None = None,
        double_encryption: bool = False,
        enable: bool = True,
        ip_write_enable: bool = False,
        ahb_write_enable: bool = False,
        ahb_read_enable: bool = True,
        ip_gcm_write_enable: bool = False,
        ahb_gcm_write_enable: bool = False,
        ahb_gcm_read_enable: bool = False,
        protection: bool = False,
        xex_enable: bool = False,
        ip_xex_write_enable: bool = False,
        ahb_xex_write_enable: bool = False,
        ahb_xex_read_enable: bool = False,
        output_name: str = "iped_table",
        encrypted_name: str = "encrypted_blob",
        image_name: str = "iped_image",
        output_format: str = "bin",
        keyblob_address: int = 0,
        binaries: BinaryImage | None = None,
        data_alignment: int = IpedContext.ENCRYPTION_BLOCK_SIZE,
        device: str | None = None,
        instance: str | None = None,
        fw_version: int = 0,
    ) -> None:
        """Initialize IPED table.

        :param family: Target family.
        :param contexts: List of configured IPED contexts.
        :param table_size: Exported table size including padding.
        :param control_word: Raw IPEDCTRL word; if set, boolean control flags are ignored.
        :param context_control: Two raw IPEDCTXCTRL words.
        :param double_encryption: Enable the IPED double encryption/decryption path.
        :param enable: Enable the IPED CTR/GCM engine.
        :param ip_write_enable: Enable CTR encryption for IP-command writes.
        :param ahb_write_enable: Enable CTR encryption for memory-mapped AHB/XIP writes.
        :param ahb_read_enable: Enable CTR decryption for memory-mapped AHB/XIP reads.
        :param ip_gcm_write_enable: Enable GCM encryption for IP-command writes.
        :param ahb_gcm_write_enable: Enable GCM encryption for memory-mapped AHB/XIP writes.
        :param ahb_gcm_read_enable: Enable GCM decryption for memory-mapped AHB/XIP reads.
        :param protection: Enable hardware protection of the loaded IPED configuration.
        :param xex_enable: Enable the IPED XEX engine.
        :param ip_xex_write_enable: Enable XEX encryption for IP-command writes.
        :param ahb_xex_write_enable: Enable XEX encryption for memory-mapped AHB/XIP writes.
        :param ahb_xex_read_enable: Enable XEX decryption for memory-mapped AHB/XIP reads.
        :param output_name: Output file name without extension for CLI export.
        :param encrypted_name: Output file name without extension for encrypted data blobs.
        :param image_name: Output file name without extension for table and encrypted data image.
        :param output_format: Output file format.
        :param keyblob_address: Absolute address where the IPED table/keyblob is placed.
        :param binaries: Optional plain data blobs to encrypt.
        :param data_alignment: Alignment of encrypted data blobs in the output image.
        :param device: Optional family-specific encryption model device identifier.
        :param instance: Optional family-specific encryption model instance identifier.
        :param fw_version: Firmware version serialized into ROM configuration blobs.
        :raises SPSDKValueError: If the table configuration is invalid.
        """
        self.family = family
        if family.name not in [device.name for device in self.get_supported_families()]:
            raise SPSDKValueError(f"IPED is not supported for family {family}.")
        self.db = get_db(family)
        self.contexts = contexts[:] if contexts else []
        self.max_contexts = self.db.get_int(self.FEATURE, "max_contexts")
        self.min_contexts = self.db.get_int(self.FEATURE, "min_contexts")
        self.address_alignment = self.db.get_int(self.FEATURE, "address_alignment")
        self.table_size = value_to_int(
            table_size if table_size is not None else self.db.get_int(self.FEATURE, "table_size")
        )
        self.control_word = (
            value_to_int(control_word)
            if control_word is not None
            else self.compose_control_word(
                double_encryption=double_encryption,
                enable=enable,
                ip_write_enable=ip_write_enable,
                ahb_write_enable=ahb_write_enable,
                ahb_read_enable=ahb_read_enable,
                ip_gcm_write_enable=ip_gcm_write_enable,
                ahb_gcm_write_enable=ahb_gcm_write_enable,
                ahb_gcm_read_enable=ahb_gcm_read_enable,
                protection=protection,
                xex_enable=xex_enable,
                ip_xex_write_enable=ip_xex_write_enable,
                ahb_xex_write_enable=ahb_xex_write_enable,
                ahb_xex_read_enable=ahb_xex_read_enable,
            )
        )
        self.context_control = context_control[:] if context_control else [0, 0]
        self.output_name = output_name
        self.encrypted_name = encrypted_name
        self.image_name = image_name
        self.output_format = output_format
        self.keyblob_address = value_to_int(keyblob_address)
        self.binaries = binaries
        self.data_alignment = value_to_int(data_alignment)
        self.device = device.lower() if device else None
        self.instance = instance.lower() if instance else None
        self.fw_version = value_to_int(fw_version)
        self.validate()

    def __repr__(self) -> str:
        """Get text representation of IPED table.

        :return: Text representation.
        """
        return f"IPED table for {self.family}"

    def __str__(self) -> str:
        """Get text representation of IPED table.

        :return: Text representation.
        """
        return self.__repr__()

    @classmethod
    def compose_control_word(
        cls,
        double_encryption: bool,
        enable: bool,
        ip_write_enable: bool,
        ahb_write_enable: bool,
        ahb_read_enable: bool,
        ip_gcm_write_enable: bool,
        ahb_gcm_write_enable: bool,
        ahb_gcm_read_enable: bool,
        protection: bool,
        xex_enable: bool,
        ip_xex_write_enable: bool,
        ahb_xex_write_enable: bool,
        ahb_xex_read_enable: bool,
    ) -> int:
        """Compose IPEDCTRL register value from boolean flags.

        The caller is responsible for enabling flags consistent with the context mode.
        A decrypted-XIP CTR boot flow typically uses ``enable`` and ``ahb_read_enable``.

        :param double_encryption: Enable the IPED double encryption/decryption path.
        :param enable: Enable the IPED CTR/GCM engine.
        :param ip_write_enable: Enable CTR encryption for IP-command writes.
        :param ahb_write_enable: Enable CTR encryption for memory-mapped AHB/XIP writes.
        :param ahb_read_enable: Enable CTR decryption for memory-mapped AHB/XIP reads.
        :param ip_gcm_write_enable: Enable GCM encryption for IP-command writes.
        :param ahb_gcm_write_enable: Enable GCM encryption for memory-mapped AHB/XIP writes.
        :param ahb_gcm_read_enable: Enable GCM decryption for memory-mapped AHB/XIP reads.
        :param protection: Enable hardware protection of the loaded IPED configuration.
        :param xex_enable: Enable the IPED XEX engine.
        :param ip_xex_write_enable: Enable XEX encryption for IP-command writes.
        :param ahb_xex_write_enable: Enable XEX encryption for memory-mapped AHB/XIP writes.
        :param ahb_xex_read_enable: Enable XEX decryption for memory-mapped AHB/XIP reads.
        :return: IPEDCTRL register value.
        """
        flags = (
            (double_encryption, cls.IPEDCTRL_CONFIG),
            (enable, cls.IPEDCTRL_IPED_EN),
            (ip_write_enable, cls.IPEDCTRL_IPWR_EN),
            (ahb_write_enable, cls.IPEDCTRL_AHBWR_EN),
            (ahb_read_enable, cls.IPEDCTRL_AHBRD_EN),
            (ip_gcm_write_enable, cls.IPEDCTRL_IPGCMWR),
            (ahb_gcm_write_enable, cls.IPEDCTRL_AHGCMWR),
            (ahb_gcm_read_enable, cls.IPEDCTRL_AHBGCMRD),
            (protection, cls.IPEDCTRL_IPED_PROTECT),
            (xex_enable, cls.IPEDCTRL_IPED_XEX_EN),
            (ip_xex_write_enable, cls.IPEDCTRL_IPSXEXWE),
            (ahb_xex_write_enable, cls.IPEDCTRL_AHBXEXWE),
            (ahb_xex_read_enable, cls.IPEDCTRL_AHBXEXRE),
        )
        control_word = 0
        for enabled, bit in flags:
            if enabled:
                control_word |= bit
        return control_word

    def validate(self) -> None:
        """Validate IPED table configuration.

        :raises SPSDKValueError: If the table configuration is invalid.
        """
        if len(self.contexts) < self.min_contexts:
            raise SPSDKValueError(
                f"At least {self.min_contexts} IPED context(s) must be configured."
            )
        if len(self.contexts) > self.max_contexts or len(self.contexts) > self.CONTEXT_COUNT:
            raise SPSDKValueError(
                f"IPED supports at most {min(self.max_contexts, self.CONTEXT_COUNT)} contexts."
            )
        if len(self.context_control) != 2:
            raise SPSDKValueError("IPED context_control must contain exactly two words.")
        if self.table_size < self.raw_table_size:
            raise SPSDKValueError(
                f"IPED table_size must be at least {hex(self.raw_table_size)} bytes."
            )
        _check_u32(self.control_word, "control_word")
        _check_u32(self.fw_version, "fw_version")
        for index, word in enumerate(self.context_control):
            _check_u32(value_to_int(word), f"context_control[{index}]")
        for context in self.contexts:
            context.validate()
        if self.rom_config_blob:
            region_ids = [
                context.region_id if context.region_id is not None else index
                for index, context in enumerate(self.contexts)
            ]
            if len(set(region_ids)) != len(region_ids):
                raise SPSDKValueError("IPED ROM configuration region IDs must be unique.")
            for context in self.contexts:
                if context.nonce is None:
                    raise SPSDKValueError("IPED ROM configuration requires nonce in every context.")
                if context.mode == IpedMode.BYPASS:
                    raise SPSDKValueError("IPED ROM configuration does not support bypass regions.")
        _check_u32(self.keyblob_address, "keyblob_address")
        if self.data_alignment <= 0:
            raise SPSDKValueError("IPED data_alignment must be positive.")
        if self.binaries is not None:
            self.binaries.validate()

    @property
    def rom_config_blob(self) -> bool:
        """Return whether this family uses the ROM/Sentinel tagged configuration format."""
        return _uses_rom_config_blob(self.family)

    @property
    def raw_table_size(self) -> int:
        """Get the IPED table size without padding."""
        if self.rom_config_blob:
            return ROM_CONFIG_HEADER_SIZE + len(self.contexts) * ROM_CONFIG_REGION_SIZE
        return self.RAW_TABLE_SIZE

    def _context_control_words(self) -> list[int]:
        """Get IPEDCTXCTRL words with freeze fields applied.

        :return: Two IPEDCTXCTRL words.
        """
        words = self.context_control[:]
        for index, context in enumerate(self.contexts):
            words[0] |= context.freeze << (index * 2)
        return words

    def export(self) -> bytes:
        """Export IPED table into binary form.

        :return: Family-specific IPED table payload.
        """
        if self.rom_config_blob:
            data = pack(
                "<BHBI3xB4x",
                0,
                self.raw_table_size,
                ROM_CONFIG_HEADER_TAG,
                self.fw_version,
                len(self.contexts),
            )
            for index, context in enumerate(self.contexts):
                data += pack(
                    "<BHBBB2xIIQ8x",
                    0,
                    ROM_CONFIG_REGION_SIZE,
                    ROM_CONFIG_REGION_TAG,
                    context.region_id if context.region_id is not None else index,
                    context.mode.tag,
                    context.start_address,
                    context.end_address,
                    context.nonce if context.nonce is not None else 0,
                )
            return data

        data = b""
        for context in self.contexts:
            data += context.export()
        data += bytes(IpedContext.SIZE * (self.CONTEXT_COUNT - len(self.contexts)))
        data += pack("<IIII", self.control_word, 0, *self._context_control_words())
        return align_block(data, self.table_size, padding=0)

    @property
    def double_encryption(self) -> bool:
        """Return whether double encryption is enabled in IPEDCTRL.

        :return: True if double encryption is enabled.
        """
        return bool(self.control_word & self.IPEDCTRL_CONFIG)

    @property
    def interleaved_gcm_tags(self) -> bool:
        """Return whether output should interleave GCM authentication tags.

        Some device encryption flows use per-chunk tags in encrypted output data.

        :return: True if GCM encryption should append one tag per 32-byte chunk.
        """
        return self.db.get_bool(self.FEATURE, "interleaved_gcm_tags", False)

    def _get_context_for_range(self, start_address: int, data_size: int) -> tuple[int, IpedContext]:
        """Find IPED context that fully contains data range.

        :param start_address: Start address of the data.
        :param data_size: Data size in bytes.
        :raises SPSDKError: If no context fully contains the data range.
        :return: Tuple containing matching context index and context.
        """
        for index, context in enumerate(self.contexts):
            end_address = start_address + context.encrypted_data_size(data_size)
            if context.matches_range(start_address, end_address):
                return index, context
        raise SPSDKError(
            f"No IPED context covers data range starting at {hex(start_address)} "
            f"with plaintext length {hex(data_size)}."
        )

    def encrypt_image(self, image: bytes, base_addr: int) -> bytes:
        """Encrypt one data blob with the matching IPED context.

        :param image: Plain data blob.
        :param base_addr: Absolute address where the blob will be stored.
        :raises SPSDKError: If no context matches the blob range or backend encryption fails.
        :return: Encrypted data blob.
        """
        context_index, context = self._get_context_for_range(base_addr, len(image))
        logger.debug(
            f"Encrypting IPED data range {hex(base_addr)}:"
            f"{hex(base_addr + len(image))} using {context.mode.label} context."
        )
        return context.encrypt_data(
            data=image,
            address=base_addr,
            double_encryption=self.double_encryption,
            family=self.family,
            device=self.device,
            instance=self.instance,
            context_nr=context.region_id if context.region_id is not None else context_index,
            interleaved_gcm_tags=self.interleaved_gcm_tags,
        )

    def export_image(self) -> BinaryImage | None:
        """Export encrypted data blobs.

        :return: Encrypted binary image, or None if no data blobs are configured.
        """
        if self.binaries is None:
            return None
        binaries: BinaryImage = deepcopy(self.binaries)
        binaries.validate()
        for binary in binaries.sub_images:
            binary.alignment = IpedContext.ENCRYPTION_BLOCK_SIZE
            binary.binary = self.encrypt_image(
                binary.export(), binary.absolute_address + self.keyblob_address
            )
            binary.sub_images = []
        binaries.alignment = self.data_alignment
        binaries.validate()
        return binaries

    def binary_image(self, encrypted_image: BinaryImage | None = None) -> BinaryImage:
        """Get IPED table and encrypted blobs as a binary image.

        :param encrypted_image: Precomputed encrypted data blobs.
        :return: Complete IPED image.
        """
        iped_image = BinaryImage(self.image_name, offset=self.keyblob_address)
        keyblob = BinaryImage(
            name=self.output_name,
            size=self.table_size,
            offset=0,
            description=f"IPED table/keyblob for {self.family}",
            binary=self.export(),
            alignment=self.table_size,
        )
        iped_image.add_image(keyblob)
        if encrypted_image:
            iped_image.add_image(encrypted_image)
        return iped_image

    def post_export(self, output_path: str) -> list[str]:
        """Export IPED table and optional encrypted data files.

        :param output_path: Output directory.
        :return: List of generated files.
        """
        os.makedirs(output_path, exist_ok=True)
        extension = file_extension(self.output_format)
        output_file = os.path.join(output_path, f"{self.output_name}{extension}")
        table_data = self.export()
        image = BinaryImage(name=self.output_name, binary=table_data, size=len(table_data))
        image.save_binary_image(output_file, file_format=self.output_format)
        generated_files = [output_file]

        encrypted_image = self.export_image()
        if encrypted_image is None:
            return generated_files

        encrypted_file = os.path.join(output_path, f"{self.encrypted_name}{extension}")
        encrypted_export = deepcopy(encrypted_image)
        encrypted_export.offset = 0
        encrypted_export.save_binary_image(encrypted_file, file_format=self.output_format)
        generated_files.append(encrypted_file)

        full_image = self.binary_image(encrypted_image=encrypted_image)
        full_image.offset -= self.keyblob_address
        image_file = os.path.join(output_path, f"{self.image_name}{extension}")
        full_image.save_binary_image(image_file, file_format=self.output_format)
        generated_files.append(image_file)
        return generated_files

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision | None = None) -> Self:
        """Parse IPED table from bytes.

        :param data: Input binary data.
        :param family: Target family used for family-specific validation.
        :raises SPSDKValueError: If the table is invalid or family is not provided.
        :return: Parsed IPED table.
        """
        if family is None:
            raise SPSDKValueError("Family must be specified to parse IPED table.")
        if _uses_rom_config_blob(family):
            if len(data) < ROM_CONFIG_HEADER_SIZE:
                raise SPSDKValueError("IPED ROM configuration header is incomplete.")
            version, blob_size, tag, fw_version, region_count = unpack_from("<BHBI3xB4x", data)
            expected_size = ROM_CONFIG_HEADER_SIZE + region_count * ROM_CONFIG_REGION_SIZE
            if version != 0 or tag != ROM_CONFIG_HEADER_TAG:
                raise SPSDKValueError("Invalid IPED ROM configuration header.")
            if blob_size != expected_size:
                raise SPSDKValueError(
                    f"Invalid IPED ROM configuration size {hex(blob_size)}; "
                    f"expected {hex(expected_size)}."
                )
            if len(data) < blob_size:
                raise SPSDKValueError("IPED ROM configuration data is incomplete.")
            if any(data[blob_size:]):
                raise SPSDKValueError("IPED ROM configuration padding must contain only zeros.")

            address_alignment = get_db(family).get_int(cls.FEATURE, "address_alignment")
            contexts = []
            for index in range(region_count):
                offset = ROM_CONFIG_HEADER_SIZE + index * ROM_CONFIG_REGION_SIZE
                (
                    region_version,
                    region_size,
                    region_tag,
                    region_id,
                    mode,
                    start_address,
                    end_address,
                    nonce,
                ) = unpack_from("<BHBBB2xIIQ8x", data, offset)
                if (
                    region_version != 0
                    or region_size != ROM_CONFIG_REGION_SIZE
                    or region_tag != ROM_CONFIG_REGION_TAG
                ):
                    raise SPSDKValueError(
                        f"Invalid IPED ROM configuration region at index {index}."
                    )
                contexts.append(
                    IpedContext(
                        start_address=start_address,
                        end_address=end_address,
                        mode=IpedMode.from_tag(mode),
                        nonce=nonce,
                        region_id=region_id,
                        address_alignment=address_alignment,
                    )
                )
            return cls(
                family=family,
                contexts=contexts,
                table_size=len(data),
                device=_get_default_backend_device(family),
                fw_version=fw_version,
            )

        if len(data) < cls.RAW_TABLE_SIZE:
            raise SPSDKValueError(
                f"IPED table must be at least {hex(cls.RAW_TABLE_SIZE)} bytes long."
            )
        if any(data[cls.RAW_TABLE_SIZE :]):
            raise SPSDKValueError("IPED table padding must contain only zeros.")

        database = get_db(family)
        address_alignment = database.get_int(cls.FEATURE, "address_alignment")
        control_word, reserved, context_control0, context_control1 = unpack_from(
            "<IIII", data, IpedContext.SIZE * cls.CONTEXT_COUNT
        )
        if reserved:
            raise SPSDKValueError("IPED table reserved word must be zero.")

        last_used_context = -1
        for index in range(cls.CONTEXT_COUNT):
            offset = index * IpedContext.SIZE
            context_data = data[offset : offset + IpedContext.SIZE]
            if context_data != bytes(IpedContext.SIZE):
                last_used_context = index

        contexts = []
        for index in range(last_used_context + 1):
            offset = index * IpedContext.SIZE
            contexts.append(
                IpedContext.parse(
                    data=data,
                    offset=offset,
                    address_alignment=address_alignment,
                    freeze=(context_control0 >> (index * 2)) & IpedContext.FREEZE_MASK,
                )
            )

        return cls(
            family=family,
            contexts=contexts,
            table_size=len(data),
            control_word=control_word,
            context_control=[context_control0, context_control1],
        )

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get validation schemas for IPED configuration.

        :param family: Target family.
        :return: List of validation schemas.
        """
        database = get_db(family)
        schemas = get_schema_file(cls.FEATURE)
        sch_family = get_schema_file("general")["family"]
        update_validation_schema_family(
            sch_family["properties"], cls.get_supported_families(), family
        )
        sch_family["main_title"] = f"IPED table Configuration for {family}."
        base_address = cls.get_default_keyblob_address(family)
        try:
            mem_block = database.device.info.memory_map.get_memory(block_name="flexspi1_ns")
            base_address = mem_block.base_address
            schemas["iped"]["properties"]["contexts"]["items"]["properties"]["start_address"][
                "template_value"
            ] = hex(base_address + 0x1000)
            schemas["iped"]["properties"]["contexts"]["items"]["properties"]["end_address"][
                "template_value"
            ] = hex(base_address + 0x2000)
            schemas["iped"]["properties"]["data_blobs"]["items"]["properties"]["address"][
                "template_value"
            ] = hex(base_address + 0x1000)
        except SPSDKError:
            pass
        schemas["iped"]["properties"]["table_size"]["template_value"] = hex(
            database.get_int(cls.FEATURE, "table_size")
        )
        schemas["iped"]["properties"]["keyblob_address"]["template_value"] = hex(
            cls.get_default_keyblob_address(family)
        )
        if database.get_bool(cls.FEATURE, "show_derivation_template_fields", False):
            iped_properties = schemas["iped"]["properties"]
            for key in (
                "instance",
                "fw_version",
                "lifecycle",
                "cust_mk_sk",
                "srkh",
                "pqc_srkh",
            ):
                if key in iped_properties:
                    iped_properties[key]["skip_in_template"] = False
            iped_properties["instance"]["template_value"] = "xspi0"
            iped_properties["fw_version"]["template_value"] = "0x44332211"
            iped_properties["lifecycle"]["template_value"] = "oem_open"
            context_properties = iped_properties["contexts"]["items"]["properties"]
            if "nonce" in context_properties:
                context_properties["nonce"]["skip_in_template"] = False
            if database.get_bool(cls.FEATURE, "rom_config_blob", False):
                context_properties["region_id"]["skip_in_template"] = False
                for key in ("iv", "key", "aad", "freeze"):
                    context_properties[key]["skip_in_template"] = True
        return [sch_family, schemas["iped_output"], schemas["iped"]]

    @staticmethod
    def get_default_keyblob_address(family: FamilyRevision) -> int:
        """Get default absolute IPED table/keyblob address for a family.

        :param family: Target family.
        :return: Default absolute address.
        """
        try:
            return (
                get_db(family)
                .device.info.memory_map.get_memory(block_name="flexspi1_ns")
                .base_address
            )
        except SPSDKError:
            return 0

    def get_config(self, data_path: str = "./") -> Config:
        """Create IPED configuration.

        :param data_path: Path to store data files.
        :return: IPED configuration.
        """
        config = Config()
        config["family"] = self.family.name
        config["revision"] = self.family.revision
        config["output_folder"] = data_path
        config["output_name"] = self.output_name
        config["encrypted_name"] = self.encrypted_name
        config["image_name"] = self.image_name
        config["output_format"] = self.output_format
        config["keyblob_address"] = hex(self.keyblob_address)
        config["data_alignment"] = self.data_alignment
        if self.device:
            config["device"] = self.device
        if self.instance:
            config["instance"] = self.instance
        if self.rom_config_blob:
            config["fw_version"] = hex(self.fw_version)
        config["table_size"] = hex(self.table_size)
        config["control_word"] = hex(self.control_word)
        config["context_control"] = [hex(word) for word in self.context_control]
        config["contexts"] = [context.get_config() for context in self.contexts]
        return config

    @staticmethod
    def _get_context_defaults(
        context_config: Config,
        derivation: _KeyDerivationContext | None,
        rom_config_blob: bool,
    ) -> tuple[list[int] | None, bytes | None]:
        """Get derived IV and key defaults for one context.

        :param context_config: Context configuration.
        :param derivation: Prepared key derivation context.
        :param rom_config_blob: Whether the family uses the ROM configuration format.
        :raises SPSDKValueError: If a required nonce is missing or invalid.
        :return: Tuple with optional IV words and encryption key.
        """
        if derivation is None:
            return None, None
        if not rom_config_blob and context_config.get("iv") is not None:
            return None, derivation.mem_enc_key

        nonce = context_config.get("nonce")
        if nonce is None:
            raise SPSDKValueError("Key derivation requires 'nonce' in every derived context.")
        nonce_value = value_to_int(nonce)
        if nonce_value < 0 or nonce_value > 0xFFFFFFFFFFFFFFFF:
            raise SPSDKValueError("IPED context nonce must fit into 64 bits.")
        mode = IpedMode.from_label(context_config.get_str("mode", IpedMode.CTR.label))
        iv_enc_key = _derive_iped_key(
            derivation.master_key,
            0x65,
            derivation.instance,
            mode.tag,
            derivation.instance_map,
        )
        if context_config.get("key") is not None or context_config.get("iv") is not None:
            logger.warning(
                "Ignoring explicit IPED context key/IV because fuse-based derivation "
                "is configured."
            )
        return (
            _generate_iv(iv_enc_key, derivation.fw_version, nonce_value),
            derivation.mem_enc_key,
        )

    @classmethod
    def _load_contexts(
        cls,
        config: Config,
        address_alignment: int,
        derivation: _KeyDerivationContext | None,
        rom_config_blob: bool,
    ) -> list[IpedContext]:
        """Load all IPED contexts from configuration.

        :param config: IPED configuration.
        :param address_alignment: Required context address alignment.
        :param derivation: Prepared key derivation context.
        :param rom_config_blob: Whether the family uses the ROM configuration format.
        :return: Loaded IPED contexts.
        """
        contexts = []
        for context_config in config.get_list_of_configs("contexts"):
            default_iv, default_key = cls._get_context_defaults(
                context_config, derivation, rom_config_blob
            )
            contexts.append(
                IpedContext.load_from_config(
                    config=context_config,
                    address_alignment=address_alignment,
                    default_iv=default_iv,
                    default_key=default_key,
                )
            )
        return contexts

    @staticmethod
    def _load_binaries(
        config: Config, encrypted_name: str, keyblob_address: int
    ) -> BinaryImage | None:
        """Load optional plain data blobs into a binary image.

        :param config: IPED configuration.
        :param encrypted_name: Name of the encrypted data image.
        :param keyblob_address: Absolute IPED keyblob address.
        :return: Binary image with plain data blobs, if configured.
        """
        if "data_blobs" not in config:
            return None
        data_blobs = config.get_list_of_configs("data_blobs")
        if not data_blobs:
            return None

        start_address = min(data_blob.get_int("address") for data_blob in data_blobs)
        binaries = BinaryImage(
            encrypted_name,
            offset=start_address - keyblob_address,
            alignment=IpedContext.ENCRYPTION_BLOCK_SIZE,
        )
        for data_blob in data_blobs:
            data_file_name = data_blob.get_input_file_name("data")
            binary = BinaryImage.load_binary_image(
                path=data_file_name,
                name=os.path.basename(data_file_name),
                alignment=IpedContext.ENCRYPTION_BLOCK_SIZE,
                size=0,
            )
            address = data_blob.get_int("address", binary.absolute_address)
            expected_offset = address - keyblob_address - binaries.offset
            if binary.offset != expected_offset:
                logger.warning(
                    f"The data blob {data_file_name} has different offset {binary.offset}, "
                    f"than expected {expected_offset}."
                )
                binary.offset = expected_offset
            binaries.add_image(binary)
        return binaries

    @staticmethod
    def _resolve_output_names(config: Config) -> tuple[str, str, str, str]:
        """Resolve and validate IPED output names.

        :param config: IPED configuration.
        :raises SPSDKValueError: If explicit output names collide.
        :return: Table name, encrypted data name, combined image name, and output format.
        """
        output_name = config.get_str("output_name", "iped_table")
        output_format = config.get_str("output_format", "bin")
        encrypted_name = config.get_str("encrypted_name", "encrypted_blob")
        image_name = config.get_str("image_name", "iped_image")
        if image_name == encrypted_name:
            if "image_name" in config:
                raise SPSDKValueError("IPED image_name and encrypted_name must be different.")
            image_name = f"{image_name}_combined"
            logger.warning(
                f"IPED combined image name changed to '{image_name}' to avoid overwriting "
                f"encrypted output '{encrypted_name}'."
            )
        if output_name in (encrypted_name, image_name):
            raise SPSDKValueError(
                "IPED output_name, encrypted_name, and image_name must be different."
            )
        return output_name, encrypted_name, image_name, output_format

    @staticmethod
    def _resolve_backend_identifiers(
        config: Config,
        family: FamilyRevision,
        derivation: _KeyDerivationContext | None,
    ) -> tuple[str | None, str | None]:
        """Resolve device and instance identifiers for the encryption model.

        :param config: IPED configuration.
        :param family: Target family.
        :param derivation: Prepared key derivation context.
        :return: Device and instance identifiers.
        """
        if derivation:
            return derivation.device, derivation.instance
        uses_prince_v2_model = _uses_prince_v2_model(family)
        device = (
            config.get_str("device").lower()
            if "device" in config
            else (_get_default_backend_device(family) if uses_prince_v2_model else None)
        )
        instance = (
            config.get_str("instance").lower()
            if "instance" in config
            else (_get_default_backend_instance(family) if uses_prince_v2_model else None)
        )
        return device, instance

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load IPED table from configuration.

        :param config: IPED configuration.
        :return: IPED table object.
        """
        family = FamilyRevision.load_from_config(config)
        database = get_db(family)
        address_alignment = database.get_int(cls.FEATURE, "address_alignment")
        derivation = _load_key_derivation_context(config, family)
        rom_config_blob = _uses_rom_config_blob(family)
        output_name, encrypted_name, image_name, output_format = cls._resolve_output_names(config)
        contexts = cls._load_contexts(config, address_alignment, derivation, rom_config_blob)
        context_control = None
        if config.get("context_control") is not None:
            context_control = [value_to_int(word) for word in config.get_list("context_control")]

        keyblob_address = config.get_int("keyblob_address", cls.get_default_keyblob_address(family))
        binaries = cls._load_binaries(config, encrypted_name, keyblob_address)
        device, instance = cls._resolve_backend_identifiers(config, family, derivation)

        return cls(
            family=family,
            contexts=contexts,
            table_size=config.get_int("table_size", database.get_int(cls.FEATURE, "table_size")),
            control_word=(
                config.get_int("control_word") if config.get("control_word") is not None else None
            ),
            context_control=context_control,
            double_encryption=config.get_bool("double_encryption", False),
            enable=config.get_bool("enable", True),
            ip_write_enable=config.get_bool("ip_write_enable", False),
            ahb_write_enable=config.get_bool("ahb_write_enable", False),
            ahb_read_enable=config.get_bool("ahb_read_enable", True),
            ip_gcm_write_enable=config.get_bool("ip_gcm_write_enable", False),
            ahb_gcm_write_enable=config.get_bool("ahb_gcm_write_enable", False),
            ahb_gcm_read_enable=config.get_bool("ahb_gcm_read_enable", False),
            protection=config.get_bool("protection", False),
            xex_enable=config.get_bool("xex_enable", False),
            ip_xex_write_enable=config.get_bool("ip_xex_write_enable", False),
            ahb_xex_write_enable=config.get_bool("ahb_xex_write_enable", False),
            ahb_xex_read_enable=config.get_bool("ahb_xex_read_enable", False),
            output_name=output_name,
            encrypted_name=encrypted_name,
            image_name=image_name,
            output_format=output_format,
            keyblob_address=keyblob_address,
            binaries=binaries,
            data_alignment=config.get_int("data_alignment", IpedContext.ENCRYPTION_BLOCK_SIZE),
            device=device,
            instance=instance,
            fw_version=(derivation.fw_version if derivation else config.get_int("fw_version", 0)),
        )

    def verify(self) -> Verifier:
        """Verify IPED table.

        :return: Verification result.
        """
        ret = Verifier(f"IPED table for {self.family}")
        try:
            self.validate()
            ret.add_record("Configuration", VerifierResult.SUCCEEDED, "Valid")
        except SPSDKError as exc:
            ret.add_record("Configuration", VerifierResult.ERROR, str(exc))
        ret.add_record_range("Contexts", len(self.contexts), min_val=self.min_contexts)
        ret.add_record_range("Table size", self.table_size, min_val=self.raw_table_size)
        ret.add_record(
            "Data blobs", VerifierResult.SUCCEEDED, "Configured" if self.binaries else "None"
        )
        return ret
