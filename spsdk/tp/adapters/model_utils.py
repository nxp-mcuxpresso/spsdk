#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Common parts used by both Device and Target SW models."""

import logging
import os
from typing import Optional, Type, cast

import yaml

from spsdk.crypto.cmac import cmac, cmac_validate
from spsdk.crypto.keys import EccCurve, PrivateKeyEcc, PublicKeyEcc
from spsdk.crypto.symmetric import aes_ctr_decrypt, aes_ctr_encrypt, aes_key_unwrap, aes_key_wrap
from spsdk.tp.tp_intf import TpIntfDescription
from spsdk.utils.misc import Endianness, load_file, write_file

logger = logging.getLogger(__name__)


class ModelConfig(TpIntfDescription):
    """Basic SW Model Configuration."""

    def __init__(self, config_file: str) -> None:
        """Initialize Basic SW Model with a configuration file.

        :param config_file: Configuration file
        """
        with open(config_file, encoding="utf-8") as f:
            config_data: dict = yaml.safe_load(f)
        self.config_file: str = config_file
        self.config_data: dict = config_data
        self.workspace: str = config_data.get("workspace", os.path.dirname(config_file))
        self.data: dict = config_data.get("data", {})
        self.is_ready: bool = config_data.get("is_ready", False)
        self.id = config_data.get("id", "fake_id")
        self.reuse_die_id_keys: bool = config_data.get("reuse_die_id_keys", True)
        self.reuse_edh_keys: bool = config_data.get("reuse_edh_keys", False)
        self.reuse_oem_cert: bool = config_data.get("reuse_oem_cert", False)
        self.reuse_ses_keys: bool = config_data.get("reuse_ses_keys", False)
        self.do_wrapping: bool = config_data.get("do_wrapping", True)
        self.do_encryption: bool = config_data.get("do_encryption", True)
        self.use_prov_data: bool = config_data.get("use_prov_data", False)
        self.edh_public_path = self.config_data["edh_public_path"]
        self.edh_private_path = self.config_data["edh_private_path"]
        self.tp_ses_kwk_path = self.config_data["tp_ses_kwk_path"]
        self.tp_ses_enc_path = self.config_data["tp_ses_enc_path"]
        self.tp_ses_mac_path = self.config_data["tp_ses_mac_path"]
        self.enc_prov_const = bytes.fromhex(self.config_data["prov_enc_const"])
        self.kwk_prov_const = bytes.fromhex(self.config_data["prov_kwk_const"])
        self.mac_prov_const = bytes.fromhex(self.config_data["prov_mac_const"])

        self.exclude_fields = ["workspace", "config_file", "config_data", "exclude_fields", "intf"]
        super().__init__(
            name=config_data.get("name", self.workspace.split("/")[-1]),
            intf=None,
            description="Generic Model",
            settings={"config_file": self.config_file},
        )

    def save(self) -> None:
        """Stores back the configuration data loaded from config file."""
        with open(self.config_file, "w", encoding="utf-8") as f:
            self.config_data["data"] = self.data
            yaml.safe_dump(self.config_data, f, indent=2, sort_keys=True)

    def get_abspath(self, file: str) -> str:
        """Return absolute path to a config/data file."""
        if os.path.isabs(file):
            return file
        return f"{self.workspace}/{file}"

    def generate_edh_keys(self) -> tuple[PrivateKeyEcc, PublicKeyEcc]:
        """Generate Ephemeral Diffie-Hellman key pair."""
        logger.info("Generating Ephemeral Diffie-Hellman keys")
        if self.reuse_edh_keys:
            dh_private = PrivateKeyEcc.load(self.get_abspath(self.edh_private_path))
            dh_public = PublicKeyEcc.load(self.get_abspath(self.edh_public_path))
        else:
            dh_private = PrivateKeyEcc.generate_key(curve_name=EccCurve.SECP256R1)

            dh_public = dh_private.get_public_key()
            dh_private.save(self.get_abspath(self.edh_private_path))
            dh_public.save(self.get_abspath(self.edh_public_path))

        return dh_private, dh_public

    def generate_session_keys(
        self,
        remote_puk_data: bytes,
        edh_private: PrivateKeyEcc,
    ) -> tuple[bytes, bytes, bytes]:
        """Generate Key-Wrapping-Key and Encryption key.

        :param remote_puk_data: X and Y coordinates of remote ephemeral public key
        :param edh_private: Local ephemeral private key
        :return: key-wrapping-key, encryption key and mac key
        """
        logger.info("Generating session keys (KWK, ENC, CMAC)")
        if self.reuse_ses_keys:
            kwk_data = load_file(self.get_abspath(self.tp_ses_kwk_path)).strip()
            enc_data = load_file(self.get_abspath(self.tp_ses_enc_path)).strip()
            mac_data = load_file(self.get_abspath(self.tp_ses_mac_path)).strip()
            assert isinstance(kwk_data, str)
            assert isinstance(enc_data, str)
            assert isinstance(mac_data, str)
            tp_ses_kwk = bytes.fromhex(kwk_data)
            tp_ses_enc = bytes.fromhex(enc_data)
            tp_ses_mac = bytes.fromhex(mac_data)
        else:
            remote_puk = PublicKeyEcc.parse(remote_puk_data)
            shared_key = edh_private.exchange(remote_puk)
            tp_ses_kwk = derive_key(shared_key, self.kwk_prov_const)
            tp_ses_enc = derive_key(shared_key, self.enc_prov_const)
            tp_ses_mac = derive_key(shared_key, self.mac_prov_const)
            write_file(tp_ses_kwk.hex(), self.get_abspath(self.tp_ses_kwk_path))
            write_file(tp_ses_enc.hex(), self.get_abspath(self.tp_ses_enc_path))
            write_file(tp_ses_mac.hex(), self.get_abspath(self.tp_ses_mac_path))
        return tp_ses_kwk, tp_ses_enc, tp_ses_mac

    def wrap_key(self, wrapping_key: bytes, key_to_wrap: bytes) -> bytes:
        """Wrap AES key using RFC3394.

        :param wrapping_key: Key used for wrapping
        :param key_to_wrap: Key to wrap
        :return: Wrapped key
        """
        if not self.do_wrapping:
            return key_to_wrap
        return aes_key_wrap(kek=wrapping_key, key_to_wrap=key_to_wrap)

    def unwrap_key(self, wrapping_key: bytes, wrapped_key: bytes) -> bytes:
        """Un-wrap AES key using RFC3394.

        :param wrapping_key: Key used for wrapping
        :param wrapped_key: Wrapped key
        :return: Original un-wrapped key
        """
        if not self.do_wrapping:
            return wrapped_key
        return aes_key_unwrap(kek=wrapping_key, wrapped_key=wrapped_key)

    def encrypt_data(
        self,
        data: bytes,
        key: bytes,
        mac_key: Optional[bytes] = None,
        counter: Optional[int] = None,
    ) -> tuple[bytes, bytes, bytes]:
        """Encrypt data using AES in mode set by model configuration.

        :param data: Data to encrypt
        :param key: AES key for encryption
        :param mac_key: CMAC key when using CTR/CMAC mode, defaults to None
        :param counter: Counter for CTR mode, defaults to None
        :return: Initialization vector/Nonce; encrypted data; GCM tag/CMAC
        """
        assert isinstance(counter, int)
        assert isinstance(mac_key, bytes)
        nonce = self.generate_nonce(counter=counter)
        cipher_text = self.encrypt_data_ctr(data=data, key=key, nonce=nonce)
        tag = cmac(data=cipher_text, key=mac_key)
        return nonce, cipher_text, tag

    def decrypt_data(
        self, ciphertext: bytes, key: bytes, mac_key: bytes, iv: bytes, tag: bytes
    ) -> Optional[bytes]:
        """Decrypt data using AES in mode set by model configuration.

        :param ciphertext: Data to decrypt
        :param key: AES key for decryption
        :param mac_key: CMAC key when using CTR/CMAC mode
        :param iv: Initialization vector/Nonce
        :param tag: GCM tag/CMAC
        :return: Decrypted data
        """
        if not cmac_validate(data=ciphertext, signature=tag, key=mac_key):
            return None
        return self.decrypt_data_ctr(ciphertext=ciphertext, key=key, nonce=iv)

    def generate_nonce(self, counter: int) -> bytes:
        """Generate nonce for AES-CTR encryption.

        :param counter: Counter value
        :return: Nonce for AES-CTR encryption
        """
        # first 12 bytes (24 characters) serves as seed for counter
        mac_const_label = self.config_data["prov_mac_const"][:24]
        nonce = bytes.fromhex(mac_const_label)
        nonce += counter.to_bytes(length=4, byteorder=Endianness.BIG.value)
        return nonce

    def encrypt_data_ctr(self, data: bytes, key: bytes, nonce: bytes) -> bytes:
        """Encrypt data using AES in CTR mode.

        :param data: Data to encrypt
        :param key: AES key for encryption
        :param nonce: Nonce with counter for encryption
        :return: Encrypted data
        """
        logger.debug("Encrypting data in AES-CTR mode")
        if not self.do_encryption:
            logger.debug("Encryption is disabled")
            return data
        return aes_ctr_encrypt(key=key, plain_data=data, nonce=nonce)

    def decrypt_data_ctr(self, ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
        """Decrypt data using AES in CTR mode.

        :param ciphertext: Encrypted data
        :param key: AES key used for decryption
        :param nonce: Nonce with counter
        :return: Decrypted data
        """
        logger.debug("Decrypting data in AES-CTR mode")
        if not self.do_encryption:
            logger.debug("Encryption is disabled")
            return ciphertext
        return aes_ctr_decrypt(key=key, encrypted_data=ciphertext, nonce=nonce)


def get_models_configs(
    config_file: str, model_id: str, config_class: Type[ModelConfig]
) -> list[TpIntfDescription]:
    """Return configuration files for SW Model derivatives.

    :param config_file: Root configuration file
    :param model_id: Model instance ID
    :param config_class: Class of derived configuration
    :return: List of descriptors
    """
    with open(config_file, encoding="utf-8") as f:
        config_data: list = yaml.safe_load(f)
    configs = []
    for device_config in config_data:
        if not os.path.isabs(device_config):
            # turn path to device config file into absolute path
            device_config = os.path.join(os.path.dirname(config_file), device_config)
            device_config = device_config.replace("\\", "/")
        device = config_class(config_file=device_config)
        if not model_id or model_id == device.id:
            configs.append(cast(TpIntfDescription, device))
    return configs


def derive_key(key: bytes, derivation_data: bytes) -> bytes:
    """Derive AES key using `derivation_data` as salt."""
    new_key = cmac(data=derivation_data, key=key)
    return new_key
