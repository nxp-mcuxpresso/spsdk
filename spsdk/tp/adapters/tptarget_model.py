#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Trust provisioning - TP Target, SW model."""
import logging
import os
from enum import Enum
from typing import Any, Optional, Union

from spsdk.crypto.crypto_types import SPSDKEncoding
from spsdk.crypto.keys import EccCurve, PrivateKeyEcc, PublicKeyEcc
from spsdk.tp.adapters.model_utils import ModelConfig, get_models_configs
from spsdk.tp.adapters.utils import OEMKeyFlags, TPFlags
from spsdk.tp.data_container import (
    AuthenticationType,
    Container,
    DataDestinationEntry,
    DataEntry,
    PayloadType,
)
from spsdk.tp.exceptions import SPSDKTpError
from spsdk.tp.tp_intf import TpIntfDescription, TpTargetInterface
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.misc import load_binary, write_file

logger = logging.getLogger(__name__)


class TpTargetSwModelConfig(ModelConfig):
    """Configuration for TP Target Model."""

    def __init__(self, config_file: str) -> None:
        """Initialize configuration for TP Device model.

        :param config_file: Path to configuration file for the model
        """
        super().__init__(config_file=config_file)
        self.description = "TP Target Model"
        self.intf = TpTargetSwModel
        self.nxp_die_id_cert_path = self.config_data["nxp_die_id_cert_path"]
        self.nxp_die_id_puk_path = self.config_data["nxp_die_id_puk_path"]
        self.nxp_die_id_prk_path = self.config_data["nxp_die_id_prk_path"]
        self.nxp_prod_card_auth_puk_path = self.config_data["nxp_prod_card_auth_puk_path"]
        self.family = self.config_data["family"]

    def as_dict(self) -> dict[str, Any]:
        """Returns whole record as dictionary.

        :return: All variables of class in dictionary.
        """
        dictionary = {
            "name": self.name,
            "description": self.description,
            "id": self.id,
            "is_ready": self.is_ready,
        }
        return dictionary

    def get_id(self) -> str:
        """Returns the ID of the model interface."""
        return self.id


class TpTargetSwModel(TpTargetInterface):
    """Trust provisioning target adapter for software model."""

    NAME = "swmodel"

    class SettingsKey(str, Enum):
        """Keys used in `get_connected_devices` in `settings` dictionary."""

        ID = "id"

    @classmethod
    def get_connected_targets(cls, settings: Optional[dict] = None) -> list[TpIntfDescription]:
        """Get all connected TP Targets of this adapter.

        :param settings: Possible settings to determine the way to find connected device, defaults to None.
        :return: List of all founded TP targets.
        """
        if settings and "config_file" in settings:
            config_file = settings["config_file"]
            target_id = settings.get("id", None)
            return get_models_configs(
                config_file=config_file, model_id=target_id, config_class=TpTargetSwModelConfig
            )
        return []

    get_connected_interfaces = get_connected_targets

    def __init__(
        self, descriptor: TpIntfDescription, *args: Union[int, str], **kwargs: Union[int, str]
    ) -> None:
        """Initialize SW Model for Target.

        :param descriptor: Descriptor with parameters necessary for model creation.
        :raises SPSDKTpError: Descriptor doesn't contain required settings
        """
        super().__init__(descriptor=descriptor)
        if not descriptor.settings:
            raise SPSDKTpError("Target Model descriptor doesn't contain settings")
        self.config = TpTargetSwModelConfig(descriptor.settings["config_file"])
        self.oem_id_public_keys: list[tuple[int, PublicKeyEcc]] = []
        self.edh_private: Optional[PrivateKeyEcc] = None
        self.edh_public: Optional[PublicKeyEcc] = None
        self.tp_ses_kwk: Optional[bytes] = None
        self.tp_ses_enc: Optional[bytes] = None
        self.tp_ses_mac: Optional[bytes] = None

    def open(self) -> None:
        """Open the TP Target adapter."""

    def close(self) -> None:
        """Close the TP Target adapter."""

    def reset_device(self) -> None:
        """Reset the connected provisioned device."""
        self.config.is_ready = False

    def load_sb_file(self, sb_file: bytes, timeout: Optional[int] = None) -> None:
        """Load SB file into provisioned device.

        :param sb_file: SB file data to be loaded into provisioned device.
        :param timeout: Timeout of operation in milliseconds.
        """
        self.config.is_ready = True

    def prove_genuinity_challenge(self, challenge: bytes, timeout: Optional[int] = None) -> bytes:
        """Prove genuinity and get back the TP response to continue process of TP.

        :param challenge: Challenge data to start TP process.
        :param timeout: Timeout of operation in milliseconds.
        :return: Trust provisioning response for TP process.
        :raises SPSDKTpError: Problem with challenge container
        """
        logger.info("Generating TP Response")
        challenge_cont = Container.parse(challenge)
        challenge_entry = challenge_cont.get_entry(PayloadType.NXP_EPH_CHALLENGE_DATA_RND)
        if not challenge_entry:
            raise SPSDKTpError("Challenge container doesn't have a CHALLENGE entry")
        challenge = challenge_entry.payload
        key_flags = challenge_entry.header.entry_extra

        nxp_die_devattest_id_cert = self._generate_nxp_die_id_devattest_cert()
        self.edh_private, self.edh_public = self.config.generate_edh_keys()
        self.oem_id_public_keys = self._generate_oem_id_keys(
            key_count=key_flags, use_existing=self.config.reuse_oem_cert
        )
        dh_public_bytes = self.edh_public.export(SPSDKEncoding.NXP)

        tp_response = Container()
        tp_response.add_entry(
            DataEntry(
                payload=nxp_die_devattest_id_cert, payload_type=PayloadType.NXP_DIE_ID_AUTH_CERT.tag
            )
        )
        tp_response.add_entry(
            DataEntry(payload=challenge, payload_type=PayloadType.NXP_EPH_CHALLENGE_DATA_RND.tag)
        )
        tp_response.add_entry(
            DataEntry(payload=dh_public_bytes, payload_type=PayloadType.NXP_EPH_DEVICE_KA_PUK.tag)
        )
        for key_index, key in self.oem_id_public_keys:
            key_data = key.export(SPSDKEncoding.NXP)
            tp_response.add_entry(
                DataEntry(
                    payload=key_data,
                    payload_type=PayloadType.OEM_DIE_DEVATTEST_ID_PUK.tag,
                    extra=key_index,
                )
            )

        tp_response.add_auth_entry(
            auth_type=AuthenticationType.ECDSA_256,
            key=load_binary(
                self.config.get_abspath(self.config.config_data["nxp_die_id_prk_path"])
            ),
        )
        return tp_response.export()

    # pylint disable=too-many-locals
    def set_wrapped_data(self, wrapped_data: bytes, timeout: Optional[int] = None) -> None:
        """Provide wrapped data to provisioned device.

        :param wrapped_data: Wrapped data to finish TP process.
        :param timeout: Timeout of operation in milliseconds.
        :raises SPSDKTpError: Invalid data from TP device.
        """
        logger.info("Setting wrapped data")
        data_container = Container.parse(wrapped_data)
        is_valid = data_container.validate(
            load_binary(self.config.get_abspath(self.config.nxp_prod_card_auth_puk_path))
        )
        if not is_valid:
            raise SPSDKTpError("Invalid WRAP DATA signature")
        logger.info("WRAP DATA signature OK")
        if not self.edh_private:
            raise SPSDKTpError("Ephemeral Private Key is not set")
        remote_ka_puk = data_container.get_entry(payload_type=PayloadType.NXP_EPH_CARD_KA_PUK)
        self.tp_ses_kwk, self.tp_ses_enc, self.tp_ses_mac = self.config.generate_session_keys(
            remote_puk_data=remote_ka_puk.payload, edh_private=self.edh_private
        )
        certificates = data_container.get_entries(
            payload_type=PayloadType.OEM_DIE_DEVATTEST_ID_CERT
        )
        logger.debug("Saving certificates")
        for cert_entry in certificates:
            assert isinstance(cert_entry, DataDestinationEntry)
            address = cert_entry.destination_header.destination
            cert_id = OEMKeyFlags.get_key_name(cert_entry.header.entry_extra)
            cert_file = self.config.data[f"oem_id_{cert_id}_cert"]
            cert_path = self.config.get_abspath(cert_file)
            logger.debug(f"Certificate {cert_id} {cert_file} goes to {hex(address)}")
            write_file(cert_entry.payload, cert_path, mode="wb")
        logger.debug("Decrypting data")
        encrypted_entry = data_container.get_entry(payload_type=PayloadType.TP_WRAP_DATA_CIPHERTEXT)
        encrypted_data = encrypted_entry.payload
        iv_entry = data_container.get_entry(payload_type=PayloadType.TP_WRAP_DATA_IV)
        initialization_vector = iv_entry.payload
        tag_entry = data_container.get_entry(payload_type=PayloadType.TP_WRAP_DATA_TAG)
        tag = tag_entry.payload

        decrypted_wrap_data = self.config.decrypt_data(
            ciphertext=encrypted_data,
            key=self.tp_ses_enc,
            mac_key=self.tp_ses_mac,
            iv=initialization_vector,
            tag=tag,
        )
        if not decrypted_wrap_data:
            raise SPSDKTpError("Data decryption failed.")

        decrypted_container = Container.parse(decrypted_wrap_data)
        logger.debug("Setting WRAP DATA")
        if self.config.use_prov_data:
            prov_data_entry = decrypted_container.get_entry(
                payload_type=PayloadType.CUST_PROD_PROV_DATA
            )
            write_file(
                prov_data_entry.payload,
                self.config.get_abspath(self.config.data["prov_data_path"]),
                mode="wb",
            )
        else:
            cmpa_entry = decrypted_container.get_entry(
                payload_type=PayloadType.CUST_PROD_CMPA_DATA_SECRET
            )

            write_file(
                cmpa_entry.payload,
                self.config.get_abspath(self.config.data["cmpa_path"]),
                mode="wb",
            )
            cfpa_entry = decrypted_container.get_entry(
                payload_type=PayloadType.CUST_PROD_CFPA_DATA_SECRET
            )
            write_file(
                cfpa_entry.payload,
                self.config.get_abspath(self.config.data["cfpa_path"]),
                mode="wb",
            )
            sb_kek_entry = decrypted_container.get_entry(
                payload_type=PayloadType.CUST_PROD_SB_KEK_SK
            )
            wrapped_sb_kek = sb_kek_entry.payload
            sb_kek = self.config.unwrap_key(
                wrapping_key=self.tp_ses_kwk, wrapped_key=wrapped_sb_kek
            )
            write_file(sb_kek.hex(), self.config.get_abspath(self.config.data["sb_kek_path"]))
            user_kek_entry = decrypted_container.get_entry(
                payload_type=PayloadType.CUST_PROD_USER_KEK_SK
            )
            wrapped_user_kek = user_kek_entry.payload
            user_kek = self.config.unwrap_key(
                wrapping_key=self.tp_ses_kwk, wrapped_key=wrapped_user_kek
            )
            write_file(user_kek.hex(), self.config.get_abspath(self.config.data["user_kek_path"]))
        logger.info("Setting wrapped data completed.")

    def _generate_oem_id_keys(
        self, key_count: int, use_existing: bool = False
    ) -> list[tuple[int, PublicKeyEcc]]:
        logger.info("Generating OEM cert public keys")
        oem_id_public_keys: list[tuple[int, PublicKeyEcc]] = []

        key_flags = OEMKeyFlags.parse(flags=key_count, family=self.config.family)
        logger.info(f"Generating {key_count} OEM_ID keys")
        for key_id in range(key_flags.oem_key_count):
            public_key = self._generate_cache_public_key(key_id=key_id, use_existing=use_existing)
            oem_id_public_keys.append((key_id, public_key))

        if key_flags.use_ca_key:
            logger.info("Generating CA OEM key")
            public_key = self._generate_cache_public_key(key_id="ca", use_existing=use_existing)
            oem_id_public_keys.append((0x10, public_key))

        if key_flags.use_rtf_key:
            logger.info("Generating RTF OEM key")
            public_key = self._generate_cache_public_key(key_id="rtf", use_existing=use_existing)
            oem_id_public_keys.append((0x20, public_key))

        return oem_id_public_keys

    def _generate_cache_public_key(
        self, key_id: Union[int, str], use_existing: bool
    ) -> PublicKeyEcc:
        public_key_path = self.config.get_abspath(self.config.data[f"oem_id_{key_id}_public"])
        if use_existing and os.path.exists(public_key_path):
            public_key = PublicKeyEcc.load(self.config.get_abspath(public_key_path))
            return public_key

        private_key = PrivateKeyEcc.generate_key(curve_name=EccCurve.SECP256R1)
        public_key = private_key.get_public_key()
        private_key.save(self.config.get_abspath(self.config.data[f"oem_id_{key_id}_private"]))
        public_key.save(self.config.get_abspath(self.config.data[f"oem_id_{key_id}_public"]))
        return public_key

    def _generate_nxp_die_id_devattest_cert(self) -> bytes:
        logger.info("Generating DIE-ID devattest certificate")
        die_id_auth_prk_path = self.config.get_abspath(
            self.config.config_data["nxp_die_id_prk_path"]
        )
        if self.config.reuse_die_id_keys and os.path.exists(die_id_auth_prk_path):
            die_id_auth_prk = PrivateKeyEcc.load(die_id_auth_prk_path)
        else:
            die_id_auth_prk = PrivateKeyEcc.generate_key(curve_name=EccCurve.SECP256R1)
            die_id_auth_prk.save(die_id_auth_prk_path)
        die_id_auth_puk = die_id_auth_prk.get_public_key()

        devattest_cert = Container()
        devattest_cert.add_entry(
            DataEntry(
                payload_type=PayloadType.NXP_DIE_ID_AUTH_PUK.tag,
                payload=die_id_auth_puk.export(SPSDKEncoding.NXP),
            )
        )
        tp_flags = TPFlags.for_family(family=self.config.family)
        if tp_flags.die_id_cert_version == 1:
            die_id_attest_prk_path = self.config.get_abspath(
                self.config.config_data["nxp_die_id_attest_prk_path"]
            )
            if self.config.reuse_die_id_keys and os.path.exists(die_id_attest_prk_path):
                die_id_attest_prk = PrivateKeyEcc.load(die_id_attest_prk_path)
            else:
                die_id_attest_prk = PrivateKeyEcc.generate_key(curve_name=EccCurve.SECP256R1)
                die_id_attest_prk.save(die_id_attest_prk_path)
            die_id_attest_puk = die_id_attest_prk.get_public_key()

            devattest_cert.add_entry(
                DataEntry(
                    payload_type=PayloadType.NXP_DIE_ATTEST_AUTH_PUK.tag,
                    payload=die_id_attest_puk.export(SPSDKEncoding.NXP),
                )
            )

        devattest_cert.add_entry(
            DataEntry(
                payload_type=PayloadType.NXP_DIE_ECID_ID_UID.tag,
                payload=bytes.fromhex(self.config.config_data["ecid"]),
            )
        )
        devattest_cert.add_entry(
            DataEntry(
                payload_type=PayloadType.NXP_DIE_RFC4122v4_ID_UUID.tag,
                payload=bytes.fromhex(self.config.config_data["uuid"]),
            )
        )
        devattest_cert.add_auth_entry(
            auth_type=AuthenticationType.ECDSA_256,
            key=PrivateKeyEcc.load(
                self.config.get_abspath(self.config.config_data["nxp_prod_devattest_prk_path"])
            ).export(),
        )
        cert_data = devattest_cert.export()
        write_file(
            cert_data,
            self.config.get_abspath(self.config.config_data["nxp_die_id_cert_path"]),
            mode="wb",
        )
        return cert_data

    @staticmethod
    def get_help() -> str:
        """Return help for this interface, including settings description.

        :return: String with help.
        """
        return """The SWMODEL adapter emulates connection with TP target. Adapter settings:
        - config_file - path to yaml config single device or aggregate of multiple models
        - id - used if multiple models are provided via `config_file`"""

    @classmethod
    def get_validation_schemas(cls) -> list[dict[str, Any]]:
        """Return all additional validation schemas for interface.

        return: List of all additional validation schemas.
        """
        sch_cfg_file = get_schema_file(DatabaseManager.TP)

        return [sch_cfg_file["target_swmodel"]]

    def read_memory(self, address: int, length: int, memory_id: int = 0) -> bytes:
        """Read data from the target's memory (simulated by a file).

        :param address: Start address
        :param length: Number of bytes to read
        :param memory_id: Memory ID, defaults to 0
        :return: Data read from the target
        """
        memory_file = self.config.get_abspath(f"x_memory_{address:#010x}.bin")
        if os.path.isfile(memory_file):
            with open(memory_file, "rb") as f:
                return f.read(length)
        else:
            new_data = bytes(length)
            with open(memory_file, "wb") as f:
                f.write(new_data)
            return new_data

    def write_memory(self, address: int, data: bytes, memory_id: int = 0) -> None:
        """Write data to the target's memory  (simulated by a file).

        :param address: Start address
        :param data: Data to write
        :param memory_id: Memory ID, defaults to 0
        :raises NotImplementedError: This function is not implemented
        """
        memory_file = self.config.get_abspath(f"x_memory_{address:#010x}.bin")
        with open(memory_file, "wb") as f:
            f.write(data)

    def erase_memory(self, address: int, length: int, memory_id: int = 0) -> None:
        """Erase target's memory.

        :param address: Start address
        :param length: Number of bytes to erase
        :param memory_id: Memory ID, defaults to 0
        """
