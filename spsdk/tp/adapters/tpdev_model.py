#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Trust provisioning - TP Device, SW model."""
import logging
import os
import shutil
from enum import Enum
from typing import Any, Optional

from spsdk.crypto.certificate import Certificate, generate_name
from spsdk.crypto.crypto_types import SPSDKEncoding, SPSDKNameOID
from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.crypto.keys import PrivateKeyEcc, PublicKeyEcc
from spsdk.crypto.rng import random_bytes
from spsdk.crypto.utils import extract_public_key
from spsdk.tp.adapters.model_utils import ModelConfig, get_models_configs
from spsdk.tp.adapters.utils import OEMCertInfo, OEMKeyFlags, TPFlags, sanitize_common_name
from spsdk.tp.data_container import (
    AuthenticationType,
    Container,
    DataDestinationEntry,
    DataEntry,
    DestinationType,
    PayloadType,
)
from spsdk.tp.exceptions import SPSDKTpError
from spsdk.tp.tp_intf import TpDevInterface, TpIntfDescription
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.misc import Endianness, find_file, load_binary, load_file, write_file

logger = logging.getLogger(__name__)


class TpDevSwModelConfig(ModelConfig):
    """Configuration for TP Device Model."""

    def __init__(self, config_file: str) -> None:
        """Initialize configuration for TP Device model.

        :param config_file: Path to configuration file for the model
        """
        super().__init__(config_file=config_file)
        self.description = "TP Device Model"
        self.intf = TpDevSwModel
        self.family = self.data["family"]

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


class TpDevSwModel(TpDevInterface):
    """Trust provisioning device adapter for software model."""

    NAME = "swmodel"

    class SettingsKey(str, Enum):
        """Keys used in `get_connected_devices` in `settings` dictionary."""

        ID = "id"

    @classmethod
    def get_connected_devices(cls, settings: Optional[dict] = None) -> list[TpIntfDescription]:
        """Get all connected TP devices of this adapter.

        :param settings: Possible settings to determine the way to find connected device, defaults to None.
        :return: List of all founded TP devices.
        """
        if settings and "config_file" in settings:
            config_file = settings["config_file"]
            model_id = settings.get("id", "")
            return get_models_configs(
                config_file=config_file, model_id=model_id, config_class=TpDevSwModelConfig
            )
        return []

    get_connected_interfaces = get_connected_devices

    def __init__(self, descriptor: TpIntfDescription) -> None:
        """Initialize TP Device Model.

        :param descriptor: Descriptor with parameters necessary for model creation.
        :raises SPSDKTpError: Descriptor doesn't contain required settings
        """
        super().__init__(descriptor=descriptor)
        if not descriptor.settings:
            raise SPSDKTpError("Device Model descriptor doesn't contain settings")
        self.config = TpDevSwModelConfig(descriptor.settings["config_file"])
        self.challenge = bytes()
        self.oem_certificates: Optional[list[tuple[bytes, int]]] = None
        self.edh_private: Optional[PrivateKeyEcc] = None
        self.edh_public: Optional[PublicKeyEcc] = None
        self.tp_ses_kwk: Optional[bytes] = None
        self.tp_ses_enc: Optional[bytes] = None
        self.tp_ses_mac: Optional[bytes] = None
        self.cert_serial_num = b"\x11" * 20
        self.coordinate_len = 32
        self.nxp_die_id_data = bytes()

    @property
    def production_quota(self) -> int:
        """Production quota/limit."""
        return self.config.data["production_quota"]

    @production_quota.setter
    def production_quota(self, value: int) -> None:
        """Production quota/limit."""
        assert isinstance(value, int)
        self.config.data["production_quota"] = value

    @property
    def production_counter(self) -> int:
        """Production quota/limit."""
        return self.config.data["production_counter"]

    @production_counter.setter
    def production_counter(self, value: int) -> None:
        """Production quota/limit."""
        assert isinstance(value, int)
        self.config.data["production_counter"] = value

    @property
    def production_remainder(self) -> int:
        """Remanding production attempts."""
        return self.production_quota - self.production_counter

    @property
    def running_hash(self) -> bytes:
        """Running hash for chaining audit log records."""
        return self.config.data["running_hash"]

    @running_hash.setter
    def running_hash(self, value: bytes) -> None:
        """Running hash for chaining audit log records."""
        assert isinstance(value, bytes)
        self.config.data["running_hash"] = value

    def open(self) -> None:
        """Open the TP device adapter."""

    def close(self) -> None:
        """Close the TP device adapter."""

    def get_prov_counter(self) -> int:
        """Get actual provisioning counter."""
        return self.production_counter

    def get_prov_remainder(self) -> int:
        """Get the number of remaining provisioning attempts."""
        return self.production_remainder

    def get_challenge(self, timeout: Optional[int] = None) -> bytes:
        """Request challenge from the TP device.

        :raises SPSDKTpError: Model not fit for generating challenge
        :param timeout: Timeout of operation in milliseconds.
        :return: Serialized DataContainer with challenge record
        """
        logger.info("Generating challenge")
        if not self.config.is_ready:
            raise SPSDKTpError("Invalid TP device")
        self.challenge = random_bytes(16)
        logger.debug(f"Challenge vector: {self.challenge.hex()}")
        container = Container()
        container.add_entry(
            DataEntry(
                payload=self.challenge,
                payload_type=PayloadType.NXP_EPH_CHALLENGE_DATA_RND.tag,
                extra=self.config.data["oem_key_flags"],
            )
        )
        logger.debug(f"Challenge container:\n{container}")
        return container.export()

    def authenticate_response(self, tp_data: bytes, timeout: Optional[int] = None) -> bytes:
        """Request TP device for TP authentication of connected MCU.

        :param tp_data: TP response of connected MCU.
        :param timeout: Timeout of operation in milliseconds.
        :return: Wrapped data after TP response processing.
        :raises SPSDKTpError: The configuration is not ready.
        """
        if not self.config.is_ready:
            raise SPSDKTpError("Invalid TP device")
        logger.info("Authenticating TP response")
        tp_response = Container.parse(tp_data)
        challenge = tp_response.get_entry(PayloadType.NXP_EPH_CHALLENGE_DATA_RND)
        if challenge.payload != self.challenge:
            raise SPSDKTpError("Invalid challenge vector received")
        logger.info("Challenge vector OK")

        nxp_die_id_cert = tp_response.get_entry(payload_type=PayloadType.NXP_DIE_ID_AUTH_CERT)
        self.nxp_die_id_data = nxp_die_id_cert.payload
        verification_key = self._get_verification_key(nxp_die_id_cert)
        is_valid = tp_response.validate(verification_key.export(SPSDKEncoding.DER))
        if not is_valid:
            raise SPSDKTpError("Invalid TP Response signature")
        logger.info("TP response signature OK")

        if self.production_remainder < 1:
            raise SPSDKTpError("Production quota exhausted, this card is useless")
        self.production_counter += 1

        oem_die_id_puks = tp_response.get_entries(payload_type=PayloadType.OEM_DIE_DEVATTEST_ID_PUK)
        self.oem_certificates = self._generate_oem_certificates(oem_die_id_puks)

        self.edh_private, self.edh_public = self.config.generate_edh_keys()
        remote_ka_puk = tp_response.get_entry(payload_type=PayloadType.NXP_EPH_DEVICE_KA_PUK)
        self.tp_ses_kwk, self.tp_ses_enc, self.tp_ses_mac = self.config.generate_session_keys(
            remote_puk_data=remote_ka_puk.payload, edh_private=self.edh_private
        )

        plain_data_cont = self._generate_plain_data(wrapping_key=self.tp_ses_kwk)
        plaintext = plain_data_cont.export()

        initialization_vector, encrypted_data, tag = self.config.encrypt_data(
            data=plaintext,
            key=self.tp_ses_enc,
            mac_key=self.tp_ses_mac,
            counter=self.production_quota,
        )

        new_running_hash = self._update_running_hash()
        log_signature = self._sign_log_hash(new_running_hash)

        prov_data_container = Container()
        prov_data_container.add_entry(
            DataEntry(
                payload=self.edh_public.export(SPSDKEncoding.NXP),
                payload_type=PayloadType.NXP_EPH_CARD_KA_PUK.tag,
            )
        )
        prov_data_container.add_entry(
            DataEntry(payload=initialization_vector, payload_type=PayloadType.TP_WRAP_DATA_IV.tag)
        )
        prov_data_container.add_entry(
            DataEntry(payload=tag, payload_type=PayloadType.TP_WRAP_DATA_TAG.tag)
        )
        prov_data_container.add_entry(
            DataEntry(payload=encrypted_data, payload_type=PayloadType.TP_WRAP_DATA_CIPHERTEXT.tag)
        )

        prov_data_container.add_entry(
            DataEntry(
                payload=self.nxp_die_id_data, payload_type=PayloadType.NXP_DIE_ID_AUTH_CERT.tag
            )
        )

        for cert, cert_id in self.oem_certificates:
            prov_data_container.add_entry(
                DataDestinationEntry(
                    payload=cert,
                    payload_type=PayloadType.OEM_DIE_DEVATTEST_ID_CERT.tag,
                    extra=cert_id,
                    destination=self.config.data[
                        f"oem_cert_{OEMKeyFlags.get_key_name(cert_id)}_addr"
                    ],
                    destination_type=DestinationType.MEMORY,
                )
            )

        prov_data_container.add_entry(
            DataEntry(
                payload=self.production_counter.to_bytes(length=4, byteorder=Endianness.BIG.value),
                payload_type=PayloadType.OEM_PROD_COUNTER.tag,
            )
        )

        prov_data_container.add_entry(
            DataEntry(payload=self.running_hash, payload_type=PayloadType.OEM_TP_LOG_HASH.tag)
        )

        prov_data_container.add_entry(
            DataEntry(payload=log_signature, payload_type=PayloadType.OEM_TP_LOG_SIGN.tag)
        )

        prov_data_container.add_auth_entry(
            auth_type=AuthenticationType.ECDSA_256,
            key=load_binary(self.config.get_abspath(self.config.data["nxp_prod_card_prk_path"])),
        )

        logger.debug(f"SET_WRAP_DATA container:\n{prov_data_container}")

        logger.info(f"New production counter: {self.production_counter}")
        logger.info(f"Remaining attempts:     {self.production_remainder}")

        self.running_hash = new_running_hash
        logger.debug(f"New running hash: {self.running_hash.hex()}")

        self.config.save()

        return prov_data_container.export()

    def _update_running_hash(self) -> bytes:
        data_to_hash = self.nxp_die_id_data
        if self.oem_certificates:
            for cert_data, _ in self.oem_certificates:
                data_to_hash += cert_data
        data_to_hash += self.production_counter.to_bytes(length=4, byteorder=Endianness.BIG.value)
        data_to_hash += self.running_hash
        new_hash = get_hash(data_to_hash)
        return new_hash

    def _sign_log_hash(self, log_hash: bytes) -> bytes:
        log_key = PrivateKeyEcc.load(self.config.get_abspath(self.config.data["oem_log_prk_path"]))
        signature = log_key.sign(log_hash, der_format=True)
        return signature

    def _get_verification_key(self, nxp_die_id_cert: DataEntry) -> PublicKeyEcc:
        cert_cont = Container.parse(nxp_die_id_cert.payload)
        verification_entry = PayloadType.NXP_DIE_ID_AUTH_PUK
        key_entry = cert_cont.get_entry(verification_entry)
        key_material = key_entry.payload
        key = PublicKeyEcc.parse(key_material)
        return key

    def _generate_oem_certificates(
        self, oem_die_id_puks: list[DataEntry]
    ) -> list[tuple[bytes, int]]:
        logger.info("Generating OEM certificates")
        oem_certificates = []
        new_uuid = random_bytes(16)

        for oem_die_id_puk in oem_die_id_puks:
            puk_material = oem_die_id_puk.payload
            key_index = oem_die_id_puk.header.entry_extra
            issuer_private_key = PrivateKeyEcc.load(
                self.config.get_abspath(self.config.data["oem_id_prk_path"])
            )

            template_data = load_binary(
                self.config.get_abspath(self.config.data["oem_id_template"])
            )
            template_data = bytearray(template_data)

            # replace public key
            cert_meta = self.config.data["oem_id_meta"]
            pub_x_slice = slice(cert_meta["pub_x"], cert_meta["pub_x"] + self.coordinate_len)
            template_data[pub_x_slice] = puk_material[: self.coordinate_len]
            pub_y_slice = slice(cert_meta["pub_y"], cert_meta["pub_y"] + self.coordinate_len)
            template_data[pub_y_slice] = puk_material[self.coordinate_len :]

            # update subject common_name
            scn_slice = slice(
                cert_meta["scn_offset"], cert_meta["scn_offset"] + cert_meta["scn_length"]
            )

            key_index_bytes = key_index.to_bytes(length=1, byteorder=Endianness.BIG.value)
            template_data[scn_slice] = (
                bytes(new_uuid.hex(), encoding="ascii")
                + b"-"
                + bytes(key_index_bytes.hex(), encoding="ascii")
            )

            # replace signature
            tbs_slice = slice(
                cert_meta["tbs_offset"], cert_meta["tbs_offset"] + cert_meta["tbs_length"]
            )
            new_signature = issuer_private_key.sign(
                data=template_data[tbs_slice], algorithm=EnumHashAlgorithm.SHA256, der_format=True
            )

            data = (
                template_data[cert_meta["tbs_offset"] : cert_meta["sig_offset"] - 3]
                + b"\x03"
                + (len(new_signature) + 1).to_bytes(length=1, byteorder=Endianness.BIG.value)
                + b"\x00"
                + new_signature
            )
            header = b"\x30\x82" + len(data).to_bytes(length=2, byteorder=Endianness.BIG.value)

            new_cert_data = header + data
            oem_certificates.append((bytes(new_cert_data), key_index))
            write_file(
                new_cert_data,
                self.config.get_abspath(
                    self.config.data[f"oem_cert_{OEMKeyFlags.get_key_name(key_index)}_path"]
                ),
                mode="wb",
            )

        return oem_certificates

    def _generate_plain_data(self, wrapping_key: bytes) -> Container:
        logger.info("Generating plain WRAP DATA")
        data_cont = Container()
        if self.config.use_prov_data:
            data_cont.add_entry(
                DataEntry(
                    payload=load_binary(
                        self.config.get_abspath(self.config.data["prov_data_path"])
                    ),
                    payload_type=PayloadType.CUST_PROD_PROV_DATA.tag,
                )
            )
            return data_cont

        sb_kek_data = load_file(self.config.get_abspath(self.config.data["sb_kek_path"])).strip()
        assert isinstance(sb_kek_data, str)
        sb_kek = bytes.fromhex(sb_kek_data)
        wrapped_sb_kek = self.config.wrap_key(wrapping_key=wrapping_key, key_to_wrap=sb_kek)
        user_kek_data = load_file(
            self.config.get_abspath(self.config.data["user_kek_path"])
        ).strip()
        assert isinstance(user_kek_data, str)
        user_kek = bytes.fromhex(user_kek_data)
        wrapped_user_kek = self.config.wrap_key(wrapping_key=wrapping_key, key_to_wrap=user_kek)
        data_cont.add_entry(
            DataEntry(
                payload=wrapped_sb_kek,
                payload_type=PayloadType.CUST_PROD_SB_KEK_SK.tag,
            )
        )
        data_cont.add_entry(
            DataEntry(
                payload=wrapped_user_kek,
                payload_type=PayloadType.CUST_PROD_USER_KEK_SK.tag,
            )
        )
        data_cont.add_entry(
            DataEntry(
                payload=load_binary(self.config.get_abspath(self.config.data["cfpa_path"])),
                payload_type=PayloadType.CUST_PROD_CFPA_DATA_SECRET.tag,
            )
        )
        data_cont.add_entry(
            DataEntry(
                payload=load_binary(self.config.get_abspath(self.config.data["cmpa_path"])),
                payload_type=PayloadType.CUST_PROD_CMPA_DATA_SECRET.tag,
            )
        )
        return data_cont

    @staticmethod
    def get_help() -> str:
        """Return help for this interface, including settings description.

        :return: String with help.
        """
        return """The SWMODEL adapter emulates connection with TP device. Adapter settings:
        - config_file - path to yaml config single device or aggregate of multiple models
        - id - used if multiple models are provided via `config_file`"""

    @classmethod
    def get_validation_schemas(cls) -> list[dict[str, Any]]:
        """Return all additional validation schemas for interface.

        return: List of all additional validation schemas.
        """
        sch_cfg_file = get_schema_file(DatabaseManager.TP)

        return [sch_cfg_file["device_swmodel"]]

    def prepare(self) -> None:
        """Prepare TP device ."""
        self.config.is_ready = True

    def upload(self, config_data: dict, config_dir: Optional[str] = None) -> None:
        """Simulate uploading required Provisioning data to TP device."""
        if not self.config.is_ready:
            raise SPSDKTpError("Invalid TP device")
        logger.info("Uploading files")
        self.config.data["family"] = config_data["family"]
        # mandatory files

        # family specific file
        data_files = (
            ["prov_data_path"]
            if self.config.use_prov_data
            else ["cmpa_path", "cfpa_path", "sb_kek_path", "user_kek_path"]
        )
        # mandatory files
        data_files += ["oem_log_prk_path", "nxp_global_attest_puk_path", "nxp_prod_cert_path"]

        for file_key in data_files:
            self.upload_file(file_key, config_data, config_dir)  # type: ignore

        if not self.config.use_prov_data:
            self._reverse_kek_files(["sb_kek_path", "user_kek_path"])

        self._validate_prod_certificate(
            cert_path=self.config.get_abspath(self.config.data["nxp_prod_cert_path"]),
            puk_path=self.config.get_abspath(self.config.data["nxp_global_attest_puk_path"]),
        )

        self.production_quota = config_data.get("production_quota", 0)
        self.production_counter = 0
        self.running_hash = bytes(32)

        oem_cert_info = OEMCertInfo.from_config(config_data=config_data)

        self.config.data["oem_id_count"] = oem_cert_info.oem_cert_count
        self.config.data["oem_cert_ca_addr"] = oem_cert_info.ca_cert_address
        self.config.data["oem_cert_rtf_addr"] = oem_cert_info.rtf_cert_address

        tp_flags = TPFlags.for_family(family=config_data["family"])
        self.config.data["tp_flags"] = tp_flags.export(as_bytes=False)

        oem_key_flags = oem_cert_info.flags
        self.config.data["oem_key_flags"] = oem_key_flags.export(as_bytes=False)
        if oem_key_flags.use_oem_keys:
            self.config.data["oem_id_config"] = config_data["oem_id_config"]
            self.upload_file("oem_id_prk_path", config_data, config_dir)  # type: ignore

            for i in range(self.config.data["oem_id_count"]):
                self.config.data[f"oem_cert_{i}_addr"] = config_data["oem_id_addresses"][i]

            self._create_oem_id_template()

        self.config.save()

    def seal(self) -> None:
        """Seal the provisioning device."""

    def _create_oem_id_template(self) -> None:
        logger.info("Creating OEM ID template")
        cert_config: dict = self.config.data["oem_id_config"]
        sanitize_common_name(cert_config["subject"])
        issuer = generate_name(cert_config["issuer"])
        subject = generate_name(cert_config["subject"])
        private_key = PrivateKeyEcc.load(
            self.config.get_abspath(self.config.data["oem_id_prk_path"])
        )
        public_key = private_key.get_public_key()
        cert = Certificate.generate_certificate(
            subject=subject,
            issuer=issuer,
            subject_public_key=public_key,
            issuer_private_key=private_key,
            serial_number=cert_config.get("serial_number"),
            duration=cert_config["duration"],
        )
        cert_raw = cert.export(SPSDKEncoding.DER)
        cert_path = self.config.get_abspath(self.config.data["oem_id_template"])
        logger.debug(f"Saving cert template to '{cert_path}'")
        cert.save(cert_path, SPSDKEncoding.DER)

        logger.debug("Extracting info about the certificate template")
        tbs = cert_raw.find(cert.tbs_certificate_bytes)

        scn = cert.subject.get_attributes_for_oid(SPSDKNameOID.COMMON_NAME)[0].value
        if isinstance(scn, str):
            scn = bytes(scn, encoding="ascii")

        scn_length = 32 + 1 + 2
        scn_offset = cert_raw.find(scn) + len(scn) - scn_length

        pub_x_start = cert_raw.find(
            public_key.public_numbers.x.to_bytes(length=32, byteorder=Endianness.BIG.value)
        )
        pub_y_start = cert_raw.find(
            public_key.public_numbers.y.to_bytes(length=32, byteorder=Endianness.BIG.value)
        )

        sig_offset = cert_raw.find(cert.signature)
        sig_length = len(cert.signature)

        self.config.data["oem_id_meta"] = {
            "scn_offset": scn_offset,
            "scn_length": scn_length,
            "coord_len": self.coordinate_len,
            "pub_x": pub_x_start,
            "pub_y": pub_y_start,
            "sig_offset": sig_offset,
            "sig_length": sig_length,
            "tbs_offset": tbs,
            "tbs_length": len(cert.tbs_certificate_bytes),
            "total": len(cert_raw),
        }

    def upload_file(self, file_key: str, config_data: dict, config_dir: str) -> None:
        """Upload a user file into model's workspace."""
        file_path = config_data.get(file_key) or ""
        if not file_path:
            raise SPSDKTpError(f"File {file_key} ({file_path or 'none'}) not found")
        dest_path = self.config.data[file_key]
        self._upload_file(file_path, config_dir, dest_path)

    def _upload_file(self, file_path: str, config_dir: str, dest_file_path: str) -> None:
        full_path = find_file(file_path, search_paths=[config_dir])
        dest_full_path = os.path.join(self.config.workspace, dest_file_path)
        logger.debug(f"Copying '{full_path}' to '{dest_full_path}'")
        shutil.copy(full_path, dest_full_path)

    def _validate_prod_certificate(self, cert_path: str, puk_path: str) -> None:
        logger.info("Validating NXP_PROD certificate")
        try:
            cert = Certificate.load(cert_path)
            puk = extract_public_key(puk_path)
            assert isinstance(puk, PublicKeyEcc)
            if not puk.verify_signature(
                signature=cert.signature,
                data=cert.tbs_certificate_bytes,
                algorithm=EnumHashAlgorithm.SHA256,
            ):
                raise SPSDKTpError("NXP_PROD certificate signature is invalid")
            cert_puk = cert.get_public_key()
            assert isinstance(cert_puk, PublicKeyEcc)
        except (Exception, SPSDKTpError) as e:
            raise SPSDKTpError(f"NXP_PROD certificate validation failed: {e}") from e

    # TODO: delete this when using properly manufactured cards
    def upload_manufacturing(self, config_data: dict, config_dir: Optional[str] = None) -> None:
        """Simulate uploading Provisioning data during manufacturing."""
        # mandatory files
        for file_key in ["nxp_prod_card_prk_path"]:
            self.upload_file(file_key, config_data, config_dir)  # type: ignore

    def _reverse_kek_files(self, kek_file_keys: list[str]) -> None:
        """Reverse data in kek files."""
        for file_key in kek_file_keys:
            file_path = self.config.get_abspath(self.config.data[file_key])
            org_file = f"{file_path}.org"
            shutil.copy(file_path, org_file)
            with open(org_file, encoding="utf-8") as org:
                with open(file_path, "w", encoding="utf-8") as f:
                    data = bytes.fromhex(org.read().strip())
                    f.write(bytes(reversed(data)).hex())
