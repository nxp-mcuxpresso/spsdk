#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Trust provisioning - TP Device, Smart Card Adapter."""

import logging
import os
from enum import Enum
from typing import Any, Dict, List, Optional, cast

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import NameOID, load_der_x509_certificate

from spsdk import SPSDKError

try:
    from smartcard.CardConnectionDecorator import CardConnection
except ImportError:
    raise SPSDKError(
        "pyscard package is missing, please install it with pip install 'spsdk[tp]' in order to use TP"
    )

from spsdk.crypto.certificate_management import (
    convert_certificate_into_bytes,
    generate_certificate,
    generate_name,
)
from spsdk.crypto.keys_management import generate_ecc_public_key
from spsdk.crypto.loaders import extract_public_key, load_private_key
from spsdk.utils.database import Database
from spsdk.utils.misc import find_file, load_binary, load_text, numberify_version, value_to_int
from spsdk.utils.schema_validator import ValidationSchemas

from .. import TP_DATA_FOLDER, TP_SCH_FILE, SPSDKTpError, TpDevInterface
from ..tp_intf import TpIntfDescription
from . import scard_commands
from .scard_utils import ProvItem, get_applet_infos
from .utils import sanitize_common_name

logger = logging.getLogger(__name__)
TP_DATA_FILE = os.path.join(TP_DATA_FOLDER, "database.yaml")


class TpSCardDescription(TpIntfDescription):
    """Smart Card interface description."""

    def __init__(
        self,
        name: str,
        version: str,
        serial_number: int,
        settings: Dict = None,
        card_connection: CardConnection = None,
    ) -> None:
        """Smart Card interface description."""
        super().__init__(name, TpDevSmartCard, "TP HSM Applet", settings, version)
        self.serial_number = serial_number
        self.card_connection = card_connection

    def get_id(self) -> int:
        """Returns the ID of the interface (smart card serial number)."""
        return self.serial_number

    def as_dict(self) -> Dict[str, Any]:
        """Returns whole record as dictionary suitable for printing."""
        data = super().as_dict()
        # don't display card_connection object in list
        data.pop("card_connection")
        return data


class TpDevSmartCard(TpDevInterface):
    """Trust provisioning device adapter for Smart Card."""

    NAME = "scard"
    ATR = "3BD518FF8191FE1FC38073C821100A"
    APPLET = "tphsmapplet"
    MIN_VERSION = "1.0.6"

    class SettingsKey(str, Enum):
        """Keys used in `get_connected_devices` in `settings` dictionary."""

        ID = "id"
        READER = "reader"

    @classmethod
    def get_connected_devices(cls, settings: Dict = None) -> List[TpIntfDescription]:
        """Get all connected TP devices of this adapter.

        :param settings: Possible settings to determine the way to find connected device, defaults to None.
        :return: List of all founded TP devices.
        """
        ret: List[TpIntfDescription] = []
        filter_id = None if settings is None else settings.get("id")
        reader = None if settings is None else settings.get("reader")
        cards = get_applet_infos(
            atr=cls.ATR, applet=cls.APPLET, filter_id=filter_id, filter_reader=reader
        )
        ret = [
            TpSCardDescription(
                name=card.reader_name,
                version=card.version,
                serial_number=card.serial_number,
                settings=settings,
                card_connection=card.card_connection,
            )
            for card in cards
        ]
        return ret

    get_connected_interfaces = get_connected_devices

    def __init__(self, descriptor: TpIntfDescription) -> None:
        """Initialize Smart Card Adapter."""
        if not descriptor.name or not isinstance(descriptor, TpSCardDescription):
            raise SPSDKTpError("Invalid SMARTCard Interface descriptor.")
        super().__init__(descriptor=descriptor)

        self.descriptor = cast(TpSCardDescription, self.descriptor)
        self.card_connection: Optional[CardConnection] = None

    def open(self) -> None:
        """Open the TP device adapter."""
        # MyPy doesn't pick up it's own "cast" operator :/
        assert isinstance(self.descriptor, TpSCardDescription)

        filter_id = None if self.descriptor.settings is None else self.descriptor.settings.get("id")
        if self.descriptor.card_connection:
            self.card_connection = self.descriptor.card_connection
        else:
            cards = get_applet_infos(atr=self.ATR, applet=self.APPLET, filter_id=filter_id)
            if not cards:
                raise SPSDKTpError("Smart card is not available.")
            if len(cards) != 1:
                raise SPSDKTpError("Multiple suitable cards found.")
            # it's possible tp use descriptor without an connection
            self.card_connection = cards[0].card_connection

        if numberify_version(self.descriptor.version) < numberify_version(self.MIN_VERSION):
            raise SPSDKTpError(
                f"Applet is out-of-date, "
                f"Min required version: {self.MIN_VERSION}, provided: {self.descriptor.version}"
            )
        logger.info(
            f"Connecting to '{self.card_connection.getReader()}'"
            f", applet: '{self.APPLET}'"
            f", serial number: {self.descriptor.serial_number}"
        )
        self.card_connection.connect()
        self.select_applet(self.APPLET)

    def close(self) -> None:
        """Close the TP device adapter."""
        if self.card_connection:
            self.card_connection.disconnect()

    def get_challenge(self, timeout: int = None) -> bytes:
        """Request challenge from the TP device.

        :param timeout: Timeout of operation in milliseconds.
        :raises SPSDKTpError: Smart card is not ready.
        :return: Challenge record, to be used for TP communication.
        """
        if not self.card_connection:
            raise SPSDKTpError("Smart card is not ready.")

        logger.debug("Getting challenge")
        challenge_cmd = scard_commands.GetChallenge()
        challenge = challenge_cmd.transmit(self.card_connection)
        logger.debug("Getting challenge complete")
        return challenge

    def authenticate_response(self, tp_data: bytes, timeout: int = None) -> bytes:
        """Request TP device for TP authentication of connected MCU.

        :param tp_data: TP response of connected MCU.
        :param timeout: Timeout of operation in milliseconds.
        :raises SPSDKTpError: Smart card is not ready.
        :return: Wrapped data after TP response processing.
        """
        if not self.card_connection:
            raise SPSDKTpError("Smart card is not ready.")

        logger.debug("Authenticating TP_RESPONSE")
        auth_resp_cmd = scard_commands.ProcessTPResponse(tp_response=tp_data)
        wrap_data = auth_resp_cmd.transmit(self.card_connection)
        logger.debug("Authenticating TP_RESPONSE complete")
        return wrap_data

    @staticmethod
    def get_help() -> str:
        """Return help for this interface, including settings description."""
        ret = """
        The adapter for SMARTCARD readers and cards support.
        There is one option:
        'id': Serial number of the Smart Card.
        """
        return ret

    @classmethod
    def get_validation_schemas(cls) -> List[Dict[str, Any]]:
        """Return all additional validation schemas for interface.

        return: List of all additional validation schemas.
        """
        sch_cfg_file = ValidationSchemas.get_schema_file(TP_SCH_FILE)

        return [sch_cfg_file["device_scard"]]

    def select_applet(self, applet: str) -> None:
        """Select applet in smart card.

        :param applet: Identification of required Applet.
        :raises SPSDKTpError: Smart card is not ready.
        """
        if not self.card_connection:
            raise SPSDKTpError("Smart card is not ready.")

        logger.debug(f"Selecting smartcard Applet: {applet}")
        select_cmd = scard_commands.Select(applet)
        select_cmd.transmit(self.card_connection)
        logger.debug("Applet selected successfully.")

    def get_applet_version(self) -> str:
        """Get selected applet version from smart card.

        :raises SPSDKTpError: Smart card is not ready.
        :return: Version of selected applet in card.
        """
        if not self.card_connection:
            raise SPSDKTpError("Smart card is not ready.")

        logger.debug("Getting selected applet version.")
        version_cmd = scard_commands.GetAppletVersion()
        applet_version = version_cmd.format(
            version_cmd.transmit(self.card_connection),
        )
        logger.debug(f"Applet version: {applet_version}")
        return applet_version

    def upload(self, config_data: dict, config_dir: str = None) -> None:
        """Upload Provisioning data."""
        logger.info("Sending CMPA")
        file_path = config_data["cmpa_path"]
        cmpa = load_binary(file_path, search_paths=[config_dir] if config_dir else None)
        cmd = scard_commands.SetProvisioningItem(prov_item=ProvItem.CMPA, data=cmpa)
        cmd.transmit(self.card_connection)

        logger.info("Sending CFPA")
        file_path = config_data["cfpa_path"]
        cfpa = load_binary(file_path, search_paths=[config_dir] if config_dir else None)
        cmd = scard_commands.SetProvisioningItem(prov_item=ProvItem.CFPA, data=cfpa)
        cmd.transmit(self.card_connection)

        logger.info("Sending SB KEK")
        file_path = config_data["sb_kek_path"]
        sb_kek = bytes.fromhex(
            load_text(file_path, search_paths=[config_dir] if config_dir else None).strip()
        )
        # Send KEK reversed, so Applet doesn't have to reverse it
        sb_kek = bytes(reversed(sb_kek))
        cmd = scard_commands.SetProvisioningItem(prov_item=ProvItem.SB_KEK, data=sb_kek)
        cmd.transmit(self.card_connection)

        logger.info("Sending USER KEK")
        file_path = config_data["user_kek_path"]
        user_kek = bytes.fromhex(
            load_text(file_path, search_paths=[config_dir] if config_dir else None).strip()
        )
        # Send KEK reversed, so Applet doesn't have to reverse it
        user_kek = bytes(reversed(user_kek))
        cmd = scard_commands.SetProvisioningItem(prov_item=ProvItem.USER_KEK, data=user_kek)
        cmd.transmit(self.card_connection)

        logger.info("Sending oem_log_prk")
        file_path = config_data["oem_log_prk_path"]
        log_prk_data = self._serialize_private_key(file_path, [config_dir] if config_dir else None)
        cmd = scard_commands.SetProvisioningItem(prov_item=ProvItem.OEM_LOG_PRK, data=log_prk_data)
        cmd.transmit(self.card_connection)

        logger.info("Sending nxp_global_attest_puk")
        file_path = config_data["nxp_global_attest_puk_path"]
        nxp_glob_puk_file = find_file(file_path, search_paths=[config_dir] if config_dir else None)
        puk = extract_public_key(nxp_glob_puk_file)
        assert isinstance(puk, ec.EllipticCurvePublicKey)
        x = puk.public_numbers().x.to_bytes(length=32, byteorder="big")
        y = puk.public_numbers().y.to_bytes(length=32, byteorder="big")

        cmd = scard_commands.SetProvisioningItem(
            prov_item=ProvItem.NXP_GLOB_PUK, data=b"\x04" + x + y
        )
        cmd.transmit(self.card_connection)

        logger.info("Sending nxp_prod_cert_path")
        file_path = config_data["nxp_prod_cert_path"]
        cert_data = self._serialize_cert(file_path, [config_dir] if config_dir else None)
        cmd = scard_commands.SetProvisioningItem(prov_item=ProvItem.NXP_PROD_CERT, data=cert_data)
        cmd.transmit(self.card_connection)

        logger.info("Sending production_quota")
        quota: int = config_data["production_quota"]
        cmd = scard_commands.SetProvisioningItem(
            prov_item=ProvItem.PROD_COUNTER, data=quota.to_bytes(length=4, byteorder="big")
        )
        cmd.transmit(self.card_connection)

        logger.info("Sending oem_id_count")
        oem_id_count: int = config_data["oem_id_count"]
        # TODO: figure out the key flags 1:0; for now we put 00
        oem_key_flags = oem_id_count << 2
        cmd = scard_commands.SetProvisioningItem(
            prov_item=ProvItem.OEM_CERT_COUNT,
            data=oem_key_flags.to_bytes(length=1, byteorder="big"),
        )
        cmd.transmit(self.card_connection)

        if oem_id_count > 0:
            logger.info("Sending oem_id_prk")
            file_path = config_data["oem_id_prk_path"]
            prk_data = self._serialize_private_key(file_path, [config_dir] if config_dir else None)
            cmd = scard_commands.SetProvisioningItem(prov_item=ProvItem.OEM_ID_PRK, data=prk_data)
            cmd.transmit(self.card_connection)

            cert_template = self._create_oem_cert_template(config_data, config_dir)
            for i in range(oem_id_count):
                cert_data = self._serialize_cert_data(
                    cert_template, config_data["oem_id_addresses"][i]
                )
                logger.info(f"Sending OEM cert template #{i+1}")
                cmd = scard_commands.SetProvisioningItem(
                    prov_item=ProvItem.OEM_CERT_TEMPLATE + i, data=cert_data
                )
                cmd.transmit(self.card_connection)

    def upload_manufacturing(self, config_data: dict, config_dir: str = None) -> None:
        """Upload Manufacturing data NXP_PROD_CARD_PRK."""
        logger.info("Sending nxp_prod_card_prk")
        file_path = config_data["nxp_prod_card_prk_path"]
        prk_data = self._serialize_private_key(file_path, [config_dir] if config_dir else None)
        cmd = scard_commands.SetProvisioningItem(prov_item=ProvItem.JC_ID_PRK, data=prk_data)
        cmd.transmit(self.card_connection)

    def setup(self) -> None:
        """Setup the provisioning device."""
        logger.info("Setting up a Smart Card")
        try:
            logger.info("Deleting filesystem")
            delete_fs = scard_commands.DeleteFileSystem()
            delete_fs.transmit(self.card_connection)
        except SPSDKTpError:
            logger.warning("Failed to delete filesystem. This is expected on the very first run")
        logger.info("Creating filesystem")
        create_fs = scard_commands.CreateFileSystem(objects_count=15)
        create_fs.transmit(self.card_connection)

        logger.info("Setting ECC params")
        ecc_params_cmd = scard_commands.SetProvisioningItem(
            prov_item=ProvItem.ECC_DOMAIN_PARAM,
            data=(
                b"\x90 \xff\xff\xff\xff\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfc\x91 Z\xc65\xd8\xaa:\x93\xe7"
                b"\xb3\xeb\xbdUv\x98\x86\xbce\x1d\x06\xb0\xccS\xb0\xf6;\xce<>'\xd2`K\x92 \xff\xff"
                b"\xff\xff\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff"
                b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x93A\x04k\x17\xd1\xf2\xe1,BG\xf8\xbc\xe6"
                b"\xe5c\xa4@\xf2w\x03}\x81-\xeb3\xa0\xf4\xa19E\xd8\x98\xc2\x96O\xe3B\xe2\xfe\x1a\x7f"
                b"\x9b\x8e\xe7\xebJ|\x0f\x9e\x16+\xce3Wk1^\xce\xcb\xb6@h7\xbfQ\xf5\x95 \xff\xff\xff"
                b"\xff\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xbc\xe6\xfa\xad\xa7\x17\x9e"
                b"\x84\xf3\xb9\xca\xc2\xfcc%Q\x97\x02\x00\x01"
            ),
        )
        ecc_params_cmd.transmit(self.card_connection)

    def seal(self) -> None:
        """Seal the provisioning device."""
        if numberify_version(self.descriptor.version) < numberify_version("1.0.7"):
            raise SPSDKTpError(
                "Card sealing operation is available in TP Applet version 1.0.7+"
                f"; provided applet has version {self.descriptor.version}"
            )
        logger.info("Start sealing the Smart Card")
        finalize_fs = scard_commands.FinalizeFileSystem()
        finalize_fs.transmit(self.card_connection)
        logger.info("Sealing Smart Card completed")

    def get_prov_counter(self) -> int:
        """Get actual provisioning counter."""
        counter_cmd = scard_commands.GetProductionCounter()
        counter = counter_cmd.format(counter_cmd.transmit(self.card_connection))
        return counter

    def get_prov_remainder(self) -> int:
        """Get the number of remaining provisioning attempts."""
        if numberify_version(self.descriptor.version) < numberify_version("1.0.9"):
            raise SPSDKTpError(
                "Prov remainder operation is available in TP Applet version 1.0.9+"
                f"; provided applet has version {self.descriptor.version}"
            )
        remainder_cmd = scard_commands.GetProductionRemainder()
        counter = remainder_cmd.format(remainder_cmd.transmit(self.card_connection))
        return counter

    @staticmethod
    def _serialize_private_key(prk_file_path: str, search_dirs: List[str] = None) -> bytes:
        prk_file = find_file(prk_file_path, search_paths=search_dirs)
        prk = load_private_key(prk_file)
        assert isinstance(prk, ec.EllipticCurvePrivateKeyWithSerialization)
        d_number = prk.private_numbers().private_value
        d_bytes = d_number.to_bytes(length=32, byteorder="big")
        return d_bytes

    @staticmethod
    def _serialize_cert(
        cert_file_path: str, search_dirs: List[str] = None, destination: int = 0
    ) -> bytes:
        cert_file = find_file(cert_file_path, search_paths=search_dirs)
        with open(cert_file, "rb") as f:
            cert_data = f.read()
        return TpDevSmartCard._serialize_cert_data(cert_data, destination)

    @staticmethod
    def _serialize_cert_data(cert_data: bytes, destination: int = 0) -> bytes:
        cert = load_der_x509_certificate(cert_data)

        scn = bytes(
            cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, encoding="ascii"
        )
        # 16B UUID, hyphen, 1B certificate ID
        scn_length = 32 + 1 + 2
        scn_offset = cert_data.index(scn) + len(scn) - scn_length

        pub_key = cert.public_key()
        assert isinstance(pub_key, ec.EllipticCurvePublicKey)
        x = pub_key.public_numbers().x.to_bytes(length=32, byteorder="big")
        y = pub_key.public_numbers().y.to_bytes(length=32, byteorder="big")
        x_offset = cert_data.index(x)
        y_offset = cert_data.index(y)

        sig_offset = cert_data.index(cert.signature)
        sig_length = len(cert.signature)

        tbs_offset = cert_data.index(cert.tbs_certificate_bytes)
        tbs_length = len(cert.tbs_certificate_bytes)

        cert_length = len(cert_data)

        return (
            cert_data
            # final certificate could be 4B longer due to changing signature size
            + bytes(4)
            + scn_offset.to_bytes(length=2, byteorder="big")
            + scn_length.to_bytes(length=2, byteorder="big")
            + x_offset.to_bytes(length=2, byteorder="big")
            + y_offset.to_bytes(length=2, byteorder="big")
            + sig_offset.to_bytes(length=2, byteorder="big")
            + sig_length.to_bytes(length=2, byteorder="big")
            + tbs_offset.to_bytes(length=2, byteorder="big")
            + tbs_length.to_bytes(length=2, byteorder="big")
            + cert_length.to_bytes(length=2, byteorder="big")
            + destination.to_bytes(length=4, byteorder="little")
        )

    @staticmethod
    def _create_oem_cert_template(config_data: dict, config_dir: str = None) -> bytes:
        logger.info("Creating OEM ID template")
        cert_config: dict = config_data["oem_id_config"]
        sanitize_common_name(cert_config["subject"])
        issuer = generate_name(cert_config["issuer"])
        subject = generate_name(cert_config["subject"])
        private_key = load_private_key(
            find_file(
                config_data["oem_id_prk_path"], search_paths=[config_dir] if config_dir else None
            )
        )
        assert isinstance(private_key, ec.EllipticCurvePrivateKey)
        public_key = generate_ecc_public_key(private_key=private_key)
        cert = generate_certificate(
            subject=subject,
            issuer=issuer,
            subject_public_key=public_key,
            issuer_private_key=private_key,
            duration=cert_config["duration"],
            if_ca=False,
            serial_number=cert_config.get("serial_number"),
        )
        cert_raw = convert_certificate_into_bytes(cert, Encoding.DER)

        database = Database(TP_DATA_FILE)
        max_size = value_to_int(
            database.get_device_value("max_oem_cert_size", config_data["family"])
        )
        if len(cert_raw) > max_size:
            raise SPSDKTpError(
                f"OEM certificate is too big: {len(cert_raw)}B, max size: {max_size}B! "
                "Please adjust information in SUBJECT and/or ISSUER portion of the certificate."
            )

        return cert_raw
