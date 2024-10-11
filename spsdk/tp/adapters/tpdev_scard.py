#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Trust provisioning - TP Device, Smart Card Adapter."""

import logging
from enum import Enum
from typing import Any, Optional, cast

from spsdk.crypto.certificate import Certificate, SPSDKNameOID, generate_name
from spsdk.crypto.crypto_types import SPSDKEncoding
from spsdk.crypto.keys import PrivateKeyEcc, PublicKeyEcc
from spsdk.crypto.utils import extract_public_key
from spsdk.exceptions import SPSDKError
from spsdk.utils.database import DatabaseManager, get_db, get_schema_file
from spsdk.utils.misc import (
    Endianness,
    find_file,
    get_hash,
    load_binary,
    load_text,
    numberify_version,
)

try:
    from smartcard.CardConnectionDecorator import CardConnection
except ImportError as e:
    raise SPSDKError(
        "pyscard package is missing, please install it with pip install 'spsdk[tp]' in order to use TP"
    ) from e


from spsdk.tp.adapters import scard_commands
from spsdk.tp.adapters.scard_utils import ProvItem, get_applet_infos
from spsdk.tp.adapters.utils import OEMCertInfo, TPFlags, sanitize_common_name
from spsdk.tp.exceptions import SPSDKTpError
from spsdk.tp.tp_intf import TpDevInterface, TpIntfDescription

logger = logging.getLogger(__name__)


class TpSCardDescription(TpIntfDescription):
    """Smart Card interface description."""

    def __init__(
        self,
        name: str,
        version: str,
        serial_number: int,
        sealed: bool,
        is_usable: bool = False,
        settings: Optional[dict] = None,
        card_connection: Optional[CardConnection] = None,
    ) -> None:
        """Smart Card interface description."""
        super().__init__(name, TpDevSmartCard, "TP HSM Applet", settings, version)
        self.serial_number = serial_number
        self.sealed = sealed
        self.is_usable = is_usable
        self.card_connection = card_connection

    def get_id(self) -> int:
        """Returns the ID of the interface (smart card serial number)."""
        return self.serial_number

    def get_id_hash(self) -> str:
        """Return the ID hash of the interface. (hash of the reader's name)."""
        return get_hash(self.name)

    def as_dict(self) -> dict[str, Any]:
        """Returns whole record as dictionary suitable for printing."""
        data = super().as_dict()
        # don't display card_connection object in list
        data.pop("card_connection")
        data["name_hash"] = self.get_id_hash()
        return data


class TpDevSmartCard(TpDevInterface):
    """Trust provisioning device adapter for Smart Card."""

    NAME = "scard"
    ATR = "3BD518FF8191FE1FC38073C821100A"
    APPLET = "tphsmapplet"
    MIN_VERSION = "1.2.0"

    class SettingsKey(str, Enum):
        """Keys used in `get_connected_devices` in `settings` dictionary."""

        ID = "id"
        READER = "reader"

    @classmethod
    def get_connected_devices(cls, settings: Optional[dict] = None) -> list[TpIntfDescription]:
        """Get all connected TP devices of this adapter.

        :param settings: Possible settings to determine the way to find connected device, defaults to None.
        :return: List of all founded TP devices.
        """
        ret: list[TpIntfDescription] = []
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
                sealed=card.sealed,
                is_usable=numberify_version(cls.MIN_VERSION) <= numberify_version(card.version),
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

    def get_challenge(self, timeout: Optional[int] = None) -> bytes:
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

    def authenticate_response(self, tp_data: bytes, timeout: Optional[int] = None) -> bytes:
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
        return "\n".join(
            [
                "The adapter for SMARTCARD readers and cards support.",
                "There are two identification options (at least one is required)",
                "   - id - Serial number of the Smart Card.",
                "   - reader - Name of the Smart Card reader.",
            ]
        )

    @classmethod
    def get_validation_schemas(cls) -> list[dict[str, Any]]:
        """Return all additional validation schemas for interface.

        return: List of all additional validation schemas.
        """
        sch_cfg_file = get_schema_file(DatabaseManager.TP)

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

    def upload(self, config_data: dict, config_dir: Optional[str] = None) -> None:
        """Upload Provisioning data."""
        family: str = config_data["family"]
        logger.info(f"Sending family name: {family}")
        cmd = scard_commands.SetProvisioningItem(
            prov_item=ProvItem.FAMILY.tag, data=family.encode("utf-8")
        )
        cmd.transmit(self.card_connection)

        tp_flags = TPFlags.for_family(family=family)
        logger.info(f"Sending TPFlags: {tp_flags}")
        cmd = scard_commands.SetProvisioningItem(
            prov_item=ProvItem.PROV_FLAGS.tag, data=tp_flags.export()
        )
        cmd.transmit(self.card_connection)

        if tp_flags.use_prov_data:
            logger.info("Sending Provisioning Data SB3 file")
            file_path = config_data["prov_data_path"]
            cmpa = load_binary(file_path, search_paths=[config_dir] if config_dir else None)
            cmd = scard_commands.SetProvisioningItem(prov_item=ProvItem.PROV_DATA.tag, data=cmpa)
            cmd.transmit(self.card_connection)
        else:
            logger.info("Sending CMPA")
            file_path = config_data["cmpa_path"]
            cmpa = load_binary(file_path, search_paths=[config_dir] if config_dir else None)
            cmd = scard_commands.SetProvisioningItem(prov_item=ProvItem.CMPA.tag, data=cmpa)
            cmd.transmit(self.card_connection)

            logger.info("Sending CFPA")
            file_path = config_data["cfpa_path"]
            cfpa = load_binary(file_path, search_paths=[config_dir] if config_dir else None)
            cmd = scard_commands.SetProvisioningItem(prov_item=ProvItem.CFPA.tag, data=cfpa)
            cmd.transmit(self.card_connection)

            logger.info("Sending SB KEK")
            file_path = config_data["sb_kek_path"]
            sb_kek = bytes.fromhex(
                load_text(file_path, search_paths=[config_dir] if config_dir else None).strip()
            )
            # Send KEK reversed, so Applet doesn't have to reverse it
            sb_kek = bytes(reversed(sb_kek))
            cmd = scard_commands.SetProvisioningItem(prov_item=ProvItem.SB_KEK.tag, data=sb_kek)
            cmd.transmit(self.card_connection)

            logger.info("Sending USER KEK")
            file_path = config_data["user_kek_path"]
            user_kek = bytes.fromhex(
                load_text(file_path, search_paths=[config_dir] if config_dir else None).strip()
            )
            # Send KEK reversed, so Applet doesn't have to reverse it
            user_kek = bytes(reversed(user_kek))
            cmd = scard_commands.SetProvisioningItem(prov_item=ProvItem.USER_KEK.tag, data=user_kek)
            cmd.transmit(self.card_connection)

        logger.info("Sending oem_log_prk")
        file_path = config_data["oem_log_prk_path"]
        log_prk_data = self._serialize_private_key(file_path, [config_dir] if config_dir else None)
        cmd = scard_commands.SetProvisioningItem(
            prov_item=ProvItem.OEM_LOG_PRK.tag, data=log_prk_data
        )
        cmd.transmit(self.card_connection)

        logger.info("Sending nxp_global_attest_puk")
        file_path = config_data["nxp_global_attest_puk_path"]

        nxp_glob_puk_file = find_file(file_path, search_paths=[config_dir] if config_dir else None)
        puk = extract_public_key(nxp_glob_puk_file)
        assert isinstance(puk, PublicKeyEcc)
        glob_puk_data = puk.export()

        cmd = scard_commands.SetProvisioningItem(
            prov_item=ProvItem.NXP_GLOB_PUK.tag, data=b"\x04" + glob_puk_data
        )
        cmd.transmit(self.card_connection)

        logger.info("Sending nxp_prod_cert_path")
        file_path = config_data["nxp_prod_cert_path"]
        cert_data = self._serialize_cert(file_path, [config_dir] if config_dir else None)
        cmd = scard_commands.SetProvisioningItem(
            prov_item=ProvItem.NXP_PROD_CERT.tag, data=cert_data
        )
        cmd.transmit(self.card_connection)

        logger.info("Sending production_quota")
        quota: int = config_data["production_quota"]
        cmd = scard_commands.SetProvisioningItem(
            prov_item=ProvItem.PROD_COUNTER.tag,
            data=quota.to_bytes(length=4, byteorder=Endianness.BIG.value),
        )
        cmd.transmit(self.card_connection)

        logger.info("Sending oem_id_count")
        oem_cert_info = OEMCertInfo.from_config(config_data=config_data)

        cmd = scard_commands.SetProvisioningItem(
            prov_item=ProvItem.OEM_CERT_COUNT.tag,
            data=oem_cert_info.flags.export(),
        )
        cmd.transmit(self.card_connection)

        if oem_cert_info.use_oem_certs:
            logger.info("Sending oem_id_prk")
            file_path = config_data["oem_id_prk_path"]
            prk_data = self._serialize_private_key(file_path, [config_dir] if config_dir else None)
            cmd = scard_commands.SetProvisioningItem(
                prov_item=ProvItem.OEM_ID_PRK.tag, data=prk_data
            )
            cmd.transmit(self.card_connection)

            template_id = -1
            cert_template = self._create_oem_cert_template(config_data, config_dir)
            for cert_address in oem_cert_info.oem_cert_addresses:
                template_id += 1
                cert_data = self._serialize_cert_data(cert_template, cert_address)
                logger.info(f"Sending OEM cert template #{template_id+1}")
                cmd = scard_commands.SetProvisioningItem(
                    prov_item=ProvItem.OEM_CERT_TEMPLATE.tag + template_id, data=cert_data
                )
                cmd.transmit(self.card_connection)

            if oem_cert_info.ca_cert_address:
                template_id += 1
                cert_data = self._serialize_cert_data(cert_template, oem_cert_info.ca_cert_address)
                logger.info("Sending OEM CA cert template")
                cmd = scard_commands.SetProvisioningItem(
                    prov_item=ProvItem.OEM_CERT_TEMPLATE.tag + template_id, data=cert_data
                )
                cmd.transmit(self.card_connection)

            if oem_cert_info.rtf_cert_address:
                template_id += 1
                cert_data = self._serialize_cert_data(cert_template, oem_cert_info.rtf_cert_address)
                logger.info("Sending OEM RTF cert template")
                cmd = scard_commands.SetProvisioningItem(
                    prov_item=ProvItem.OEM_CERT_TEMPLATE.tag + template_id, data=cert_data
                )
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
            prov_item=ProvItem.ECC_DOMAIN_PARAM.tag,
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

    def get_seal_status(self) -> bool:
        """Check if provisioning device is sealed."""
        if numberify_version(self.descriptor.version) < numberify_version("1.2.0"):
            raise SPSDKTpError(
                "Getting card seal status operation is available in TP Applet version 1.2.0+"
                f"; provided applet has version {self.descriptor.version}"
            )
        logger.info("Start getting the card seal status")
        get_seal_status = scard_commands.GetSealState()
        is_sealed = get_seal_status.format(get_seal_status.transmit(self.card_connection))
        logger.info(f"Card is {'LOCKED' if is_sealed else 'UNLOCKED'}")
        return is_sealed

    def get_family(self) -> str:
        """Get the chip family name stored in the provisioning device."""
        if numberify_version(self.descriptor.version) < numberify_version("1.2.0"):
            raise SPSDKTpError(
                "Getting family is available in TP Applet version 1.2.0+"
                f"; provided applet has version {self.descriptor.version}"
            )
        logger.info("Getting family name from the card")
        get_family = scard_commands.GetFamily()
        family = get_family.format(get_family.transmit(self.card_connection))
        logger.info(f"Family: {family}")
        return family

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
    def _serialize_private_key(
        prk_file_path: str, search_dirs: Optional[list[str]] = None
    ) -> bytes:
        prk_file = find_file(prk_file_path, search_paths=search_dirs)
        prk = PrivateKeyEcc.load(prk_file)
        d_number = prk.key.private_numbers().private_value
        d_bytes = d_number.to_bytes(length=32, byteorder=Endianness.BIG.value)
        return d_bytes

    @staticmethod
    def _serialize_cert(
        cert_file_path: str, search_dirs: Optional[list[str]] = None, destination: int = 0
    ) -> bytes:
        cert_file = find_file(cert_file_path, search_paths=search_dirs)
        cert_data = load_binary(cert_file)
        return TpDevSmartCard._serialize_cert_data(cert_data, destination)

    @staticmethod
    def _serialize_cert_data(cert_data: bytes, destination: int = 0) -> bytes:
        cert = Certificate.parse(cert_data)
        # cert_data might PEM or DER encoded
        # we need to have it in DER for further use
        cert_data = cert.export(SPSDKEncoding.DER)

        scn_raw = cert.subject.get_attributes_for_oid(SPSDKNameOID.COMMON_NAME)[0].value
        scn = bytes(scn_raw, encoding="ascii") if isinstance(scn_raw, str) else scn_raw

        # 16B UUID, hyphen, 1B certificate ID
        scn_length = 32 + 1 + 2
        scn_offset = cert_data.index(scn) + len(scn) - scn_length
        pub_key = cert.get_public_key()
        assert isinstance(pub_key, PublicKeyEcc)
        x = pub_key.x.to_bytes(length=32, byteorder=Endianness.BIG.value)
        y = pub_key.y.to_bytes(length=32, byteorder=Endianness.BIG.value)
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
            + scn_offset.to_bytes(length=2, byteorder=Endianness.BIG.value)
            + scn_length.to_bytes(length=2, byteorder=Endianness.BIG.value)
            + x_offset.to_bytes(length=2, byteorder=Endianness.BIG.value)
            + y_offset.to_bytes(length=2, byteorder=Endianness.BIG.value)
            + sig_offset.to_bytes(length=2, byteorder=Endianness.BIG.value)
            + sig_length.to_bytes(length=2, byteorder=Endianness.BIG.value)
            + tbs_offset.to_bytes(length=2, byteorder=Endianness.BIG.value)
            + tbs_length.to_bytes(length=2, byteorder=Endianness.BIG.value)
            + cert_length.to_bytes(length=2, byteorder=Endianness.BIG.value)
            + destination.to_bytes(length=4, byteorder=Endianness.LITTLE.value)
        )

    @staticmethod
    def _create_oem_cert_template(config_data: dict, config_dir: Optional[str] = None) -> bytes:
        family = config_data["family"]
        logger.info("Creating OEM ID template")
        cert_config: dict = config_data["oem_id_config"]
        sanitize_common_name(cert_config["subject"])
        issuer = generate_name(cert_config["issuer"])
        subject = generate_name(cert_config["subject"])
        private_key = PrivateKeyEcc.load(
            find_file(
                config_data["oem_id_prk_path"], search_paths=[config_dir] if config_dir else None
            )
        )
        public_key = private_key.get_public_key()
        cert = Certificate.generate_certificate(
            subject=subject,
            issuer=issuer,
            subject_public_key=public_key,
            issuer_private_key=private_key,
            duration=cert_config["duration"],
            serial_number=cert_config.get("serial_number"),
        )
        cert_raw = cert.export(SPSDKEncoding.DER)

        db = get_db(family, "latest")
        max_size = db.get_int(DatabaseManager.TP, "max_oem_cert_size")
        if len(cert_raw) > max_size:
            raise SPSDKTpError(
                f"OEM certificate is too big: {len(cert_raw)}B, max size: {max_size}B! "
                "Please adjust information in SUBJECT and/or ISSUER portion of the certificate."
            )

        return cert_raw
