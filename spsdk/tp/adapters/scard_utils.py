#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Utilities used in SmartCard."""

import logging
from typing import NamedTuple, Optional

from spsdk.apps.utils.utils import format_raw_data
from spsdk.exceptions import SPSDKError
from spsdk.utils.misc import get_hash
from spsdk.utils.spsdk_enum import SpsdkEnum

try:
    from smartcard.CardConnectionDecorator import CardConnection
    from smartcard.CardConnectionEvent import CardConnectionEvent
    from smartcard.CardConnectionObserver import CardConnectionObserver
    from smartcard.CardRequest import CardRequest
    from smartcard.CardType import ATRCardType
    from smartcard.System import readers
    from smartcard.util import toBytes
except ImportError as import_error:
    raise SPSDKError(
        "pyscard package is missing, please install it with pip install 'spsdk[tp]' in order to use TP"
    ) from import_error


from spsdk.tp.adapters import scard_commands

logger = logging.getLogger(__name__)


class ProvItem(SpsdkEnum):
    """Provisioning item indexes."""

    OEM_CERT_COUNT = (0x1001, "oem_id_count")
    KEY_WRAP_ENABLE = (0x1002, "key_wrap_enable")
    ECC_DOMAIN_PARAM = (0x1003, "ecc_domain_param")
    JC_ID_PRK = (0x0000, "jc_id_prk")
    NXP_GLOB_PUK = (0x0001, "nxp_glob_puk")
    NXP_PROD_CERT = (0x0002, "nxp_prod_cert")
    OEM_ID_PRK = (0x0003, "oem_id_prk")
    OEM_LOG_PRK = (0x0004, "oem_log_prk")
    SB_KEK = (0x0005, "sb_kek")
    USER_KEK = (0x0006, "user_kek")
    CFPA = (0x0007, "cfpa")
    CMPA = (0x0008, "cmpa")
    PROD_COUNTER = (0x0009, "prod_counter")
    PROV_DATA = (0x000A, "prov_data")
    PROV_FLAGS = (0x000B, "prov_flags")
    FAMILY = (0x000C, "family")
    OEM_CERT_TEMPLATE = (0x0100, "oem_cert_template")


class LoggerConnectionObserver(CardConnectionObserver):
    """Overriding standard CardConnectionObserver, to enable proper logging."""

    def update(
        self, cardconnection: CardConnection, cardconnectionevent: CardConnectionEvent
    ) -> None:
        """New card connection event. Just log it.

        :param cardconnection: Card connection object.
        :param cardconnectionevent: Card connection event.
        """
        reader = cardconnection.getReader()
        if cardconnectionevent.type == "connect":
            logger.debug(f"connecting to {reader}")
        elif cardconnectionevent.type == "disconnect":
            logger.debug(f"disconnecting from {reader}")
        elif cardconnectionevent.type == "command":
            command_data = bytes(cardconnectionevent.args[0])
            if len(command_data) < 16:
                logger.debug(f"> {format_raw_data(command_data)}")
            else:
                data_start = 7 if command_data[4] == 0 else 5
                logger.debug(
                    f"> {format_raw_data(command_data[:data_start])}\n"
                    f"{format_raw_data(command_data[data_start:], use_hexdump=True)}"
                )
        elif cardconnectionevent.type == "response":
            if [] == cardconnectionevent.args[0]:
                logger.debug(
                    f"< {format(cardconnectionevent.args[1], '02x')} {format(cardconnectionevent.args[2], '02x')}"
                )
            else:
                logger.debug(
                    f"< data:\n{format_raw_data(bytes(cardconnectionevent.args[0]), use_hexdump=True)}",
                )
                logger.debug(
                    f"< {format(cardconnectionevent.args[1], '02x')} {format(cardconnectionevent.args[2], '02x')}",
                )
        else:
            logger.info(f"Something Interesting{cardconnectionevent}")


class AppletInfo(NamedTuple):
    """Simple storage for information about a reader/card/applet."""

    reader_name: str
    version: str
    serial_number: int
    sealed: bool
    card_connection: CardConnection


def get_readers() -> list[tuple[str, str]]:
    """Return list of all readers in the system.

    Each reader is represented by a tuple:
        1. item: card reader name
        2. item: hash of the card reader's name
    """
    return [(str(reader), get_hash(str(reader))) for reader in readers()]


def get_applet_infos(
    atr: str, applet: str, filter_id: Optional[int] = None, filter_reader: Optional[str] = None
) -> list[AppletInfo]:
    """Collets information about attached card readers.

    :param atr: Select the card's ATR (after reset value)
    :param applet: Name of an applet to look for
    :param filter_id: Filter the card's ID (serial number), defaults to None
    :param filter_reader: Name of the preferred reader
    :return: List of card/applets fulfilling the search criteria.
    """
    ret = []
    card_readers = get_readers()
    for reader_tuple in card_readers:
        if filter_reader and filter_reader not in reader_tuple:
            continue
        logger.info(f"Checking reader {reader_tuple}")
        try:
            request = CardRequest(
                readers=[reader_tuple[0]],
                cardType=ATRCardType(toBytes(atr)),
                timeout=0.1,
            )
            scard = request.waitforcard()
        # pylint: disable=broad-except
        except Exception as e:
            # if anything goes wrong, just log the error and move on to next reader
            logger.debug(str(e))
            continue
        assert isinstance(scard.connection, CardConnection)
        try:
            scard.connection.addObserver(LoggerConnectionObserver())
            scard.connection.connect()
            select_cmd = scard_commands.Select(applet=applet)
            select_cmd.transmit(scard.connection)
            serial_number_cmd = scard_commands.GetSerialNumber()
            serial_number = serial_number_cmd.format(
                serial_number_cmd.transmit(scard.connection),
            )
            if filter_id and str(filter_id) != str(serial_number):
                continue
            version_cmd = scard_commands.GetAppletVersion()
            version = version_cmd.format(version_cmd.transmit(scard.connection))
            sealed_cmd = scard_commands.GetSealState()
            sealed = sealed_cmd.format(sealed_cmd.transmit(scard.connection))
            ret.append(
                AppletInfo(
                    reader_name=reader_tuple[0],
                    version=version,
                    serial_number=serial_number,
                    sealed=sealed,
                    card_connection=scard.connection,
                )
            )
        # pylint: disable=broad-except
        except Exception as e:
            # if anything goes wrong, just log the error and move on to next reader
            logger.debug(str(e))
            scard.connection.disconnect()
            continue

    return ret
