#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""AHAB signed message implementation.

This module provides classes and functions to create, parse, and manipulate AHAB
(Advanced High Assurance Boot) signed messages. The implementation supports various
message types such as key provisioning, lifecycle management, secure fuse operations,
and debug authentication.

Signed messages are used for secure communication with NXP devices that support
EdgeLock security features. The module allows customization of container values
according to device-specific requirements - consult your device reference manual
for allowed values and message formats.
"""

import datetime
import logging
import os
from abc import abstractmethod
from inspect import isclass
from struct import calcsize, pack, unpack
from typing import Any, Optional, Type, Union

from typing_extensions import Self, TypeAlias

from spsdk.crypto.hkdf import hkdf
from spsdk.crypto.keys import PrivateKeyEcc, PublicKeyEcc
from spsdk.exceptions import (
    SPSDKError,
    SPSDKNotImplementedError,
    SPSDKParsingError,
    SPSDKValueError,
)
from spsdk.image.ahab.ahab_abstract_interfaces import Container
from spsdk.image.ahab.ahab_container import AHABContainerBase
from spsdk.image.ahab.ahab_data import (
    CONTAINER_ALIGNMENT,
    LITTLE_ENDIAN,
    RESERVED,
    UINT8,
    UINT16,
    UINT32,
    AhabChipConfig,
    FlagsSrkSet,
    KeyAlgorithm,
    KeyDerivationAlgorithm,
    KeyType,
    KeyUsage,
    LifeCycle,
    LifeTime,
    create_chip_config,
)
from spsdk.image.ahab.ahab_sign_block import SignatureBlock, SignatureBlockV2
from spsdk.image.ahab.ahab_signature import ContainerSignature
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.binary_image import BinaryImage
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, get_db, update_validation_schema_family
from spsdk.utils.misc import (
    BinaryPattern,
    Endianness,
    align,
    align_block,
    get_printable_path,
    value_to_int,
)
from spsdk.utils.schema_validator import CommentedConfig
from spsdk.utils.spsdk_enum import SpsdkEnum
from spsdk.utils.verifier import Verifier, VerifierResult

logger = logging.getLogger(__name__)


class SignedMessageTags(SpsdkEnum):
    """Signed message container related tags."""

    SIGNED_MSG = (0x89, "SIGNED_MSG", "Signed message.")


class MessageCommands(SpsdkEnum):
    """Signed messages commands."""

    KEYSTORE_REPROVISIONING_ENABLE_REQ = (
        0x3F,
        "KEYSTORE_REPROVISIONING_ENABLE_REQ",
        "Key store reprovisioning enable",
    )

    KEY_EXCHANGE_REQ = (
        0x47,
        "KEY_EXCHANGE_REQ",
        "Key exchange signed message content",
    )
    WRITE_SEC_FUSE_REQ = (0x91, "WRITE_SEC_FUSE_REQ", "Write secure fuse request.")
    RETURN_LIFECYCLE_UPDATE_REQ = (
        0xA0,
        "RETURN_LIFECYCLE_UPDATE_REQ",
        "Return lifecycle update request.",
    )
    DAT_AUTHENTICATION_REQ = (
        0xC8,
        "DAT_AUTHENTICATION_REQ",
        "Debug authentication request, internally used for DAT procedure.",
    )


class Message(Container):
    """Class representing the Signed message.

    Message::
        +-----+--------------+--------------+----------------+----------------+
        |Off  |    Byte 3    |    Byte 2    |      Byte 1    |     Byte 0     |
        +-----+--------------+--------------+----------------+----------------+
        |0x00 |                      Message header                           |
        +-----+---------------------------------------------------------------+
        |0x10 |                      Message payload                          |
        +-----+---------------------------------------------------------------+


    Message header::
        +-----+--------------+--------------+----------------+----------------+
        |Off  |    Byte 3    |    Byte 2    |      Byte 1    |     Byte 0     |
        +-----+--------------+--------------+----------------+----------------+
        |0x00 | Cert version |  Permission  |           Issue date            |
        +-----+--------------+--------------+---------------------------------+
        |0x04 |   Reserved   |    Command   |             Reserved            |
        +-----+--------------+--------------+---------------------------------+
        |0x08 |                                                               |
        |     |                 Unique ID (64 or 128 bits)                    |
        |0x.. |                                                               |
        +-----+---------------------------------------------------------------+

        The message header is common for all signed messages.

    """

    UNIQUE_ID_LEN = 8
    TAG = 0
    PAYLOAD_LENGTH = 0

    def __init__(
        self,
        family: FamilyRevision,
        cert_ver: int = 0,
        permissions: int = 0,
        issue_date: Optional[int] = None,
        cmd: int = 0,
        unique_id: Optional[bytes] = None,
        unique_id_len: int = UNIQUE_ID_LEN,
    ) -> None:
        """Message used to sign and send to device with EdgeLock.

        :param family: Family revision
        :param cert_ver: Certificate version, defaults to 0
        :param permissions: Certificate permission, to be used in future
            The stated permission must allow the operation requested by the signed message
            , defaults to 0
        :param issue_date: Issue date, defaults to None (Current date will be applied)
        :param cmd: Message command ID, defaults to 0
        :param unique_id: UUID of device, defaults to None
        :param unique_id_len: UUID length - 64 or 128 bits, defaults to 64 bits (8 bytes)
        """
        self.family = family
        self.cert_ver = cert_ver
        self.permissions = permissions
        now = datetime.datetime.now()
        self.issue_date = issue_date or (now.month << 12 | now.year)
        self.cmd = cmd
        self.unique_id_len = unique_id_len
        self.unique_id = unique_id or bytes(self.unique_id_len)
        if len(self.unique_id) > self.unique_id_len:
            logger.warning(
                f"The given UUID is longer than used {self.unique_id_len} "
                "bytes and will be truncated"
            )

    def __repr__(self) -> str:
        return f"Message, {MessageCommands.get_description(self.TAG, 'Base Class')}"

    def __str__(self) -> str:
        ret = repr(self) + ":\n"
        ret += (
            f"  Certificate version:{self.cert_ver}\n"
            f"  Permissions:        {hex(self.permissions)}\n"
            f"  Issue date:         {hex(self.issue_date)}\n"
            f"  UUID:               {self.unique_id.hex() if self.unique_id else 'Not Available'}"
        )
        return ret

    def __len__(self) -> int:
        """Returns the total length of a container.

        The length includes the fixed as well as the variable length part.
        """
        return self.fixed_length() + self.unique_id_len + self.payload_len

    @property
    def payload_len(self) -> int:
        """Message payload length in bytes."""
        return self.PAYLOAD_LENGTH

    @classmethod
    def format(cls) -> str:
        """Format of binary representation without UUID."""
        return (
            super().format()
            + UINT16  # Issue Date
            + UINT8  # Permission
            + UINT8  # Certificate version
            + UINT16  # Reserved to zero
            + UINT8  # Command
            + UINT8  # Reserved
        )

    def post_export(self, output_path: str) -> list[str]:
        """Post export.

        :param output_path: Base directory for exported files
        :raises SPSDKNotImplementedError: If post-export is not implemented for this message type
        """
        raise SPSDKNotImplementedError("Post export is not implemented for this message type")

    def verify(self) -> Verifier:
        """Verify general message properties."""
        name = (
            MessageCommands.get_label(self.cmd)
            if self.cmd in MessageCommands.tags()
            else hex(self.cmd)
        )
        ret = Verifier(f"Message: {name}")
        ret.add_record_bit_range("Certificate version", self.cert_ver, 8)
        ret.add_record_bit_range("Certificate permission", self.permissions, 8)
        ret.add_record_bit_range("Issue date", self.issue_date, 16)
        ret.add_record_enum("Command", self.cmd, MessageCommands)
        ret.add_record_bytes(
            "Unique ID",
            self.unique_id,
            min_length=self.unique_id_len,
            max_length=16,
        )
        return ret

    def export(self) -> bytes:
        """Exports message into to bytes array.

        :return: Bytes representation of message object.
        """
        msg = pack(
            self.format(),
            self.issue_date,
            self.permissions,
            self.cert_ver,
            RESERVED,
            self.cmd,
            RESERVED,
        )
        msg += self.unique_id[: self.unique_id_len]
        msg += self.export_payload()
        return msg

    @abstractmethod
    def export_payload(self) -> bytes:
        """Exports message payload to bytes array.

        :return: Bytes representation of message payload.
        """

    @classmethod
    def load_from_config(cls, config: Config, family: FamilyRevision) -> Self:
        """Converts the configuration option into an message object.

        "config" content of container configurations.

        :param config: Message configuration dictionaries.
        :param family: Family revision
        :return: Message object.
        """
        command = config.get_dict("command")
        if len(command) != 1:
            raise SPSDKError(f"Invalid config field command: {command}")
        msg_cls = cls.get_message_class(list(command.keys())[0])
        return msg_cls._load_from_config(config, family, cls)

    @classmethod
    def load_from_config_generic(cls, config: Config) -> tuple[int, int, Optional[int], bytes]:
        """Converts the general configuration option into an message object.

        "config" content of container configurations.

        :param config: Message configuration dictionaries.
        :return: Message object.
        """
        cert_ver = config.get_int("cert_version", 0)
        permission = config.get_int("cert_permission", 0)
        if "issue_date" in config:
            year, month = config.get_str("issue_date").split("-")
            issue_date = max(min(12, int(month)), 1) << 12 | int(year)
        else:
            issue_date = None

        uuid = bytes.fromhex(config.get("uuid", bytes(cls.UNIQUE_ID_LEN).hex()))
        return (cert_ver, permission, issue_date, uuid)

    @classmethod
    def _load_from_config(
        cls, config: Config, family: FamilyRevision, base_cls: type["Message"]
    ) -> Self:
        """Converts the configuration option into an message object.

        "config" content of container configurations.

        :param config: Message configuration dictionaries.
        :param family: Family revision for message configuration.
        :param base_cls: Base message class for configuration loading.
        :raises SPSDKError: Invalid configuration detected.
        :return: Message object.
        """
        raise SPSDKNotImplementedError("'_load_from_config' must be implemented in child class")

    def _create_general_config(self) -> Config:
        """Create configuration of the general parts of  Message.

        :return: Configuration dictionary.
        """
        assert isinstance(self.unique_id, bytes)
        cfg = Config()
        cfg["cert_version"] = self.cert_ver
        cfg["cert_permission"] = self.permissions
        cfg["issue_date"] = f"{(self.issue_date & 0xfff)}-{(self.issue_date>>12) & 0xf}"
        cfg["uuid"] = self.unique_id.hex()

        return cfg

    @abstractmethod
    def get_config(self) -> Config:
        """Create configuration of the Signed Message.

        :return: Configuration dictionary.
        """

    @classmethod
    def get_message_class(cls, cmd: str) -> Type[Self]:
        """Get the dedicated message class for command."""
        for var in globals():
            obj = globals()[var]
            if isclass(obj) and issubclass(obj, Message) and obj is not Message:
                assert issubclass(obj, Message)  # pylint: disable=assert-instance
                if MessageCommands.from_label(cmd) == obj.TAG:
                    return obj  # type: ignore

        raise SPSDKValueError(f"Command {cmd} is not supported.")

    @classmethod
    def parse(cls, data: bytes, family: Optional[FamilyRevision] = None) -> Self:
        """Parse input binary to the signed message object.

        :param data: Binary data with Container block to parse.
        :param family: Family revision context.
        :return: Object recreated from the binary data.
        """
        if family is None:
            raise SPSDKValueError("Family revision must be provided for parsing")
        (
            issue_date,  # issue Date
            permission,  # permission
            certificate_version,  # certificate version
            _,  # Reserved to zero
            command,  # Command
            _,  # Reserved
        ) = unpack(cls.format(), data[: cls.fixed_length()])

        uuid = data[cls.fixed_length() : cls.fixed_length() + cls.UNIQUE_ID_LEN]
        cmd_name = MessageCommands.get_label(command)
        msg_cls = cls.get_message_class(cmd_name)
        parsed_msg = msg_cls(
            family=family,
            cert_ver=certificate_version,
            permissions=permission,
            issue_date=issue_date,
            unique_id=uuid,
            unique_id_len=cls.UNIQUE_ID_LEN,
        )
        parsed_msg.parse_payload(data[cls.fixed_length() + cls.UNIQUE_ID_LEN :])
        return parsed_msg

    @abstractmethod
    def parse_payload(self, data: bytes) -> None:
        """Parse payload.

        :param data: Binary data with Payload to parse.
        """


class MessageV2(Message):
    """Class representing the Signed message version 2."""

    UNIQUE_ID_LEN = 16


class MessageReturnLifeCycle(Message):
    """Return life cycle request message class representation."""

    TAG = MessageCommands.RETURN_LIFECYCLE_UPDATE_REQ.tag
    PAYLOAD_LENGTH = 4

    def __init__(
        self,
        family: FamilyRevision,
        cert_ver: int = 0,
        permissions: int = 0,
        issue_date: Optional[int] = None,
        unique_id: Optional[bytes] = None,
        unique_id_len: int = Message.UNIQUE_ID_LEN,
        life_cycle: int = 0,
    ) -> None:
        """Message used to sign and send to device with EdgeLock.

        :param family: Family revision of the device
        :param cert_ver: Certificate version, defaults to 0
        :param permissions: Certificate permission, to be used in future
            The stated permission must allow the operation requested by the signed message
            , defaults to 0
        :param issue_date: Issue date, defaults to None (Current date will be applied)
        :param unique_id: UUID of device, defaults to None
        :param unique_id_len: UUID length - 64 or 128 bits, defaults to 64 bits (8 bytes)
        :param life_cycle: Requested life cycle, defaults to 0
        """
        super().__init__(
            family=family,
            cert_ver=cert_ver,
            permissions=permissions,
            issue_date=issue_date,
            cmd=self.TAG,
            unique_id=unique_id,
            unique_id_len=unique_id_len,
        )
        self.life_cycle = life_cycle

    def __str__(self) -> str:
        ret = super().__str__() + "\n"
        ret += f"  Life Cycle:         {hex(self.life_cycle)}"
        return ret

    def export_payload(self) -> bytes:
        """Exports message payload to bytes array.

        :return: Bytes representation of message payload.
        """
        return self.life_cycle.to_bytes(length=4, byteorder=Endianness.LITTLE.value)

    def parse_payload(self, data: bytes) -> None:
        """Parse payload.

        :param data: Binary data with Payload to parse.
        """
        self.life_cycle = int.from_bytes(data[:4], byteorder=Endianness.LITTLE.value)

    @classmethod
    def _load_from_config(
        cls, config: Config, family: FamilyRevision, base_cls: type[Message] = Message
    ) -> Self:
        """Converts the configuration option into an message object.

        "config" content of container configurations.

        :param config: Message configuration dictionaries.
        :param family: Family revision context.
        :param base_cls: Base message class for configuration loading.
        :raises SPSDKError: Invalid configuration detected.
        :return: Message object.
        """
        command = config.get_config("command")
        if len(command) != 1:
            raise SPSDKError(f"Invalid config field command: {command}")
        command_name = list(command.keys())[0]
        if MessageCommands.from_label(command_name) != MessageReturnLifeCycle.TAG:
            raise SPSDKError("Invalid configuration for Return Life Cycle Request command.")

        cert_ver, permission, issue_date, uuid = cls.load_from_config_generic(config)

        life_cycle = command.get_int("RETURN_LIFECYCLE_UPDATE_REQ")

        return cls(
            family=family,
            cert_ver=cert_ver,
            permissions=permission,
            issue_date=issue_date,
            unique_id=uuid,
            unique_id_len=base_cls.UNIQUE_ID_LEN,
            life_cycle=life_cycle,
        )

    def get_config(self) -> Config:
        """Create configuration of the Signed Message.

        :return: Configuration dictionary.
        """
        cfg = self._create_general_config()
        cmd_cfg = {}
        cmd_cfg[MessageCommands.get_label(self.TAG)] = self.life_cycle
        cfg["command"] = cmd_cfg

        return cfg

    def verify(self) -> Verifier:
        """Verify message properties."""
        ret = super().verify()
        ret.add_record_range("Life Cycle", self.life_cycle)
        return ret


class MessageWriteSecureFuse(Message):
    """Write secure fuse request message class representation."""

    TAG = MessageCommands.WRITE_SEC_FUSE_REQ.tag
    PAYLOAD_FORMAT = LITTLE_ENDIAN + UINT16 + UINT8 + UINT8

    def __init__(
        self,
        family: FamilyRevision,
        cert_ver: int = 0,
        permissions: int = 0,
        issue_date: Optional[int] = None,
        unique_id: Optional[bytes] = None,
        unique_id_len: int = Message.UNIQUE_ID_LEN,
        fuse_id: int = 0,
        length: int = 0,
        flags: int = 0,
        data: Optional[list[int]] = None,
    ) -> None:
        """Message used to sign and send to device with EdgeLock.

        :param family: Family revision of the device
        :param cert_ver: Certificate version, defaults to 0
        :param permissions: Certificate permission, to be used in future
            The stated permission must allow the operation requested by the signed message
            , defaults to 0
        :param issue_date: Issue date, defaults to None (Current date will be applied)
        :param unique_id: UUID of device, defaults to None
        :param unique_id_len: UUID length - 64 or 128 bits, defaults to 64 bits (8 bytes)
        :param fuse_id: Fuse ID, defaults to 0
        :param length: Fuse length, defaults to 0
        :param flags: Fuse flags, defaults to 0
        :param data: List of fuse values
        """
        super().__init__(
            family=family,
            cert_ver=cert_ver,
            permissions=permissions,
            issue_date=issue_date,
            cmd=self.TAG,
            unique_id=unique_id,
            unique_id_len=unique_id_len,
        )
        self.fuse_id = fuse_id
        self.length = length
        self.flags = flags
        self.fuse_data: list[int] = data or []

    def __str__(self) -> str:
        ret = super().__str__() + "\n"
        ret += f"  Fuse Index:         {hex(self.fuse_id)}, {self.fuse_id}\n"
        ret += f"  Fuse Length:        {self.length}\n"
        ret += f"  Fuse Flags:         {hex(self.flags)}\n"
        for i, data in enumerate(self.fuse_data):
            ret += f"    Fuse{i} Value:         0x{data:08X}"
        return ret

    @property
    def payload_len(self) -> int:
        """Message payload length in bytes."""
        return 4 + len(self.fuse_data) * 4

    def export_payload(self) -> bytes:
        """Exports message payload to bytes array.

        :return: Bytes representation of message payload.
        """
        payload = pack(self.PAYLOAD_FORMAT, self.fuse_id, self.length, self.flags)
        for data in self.fuse_data:
            payload += data.to_bytes(4, Endianness.LITTLE.value)
        return payload

    def parse_payload(self, data: bytes) -> None:
        """Parse payload.

        :param data: Binary data with Payload to parse.
        """
        self.fuse_id, self.length, self.flags = unpack(self.PAYLOAD_FORMAT, data[:4])
        self.fuse_data.clear()
        for i in range(self.length):
            self.fuse_data.append(
                int.from_bytes(data[4 + i * 4 : 8 + i * 4], Endianness.LITTLE.value)
            )

    @classmethod
    def _load_from_config(
        cls, config: Config, family: FamilyRevision, base_cls: type[Message] = Message
    ) -> Self:
        """Converts the configuration option into an message object.

        "config" content of container configurations.

        :param config: Message configuration dictionaries.
        :param family: Family revision context.
        :param base_cls: Base message class for configuration loading.
        :raises SPSDKError: Invalid configuration detected.
        :return: Message object.
        """
        command = config.get_config("command")
        if len(command) != 1:
            raise SPSDKError(f"Invalid config field command: {command}")
        command_name = list(command.keys())[0]
        if MessageCommands.from_label(command_name) != MessageWriteSecureFuse.TAG:
            raise SPSDKError("Invalid configuration for Write secure fuse Request command.")

        cert_ver, permission, issue_date, uuid = cls.load_from_config_generic(config)

        secure_fuse = command.get_config("WRITE_SEC_FUSE_REQ")
        fuse_id = secure_fuse.get_int("id")
        flags = secure_fuse.get_int("flags", 0)
        data_list = secure_fuse.get_list("data", [])
        data = []
        for x in data_list:
            data.append(value_to_int(x))
        length = len(data_list)
        return cls(
            family=family,
            cert_ver=cert_ver,
            permissions=permission,
            issue_date=issue_date,
            unique_id=uuid,
            unique_id_len=base_cls.UNIQUE_ID_LEN,
            fuse_id=fuse_id,
            length=length,
            flags=flags,
            data=data,
        )

    def get_config(self) -> Config:
        """Create configuration of the Signed Message.

        :return: Configuration dictionary.
        """
        cfg = self._create_general_config()
        write_fuse_cfg: dict[str, Any] = {}
        cmd_cfg = {}
        write_fuse_cfg["id"] = self.fuse_id
        write_fuse_cfg["flags"] = self.flags
        write_fuse_cfg["data"] = [f"0x{x:08X}" for x in self.fuse_data]

        cmd_cfg[MessageCommands.get_label(self.TAG)] = write_fuse_cfg
        cfg["command"] = cmd_cfg

        return cfg

    def verify(self) -> Verifier:
        """Verify message properties."""
        ret = super().verify()
        if self.fuse_data is None:
            ret.add_record("Fuse data", VerifierResult.ERROR, "Doesn't exists")
        else:
            ret.add_record_range("Fuse data count", len(self.fuse_data) != self.length)
            for i, val in enumerate(self.fuse_data):
                ret.add_record_bit_range(f"Data{i}", val)
        return ret


class MessageKeyStoreReprovisioningEnable(Message):
    """Key store reprovisioning enable request message class representation."""

    TAG = MessageCommands.KEYSTORE_REPROVISIONING_ENABLE_REQ.tag
    PAYLOAD_LENGTH = 12
    PAYLOAD_FORMAT = LITTLE_ENDIAN + UINT8 + UINT8 + UINT16 + UINT32 + UINT32

    FLAGS = 0  # 0 : HSM storage.
    TARGET = 0  # Target ELE

    def __init__(
        self,
        family: FamilyRevision,
        cert_ver: int = 0,
        permissions: int = 0,
        issue_date: Optional[int] = None,
        unique_id: Optional[bytes] = None,
        unique_id_len: int = Message.UNIQUE_ID_LEN,
        monotonic_counter: int = 0,
        user_sab_id: int = 0,
    ) -> None:
        """Key store reprovisioning enable signed message class init.

        :param family: Family revision
        :param cert_ver: Certificate version, defaults to 0
        :param permissions: Certificate permission, to be used in future
            The stated permission must allow the operation requested by the signed message
            , defaults to 0
        :param issue_date: Issue date, defaults to None (Current date will be applied)
        :param unique_id: UUID of device, defaults to None
        :param unique_id_len: UUID length - 64 or 128 bits, defaults to 64 bits (8 bytes)
        :param monotonic_counter: Monotonic counter value, defaults to 0
        :param user_sab_id: User SAB id, defaults to 0
        """
        super().__init__(
            family=family,
            cert_ver=cert_ver,
            permissions=permissions,
            issue_date=issue_date,
            cmd=self.TAG,
            unique_id=unique_id,
            unique_id_len=unique_id_len,
        )
        self.flags = self.FLAGS
        self.target = self.TARGET
        self.reserved = RESERVED
        self.monotonic_counter = monotonic_counter
        self.user_sab_id = user_sab_id

    def export_payload(self) -> bytes:
        """Exports message payload to bytes array.

        :return: Bytes representation of message payload.
        """
        return pack(
            self.PAYLOAD_FORMAT,
            self.flags,
            self.target,
            self.reserved,
            self.monotonic_counter,
            self.user_sab_id,
        )

    def parse_payload(self, data: bytes) -> None:
        """Parse payload.

        :param data: Binary data with Payload to parse.
        """
        self.flags, self.target, self.reserved, self.monotonic_counter, self.user_sab_id = unpack(
            self.PAYLOAD_FORMAT, data[: self.PAYLOAD_LENGTH]
        )

    def verify(self) -> Verifier:
        """Verify message properties."""
        ret = super().verify()
        ret.add_record("Flags", self.flags == self.FLAGS, self.flags)
        ret.add_record("Target", self.target == self.TARGET, self.target)
        ret.add_record("Reserved", self.reserved == RESERVED, self.reserved)
        ret.add_record_range("Monotonic counter", self.monotonic_counter)
        ret.add_record_bit_range("User SAB ID", self.user_sab_id)
        return ret

    def __str__(self) -> str:
        ret = super().__str__() + "\n"
        ret += (
            f"  Monotonic counter value: 0x{self.monotonic_counter:08X}, {self.monotonic_counter}\n"
        )
        ret += f"  User SAB id:             0x{self.user_sab_id:08X}, {self.user_sab_id}"
        return ret

    @classmethod
    def _load_from_config(
        cls, config: Config, family: FamilyRevision, base_cls: type[Message] = Message
    ) -> Self:
        """Converts the configuration option into an message object.

        "config" content of container configurations.

        :param config: Message configuration dictionaries.
        :param family: Family revision context.
        :param base_cls: Base message class for configuration loading.
        :raises SPSDKError: Invalid configuration detected.
        :return: Message object.
        """
        command = config.get_config("command")
        if len(command) != 1:
            raise SPSDKError(f"Invalid config field command: {command}")
        command_name = list(command.keys())[0]
        if MessageCommands.from_label(command_name) != cls.TAG:
            raise SPSDKError("Invalid configuration for Write secure fuse Request command.")

        cert_ver, permission, issue_date, uuid = cls.load_from_config_generic(config)

        keystore_repr_en = command.get_config("KEYSTORE_REPROVISIONING_ENABLE_REQ")
        monotonic_counter = keystore_repr_en.get_int("monotonic_counter", 0)
        user_sab_id = keystore_repr_en.get_int("user_sab_id", 0)
        return cls(
            family=family,
            cert_ver=cert_ver,
            permissions=permission,
            issue_date=issue_date,
            unique_id=uuid,
            unique_id_len=base_cls.UNIQUE_ID_LEN,
            monotonic_counter=monotonic_counter,
            user_sab_id=user_sab_id,
        )

    def get_config(self) -> Config:
        """Create configuration of the Signed Message.

        :return: Configuration dictionary.
        """
        cfg = self._create_general_config()
        keystore_repr_en_cfg: dict[str, Any] = {}
        cmd_cfg = {}
        keystore_repr_en_cfg["monotonic_counter"] = f"0x{self.monotonic_counter:08X}"
        keystore_repr_en_cfg["user_sab_id"] = f"0x{self.user_sab_id:08X}"

        cmd_cfg[MessageCommands.get_label(self.TAG)] = keystore_repr_en_cfg
        cfg["command"] = cmd_cfg

        return cfg


class MessageKeyExchange(Message):
    """Key exchange request message class representation with ECDH support."""

    TAG = MessageCommands.KEY_EXCHANGE_REQ.tag
    PAYLOAD_LENGTH = 27 * 4
    PAYLOAD_VERSION = 0x07
    PAYLOAD_FORMAT = (
        LITTLE_ENDIAN
        + UINT8  # TAG
        + UINT8  # Version
        + UINT16  # Reserved
        + UINT32  # Key store ID
        + UINT32  # Key exchange algorithm
        + UINT16  # Salt Flags
        + UINT16  # Derived key group
        + UINT16  # Derived key size bits
        + UINT16  # Derived key type
        + UINT32  # Derived key lifetime
        + UINT32  # Derived key usage
        + UINT32  # Derived key permitted algorithm
        + UINT32  # Derived key lifecycle
        + UINT32  # Derived key ID
        + UINT32  # Private key ID
        + "32s"  # Input peer public key digest word [0-7]
        + "32s"  # Input user fixed info digest word [0-7]
    )

    def __init__(
        self,
        family: FamilyRevision,
        cert_ver: int = 0,
        permissions: int = 0,
        issue_date: Optional[int] = None,
        unique_id: Optional[bytes] = None,
        unique_id_len: int = Message.UNIQUE_ID_LEN,
        key_store_id: int = 0,
        key_exchange_algorithm: KeyAlgorithm = KeyAlgorithm.HKDF_SHA256,
        salt_flags: int = 0,
        derived_key_grp: int = 0,
        derived_key_size_bits: int = 0,
        derived_key_type: KeyType = KeyType.AES,
        derived_key_lifetime: LifeTime = LifeTime.PERSISTENT,
        derived_key_usage: Optional[list[KeyUsage]] = None,
        derived_key_permitted_algorithm: KeyDerivationAlgorithm = KeyDerivationAlgorithm.HKDF_SHA256,
        derived_key_lifecycle: LifeCycle = LifeCycle.OPEN,
        derived_key_id: int = 0,
        private_key_id: int = 0,
        input_peer_public_key_digest: bytes = bytes(),
        input_user_fixed_info_digest: bytes = bytes(),
        oem_private_key: Optional[PrivateKeyEcc] = None,
        nxp_prod_ka_pub: Optional[PublicKeyEcc] = None,
    ) -> None:
        """Key exchange signed message class init with ECDH support.

        :param family: Family revision for the message
        :param cert_ver: Certificate version, defaults to 0
        :param permissions: Certificate permission, to be used in future
            The stated permission must allow the operation requested by the signed message
            , defaults to 0
        :param issue_date: Issue date, defaults to None (Current date will be applied)
        :param unique_id: UUID of device, defaults to None
        :param unique_id_len: UUID length - 64 or 128 bits, defaults to 64 bits (8 bytes)
        :param key_store_id: Key store ID where to store the derived key. It must be the key store ID
            related to the key management handle set in the command API, defaults to 0
        :param key_exchange_algorithm: Algorithm used by the key exchange process:

            | HKDF SHA256 0x09020109
            | HKDF SHA384 0x0902010A
            | , defaults to HKDF_SHA256

        :param salt_flags: Bit field indicating the requested operations:

            | Bit 0: Salt in step #1 (HKDF-extract) of HMAC based two-step key derivation process:
            | - 0: Use zeros salt;
            | - 1:Use peer public key hash as salt;
            | Bit 1: In case of ELE import, salt used to derive OEM_IMPORT_WRAP_SK and OEM_IMPORT_CMAC_SK:
            | - 0: Zeros string;
            | - 1: Device SRKH.
            | Bit 2 to 15: Reserved, defaults to 0

        :param derived_key_grp: Derived key group. 100 groups are available per key store. It must be a
            value in the range [0; 99]. Keys belonging to the same group can be managed through
            the Manage key group command, defaults to 0
        :param derived_key_size_bits:  Derived key size bits attribute, defaults to 0
        :param derived_key_type:

            +-------------------+-------+------------------+
            |Key type           | Value | Key size in bits |
            +===================+=======+==================+
            |   AES             |0x2400 | 128/192/256      |
            +-------------------+-------+------------------+
            |  HMAC             |0x1100 | 224/256/384/512  |
            +-------------------+-------+------------------+
            | OEM_IMPORT_MK_SK* |0x9200 | 128/192/256      |
            +-------------------+-------+------------------+

            , defaults to AES

        :param derived_key_lifetime: Derived key lifetime attribute

            | VOLATILE           0x00  Standard volatile key.
            | PERSISTENT         0x01  Standard persistent key.
            | PERMANENT          0xFF  Standard permanent key., defaults to PERSISTENT

        :param derived_key_usage: Derived key usage attribute.

            | Cache  0x00000004  Permission to cache the key in the ELE internal secure memory.
            |                     This usage is set by default by ELE FW for all keys generated or imported.
            | Encrypt  0x00000100  Permission to encrypt a message with the key. It could be cipher
            |                     encryption, AEAD encryption or asymmetric encryption operation.
            | Decrypt  0x00000200  Permission to decrypt a message with the key. It could be
            |                     cipher decryption, AEAD decryption or asymmetric decryption operation.
            | Sign message  0x00000400  Permission to sign a message with the key. It could be
            |                     a MAC generation or an asymmetric message signature operation.
            | Verify message  0x00000800  Permission to verify a message signature with the key.
            |                     It could be a MAC verification or an asymmetric message signature
            |                     verification operation.
            | Sign hash  0x00001000  Permission to sign a hashed message with the key
            |                     with an asymmetric signature operation. Setting this permission automatically
            |                     sets the Sign Message usage.
            | Verify hash  0x00002000  Permission to verify a hashed message signature with
            |                     the key with an asymmetric signature verification operation.
            |                     Setting this permission automatically sets the Verify Message usage.
            | Derive  0x00004000  Permission to derive other keys from this key.
            | , defaults to 0

        :param derived_key_permitted_algorithm: Derived key permitted algorithm attribute

            | HKDF SHA256 (HMAC two-step)  0x08000109
            | HKDF SHA384 (HMAC two-step)  0x0800010A, defaults to HKDF_SHA256

        :param derived_key_lifecycle: Derived key lifecycle attribute

            | CURRENT  0x00  Key is usable in current lifecycle.
            | OPEN  0x01  Key is usable in open lifecycle.
            | CLOSED  0x02  Key is usable in closed lifecycle.
            | CLOSED and LOCKED  0x04  Key is usable in closed and locked lifecycle.
            | , defaults to OPEN

        :param derived_key_id: Derived key ID attribute. It could be:

            - Wanted key identifier of the generated key: only supported by persistent
                and permanent keys;
            - 0x00000000 to let the FW chose the key identifier: supported by all
                keys (all persistence levels). , defaults to 0

        :param private_key_id: Identifier in the ELE key storage of the private key to use with the peer
            public key during the key agreement process, defaults to 0
        :param input_peer_public_key_digest: Input peer public key digest buffer.
            The algorithm used to generate the digest must be SHA256, defaults to list(8)
        :param input_user_fixed_info_digest: Input user fixed info digest buffer.
            The algorithm used to generate the digest must be SHA256, defaults to list(8)
        :param oem_private_key: OEM P256 private key for ECDH, defaults to None
        :param nxp_prod_ka_pub: NXP production key agreement public key, defaults to None
        """
        super().__init__(
            family=family,
            cert_ver=cert_ver,
            permissions=permissions,
            issue_date=issue_date,
            cmd=self.TAG,
            unique_id=unique_id,
            unique_id_len=unique_id_len,
        )
        self.tag = self.TAG
        self.version = self.PAYLOAD_VERSION
        self.reserved = RESERVED
        self.key_store_id = key_store_id
        self.key_exchange_algorithm = key_exchange_algorithm
        self.salt_flags = salt_flags
        self.derived_key_grp = derived_key_grp
        self.derived_key_size_bits = derived_key_size_bits
        self.derived_key_type = derived_key_type
        self.derived_key_lifetime = derived_key_lifetime
        self.derived_key_usage = derived_key_usage or []
        self.derived_key_permitted_algorithm = derived_key_permitted_algorithm
        self.derived_key_lifecycle = derived_key_lifecycle
        self.derived_key_id = derived_key_id
        self.private_key_id = private_key_id
        self.input_user_fixed_info_digest = input_user_fixed_info_digest

        # ECDH specific attributes
        self.oem_private_key = oem_private_key
        self.nxp_prod_ka_pub = nxp_prod_ka_pub

        # Derived keys storage
        self._shared_secret: Optional[bytes] = None
        self._oem_import_mk_sk: Optional[bytes] = None
        self._oem_import_wrap_sk: Optional[bytes] = None
        self._oem_import_cmac_sk: Optional[bytes] = None

        if input_peer_public_key_digest == bytes(32) and oem_private_key:
            oem_public_key = oem_private_key.get_public_key()
            # Calculate SHA256 hash using SPSDK crypto API
            self.input_peer_public_key_digest = oem_public_key.key_hash()
            msg = f"Calculated input_peer_public_key_digest: {self.input_peer_public_key_digest.hex()}"
            logger.info(msg)
        else:
            self.input_peer_public_key_digest = input_peer_public_key_digest

    def perform_ecdh_key_derivation(self, srkh: Optional[bytes] = None) -> None:
        """Perform ECDH key derivation following the C code flow.

        This method:
        1. Performs ECDH with NXP_PROD_KA_PUB to get shared secret
        2. Derives OEM_Import_MK_SK from shared secret using HKDF
        3. Derives OEM_Import_Wrap_SK and OEM_Import_CMAC_SK from OEM_Import_MK_SK

        :param srkh: Optional SRKH for salt in key derivation, defaults to None
        :raises SPSDKError: If ECDH keys are not provided or ECDH fails
        """
        if not self.oem_private_key or not self.nxp_prod_ka_pub:
            raise SPSDKError(
                "OEM private key and NXP production KA public key are required for ECDH"
            )

        try:

            self._shared_secret = self.oem_private_key.exchange(
                peer_public_key=self.nxp_prod_ka_pub
            )
            logger.info(f"ECDH shared secret: {self._shared_secret.hex()}")

            # Derive OEM_Import_MK_SK from shared secret using HKDF
            self._oem_import_mk_sk = hkdf(
                salt=bytes(32),  # No salt for first derivation
                ikm=self._shared_secret,
                info=b"",  # No info for first derivation
                length=32,
            )
            logger.info(f"Derived OEM_Import_MK_SK: {self._oem_import_mk_sk.hex()}")

            # Use SRKH as salt if provided and salt_flags bit 1 is set
            salt = srkh if (srkh and (self.salt_flags & 0x02)) else bytes(32)

            # Derive OEM_Import_Wrap_SK from OEM_Import_MK_SK
            self._oem_import_wrap_sk = hkdf(
                salt=salt,
                ikm=self._oem_import_mk_sk,
                info=b"oemelefwkeyimportwrap256",
                length=32,
            )
            logger.info(f"Derived OEM_Import_Wrap_SK: {self._oem_import_wrap_sk.hex()}")

            # Derive OEM_Import_CMAC_SK from OEM_Import_MK_SK
            self._oem_import_cmac_sk = hkdf(
                salt=salt,
                ikm=self._oem_import_mk_sk,
                info=b"oemelefwkeyimportcmac256",
                length=32,
            )
            logger.info(f"Derived OEM_Import_CMAC_SK: {self._oem_import_cmac_sk.hex()}")

        except Exception as exc:
            raise SPSDKError(f"ECDH key derivation failed: {str(exc)}") from exc

    @property
    def shared_secret(self) -> Optional[bytes]:
        """Get the ECDH shared secret."""
        return self._shared_secret

    @property
    def oem_import_mk_sk(self) -> Optional[bytes]:
        """Get the derived OEM_Import_MK_SK."""
        return self._oem_import_mk_sk

    @property
    def oem_import_wrap_sk(self) -> Optional[bytes]:
        """Get the derived OEM_Import_Wrap_SK."""
        return self._oem_import_wrap_sk

    @property
    def oem_import_cmac_sk(self) -> Optional[bytes]:
        """Get the derived OEM_Import_CMAC_SK."""
        return self._oem_import_cmac_sk

    def export_payload(self) -> bytes:
        """Exports message payload to bytes array.

        :return: Bytes representation of message payload.
        """
        derived_key_usage = 0
        for usage in self.derived_key_usage:
            derived_key_usage |= usage.tag
        return pack(
            self.PAYLOAD_FORMAT,
            self.tag,
            self.version,
            self.reserved,
            self.key_store_id,
            self.key_exchange_algorithm.tag,
            self.derived_key_grp,
            self.salt_flags,
            self.derived_key_type.tag,
            self.derived_key_size_bits,
            self.derived_key_lifetime.tag,
            derived_key_usage,
            self.derived_key_permitted_algorithm.tag,
            self.derived_key_lifecycle.tag,
            self.derived_key_id,
            self.private_key_id,
            self.input_peer_public_key_digest,
            self.input_user_fixed_info_digest,
        )

    def parse_payload(self, data: bytes) -> None:
        """Parse payload.

        :param data: Binary data with Payload to parse.
        """
        (
            self.tag,
            self.version,
            self.reserved,
            self.key_store_id,
            key_exchange_algorithm,
            self.derived_key_grp,
            self.salt_flags,
            derived_key_type,
            self.derived_key_size_bits,
            derived_key_lifetime,
            derived_key_usage,
            derived_key_permitted_algorithm,
            derived_key_lifecycle,
            self.derived_key_id,
            self.private_key_id,
            input_peer_public_key_digest,
            input_user_fixed_info_digest,
        ) = unpack(self.PAYLOAD_FORMAT, data[: self.PAYLOAD_LENGTH])

        # Do some post process
        self.key_exchange_algorithm = KeyAlgorithm.from_tag(key_exchange_algorithm)
        self.derived_key_type = KeyType.from_tag(derived_key_type)
        self.derived_key_lifetime = LifeTime.from_tag(derived_key_lifetime)
        self.derived_key_permitted_algorithm = KeyDerivationAlgorithm.from_tag(
            derived_key_permitted_algorithm
        )
        self.derived_key_lifecycle = LifeCycle.from_tag(derived_key_lifecycle)

        self.input_peer_public_key_digest = input_peer_public_key_digest
        self.input_user_fixed_info_digest = input_user_fixed_info_digest
        self.derived_key_usage.clear()
        for tag in KeyUsage.tags():
            if tag & derived_key_usage:
                self.derived_key_usage.append(KeyUsage.from_tag(tag))

    def verify(self) -> Verifier:
        """Verify message properties."""
        ret = super().verify()
        ret.add_record_range("KeyStore ID", self.key_store_id)
        ret.add_record_enum("Key exchange algorithm", self.key_exchange_algorithm, KeyAlgorithm)
        ret.add_record_range("Salt flags", self.salt_flags)
        ret.add_record_range("Derived key group", self.derived_key_grp)
        ret.add_record_range("Derived key bit size", self.derived_key_size_bits)
        ret.add_record_enum("Derived key type", self.derived_key_type, KeyType)
        ret.add_record_enum("Derived key life time", self.derived_key_lifetime, LifeTime)
        for key_usage in self.derived_key_usage:
            ret.add_record_enum(f"Derived key usage [{key_usage.label}]", key_usage, KeyUsage)
        ret.add_record_enum(
            "Derived key permitted algorithm",
            self.derived_key_permitted_algorithm,
            KeyDerivationAlgorithm,
        )
        ret.add_record_enum("Derived key life cycle", self.derived_key_lifecycle, LifeCycle)
        ret.add_record_range("Derived key ID", self.derived_key_id)
        ret.add_record_range("Private key ID", self.private_key_id)
        ret.add_record_bytes(
            "Input peer public key digest",
            self.input_user_fixed_info_digest,
            min_length=32,
            max_length=32,
        )
        ret.add_record_bytes(
            "Input user public fixed info digest",
            self.input_peer_public_key_digest,
            min_length=32,
            max_length=32,
        )

        # Verify ECDH keys if provided
        if self.oem_private_key:
            ret.add_record("OEM Private Key", VerifierResult.SUCCEEDED, "Provided")
        if self.nxp_prod_ka_pub:
            ret.add_record("NXP PROD KA Pub", VerifierResult.SUCCEEDED, "Provided")

        # Verify derived keys if ECDH was performed
        if self._shared_secret:
            ret.add_record_bytes(
                "ECDH Shared Secret", self._shared_secret, min_length=32, max_length=32
            )
        if self._oem_import_mk_sk:
            ret.add_record_bytes(
                "OEM Import MK SK", self._oem_import_mk_sk, min_length=32, max_length=32
            )
        if self._oem_import_wrap_sk:
            ret.add_record_bytes(
                "OEM Import Wrap SK", self._oem_import_wrap_sk, min_length=32, max_length=32
            )
        if self._oem_import_cmac_sk:
            ret.add_record_bytes(
                "OEM Import CMAC SK", self._oem_import_cmac_sk, min_length=32, max_length=32
            )

        return ret

    def __str__(self) -> str:
        ret = super().__str__() + "\n"
        ret += f"  KeyStore ID value: 0x{self.key_store_id:08X}, {self.key_store_id}\n"
        ret += f"  Key exchange algorithm value: {self.key_exchange_algorithm.label}\n"
        ret += f"  Salt flags value: 0x{self.salt_flags:08X}, {self.salt_flags}\n"
        ret += f"  Derived key group value: 0x{self.derived_key_grp:08X}, {self.derived_key_grp}\n"
        ret += f"  Derived key bit size value: 0x{self.derived_key_size_bits:08X}, {self.derived_key_size_bits}\n"
        ret += f"  Derived key type value: {self.derived_key_type.label}\n"
        ret += f"  Derived key life time value: {self.derived_key_lifetime.label}\n"
        ret += f"  Derived key usage value: {[x.label for x in self.derived_key_usage]}\n"
        ret += f"  Derived key permitted algorithm value: {self.derived_key_permitted_algorithm.label}\n"
        ret += f"  Derived key life cycle value: {self.derived_key_lifecycle.label}\n"
        ret += f"  Derived key ID value: 0x{self.derived_key_id:08X}, {self.derived_key_id}\n"
        ret += f"  Private key ID value: 0x{self.private_key_id:08X}, {self.private_key_id}\n"
        ret += f"  Input peer public key digest value: {self.input_peer_public_key_digest.hex()}\n"
        ret += f"  Input user public fixed info digest value: {self.input_peer_public_key_digest.hex()}\n"

        # Add ECDH information
        if self.oem_private_key:
            ret += "  OEM Private Key: Available\n"
        if self.nxp_prod_ka_pub:
            ret += f"  NXP Production KA Public Key: {self.nxp_prod_ka_pub}\n"
        if self._shared_secret:
            ret += f"  ECDH Shared Secret: {self._shared_secret.hex()}\n"
        if self._oem_import_mk_sk:
            ret += f"  OEM Import MK SK: {self._oem_import_mk_sk.hex()}\n"
        if self._oem_import_wrap_sk:
            ret += f"  OEM Import Wrap SK: {self._oem_import_wrap_sk.hex()}\n"
        if self._oem_import_cmac_sk:
            ret += f"  OEM Import CMAC SK: {self._oem_import_cmac_sk.hex()}\n"

        return ret

    @classmethod
    def _load_from_config(
        cls, config: Config, family: FamilyRevision, base_cls: type[Message] = Message
    ) -> Self:
        """Converts the configuration option into an message object.

        "config" content of container configurations.

        :param config: Message configuration dictionaries.
        :param family: Family revision context.
        :param base_cls: Base message class for configuration loading.
        :raises SPSDKError: Invalid configuration detected.
        :return: Message object.
        """
        command = config.get_config("command")
        if len(command) != 1:
            raise SPSDKError(f"Invalid config field command: {command}")
        command_name = list(command.keys())[0]
        if MessageCommands.from_label(command_name) != MessageKeyExchange.TAG:
            raise SPSDKError("Invalid configuration for Key Exchange Request command.")

        cert_ver, permission, issue_date, uuid = cls.load_from_config_generic(config)

        key_exchange = command.get_config("KEY_EXCHANGE_REQ")

        key_store_id = key_exchange.get_int("key_store_id", 0)
        key_exchange_algorithm = KeyAlgorithm.from_attr(
            key_exchange.get_str("key_exchange_algorithm", "HKDF SHA256")
        )
        salt_flags = key_exchange.get_int("salt_flags", 0)
        derived_key_grp = key_exchange.get_int("derived_key_grp", 0)
        derived_key_size_bits = key_exchange.get_int("derived_key_size_bits", 128)
        derived_key_type = KeyType.from_attr(key_exchange.get_str("derived_key_type", "AES"))
        derived_key_lifetime = LifeTime.from_attr(
            key_exchange.get_str("derived_key_lifetime", "PERSISTENT")
        )
        derived_key_usage = [
            KeyUsage.from_attr(x) for x in key_exchange.get_list("derived_key_usage", [])
        ]
        derived_key_permitted_algorithm = KeyDerivationAlgorithm.from_attr(
            key_exchange.get_str("derived_key_permitted_algorithm", "HKDF SHA256")
        )
        derived_key_lifecycle = LifeCycle.from_attr(
            key_exchange.get_str("derived_key_lifecycle", "OPEN")
        )
        derived_key_id = key_exchange.get_int("derived_key_id", 0)
        private_key_id = key_exchange.get_int("private_key_id", 0)
        input_peer_public_key_digest = key_exchange.load_symmetric_key(
            "input_peer_public_key_digest", expected_size=32, default=bytes(32)
        )
        input_user_fixed_info_digest = key_exchange.load_symmetric_key(
            "input_user_fixed_info_digest", expected_size=32, default=bytes(32)
        )

        # Load ECDH parameters if provided
        oem_private_key = None
        nxp_prod_ka_pub = None

        if "oem_private_key" in key_exchange:
            oem_private_key = PrivateKeyEcc.load(
                key_exchange.get_input_file_name("oem_private_key")
            )

        # If input_peer_public_key_digest is empty/zeros and we have oem_private_key, calculate it
        if input_peer_public_key_digest == bytes(32) and oem_private_key:

            oem_public_key = oem_private_key.get_public_key()
            input_peer_public_key_digest = oem_public_key.key_hash()
            msg = (
                "Calculated input_peer_public_key_digest from OEM private key"
                + f" during config loading {input_peer_public_key_digest.hex()}"
            )
            logger.info(msg)
            input_user_fixed_info_digest = key_exchange.load_symmetric_key(
                "input_user_fixed_info_digest", expected_size=32, default=bytes(32)
            )

        if "nxp_prod_ka_pub" in key_exchange:
            nxp_prod_ka_pub = PublicKeyEcc.load(key_exchange.get_input_file_name("nxp_prod_ka_pub"))

        ret = cls(
            family=family,
            cert_ver=cert_ver,
            permissions=permission,
            issue_date=issue_date,
            unique_id=uuid,
            unique_id_len=base_cls.UNIQUE_ID_LEN,
            key_store_id=key_store_id,
            key_exchange_algorithm=key_exchange_algorithm,
            salt_flags=salt_flags,
            derived_key_grp=derived_key_grp,
            derived_key_size_bits=derived_key_size_bits,
            derived_key_type=derived_key_type,
            derived_key_lifetime=derived_key_lifetime,
            derived_key_usage=derived_key_usage,
            derived_key_permitted_algorithm=derived_key_permitted_algorithm,
            derived_key_lifecycle=derived_key_lifecycle,
            derived_key_id=derived_key_id,
            private_key_id=private_key_id,
            input_peer_public_key_digest=input_peer_public_key_digest,
            input_user_fixed_info_digest=input_user_fixed_info_digest,
            oem_private_key=oem_private_key,
            nxp_prod_ka_pub=nxp_prod_ka_pub,
        )

        # Perform ECDH key derivation if both keys are provided
        if oem_private_key and nxp_prod_ka_pub:
            srkh = None
            if "srkh" in key_exchange:
                srkh = key_exchange.load_symmetric_key("srkh", expected_size=32)
            ret.perform_ecdh_key_derivation(srkh=srkh)
            logger.info("ECDH key derivation completed during configuration loading")

        return ret

    def get_config(self) -> Config:
        """Create configuration of the Signed Message.

        :return: Configuration dictionary.
        """
        cfg = self._create_general_config()
        key_exchange_cfg: dict[str, Any] = {}
        cmd_cfg = {}
        key_exchange_cfg["key_store_id"] = f"0x{self.key_store_id:08X}"
        key_exchange_cfg["key_exchange_algorithm"] = self.key_exchange_algorithm.label
        key_exchange_cfg["salt_flags"] = f"0x{self.salt_flags:08X}"
        key_exchange_cfg["derived_key_grp"] = self.derived_key_grp
        key_exchange_cfg["derived_key_size_bits"] = self.derived_key_size_bits
        key_exchange_cfg["derived_key_type"] = self.derived_key_type.label
        key_exchange_cfg["derived_key_lifetime"] = self.derived_key_lifetime.label
        key_exchange_cfg["derived_key_usage"] = [x.label for x in self.derived_key_usage]
        key_exchange_cfg["derived_key_permitted_algorithm"] = (
            self.derived_key_permitted_algorithm.label
        )
        key_exchange_cfg["derived_key_lifecycle"] = self.derived_key_lifecycle.label
        key_exchange_cfg["derived_key_id"] = self.derived_key_id
        key_exchange_cfg["private_key_id"] = self.private_key_id
        key_exchange_cfg["input_peer_public_key_digest"] = self.input_peer_public_key_digest.hex()
        key_exchange_cfg["input_user_fixed_info_digest"] = (
            self.input_user_fixed_info_digest.hex()
            if self.input_user_fixed_info_digest
            else bytes(32).hex()
        )
        cmd_cfg[MessageCommands.get_label(self.TAG)] = key_exchange_cfg
        cfg["command"] = cmd_cfg

        return cfg

    def get_derived_keys_info(self) -> dict[str, Optional[str]]:
        """Get information about derived keys for external use.

        :return: Dictionary containing hex representations of derived keys
        """
        return {
            "shared_secret": self._shared_secret.hex() if self._shared_secret else None,
            "oem_import_mk_sk": self._oem_import_mk_sk.hex() if self._oem_import_mk_sk else None,
            "oem_import_wrap_sk": (
                self._oem_import_wrap_sk.hex() if self._oem_import_wrap_sk else None
            ),
            "oem_import_cmac_sk": (
                self._oem_import_cmac_sk.hex() if self._oem_import_cmac_sk else None
            ),
        }

    def post_export(self, output_path: str) -> list[str]:
        """Export remaining derived keys to files.

        :param output_path: Base directory for exported files
        :return: List of exported file paths
        """
        return self.export_derived_keys(output_path)

    def export_derived_keys(self, output_dir: str = "./") -> list[str]:
        """Export derived keys to files.

        :param output_dir: Directory to save the key files
        :return: Dictionary mapping key names to file paths
        :raises SPSDKError: If ECDH has not been performed or output directory is invalid
        """
        if not self._shared_secret:
            raise SPSDKError("ECDH key derivation must be performed before exporting keys")

        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        exported_files = []

        key_data = {
            "shared_secret": self._shared_secret,
            "oem_import_mk_sk": self._oem_import_mk_sk,
            "oem_import_wrap_sk": self._oem_import_wrap_sk,
            "oem_import_cmac_sk": self._oem_import_cmac_sk,
        }

        for key_name, key_bytes in key_data.items():
            if key_bytes:
                file_path = os.path.join(output_dir, f"{key_name}.bin")
                with open(file_path, "wb") as f:
                    f.write(key_bytes)
                exported_files.append(file_path)
                logger.info(f"Exported {key_name} to {get_printable_path(file_path)}")

        return exported_files


class MessageDat(Message):
    """Debug authentication request message class representation."""

    TAG = MessageCommands.DAT_AUTHENTICATION_REQ.tag
    PAYLOAD_LENGTH = 32 + 2
    CHALLENGE_VECTOR_LEN = 32

    def __init__(
        self,
        family: FamilyRevision,
        cert_ver: int = 0,
        permissions: int = 0,
        issue_date: Optional[int] = None,
        unique_id: Optional[bytes] = None,
        unique_id_len: int = Message.UNIQUE_ID_LEN,
        challenge_vector: bytes = bytes(32),
        authentication_beacon: int = 0,
    ) -> None:
        """Message used to sign and send to device with EdgeLock.

        :param family: Family revision of the device
        :param cert_ver: Certificate version, defaults to 0
        :param permissions: Certificate permission, to be used in future
            The stated permission must allow the operation requested by the signed message
            , defaults to 0
        :param issue_date: Issue date, defaults to None (Current date will be applied)
        :param unique_id: UUID of device, defaults to None
        :param unique_id_len: UUID length - 64 or 128 bits, defaults to 64 bits (8 bytes)
        :param challenge_vector: 32 bytes of challenge request got's from device by DAC.
        :param authentication_beacon: Authentication beacon in range specified in authentication_beacon_length in bytes.
        """
        super().__init__(
            family=family,
            cert_ver=cert_ver,
            permissions=permissions,
            issue_date=issue_date,
            cmd=self.TAG,
            unique_id=unique_id,
            unique_id_len=unique_id_len,
        )

        self.challenge_vector = challenge_vector
        self.authentication_beacon = authentication_beacon
        authentication_beacon_length = get_db(family).get_int(
            DatabaseManager.DAT, "auth_beacon_length", 2
        )
        if authentication_beacon_length not in [2, 4]:
            raise SPSDKValueError(
                f"Invalid authentication beacon length: {authentication_beacon_length}"
            )
        self.authentication_beacon_length = authentication_beacon_length

    @property
    def payload_len(self) -> int:
        """Message payload length in bytes."""
        return 32 + self.authentication_beacon_length

    def __str__(self) -> str:
        ret = super().__str__() + "\n"
        ret += f"  Challenge Vector: {self.challenge_vector.hex()}"
        ret += f"  Authentication beacon: {self.authentication_beacon:08x}"
        return ret

    def export_payload(self) -> bytes:
        """Exports message payload to bytes array.

        :return: Bytes representation of message payload.
        """
        return self.challenge_vector[
            : self.CHALLENGE_VECTOR_LEN
        ] + self.authentication_beacon.to_bytes(
            length=self.authentication_beacon_length, byteorder=Endianness.LITTLE.value
        )

    def parse_payload(self, data: bytes) -> None:
        """Parse payload.

        :param data: Binary data with Payload to parse.
        """
        self.challenge_vector = data[: self.CHALLENGE_VECTOR_LEN]
        self.authentication_beacon = int.from_bytes(
            data[32 : 32 + self.authentication_beacon_length], byteorder=Endianness.LITTLE.value
        )

    @classmethod
    def _load_from_config(
        cls, config: Config, family: FamilyRevision, base_cls: type[Message] = Message
    ) -> Self:
        """Converts the configuration option into an message object.

        "config" content of container configurations.

        :param config: Message configuration dictionaries.
        :param family: Family revision context.
        :param base_cls: Base message class for configuration loading.
        :raises SPSDKError: Invalid configuration detected.
        :return: Message object.
        """
        command = config.get_config("command")
        if len(command) != 1:
            raise SPSDKError(f"Invalid config field command: {command}")
        command_name = list(command.keys())[0]
        if MessageCommands.from_label(command_name) != MessageDat.TAG:
            raise SPSDKError("Invalid configuration for DAT Request command.")

        cert_ver, permission, issue_date, uuid = cls.load_from_config_generic(config)

        dat_cfg = command.get_config("DAT_AUTHENTICATION_REQ")
        challenge_vector = dat_cfg.load_symmetric_key(
            "challenge_vector", MessageDat.CHALLENGE_VECTOR_LEN
        )
        authentication_beacon = dat_cfg.get_int("authentication_beacon", 0)

        return cls(
            family=family,
            cert_ver=cert_ver,
            permissions=permission,
            issue_date=issue_date,
            unique_id=uuid,
            unique_id_len=base_cls.UNIQUE_ID_LEN,
            challenge_vector=challenge_vector,
            authentication_beacon=authentication_beacon,
        )

    def get_config(self) -> Config:
        """Create configuration of the Signed Message.

        :return: Configuration dictionary.
        """
        cfg = self._create_general_config()
        cmd_cfg = {}
        dat_cfg = {
            "challenge_vector": self.challenge_vector.hex(),
            "authentication_beacon": self.authentication_beacon,
        }
        cmd_cfg[MessageCommands.get_label(self.TAG)] = dat_cfg
        cfg["command"] = cmd_cfg

        return cfg

    def verify(self) -> Verifier:
        """Verify message properties."""
        ret = super().verify()
        ret.add_record_bytes(
            "Challenge Vector",
            self.challenge_vector,
            min_length=self.CHALLENGE_VECTOR_LEN,
            max_length=self.CHALLENGE_VECTOR_LEN,
        )
        ret.add_record_range(
            "Authentication Beacon",
            self.authentication_beacon,
            min_val=0,
            max_val=(1 << self.authentication_beacon_length * 8) - 1,
        )
        return ret


class SignedMessageContainer(AHABContainerBase):
    """Class representing the Signed message container.

    DAT Container::

        +-----+--------------+--------------+----------------+----------------+
        |Off  |    Byte 3    |    Byte 2    |      Byte 1    |     Byte 0     |
        +-----+--------------+--------------+----------------+----------------+
        |0x00 |    Tag       | Length (MSB) | Length (LSB)   |     Version    |
        +-----+--------------+--------------+----------------+----------------+
        |0x04 |                          Flags                                |
        +-----+--------------+--------------+---------------------------------+
        |0x08 |   Reserved   | Fuse version |       Software version          |
        +-----+--------------+--------------+---------------------------------+
        |0x10 |                      Signature Block                          |
        +-----+---------------------------------------------------------------+

    Signed Message::

        +-----+--------------+--------------+----------------+----------------+
        |Off  |    Byte 3    |    Byte 2    |      Byte 1    |     Byte 0     |
        +-----+--------------+--------------+----------------+----------------+
        |0x00 |    Tag       | Length (MSB) | Length (LSB)   |     Version    |
        +-----+--------------+--------------+----------------+----------------+
        |0x04 |                          Flags                                |
        +-----+--------------+--------------+---------------------------------+
        |0x08 |   Reserved   | Fuse version |       Software version          |
        +-----+--------------+--------------+---------------------------------+
        |0x10 |                    Message descriptor                         |
        +-----+---------------------------------------------------------------+
        |0x34 |                      Message header                           |
        +-----+---------------------------------------------------------------+
        |0x44 |                      Message payload                          |
        +-----+---------------------------------------------------------------+
        |0xXX |                      Signature Block                          |
        +-----+---------------------------------------------------------------+

    Message descriptor::
        +-----+--------------+--------------+----------------+----------------+
        |Off  |    Byte 3    |    Byte 2    |      Byte 1    |     Byte 0     |
        +-----+--------------+--------------+----------------+----------------+
        |0x00 |                   Reserved                   |      Flags     |
        +-----+----------------------------------------------+----------------+
        |0x04 |                       IV (256 bits)                           |
        +-----+---------------------------------------------------------------+

    """

    TAG = SignedMessageTags.SIGNED_MSG.tag
    ENCRYPT_IV_LEN = 32
    NAME = "Signed Message"
    SIGNATURE_BLOCK = SignatureBlock
    MESSAGE_TYPE = Message

    def __init__(
        self,
        chip_config: AhabChipConfig,
        flags: int = 0,
        fuse_version: int = 0,
        sw_version: int = 0,
        message: Optional[Union[Message, MessageV2]] = None,
        signature_block: Optional[Union[SignatureBlock, SignatureBlockV2]] = None,
        encrypt_iv: Optional[bytes] = None,
    ):
        """Class object initializer.

        :chip_config: Chip configuration for AHAB.
        :param flags: flags.
        :param fuse_version: value must be equal to or greater than the version
            stored in the fuses to allow loading this container.
        :param sw_version: used by PHBC (Privileged Host Boot Companion) to select
            between multiple images with same fuse version field.
        :param message: Message command to be signed.
        :param signature_block: signature block.
        :param encrypt_iv: Encryption Initial Vector - if defined the encryption is used.
        """
        super().__init__(
            chip_config=chip_config,
            flags=flags,
            fuse_version=fuse_version,
            sw_version=sw_version,
            signature_block=signature_block,
        )
        self.message = message
        self.encrypt_iv = encrypt_iv

    def __eq__(self, other: object) -> bool:
        if isinstance(other, type(self)):
            if super().__eq__(other) and self.message == other.message:
                return True

        return False

    def __repr__(self) -> str:
        return f"Signed Message, {'Encrypted' if self.encrypt_iv else 'Plain'}"

    def __str__(self) -> str:
        return (
            f"  Flags:              {hex(self.flags)}\n"
            f"  Fuse version:       {hex(self.fuse_version)}\n"
            f"  SW version:         {hex(self.sw_version)}\n"
            f"  Signature Block:\n{str(self.signature_block)}\n"
            f"  Message:\n{str(self.message)}\n"
            f"  Encryption IV:      {self.encrypt_iv.hex() if self.encrypt_iv else 'Not Available'}"
        )

    @property
    def _signature_block_offset(self) -> int:
        """Returns current signature block offset.

        :return: Offset in bytes of Signature block.
        """
        # Constant size of Container header + Image array Entry table
        assert isinstance(self.message, Message)
        return calcsize(self.format()) + len(self.message)

    def __len__(self) -> int:
        """Get total length of AHAB container.

        :return: Size in bytes of Message.
        """
        return (
            self._signature_block_offset + align(len(self.signature_block), CONTAINER_ALIGNMENT)
            if self.signature_block
            else 0
        )

    @classmethod
    def format(cls) -> str:
        """Format of binary representation."""
        return (
            super().format()
            + UINT8  # Descriptor Flags
            + UINT8  # Reserved
            + UINT16  # Reserved
            + "32s"  # IV - Initial Vector if encryption is enabled
        )

    def update_fields(self) -> None:
        """Updates all volatile information in whole container structure.

        :raises SPSDKError: When inconsistent image array length is detected.
        """
        # 0. Update the signature block to get overall size of it if used
        if self.signature_block:
            self.signature_block.update_fields()
            # 1. Update length
            self.length = len(self)
            # 2. Sign the image header
            if self.flag_srk_set != FlagsSrkSet.NONE:
                assert isinstance(self.signature_block.signature, ContainerSignature)
                self.signature_block.sign_itself(self.get_signature_data())
        else:
            # 0. Update length
            self.length = len(self)

    def _export(self) -> bytes:
        """Export raw data without updates fields into bytes.

        :return: bytes representing container header content including the signature block.
        """
        signed_message = pack(
            self.format(),
            self.version,
            len(self),
            self.tag,
            self.flags,
            self.sw_version,
            self.fuse_version,
            RESERVED,
            self._signature_block_offset,
            RESERVED,  # Reserved field
            1 if self.encrypt_iv else 0,
            RESERVED,
            RESERVED,
            self.encrypt_iv if self.encrypt_iv else bytes(32),
        )
        # Add Message Header + Message Payload
        assert isinstance(self.message, Message)
        signed_message += self.message.export()
        # Add Signature Block
        if self.signature_block:
            signed_message += align_block(self.signature_block.export(), CONTAINER_ALIGNMENT)
        return signed_message

    def export(self) -> bytes:
        """Export the signed image into one chunk.

        :raises SPSDKValueError: if the number of images doesn't correspond the the number of
            entries in image array info.
        :return: images exported into single binary
        """
        return self._export()

    def verify(self) -> Verifier:
        """Verify message properties."""
        ret = self._verify()
        if self.encrypt_iv:
            ret.add_record_bytes(
                "Encryption initialization vector", self.encrypt_iv, min_length=32, max_length=32
            )
        else:
            ret.add_record("Encryption initialization vector", VerifierResult.SUCCEEDED, "Not used")
        if self.message is None:
            ret.add_record("Message", VerifierResult.ERROR, "Doesn't exists")
        else:
            ret.add_child(self.message.verify())

        return ret

    @classmethod
    def parse(cls, data: bytes, chip_config: AhabChipConfig) -> Self:  # type: ignore # pylint: disable=arguments-differ
        """Parse input binary to the signed message object.

        :param data: Binary data with Container block to parse.
        :param chip_config: Ahab image chip configuration.
        :return: The Signed Message Container
        """
        cls.check_container_head(data)
        image_format = cls.format()
        (
            _,  # version
            container_length,
            _,  # tag
            flags,
            sw_version,
            fuse_version,
            _,  # number_of_images
            signature_block_offset,
            _,  # reserved
            descriptor_flags,
            _,  # reserved
            _,  # reserved
            iv,
        ) = unpack(image_format, data[: cls.fixed_length()])

        ret = cls(
            chip_config=chip_config,
            flags=flags,
            fuse_version=fuse_version,
            sw_version=sw_version,
            message=cls.MESSAGE_TYPE.parse(
                data[cls.fixed_length() : signature_block_offset], family=chip_config.family
            ),
            encrypt_iv=iv if bool(descriptor_flags & 0x01) else None,
        )
        ret.length = container_length
        ret.signature_block = cls.SIGNATURE_BLOCK.parse(
            data[signature_block_offset:], ret.chip_config
        )
        return ret

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the Signed Message.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        cfg = self._create_config(0, data_path)
        cfg["output"] = "N/A"

        assert isinstance(self.message, Message)
        cfg["message"] = self.message.get_config()

        return cfg

    @classmethod
    def load_from_config(cls, chip_config: AhabChipConfig, config: Config) -> Self:
        """Converts the configuration option into an Signed message object.

        "config" content of container configurations.

        :param chip_config: Ahab chip configuration.
        :param config: Signed Message configuration dictionaries.
        :return: Message object.
        """
        signed_msg = cls(chip_config)
        signed_msg.load_from_config_generic(config)

        message = config.get_config("message")

        signed_msg.message = cls.MESSAGE_TYPE.load_from_config(message, chip_config.family)

        return signed_msg

    def image_info(self) -> BinaryImage:
        """Get Image info object.

        :return: Signed Message Info object.
        """
        assert isinstance(self.message, Message)
        ret = BinaryImage(
            name="Signed Message",
            size=len(self),
            offset=0,
            binary=self.export(),
            description=(f"Signed Message for {MessageCommands.get_label(self.message.TAG)}"),
        )
        return ret

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get list of validation schemas.

        :param family: Family for which the validation schema should be generated.
        :return: Validation list of schemas.
        """
        sch = get_schema_file(DatabaseManager.SIGNED_MSG)
        sch_family = get_schema_file("general")["family"]
        update_validation_schema_family(
            sch_family["properties"], SignedMessage.get_supported_families(), family
        )
        return [sch_family, sch["signed_message"]]


class SignedMessageContainerV2(SignedMessageContainer):
    """Class representing the Signed message container V2."""

    VERSION = 0x02
    SIGNATURE_BLOCK: TypeAlias = SignatureBlockV2
    MESSAGE_TYPE: TypeAlias = MessageV2

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get list of validation schemas.

        :param family: Family for which the validation schema should be generated.
        :return: Validation list of schemas.
        """
        db = get_db(family)
        container_type = db.get_list(DatabaseManager.AHAB, "container_types", [])
        hide_force_container_type = len(container_type) <= 1
        container_type_2 = 2 in container_type
        certificate_supported = "certificate_supported" in db.get_list(
            DatabaseManager.AHAB, "sub_features", []
        )
        sch = get_schema_file(DatabaseManager.SIGNED_MSG)
        sch_family = get_schema_file("general")["family"]
        update_validation_schema_family(
            sch_family["properties"], SignedMessage.get_supported_families(), family
        )

        sch["signed_message"]["properties"]["container_version"][
            "skip_in_template"
        ] = hide_force_container_type

        if not certificate_supported:
            sch["signed_message"]["properties"].pop("certificate")
        if container_type_2:
            sch["signed_message"]["properties"]["check_all_signatures"]["skip_in_template"] = False
            sch["signed_message"]["properties"]["srk_table"]["properties"]["srk_table_#2"][
                "skip_in_template"
            ] = False
            sch["signed_message"]["properties"]["signer_#2"]["skip_in_template"] = False
        return [sch_family, sch["signed_message"]]


class SignedMessage(FeatureBaseClass):
    """Signed message class."""

    FEATURE = DatabaseManager.AHAB

    def __init__(
        self,
        family: FamilyRevision,
        signed_msg_container: Optional[
            Union[SignedMessageContainer, SignedMessageContainerV2]
        ] = None,
    ) -> None:
        """AHAB Image constructor.

        :param family: Name of device family.
        :param ahab_containers: _description_, defaults to None
        :raises SPSDKValueError: Invalid input configuration.
        """
        self.chip_config = create_chip_config(family=family)
        self.signed_msg_container = signed_msg_container
        self._container_type: Optional[
            Union[Type[SignedMessageContainer], Type[SignedMessageContainerV2]]
        ] = None
        self.db = get_db(family)

    @property
    def family(self) -> FamilyRevision:
        """Just public family member."""
        return self.chip_config.family

    @family.setter
    def family(self, value: FamilyRevision) -> None:
        """Just public family member."""
        self.chip_config.family = value

    @property
    def container_type(self) -> Union[Type[SignedMessageContainer], Type[SignedMessageContainerV2]]:
        """Get container class type."""
        if self._container_type is None:
            if self.signed_msg_container is None:
                raise SPSDKError("Can't determine the Signed Message Container type.")
            self._container_type = type(self.signed_msg_container)
        return self._container_type

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, type(self))
            and super().__eq__(other)
            and self.signed_msg_container == other.signed_msg_container
            and self.chip_config == other.chip_config
        )

    def __repr__(self) -> str:
        return (
            "Signed Message, "
            f"{self.signed_msg_container.__repr__() if self.signed_msg_container else 'Not specified'}"
        )

    def __str__(self) -> str:
        ret = "Signed message:\n"
        if self.signed_msg_container:
            ret += str(self.signed_msg_container)
        else:
            ret += "Signed message container is not specified."
        return ret

    def __len__(self) -> int:
        """Get maximal size of AHAB Image.

        :return: Size in Bytes of AHAB Image.
        """
        if self.signed_msg_container:
            return len(self.signed_msg_container)
        return 0

    def update_fields(self) -> None:
        """Automatically updates all volatile fields in every Signed message container."""
        if self.signed_msg_container:
            self.signed_msg_container.update_fields()

    def export(self) -> bytes:
        """Export Signed message image.

        :return: Signed message image.
        """
        self.verify().validate()
        return self.image_info().export()

    def post_export(self, output_path: str) -> list[str]:
        """Post export artifacts.

        :param output_path: Path to export artifacts
        :return: List of post export artifacts
        """
        assert isinstance(
            self.signed_msg_container, (SignedMessageContainer, SignedMessageContainerV2)
        ), "Invalid container type"
        assert isinstance(
            self.signed_msg_container.message, (Message, MessageV2)
        ), "Invalid message type"
        return self.signed_msg_container.message.post_export(output_path)

    def image_info(self) -> BinaryImage:
        """Get Image info object."""
        ret = BinaryImage(
            name="Signed Message Image",
            size=len(self),
            alignment=CONTAINER_ALIGNMENT,
            offset=0,
            description=f"Signed Message Image for {self.chip_config.family}",
            pattern=BinaryPattern("zeros"),
        )
        if self.signed_msg_container:
            ret.add_image(self.signed_msg_container.image_info())

        return ret

    @classmethod
    def pre_parse_verify(cls, data: bytes) -> Verifier:
        """Pre-Parse verify of AHAB container.

        :param data: Binary data with Container block to pre-parse.
        :return: Verifier of pre-parsed binary data.
        """
        try:
            return cls._parse_signed_message_type(data).pre_parse_verify(data)
        except SPSDKError as exc:
            ver = Verifier("Signed message")
            ver.add_record("Container type", VerifierResult.ERROR, str(exc))
            return ver

    def verify(self) -> Verifier:
        """Verifier object data."""
        ret = Verifier("Signed Message Image", description=str(self))
        if self.signed_msg_container:
            ret.add_child(self.signed_msg_container.verify())
        else:
            ret.add_record("Signed message Container", VerifierResult.ERROR, "Missing")

        return ret

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the Signed Message.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        assert isinstance(self.signed_msg_container, SignedMessageContainer)
        cfg = self.signed_msg_container.get_config(data_path)
        cfg["family"] = self.chip_config.family.name
        cfg["revision"] = self.chip_config.family.revision
        return cfg

    @classmethod
    def get_validation_schemas_from_cfg(cls, config: Config) -> list[dict[str, Any]]:
        """Get validation schema based on configuration.

        :param config: Valid configuration
        :return: Validation schemas
        """
        config.check(cls.get_validation_schemas_basic())
        family = FamilyRevision.load_from_config(config)
        signed_msg_class = cls._get_signed_message_class(family)
        return signed_msg_class.get_validation_schemas(family)

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Converts the configuration option into an Signed message object.

        "config" content of container configurations.

        :param config: Signed Message configuration dictionaries.
        :return: Signed message object.
        """
        family = FamilyRevision.load_from_config(config)
        signed_msg_class = cls._get_signed_message_class(family)

        ret = cls(family=family)
        ret.signed_msg_container = signed_msg_class.load_from_config(ret.chip_config, config)
        return ret

    @classmethod
    def parse(cls, data: bytes, family: Optional[FamilyRevision] = None) -> Self:
        """Parse input binary chunk to the container object.

        :param data: Input binary data to parse
        :param family: The MCU family

        :raises SPSDKError: No AHAB container found in binary data.
        """
        if family is None:
            raise SPSDKValueError("Missing family parameter to parse method of signed message")
        ret = cls(family)
        signed_msg_class = ret._parse_signed_message_type(data)
        signed_message = signed_msg_class.parse(data, ret.chip_config)
        ret.signed_msg_container = signed_message

        return ret

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get list of validation schemas.

        :param family: Family for which the validation schema should be generated.
        :return: Validation list of schemas.
        """
        return cls._get_signed_message_class(family=family).get_validation_schemas(family=family)

    @property
    def srk_count(self) -> int:
        """Get  count of used SRKs."""
        if self.signed_msg_container:
            return self.signed_msg_container.srk_count
        return 0

    def get_srk_hash(self, srk_id: int = 0) -> bytes:
        """Get SRK hash.

        :param srk_id: ID of SRK table in case of using multiple Signatures, default is 0.
        :return: SHA256 hash of SRK table.
        """
        if self.signed_msg_container:
            return self.signed_msg_container.get_srk_hash(srk_id)
        return b""

    @classmethod
    def get_config_template(
        cls, family: FamilyRevision, message: Optional[MessageCommands] = None
    ) -> str:
        """Get AHAB configuration template.

        :param family: Family for which the template should be generated.
        :param message: Generate the template just for one message type, if not used , its generated for all messages
        :return: Dictionary of individual templates (key is name of template, value is template itself).
        """
        val_schemas = cls.get_validation_schemas(family=family)
        if message:
            for cmd_sch in val_schemas[1]["properties"]["message"]["properties"]["command"][
                "oneOf"
            ]:
                cmd_sch["skip_in_template"] = bool(message.label not in cmd_sch["properties"])

        return CommentedConfig(
            f"Signed message Configuration template for {family}.", val_schemas
        ).get_template()

    @staticmethod
    def _parse_signed_message_type(
        data: bytes,
    ) -> Union[Type[SignedMessageContainer], Type[SignedMessageContainerV2]]:
        """Recognize container type from binary data.

        :param data: Data of signed message.
        :raises SPSDKParsingError: In case of invalid data detected.
        :return: Container type
        """
        if not SignedMessageContainer.check_container_head(data).has_errors:
            logger.debug("Detected Signed message classic version in parsed data.")
            return SignedMessageContainer
        if not SignedMessageContainerV2.check_container_head(data).has_errors:
            logger.debug("Detected Signed message PQC version in parsed data.")
            return SignedMessageContainerV2

        raise SPSDKParsingError("Cannot determine the container type")

    @staticmethod
    def _get_signed_message_class(
        family: FamilyRevision,
    ) -> Union[Type[SignedMessageContainer], Type[SignedMessageContainerV2]]:
        """Recognize container type from binary data.

        :param data: Binary data
        :return: Container type
        """
        db = get_db(family)
        container_type_2 = bool(2 in db.get_list(DatabaseManager.AHAB, "container_types", []))
        if container_type_2:
            logger.debug("Chosen Signed message PQC version.")
            return SignedMessageContainerV2

        logger.debug("Chosen Signed message classic version.")
        return SignedMessageContainer
