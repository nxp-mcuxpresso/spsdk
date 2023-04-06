#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Implementation of raw AHAB container support.

This module represents a generic AHAB container implementation. You can set the
containers values at will. From this perspective, consult with your reference
manual of your device for allowed values.
"""
import datetime
import logging
from inspect import isclass
from struct import calcsize, pack, unpack
from typing import Any, Dict, List, Optional, Tuple, Type

from ruamel.yaml import CommentedMap as CM

from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.image.ahab import SIGNED_MSG_SCH_FILE
from spsdk.image.ahab.ahab_abstract_interfaces import LITTLE_ENDIAN, Container
from spsdk.image.ahab.ahab_container import (
    CONTAINER_ALIGNMENT,
    RESERVED,
    UINT8,
    UINT16,
    AHABContainerBase,
    AHABImage,
    SignatureBlock,
)
from spsdk.utils.easy_enum import Enum
from spsdk.utils.images import BinaryImage
from spsdk.utils.misc import align, align_block, check_range, value_to_bytes, value_to_int
from spsdk.utils.schema_validator import ConfigTemplate, ValidationSchemas

logger = logging.getLogger(__name__)


class SignedMessageTags(Enum):
    """Signed message container related tags."""

    SIGNED_MSG = (0x89, "Signed message.")


class MessageCommands(Enum):
    """Signed messages commands."""

    RETURN_LIFECYCLE_UPDATE_REQ = (0xA0, "Return lifecycle update request.")
    WRITE_SEC_FUSE_REQ = (0x91, "Write secure fuse request.")


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
        |0x08 |                 Unique ID (Lower 32 bits)                     |
        +-----+---------------------------------------------------------------+
        |0x0c |                 Unique ID (Upper 32 bits)                     |
        +-----+---------------------------------------------------------------+

        The message header is common for all signed messages.

    """

    UNIQUE_ID_LEN = 8
    TAG = 0

    def __init__(
        self,
        cert_ver: int = 0,
        permissions: int = 0,
        issue_date: Optional[int] = None,
        cmd: int = 0,
        unique_id: Optional[bytes] = None,
        payload: Optional[bytes] = None,
    ) -> None:
        """Message used to sign and send to device with EdgeLock.

        :param cert_ver: Certificate version, defaults to 0
        :param permissions: Certificate permission, to be used in future
            The stated permission must allow the operation requested by the signed message
            , defaults to 0
        :param issue_date: Issue date, defaults to None (Current date will be applied)
        :param cmd: Message command ID, defaults to 0
        :param unique_id: UUID of device (least 64 bits is used), defaults to None
        :param payload: Command payload data, defaults to None
        """
        self.cert_ver = cert_ver
        self.permissions = permissions
        now = datetime.datetime.now()
        self.issue_date = issue_date or (now.month << 12 | now.year)
        self.cmd = cmd
        self.unique_id = unique_id or b""
        self.payload = payload or b""

    # We need to extend the format, as the parent provides only endianness,
    # and length.
    @classmethod
    def _format(cls) -> str:
        return (
            super()._format()
            + UINT16  # Issue Date
            + UINT8  # Permission
            + UINT8  # Certificate version
            + UINT16  # Reserved to zero
            + UINT8  # Command
            + UINT8  # Reserved
            + "4s"  # Unique ID (Lower 32 bits)
            + "4s"  # Unique ID (Upper 32 bits)
        )

    def validate(self) -> None:
        """Validate general message properties."""
        if self.cert_ver is None or not check_range(self.cert_ver, end=(1 << 8) - 1):
            raise SPSDKValueError(
                f"Message: Invalid certificate version: {hex(self.cert_ver) if self.cert_ver else 'None'}"
            )

        if self.permissions is None or not check_range(self.permissions, end=(1 << 8) - 1):
            raise SPSDKValueError(
                f"Message: Invalid certificate permission: {hex(self.permissions) if self.permissions else 'None'}"
            )

        if self.issue_date is None or not check_range(self.issue_date, start=1, end=(1 << 16) - 1):
            raise SPSDKValueError(
                f"Message: Invalid issue date: {hex(self.issue_date) if self.issue_date else 'None'}"
            )

        if self.cmd is None or MessageCommands.get(self.cmd) is None:
            raise SPSDKValueError(
                f"Message: Invalid command: {hex(self.cmd) if self.cmd else 'None'}"
            )

        if self.unique_id is None or len(self.unique_id) < Message.UNIQUE_ID_LEN:
            raise SPSDKValueError(
                f"Message: Invalid unique ID: {self.unique_id.hex() if self.unique_id else 'None'}"
            )

        if (
            self.payload is None
            or not len(self.payload)
            or len(self.payload) != align(len(self.payload), alignment=4)
        ):
            raise SPSDKValueError(
                f"Message: Invalid payload: {self.payload.hex() if self.payload else 'None'}"
            )

    def export(self) -> bytes:
        """Exports message into to bytes array.

        :return: Bytes representation of message object.
        """
        msg = pack(
            self._format(),
            self.issue_date,
            self.permissions,
            self.cert_ver,
            RESERVED,
            self.cmd,
            RESERVED,
            self.unique_id[:4],
            self.unique_id[4:8],
        )
        msg += self.export_payload()
        return msg

    def export_payload(self) -> bytes:
        """Exports message payload to bytes array.

        :return: Bytes representation of message payload.
        """
        return align_block(self.payload, alignment=4)

    @staticmethod
    def load_from_config(config: Dict[str, Any]) -> "Message":
        """Converts the configuration option into an message object.

        "config" content of container configurations.

        :param config: Message configuration dictionaries.
        :return: Message object.
        """
        command = config.get("command")
        assert command and len(command) == 1
        msg_cls = Message.getMessageClass(list(command.keys())[0])
        return msg_cls.load_from_config(config)

    @staticmethod
    def load_from_config_generic(config: Dict[str, Any]) -> Tuple[int, int, Optional[int], bytes]:
        """Converts the general configuration option into an message object.

        "config" content of container configurations.

        :param config: Message configuration dictionaries.
        :return: Message object.
        """
        cert_ver = value_to_int(config.get("cert_version", 0))
        permission = value_to_int(config.get("permission", 0))
        issue_date_raw = config.get("issue_date", None)
        if issue_date_raw:
            assert isinstance(issue_date_raw, str)
            year, month = issue_date_raw.split("-")
            issue_date = max(min(12, int(month)), 1) << 12 | int(year)
        else:
            issue_date = None

        uuid = bytes.fromhex(config.get("uuid", bytes(Message.UNIQUE_ID_LEN)))
        return (cert_ver, permission, issue_date, uuid)

    def _create_general_config(self) -> CM:
        """Create configuration of the general parts of  Message.

        :return: Configuration dictionary.
        """
        assert self.unique_id
        cfg = CM()
        cfg["cert_version"] = self.cert_ver
        cfg["cert_permission"] = self.permissions
        cfg["issue_date"] = f"{(self.issue_date & 0xfff)}-{(self.issue_date>>12) & 0xf}"
        cfg["uuid"] = self.unique_id.hex()

        return cfg

    def create_config(self) -> CM:
        """Create configuration of the Signed Message.

        :return: Configuration dictionary.
        """
        assert self.payload
        cfg = self._create_general_config()
        cmd_cfg = CM()
        cmd_cfg[MessageCommands.get(self.cmd)] = self.payload.hex()
        cfg["command"] = cmd_cfg

        return cfg

    @staticmethod
    def getMessageClass(cmd: str) -> Type["Message"]:
        """Get the dedicated message class for command."""
        for var in globals():
            obj = globals()[var]
            if isclass(obj) and issubclass(obj, Message) and obj is not Message:
                assert isinstance(obj, type(Message))
                if MessageCommands.get(cmd) == obj.TAG:
                    return obj

        raise SPSDKValueError(f"Command {cmd} is not supported.")

    @staticmethod
    def parse(binary: bytes) -> "Message":
        """Parse input binary to the signed message object.

        :param binary: Binary data with Container block to parse.
        :return: Object recreated from the binary data.
        """
        (
            issue_date,  # issue Date
            permission,  # permission
            certificate_version,  # certificate version
            _,  # Reserved to zero
            command,  # Command
            _,  # Reserved
            uuid_lower,  # Unique ID (Lower 32 bits)
            uuid_upper,  # Unique ID (Upper 32 bits)
        ) = unpack(Message._format(), binary[: Message.fixed_length()])

        cmd_name = str(MessageCommands.get(command))
        parsed_msg = Message.getMessageClass(cmd_name)(
            cert_ver=certificate_version,
            permissions=permission,
            issue_date=issue_date,
            unique_id=uuid_lower + uuid_upper,
        )
        parsed_msg.payload = binary[Message.fixed_length() :]
        return parsed_msg


class MessageReturnLifeCycle(Message):
    """Return life cycle request message class representation."""

    TAG = MessageCommands.RETURN_LIFECYCLE_UPDATE_REQ

    def __init__(
        self,
        cert_ver: int = 0,
        permissions: int = 0,
        issue_date: Optional[int] = None,
        unique_id: Optional[bytes] = None,
        life_cycle: int = 0,
    ) -> None:
        """Message used to sign and send to device with EdgeLock.

        :param cert_ver: Certificate version, defaults to 0
        :param permissions: Certificate permission, to be used in future
            The stated permission must allow the operation requested by the signed message
            , defaults to 0
        :param issue_date: Issue date, defaults to None (Current date will be applied)
        :param unique_id: UUID of device (least 64 bits is used), defaults to None
        :param life_cycle: Requested life cycle, defaults to 0
        """
        super().__init__(
            cert_ver=cert_ver,
            permissions=permissions,
            issue_date=issue_date,
            cmd=self.TAG,
            unique_id=unique_id,
        )
        self.life_cycle = life_cycle

    @property
    def life_cycle(self) -> int:
        """Get the requested life cycle.

        :return: Requested life cycle ID.
        """
        assert self.payload
        return int.from_bytes(self.payload, byteorder="little")

    @life_cycle.setter
    def life_cycle(self, lc: int) -> None:
        """Set the requested life cycle."""
        self.payload = lc.to_bytes(length=4, byteorder="little")

    @staticmethod
    def load_from_config(config: Dict[str, Any]) -> "Message":
        """Converts the configuration option into an message object.

        "config" content of container configurations.

        :param config: Signed Message configuration dictionaries.
        :raises SPSDKError: Invalid configuration detected.
        :return: Message object.
        """
        command = config.get("command", dict())
        if not isinstance(command, dict) or len(command) != 1:
            raise SPSDKError(f"Invalid config field command: {command}")
        command_name = list(command.keys())[0]
        if MessageCommands.get(command_name) != MessageReturnLifeCycle.TAG:
            raise SPSDKError("Invalid configuration for Return Life Cycle Request command.")

        cert_ver, permission, issue_date, uuid = Message.load_from_config_generic(config)

        life_cycle = command.get("RETURN_LIFECYCLE_UPDATE_REQ")
        assert isinstance(life_cycle, int)

        return MessageReturnLifeCycle(
            cert_ver=cert_ver,
            permissions=permission,
            issue_date=issue_date,
            unique_id=uuid,
            life_cycle=life_cycle,
        )

    def create_config(self) -> CM:
        """Create configuration of the Signed Message.

        :return: Configuration dictionary.
        """
        cfg = self._create_general_config()
        cmd_cfg = CM()
        cmd_cfg[MessageCommands.get(self.TAG)] = self.life_cycle
        cfg["command"] = cmd_cfg

        return cfg

    def validate(self) -> None:
        """Validate general message properties."""
        super().validate()
        if self.payload is None or len(self.payload) != 4:
            raise SPSDKValueError(
                f"Message Return Life Cycle request: Invalid payload: {self.payload.hex() if self.payload else 'None'}"
            )


class MessageWriteSecureFuse(Message):
    """Write secure fuse request message class representation."""

    TAG = MessageCommands.WRITE_SEC_FUSE_REQ

    def __init__(
        self,
        cert_ver: int = 0,
        permissions: int = 0,
        issue_date: Optional[int] = None,
        unique_id: Optional[bytes] = None,
        fuse_id: int = 0,
        length: int = 0,
        flags: int = 0,
        data: bytes = bytes(4),
    ) -> None:
        """Message used to sign and send to device with EdgeLock.

        :param cert_ver: Certificate version, defaults to 0
        :param permissions: Certificate permission, to be used in future
            The stated permission must allow the operation requested by the signed message
            , defaults to 0
        :param issue_date: Issue date, defaults to None (Current date will be applied)
        :param unique_id: UUID of device (least 64 bits is used), defaults to None
        :param fuse_id: Fuse ID, defaults to 0
        :param length: Fuse length, defaults to 0
        :param flags: Fuse flags, defaults to 0
        :param data: Fuse value, defaults to zero 4 byte value
        """
        super().__init__(
            cert_ver=cert_ver,
            permissions=permissions,
            issue_date=issue_date,
            cmd=self.TAG,
            unique_id=unique_id,
        )
        self.fuse_id = fuse_id
        self.length = length
        self.flags = flags
        self.fuse_data = data

        self.update_payload()

    def update_payload(self) -> None:
        """Set the requested write secure fuse payload."""
        payload = pack(
            LITTLE_ENDIAN + UINT16 + UINT8 + UINT8, self.fuse_id, self.length, self.flags
        )
        payload += self.fuse_data
        self.payload = payload

    @staticmethod
    def load_from_config(config: Dict[str, Any]) -> "Message":
        """Converts the configuration option into an message object.

        "config" content of container configurations.

        :param config: Signed Message configuration dictionaries.
        :raises SPSDKError: Invalid configuration detected.
        :return: Message object.
        """
        command = config.get("command", dict())
        if not isinstance(command, dict) or len(command) != 1:
            raise SPSDKError(f"Invalid config field command: {command}")
        command_name = list(command.keys())[0]
        if MessageCommands.get(command_name) != MessageWriteSecureFuse.TAG:
            raise SPSDKError("Invalid configuration for Write secure fuse Request command.")

        cert_ver, permission, issue_date, uuid = Message.load_from_config_generic(config)

        secure_fuse = command.get("WRITE_SEC_FUSE_REQ")
        assert isinstance(secure_fuse, dict)
        fuse_id = secure_fuse.get("id")
        assert isinstance(fuse_id, int)
        flags: int = secure_fuse.get("flags", 0)
        data_list: List = secure_fuse.get("data", [])
        data = bytes()
        for x in data_list:
            data += value_to_bytes(x, byte_cnt=4, endianness="little")
        length = len(data_list)
        return MessageWriteSecureFuse(
            cert_ver=cert_ver,
            permissions=permission,
            issue_date=issue_date,
            unique_id=uuid,
            fuse_id=fuse_id,
            length=length,
            flags=flags,
            data=data,
        )

    def create_config(self) -> CM:
        """Create configuration of the Signed Message.

        :return: Configuration dictionary.
        """
        cfg = self._create_general_config()
        write_fuse_cfg = CM()
        cmd_cfg = CM()
        write_fuse_cfg["id"] = self.fuse_id
        write_fuse_cfg["flags"] = self.flags
        write_fuse_cfg["data"] = self.fuse_data.hex()
        cmd_cfg[MessageCommands.get(self.TAG)] = write_fuse_cfg
        cfg["command"] = cmd_cfg

        return cfg

    def validate(self) -> None:
        """Validate general message properties."""
        super().validate()
        if self.payload is None or len(self.payload) != 4:
            raise SPSDKValueError(
                f"Message Write secure fuse request: Invalid payload: {self.payload.hex() if self.payload else 'None'}"
            )


class SignedMessage(AHABContainerBase):
    """Class representing the Signed message.

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

    TAG = SignedMessageTags.SIGNED_MSG
    ENCRYPT_IV_LEN = 32

    def __init__(
        self,
        flags: int = 0,
        fuse_version: int = 0,
        sw_version: int = 0,
        message: Optional[Message] = None,
        signature_block: Optional[SignatureBlock] = None,
        encrypt_iv: Optional[bytes] = None,
    ):
        """Class object initializer.

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
            flags=flags,
            fuse_version=fuse_version,
            sw_version=sw_version,
            signature_block=signature_block,
        )
        self.message = message
        self.encrypt_iv = encrypt_iv

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SignedMessage):
            if super().__eq__(other) and self.message == other.message:
                return True

        return False

    @property
    def _signature_block_offset(self) -> int:
        """Returns current signature block offset.

        :return: Offset in bytes of Signature block.
        """
        # Constant size of Container header + Image array Entry table
        assert self.message
        return align(
            calcsize(self._format()) + len(self.message),
            CONTAINER_ALIGNMENT,
        )

    def __len__(self) -> int:
        """Get total length of AHAB container.

        :return: Size in bytes of Message.
        """
        return self._signature_block_offset + len(self.signature_block)

    # We need to extend the format, as the parent provides only endianness,
    # and length.
    @classmethod
    def _format(cls) -> str:
        return (
            super()._format()
            + UINT8  # Descriptor Flags
            + UINT8  # Reserved
            + UINT16  # Reserved
            + "32s"  # IV - Initial Vector if encryption is enabled
        )

    def update_fields(self) -> None:
        """Updates all volatile information in whole container structure.

        :raises SPSDKError: When inconsistent image array length is detected.
        """
        # 0. Update length
        self.length = len(self)
        # 1. Encrypt all images if applicable
        # TODO :-)
        # 2. Update the signature block to get overall size of it
        self.signature_block.update_fields()
        # 3. Sign the image header
        if self.flag_srk_set != "none":
            assert self.signature_block.signature
            self.signature_block.signature.sign(self.get_signature_data())

    def _export(self) -> bytes:
        """Export raw data without updates fields into bytes.

        :return: bytes representing container header content including the signature block.
        """
        signed_message = pack(
            self._format(),
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
        assert self.message
        signed_message += self.message.export()
        # Add Signature Block
        signed_message += align_block(self.signature_block.export(), CONTAINER_ALIGNMENT)
        return signed_message

    def export(self) -> bytes:
        """Export the signed image into one chunk.

        :raises SPSDKValueError: if the number of images doesn't correspond the the number of
            entries in image array info.
        :return: images exported into single binary
        """
        self.update_fields()
        self.validate({})
        return self._export()

    def validate(self, data: Dict[str, Any]) -> None:
        """Validate object data.

        :param data: Additional validation data.
        :raises SPSDKValueError: Invalid any value of Image Array entry
        """
        data["flag_used_srk_id"] = self.flag_used_srk_id

        if self.length != len(self):
            raise SPSDKValueError(
                f"Container Header: Invalid block length: {self.length} != {len(self)}"
            )
        super().validate(data)
        if self.encrypt_iv and len(self.encrypt_iv) != self.ENCRYPT_IV_LEN:
            raise SPSDKValueError(
                "Signed Message: Invalid Encryption initialization vector length: "
                f"{len(self.encrypt_iv)*8} Bits != {self.ENCRYPT_IV_LEN * 8} Bits"
            )
        if self.message is None:
            raise SPSDKValueError("Signed Message: Invalid Message payload.")
        self.message.validate()

    @staticmethod
    def parse(binary: bytes) -> "SignedMessage":
        """Parse input binary to the signed message object.

        :param binary: Binary data with Container block to parse.
        :return: Object recreated from the binary data.
        """
        SignedMessage._check_container_head(binary)
        image_format = SignedMessage._format()
        (
            _,  # version
            _,  # container_length
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
        ) = unpack(image_format, binary[: SignedMessage.fixed_length()])

        parsed_signed_msg = SignedMessage(
            flags=flags,
            fuse_version=fuse_version,
            sw_version=sw_version,
            encrypt_iv=iv if bool(descriptor_flags & 0x01) else None,
        )
        parsed_signed_msg.signature_block = SignatureBlock.parse(binary, signature_block_offset)

        # Parse also Message itself
        parsed_signed_msg.message = Message.parse(
            binary[SignedMessage.fixed_length() : signature_block_offset]
        )
        return parsed_signed_msg

    def create_config(self, data_path: str) -> CM:
        """Create configuration of the Signed Message.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        self.validate({})
        cfg = self._create_config(0, data_path)
        cfg.yaml_set_start_comment(
            "Signed Message recreated configuration from :"
            f"{datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}."
        )
        cfg["family"] = "N/A"
        cfg["revision"] = "N/A"
        cfg["output"] = "N/A"

        assert self.message
        cfg["message"] = self.message.create_config()

        return cfg

    @staticmethod
    def load_from_config(
        config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> "SignedMessage":
        """Converts the configuration option into an Signed message object.

        "config" content of container configurations.

        :param config: Signed Message configuration dictionaries.
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: Message object.
        """
        signed_msg = SignedMessage()
        signed_msg.search_paths = search_paths or []
        AHABContainerBase.load_from_config_generic(signed_msg, config)

        message = config.get("message")
        assert isinstance(message, dict)

        signed_msg.message = Message.load_from_config(message)

        return signed_msg

    def image_info(self) -> BinaryImage:
        """Get Image info object.

        :return: Signed Message Info object.
        """
        self.validate({})
        assert self.message
        ret = BinaryImage(
            name="Signed Message",
            size=len(self),
            offset=0,
            binary=self.export(),
            description=(f"Signed Message for {MessageCommands.get(self.message.TAG)}"),
        )
        return ret

    @staticmethod
    def get_validation_schemas() -> List[Dict[str, Any]]:
        """Get list of validation schemas.

        :return: Validation list of schemas.
        """
        return [ValidationSchemas.get_schema_file(SIGNED_MSG_SCH_FILE)]

    @staticmethod
    def generate_config_template(family: str) -> Dict[str, Any]:
        """Generate AHAB configuration template.

        :param family: Family for which the template should be generated.
        :return: Dictionary of individual templates (key is name of template, value is template itself).
        """
        val_schemas = SignedMessage.get_validation_schemas()

        if family in AHABImage.get_supported_families():
            yaml_data = ConfigTemplate(
                f"Signed message Configuration template for {family}.",
                val_schemas,
            ).export_to_yaml()

            return {f"{family}_signed_msg": yaml_data}

        return {}
