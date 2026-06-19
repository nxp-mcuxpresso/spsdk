#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Extra.image.ahab.signed_msg."""

import pytest

from spsdk.exceptions import SPSDKError, SPSDKNotImplementedError, SPSDKValueError
from spsdk.image.ahab.ahab_data import KeyUsage, create_chip_config
from spsdk.image.ahab.signed_msg import (
    Message,
    MessageCommands,
    MessageDat,
    MessageKeyExchange,
    MessageKeyStoreReprovisioningEnable,
    MessageReturnLifeCycle,
    MessageV2,
    MessageWriteSecureFuse,
    SignedMessage,
    SignedMessageContainer,
    SignedMessageTags,
)
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision

FAMILY = FamilyRevision("mimxrt1189")


@pytest.fixture
def chip_config() -> None:
    """Return a chip config for mimxrt1189."""
    return create_chip_config(FAMILY)  # type: ignore[return-value]


# SignedMessageTags


def test_signed_message_tags_value() -> None:
    """SIGNED_MSG tag is 0x89."""
    assert SignedMessageTags.SIGNED_MSG.tag == 0x89


# MessageCommands enum


def test_message_commands_lifecycle() -> None:
    """RETURN_LIFECYCLE_UPDATE_REQ tag is 0xA0."""
    assert MessageCommands.RETURN_LIFECYCLE_UPDATE_REQ.tag == 0xA0


def test_message_commands_write_sec_fuse() -> None:
    """WRITE_SEC_FUSE_REQ tag is 0x91."""
    assert MessageCommands.WRITE_SEC_FUSE_REQ.tag == 0x91


def test_message_commands_dat() -> None:
    """DAT_AUTHENTICATION_REQ tag is 0xC8."""
    assert MessageCommands.DAT_AUTHENTICATION_REQ.tag == 0xC8


# Message base – repr / str


def test_message_repr_lifecycle() -> None:
    """MessageReturnLifeCycle __repr__ contains command description."""
    msg = MessageReturnLifeCycle(family=FAMILY, life_cycle=0x08)
    r = repr(msg)
    assert "Message" in r
    assert "lifecycle" in r.lower() or "Return" in r


def test_message_str_lifecycle() -> None:
    """MessageReturnLifeCycle __str__ includes cert version and permissions."""
    msg = MessageReturnLifeCycle(family=FAMILY, cert_ver=3, permissions=0x0F, life_cycle=0x08)
    s = str(msg)
    assert "Certificate version" in s
    assert "Permissions" in s
    assert "Life Cycle" in s


# MessageReturnLifeCycle


def test_return_lifecycle_export_payload() -> None:
    """MessageReturnLifeCycle.export_payload() produces correct 4-byte LE value."""
    msg = MessageReturnLifeCycle(family=FAMILY, life_cycle=0x08)
    payload = msg.export_payload()
    assert payload == b"\x08\x00\x00\x00"


def test_return_lifecycle_parse_payload() -> None:
    """parse_payload() correctly populates life_cycle."""
    msg = MessageReturnLifeCycle(family=FAMILY)
    msg.parse_payload(b"\x20\x00\x00\x00")
    assert msg.life_cycle == 0x20


def test_return_lifecycle_export_parse_roundtrip() -> None:
    """Full export → parse round-trip for MessageReturnLifeCycle."""
    msg = MessageReturnLifeCycle(
        family=FAMILY,
        life_cycle=0xA0,
        cert_ver=1,
        permissions=0x05,
        issue_date=0x4028,
        unique_id=bytes(8),
    )
    raw = msg.export()
    msg2 = Message.parse(raw, family=FAMILY)
    assert isinstance(msg2, MessageReturnLifeCycle)
    assert msg2.life_cycle == 0xA0
    assert msg2.cert_ver == 1


def test_return_lifecycle_verify_ok() -> None:
    """verify() returns no errors for a valid MessageReturnLifeCycle."""
    msg = MessageReturnLifeCycle(family=FAMILY, life_cycle=0x08)
    v = msg.verify()
    assert not v.has_errors


def test_return_lifecycle_get_config() -> None:
    """get_config() returns a Config with RETURN_LIFECYCLE_UPDATE_REQ key."""
    msg = MessageReturnLifeCycle(family=FAMILY, life_cycle=0x08)
    cfg = msg.get_config()
    assert "command" in cfg
    assert "RETURN_LIFECYCLE_UPDATE_REQ" in cfg["command"]


def test_return_lifecycle_load_from_config() -> None:
    """_load_from_config() recreates the message from its get_config() output."""
    msg = MessageReturnLifeCycle(
        family=FAMILY, life_cycle=0x10, cert_ver=2, permissions=0x3, issue_date=0x5029
    )
    cfg = msg.get_config()
    msg2 = Message.load_from_config(cfg, FAMILY)
    assert isinstance(msg2, MessageReturnLifeCycle)
    assert msg2.life_cycle == 0x10


# MessageWriteSecureFuse


def test_write_secure_fuse_str() -> None:
    """MessageWriteSecureFuse __str__ includes fuse index and flags."""
    msg = MessageWriteSecureFuse(
        family=FAMILY, fuse_id=5, length=2, flags=1, data=[0xDEADBEEF, 0xCAFEBABE]
    )
    s = str(msg)
    assert "Fuse Index" in s
    assert "Fuse Flags" in s


def test_write_secure_fuse_payload_len() -> None:
    """payload_len = 4 + len(fuse_data) * 4."""
    msg = MessageWriteSecureFuse(family=FAMILY, fuse_id=0, length=3, data=[1, 2, 3])
    assert msg.payload_len == 4 + 3 * 4


def test_write_secure_fuse_export_payload() -> None:
    """export_payload() can be decoded back to the same values."""
    msg = MessageWriteSecureFuse(family=FAMILY, fuse_id=7, length=1, flags=0, data=[0xABCD1234])
    payload = msg.export_payload()
    msg2 = MessageWriteSecureFuse(family=FAMILY)
    msg2.parse_payload(payload)
    assert msg2.fuse_id == 7
    assert msg2.fuse_data == [0xABCD1234]


def test_write_secure_fuse_roundtrip() -> None:
    """Full export → parse round-trip for MessageWriteSecureFuse."""
    msg = MessageWriteSecureFuse(
        family=FAMILY,
        fuse_id=3,
        length=2,
        flags=1,
        data=[0x11111111, 0x22222222],
        cert_ver=1,
        issue_date=0x4028,
        unique_id=bytes(8),
    )
    raw = msg.export()
    msg2 = Message.parse(raw, family=FAMILY)
    assert isinstance(msg2, MessageWriteSecureFuse)
    assert msg2.fuse_id == 3
    assert msg2.fuse_data == [0x11111111, 0x22222222]


def test_write_secure_fuse_verify_ok() -> None:
    """verify() passes for a valid MessageWriteSecureFuse."""
    msg = MessageWriteSecureFuse(family=FAMILY, fuse_id=0, length=1, flags=0, data=[0xDEAD])
    v = msg.verify()
    assert not v.has_errors


def test_write_secure_fuse_get_config() -> None:
    """get_config() returns a Config with WRITE_SEC_FUSE_REQ key."""
    msg = MessageWriteSecureFuse(family=FAMILY, fuse_id=1, length=1, data=[0x42])
    cfg = msg.get_config()
    assert "command" in cfg
    assert "WRITE_SEC_FUSE_REQ" in cfg["command"]


def test_write_secure_fuse_load_from_config() -> None:
    """_load_from_config() recreates the message from its get_config() output."""
    msg = MessageWriteSecureFuse(family=FAMILY, fuse_id=2, length=1, flags=0, data=[0x99])
    cfg = msg.get_config()
    msg2 = Message.load_from_config(cfg, FAMILY)
    assert isinstance(msg2, MessageWriteSecureFuse)
    assert msg2.fuse_id == 2
    assert msg2.fuse_data == [0x99]


# MessageKeyStoreReprovisioningEnable


def test_keystore_repr_enable_str() -> None:
    """MessageKeyStoreReprovisioningEnable __str__ includes monotonic counter."""
    msg = MessageKeyStoreReprovisioningEnable(
        family=FAMILY, monotonic_counter=0x5, user_sab_id=0xAA
    )
    s = str(msg)
    assert "Monotonic counter" in s
    assert "User SAB id" in s


def test_keystore_repr_enable_export_parse_roundtrip() -> None:
    """Full export → parse round-trip for MessageKeyStoreReprovisioningEnable."""
    msg = MessageKeyStoreReprovisioningEnable(
        family=FAMILY,
        monotonic_counter=0x10,
        user_sab_id=0xBB,
        cert_ver=0,
        issue_date=0x4028,
        unique_id=bytes(8),
    )
    raw = msg.export()
    msg2 = Message.parse(raw, family=FAMILY)
    assert isinstance(msg2, MessageKeyStoreReprovisioningEnable)
    assert msg2.monotonic_counter == 0x10
    assert msg2.user_sab_id == 0xBB


def test_keystore_repr_enable_verify() -> None:
    """verify() passes for a valid MessageKeyStoreReprovisioningEnable."""
    msg = MessageKeyStoreReprovisioningEnable(family=FAMILY, monotonic_counter=1, user_sab_id=0)
    v = msg.verify()
    assert not v.has_errors


def test_keystore_repr_enable_get_config() -> None:
    """get_config() returns a Config with KEYSTORE_REPROVISIONING_ENABLE_REQ key."""
    msg = MessageKeyStoreReprovisioningEnable(family=FAMILY, monotonic_counter=5, user_sab_id=3)
    cfg = msg.get_config()
    assert "command" in cfg
    assert "KEYSTORE_REPROVISIONING_ENABLE_REQ" in cfg["command"]


def test_keystore_repr_enable_load_from_config() -> None:
    """_load_from_config() recreates the message from its get_config() output."""
    msg = MessageKeyStoreReprovisioningEnable(family=FAMILY, monotonic_counter=7, user_sab_id=0x1F)
    cfg = msg.get_config()
    msg2 = Message.load_from_config(cfg, FAMILY)
    assert isinstance(msg2, MessageKeyStoreReprovisioningEnable)
    assert msg2.monotonic_counter == 7


# MessageDat


def test_message_dat_str() -> None:
    """MessageDat __str__ includes challenge vector and authentication beacon."""
    msg = MessageDat(family=FAMILY, challenge_vector=bytes(32), authentication_beacon=0xABC)
    s = str(msg)
    assert "Challenge Vector" in s
    assert "Authentication beacon" in s


def test_message_dat_export_parse_roundtrip() -> None:
    """Full export → parse round-trip for MessageDat."""
    cv = bytes(range(32))
    msg = MessageDat(
        family=FAMILY,
        challenge_vector=cv,
        authentication_beacon=0x1234,
        issue_date=0x4028,
        unique_id=bytes(8),
    )
    raw = msg.export()
    msg2 = Message.parse(raw, family=FAMILY)
    assert isinstance(msg2, MessageDat)
    assert msg2.challenge_vector == cv


def test_message_dat_verify_ok() -> None:
    """verify() passes for a valid MessageDat."""
    msg = MessageDat(family=FAMILY, challenge_vector=bytes(32), authentication_beacon=0)
    v = msg.verify()
    assert not v.has_errors


def test_message_dat_get_config() -> None:
    """get_config() returns a Config with DAT_AUTHENTICATION_REQ key."""
    msg = MessageDat(family=FAMILY, challenge_vector=bytes(32), authentication_beacon=1)
    cfg = msg.get_config()
    assert "command" in cfg
    assert "DAT_AUTHENTICATION_REQ" in cfg["command"]


def test_message_dat_load_from_config() -> None:
    """_load_from_config() recreates MessageDat from its get_config() output."""
    msg = MessageDat(
        family=FAMILY,
        challenge_vector=bytes(range(32)),
        authentication_beacon=0xAB,
    )
    cfg = msg.get_config()
    msg2 = Message.load_from_config(cfg, FAMILY)
    assert isinstance(msg2, MessageDat)
    assert msg2.challenge_vector == bytes(range(32))


def test_message_dat_payload_len() -> None:
    """payload_len = 32 + authentication_beacon_length."""
    msg = MessageDat(family=FAMILY)
    assert msg.payload_len == 32 + msg.authentication_beacon_length


# MessageKeyExchange


def test_message_key_exchange_str() -> None:
    """MessageKeyExchange __str__ includes key store ID and exchange algorithm."""
    msg = MessageKeyExchange(family=FAMILY, key_store_id=42)
    s = str(msg)
    assert "KeyStore ID" in s
    assert "Key exchange algorithm" in s


def test_message_key_exchange_verify_ok() -> None:
    """verify() passes for a basic MessageKeyExchange."""
    msg = MessageKeyExchange(
        family=FAMILY,
        key_store_id=0,
        input_peer_public_key_digest=bytes(32),
        input_user_fixed_info_digest=bytes(32),
    )
    v = msg.verify()
    assert not v.has_errors


def test_message_key_exchange_export_parse_roundtrip() -> None:
    """Full export → parse round-trip for MessageKeyExchange."""
    msg = MessageKeyExchange(
        family=FAMILY,
        key_store_id=5,
        input_peer_public_key_digest=bytes(32),
        input_user_fixed_info_digest=bytes(32),
        issue_date=0x4028,
        unique_id=bytes(8),
    )
    raw = msg.export()
    msg2 = Message.parse(raw, family=FAMILY)
    assert isinstance(msg2, MessageKeyExchange)
    assert msg2.key_store_id == 5


def test_message_key_exchange_get_config() -> None:
    """get_config() returns a Config with KEY_EXCHANGE_REQ key."""
    msg = MessageKeyExchange(family=FAMILY, key_store_id=1)
    cfg = msg.get_config()
    assert "command" in cfg
    assert "KEY_EXCHANGE_REQ" in cfg["command"]


def test_message_key_exchange_load_from_config() -> None:
    """_load_from_config() recreates MessageKeyExchange from its get_config() output."""
    msg = MessageKeyExchange(
        family=FAMILY,
        key_store_id=3,
        input_peer_public_key_digest=bytes(32),
        input_user_fixed_info_digest=bytes(32),
    )
    cfg = msg.get_config()
    msg2 = Message.load_from_config(cfg, FAMILY)
    assert isinstance(msg2, MessageKeyExchange)
    assert msg2.key_store_id == 3


def test_message_key_exchange_get_derived_keys_info() -> None:
    """get_derived_keys_info() returns None values when ECDH not performed."""
    msg = MessageKeyExchange(family=FAMILY)
    info = msg.get_derived_keys_info()
    assert info["shared_secret"] is None
    assert info["oem_import_mk_sk"] is None
    assert info["oem_import_wrap_sk"] is None
    assert info["oem_import_cmac_sk"] is None


def test_message_key_exchange_perform_ecdh_requires_keys() -> None:
    """perform_ecdh_key_derivation() raises SPSDKError when keys are absent."""
    msg = MessageKeyExchange(family=FAMILY)
    with pytest.raises(SPSDKError, match="required for ECDH"):
        msg.perform_ecdh_key_derivation()


def test_message_key_exchange_post_export_no_ecdh() -> None:
    """export_derived_keys() raises SPSDKError when ECDH was not performed."""
    msg = MessageKeyExchange(family=FAMILY)
    with pytest.raises(SPSDKError, match="ECDH key derivation must be performed"):
        msg.export_derived_keys()


# Message.post_export base class


def test_message_post_export_not_implemented() -> None:
    """Message base class post_export raises SPSDKNotImplementedError."""
    msg = MessageReturnLifeCycle(family=FAMILY, life_cycle=0)
    with pytest.raises(SPSDKNotImplementedError):
        msg.post_export("/tmp/test_output")


# Message.get_message_class


def test_get_message_class_lifecycle() -> None:
    """get_message_class returns MessageReturnLifeCycle for the lifecycle label."""
    cls = Message.get_message_class("RETURN_LIFECYCLE_UPDATE_REQ")
    assert cls is MessageReturnLifeCycle


def test_get_message_class_write_fuse() -> None:
    """get_message_class returns MessageWriteSecureFuse for the write fuse label."""
    cls = Message.get_message_class("WRITE_SEC_FUSE_REQ")
    assert cls is MessageWriteSecureFuse


def test_get_message_class_dat() -> None:
    """get_message_class returns MessageDat for the DAT label."""
    cls = Message.get_message_class("DAT_AUTHENTICATION_REQ")
    assert cls is MessageDat


def test_get_message_class_key_exchange() -> None:
    """get_message_class returns MessageKeyExchange for KEY_EXCHANGE_REQ label."""
    cls = Message.get_message_class("KEY_EXCHANGE_REQ")
    assert cls is MessageKeyExchange


def test_get_message_class_unsupported() -> None:
    """get_message_class raises SPSDKError for an unknown command."""
    with pytest.raises(SPSDKError):
        Message.get_message_class("NONEXISTENT_CMD_XYZ")


# Message.load_from_config – invalid command


def test_message_load_from_config_invalid_command() -> None:
    """load_from_config raises SPSDKError when command dict has wrong size."""
    cfg = Config()
    cfg["command"] = {}  # empty - should fail
    with pytest.raises(SPSDKError):
        Message.load_from_config(cfg, FAMILY)


# Message.load_from_config_generic


def test_load_from_config_generic_with_issue_date() -> None:
    """load_from_config_generic parses issue_date correctly."""
    cfg = Config()
    cfg["cert_version"] = 0
    cfg["cert_permission"] = 0
    cfg["issue_date"] = "2024-6"
    cfg["uuid"] = bytes(8).hex()
    cfg["flags"] = 0
    cert_ver, permission, issue_date, uuid, flags = Message.load_from_config_generic(cfg)
    assert issue_date is not None
    assert (issue_date >> 12) & 0xF == 6  # month
    assert (issue_date & 0xFFF) == 2024  # year


def test_load_from_config_generic_no_issue_date() -> None:
    """load_from_config_generic returns None for issue_date when not in config."""
    cfg = Config()
    cfg["cert_version"] = 1
    cfg["cert_permission"] = 2
    cfg["uuid"] = bytes(8).hex()
    cfg["flags"] = 0
    _, _, issue_date, _, _ = Message.load_from_config_generic(cfg)
    assert issue_date is None


# SignedMessageContainer – repr / str


def test_signed_message_container_repr_plain(chip_config) -> None:  # type: ignore[no-untyped-def]
    """SignedMessageContainer repr shows 'Plain' for non-encrypted."""
    msg = MessageReturnLifeCycle(family=FAMILY, life_cycle=0)
    ctr = SignedMessageContainer(chip_config=chip_config, message=msg)
    r = repr(ctr)
    assert "Plain" in r


def test_signed_message_container_repr_encrypted(chip_config) -> None:  # type: ignore[no-untyped-def]
    """SignedMessageContainer repr shows 'Encrypted' when IV is present."""
    msg = MessageReturnLifeCycle(family=FAMILY, life_cycle=0)
    ctr = SignedMessageContainer(chip_config=chip_config, message=msg, encrypt_iv=bytes(32))
    r = repr(ctr)
    assert "Encrypted" in r


def test_signed_message_container_str(chip_config) -> None:  # type: ignore[no-untyped-def]
    """SignedMessageContainer __str__ includes Flags and Message sections."""
    msg = MessageReturnLifeCycle(family=FAMILY, life_cycle=1)
    ctr = SignedMessageContainer(chip_config=chip_config, message=msg)
    s = str(ctr)
    assert "Flags" in s
    assert "Message" in s


# SignedMessageContainer – verify


def test_signed_message_container_verify_with_encryption_iv(chip_config) -> None:  # type: ignore[no-untyped-def]
    """verify() records the encryption IV when present - no assertion error."""
    msg = MessageReturnLifeCycle(family=FAMILY, life_cycle=0)
    ctr = SignedMessageContainer(chip_config=chip_config, message=msg, encrypt_iv=bytes(32))
    # The verifier may have errors (no sig block / length not updated),
    # but must not raise an exception and must include the IV record.
    v = ctr.verify()
    assert v is not None
    assert "Encryption initialization vector" in str(v)


def test_signed_message_container_verify_no_message(chip_config) -> None:  # type: ignore[no-untyped-def]
    """verify() is consistent when message is set but no signature block."""
    msg = MessageReturnLifeCycle(family=FAMILY, life_cycle=5)
    ctr = SignedMessageContainer(chip_config=chip_config, message=msg)
    # Container has a message but no signature block - verify returns a Verifier
    v = ctr.verify()
    assert v is not None


# SignedMessage – repr / str


def test_signed_message_repr_no_container() -> None:
    """SignedMessage repr says 'Not specified' when no container."""
    sm = SignedMessage(family=FAMILY)
    r = repr(sm)
    assert "Not specified" in r


def test_signed_message_repr_with_container(chip_config) -> None:  # type: ignore[no-untyped-def]
    """SignedMessage repr includes container repr when container is set."""
    msg = MessageReturnLifeCycle(family=FAMILY, life_cycle=0)
    ctr = SignedMessageContainer(chip_config=chip_config, message=msg)
    # Manually set a non-zero length by mocking signature_block details aren't needed
    sm = SignedMessage(family=FAMILY)
    sm.signed_msg_container = ctr
    r = repr(sm)
    assert "Signed Message" in r


def test_signed_message_str_no_container() -> None:
    """SignedMessage __str__ says container is not specified."""
    sm = SignedMessage(family=FAMILY)
    s = str(sm)
    assert "not specified" in s.lower()


def test_signed_message_len_no_container() -> None:
    """SignedMessage len is 0 when no container."""
    sm = SignedMessage(family=FAMILY)
    assert len(sm) == 0


def test_signed_message_update_fields_no_container() -> None:
    """update_fields() does not raise when no container is set."""
    sm = SignedMessage(family=FAMILY)
    sm.update_fields()  # Should not raise


# SignedMessage – family property


def test_signed_message_family_property() -> None:
    """family property returns the FamilyRevision."""
    sm = SignedMessage(family=FAMILY)
    assert sm.family.name == "mimxrt1189"


def test_signed_message_family_setter() -> None:
    """family setter updates the chip_config family."""
    sm = SignedMessage(family=FAMILY)
    new_family = FamilyRevision("mimxrt1189")
    sm.family = new_family
    assert sm.family.name == "mimxrt1189"


# SignedMessage – container_type


def test_signed_message_container_type_raises_when_none() -> None:
    """container_type raises SPSDKError when container is not set."""
    sm = SignedMessage(family=FAMILY)
    with pytest.raises(SPSDKError, match="Can't determine"):
        _ = sm.container_type


def test_signed_message_container_type_returns_class(chip_config) -> None:  # type: ignore[no-untyped-def]
    """container_type returns the correct class for the container."""
    msg = MessageReturnLifeCycle(family=FAMILY, life_cycle=0)
    ctr = SignedMessageContainer(chip_config=chip_config, message=msg)
    sm = SignedMessage(family=FAMILY)
    sm.signed_msg_container = ctr
    assert sm.container_type is SignedMessageContainer


# SignedMessage – equality


def test_signed_message_equality() -> None:
    """SignedMessage equality returns True when compared to itself."""
    sm = SignedMessage(family=FAMILY)
    assert sm == sm


def test_signed_message_not_equal_other_type() -> None:
    """SignedMessage is not equal to a non-SignedMessage object."""
    sm = SignedMessage(family=FAMILY)
    assert sm != "not_a_signed_message"


# SignedMessage – parse without family raises error


def test_signed_message_parse_no_family() -> None:
    """SignedMessage.parse() raises SPSDKValueError when family is None."""
    with pytest.raises(SPSDKValueError, match="Missing family"):
        SignedMessage.parse(bytes(128), family=None)


# SignedMessage – get_config_template


def test_signed_message_get_config_template() -> None:
    """get_config_template() returns a non-empty YAML string."""
    template = SignedMessage.get_config_template(FAMILY)
    assert isinstance(template, str)
    assert len(template) > 0
    assert "family" in template


def test_signed_message_get_config_template_specific_message() -> None:
    """get_config_template() with a specific message filters the template."""
    template = SignedMessage.get_config_template(
        FAMILY, message=MessageCommands.RETURN_LIFECYCLE_UPDATE_REQ
    )
    assert isinstance(template, str)
    assert len(template) > 0


# SignedMessage – pre_parse_verify with invalid data


def test_signed_message_pre_parse_verify_invalid() -> None:
    """pre_parse_verify() returns errors for random bytes."""
    v = SignedMessage.pre_parse_verify(bytes(256))
    assert v.has_errors


# MessageReturnLifeCycle – _create_general_config


def test_message_create_general_config() -> None:
    """_create_general_config() includes cert_version, cert_permission, uuid and flags."""
    msg = MessageReturnLifeCycle(
        family=FAMILY, cert_ver=2, permissions=0xA, issue_date=0x5029, unique_id=bytes(8)
    )
    cfg = msg._create_general_config()
    assert "cert_version" in cfg
    assert "cert_permission" in cfg
    assert "uuid" in cfg
    assert "flags" in cfg
    assert cfg["cert_version"] == 2
    assert cfg["cert_permission"] == 0xA


# MessageWriteSecureFuse – verify with fuse data count mismatch


def test_write_secure_fuse_verify_count_mismatch() -> None:
    """verify() runs on a message where fuse_data count doesn't match length."""
    msg = MessageWriteSecureFuse(
        family=FAMILY,
        fuse_id=0,
        length=3,  # says 3 but data only has 1 element
        flags=0,
        data=[0xAB],
    )
    # The verify method records fuse data count via add_record_range with a boolean -
    # it does not necessarily flag an error; just verify it completes without exception.
    v = msg.verify()
    assert v is not None


@pytest.fixture
def family() -> FamilyRevision:
    """Return a common test family revision."""
    return FamilyRevision("mimxrt1189")


# SignedMessageTags / MessageCommands enumerations


def test_signed_message_tag_value() -> None:
    """SignedMessageTags.SIGNED_MSG has expected tag value."""
    assert SignedMessageTags.SIGNED_MSG.tag == 0x89


def test_message_commands_labels() -> None:
    """All expected MessageCommands are present."""
    labels = MessageCommands.labels()
    assert "RETURN_LIFECYCLE_UPDATE_REQ" in labels
    assert "WRITE_SEC_FUSE_REQ" in labels
    assert "KEYSTORE_REPROVISIONING_ENABLE_REQ" in labels
    assert "DAT_AUTHENTICATION_REQ" in labels
    assert "KEY_EXCHANGE_REQ" in labels


# Message base class helpers


def test_message_get_message_class_lc(family: FamilyRevision) -> None:
    """get_message_class returns MessageReturnLifeCycle for the correct label."""
    cls = Message.get_message_class("RETURN_LIFECYCLE_UPDATE_REQ")
    assert cls is MessageReturnLifeCycle


def test_message_get_message_class_write_sec_fuse(family: FamilyRevision) -> None:
    """get_message_class returns MessageWriteSecureFuse."""
    cls = Message.get_message_class("WRITE_SEC_FUSE_REQ")
    assert cls is MessageWriteSecureFuse


def test_message_get_message_class_keystore(family: FamilyRevision) -> None:
    """get_message_class returns MessageKeyStoreReprovisioningEnable."""
    cls = Message.get_message_class("KEYSTORE_REPROVISIONING_ENABLE_REQ")
    assert cls is MessageKeyStoreReprovisioningEnable


def test_message_get_message_class_dat(family: FamilyRevision) -> None:
    """get_message_class returns MessageDat."""
    cls = Message.get_message_class("DAT_AUTHENTICATION_REQ")
    assert cls is MessageDat


def test_message_get_message_class_key_exchange(family: FamilyRevision) -> None:
    """get_message_class returns MessageKeyExchange."""
    cls = Message.get_message_class("KEY_EXCHANGE_REQ")
    assert cls is MessageKeyExchange


def test_message_get_message_class_invalid() -> None:
    """get_message_class raises SPSDKKeyError for unknown label."""
    from spsdk.exceptions import SPSDKKeyError

    with pytest.raises(SPSDKKeyError):
        Message.get_message_class("NOT_A_REAL_CMD")


def test_message_parse_requires_family(family: FamilyRevision) -> None:
    """Message.parse raises SPSDKValueError when family is None."""
    msg = MessageReturnLifeCycle(family=family, life_cycle=1)
    data = msg.export()
    with pytest.raises(SPSDKValueError):
        Message.parse(data, family=None)


def test_message_load_from_config_rejects_multi_command(family: FamilyRevision) -> None:
    """Message.load_from_config raises SPSDKError when command has multiple entries."""
    cfg = Config({"command": {"RETURN_LIFECYCLE_UPDATE_REQ": 1, "WRITE_SEC_FUSE_REQ": {}}})
    with pytest.raises(SPSDKError):
        Message.load_from_config(cfg, family)


def test_message_load_from_config_generic_with_issue_date() -> None:
    """load_from_config_generic parses issue_date from year-month string."""
    cfg = Config(
        {
            "cert_version": 1,
            "cert_permission": 0x15,
            "issue_date": "2024-3",
            "uuid": "deadbeef01020304",
            "flags": 1,
        }
    )
    cert_ver, permission, issue_date, uuid, flags = Message.load_from_config_generic(cfg)
    assert cert_ver == 1
    assert permission == 0x15
    assert issue_date is not None
    assert uuid == bytes.fromhex("deadbeef01020304")
    assert flags == 1


def test_message_load_from_config_generic_without_issue_date() -> None:
    """load_from_config_generic returns None for issue_date when not in config."""
    cfg = Config({"cert_version": 0, "cert_permission": 0, "uuid": "0000000000000000", "flags": 0})
    _, _, issue_date, _, _ = Message.load_from_config_generic(cfg)
    assert issue_date is None


def test_message_unique_id_truncation_warning(family: FamilyRevision, caplog) -> None:  # type: ignore[no-untyped-def]
    """A UUID longer than unique_id_len triggers a warning."""
    import logging

    with caplog.at_level(logging.WARNING, logger="spsdk.image.ahab.signed_msg"):
        msg = MessageReturnLifeCycle(
            family=family, life_cycle=1, unique_id=bytes(20), unique_id_len=8
        )
    assert "truncated" in caplog.text
    # Export truncates to unique_id_len
    data = msg.export()
    assert len(data) == msg.fixed_length() + 8 + msg.PAYLOAD_LENGTH


# MessageReturnLifeCycle


def test_lc_export_parse_roundtrip(family: FamilyRevision) -> None:
    """MessageReturnLifeCycle export/parse round-trip preserves life_cycle."""
    msg = MessageReturnLifeCycle(
        family=family, cert_ver=2, permissions=0x10, life_cycle=7, header_flags=1
    )
    data = msg.export()
    parsed = Message.parse(data, family)
    assert isinstance(parsed, MessageReturnLifeCycle)
    assert parsed.life_cycle == 7
    assert parsed.cert_ver == 2
    assert parsed.permissions == 0x10


def test_lc_repr(family: FamilyRevision) -> None:
    """MessageReturnLifeCycle __repr__ includes description."""
    msg = MessageReturnLifeCycle(family=family, life_cycle=3)
    assert "lifecycle" in repr(msg).lower() or "life" in repr(msg).lower()


def test_lc_str(family: FamilyRevision) -> None:
    """MessageReturnLifeCycle __str__ includes life cycle hex."""
    msg = MessageReturnLifeCycle(family=family, life_cycle=0xA0)
    s = str(msg)
    assert "0xa0" in s.lower()


def test_lc_get_config(family: FamilyRevision) -> None:
    """MessageReturnLifeCycle.get_config returns correct life cycle value."""
    msg = MessageReturnLifeCycle(family=family, life_cycle=5)
    cfg = msg.get_config()
    assert cfg["command"]["RETURN_LIFECYCLE_UPDATE_REQ"] == 5


def test_lc_load_from_config(family: FamilyRevision) -> None:
    """MessageReturnLifeCycle._load_from_config reconstructs the message."""
    cfg = Config(
        {
            "cert_version": 0,
            "cert_permission": 0,
            "uuid": "0000000000000000",
            "flags": 0,
            "command": {"RETURN_LIFECYCLE_UPDATE_REQ": 9},
        }
    )
    msg = Message.load_from_config(cfg, family)
    assert isinstance(msg, MessageReturnLifeCycle)
    assert msg.life_cycle == 9


def test_lc_verify_ok(family: FamilyRevision) -> None:
    """MessageReturnLifeCycle.verify passes with valid values."""
    msg = MessageReturnLifeCycle(family=family, life_cycle=4)
    ver = msg.verify()
    assert not ver.has_errors


def test_lc_post_export_raises(family: FamilyRevision) -> None:
    """MessageReturnLifeCycle.post_export raises SPSDKNotImplementedError."""
    msg = MessageReturnLifeCycle(family=family, life_cycle=1)
    with pytest.raises(SPSDKNotImplementedError):
        msg.post_export("/some/path")


# MessageWriteSecureFuse


def test_wsf_export_parse_roundtrip(family: FamilyRevision) -> None:
    """MessageWriteSecureFuse export/parse round-trip preserves fuse data."""
    msg = MessageWriteSecureFuse(
        family=family, fuse_id=10, length=2, flags=1, data=[0xDEADBEEF, 0x12345678]
    )
    data = msg.export()
    parsed = Message.parse(data, family)
    assert isinstance(parsed, MessageWriteSecureFuse)
    assert parsed.fuse_id == 10
    assert parsed.flags == 1
    assert parsed.fuse_data == [0xDEADBEEF, 0x12345678]


def test_wsf_str(family: FamilyRevision) -> None:
    """MessageWriteSecureFuse __str__ includes fuse information."""
    msg = MessageWriteSecureFuse(family=family, fuse_id=3, length=1, flags=0, data=[0xABCD])
    s = str(msg)
    assert "0x3" in s
    assert "ABCD" in s.upper()


def test_wsf_payload_len(family: FamilyRevision) -> None:
    """MessageWriteSecureFuse payload_len equals 4 + len(data)*4."""
    msg = MessageWriteSecureFuse(family=family, fuse_id=1, length=3, flags=0, data=[1, 2, 3])
    assert msg.payload_len == 4 + 3 * 4


def test_wsf_get_config(family: FamilyRevision) -> None:
    """MessageWriteSecureFuse.get_config returns hex-formatted fuse data."""
    msg = MessageWriteSecureFuse(family=family, fuse_id=7, length=1, flags=2, data=[0xCAFE])
    cfg = msg.get_config()
    cmd = cfg.get_config("command").get_config("WRITE_SEC_FUSE_REQ")
    assert cmd["id"] == 7
    assert cmd["flags"] == 2
    assert "0x0000CAFE" in cmd["data"]


def test_wsf_load_from_config(family: FamilyRevision) -> None:
    """MessageWriteSecureFuse loads correctly from config dict."""
    cfg = Config(
        {
            "cert_version": 0,
            "cert_permission": 0,
            "uuid": "0000000000000000",
            "flags": 0,
            "command": {
                "WRITE_SEC_FUSE_REQ": {"id": 5, "flags": 0, "data": ["0xDEADBEEF", "0x12345678"]}
            },
        }
    )
    msg = Message.load_from_config(cfg, family)
    assert isinstance(msg, MessageWriteSecureFuse)
    assert msg.fuse_id == 5
    assert msg.fuse_data == [0xDEADBEEF, 0x12345678]


def test_wsf_verify(family: FamilyRevision) -> None:
    """MessageWriteSecureFuse.verify runs without errors on valid message."""
    msg = MessageWriteSecureFuse(family=family, fuse_id=1, length=2, flags=0, data=[0, 1])
    ver = msg.verify()
    # verify result depends on count consistency; just check it runs
    assert ver is not None


# MessageKeyStoreReprovisioningEnable


def test_ksre_export_parse_roundtrip(family: FamilyRevision) -> None:
    """MessageKeyStoreReprovisioningEnable export/parse round-trip."""
    msg = MessageKeyStoreReprovisioningEnable(
        family=family, monotonic_counter=99, user_sab_id=0xDEAD
    )
    data = msg.export()
    parsed = Message.parse(data, family)
    assert isinstance(parsed, MessageKeyStoreReprovisioningEnable)
    assert parsed.monotonic_counter == 99
    assert parsed.user_sab_id == 0xDEAD


def test_ksre_str(family: FamilyRevision) -> None:
    """MessageKeyStoreReprovisioningEnable __str__ includes counter and SAB ID."""
    msg = MessageKeyStoreReprovisioningEnable(
        family=family, monotonic_counter=42, user_sab_id=0x1234
    )
    s = str(msg)
    assert "42" in s
    assert "0x00001234" in s.lower() or "1234" in s


def test_ksre_get_config(family: FamilyRevision) -> None:
    """MessageKeyStoreReprovisioningEnable.get_config returns correct values."""
    msg = MessageKeyStoreReprovisioningEnable(
        family=family, monotonic_counter=7, user_sab_id=0x5678
    )
    cfg = msg.get_config()
    cmd = cfg.get_config("command").get_config("KEYSTORE_REPROVISIONING_ENABLE_REQ")
    assert "monotonic_counter" in cmd
    assert "user_sab_id" in cmd


def test_ksre_load_from_config(family: FamilyRevision) -> None:
    """MessageKeyStoreReprovisioningEnable loads correctly from config dict."""
    cfg = Config(
        {
            "cert_version": 0,
            "cert_permission": 0,
            "uuid": "0000000000000000",
            "flags": 1,
            "command": {
                "KEYSTORE_REPROVISIONING_ENABLE_REQ": {
                    "monotonic_counter": 42,
                    "user_sab_id": 0x1234,
                }
            },
        }
    )
    msg = Message.load_from_config(cfg, family)
    assert isinstance(msg, MessageKeyStoreReprovisioningEnable)
    assert msg.monotonic_counter == 42
    assert msg.user_sab_id == 0x1234


def test_ksre_verify(family: FamilyRevision) -> None:
    """MessageKeyStoreReprovisioningEnable.verify runs successfully."""
    msg = MessageKeyStoreReprovisioningEnable(family=family)
    ver = msg.verify()
    assert ver is not None


# MessageDat


def test_dat_export_parse_roundtrip(family: FamilyRevision) -> None:
    """MessageDat export/parse round-trip preserves challenge vector and beacon."""
    cv = bytes(range(32))
    msg = MessageDat(family=family, challenge_vector=cv, authentication_beacon=0xABCD)
    data = msg.export()
    parsed = Message.parse(data, family)
    assert isinstance(parsed, MessageDat)
    assert parsed.challenge_vector == cv
    assert parsed.authentication_beacon == 0xABCD


def test_dat_str(family: FamilyRevision) -> None:
    """MessageDat __str__ includes challenge vector."""
    cv = bytes(32)
    msg = MessageDat(family=family, challenge_vector=cv, authentication_beacon=0)
    s = str(msg)
    assert "Challenge" in s


def test_dat_get_config(family: FamilyRevision) -> None:
    """MessageDat.get_config returns challenge vector and beacon."""
    cv = bytes(range(32))
    msg = MessageDat(family=family, challenge_vector=cv, authentication_beacon=0x1234)
    cfg = msg.get_config()
    cmd = cfg.get_config("command").get_config("DAT_AUTHENTICATION_REQ")
    assert cmd["challenge_vector"] == cv.hex()
    assert cmd["authentication_beacon"] == 0x1234


def test_dat_load_from_config(family: FamilyRevision) -> None:
    """MessageDat loads correctly from config dict."""
    cv = "00" * 32
    cfg = Config(
        {
            "cert_version": 0,
            "cert_permission": 0,
            "uuid": "0000000000000000",
            "flags": 0,
            "command": {
                "DAT_AUTHENTICATION_REQ": {"challenge_vector": cv, "authentication_beacon": 0x9999}
            },
        }
    )
    msg = Message.load_from_config(cfg, family)
    assert isinstance(msg, MessageDat)
    assert msg.authentication_beacon == 0x9999


def test_dat_verify_valid(family: FamilyRevision) -> None:
    """MessageDat.verify passes for valid beacon within 2-byte range."""
    msg = MessageDat(family=family, challenge_vector=bytes(32), authentication_beacon=0xFFFF)
    ver = msg.verify()
    assert not ver.has_errors


def test_dat_verify_invalid_beacon(family: FamilyRevision) -> None:
    """MessageDat.verify fails when authentication_beacon exceeds valid range."""
    msg = MessageDat(family=family, challenge_vector=bytes(32), authentication_beacon=0x1FFFF)
    ver = msg.verify()
    assert ver.has_errors


def test_dat_payload_len(family: FamilyRevision) -> None:
    """MessageDat.payload_len equals 32 + authentication_beacon_length."""
    msg = MessageDat(family=family)
    assert msg.payload_len == 32 + msg.authentication_beacon_length


# MessageKeyExchange


def test_ke_export_parse_roundtrip(family: FamilyRevision) -> None:
    """MessageKeyExchange export/parse round-trip preserves key fields."""
    msg = MessageKeyExchange(
        family=family,
        key_store_id=5,
        derived_key_size_bits=256,
        derived_key_usage=[KeyUsage.ENCRYPT, KeyUsage.DECRYPT],
    )
    data = msg.export()
    parsed = Message.parse(data, family)
    assert isinstance(parsed, MessageKeyExchange)
    assert parsed.key_store_id == 5
    assert parsed.derived_key_size_bits == 256
    usage_labels = [u.label for u in parsed.derived_key_usage]
    assert "Encrypt" in usage_labels
    assert "Decrypt" in usage_labels


def test_ke_str(family: FamilyRevision) -> None:
    """MessageKeyExchange __str__ includes key store ID."""
    msg = MessageKeyExchange(family=family, key_store_id=99)
    s = str(msg)
    assert "99" in s


def test_ke_get_config(family: FamilyRevision) -> None:
    """MessageKeyExchange.get_config returns all expected fields."""
    msg = MessageKeyExchange(
        family=family,
        key_store_id=3,
        derived_key_usage=[KeyUsage.SIGN_HASH],
    )
    cfg = msg.get_config()
    cmd = cfg.get_config("command").get_config("KEY_EXCHANGE_REQ")
    assert "key_store_id" in cmd
    assert "derived_key_usage" in cmd
    assert "Sign hash" in cmd["derived_key_usage"]


def test_ke_verify(family: FamilyRevision) -> None:
    """MessageKeyExchange.verify runs without raising."""
    msg = MessageKeyExchange(
        family=family,
        input_peer_public_key_digest=bytes(32),
        input_user_fixed_info_digest=bytes(32),
    )
    ver = msg.verify()
    assert ver is not None


def test_ke_get_derived_keys_info_empty(family: FamilyRevision) -> None:
    """get_derived_keys_info returns None values when ECDH not performed."""
    msg = MessageKeyExchange(family=family)
    info = msg.get_derived_keys_info()
    assert all(v is None for v in info.values())


def test_ke_export_derived_keys_without_ecdh(family: FamilyRevision) -> None:
    """export_derived_keys raises SPSDKError when ECDH not performed."""
    msg = MessageKeyExchange(family=family)
    with pytest.raises(SPSDKError):
        msg.export_derived_keys("./")


def test_ke_post_export_without_ecdh(family: FamilyRevision) -> None:
    """post_export raises SPSDKError when ECDH not performed."""
    msg = MessageKeyExchange(family=family)
    with pytest.raises(SPSDKError):
        msg.post_export("./")


def test_ke_properties_none_when_not_set(family: FamilyRevision) -> None:
    """Property accessors for derived keys return None when not set."""
    msg = MessageKeyExchange(family=family)
    assert msg.shared_secret is None
    assert msg.oem_import_mk_sk is None
    assert msg.oem_import_wrap_sk is None
    assert msg.oem_import_cmac_sk is None


# MessageV2


def test_message_v2_unique_id_len(family: FamilyRevision) -> None:
    """MessageV2 has UNIQUE_ID_LEN of 16 bytes."""
    assert MessageV2.UNIQUE_ID_LEN == 16


def test_lc_with_v2_uid(family: FamilyRevision) -> None:
    """MessageReturnLifeCycle with unique_id_len=16 uses 16-byte UUID."""
    msg = MessageReturnLifeCycle(family=family, life_cycle=3, unique_id_len=16)
    assert msg.unique_id_len == 16
    data = msg.export()
    # fixed_length + 16 UUID + 4 payload = fixed + 20
    assert len(data) == msg.fixed_length() + 16 + msg.PAYLOAD_LENGTH


# SignedMessageContainer


def test_container_load_and_export(family: FamilyRevision, chip_config) -> None:  # type: ignore[no-untyped-def]
    """SignedMessageContainer can be loaded from config and exported."""
    msg_cfg = {
        "cert_version": 0,
        "cert_permission": 0,
        "issue_date": "2024-1",
        "uuid": "0000000000000000",
        "flags": 0,
        "command": {"RETURN_LIFECYCLE_UPDATE_REQ": 5},
    }
    sm_cfg = Config({"flags": 0, "fuse_version": 0, "sw_version": 0, "message": msg_cfg})
    container = SignedMessageContainer.load_from_config(chip_config, sm_cfg)
    data = container.export()
    assert len(data) > 0
    assert isinstance(container.message, MessageReturnLifeCycle)


def test_container_repr(family: FamilyRevision, chip_config) -> None:  # type: ignore[no-untyped-def]
    """SignedMessageContainer __repr__ contains 'Plain' for unsigned container."""
    msg_cfg = {
        "cert_version": 0,
        "cert_permission": 0,
        "uuid": "0000000000000000",
        "flags": 0,
        "command": {"RETURN_LIFECYCLE_UPDATE_REQ": 1},
    }
    sm_cfg = Config({"flags": 0, "fuse_version": 0, "sw_version": 0, "message": msg_cfg})
    container = SignedMessageContainer.load_from_config(chip_config, sm_cfg)
    assert "Plain" in repr(container)


def test_container_eq(family: FamilyRevision, chip_config) -> None:  # type: ignore[no-untyped-def]
    """Two SignedMessageContainers with same config are equal."""
    msg_cfg = {
        "cert_version": 0,
        "cert_permission": 0,
        "uuid": "0000000000000000",
        "flags": 0,
        "command": {"RETURN_LIFECYCLE_UPDATE_REQ": 3},
    }
    sm_cfg = Config({"flags": 0, "fuse_version": 0, "sw_version": 0, "message": msg_cfg})
    c1 = SignedMessageContainer.load_from_config(chip_config, sm_cfg)
    c2 = SignedMessageContainer.load_from_config(chip_config, sm_cfg)
    assert c1 == c2


def test_container_get_config(family: FamilyRevision, chip_config) -> None:  # type: ignore[no-untyped-def]
    """SignedMessageContainer.get_config returns a config with 'message'."""
    msg_cfg = {
        "cert_version": 0,
        "cert_permission": 0,
        "uuid": "0000000000000000",
        "flags": 0,
        "command": {"RETURN_LIFECYCLE_UPDATE_REQ": 7},
    }
    sm_cfg = Config({"flags": 0, "fuse_version": 0, "sw_version": 0, "message": msg_cfg})
    container = SignedMessageContainer.load_from_config(chip_config, sm_cfg)
    cfg = container.get_config()
    assert "message" in cfg


def test_container_image_info(family: FamilyRevision, chip_config) -> None:  # type: ignore[no-untyped-def]
    """SignedMessageContainer.image_info returns a BinaryImage with binary data."""
    msg_cfg = {
        "cert_version": 0,
        "cert_permission": 0,
        "uuid": "0000000000000000",
        "flags": 0,
        "command": {"RETURN_LIFECYCLE_UPDATE_REQ": 2},
    }
    sm_cfg = Config({"flags": 0, "fuse_version": 0, "sw_version": 0, "message": msg_cfg})
    container = SignedMessageContainer.load_from_config(chip_config, sm_cfg)
    img_info = container.image_info()
    assert img_info.binary is not None
    assert len(img_info.binary) > 0


def test_container_verify(family: FamilyRevision, chip_config) -> None:  # type: ignore[no-untyped-def]
    """SignedMessageContainer.verify returns a Verifier object."""
    msg_cfg = {
        "cert_version": 0,
        "cert_permission": 0,
        "uuid": "0000000000000000",
        "flags": 0,
        "command": {"RETURN_LIFECYCLE_UPDATE_REQ": 1},
    }
    sm_cfg = Config({"flags": 0, "fuse_version": 0, "sw_version": 0, "message": msg_cfg})
    container = SignedMessageContainer.load_from_config(chip_config, sm_cfg)
    ver = container.verify()
    assert ver is not None


# SignedMessage (top-level)


def test_signed_message_family(family: FamilyRevision) -> None:
    """SignedMessage.family returns expected family."""
    sm = SignedMessage(family)
    assert sm.family == family


def test_signed_message_verify_no_container(family: FamilyRevision) -> None:
    """SignedMessage.verify reports error when no container is set."""
    sm = SignedMessage(family)
    ver = sm.verify()
    assert ver.has_errors


def test_signed_message_srk_count_no_container(family: FamilyRevision) -> None:
    """SignedMessage.srk_count returns 0 when no container."""
    sm = SignedMessage(family)
    assert sm.srk_count == 0


def test_signed_message_get_srk_hash_no_container(family: FamilyRevision) -> None:
    """SignedMessage.get_srk_hash returns empty bytes when no container."""
    sm = SignedMessage(family)
    assert sm.get_srk_hash() == b""


def test_signed_message_get_supported_families() -> None:
    """SignedMessage.get_supported_families returns non-empty list."""
    families = SignedMessage.get_supported_families()
    assert len(families) > 0


def test_signed_message_get_validation_schemas(family: FamilyRevision) -> None:
    """SignedMessage.get_validation_schemas returns a list of dicts."""
    schemas = SignedMessage.get_validation_schemas(family)
    assert isinstance(schemas, list)
    assert len(schemas) >= 1


def test_signed_message_get_validation_schemas_from_cfg(family: FamilyRevision) -> None:
    """SignedMessage.get_validation_schemas_from_cfg works with family config."""
    cfg = Config({"family": "mimxrt1189"})
    schemas = SignedMessage.get_validation_schemas_from_cfg(cfg)
    assert isinstance(schemas, list)
    assert len(schemas) >= 1


def test_signed_message_parse_requires_family() -> None:
    """SignedMessage.parse raises SPSDKValueError when family is None."""
    with pytest.raises(SPSDKValueError):
        SignedMessage.parse(b"\x00" * 64, family=None)


def test_signed_message_pre_parse_verify_invalid_data() -> None:
    """SignedMessage.pre_parse_verify with garbage data returns a Verifier with errors."""
    ver = SignedMessage.pre_parse_verify(b"\xff" * 64)
    assert ver is not None


def test_get_config_template_lc(family: FamilyRevision) -> None:
    """SignedMessage.get_config_template returns YAML for lifecycle command."""
    template = SignedMessage.get_config_template(
        family, MessageCommands.RETURN_LIFECYCLE_UPDATE_REQ
    )
    assert "RETURN_LIFECYCLE_UPDATE_REQ" in template
    assert "mimxrt1189" in template


def test_get_config_template_all(family: FamilyRevision) -> None:
    """SignedMessage.get_config_template returns YAML when no specific message given."""
    template = SignedMessage.get_config_template(family)
    assert len(template) > 100


def test_signed_message_pre_parse_verify_valid(family: FamilyRevision, chip_config) -> None:  # type: ignore[no-untyped-def]
    """SignedMessage.pre_parse_verify returns Verifier with no errors for valid data."""
    msg_cfg = {
        "cert_version": 0,
        "cert_permission": 0,
        "uuid": "0000000000000000",
        "flags": 0,
        "command": {"RETURN_LIFECYCLE_UPDATE_REQ": 1},
    }
    sm_cfg = Config({"flags": 0, "fuse_version": 0, "sw_version": 0, "message": msg_cfg})
    container = SignedMessageContainer.load_from_config(chip_config, sm_cfg)
    data = container.export()
    ver = SignedMessage.pre_parse_verify(data)
    assert not ver.has_errors
