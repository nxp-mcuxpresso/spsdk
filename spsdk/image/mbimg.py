#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Master Boot Image."""

import struct
from typing import Any, List, Optional, Sequence, Union

from Crypto.Cipher import AES
from crcmod.predefined import mkPredefinedCrcFun

from spsdk.crypto import SignatureProvider
from spsdk.image.keystore import KeySourceType, KeyStore
from spsdk.image.trustzone import TrustZone, TrustZoneType
from spsdk.utils import misc
from spsdk.utils.crypto import crypto_backend, CertBlock, serialize_ecc_signature
from spsdk.utils.easy_enum import Enum


########################################################################################################################
# Master Boot Image Class (LPC55)
########################################################################################################################
class MasterBootImageType(Enum):
    """Enumeration of various types of MBIs."""
    PLAIN_IMAGE = (0x00, "Plain Image (either XIP or Load-to-RAM)")
    SIGNED_RAM_IMAGE = (0x01, "Plain Signed Load-to-RAM Image")
    CRC_RAM_IMAGE = (0x02, "Plain CRC Load-to-RAM Image")
    ENCRYPTED_RAM_IMAGE = (0x03, "Encrypted Load-to-RAM Image")
    SIGNED_XIP_IMAGE = (0x04, "Plain Signed XIP Image")
    CRC_XIP_IMAGE = (0x05, "Plain CRC XIP Image")
    SIGNED_XIP_NXP_IMAGE = (0x08, "Plain Signed XIP Image NXP Key")

    @staticmethod
    def is_xip(image_type: int) -> bool:
        """True is the image type is executed in place (XIP)."""
        return image_type in [MasterBootImageType.PLAIN_IMAGE,
                              MasterBootImageType.SIGNED_XIP_IMAGE,
                              MasterBootImageType.CRC_XIP_IMAGE,
                              MasterBootImageType.SIGNED_XIP_NXP_IMAGE]

    @staticmethod
    def is_copied_to_ram(image_type: int) -> bool:
        """True is the image type is copied and executed in RAM."""
        return image_type in [MasterBootImageType.CRC_RAM_IMAGE,
                              MasterBootImageType.SIGNED_RAM_IMAGE,
                              MasterBootImageType.ENCRYPTED_RAM_IMAGE]

    @staticmethod
    def has_crc(image_type: int) -> bool:
        """True is the image type contains CRC; False otherwise."""
        return image_type in [MasterBootImageType.CRC_XIP_IMAGE, MasterBootImageType.CRC_RAM_IMAGE]

    @staticmethod
    def is_signed(image_type: int) -> bool:
        """True is the image type is signed; False otherwise."""
        return image_type in [MasterBootImageType.SIGNED_XIP_IMAGE,
                              MasterBootImageType.SIGNED_RAM_IMAGE,
                              MasterBootImageType.ENCRYPTED_RAM_IMAGE,
                              MasterBootImageType.SIGNED_XIP_NXP_IMAGE]

    @staticmethod
    def is_encrypted(image_type: int) -> bool:
        """True is the image type is encrypted; False otherwise."""
        return image_type == MasterBootImageType.ENCRYPTED_RAM_IMAGE

    @staticmethod
    def has_hmac(image_type: int) -> bool:
        """Whether the image contains HMAC."""
        return MasterBootImageType.is_signed(image_type) and MasterBootImageType.is_copied_to_ram(image_type)


class MultipleImageEntry:
    """The class represents an entry in relocation table.

    It also contains a corresponding image (binary)
    """
    # flag to simply copy load segment into target memory
    LTI_LOAD = (1 << 0)

    def __init__(self, img: bytes, dst_addr: int, flags: int = LTI_LOAD):
        """Constructor.

        :param img: binary image data
        :param dst_addr: destination address
        :param flags: see LTI constants
        """
        assert 0 <= dst_addr <= 0xFFFFFFFF
        assert flags == self.LTI_LOAD  # for now, other section types (INIT) are not supported
        self._img = img
        self._src_addr = 0
        self._dst_addr = dst_addr
        self._flags = flags

    @property
    def image(self) -> bytes:
        """Binary image data."""
        return self._img

    @property
    def src_addr(self) -> int:
        """Source address; this value is calculated automatically when building the image."""
        return self._src_addr

    @src_addr.setter
    def src_addr(self, value: int) -> None:
        """Setter.

        :param value: to set
        """
        self._src_addr = value

    @property
    def dst_addr(self) -> int:
        """Destination address."""
        return self._dst_addr

    @property
    def size(self) -> int:
        """Size of the image (not aligned)."""
        return len(self.image)

    @property
    def flags(self) -> int:
        """Flags, currently not used."""
        return self._flags

    @property
    def is_load(self) -> bool:
        """True if entry represents LOAD section."""
        return (self.flags & self.LTI_LOAD) != 0

    def export_entry(self) -> bytes:
        """Export relocation table entry in binary form."""
        result = bytes()
        result += struct.pack("<I", self.src_addr)  # source address
        result += struct.pack("<I", self.dst_addr)  # dest address
        result += struct.pack("<I", self.size)  # length
        result += struct.pack("<I", self.flags)  # flags
        return result

    def export_image(self) -> bytes:
        """Binary image aligned to the 4-bytes boundary."""
        return misc.align_block(self.image, 4)


class MultipleImageTable:
    """The class allows to merge several images into single image and add relocation table.

    It can be used for multicore images (one image for each core)
    or trustzone images (merging secure and non-secure image)
    """

    def __init__(self) -> None:
        """Initialize the Multiple Image Table."""
        self._entries: List[MultipleImageEntry] = list()

    @property
    def header_version(self) -> int:
        """Format version of the structure for the header."""
        return 0

    @property
    def entries(self) -> Sequence[MultipleImageEntry]:
        """List of all entries."""
        return self._entries

    def add_entry(self, entry: MultipleImageEntry) -> None:
        """Add entry into relocation table.

        :param entry: to add
        """
        self._entries.append(entry)

    def reloc_table(self, start_addr: int) -> bytes:
        """Relocate table.

        :param start_addr: start address of the relocation table
        :return: export relocation table in binary form
        """
        result = bytes()
        # export relocation entries table
        for entry in self.entries:
            result += entry.export_entry()
        # export relocation table header
        result += struct.pack("<I", 0x4C54424C)  # header marker
        result += struct.pack("<I", self.header_version)  # version
        result += struct.pack("<I", len(self._entries))  # number of entries
        result += struct.pack("<I", start_addr)  # pointer to entries
        return result

    def export(self, start_addr: int) -> bytes:
        """Export.

        :param start_addr: start address where the images are exported;
                        the value matches source address for the first image
        :return: images with relocation table
        """
        assert self._entries, 'There must be at least one entry for export'
        src_addr = start_addr
        result = bytes()
        for entry in self.entries:
            if entry.is_load:
                entry.src_addr = src_addr
                entry_img = entry.export_image()
                result += entry_img
                src_addr += len(entry_img)
        result += self.reloc_table(start_addr + len(result))
        # TODO result += struct.pack("<I", src_addr)  # pointer to relocation table
        return result


# pylint: disable=too-many-instance-attributes
class MasterBootImage:
    """Basic representation of Master Boot Image layout."""

    # offset alignment of the certificate position
    _IMAGE_ALIGNMENT = 4

    IMAGE_LENGTH_OFFSET = 0x20
    # offset with flags: image type, trust zone, key-store and HW_USER_KEY_EN
    IMAGE_FLAGS_OFFSET = 0x24
    # flag for image type, if the image contains key-store
    _KEY_STORE_FLAG = 0x8000
    # flag that image contains relocation table
    _RELOC_TABLE_FLAG = 0x800
    # enableHwUserModeKeys : flag for controlling secure hardware key bus. If enabled(1), then it is possible to access
    # keys on hardware secure bus from non-secure application, else non-secure application will read zeros.
    _HW_USER_KEY_EN_FLAG = 0x1000

    CRC_BLOCK_OFFSET = 0x28
    CERTIFICATE_OFFSET = 0x28
    LOAD_ADDR_OFFSET = 0x34
    # offset in the image, where the HMAC table is located
    HMAC_OFFSET = 64
    # size of HMAC table in bytes
    HMAC_SIZE = 32
    # length of user key or master key, in bytes
    _HMAC_KEY_LENGTH = 32
    # length of derived key for HMAC, in bytes
    _HMAC_DERIVED_KEY_LEN = 16
    # length of counter initialization vector
    _CTR_INIT_VECTOR_SIZE = 16

    @property
    def app_len(self) -> int:
        """Length of binary app data; this includes also size of the relocation table."""
        result = len(self.app)
        if self.app_table:
            result += len(self.app_table.export(0))
        return result

    @property
    def data(self) -> bytes:
        """Plain, unsigned binary data for the image.

        It consists of:
        - application image
        - optionally trust zone data
        Please mind the result does not contain: certification block, HMAC, keystore and signature
        """
        # binary image
        data = self.app
        if self.app_table:
            data += self.app_table.export(len(data))
        # trust zone data
        data += self.trust_zone.export()
        return data

    @property
    def total_len(self) -> int:
        """Total length of the image.

        It is sum of:
        - image length + length of trust zone data
        - HMAC length
        - KeyStore length
        - certificate length (+ for encrypted images also encrypted header and CRT init vector)
        - signature length
        """
        plain_data = self.data
        certificate_len = len(self._certificate(plain_data))
        hmac_data_len = len(self._hmac(self.data))
        key_store_len = len(self.key_store.export()) if self.key_store else 0
        return len(plain_data) + hmac_data_len + key_store_len + certificate_len + self.signature_len

    # pylint: disable=too-many-arguments
    def __init__(self, app: Union[bytes, bytearray],
                 load_addr: int,
                 image_type: MasterBootImageType = MasterBootImageType.PLAIN_IMAGE,
                 trust_zone: Optional[TrustZone] = None, app_table: Optional[MultipleImageTable] = None,
                 cert_block: Optional[CertBlock] = None, priv_key_pem_data: Optional[bytes] = None,
                 hmac_key: Union[bytes, str] = None, key_store: KeyStore = None,
                 enable_hw_user_mode_keys: bool = False, ctr_init_vector: bytes = None) -> None:
        """Constructor.

        :param app: input image (binary)
        :param load_addr: address in RAM, where 'RAM' image will be copied;
            for XIP images address, where the image is located in FLASH memory
        :param image_type: type of the master boot image
        :param trust_zone: TrustZone instance; None to use default settings (TrustZone enabled)
        :param app_table: optional table with additional images; None if no additional images needed
        :param cert_block: block of certificates; None for unsigned image
        :param priv_key_pem_data: private key to sign the image, decrypted binary data in PEM format
        :param hmac_key: optional key for HMAC generation (either binary ot HEX string; 32 bytes);
            None if HMAC is not in the image
            If key_store.key_source == KeySourceType.KEYSTORE, this is a user-key from key-store
            If key_store.key_source == KeySourceType.OTP, this is a master-key burned in OTP
        :param key_store: optional key store binary content; None if key store is not in the image
        :param enable_hw_user_mode_keys: flag for controlling secure hardware key bus. If true, then it is possible to
            access keys on hardware secure bus from non-secure application, else non-secure application will read zeros.
        :param ctr_init_vector: optional initial vector for encryption counter; None to use random vector
        :raises TypeError: if type is not binary data
        :raises ValueError: if images are not loaded from RAM
        """
        if not isinstance(app, (bytes, bytearray)):
            raise TypeError("app must be binary data (bytes, bytearray)")
        if app_table and not MasterBootImageType.is_copied_to_ram(image_type):
            raise ValueError('app_table can be used only for images loaded to RAM')
        assert load_addr >= 0
        self.load_addr = load_addr
        self.image_type = image_type
        alignment = MasterBootImage._IMAGE_ALIGNMENT
        self.app = misc.align_block(bytes(app), alignment)
        self.app_table = app_table
        # hmac + key store
        self.hmac_key = bytes.fromhex(hmac_key) if isinstance(hmac_key, str) else hmac_key
        self.key_store = key_store
        # trust zone
        self.trust_zone = trust_zone or TrustZone.enabled()
        # security stuff
        self.cert_block = cert_block
        if self.cert_block:
            self.cert_block.alignment = 4  # type: ignore   # this value is used by elf-to-sb-gui
            self.signature_len = self.cert_block.signature_size  # type: ignore
        else:
            self.signature_len = 0
        self._priv_key_pem_data = priv_key_pem_data
        self.enable_hw_user_mode_keys = enable_hw_user_mode_keys
        self.ctr_init_vector = ctr_init_vector
        if MasterBootImageType.is_encrypted(self.image_type) and not ctr_init_vector:
            self.ctr_init_vector = crypto_backend().random_bytes(self._CTR_INIT_VECTOR_SIZE)
        self._verify_private_key()
        # validate parameters
        self._validate_new_instance()

    def _validate_new_instance(self) -> None:
        """Validate new instance.

        :raise ValueError: if there are invalid or conflicting parameters
        """
        # table
        if self.app_table:
            if not self.app_table.entries:
                raise ValueError("app_table is empty")

        # image size
        if len(self.app) < self.HMAC_OFFSET:
            raise ValueError("Image must be at least {} bytes".format(str(self.HMAC_OFFSET)))

        # security stuff
        if MasterBootImageType.is_signed(self.image_type):
            if not self.cert_block:
                raise ValueError("Certificate block must be specified for signed image (cert_block)")
            if not self._priv_key_pem_data:
                raise ValueError("Private Key must be specified for signed image (priv_key_path)")
        else:
            if self.cert_block:
                raise ValueError("Certificate block must be specified only for signed image (cert_block)")
            if self._priv_key_pem_data:
                raise ValueError("Private Key must be specified only for signed image (priv_key_path)")

        if MasterBootImageType.is_encrypted(self.image_type):
            if not self.ctr_init_vector or (len(self.ctr_init_vector) != self._CTR_INIT_VECTOR_SIZE):
                raise ValueError(f"Invalid length of CTR init vector, expected {str(self._CTR_INIT_VECTOR_SIZE)} bytes")

        # hmac
        if MasterBootImageType.has_hmac(self.image_type):
            if not self.hmac_key:
                raise ValueError("HMAC key must be specified for load-to-ram signed images (hmac_key)")
        else:
            if self.hmac_key:
                raise ValueError("HMAC user key cannot be applied into selected image (hmac_user_key)")
            if self.key_store:
                raise ValueError("KeyStore cannot be applied into selected image (key_store)")

    def _verify_private_key(self) -> None:
        """Verifies private key.

        :raise ValueError: if any parameter not valid
        """
        if self._priv_key_pem_data:
            cert_blk = self.cert_block
            assert cert_blk is not None
            if not cert_blk.verify_private_key(self._priv_key_pem_data):  # type: ignore
                raise ValueError('Signature verification failed, private key does not match to certificate')

    def info(self) -> str:
        """Text description of the instance."""
        msg = "Master Boot Image"
        msg += "Image type       : {}\n".format(MasterBootImageType.desc(self.image_type))
        msg += "Img load addr    : {}\n".format(hex(self.load_addr))
        msg += "Image length     : {}\n".format(len(self.data))
        msg += "HW user mode keys: {}\n".format("enabled" if self.enable_hw_user_mode_keys else "disabled")
        msg += "TrustZone        : {}\n".format(TrustZoneType.desc(self.trust_zone.type))
        if self.cert_block:
            msg += "[Certificate Block]\n"
            msg += self.cert_block.info()
        if self._priv_key_pem_data:
            msg += "Private Key  : {Yes}\n"
        return msg

    def _calculate_flags(self) -> int:
        flags = (self.trust_zone.type << 8) + self.image_type
        if self.key_store and self.key_store.export():
            flags |= self._KEY_STORE_FLAG
        if self.app_table:
            flags |= self._RELOC_TABLE_FLAG
        if self.enable_hw_user_mode_keys:
            flags |= self._HW_USER_KEY_EN_FLAG
        return flags

    def _update_ivt(self, data: bytes) -> bytes:
        data = bytearray(data)
        data[self.IMAGE_LENGTH_OFFSET: self.IMAGE_LENGTH_OFFSET + 4] = struct.pack("<I", self.total_len)
        # flags
        flags = self._calculate_flags()
        data[self.IMAGE_FLAGS_OFFSET: self.IMAGE_FLAGS_OFFSET + 4] = struct.pack("<I", flags)
        #
        data[self.LOAD_ADDR_OFFSET: self.LOAD_ADDR_OFFSET + 4] = struct.pack("<I", self.load_addr)
        if MasterBootImageType.is_signed(self.image_type):
            data[self.CERTIFICATE_OFFSET: self.CERTIFICATE_OFFSET + 4] = struct.pack("<I", self.app_len)
        if MasterBootImageType.has_crc(self.image_type):
            # calculate CRC using MPEG2 specification over all of data (app and trustzone)
            # expect for 4 bytes at CRC_BLOCK_OFFSET and put the resulting CRC there
            crc32_function = mkPredefinedCrcFun('crc-32-mpeg')
            crc = crc32_function(data[:self.CRC_BLOCK_OFFSET])
            crc = crc32_function(data[self.CRC_BLOCK_OFFSET + 4:], crc)
            data[self.CRC_BLOCK_OFFSET: self.CRC_BLOCK_OFFSET + 4] = struct.pack("<I", crc)
        return bytes(data)

    def _certificate(self, encr_data: bytes) -> bytes:
        """Create certificate optionally followed by encrypted image header and CTR init vector.

        :param encr_data: encrypted data for encrypted image; plain data otherwise
        :return:
        - for encrypted image: certificate with encrypted image header and CTR init vector
        - for signed image: certificate
        - for plain image: empty bytes
        """
        if not self.cert_block:
            return bytes()

        # for encrypted image create encrypted header located behind certificate
        if MasterBootImageType.is_encrypted(self.image_type):
            assert self.ctr_init_vector
            encr_header = encr_data[:56] + self.ctr_init_vector
        else:
            encr_header = bytes()
        self.cert_block.image_length = len(encr_data) + len(self.cert_block.export()) + len(encr_header)  # type: ignore
        return self.cert_block.export() + encr_header

    def _hmac(self, data: bytes) -> bytes:
        """Calculate HMAC for provided data.

        :param data: to calculate hmac
        :return: calculated hmac; empty bytes if the block does not contain any HMAC
        """
        if not MasterBootImageType.has_hmac(self.image_type):
            return bytes()

        assert self.hmac_key and len(self.hmac_key) == self._HMAC_KEY_LENGTH
        key = KeyStore.derive_hmac_key(self.hmac_key)
        assert len(key) == self._HMAC_DERIVED_KEY_LEN
        result = crypto_backend().hmac(key, data)
        assert len(result) == self.HMAC_SIZE
        return result

    def _encrypt(self, data: bytes) -> bytes:
        if not MasterBootImageType.is_encrypted(self.image_type):
            return data

        assert self.key_store, "key_store must be specified for encrypted image"
        assert self.hmac_key and len(self.hmac_key) == self._HMAC_KEY_LENGTH
        assert self.ctr_init_vector

        if self.key_store.key_source == KeySourceType.KEYSTORE:
            key = self.hmac_key  # user_key, the key not derived
        elif self.key_store.key_source == KeySourceType.OTP:
            key = self.key_store.derive_enc_image_key(self.hmac_key)
        else:
            assert False, "Unsupported key_source"

        aes = AES.new(key, AES.MODE_CTR, initial_value=self.ctr_init_vector, nonce=bytes())
        return aes.encrypt(data)

    def export(self) -> bytes:
        """Master boot image (binary)."""
        data = self._update_ivt(self.data)

        # signed or encrypted
        if MasterBootImageType.is_signed(self.image_type):
            assert self._priv_key_pem_data
            cb = self.cert_block
            assert (cb is not None) and cb.verify_private_key(self._priv_key_pem_data)  # type: ignore
            # encrypt
            encr_data = self._encrypt(data)
            encr_data = (self._update_ivt(encr_data[:self.HMAC_OFFSET]) +  # header
                         encr_data[self.HMAC_OFFSET:self.app_len] +  # encrypted image
                         self._certificate(encr_data) +  # certificate + encoded image header + CTR init vector
                         encr_data[self.app_len:])  # TZ encoded data
            encr_data += crypto_backend().rsa_sign(self._priv_key_pem_data, encr_data)  # signature
            # hmac + key store
            if MasterBootImageType.has_hmac(self.image_type):
                hmac_keystore = self._hmac(encr_data[:self.HMAC_OFFSET])
                if self.key_store:
                    hmac_keystore += self.key_store.export()
                encr_data = encr_data[:self.HMAC_OFFSET] + hmac_keystore + encr_data[self.HMAC_OFFSET:]
            return bytes(encr_data)

        return bytes(data)

    @classmethod
    def parse(cls, data: bytes, offset: int = 0, **kwargs: Any) -> None:
        """Parse."""
        raise NotImplementedError()


class MasterBootImageManifest:
    """MasterBootImage Manifest used in Niobe4Analog."""

    MAGIC = b"imgm"
    # FORMAT = "<4s2H3L"
    FORMAT = "<4s4L"
    # FORMAT_VERSION = "1.0"
    FORMAT_VERSION = 0x0001_0000
    DIGEST_PRESENT_FLAG = 0x8000_0000

    def __init__(self, firmware_version: int, trust_zone: TrustZone,
                 sign_hash_len: int = None) -> None:
        """Initialize MBI Manifest object.

        :param firmware_version: firmware version
        :param sign_hash_len: length of hash used for singing, defaults to None
        :param trust_zone: TrustZone instance, defaults to None
        """
        self.firmware_version = firmware_version
        self.sign_hash_len = sign_hash_len
        self.trust_zone = trust_zone
        self.total_length = self._calculate_length()
        self.flags = self._calculate_flags()

    def _calculate_length(self) -> int:
        length = struct.calcsize(self.FORMAT)
        # trustzone is always present
        length += len(self.trust_zone.export())
        return length

    def _calculate_flags(self) -> int:
        if not self.sign_hash_len:
            return 0
        hash_len_types = {0: 0, 32: 1, 48: 2, 64: 3}
        return self.DIGEST_PRESENT_FLAG | hash_len_types[self.sign_hash_len]

    def export(self) -> bytes:
        """Serialize MBI Manifest."""
        data = struct.pack(
            self.FORMAT,
            self.MAGIC,
            # *[int(part) for part in self.FORMAT_VERSION.split('.')],
            self.FORMAT_VERSION,
            self.firmware_version,
            self.total_length,
            self.flags
        )
        return data


class MasterBootImageN4Analog(MasterBootImage):
    """Master Boot Image layout specific for Niobe4Analog."""

    # flag indication presence of dual boot version (Used by Niobe4Analog)
    _DUAL_BOOT_VERSION_FLAG = 0x400

    def __init__(self, app: bytes, load_addr: int,
                 dual_boot_version: int = None, firmware_version: int = 1,
                 sign_hash_len: int = 0,
                 signature_provider: SignatureProvider = None, **kwargs: Any) -> None:
        """Initialize MBI for Niobe4Analog.

        :param app: application binary
        :param load_addr: Addres where to load application
        :param dual_boot_version: Version of dualboot application, defaults to None
        :param firmware_version: Firmware version, defaults to None
        :param sign_hash_len: Length of hash used for singing, defaults to 0
        :param signature_provider: Signature provider meant to sign the image
        :param kwargs: keyword arguments passed to MasterBootImage
        """
        super().__init__(app=app, load_addr=load_addr, **kwargs)
        self.dual_boot_version = dual_boot_version
        self.manifest = None
        self.signature_provider = signature_provider
        assert self.trust_zone, "TrustZone was not set in parent class!"
        if MasterBootImageType.is_signed(self.image_type):
            self.manifest = MasterBootImageManifest(
                firmware_version, sign_hash_len=sign_hash_len,
                trust_zone=self.trust_zone
            )

    def _calculate_flags(self) -> int:
        flags = super()._calculate_flags()
        if self.dual_boot_version:
            flags |= self._DUAL_BOOT_VERSION_FLAG
            flags |= self.dual_boot_version << 16
        return flags

    @property
    def data(self) -> bytes:
        """Plain, unsigned binary data for the image.

        It consists of:
        - application image
        - image manifest for signed image types
        - optionally trust zone data
        Please mind the result does not contain: certification block, HMAC, keystore and signature
        """
        # binary image
        data = self.app
        if MasterBootImageType.is_signed(self.image_type):
            assert self.cert_block, "Certificate Block is not set!"
            data += self.cert_block.export()
            assert self.manifest, "MasterBootImageManifest is not set!"
            data += self.manifest.export()
        # trust zone data
        data += self.trust_zone.export()
        if MasterBootImageType.is_signed(self.image_type):
            assert self.signature_provider, "Signature provider is not set!"
            signature = self.signature_provider.sign(data)
            assert signature, "Signature is not set!"
            data += serialize_ecc_signature(signature, 32)
        return data

    def _validate_new_instance(self) -> None:
        """Temporarily disable instance checking due to external singing."""
        pass

    @property
    def total_len(self) -> int:
        """Return the total (expected) length of the image."""
        image_length = len(self.app)
        image_length += len(self.trust_zone.export())
        if MasterBootImageType.is_signed(self.image_type):
            assert self.manifest, "MasterBootImageManifest is not set!"
            image_length += len(self.manifest.export())
            assert self.cert_block, "Certificate Block is not set!"
            image_length += self.cert_block.expected_size  # type: ignore
            # signature length
            image_length += 64
        return image_length

    def export(self) -> bytes:
        """Master boot image (binary)."""
        data = self._update_ivt(self.data)
        return data
