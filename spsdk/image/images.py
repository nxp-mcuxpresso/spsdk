#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Image."""

from datetime import datetime, timezone
from io import SEEK_CUR, SEEK_END, BufferedReader, BytesIO
from struct import unpack_from
from typing import Any, Optional, Union

from spsdk.crypto.certificate import Certificate
from spsdk.crypto.crypto_types import SPSDKEncoding
from spsdk.crypto.keys import PrivateKeyRsa
from spsdk.crypto.rng import random_bytes
from spsdk.crypto.symmetric import aes_ccm_decrypt, aes_ccm_encrypt
from spsdk.exceptions import SPSDKError, SPSDKParsingError
from spsdk.image.commands import (
    CmdAuthData,
    CmdInstallKey,
    EnumAlgorithm,
    EnumAuthDat,
    EnumCertFormat,
    EnumEngine,
    EnumInsKey,
)
from spsdk.image.header import Header, Header2
from spsdk.image.misc import NotEnoughBytesException, read_raw_data, read_raw_segment
from spsdk.image.secret import MAC, CertificateImg, Signature, SrkTable
from spsdk.image.segments import (
    AbstractFCB,
    FlexSPIConfBlockFCB,
    PaddingFCB,
    SegAPP,
    SegBDS3a,
    SegBDS3b,
    SegBDT,
    SegBEE,
    SegBIC1,
    SegCSF,
    SegDCD,
    SegIVT2,
    SegIVT3a,
    SegIVT3b,
    SegTag,
    SegXMCD,
    XMCDHeader,
)
from spsdk.utils.misc import align, align_block, extend_block
from spsdk.utils.spsdk_enum import SpsdkEnum

# This caused issue on Python 3.xx with pylint version 3.2.5 on LINUX
# pylint: disable=attribute-defined-outside-init

########################################################################################################################
# i.MX Boot Image Classes
########################################################################################################################


class EnumAppType(SpsdkEnum):
    """Type of the application image."""

    SCFW = (1, "SCFW")
    M4_0 = (2, "M4_0")
    M4_1 = (3, "M4_1")
    APP = (4, "APP")  # actually this means APP or A35 or A53
    A72 = (5, "A72")
    SCD = (6, "SCD")


class BootImgBase:
    """IMX Boot Image Base."""

    def __init__(self, address: int, offset: int) -> None:
        """Initialize boot image object.

        :param address: The start address of img in target memory
        :param offset: The IVT offset
        """
        self.address = address
        self.offset = offset
        self._dcd: Optional[SegDCD] = None

    @property
    def dcd(self) -> Optional[SegDCD]:
        """Device configuration data (DCD) segment; None if not assigned."""
        return self._dcd

    @dcd.setter
    def dcd(self, value: SegDCD) -> None:
        """Setter.

        :param value: new DCD segment
        """
        assert isinstance(value, SegDCD)
        self._dcd = value

    def __repr__(self) -> str:
        return f"Boot Image Base Class: {self.__class__.__name__}"

    def __str__(self) -> str:
        """Text info about the instance.

        :raises NotImplementedError: Derived class has to implement this method
        """
        raise NotImplementedError("Derived class has to implement this method.")

    def add_image(self, data: bytes, img_type: EnumAppType, address: int) -> None:
        """Add specific image into the main boot image.

        :param data: Raw binary data of the application image
        :param img_type: see EnumAppType
        :param address: TBD
        :raises NotImplementedError: Derived class has to implement this method
        """
        raise NotImplementedError("Derived class has to implement this method.")

    def export(self) -> bytes:
        """Binary representation of the instance (serialization).

        :raises NotImplementedError: Derived class has to implement this method
        """
        raise NotImplementedError("Derived class has to implement this method.")

    @classmethod
    def parse(
        cls,
        stream: Union[bytes, bytearray, BufferedReader, BytesIO],
        step: int = 0x100,
        size: Optional[int] = None,
    ) -> "BootImgBase":
        """Parse of IMX Boot Image Base.

        :raises NotImplementedError: Derived class has to implement this method
        """
        raise NotImplementedError("Derived class has to implement this method.")


########################################################################################################################
# Boot Image V1 Segments (i.MX5)
########################################################################################################################

# Obsolete, will not be implemented

########################################################################################################################
# Boot Image V2 (i.MX-RT)
########################################################################################################################


# pylint: disable=too-many-public-methods
class BootImgRT(BootImgBase):
    """IMX Boot Image v2."""

    # offset of the BEE PRDB Header segment
    BEE_OFFSET = 0x400
    # IVT offset for NOR flash
    IVT_OFFSET_NOR_FLASH = 0x1000
    # IVT offset for other memories
    IVT_OFFSET_OTHER = 0x400
    # IVT offset for other memories
    IVT_OFFSET_OTHER2 = 0xC00
    # supported IVT offsets
    IVT_OFFSETS = (0, IVT_OFFSET_OTHER, IVT_OFFSET_OTHER2, IVT_OFFSET_NOR_FLASH)
    # possible FCB offsets
    FCB_OFFSETS = (0, 0x400)
    # XMCD offset relative to IVT
    XMCD_IVT_OFFSET = 0x40
    # list of supported versions
    VERSIONS = (0x40, 0x41, 0x42, 0x43)
    # The offset and align value of APP segment (for XIP and non-XIP image)
    XIP_APP_OFFSET = 0x2000
    NON_XIP_APP_OFFSET = 0x1000
    # The value of CSF segment size
    CSF_SIZE = 0x2000
    # The length of BDT segment
    BDT_SIZE = 0x20
    # The length of DEK key section; Note: Dek key is just 16 bytes
    DEK_SIZE = 0x200  # Is this sector size alignment???

    def __init__(
        self,
        address: int,
        offset: int = IVT_OFFSET_NOR_FLASH,
        version: int = 0x40,
        plugin: bool = False,
    ):
        """Initialize boot image object.

        :param address: The start address of img in target memory, where the image is executed
        :param offset: The IVT offset; use IVT_OFFSET_NOR_FLASH for NOR-FLASH or IVT_OFFSET_OTHER
        :param version: The version of boot img format; default value should be used
        :param plugin: Do not use; see `self.plugin` property
        :raises SPSDKError: If invalid IVT offset
        :raises SPSDKError: If invalid version
        :raises SPSDKError: If Plugin is not supported
        """
        if offset not in BootImgRT.IVT_OFFSETS:
            raise SPSDKError("Invalid IVT offset")
        if version not in self.VERSIONS:
            raise SPSDKError("Invalid version")
        if plugin is True:
            raise SPSDKError("Plugin is not supported")  # not supported yet
        super().__init__(address, offset)
        self._nonce: Optional[bytes] = None
        self._dek_key: Optional[bytes] = None
        self._mac: Optional[bytes] = None
        self._fcb: AbstractFCB = PaddingFCB(self.IVT_OFFSET_OTHER)
        self._bee: SegBEE = SegBEE([])
        self._ivt: SegIVT2 = SegIVT2(version)
        self._bdt: SegBDT = SegBDT(plugin=int(plugin))
        self._app: SegAPP = SegAPP()
        self._dcd: Optional[SegDCD] = None
        self._csf: Optional[SegCSF] = None
        self._xmcd: Optional[SegXMCD] = None

    @property
    def version(self) -> int:
        """Version of the image format; must be from BootImgRT.VERSIONS."""
        return self._ivt.version

    @property
    def dek_key(self) -> Optional[bytes]:
        """DEK key for encrypted images; None for non-encrypted images."""
        return self._dek_key

    @dek_key.setter
    def dek_key(self, value: bytes) -> None:
        """Setter.

        :param value: DEK key for encrypted images
        :raises SPSDKError: If invalid length of DEK key
        """
        if len(value) != MAC.AES128_BLK_LEN:
            raise SPSDKError("Invalid length of DEK key")
        self._dek_key = value

    @property
    def plugin(self) -> bool:
        """Flag whether it is plugin image type; It is not fully supported by SPSDK yet.

        Plugin is designed to load a boot image from devices that are not natively supported by boot ROM.
        """
        return bool(self._bdt.plugin)

    @property
    def ivt(self) -> SegIVT2:
        """Image Vector Table (IVT) segment."""
        return self._ivt

    @ivt.setter
    def ivt(self, value: SegIVT2) -> None:
        """Setter.

        :param value: new value
        """
        assert isinstance(value, SegIVT2)
        self._ivt = value

    @property
    def ivt_offset(self) -> int:
        """Offset of the Image Vector Table (IVT) in the image."""
        return self.offset

    @ivt_offset.setter
    def ivt_offset(self, value: int) -> None:
        """Setter.

        :param value: new IVT offset
        :raises SPSDKError: If invalid IVT offset
        """
        if value not in self.IVT_OFFSETS:
            raise SPSDKError("Invalid IVT offset")
        self.offset = value

    @property
    def bdt(self) -> SegBDT:
        """Boot Data Table."""
        return self._bdt

    @bdt.setter
    def bdt(self, value: SegBDT) -> None:
        """Setter.

        :param value: new BDT value
        """
        assert isinstance(value, SegBDT)
        self._bdt = value

    @property
    def app(self) -> SegAPP:
        """Segment with application image."""
        return self._app

    @app.setter
    def app(self, value: SegAPP) -> None:
        """Setter.

        :param value: new application image
        """
        assert isinstance(value, SegAPP)
        self._app = value

    @property
    def csf(self) -> Optional[SegCSF]:
        """Command Sequence File (CSF), signature block for Secure Boot."""
        return self._csf

    @csf.setter
    def csf(self, value: SegCSF) -> None:
        """Setter.

        :param value: new CSF
        """
        assert isinstance(value, SegCSF)
        self._csf = value
        self._update()

    @property
    def enabled_csf(self) -> Optional[SegCSF]:
        """Enabled Command Sequence File (CSF) segment; None if CSF is not defined or it is not enabled."""
        return None if (self.csf is None) or not self.csf.enabled else self.csf

    @property
    def fcb(self) -> AbstractFCB:
        """Flash Configuration(Control) Block, binary data; content depends on FLASH type."""
        return self._fcb

    @fcb.setter
    def fcb(self, fcb: AbstractFCB) -> None:
        """Setter.

        :param fcb: FCB instance to be set
        """
        assert isinstance(fcb, AbstractFCB)
        self._fcb = fcb

    def set_flexspi_fcb(self, data: Union[bytes, FlexSPIConfBlockFCB]) -> None:
        """Set FlexSPI external FLASH configuration.

        :param data: FlexSPIConfBlockFCB or binary data representing
        """
        self.fcb = (
            data if isinstance(data, FlexSPIConfBlockFCB) else FlexSPIConfBlockFCB.parse(data)
        )

    @property
    def xmcd(self) -> Optional[SegXMCD]:
        """Return the XMCD block."""
        return self._xmcd

    @xmcd.setter
    def xmcd(self, xmcd: SegXMCD) -> None:
        """Sets the XMCD block."""
        assert isinstance(xmcd, SegXMCD)
        self._xmcd = xmcd

    def set_xmcd(self, data: Union[bytes, SegXMCD]) -> None:
        """Sets the XMCD block."""
        self.xmcd = data if isinstance(data, SegXMCD) else SegXMCD.parse(data)

    @property
    def bee(self) -> SegBEE:
        """:return: BEE segment that contains configuration of encrypted XIP.

        By default, BEE segment is empty. PRDB regions may be specified only for XIP images.
        """
        return self._bee

    @bee.setter
    def bee(self, bee: SegBEE) -> None:
        """Setter.

        :param bee: BEE instance to be set
        """
        assert isinstance(bee, SegBEE)
        self._bee = bee

    @property
    def app_offset(self) -> int:
        """:return: offset in the binary image, where the application starts.

        Please mind: the offset include FCB block (even the FCB block is not exported)
        The offset is 0x2000 for XIP images and 0x1000 for non-XIP images
        """
        return self.get_app_offset(self.ivt_offset)

    @staticmethod
    def get_app_offset(ivt_offset: int) -> int:
        """:return: offset in the binary image, where the application starts.

        Please mind: the offset include FCB block (even the FCB block is not exported)
        The offset is 0x2000 for XIP images and 0x1000 for non-XIP images

        :param ivt_offset: Offset of IVT segment
        """
        return (
            BootImgRT.XIP_APP_OFFSET
            if (ivt_offset == BootImgRT.IVT_OFFSET_NOR_FLASH)
            else BootImgRT.NON_XIP_APP_OFFSET
        )

    @property
    def size(self) -> int:
        """Size of the exported binary data.

        Please mind, FCB is exported optionally, but it is always included in the size
        """
        if self.fcb.enabled:
            result = self.app_offset + self.app.space
        else:
            result = self.app_offset + self.app.space - self.ivt_offset
        if (self.csf is not None) and self.csf.enabled:
            result += self.csf.space
        return result

    def _update(self) -> None:
        """Update Image Object."""
        # fcb
        self.fcb.padding_len = self.BEE_OFFSET - self.fcb.size if self.fcb.enabled else 0
        # bee
        if (self.ivt_offset == self.IVT_OFFSET_NOR_FLASH) and self.fcb.enabled:
            self.bee.padding_len = self.ivt_offset - self.BEE_OFFSET - self.bee.size
        else:
            self.bee.padding_len = 0
        self.bee.update()
        # padding for APP sections
        self.app.padding_len = 0
        # Set IVT section
        self.ivt.padding_len = 0
        self.ivt.ivt_address = self.address + self.ivt_offset
        self.ivt.bdt_address = self.ivt.ivt_address + self.ivt.space
        self.ivt.dcd_address = 0
        self.ivt.csf_address = 0
        # Set BDT section
        self.bdt.app_start = self.address
        self.bdt.app_length = self.app_offset + self.app.size
        self.bdt.plugin = 1 if self.plugin else 0
        self.bdt.padding_len = self.BDT_SIZE - self.bdt.size
        if self.dcd is not None:
            self.ivt.dcd_address = self.ivt.bdt_address + self.bdt.space
            self.dcd.padding_len = 0
        csf = self.enabled_csf
        if csf:
            self._update_csf(csf)

    @property
    def dek_ram_address(self) -> int:
        """Address of the DEK key in the RAM memory retrieved from the corresponding command.

        -1 if the image does not contain command for DEK key installation
        """
        csf = self.enabled_csf
        if csf:
            for cmd in csf.commands:
                if isinstance(cmd, CmdInstallKey) and (
                    cmd.certificate_format == EnumCertFormat.BLOB
                ):
                    return cmd.cmd_data_location
        return -1

    @property
    def dek_img_offset(self) -> int:
        """Offset of the DEK key in the image; -1 if DEK key address is available (see `dek_ram_address`)."""
        result = self.dek_ram_address
        return result if result < 0 else result - self.address

    def _update_csf(self, csf: SegCSF) -> None:
        """Update CSF segment.

        :param csf: CSF segment tu be updated
        :raises SPSDKError: If nonce not present
        :raises SPSDKError: If mac not present
        """
        self.app.padding_len = align(self.app.size, 0x1000) - self.app.size
        csf.update(True)
        self.ivt.csf_address = self.address + self.app_offset + self.app.space
        csf.padding_len = self.CSF_SIZE - csf.size
        self.bdt.app_length = self.app_offset + self.app.space + csf.space
        if self.hab_encrypted:
            # calculate address of a DEK key
            for cmd in csf.commands:
                if isinstance(cmd, CmdInstallKey) and (
                    cmd.certificate_format == EnumCertFormat.BLOB
                ):
                    cmd.cmd_data_location = self.address + self.bdt.app_length
            #
            self.bdt.app_length += self.DEK_SIZE  # to include DEK
            # update encryption signature
            if not self._nonce:
                raise SPSDKError("Nonce not present")
            if not self._mac:
                raise SPSDKError("Mac not present")
            for mac in csf.macs:
                mac.update_aead_encryption_params(self._nonce, self._mac)

    def __repr__(self) -> str:
        return f"Boot Image RT, Size: {self.size}B"

    def __str__(self) -> str:
        """Text info about the instance."""
        self._update()
        # Print FCB
        msg = "#" * 60 + "\n"
        msg += "# FCB (Flash Configuration Block)\n"
        msg += "#" * 60 + "\n\n"
        msg += str(self.fcb)
        # Print BEE
        if self.bee_encrypted:
            msg += "#" * 60 + "\n"
            msg += "# BEE (Encrypted XIP configuration)\n"
            msg += "#" * 60 + "\n\n"
            msg += str(self.bee)
        # Print IVT
        msg += "#" * 60 + "\n"
        msg += "# IVT (Image Vector Table)\n"
        msg += "#" * 60 + "\n\n"
        msg += str(self.ivt)
        # Print BDI
        msg += "#" * 60 + "\n"
        msg += "# BDI (Boot Data Info)\n"
        msg += "#" * 60 + "\n\n"
        msg += str(self.bdt)
        # Print DCD
        if (self.dcd is not None) and self.dcd.enabled:
            msg += "#" * 60 + "\n"
            msg += "# DCD (Device Config Data)\n"
            msg += "#" * 60 + "\n\n"
            msg += str(self.dcd)
        # Print XMCD
        if self.xmcd:
            msg += "#" * 60 + "\n"
            msg += "# XMCD (External Memory Configuration Data)\n"
            msg += "#" * 60 + "\n\n"
            msg += str(self.xmcd)
        # Print CSF
        csf = self.enabled_csf
        if csf:
            msg += "#" * 60 + "\n"
            msg += "# CSF (Code Signing Data)\n"
            msg += "#" * 60 + "\n\n"
            msg += str(csf)
        return msg

    def add_image(
        self,
        data: bytes,
        img_type: EnumAppType = EnumAppType.APP,
        address: int = -1,
        dek_key: Optional[bytes] = None,
        nonce: Optional[bytes] = None,
    ) -> None:
        """Add specific image into the main boot image.

        :param data: Raw data of img
        :param img_type: value must be EnumAppType.APP, no other options supported in this class
        :param address: start address of the application (entry point); Use -1 to detect the address from the image
        :param dek_key: key for AES128 image HAB encryption [16 bytes],
                    - use None for non-encrypted images;
                    - use empty bytes to create random key (recommended)
                    - use fixed key for testing to produce stable output
        :param nonce: initial vector for AEAD HAB encryption, if not specified random value is used;
                        For non-encrypted image use `None`
                        The parameter should be used only for testing to produce stable output
        :raises ValueError: if any parameter is not valid
        :raises SPSDKError: If invalid image type
        :raises SPSDKError: If image was already added
        :raises SPSDKError: If entry_addr not detected from image, must be specified explicitly
        :raises SPSDKError: If hab is not encrypted
        :raises SPSDKError: If nonce is not empty
        """
        if img_type != EnumAppType.APP:
            raise SPSDKError("Invalid image type")
        if self.app.data:
            raise SPSDKError("Image was already added")
        entry_addr = unpack_from("<I", data, 4)[0]
        if entry_addr == 0:  # there can be padding for images located in RAM, see flashloader
            entry_addr = address
            if entry_addr <= 0:
                raise SPSDKError("entry_addr not detected from image, must be specified explicitly")
        elif address >= 0 and address != entry_addr:
            raise SPSDKError("entry_address does not match with the image")
        self._ivt.app_address = entry_addr
        self.app.data = data
        if dek_key is not None:  # encrypted?
            # initialize DEK key
            self._dek_key = bytes([0]) * MAC.AES128_BLK_LEN if len(dek_key) == 0 else dek_key
            if len(self._dek_key) != MAC.AES128_BLK_LEN:
                raise SPSDKError(f"Invalid dek_key length, expected {MAC.AES128_BLK_LEN} bytes")
            # initialize NONCE
            if nonce:
                self._nonce = nonce
            nonce_len = BootImgRT.aead_nonce_len(self.app.size)
            if self._nonce is None:
                self._nonce = random_bytes(nonce_len)
            elif len(self._nonce) != nonce_len:
                raise SPSDKError(f"Invalid nonce length, expected {nonce_len} bytes")
            # encrypt APP
            if not self.hab_encrypted:
                raise SPSDKError("Hab is not encrypted")
            self.app.data = self._hab_encrypt_app_data(align_block(data, MAC.AES128_BLK_LEN))
        else:
            if nonce is not None:
                raise SPSDKError("Nonce is not empty")

    def add_dcd_bin(self, data: bytes) -> None:
        """Add DCD binary data.

        :param data: DCD binary data to be added
        :raises SPSDKError: If DCD is already present
        :raises SPSDKError: If DCD is not enabled
        """
        if self.dcd is not None:
            raise SPSDKError("DCD is already present")
        self.dcd = SegDCD.parse(data)
        if not self.dcd:
            raise SPSDKError("DCD must be enabled to include DCD into export")

    def add_csf_standard_auth(
        self,
        version: int,
        srk_table: SrkTable,
        src_key_index: int,
        csf_cert: bytes,
        csf_priv_key: PrivateKeyRsa,
        img_cert: bytes,
        img_priv_key: PrivateKeyRsa,
    ) -> None:
        """Add CSF with standard authentication.

        Before calling, application image and address must be assigned

        :param version: CSF segment version
        :param srk_table: SRK table of root certificates; must contain min 1, max 4 certificates
        :param src_key_index: index of selected SRK key used for authentication
        :param csf_cert: CSF certificate
        :param csf_priv_key: CSF private key
        :param img_cert: IMG certificate
        :param img_priv_key: IMG private key; decrypted binary data in PEM format
        :raises SPSDKError: If invalid length of srk table
        :raises SPSDKError: If invalid index of selected SRK key
        :raises SPSDKError: If application data not present
        """
        if not 1 <= len(srk_table) <= 4:
            raise SPSDKError("Invalid length of srk table")
        if not 0 <= src_key_index < len(srk_table):
            raise SPSDKError("Invalid index of selected SRK key")
        csf = SegCSF(version=version, enabled=True)
        # install SRK
        cmd_ins = CmdInstallKey(
            EnumInsKey.CLR, EnumCertFormat.SRK, EnumAlgorithm.SHA256, src_key_index, 0
        )
        cmd_ins.cmd_data_reference = srk_table
        csf.append_command(cmd_ins)
        # install CSF certificate
        cmd_ins = CmdInstallKey(EnumInsKey.CSF, EnumCertFormat.X509, EnumAlgorithm.ANY, 0, 1)
        cert = Certificate.parse(csf_cert)
        cmd_ins.cmd_data_reference = CertificateImg(
            version=version, data=cert.export(SPSDKEncoding.DER)
        )
        csf.append_command(cmd_ins)
        # authenticate content of the CSF segment
        cmd_auth = CmdAuthData(
            EnumAuthDat.CLR,
            1,
            EnumCertFormat.CMS,
            EnumEngine.DCP,
            certificate=cert,
            private_key=csf_priv_key,
        )
        cmd_auth.cmd_data_reference = Signature(version=version)
        csf.append_command(cmd_auth)
        # install image certificate
        cmd_ins = CmdInstallKey(EnumInsKey.CLR, EnumCertFormat.X509, EnumAlgorithm.ANY, 0, 2)
        cert = Certificate.parse(img_cert)
        cmd_ins.cmd_data_reference = CertificateImg(
            version=version, data=cert.export(SPSDKEncoding.DER)
        )
        csf.append_command(cmd_ins)
        # authenticate image data
        cmd_auth = CmdAuthData(
            EnumAuthDat.CLR,
            2,
            EnumCertFormat.CMS,
            EnumEngine.DCP,
            certificate=cert,
            private_key=img_priv_key,
        )
        cmd_auth.append(self.address + self.ivt_offset, SegIVT2.SIZE + BootImgRT.BDT_SIZE)
        if self.dcd:
            cmd_auth.append(
                self.address + self.ivt_offset + SegIVT2.SIZE + BootImgRT.BDT_SIZE,
                self.dcd.size,
            )
        app_data = self.app.data
        if app_data is None:
            raise SPSDKError("Application data not present")
        cmd_auth.append(self.address + self.app_offset, align(len(app_data), 16))
        cmd_auth.cmd_data_reference = Signature(version=version)
        csf.append_command(cmd_auth)
        self.csf = csf

    @property
    def bee_encrypted(self) -> bool:
        """True if BEE encrypted XIP image (with SW keys); False otherwise; see also `hab_encrypted`."""
        return self.bee.size > 0

    @property
    def hab_encrypted(self) -> bool:
        """True if HAB encrypted; False otherwise; see also `bee_encrypted`."""
        return self._dek_key is not None

    @staticmethod
    def aead_nonce_len(app_data_len: int) -> int:
        """Nonce len for AEAD encryption.

        Note: The code was taken from CST tool
        """
        if app_data_len < 0x10000:
            len_bytes = 2
        elif app_data_len < 0x1000000:
            len_bytes = 3
        else:
            len_bytes = 4
        return 16 - 1 - len_bytes  # AES_BLOCK_BYTES - FLAG_BYTES - len_bytes

    def _hab_encrypt_app_data(self, app_data: bytes) -> bytes:
        """HAB Encrypt application data.

        :param app_data: application data to be encrypted
        :return: encrypted application data (using HAB encryption)
        :raises SPSDKError: If nonce is not present
        :raises SPSDKError: If invalid length of application data
        :raises SPSDKError: If DEK key is not present
        :raises SPSDKError: If invalid length of encrypted data
        """
        if self._nonce is None:
            raise SPSDKError("Nonce is not present")
        if not len(app_data) & (MAC.AES128_BLK_LEN - 1) == 0:
            raise SPSDKError("Invalid length of application data")
        dek = self.dek_key
        if dek is None:
            raise SPSDKError("DEK key is not present")
        encr = aes_ccm_encrypt(
            key=dek,
            plain_data=app_data,
            nonce=self._nonce,
            associated_data=b"",
            tag_len=MAC.AES128_BLK_LEN,
        )
        if len(encr) != len(app_data) + 16:
            raise SPSDKError("Invalid length of encrypted data")
        self._mac = encr[-16:]
        return encr[:-16]

    @property
    def decrypted_app_data(self) -> bytes:
        """Return decrypted binary application data.

        Note: dek key, mac and nonce must be assigned for decryption
        :raises SPSDKError: If application not present
        :raises SPSDKError: If invalid length of application data
        :raises SPSDKError: If Mac or nonce or dek not present
        """
        app_data = self.app.data
        if not app_data:
            raise SPSDKError("Application not present")
        if not self.hab_encrypted:
            return app_data

        if not len(app_data) & (MAC.AES128_BLK_LEN - 1) == 0:
            raise SPSDKError("Invalid length of application data")
        mac = self._mac
        dek = self.dek_key
        if not (mac and self._nonce and dek):
            raise SPSDKError("Mac or nonce or dek not present")
        return aes_ccm_decrypt(
            key=dek,
            encrypted_data=app_data + mac,
            nonce=self._nonce,
            associated_data=b"",
            tag_len=MAC.AES128_BLK_LEN,
        )

    def add_csf_encrypted(
        self,
        version: int,
        srk_table: SrkTable,
        src_key_index: int,
        csf_cert: bytes,
        csf_priv_key: PrivateKeyRsa,
        img_cert: bytes,
        img_priv_key: PrivateKeyRsa,
    ) -> None:
        """Add CSF with image encryption.

        Before calling, application image and address must be assigned

        :param version: CSF segment version
        :param srk_table: SRK table of root certificates; must contain min 1, max 4 certificates
        :param src_key_index: index of selected SRK key used for authentication, 0..srk_table.len - 1
        :param csf_cert: CSF certificate
        :param csf_priv_key: CSF private key
        :param img_cert: IMG certificate
        :param img_priv_key: IMG private key
        :raises SPSDKError: If invalid length of srk table
        :raises SPSDKError: If invalid index of srk table
        :raises SPSDKError: If application data is not present
        """
        if not 1 <= len(srk_table) <= 4:
            raise SPSDKError("Invalid length of srk table")
        if not 0 <= src_key_index < len(srk_table):
            raise SPSDKError("Invalid index of srk table")
        csf = SegCSF(version=version, enabled=True)
        # install SRK
        cmd_ins = CmdInstallKey(
            EnumInsKey.CLR, EnumCertFormat.SRK, EnumAlgorithm.SHA256, src_key_index, 0
        )
        cmd_ins.cmd_data_reference = srk_table
        csf.append_command(cmd_ins)
        # install CSF certificate
        cmd_ins = CmdInstallKey(EnumInsKey.CSF, EnumCertFormat.X509, EnumAlgorithm.ANY, 0, 1)
        cert = Certificate.parse(csf_cert)
        cmd_ins.cmd_data_reference = CertificateImg(
            version=version, data=cert.export(SPSDKEncoding.DER)
        )
        csf.append_command(cmd_ins)
        # authenticate content of the CSF segment
        cmd_auth = CmdAuthData(
            EnumAuthDat.CLR,
            1,
            EnumCertFormat.CMS,
            EnumEngine.DCP,
            certificate=cert,
            private_key=csf_priv_key,
        )
        cmd_auth.cmd_data_reference = Signature(version=version)
        csf.append_command(cmd_auth)
        # install image certificate
        cmd_ins = CmdInstallKey(EnumInsKey.CLR, EnumCertFormat.X509, EnumAlgorithm.ANY, 0, 2)
        cert = Certificate.parse(img_cert)
        cmd_ins.cmd_data_reference = CertificateImg(
            version=version, data=cert.export(SPSDKEncoding.DER)
        )
        csf.append_command(cmd_ins)
        # authenticate image data
        cmd_auth = CmdAuthData(
            EnumAuthDat.CLR,
            2,
            EnumCertFormat.CMS,
            EnumEngine.DCP,
            certificate=cert,
            private_key=img_priv_key,
        )
        cmd_auth.append(self.address + self.ivt_offset, SegIVT2.SIZE + BootImgRT.BDT_SIZE)
        app_data = self.app.data
        if app_data is None:
            raise SPSDKError("Application data is not present")
        cmd_auth.cmd_data_reference = Signature(version=version)
        csf.append_command(cmd_auth)
        # install DEK key
        cmd_ins = CmdInstallKey(EnumInsKey.ABS, EnumCertFormat.BLOB, EnumAlgorithm.ANY, 0, 0)
        csf.append_command(cmd_ins)
        # check encrypted data
        cmd_auth = CmdAuthData(
            EnumAuthDat.CLR,
            0,
            EnumCertFormat.AEAD,
            EnumEngine.DCP,
            certificate=cert,
            private_key=img_priv_key,
        )
        if app_data is None:
            raise SPSDKError("Application data is not present")
        cmd_auth.append(self.address + self.app_offset, align(len(app_data), 16))
        cmd_auth.cmd_data_reference = MAC(version=version, nonce_len=0xD, mac_len=16)
        csf.append_command(cmd_auth)
        #
        self.csf = csf

    def export_fcb(self) -> bytes:
        """Export FCB segment.

        :return: binary FCB segment
        :raises SPSDKError: If invalid length of data
        """
        if not self.fcb.enabled:
            return b""
        data = self.fcb.export()
        if len(data) != self.fcb.space:
            raise SPSDKError("Invalid length of data")
        return data

    def export_bee(self) -> bytes:
        """Export BEE segment.

        :return: binary BEE segment
        :raises SPSDKError: if any BEE region is configured for images not located in the FLASH
        """
        data = b""
        if self.ivt_offset == self.IVT_OFFSET_NOR_FLASH:
            data = self.bee.export()
        elif self.bee.space > 0:
            raise SPSDKError("BEE can be configured only for XIP images located in FLASH")
        return data

    def export_dcd(self) -> bytes:
        """Export DCD segment.

        :return: binary DCD segment
        :raises SPSDKError: If DCD padding is not set
        """
        dcd_data = b""
        if (self.dcd is not None) and self.dcd.enabled:
            if self.dcd.padding_len != 0:
                raise SPSDKError("Padding can not be present")
            dcd_data = self.dcd.export()
        return dcd_data

    def export_csf(self, data: bytes, zulu: datetime = datetime.now(timezone.utc)) -> bytes:
        """Export CSF segment.

        :param data: generated binary data used for creating of signature
        :param zulu: current UTC datetime
        :return: binary CFD segment
        """
        csf_data = b""
        if self.enabled_csf:
            base_data_addr = self.address if self.fcb.enabled else self.address + self.ivt_offset
            self.enabled_csf.update_signatures(zulu, data, base_data_addr)
            csf_data = self.enabled_csf.export()
        return csf_data

    def _bee_encrypt_img_data(self, data: bytes) -> bytes:
        """Encrypt data located in BEE regions.

        :param data: image data (including IVT offset) to be encrypted
        :return: the image with encrypted regions
        :raises SPSDKError: If image configuration is invalid and BEE encryption cannot be applied
        """
        if not self.bee_encrypted:
            return data

        if self.ivt_offset != self.IVT_OFFSET_NOR_FLASH:
            raise SPSDKError("BEE encryption is supported only for NOR FLASH")
        if self.hab_encrypted:
            raise SPSDKError("BEE encryption cannot be used for HAB encrypted images")

        # encrypt
        return data[: self.ivt_offset] + self.bee.encrypt_data(
            self.address + self.ivt_offset, data[self.ivt_offset :]
        )

    def export(
        self,
        zulu: datetime = datetime.now(timezone.utc),
    ) -> bytes:
        """Export image as bytes array.

        :param zulu: optional UTC datetime; should be used only if you need fixed datetime for the test
                Note: the parameter is applied to CSF only, so it is not used for unsigned images
        :raises SPSDKError: If the image is not encrypted
        :raises SPSDKError: If padding is present
        :raises SPSDKError: If invalid alignment of application
        :return: bytes
        """
        csf = self.enabled_csf
        if csf:
            csf.update_signatures(zulu, b"", 0)  # dummy call to provide size of the CSF section
        elif self.dek_key is not None:
            raise SPSDKError("CSF must be assigned for encrypted images")

        self._update()
        # FCB
        data = self.export_fcb()
        # BEE
        bee_data = self.export_bee()
        data += bee_data
        # IVT
        ivt_data = self.ivt.export()
        data += ivt_data
        # BDT
        bdt_data = self.bdt.export()
        data += bdt_data
        # DCD
        dcd_data = self.export_dcd()
        data += dcd_data
        # padding before APP
        app_alignment = self.app_offset if self.fcb.enabled else self.app_offset - self.ivt_offset
        if not app_alignment >= len(data):
            raise SPSDKError("Invalid alignment of application")
        data = extend_block(data, app_alignment)
        # APP
        app_data = self.app.export()
        data += app_data
        # CSF
        csf_data = self.export_csf(data=data, zulu=zulu)
        data += csf_data
        return self._bee_encrypt_img_data(data)

    @classmethod
    def _find_ivt_pos(
        cls, strm: Union[BufferedReader, BytesIO], size: Optional[int] = None
    ) -> tuple[Header, int, int]:
        """Search IVT start position in the image; used by parser.

        :param strm: of image data; start seeking from current position
        :param size: maximum length
        :raises SPSDKError: Raised when IVT is not found
        :return: tuple with: Header, start position, end position
        """
        start_pos = strm.tell()
        end_pos = strm.seek(0, SEEK_END)

        if size:
            end_pos = min(start_pos + size, end_pos)

        for ivt_ofs in cls.IVT_OFFSETS:
            if start_pos + ivt_ofs > end_pos:
                break
            strm.seek(start_pos + ivt_ofs)
            header_data = read_raw_data(strm, Header.SIZE, no_seek=True)
            try:
                header = Header.parse(header_data, required_tag=SegTag.IVT2.tag)
                if (header.length == SegIVT2.SIZE) and (header.param in cls.VERSIONS):
                    return header, start_pos + ivt_ofs, end_pos
            except SPSDKParsingError:  # ignore different header tags
                pass

        raise SPSDKError("IVT not found")

    @classmethod
    def _find_fcb_pos(
        cls, stream: Union[BufferedReader, BytesIO], size: Optional[int] = None
    ) -> Optional[int]:
        """Search for FCB start position.

        :param stream: data to search through
        :param size: maximal size to search through; default: whole stream
        :return: Starting location of FCB, None if FCB is not found
        """
        start_pos = stream.seek(0)
        end_pos = stream.seek(0, SEEK_END)

        if size:
            end_pos = min(start_pos + size, end_pos)

        for possible_offset in cls.FCB_OFFSETS:
            current_pos = start_pos + possible_offset
            if current_pos > end_pos:
                break
            stream.seek(current_pos)
            data = read_raw_data(stream, len(FlexSPIConfBlockFCB.TAG))
            if data == FlexSPIConfBlockFCB.TAG:
                return current_pos

        return None

    @classmethod
    def parse(
        cls,
        stream: Union[bytes, bytearray, BufferedReader, BytesIO],
        step: int = 0,
        size: Optional[int] = None,
    ) -> "BootImgRT":
        """Parse bootable RT image from stream buffer or bytes array.

        :param stream: The stream buffer or bytes array
        :param step: Image searching step (this parameter is not used for RT)
        :param size: parsing size; None to parse till the end of the stream
        :raises SPSDKError: Raised when the value type is incorrect
        :return: BootImgRT object
        """
        if isinstance(stream, (bytes, bytearray)):
            stream = BytesIO(stream)

        if not isinstance(stream, (BufferedReader, BytesIO)):
            raise SPSDKError(f' Not correct value type: "{type(stream)}" !')

        header, start_pos, end_pos = cls._find_ivt_pos(stream, size)

        obj = BootImgRT(0, version=header.param)
        img_size = end_pos - start_pos
        if start_pos > 0:
            obj.ivt_offset = start_pos

        # Parse IVT
        obj.ivt = SegIVT2.parse(read_raw_segment(stream, SegTag.IVT2.tag))

        # Try to find XMCD segment
        stream.seek(start_pos + cls.XMCD_IVT_OFFSET)
        try:
            xmcd_header = XMCDHeader.parse(read_raw_data(stream, XMCDHeader.SIZE))
            xmcd_data = read_raw_data(stream, xmcd_header.config_data_size)
            obj.xmcd = SegXMCD(header=xmcd_header, config_data=xmcd_data)
        except SPSDKParsingError:
            # No XMCD found
            pass
        # Parse BDT
        stream.seek(start_pos + obj.ivt.bdt_address - obj.ivt.ivt_address)
        obj.bdt = SegBDT.parse(read_raw_data(stream, SegBDT.SIZE))
        obj.ivt_offset = obj.ivt.ivt_address - obj.bdt.app_start
        obj.address = obj.bdt.app_start
        # Parse DCD
        if obj.ivt.dcd_address:
            stream.seek(start_pos + obj.ivt.dcd_address - obj.ivt.ivt_address)
            obj.dcd = SegDCD.parse(read_raw_segment(stream, SegTag.DCD.tag))
        # Parse APP
        if obj.ivt.csf_address > 0:
            app_size = obj.ivt.csf_address - obj.ivt.ivt_address - (obj.app_offset - obj.ivt_offset)
        else:
            app_size = img_size - (obj.app_offset - obj.ivt_offset)
        obj.app.data = read_raw_data(stream, app_size, obj.app_offset - obj.ivt_offset + start_pos)
        obj.app.padding = 0
        # Parse CSF
        if obj.ivt.csf_address:
            csf_start = start_pos + (obj.ivt.csf_address - obj.ivt.ivt_address)
            obj.csf = SegCSF.parse(read_raw_data(stream, cls.CSF_SIZE, csf_start))
            # detect encrypted image using MAC section
            mac = next(obj.csf.macs, None)
            if mac:
                obj._nonce = mac.nonce
                obj._mac = mac.mac
                obj._dek_key = bytes([0]) * MAC.AES128_BLK_LEN  # dek key is not known

        # Parse FCB
        fcb_size = FlexSPIConfBlockFCB().size
        fcb_position = cls._find_fcb_pos(stream)
        if fcb_position is not None:
            fcb_data = read_raw_data(stream, fcb_size, fcb_position)
            obj.set_flexspi_fcb(fcb_data)
        else:
            obj.fcb = PaddingFCB(fcb_size, enabled=True)

        return obj


########################################################################################################################
# Boot Image V2 (i.MX6, i.MX7)
########################################################################################################################


class BootImg2(BootImgBase):
    """IMX Boot Image v2."""

    # The value of CSF segment size
    CSF_SIZE = 0x2000
    # The align value of APP segment
    APP_ALIGN = 0x1000
    # The value of img head size
    #           offset | size
    HEAD_SIZE = {0x400: 0xC00, 0x100: 0x300}

    @property
    def version(self) -> int:
        """Version of IMX Boot Image v2."""
        return self._ivt.version

    @version.setter
    def version(self, value: int) -> None:
        self._ivt.version = value

    @property
    def plugin(self) -> bool:
        """Plugin."""
        return self._plg

    @plugin.setter
    def plugin(self, value: bool) -> None:
        assert isinstance(value, bool)
        self._plg = value

    @property
    def ivt(self) -> SegIVT2:
        """IVT."""
        return self._ivt

    @ivt.setter
    def ivt(self, value: SegIVT2) -> None:
        assert isinstance(value, SegIVT2)
        self._ivt = value

    @property
    def bdt(self) -> SegBDT:
        """BDT."""
        return self._bdt

    @bdt.setter
    def bdt(self, value: SegBDT) -> None:
        assert isinstance(value, SegBDT)
        self._bdt = value

    @property
    def app(self) -> SegAPP:
        """APP."""
        return self._app

    @app.setter
    def app(self, value: SegAPP) -> None:
        assert isinstance(value, SegAPP)
        self._app = value

    @property
    def csf(self) -> SegCSF:
        """CSF."""
        return self._csf

    @csf.setter
    def csf(self, value: SegCSF) -> None:
        assert isinstance(value, SegCSF)
        self._csf = value

    @property
    def size(self) -> int:
        """Size of IMX Boot Image v2.."""
        result = self.ivt.space
        result += self.bdt.space
        if self.dcd:
            result += self.dcd.space
        result += self.app.space
        result += self.csf.space
        return result

    def __init__(
        self,
        address: int = 0,
        offset: int = 0x400,
        version: int = 0x41,
        plugin: bool = False,
    ) -> None:
        """Initialize boot image object.

        :param address: The start address of img in target memory
        :param offset: The IVT offset
        :param version: The version of boot img format
        :param plugin: if plugin
        """
        super().__init__(address, offset)
        self._ivt = SegIVT2(version)
        self._bdt = SegBDT()
        self._app = SegAPP()
        self._dcd = SegDCD()
        self._csf = SegCSF()
        self._plg = plugin

    def _update(self) -> None:
        """Update Image Object."""
        # Set zero padding for IVT and BDT sections
        self.ivt.padding = 0
        self.bdt.padding = 0
        # Calculate padding for DCD, APP and CSF sections
        tmp_val = self.ivt.space + self.bdt.space
        if self.dcd:
            tmp_val += self.dcd.size
        head_size = 0xC00 if self.offset not in self.HEAD_SIZE else self.HEAD_SIZE[self.offset]
        if self.dcd:
            self.dcd.padding = head_size - tmp_val
        tmp_val = self.app.size % self.APP_ALIGN
        self.app.padding = self.APP_ALIGN - tmp_val if tmp_val > 0 else 0
        # Set IVT section
        self.ivt.ivt_address = self.address + self.offset
        self.ivt.bdt_address = self.ivt.ivt_address + self.ivt.space
        if self.dcd:
            self.ivt.dcd_address = self.ivt.bdt_address + self.bdt.space
            self.ivt.app_address = self.ivt.dcd_address + self.dcd.space
        else:
            self.ivt.dcd_address = 0
            self.ivt.app_address = self.ivt.bdt_address + self.bdt.space
        if self.csf.enabled:
            self.ivt.csf_address = self.ivt.app_address + self.app.space
            self.csf.padding = self.CSF_SIZE - self.csf.size
        else:
            self.ivt.csf_address = 0
        # Set BDT section
        self.bdt.app_start = self.ivt.ivt_address - self.offset
        self.bdt.app_length = self.size + self.offset
        self.bdt.plugin = 1 if self.plugin else 0

    def __repr__(self) -> str:
        return f"Boot Image v2, Size: {self.size}B"

    def __str__(self) -> str:
        """String representation of the IMX Boot Image v2."""
        self._update()
        # Print IVT
        msg = "#" * 60 + "\n"
        msg += "# IVT (Image Vector Table)\n"
        msg += "#" * 60 + "\n\n"
        msg += str(self.ivt)
        # Print DBI
        msg += "#" * 60 + "\n"
        msg += "# BDI (Boot Data Info)\n"
        msg += "#" * 60 + "\n\n"
        msg += str(self.bdt)
        # Print DCD
        if self.dcd:
            msg += "#" * 60 + "\n"
            msg += "# DCD (Device Config Data)\n"
            msg += "#" * 60 + "\n\n"
            msg += str(self.dcd)
        # Print CSF
        if self.csf.enabled:
            msg += "#" * 60 + "\n"
            msg += "# CSF (Code Signing Data)\n"
            msg += "#" * 60 + "\n\n"
            msg += str(self.csf)
        return msg

    def add_image(
        self, data: bytes, img_type: EnumAppType = EnumAppType.APP, address: int = 0
    ) -> None:
        """Add specific image into the main boot image.

        :param data: Raw data of img
        :param img_type: Type of img
        :param address: address in RAM
        :raises Exception: Raised when the data type is unknown
        """
        if img_type == EnumAppType.APP:
            self.app.data = data
            if address != 0:
                self.address = address
        else:
            raise SPSDKError("Unknown data type !")

    def export(self) -> bytes:
        """Export image as bytes array.

        :return: bytes
        """
        self._update()
        data = self.ivt.export()
        data += self.bdt.export()
        if self.dcd:
            data += self.dcd.export()
        data += self.app.export()
        data += self.csf.export()
        return data

    @classmethod
    def parse(
        cls,
        stream: Union[bytes, bytearray, BufferedReader, BytesIO],
        step: int = 0x100,
        size: Optional[int] = None,
    ) -> "BootImg2":
        """Parse image from stream buffer or bytes array.

        :param stream: The stream buffer or bytes array
        :param step: Image searching step
        :param size: parsing size
        :raises SPSDKError: Raised when value type is incorrect
        :raises SPSDKError: Raised when there is not an i.MX Boot Image
        :return: BootImg2 object
        """
        if isinstance(stream, (bytes, bytearray)):
            stream = BytesIO(stream)

        if not isinstance(stream, (BufferedReader, BytesIO)):
            raise SPSDKError(f"Not correct value type: {type(stream)} !")

        header = Header()
        start_index = stream.tell()
        last_index = stream.seek(0, SEEK_END)
        stream.seek(start_index)

        if size:
            last_index = min(start_index + size, last_index)

        imx_image = False
        while start_index < (last_index - Header.SIZE):
            header = Header.parse(read_raw_data(stream, Header.SIZE, no_seek=True))
            if (
                header.tag == SegTag.IVT2
                or header.length == SegIVT2.SIZE
                or header.param in (0x40, 0x41, 0x42, 0x43)
            ):
                imx_image = True
                break

            start_index = stream.seek(step, SEEK_CUR)

        if not imx_image:
            raise SPSDKError("Not an i.MX Boot Image!")

        obj = BootImg2()
        if header.param:
            obj.version = header.param

        img_size = last_index - start_index
        if start_index > 0:
            obj.offset = start_index

        # Parse IVT
        obj.ivt = SegIVT2.parse(read_raw_segment(stream, SegTag.IVT2.tag))
        # Parse BDT
        obj.bdt = SegBDT.parse(read_raw_data(stream, SegBDT.SIZE))
        obj.offset = obj.ivt.ivt_address - obj.bdt.app_start
        obj.address = obj.bdt.app_start
        obj.plugin = bool(obj.bdt.plugin)
        # Parse DCD
        if obj.ivt.dcd_address:
            obj.dcd = SegDCD.parse(read_raw_segment(stream, SegTag.DCD.tag))
            obj.dcd.padding = (obj.ivt.app_address - obj.ivt.dcd_address) - obj.dcd.size
        # Parse APP
        app_start = start_index + (obj.ivt.app_address - obj.ivt.ivt_address)
        app_size = (
            obj.ivt.csf_address - obj.ivt.app_address
            if obj.ivt.csf_address
            else obj.bdt.app_length - (obj.bdt.app_start - obj.ivt.app_address)
        )
        app_size = img_size - app_start if app_size > (img_size - app_start) else app_size
        obj.app.data = read_raw_data(stream, app_size, app_start)
        obj.app.padding = 0
        # Parse CSF
        if obj.ivt.csf_address:
            csf_start = start_index + (obj.ivt.csf_address - obj.ivt.ivt_address)
            try:
                obj.csf = SegCSF.parse(read_raw_data(stream, cls.CSF_SIZE, csf_start))
                obj.csf.padding = cls.CSF_SIZE - obj.csf.size
            except NotEnoughBytesException:
                pass

        return obj


########################################################################################################################
# Boot Image V2b (i.MX8M)
########################################################################################################################


class BootImg8m(BootImgBase):
    """IMX Boot Image."""

    # The value of CSF segment size
    CSF_SIZE = 0x2000
    # The align value of APP segment
    APP_ALIGN = 0x1000
    # The value of img head size
    #           offset | size
    HEAD_SIZE = {0x400: 0xC00, 0x100: 0x300}

    @property
    def version(self) -> int:
        """Version of IMX Boot Image."""
        return self._ivt.version

    @version.setter
    def version(self, value: int) -> None:
        self._ivt.version = value

    @property
    def plugin(self) -> bool:
        """Plugin."""
        return self._plg

    @plugin.setter
    def plugin(self, value: bool) -> None:
        assert isinstance(value, bool)
        self._plg = value

    @property
    def ivt(self) -> SegIVT2:
        """IVT."""
        return self._ivt

    @ivt.setter
    def ivt(self, value: SegIVT2) -> None:
        assert isinstance(value, SegIVT2)
        self._ivt = value

    @property
    def bdt(self) -> SegBDT:
        """BDT."""
        return self._bdt

    @bdt.setter
    def bdt(self, value: SegBDT) -> None:
        assert isinstance(value, SegBDT)
        self._bdt = value

    @property
    def app(self) -> SegAPP:
        """APP."""
        return self._app

    @app.setter
    def app(self, value: SegAPP) -> None:
        assert isinstance(value, SegAPP)
        self._app = value

    @property
    def csf(self) -> SegCSF:
        """CSF."""
        return self._csf

    @csf.setter
    def csf(self, value: SegCSF) -> None:
        assert isinstance(value, SegCSF)
        self._csf = value

    @property
    def size(self) -> int:
        """Size of IMX Boot Image."""
        result = self.ivt.space
        result += self.bdt.space
        if self.dcd:
            result += self.dcd.space
        result += self.app.space
        result += self.csf.space
        return result

    def __init__(
        self,
        address: int = 0,
        offset: int = 0x400,
        version: int = 0x41,
        plugin: bool = False,
    ) -> None:
        """Initialize boot image object.

        :param address: The start address of img in target memory
        :param offset: The IVT offset
        :param version: The version of boot img format
        :param plugin: if plugin
        """
        super().__init__(address, offset)
        self._ivt = SegIVT2(version)
        self._bdt = SegBDT()
        self._app = SegAPP()
        self._dcd = SegDCD()
        self._csf = SegCSF()
        self._plg = plugin

    def _update(self) -> None:
        # Set zero padding for IVT and BDT sections
        self.ivt.padding = 0
        self.bdt.padding = 0
        # Calculate padding for DCD, APP and CSF sections
        tmp_val = self.ivt.space + self.bdt.space
        if self.dcd:
            tmp_val += self.dcd.size
        head_size = 0xC00 if self.offset not in self.HEAD_SIZE else self.HEAD_SIZE[self.offset]
        if self.dcd:
            self.dcd.padding = head_size - tmp_val
        tmp_val = self.app.size % self.APP_ALIGN
        self.app.padding = self.APP_ALIGN - tmp_val if tmp_val > 0 else 0
        # Set IVT section
        self.ivt.ivt_address = self.address + self.offset
        self.ivt.bdt_address = self.ivt.ivt_address + self.ivt.space
        if self.dcd:
            if self.dcd.enabled:
                self.ivt.dcd_address = self.ivt.bdt_address + self.bdt.space
                self.ivt.app_address = self.ivt.dcd_address + self.dcd.space
            else:
                self.ivt.dcd_address = 0
                self.ivt.app_address = self.ivt.bdt_address + self.bdt.space
        if self.csf.enabled:
            self.ivt.csf_address = self.ivt.app_address + self.app.space
            self.csf.padding = self.CSF_SIZE - self.csf.size
        else:
            self.ivt.csf_address = 0
        # Set BDT section
        self.bdt.app_start = self.ivt.ivt_address - self.offset
        self.bdt.app_length = self.size + self.offset
        self.bdt.plugin = 1 if self.plugin else 0

    def __repr__(self) -> str:
        return f"Boot Image i.MX v8, Size: {self.size}B"

    def __str__(self) -> str:
        """String representation of the IMX Boot Image."""
        self._update()
        # Print IVT
        msg = "#" * 60 + "\n"
        msg += "# IVT (Image Vector Table)\n"
        msg += "#" * 60 + "\n\n"
        msg += str(self.ivt)
        # Print DBI
        msg += "#" * 60 + "\n"
        msg += "# BDI (Boot Data Info)\n"
        msg += "#" * 60 + "\n\n"
        msg += str(self.bdt)
        # Print DCD
        if self.dcd:
            msg += "#" * 60 + "\n"
            msg += "# DCD (Device Config Data)\n"
            msg += "#" * 60 + "\n\n"
            msg += str(self.dcd)
        # Print CSF
        if self.csf.enabled:
            msg += "#" * 60 + "\n"
            msg += "# CSF (Code Signing Data)\n"
            msg += "#" * 60 + "\n\n"
            msg += str(self.csf)
        return msg

    def add_image(
        self, data: bytes, img_type: EnumAppType = EnumAppType.APP, address: int = 0
    ) -> None:
        """Add specific image into the main boot image.

        :param data: Raw data of img
        :param img_type: Type of img
        :param address: address in RAM
        :raises Exception: raised when data type is unknown
        """
        if img_type == EnumAppType.APP:
            self.app.data = data
            if address != 0:
                self.address = address
        else:
            raise SPSDKError("Unknown data type !")

    def export(self) -> bytes:
        """Export Image as bytes array.

        :return: bytes
        """
        self._update()
        data = self.ivt.export()
        data += self.bdt.export()
        if self.dcd:
            data += self.dcd.export()
        data += self.app.export()
        data += self.csf.export()
        return data

    @classmethod
    def parse(
        cls,
        stream: Union[bytes, bytearray, BufferedReader, BytesIO],
        step: int = 0x100,
        size: Optional[int] = None,
    ) -> BootImgBase:
        """Parse image from stream buffer or bytes array.

        :param stream: The stream buffer or bytes array
        :param step: Image searching step
        :param size: parsing size
        :raises SPSDKError: Raised when the value type is incorrect
        :raises SPSDKError: Raised when there is not an i.MX Boot Image
        :return: BootImg2 object
        """
        if isinstance(stream, (bytes, bytearray)):
            stream = BytesIO(stream)

        if not isinstance(stream, (BufferedReader, BytesIO)):
            raise SPSDKError(f"Not correct value type: {type(stream)}!")

        header = Header()
        start_index = stream.tell()
        last_index = stream.seek(0, SEEK_END)
        stream.seek(start_index)

        if size:
            last_index = min(start_index + size, last_index)

        imx_image = False
        while start_index < (last_index - Header.SIZE):
            header = Header.parse(read_raw_data(stream, Header.SIZE, no_seek=True))
            if (
                header.tag == SegTag.IVT2
                or header.length == SegIVT2.SIZE
                or header.param in (0x40, 0x41, 0x42, 0x43)
            ):
                imx_image = True
                break

            start_index = stream.seek(step, SEEK_CUR)

        if not imx_image:
            raise SPSDKError("Not an i.MX Boot Image!")

        obj = cls(version=header.param)
        img_size = last_index - start_index
        if start_index > 0:
            obj.offset = start_index

        # Parse IVT
        obj.ivt = SegIVT2.parse(read_raw_segment(stream, SegTag.IVT2.tag))
        # Parse BDT
        obj.bdt = SegBDT.parse(read_raw_data(stream, SegBDT.SIZE))
        obj.offset = obj.ivt.ivt_address - obj.bdt.app_start
        obj.address = obj.bdt.app_start
        obj.plugin = bool(obj.bdt.plugin)
        # Parse DCD
        if obj.ivt.dcd_address:
            obj.dcd = SegDCD.parse(read_raw_segment(stream, SegTag.DCD.tag))
            obj.dcd.padding = (obj.ivt.app_address - obj.ivt.dcd_address) - obj.dcd.size
        # Parse APP
        app_start = start_index + (obj.ivt.app_address - obj.ivt.ivt_address)
        app_size = (
            obj.ivt.csf_address - obj.ivt.app_address
            if obj.ivt.csf_address
            else obj.bdt.app_length - (obj.bdt.app_start - obj.ivt.app_address)
        )
        app_size = img_size - app_start if app_size > (img_size - app_start) else app_size
        obj.app.data = read_raw_data(stream, app_size, app_start)
        obj.app.padding = 0
        # Parse CSF
        # Finalize the code below
        # if obj.ivt.csf_address:
        #    obj.csf = SegCSF.parse(buffer)
        #    obj.csf.padding = obj.bdt.length - ((obj.ivt.csf_address - obj.ivt.ivt_address) + obj.csf.size)

        return obj


########################################################################################################################
# Boot Image V3a: i.MX8QXP-A0
########################################################################################################################


class BootImg3a(BootImgBase):
    """i.MX Boot Image v3a."""

    IMG_TYPE_CSF = 0x01
    IMG_TYPE_SCD = 0x02
    IMG_TYPE_EXEC = 0x03
    IMG_TYPE_DATA = 0x04

    SCFW_FLAGS_APP = 0x01355FC4
    SCFW_FLAGS_M4_0 = 0x4A5162
    SCFW_FLAGS_M4_1 = 0x4F52A3
    SCFW_FLAGS_SCFW = 0x1

    INITIAL_LOAD_ADDR_SCU_ROM = 0x2000E000
    INITIAL_LOAD_ADDR_AP_ROM = 0x00110000
    INITIAL_LOAD_ADDR_FLEXSPI = 0x08000000

    # The value of CSF segment size
    CSF_SIZE = 0x2000
    # The align value of APP segment
    IMG_AUTO_ALIGN = 0x10
    SECTOR_SIZE = 0x200
    APP_ALIGN = 0x1200
    # The value of img head size
    #           offset | size
    HEAD_SIZE = {0x400: 0xC400, 0x1000: 0x1400}

    PADDING_VAL = 0x00

    COUNT_OF_CONTAINERS = 2

    @property
    def plg(self) -> bool:
        """PLG."""
        return self._plg

    @plg.setter
    def plg(self, value: bool) -> None:
        assert isinstance(value, bool)
        self._plg = value

    @property
    def ivt(self) -> list[SegIVT3a]:
        """IVT."""
        return self._ivt

    @ivt.setter
    def ivt(self, value: list) -> None:
        assert isinstance(value, list) and isinstance(value[0], SegIVT3a)
        self._ivt = value

    @property
    def bdt(self) -> list[SegBDS3a]:
        """BDT."""
        return self._bdt

    @bdt.setter
    def bdt(self, value: list) -> None:
        assert isinstance(value, list) and isinstance(value[0], SegBDS3a)
        self._bdt = value

    @property
    def csf(self) -> SegCSF:
        """CSF."""
        return self._csf

    @csf.setter
    def csf(self, value: SegCSF) -> None:
        assert isinstance(value, SegCSF)
        self._csf = value

    def __init__(self, address: int = 0, offset: int = 0x400, version: int = 0x43) -> None:
        """Initialize boot image object.

        :param address: The start address of img in target memory
        :param offset: The IVT offset
        :param version: The version of boot img format
        """
        super().__init__(address, offset)
        self._ivt = [SegIVT3a(version), SegIVT3a(version)]
        self._ivt[0].next = self._ivt[0].size
        self._ivt[0].version = 0x01
        self._ivt[1].version = 0x01
        self._bdt = [SegBDS3a(), SegBDS3a()]
        self.app = [
            [SegAPP() for _ in range(SegBDS3a.IMAGES_MAX_COUNT)],
            [SegAPP() for _ in range(SegBDS3a.IMAGES_MAX_COUNT)],
        ]
        self._dcd = SegDCD()
        self._csf = SegCSF()
        self._plg = False
        if not isinstance(self.address, list):
            self.address = [self.INITIAL_LOAD_ADDR_SCU_ROM, self.INITIAL_LOAD_ADDR_AP_ROM]  # type: ignore
        self._sdc_address = 0

    @staticmethod
    def _compute_padding(size: int, sector_size: int) -> int:
        return (size // sector_size + (size % sector_size > 0)) * sector_size - size

    def _update(self) -> None:
        # Set zero padding for IVT and BDT sections
        for container in range(self.COUNT_OF_CONTAINERS):
            self.ivt[container].padding = 0
            self.bdt[container].padding = 0

            # Set IVT section
            self.ivt[container].ivt_address = (
                self.address[container]  # type: ignore
                + self.offset
                + container * self.ivt[container].size
            )
            self.ivt[container].bdt_address = (
                self.ivt[container].ivt_address
                + self.ivt[container].space * (self.COUNT_OF_CONTAINERS - container)
                + container * self.bdt[container].size
            )

            if container == 0:
                if self.dcd:
                    self.ivt[container].dcd_address = (
                        self.ivt[container].bdt_address + self.bdt[container].space * 2
                    )
                    if self.csf.enabled:
                        self.ivt[container].csf_address = (
                            self.ivt[container].dcd_address + self.dcd.space
                        )
                    else:
                        self.ivt[container].csf_address = 0
                else:
                    self.ivt[container].dcd_address = 0
                    if self.csf.enabled:
                        self.ivt[container].csf_address = (
                            self.ivt[container].bdt_address + self.bdt[container].space * 2
                        )
                    else:
                        self.ivt[container].csf_address = 0
            else:
                self.ivt[container].dcd_address = 0
                self.ivt[container].csf_address = 0

            self.app[container][0].padding = self._compute_padding(
                self.bdt[container].images[0].image_size, self.SECTOR_SIZE
            )
            if self.bdt[container].images_count != 0:
                self.bdt[container].boot_data_size = self.bdt[container].size
                if container == 0:
                    self.bdt[container].images[0].image_source = self.APP_ALIGN
                else:
                    last_image_index = self.bdt[container - 1].images_count - 1
                    last_image_address = (
                        self.bdt[container - 1].images[last_image_index].image_source
                    )
                    self.bdt[container].images[0].image_source = (
                        last_image_address + self.app[container - 1][last_image_index].space
                    )
            for i in range(self.bdt[container].images_count - 1):
                self.bdt[container].images[i + 1].image_source = (
                    self.bdt[container].images[i].image_source + self.app[container][i].space
                )
                self.app[container][i + 1].padding = self._compute_padding(
                    self.bdt[container].images[i + 1].image_size, self.SECTOR_SIZE
                )
            if container == self.COUNT_OF_CONTAINERS - 1:
                self.app[container][self.bdt[container].images_count - 1].padding = 0
                # Set BDT section

    def __repr__(self) -> str:
        return "Boot Image i.MX v3a"

    def __str__(self) -> str:
        """String representation of the i.MX Boot Image v3a."""
        self._update()
        # Print IVT
        msg = "#" * 60 + "\n"
        msg += "# IVT (Image Vector Table)\n"
        msg += "#" * 60 + "\n\n"
        for index, ivt in enumerate(self.ivt):
            msg += "-" * 60 + "\n"
            msg += f"- IVT[{index}]\n"
            msg += "-" * 60 + "\n\n"
            msg += str(ivt)
        # Print BDI
        msg += "#" * 60 + "\n"
        msg += "# BDI (Boot Data Info)\n"
        msg += "#" * 60 + "\n\n"
        for index, bdi in enumerate(self.bdt):
            msg += "-" * 60 + "\n"
            msg += f"- BDI[{index}]\n"
            msg += "-" * 60 + "\n\n"
            msg += str(bdi)
        # Print DCD
        if self.dcd:
            msg += "#" * 60 + "\n"
            msg += "# DCD (Device Config Data)\n"
            msg += "#" * 60 + "\n\n"
            msg += str(self.dcd)
        # Print CSF
        if self.csf.enabled:
            msg += "#" * 60 + "\n"
            msg += "# CSF (Code Signing Data)\n"
            msg += "#" * 60 + "\n\n"
            msg += str(self.csf)
        return msg

    def add_image(
        self, data: bytes, img_type: EnumAppType = EnumAppType.APP, address: int = 0
    ) -> None:
        """Add specific image into the main boot image.

        :param data: Raw data of image
        :param img_type: Type of image
        :param address: address in RAM
        :raises Exception: raised when data type is unknown
        """
        if img_type == EnumAppType.APP:
            image_index = self.bdt[1].images_count
            self.bdt[1].images[image_index].image_destination = address
            self.bdt[1].images[image_index].image_entry = address
            self.bdt[1].images[image_index].image_size = len(data)
            self.bdt[1].images[image_index].rom_flags = 0
            self.bdt[1].images[image_index].hab_flags = self.IMG_TYPE_EXEC
            self.bdt[1].images[image_index].scfw_flags = self.SCFW_FLAGS_APP
            self.bdt[1].images_count += 1

            self.app[1][image_index].data = data
            self.app[1][image_index].padding = self._compute_padding(len(data), self.SECTOR_SIZE)

        elif img_type in (EnumAppType.M4_0, EnumAppType.M4_1):
            image_index = self.bdt[0].images_count
            self.bdt[0].images[image_index].image_destination = address
            self.bdt[0].images[image_index].image_entry = address
            self.bdt[0].images[image_index].image_size = len(data)
            self.bdt[0].images[image_index].rom_flags = 0
            self.bdt[0].images[image_index].hab_flags = self.IMG_TYPE_EXEC
            self.bdt[0].images[image_index].scfw_flags = (
                self.SCFW_FLAGS_M4_0 if img_type == EnumAppType.M4_0 else self.SCFW_FLAGS_M4_1
            )
            self.bdt[0].images_count += 1

            self.app[0][image_index].data = data
            self.app[0][image_index].padding = self._compute_padding(len(data), self.SECTOR_SIZE)

        elif img_type == EnumAppType.SCFW:
            image_index = self.bdt[0].images_count
            self.bdt[0].images[image_index].image_destination = 0x1FFE0000
            self.bdt[0].images[image_index].image_entry = 0x1FFE0000
            self.bdt[0].images[image_index].image_size = len(data)
            self.bdt[0].images[image_index].rom_flags = 0
            self.bdt[0].images[image_index].hab_flags = self.IMG_TYPE_EXEC
            self.bdt[0].images[image_index].scfw_flags = self.SCFW_FLAGS_SCFW
            self.bdt[0].images_count += 1

            self.app[0][image_index].data = data
            self.app[0][image_index].padding = self._compute_padding(len(data), self.SECTOR_SIZE)
            self._sdc_address = (
                self.bdt[0].images[image_index].image_destination
                + len(data)
                + self._compute_padding(len(data), self.IMG_AUTO_ALIGN)
            )

        elif img_type == EnumAppType.SCD:
            if self._sdc_address == 0:
                raise SPSDKError("SCFW have to be define before SCD!")
            image_index = self.bdt[0].images_count
            self.bdt[0].images[image_index].image_destination = self._sdc_address
            self.bdt[0].images[image_index].image_entry = 0
            self.bdt[0].images[image_index].image_size = len(data)
            self.bdt[0].images[image_index].rom_flags = 0
            self.bdt[0].images[image_index].hab_flags = self.IMG_TYPE_SCD
            self.bdt[0].images[image_index].scfw_flags = 0x1
            self.bdt[0].images_count += 1

            self.app[0][image_index].data = data
            self.app[0][image_index].padding = self._compute_padding(len(data), self.SECTOR_SIZE)

        else:
            raise SPSDKError("Unknown data type!")

    def export(self) -> bytes:
        """Export Image as binary blob."""
        self._update()
        data = bytes()
        data += self.ivt[0].export()
        data += self.ivt[1].export()
        data += self.bdt[0].export()
        data += self.bdt[1].export()
        if self.dcd:
            data += self.dcd.export()
        data += self.csf.export()
        data += bytes(
            [self.PADDING_VAL] * self._compute_padding(len(data), self.APP_ALIGN - self.offset)
        )

        for container in range(self.COUNT_OF_CONTAINERS):
            for image in range(self.bdt[container].images_count):
                data += self.app[container][image].export()

        return data

    @classmethod
    def parse(
        cls,
        stream: Union[bytes, bytearray, BufferedReader, BytesIO],
        step: int = 0x100,
        size: Optional[int] = None,
    ) -> BootImgBase:
        """Parse image from stream buffer or bytes array.

        :param stream: The stream buffer or bytes array
        :param step: Image searching step
        :param size: parsing size
        :raises SPSDKError: Raised when the values type is incorrect
        :raises SPSDKError: Raised when there is not an i.MX Boot Image
        :return: BootImg3a object
        """
        if isinstance(stream, (bytes, bytearray)):
            stream = BytesIO(stream)

        if not isinstance(stream, (BufferedReader, BytesIO)):
            raise SPSDKError(f"Not correct value type: {type(stream)}!")

        header = Header()
        start_index = stream.tell()
        last_index = stream.seek(0, SEEK_END)
        stream.seek(start_index)

        if size:
            last_index = min(start_index + size, last_index)

        imx_image = False
        while start_index < (last_index - Header.SIZE):
            header = Header.parse(read_raw_data(stream, Header.SIZE, no_seek=True))
            if (
                header.tag == SegTag.IVT3
                or header.length == SegIVT3a.SIZE
                or header.param in (0x43,)
            ):
                imx_image = True
                break

            start_index = stream.seek(step, SEEK_CUR)

        if not imx_image:
            raise SPSDKError("Not an i.MX Boot Image!")

        obj = cls(version=header.param)
        if start_index > 0:
            obj.offset = start_index
        # Parse IVT
        obj.ivt[0] = SegIVT3a.parse(read_raw_segment(stream, SegTag.IVT3.tag))
        obj.ivt[1] = SegIVT3a.parse(read_raw_segment(stream, SegTag.IVT3.tag))
        # Parse BDT
        obj.bdt[0] = SegBDS3a.parse(read_raw_data(stream, SegBDS3a.SIZE))
        obj.bdt[1] = SegBDS3a.parse(read_raw_data(stream, SegBDS3a.SIZE))
        # Parse DCD
        if obj.ivt[0].dcd_address:
            stream.seek(start_index + (obj.ivt[0].dcd_address - obj.ivt[0].ivt_address), 0)
            obj.dcd = SegDCD.parse(read_raw_segment(stream, SegTag.DCD.tag))
        # Parse CSF
        if obj.ivt[0].csf_address:
            stream.seek(start_index + (obj.ivt[0].csf_address - obj.ivt[0].ivt_address), 0)
            obj.csf = SegCSF.parse(read_raw_segment(stream, SegTag.CSF.tag))
        # Parse IMAGES
        for container in range(obj.COUNT_OF_CONTAINERS):
            for i in range(obj.bdt[container].images_count):
                stream.seek(obj.bdt[container].images[i].image_source - obj.offset, 0)
                obj.app[container][i].data = read_raw_data(
                    stream, obj.bdt[container].images[i].image_size
                )

        return obj


########################################################################################################################
# Boot Image V3b: i.MX8QM-A0
########################################################################################################################


class BootImg3b(BootImgBase):
    """IMX Boot Image v3b."""

    IMG_TYPE_CSF = 0x01
    IMG_TYPE_SCD = 0x02
    IMG_TYPE_EXEC = 0x03
    IMG_TYPE_DATA = 0x04

    SCFW_FLAGS_A53 = 0x1354014
    SCFW_FLAGS_A72 = 0x1354065
    SCFW_FLAGS_M4_0 = 0x4A5162
    SCFW_FLAGS_M4_1 = 0x4F52A3
    SCFW_FLAGS_SCFW = 0x1

    INITIAL_LOAD_ADDR_SCU_ROM = 0x2000E000
    INITIAL_LOAD_ADDR_AP_ROM = 0x00110000
    INITIAL_LOAD_ADDR_FLEXSPI = 0x08000000

    # The value of CSF segment size
    CSF_SIZE = 0x2000
    # The align value for img
    IMG_AUTO_ALIGN = 0x10
    # The align value for sector
    SECTOR_SIZE = 0x200
    # The align value of APP segment
    APP_ALIGN = 0x1200

    PADDING_VAL = 0x00
    # The value of img head size
    #           offset | size
    HEAD_SIZE = {0x400: 0xC400, 0x1000: 0x1400}

    COUNT_OF_CONTAINERS = 2

    @property
    def plg(self) -> bool:
        """PLG."""
        return self._plg

    @plg.setter
    def plg(self, value: bool) -> None:
        assert isinstance(value, bool)
        self._plg = value

    @property
    def ivt(self) -> list[SegIVT3b]:
        """IVT."""
        return self._ivt

    @ivt.setter
    def ivt(self, value: list) -> None:
        assert isinstance(value, list)
        if len(value) != self.COUNT_OF_CONTAINERS:
            raise SPSDKError("Invalid value of IVT")
        assert isinstance(value[0], SegIVT3b)
        self._ivt = value

    @property
    def bdt(self) -> list[SegBDS3b]:
        """BDT."""
        return self._bdt

    @bdt.setter
    def bdt(self, value: list) -> None:
        assert isinstance(value, list)
        if len(value) != self.COUNT_OF_CONTAINERS:
            raise SPSDKError("Invalid value of BDT")
        assert isinstance(value[0], SegBDS3b)
        self._bdt = value

    @property
    def csf(self) -> SegCSF:
        """CSF."""
        return self._csf

    @csf.setter
    def csf(self, value: SegCSF) -> None:
        assert isinstance(value, SegCSF)
        self._csf = value

    def __init__(self, address: int = 0, offset: int = 0x400, version: int = 0x43) -> None:
        """Initialize boot image object.

        :param address: The start address of img in target memory
        :param offset: The IVT offset
        :param version: The version of boot img format
        """
        super().__init__(address, offset)
        self._ivt = [SegIVT3b(version), SegIVT3b(version)]
        self._bdt = [SegBDS3b(), SegBDS3b()]
        self.app = [
            [SegAPP() for _ in range(SegBDS3b.IMAGES_MAX_COUNT)],
            [SegAPP() for _ in range(SegBDS3b.IMAGES_MAX_COUNT)],
        ]
        self._dcd = SegDCD()
        self.scd = SegAPP()
        self._csf = SegCSF()
        self._plg = False
        self._scd_address = 0
        if not isinstance(self.address, int):
            self.address = [self.INITIAL_LOAD_ADDR_SCU_ROM, self.INITIAL_LOAD_ADDR_AP_ROM]

    @staticmethod
    def _compute_padding(image_size: int, sector_size: int) -> int:
        return (
            (image_size // sector_size + (image_size % sector_size > 0)) * sector_size
        ) - image_size

    def _update(self) -> None:
        # Set zero padding for IVT and BDT sections
        for container in range(self.COUNT_OF_CONTAINERS):
            self.ivt[container].padding = 0
            self.bdt[container].padding = 0

            # Set IVT section
            self.ivt[container].ivt_address = (
                self.address[container]  # type: ignore
                + self.offset
                + container * self.ivt[container].size
            )
            self.ivt[container].bdt_address = (
                self.ivt[container].ivt_address
                + self.ivt[container].space * (2 - container)
                + container * self.bdt[container].size
            )
            if container == 0:
                if self.dcd:
                    self.ivt[container].dcd_address = (
                        self.ivt[container].bdt_address + self.bdt[container].space * 2
                    )
                    if self.csf.enabled:
                        self.ivt[container].csf_address = (
                            self.ivt[container].dcd_address + self.dcd.space
                        )
                    else:
                        self.ivt[container].csf_address = 0
                else:
                    self.ivt[container].dcd_address = 0
                    if self.csf.enabled:
                        self.ivt[container].csf_address = (
                            self.ivt[container].bdt_address + self.bdt[container].space * 2
                        )
                    else:
                        self.ivt[container].csf_address = 0
            else:
                self.ivt[container].dcd_address = 0
                self.ivt[container].csf_address = 0

            self.app[container][0].padding = self._compute_padding(
                self.bdt[container].images[0].image_size, self.SECTOR_SIZE
            )
            if self.bdt[container].images_count != 0:
                self.bdt[container].boot_data_size = self.bdt[container].size
                if container == 0:
                    self.bdt[container].images[0].image_source = self.APP_ALIGN
                else:
                    last_image_index = self.bdt[container - 1].images_count - 1
                    last_image_address = (
                        self.bdt[container - 1].images[last_image_index].image_source
                    )
                    self.bdt[container].images[0].image_source = (
                        last_image_address + self.app[container - 1][last_image_index].space
                    )
            next_image_address = 0
            for i in range(self.bdt[container].images_count - 1):
                self.bdt[container].images[i + 1].image_source = (
                    self.bdt[container].images[i].image_source + self.app[container][i].space
                )
                self.app[container][i + 1].padding = self._compute_padding(
                    self.bdt[container].images[i + 1].image_size, self.SECTOR_SIZE
                )
                next_image_address = (
                    self.bdt[container].images[i + 1].image_source
                    + self.app[container][i + 1].space
                )

            if container == 0:
                if self.bdt[container].scd.image_destination != 0:
                    self.bdt[container].scd.image_source = next_image_address
                    self.scd.padding = self._compute_padding(
                        self.bdt[0].scd.image_size, self.SECTOR_SIZE
                    )
                    next_image_address += self.scd.space
                    # Set BDT section

                if self.csf.enabled:
                    self.bdt[container].csf.image_source = next_image_address
                    self.csf.padding = self._compute_padding(
                        self.bdt[0].csf.image_size, self.SECTOR_SIZE
                    )
                    next_image_address += self.csf.space
                    # Set BDT section

    def __repr__(self) -> str:
        return "Boot Image i.MX v3b"

    def __str__(self) -> str:
        """String representation of the IMX Boot Image v3b."""
        self._update()
        # Print IVT
        msg = "#" * 60 + "\n"
        msg += "# IVT (Image Vector Table)\n"
        msg += "#" * 60 + "\n\n"
        for index, ivt in enumerate(self.ivt):
            msg += "-" * 60 + "\n"
            msg += f"- IVT[{index}]\n"
            msg += "-" * 60 + "\n\n"
            msg += str(ivt)
        # Print BDI
        msg += "#" * 60 + "\n"
        msg += "# BDI (Boot Data Info)\n"
        msg += "#" * 60 + "\n\n"
        for index, bdi in enumerate(self.bdt):
            msg += "-" * 60 + "\n"
            msg += f"- BDI[{index}]\n"
            msg += "-" * 60 + "\n\n"
            msg += str(bdi)
        # Print DCD
        if self.dcd:
            msg += "#" * 60 + "\n"
            msg += "# DCD (Device Config Data)\n"
            msg += "#" * 60 + "\n\n"
            msg += str(self.dcd)
        # Print CSF
        if self.csf.enabled:
            msg += "#" * 60 + "\n"
            msg += "# CSF (Code Signing Data)\n"
            msg += "#" * 60 + "\n\n"
            msg += str(self.csf)
        return msg

    def add_image(
        self, data: bytes, img_type: EnumAppType = EnumAppType.APP, address: int = 0
    ) -> None:
        """Add specific image into the main boot image.

        :param data: Raw data of image
        :param img_type: Type of image
        :param address: address in RAM
        :raises Exception: raised SCFW is not defined before SCD
        :raises Exception: raised when there is unknown image type
        """
        if img_type in (EnumAppType.APP, EnumAppType.A72):
            image_index = self.bdt[1].images_count
            self.app[1][image_index].data = data

            self.bdt[1].images[image_index].image_destination = address
            self.bdt[1].images[image_index].image_entry = address
            self.bdt[1].images[image_index].image_size = len(data)

            if img_type == EnumAppType.APP:
                self.bdt[1].images[image_index].flags = self.SCFW_FLAGS_A53
            elif img_type == EnumAppType.A72:
                self.bdt[1].images[image_index].flags = self.SCFW_FLAGS_A72

            self.app[1][image_index].padding = self._compute_padding(len(data), self.SECTOR_SIZE)
            self.bdt[1].images_count += 1

        elif img_type in (EnumAppType.M4_0, EnumAppType.M4_1):
            image_index = self.bdt[0].images_count
            self.app[0][image_index].data = data

            self.bdt[0].images[image_index].image_destination = address
            self.bdt[0].images[image_index].image_entry = address
            self.bdt[0].images[image_index].image_size = len(data)

            if img_type == EnumAppType.M4_0:
                self.bdt[0].images[image_index].flags = self.SCFW_FLAGS_M4_0
            elif img_type == EnumAppType.M4_1:
                self.bdt[0].images[image_index].flags = self.SCFW_FLAGS_M4_1

            self.app[0][image_index].padding = (
                (len(data) // self.SECTOR_SIZE + (len(data) % self.SECTOR_SIZE > 0))
                * self.SECTOR_SIZE
            ) - len(data)
            self.bdt[0].images_count += 1

        elif img_type == EnumAppType.SCFW:
            image_index = self.bdt[0].images_count
            self.bdt[0].images[image_index].image_destination = 0x30FE0000
            self.bdt[0].images[image_index].image_entry = 0x1FFE0000
            self.bdt[0].images[image_index].image_size = len(data)
            self.bdt[0].images[image_index].flags = self.SCFW_FLAGS_SCFW
            self._scd_address = (
                self.bdt[0].images[image_index].image_destination
                + len(data)
                + self._compute_padding(len(data), self.IMG_AUTO_ALIGN)
            )
            self.bdt[0].images_count += 1

            self.app[0][image_index].data = data
            self.app[0][image_index].padding = self._compute_padding(len(data), self.SECTOR_SIZE)

        elif img_type == EnumAppType.SCD:
            if self._scd_address == 0:
                raise SPSDKError("SCFW have to be define before SCD!")
            self.scd.data = data
            self.scd.padding = self._compute_padding(len(data), self.SECTOR_SIZE)
            self.bdt[0].scd.image_destination = self._scd_address
            self.bdt[0].scd.image_entry = 0
            self.bdt[0].scd.image_size = len(data)
            self.ivt[0].scd_address = self.bdt[0].scd.image_destination

        else:
            raise SPSDKError("Unknown image type!")

    def export(self) -> bytes:
        """Export."""
        self._update()
        # data = bytearray(self._offset)
        data = bytes()
        data += self.ivt[0].export()
        data += self.ivt[1].export()
        data += self.bdt[0].export()
        data += self.bdt[1].export()
        if self.dcd:
            data += self.dcd.export()
        data += bytes(
            [self.PADDING_VAL] * self._compute_padding(len(data), self.APP_ALIGN - self.offset)
        )

        for container in range(self.COUNT_OF_CONTAINERS):
            for i in range(self.bdt[container].images_count):
                data += self.app[container][i].export()

        if self.bdt[0].scd.image_source != 0:
            data += self.scd.export()

        if self.bdt[0].csf.image_source != 0:
            data += self.csf.export()

        return data

    @classmethod
    def parse(
        cls,
        stream: Union[bytes, bytearray, BufferedReader, BytesIO],
        step: int = 0x100,
        size: Optional[int] = None,
    ) -> BootImgBase:
        """Parse image from stream buffer or bytes array.

        :param stream: The stream buffer or bytes array
        :param step: Image searching step
        :param size: parsing size
        :raises SPSDKError: When the value is incorrect
        :raises SPSDKError: If there is not an i.MX Boot Image
        :return: BootImg3b object
        """
        if isinstance(stream, (bytes, bytearray)):
            stream = BytesIO(stream)

        if not isinstance(stream, (BufferedReader, BytesIO)):
            raise SPSDKError(f"Not correct value type: {type(stream)}!")

        header = Header()
        start_index = stream.tell()
        last_index = stream.seek(0, SEEK_END)
        stream.seek(start_index)

        if size:
            last_index = min(start_index + size, last_index)

        imx_image = False
        while start_index < (last_index - Header.SIZE):
            header = Header.parse(read_raw_data(stream, Header.SIZE, no_seek=True))
            if (
                header.tag == SegTag.IVT2
                or header.length == SegIVT3b.SIZE
                or header.param in (0x43,)
            ):
                imx_image = True
                break

            start_index = stream.seek(step, SEEK_CUR)

        if not imx_image:
            raise SPSDKError("Not an i.MX Boot Image!")

        obj = cls(version=header.param)
        if start_index > 0:
            obj.offset = start_index
        # Parse IVT
        obj.ivt[0] = SegIVT3b.parse(read_raw_segment(stream, SegTag.IVT2.tag))
        obj.ivt[1] = SegIVT3b.parse(read_raw_segment(stream, SegTag.IVT2.tag))
        # Parse BDT
        obj.bdt[0] = SegBDS3b.parse(read_raw_data(stream, SegBDS3b.SIZE))
        obj.bdt[1] = SegBDS3b.parse(read_raw_data(stream, SegBDS3b.SIZE))
        # Parse DCD
        if obj.ivt[0].dcd_address:
            stream.seek(start_index + (obj.ivt[0].dcd_address - obj.ivt[0].ivt_address), 0)
            obj.dcd = SegDCD.parse(read_raw_segment(stream, SegTag.DCD.tag))
        # Parse IMAGES
        for container in range(obj.COUNT_OF_CONTAINERS):
            for i in range(obj.bdt[container].images_count):
                stream.seek(obj.bdt[container].images[i].image_source - obj.offset, 0)
                obj.app[container][i].data = read_raw_data(
                    stream, obj.bdt[container].images[i].image_size
                )
        # Parse SCD
        if obj.bdt[0].scd.image_source != 0:
            stream.seek(obj.bdt[0].scd.image_source - obj.offset, 0)
            obj.scd.data = read_raw_data(stream, obj.bdt[0].scd.image_size)
        # Parse CSF
        if obj.bdt[0].csf.image_source != 0:
            stream.seek(obj.bdt[0].csf.image_source - obj.offset, 0)
            obj.csf = SegCSF.parse(read_raw_segment(stream, SegTag.CSF.tag))

        return obj


########################################################################################################################
# Boot Image V4: i.MX8DM, i.MX8QM_B0, i.MX8QXP_B0
########################################################################################################################


class BootImg4(BootImgBase):
    """i.MX Boot Image v4."""

    def __init__(self, address: int = 0, offset: int = 0x400) -> None:
        """Initialize boot image object.

        :param address: The start address of image in target memory
        :param offset: The image offset
        """
        super().__init__(address, offset)
        self._dcd = SegDCD()
        self._cont1_header = SegBIC1()
        self._cont2_header = SegBIC1()

    def _update(self) -> None:
        pass

    def __repr__(self) -> str:
        return "Boot Image i.MX v4"

    def __str__(self) -> str:
        """String representation of the i.MX Boot Image v4."""
        self._update()
        msg = ""
        msg += "#" * 60 + "\n"
        msg += "# Boot Images Container 1\n"
        msg += "#" * 60 + "\n\n"
        msg += str(self._cont1_header)
        msg += "#" * 60 + "\n"
        msg += "# Boot Images Container 2\n"
        msg += "#" * 60 + "\n\n"
        msg += str(self._cont2_header)
        if self.dcd:
            if self.dcd.enabled:
                msg += "#" * 60 + "\n"
                msg += "# DCD (Device Config Data)\n"
                msg += "#" * 60 + "\n\n"
                msg += str(self.dcd)
        return msg

    def add_image(self, data: bytes, img_type: EnumAppType, address: int) -> None:
        """Add image.

        :raises NotImplementedError: Not yet implemented
        """
        raise NotImplementedError("Not yet implemented.")

    def export(self) -> bytes:
        """Export."""
        self._update()
        data = bytes()
        data += self._cont1_header.export()
        data += self._cont2_header.export()
        # Complete Implementation
        return data

    @classmethod
    def parse(
        cls,
        stream: Union[bytes, bytearray, BufferedReader, BytesIO],
        step: int = 0x100,
        size: Optional[int] = None,
    ) -> BootImgBase:
        """Parse image from stream buffer or bytes array.

        :param stream: The stream buffer or bytes array
        :param step: Image searching step
        :param size: parsing size
        :return: BootImg4 object
        :raises SPSDKError: Raised when the value type is incorrect
        :raises SPSDKError: If there is not an i.MX Boot Image
        """
        if isinstance(stream, (bytes, bytearray)):
            stream = BytesIO(stream)

        if not isinstance(stream, (BufferedReader, BytesIO)):
            raise SPSDKError(f" Not correct value type: '{type(stream)}' !")

        start_index = stream.tell()
        last_index = stream.seek(0, SEEK_END)
        stream.seek(start_index)

        if size:
            last_index = min(start_index + size, last_index)

        imx_image = False
        while start_index < (last_index - Header.SIZE):
            header = Header.parse(read_raw_data(stream, Header2.SIZE, no_seek=True))
            if header.tag == SegTag.BIC1:
                imx_image = True
                break

            start_index = stream.seek(step, SEEK_CUR)

        if not imx_image:
            raise SPSDKError(" Not an i.MX Boot Image !")

        obj = cls()
        if start_index > 0:
            obj.offset = start_index

        # Parse Containers
        obj._cont1_header = SegBIC1.parse(read_raw_data(stream, 0x400))
        obj._cont2_header = SegBIC1.parse(read_raw_data(stream, 0x400))
        # Complete Implementation
        return obj


########################################################################################################################
# i.MX Kernel Image Classes
########################################################################################################################


class KernelImg:
    """IMX Kernel Image."""

    IMAGE_MIN_SIZE = 0x1000

    @property
    def address(self) -> int:
        """Address."""
        return self._ivt.app_address

    @address.setter
    def address(self, value: int) -> None:
        self._ivt.app_address = value

    @property
    def version(self) -> int:
        """Version."""
        return self._ivt.version

    @version.setter
    def version(self, value: int) -> None:
        self._ivt.version = value

    @property
    def app(self) -> Optional[bytes]:
        """APP."""
        return self._app.data

    @app.setter
    def app(self, value: Union[bytes, bytearray]) -> None:
        assert isinstance(value, (bytes, bytearray))
        self._app.data = value

    @property
    def csf(self) -> SegCSF:
        """CSF."""
        return self._csf

    @csf.setter
    def csf(self, value: SegCSF) -> None:
        assert isinstance(value, SegCSF)
        self._csf = value

    def __init__(
        self,
        address: int = 0,
        app: Optional[bytes] = None,
        csf: Optional[Union[SegCSF, Any]] = None,
        version: int = 0x41,
    ) -> None:
        """Initialize the IMX Kernel Image."""
        self._ivt = SegIVT2(version)
        self._ivt.app_address = address
        self._app = SegAPP(app)
        self._csf = SegCSF() if csf is None else csf

    def __str__(self) -> str:
        return ""

    def __repr__(self) -> str:
        return ""

    def _update(self) -> None:
        pass

    def export(self) -> bytes:
        """Export."""
        self._update()
        data = self._app.export()
        data += self._ivt.export()
        data += self._csf.export()
        return data

    @classmethod
    def _check_data_to_parse(cls, data: Union[str, bytes]) -> None:
        """Check data to parse."""
        assert isinstance(data, (bytes, str))
        if not len(data) > cls.IMAGE_MIN_SIZE:
            raise SPSDKError("Invalid length of data to be parsed")


########################################################################################################################
# i.MX Image Public Methods
########################################################################################################################


def parse(
    stream: Union[bytes, bytearray, BufferedReader, BytesIO],
    step: int = 0x100,
    size: Optional[int] = None,
) -> BootImgBase:
    """Common parser for all versions of i.MX boot images.

    :param stream: stream buffer to image
    :param step: Image searching step
    :param size: parsing size
    :return: the object of boot image
    :raises SPSDKError: Raised when the format of string is incorrect
    :raises SPSDKError: When not i.MX Boot Image is passed
    """
    if isinstance(stream, (bytes, bytearray)):
        stream = BytesIO(stream)

    if not isinstance(stream, (BufferedReader, BytesIO)):
        raise SPSDKError(f"Not correct value type: '{type(stream)}' !")

    # calculate stream size
    start_index = stream.tell()
    last_index = stream.seek(0, SEEK_END)
    stream.seek(start_index)

    if size:
        last_index = min(start_index + size, last_index)

    while start_index < (last_index - Header.SIZE):
        raw = read_raw_data(stream, Header.SIZE, no_seek=True)

        if (
            raw[0] == SegTag.IVT2.tag
            and ((raw[1] << 8) | raw[2]) == SegIVT2.SIZE
            and raw[3] in (0x40, 0x41, 0x42)
        ):
            return BootImg2.parse(stream)

        if (
            raw[0] == SegTag.IVT2.tag
            and ((raw[1] << 8) | raw[2]) == SegIVT3b.SIZE
            and raw[3] in (0x43,)
        ):
            return BootImg3b.parse(stream)

        if (
            raw[0] == SegTag.IVT3.tag
            and ((raw[1] << 8) | raw[2]) == SegIVT3a.SIZE
            and raw[3] in (0x43,)
        ):
            return BootImg3a.parse(stream)

        if raw[3] == SegTag.BIC1.tag:
            return BootImg4.parse(stream)

        start_index = stream.seek(step, SEEK_CUR)

    raise SPSDKError(" Not an i.MX Boot Image !")
