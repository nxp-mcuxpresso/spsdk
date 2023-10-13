#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This module contains Bootable image related code."""


import logging
import os
from inspect import isclass
from typing import Any, Dict, List, Optional, Type, Union

from typing_extensions import Self

from spsdk.exceptions import SPSDKError, SPSDKParsingError, SPSDKValueError
from spsdk.image.ahab.ahab_container import AHABImage
from spsdk.image.fcb.fcb import FCB
from spsdk.image.hab.hab_container import HabContainer
from spsdk.image.mbi.mbi import MasterBootImage, get_mbi_class
from spsdk.image.xmcd.xmcd import XMCD
from spsdk.utils.abstract import BaseClass
from spsdk.utils.misc import BinaryPattern, load_binary, load_configuration, write_file
from spsdk.utils.schema_validator import CommentedConfig, check_config

logger = logging.getLogger(__name__)


class Segment(BaseClass):
    """Base Bootable Image Segment class."""

    NAME = "Base"
    CFG_NAME: Optional[str] = None
    SIZE = -1

    def __init__(self, raw_block: Optional[bytes] = None) -> None:
        """Segment initialization, at least raw data are stored.

        :param raw_block: Raw data of segment.
        """
        self.raw_block = raw_block or bytes()

    def __repr__(self) -> str:
        """Object representation in string format."""
        return f"Bootable image segment: {self.NAME}"

    def __str__(self) -> str:
        """Object description in string format."""
        return self.__repr__()

    def export(self) -> bytes:
        """Serialize object into bytes array.

        :return: Raw binary block of segment
        """
        return self.raw_block

    @classmethod
    def cfg_key(cls) -> str:
        """Configuration key name."""
        return cls.CFG_NAME or cls.NAME

    @classmethod
    def parse(
        cls,
        binary: bytes,
        family: str = "Unknown",
        mem_type: str = "Unknown",
        revision: str = "latest",
        pattern: str = "zeros",
    ) -> Self:
        """Parse binary block into Segment object.

        :param binary: binary image.
        :param family: Chip family.
        :param mem_type: Used memory type.
        :param revision: Optional Chip family revision.
        :param pattern: Default Binary pattern of empty segment.
        :raises SPSDKError: If given binary block size is not equal to block size in header
        """
        if cls.SIZE > 0 and len(binary) < cls.SIZE:
            raise SPSDKParsingError("The input binary block is smaller than parsed segment.")
        if cls.SIZE > 0 and binary[: cls.SIZE] == BinaryPattern(pattern).get_block(cls.SIZE):
            return cls()
        return cls(raw_block=binary[: cls.SIZE] if cls.SIZE > 0 else binary)

    def create_config(self, path: str) -> Union[str, int]:
        """Create configuration including store the data to specified path.

        :param path: Path where the information should be stored
        :returns: Value of segment to configuration file
        """
        ret = ""
        if self.raw_block:
            ret = f"segment_{self.NAME}.bin"
            file_name = os.path.join(path, ret)
            write_file(self.raw_block, file_name, mode="wb")
        return ret

    @classmethod
    def load_from_config(
        cls, config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> Self:
        """Load segment from configuration.

        :param config: Configuration of Segment.
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        cfg_value = config.get(cls.cfg_key())
        if not cfg_value:
            return cls()

        if not isinstance(cfg_value, str):
            raise SPSDKValueError(f"Except the binary file path to load {cls.NAME} segment.")
        binary = load_binary(path=cfg_value, search_paths=search_paths)
        if cls.SIZE > 0 and len(binary) > cls.SIZE:
            raise SPSDKValueError(
                f"The binary file has invalid length for {cls.NAME} segment: {len(binary)} != {cls.SIZE}."
            )
        return cls(raw_block=binary)


class SegmentKeyBlob(Segment):
    """Bootable Image KeyBlob Segment class."""

    NAME = "keyblob"
    SIZE = 256


class SegmentFcb(Segment):
    """Bootable Image FCB Segment class."""

    NAME = "fcb"
    SIZE = 512

    def __init__(self, raw_block: Optional[bytes] = None, fcb: Optional[FCB] = None) -> None:
        """Segment initialization, at least raw data are stored.

        :param raw_block: Raw data of segment.
        :param fcb: FCB class.
        """
        super().__init__(raw_block)
        self.fcb = fcb
        if fcb and self.raw_block != fcb.export():
            raise SPSDKValueError("The FCB block doesn't match the raw data.")

    @classmethod
    def parse(
        cls,
        binary: bytes,
        family: str = "Unknown",
        mem_type: str = "Unknown",
        revision: str = "latest",
        pattern: str = "zeros",
    ) -> Self:
        """Parse binary block into Segment object.

        :param binary: binary image.
        :param family: Chip family.
        :param mem_type: Used memory type.
        :param revision: Optional Chip family revision.
        :param pattern: Default Binary pattern of empty segment.
        :raises SPSDKError: If given binary block size is not equal to block size in header
        """
        if len(binary) < cls.SIZE:
            raise SPSDKParsingError("The input binary block is smaller than FCB.")

        if binary[:4] != b"FCFB":
            return cls()

        return cls(
            raw_block=binary[: cls.SIZE],
            fcb=FCB.parse(binary[: cls.SIZE], family=family, mem_type=mem_type, revision=revision),
        )

    def create_config(self, path: str) -> Union[str, int]:
        """Create configuration including store the data to specified path.

        :param path: Path where the information should be stored
        :returns: Value of segment to configuration file
        """
        ret = super().create_config(path)
        if self.fcb:
            write_file(self.fcb.create_config(), os.path.join(path, "segment_fcb.yaml"))
        return ret

    @classmethod
    def load_from_config(
        cls, config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> Self:
        """Load segment from configuration.

        :param config: Configuration of Segment.
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        # Try to load FCB from configuration as a first attempt
        cfg_value = config.get(cls.cfg_key())
        if not cfg_value:
            return cls()
        try:
            fcb = FCB.load_from_config(load_configuration(cfg_value, search_paths=search_paths))
            return cls(raw_block=fcb.export(), fcb=fcb)
        except SPSDKError:
            return super().load_from_config(config, search_paths)


class SegmentImageVersion(Segment):
    """Bootable Image Image version Segment class."""

    NAME = "image_version"
    SIZE = 4

    def create_config(self, path: str) -> Union[str, int]:
        """Create configuration including store the data to specified path.

        :param path: Path where the information should be stored
        :returns: Value of segment to configuration file
        """
        return int.from_bytes(self.raw_block[:4], "little")

    @classmethod
    def load_from_config(
        cls, config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> Self:
        """Load segment from configuration.

        :param config: Configuration of Segment.
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        cfg_value = config.get(cls.cfg_key(), 0)
        if not isinstance(cfg_value, int):
            raise SPSDKValueError(
                f"Invalid value for image version. It should be integer, and is: {cfg_value}"
            )
        return cls(raw_block=cfg_value.to_bytes(length=cls.SIZE, byteorder="little"))


class SegmentImageVersionAntiPole(Segment):
    """Bootable Image Image version with antipole value Segment class."""

    NAME = "image_version_ap"
    CFG_NAME = "image_version"
    SIZE = 4

    def create_config(self, path: str) -> Union[str, int]:
        """Create configuration including store the data to specified path.

        :param path: Path where the information should be stored
        :returns: Value of segment to configuration file
        """
        return int.from_bytes(self.raw_block[:2], "little")

    @classmethod
    def load_from_config(
        cls, config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> Self:
        """Load segment from configuration.

        :param config: Configuration of Segment.
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        cfg_value = config.get(cls.cfg_key(), 0)
        if not isinstance(cfg_value, int):
            raise SPSDKValueError(
                f"Invalid value for image version. It should be integer, and is: {cfg_value}"
            )
        image_version = (cfg_value or 0) & 0xFFFF
        image_version |= (image_version ^ 0xFFFF) << 16
        return cls(raw_block=image_version.to_bytes(length=cls.SIZE, byteorder="little"))


class SegmentKeyStore(Segment):
    """Bootable Image KeyStore Segment class."""

    NAME = "keystore"
    SIZE = 2048


class SegmentBeeHeader0(Segment):
    """Bootable Image BEE encryption header 0 Segment class."""

    NAME = "bee_header_0"
    SIZE = 512


class SegmentBeeHeader1(Segment):
    """Bootable Image BEE encryption header 1 Segment class."""

    NAME = "bee_header_1"
    SIZE = 512


class SegmentXmcd(Segment):
    """Bootable Image XMCD Segment class."""

    NAME = "xmcd"
    SIZE = 256

    def __init__(self, raw_block: Optional[bytes] = None, xmcd: Optional[XMCD] = None) -> None:
        """Segment initialization, at least raw data are stored.

        :param raw_block: Raw data of segment.
        :param xmcd: XMCD class.
        """
        super().__init__(raw_block)
        self.xmcd = xmcd
        if xmcd and self.raw_block != xmcd.export():
            raise SPSDKValueError("The XMCD block doesn't match the raw data.")

    @classmethod
    def parse(
        cls,
        binary: bytes,
        family: str = "Unknown",
        mem_type: str = "Unknown",
        revision: str = "latest",
        pattern: str = "zeros",
    ) -> Self:
        """Parse binary block into Segment object.

        :param binary: binary image.
        :param family: Chip family.
        :param mem_type: Used memory type.
        :param revision: Optional Chip family revision.
        :param pattern: Default Binary pattern of empty segment.
        :raises SPSDKError: If given binary block size is not equal to block size in header
        """
        if len(binary) < cls.SIZE:
            raise SPSDKParsingError("The input binary block is smaller than XMCD.")
        # Check if there is header of XMCD exists
        if binary[:8] == bytes(8):
            return cls(raw_block=binary[: cls.SIZE])

        xmcd = XMCD.parse(binary, family=family, revision=revision)
        return cls(raw_block=xmcd.export(), xmcd=xmcd)

    def create_config(self, path: str) -> Union[str, int]:
        """Create configuration including store the data to specified path.

        :param path: Path where the information should be stored
        :returns: Value of segment to configuration file
        """
        ret = super().create_config(path)
        if self.xmcd:
            write_file(self.xmcd.create_config(), os.path.join(path, "segment_xmcd.yaml"))
        return ret

    @classmethod
    def load_from_config(
        cls, config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> Self:
        """Load segment from configuration.

        :param config: Configuration of Segment.
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        # Try to load XMCD from configuration as a first attempt
        cfg_value = config.get(cls.cfg_key())
        if not cfg_value:
            return cls()
        try:
            xmcd = XMCD.load_from_config(load_configuration(cfg_value, search_paths=search_paths))
            return cls(raw_block=xmcd.export(), xmcd=xmcd)
        except SPSDKError:
            return super().load_from_config(config, search_paths)


class SegmentMbi(Segment):
    """Bootable Image Master Boot Image(MBI) Segment class."""

    NAME = "mbi"

    def __init__(
        self, raw_block: Optional[bytes] = None, mbi: Optional[MasterBootImage] = None
    ) -> None:
        """Segment initialization, at least raw data are stored.

        :param raw_block: Raw data of segment.
        :param mbi: Master boot image class.
        """
        super().__init__(raw_block)
        self.mbi = mbi
        if mbi and self.raw_block != mbi.export():
            raise SPSDKValueError("The MBI block doesn't match the raw data.")

    @classmethod
    def parse(
        cls,
        binary: bytes,
        family: str = "Unknown",
        mem_type: str = "Unknown",
        revision: str = "latest",
        pattern: str = "zeros",
    ) -> Self:
        """Parse binary block into Segment object.

        :param binary: binary image.
        :param family: Chip family.
        :param mem_type: Used memory type.
        :param revision: Optional Chip family revision.
        :param pattern: Default Binary pattern of empty segment.
        :raises SPSDKError: If given binary block size is not equal to block size in header
        """
        mbi = MasterBootImage.parse(family=family, data=binary)
        return cls(raw_block=binary, mbi=mbi)

    def create_config(self, path: str) -> Union[str, int]:
        """Create configuration including store the data to specified path.

        :param path: Path where the information should be stored
        :returns: Value of segment to configuration file
        """
        ret = super().create_config(path)
        if self.mbi:
            self.mbi.create_config(path)
        return ret

    @classmethod
    def load_from_config(
        cls, config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> Self:
        """Load segment from configuration.

        :param config: Configuration of Segment.
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        # Try to load MBI from configuration as a first attempt
        cfg_value = config.get(cls.cfg_key(), config.get("application"))
        try:
            config_data = load_configuration(cfg_value, search_paths=search_paths)
        except SPSDKError:
            # In case that the file is not configuration, load is as binary
            return super().load_from_config(config, search_paths)
        try:
            new_search_paths = [os.path.dirname(cfg_value)]
            if search_paths:
                new_search_paths.extend(search_paths)
            mbi_cls = get_mbi_class(config_data)
            check_config(
                config_data, mbi_cls.get_validation_schemas(), search_paths=new_search_paths
            )
            mbi = mbi_cls()
            mbi.load_from_config(config_data, search_paths=new_search_paths)
            return cls(raw_block=mbi.export(), mbi=mbi)
        except SPSDKError as exc:
            raise SPSDKValueError(
                f"Cannot export MBI container from the configuration:\n{str(exc)}"
            ) from exc


class SegmentHab(Segment):
    """Bootable Image High Assurance Boot(HAB) Segment class."""

    NAME = "hab_container"

    def __init__(
        self, raw_block: Optional[bytes] = None, hab: Optional[HabContainer] = None
    ) -> None:
        """Segment initialization, at least raw data are stored.

        :param raw_block: Raw data of segment.
        :param hab: High Assurance Boot class.
        """
        super().__init__(raw_block)
        self.hab = hab
        if hab and self.raw_block != hab.export():
            raise SPSDKValueError("The HAB block doesn't match the raw data.")

    @classmethod
    def parse(
        cls,
        binary: bytes,
        family: str = "Unknown",
        mem_type: str = "Unknown",
        revision: str = "latest",
        pattern: str = "zeros",
    ) -> Self:
        """Parse binary block into Segment object.

        :param binary: binary image.
        :param family: Chip family.
        :param mem_type: Used memory type.
        :param revision: Optional Chip family revision.
        :param pattern: Default Binary pattern of empty segment.
        :raises SPSDKError: If given binary block size is not equal to block size in header
        """
        hab = HabContainer.parse(data=binary)
        return cls(raw_block=binary, hab=hab)

    @classmethod
    def load_from_config(
        cls, config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> Self:
        """Load segment from configuration.

        :param config: Configuration of Segment.
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        # Try to load HAB from configuration as a first attempt
        cfg_value = config[cls.cfg_key()]
        try:
            parsed_conf = load_configuration(cfg_value, search_paths=search_paths)
        except (SPSDKError, UnicodeDecodeError):
            return super().load_from_config(config, search_paths)
        try:
            schemas = HabContainer.get_validation_schemas()
            check_config(parsed_conf, schemas, search_paths=search_paths)
            config = HabContainer.transform_bd_configuration(parsed_conf)
            hab: HabContainer = HabContainer.load_from_config(config, search_paths=search_paths)
            return cls(raw_block=hab.export(), hab=hab)
        except SPSDKError as exc:
            raise SPSDKValueError(
                f"Cannot export HAB container from the configuration:\n{str(exc)}"
            ) from exc


class SegmentAhab(Segment):
    """Bootable Image Advanced High Assurance Boot(HAB) Segment class."""

    NAME = "ahab_container"

    def __init__(self, raw_block: Optional[bytes] = None, ahab: Optional[AHABImage] = None) -> None:
        """Segment initialization, at least raw data are stored.

        :param raw_block: Raw data of segment.
        :param ahab: Advanced High Assurance Boot class.
        """
        super().__init__(raw_block)
        self.ahab = ahab
        if ahab and self.raw_block != ahab.export():
            raise SPSDKValueError("The AHAB block doesn't match the raw data.")

    @classmethod
    def parse(
        cls,
        binary: bytes,
        family: str = "Unknown",
        mem_type: str = "Unknown",
        revision: str = "latest",
        pattern: str = "zeros",
    ) -> Self:
        """Parse binary block into Segment object.

        :param binary: binary image.
        :param family: Chip family.
        :param mem_type: Used memory type.
        :param revision: Optional Chip family revision.
        :param pattern: Default Binary pattern of empty segment.
        :raises SPSDKError: If given binary block size is not equal to block size in header
        """
        ahab = AHABImage(family=family, revision=revision)
        ahab.parse(binary)
        return cls(raw_block=binary, ahab=ahab)

    def create_config(self, path: str) -> Union[str, int]:
        """Create configuration including store the data to specified path.

        :param path: Path where the information should be stored
        :returns: Value of segment to configuration file
        """
        ret = super().create_config(path)
        if self.ahab:
            yaml = CommentedConfig(
                "AHAB configuration",
                self.ahab.get_validation_schemas(),
                self.ahab.create_config(path),
                export_template=False,
            ).export_to_yaml()
            write_file(yaml, os.path.join(path, "segment_ahab_container.yaml"))
        return ret

    @classmethod
    def load_from_config(
        cls, config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> Self:
        """Load segment from configuration.

        :param config: Configuration of Segment.
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        # Try to load AHAB from configuration as a first attempt
        cfg_value = config[cls.cfg_key()]
        try:
            config_data = load_configuration(cfg_value, search_paths=search_paths)
        except SPSDKError:
            # In case that the file is not configuration, load is as binary
            return super().load_from_config(config, search_paths)

        try:
            new_search_paths = [os.path.dirname(cfg_value)]
            if search_paths:
                new_search_paths.extend(search_paths)
            schemas = AHABImage.get_validation_schemas()
            check_config(config_data, schemas, search_paths=new_search_paths)
            ahab = AHABImage.load_from_config(config_data, search_paths=new_search_paths)
            return cls(raw_block=ahab.export(), ahab=ahab)
        except SPSDKError as exc:
            raise SPSDKValueError(
                f"Cannot export AHAB container from the configuration:\n{str(exc)}"
            ) from exc


def get_segments() -> Dict[str, Type[Segment]]:
    """Get list of all supported segments."""
    ret = {}
    for var in globals():
        obj = globals()[var]
        if isclass(obj) and issubclass(obj, Segment) and obj is not Segment:
            assert issubclass(obj, Segment)
            ret[obj.NAME] = obj
    return ret


SEGMENTS_LIST = get_segments()


def get_segment_class(name: str) -> Type["Segment"]:
    """Get the segment class type.

    :return: Segment class type.
    """
    if name not in SEGMENTS_LIST:
        raise SPSDKValueError(f"Unsupported Bootable image segment name: {name}")
    return SEGMENTS_LIST[name]
