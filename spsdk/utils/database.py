#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module to manage used databases in SPSDK."""

import atexit
import logging
import os
import pickle
import shutil
from copy import copy, deepcopy
from typing import Any, Dict, Iterator, List, Optional, Tuple, Union

import platformdirs
from typing_extensions import Self

import spsdk
from spsdk import (
    SPSDK_ADDONS_DATA_FOLDER,
    SPSDK_CACHE_DISABLED,
    SPSDK_DATA_FOLDER,
    SPSDK_RESTRICTED_DATA_FOLDER,
    version,
)
from spsdk.apps.utils import spsdk_logger
from spsdk.crypto.hash import EnumHashAlgorithm, Hash, get_hash
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.utils.misc import (
    deep_update,
    find_first,
    load_configuration,
    value_to_bool,
    value_to_int,
)

logger = logging.getLogger(__name__)


class SPSDKErrorMissingDevice(SPSDKError):
    """Missing device in database."""


class Features:
    """Features dataclass represents a single device revision."""

    def __init__(
        self, name: str, is_latest: bool, device: "Device", features: Dict[str, Dict[str, Any]]
    ) -> None:
        """Constructor of revision.

        :param name: Revision name
        :param is_latest: Mark if this revision is latest.
        :param device: Reference to its device
        :param features: Features
        """
        self.name = name
        self.is_latest = is_latest
        self.device = device
        self.features = features

    def check_key(self, feature: str, key: Union[List[str], str]) -> bool:
        """Check if the key exist in database.

        :param feature: Feature name
        :param key: Item key or key path in list like ['grp1', 'grp2', 'key']
        :raises SPSDKValueError: Unsupported feature
        :return: True if exist False otherwise
        """
        if feature not in self.features:
            raise SPSDKValueError(f"Unsupported feature: '{feature}'")
        db_dict = self.features[feature]

        if isinstance(key, list):
            while len(key) > 1:
                act_key = key.pop(0)
                if act_key not in db_dict or not isinstance(db_dict[act_key], dict):
                    return False
                db_dict = db_dict[act_key]
            key = key[0]

        assert isinstance(key, str)
        return key in db_dict

    def get_value(self, feature: str, key: Union[List[str], str], default: Any = None) -> Any:
        """Get value.

        :param feature: Feature name
        :param key: Item key or key path in list like ['grp1', 'grp2', 'key']
        :param default: Default value in case of missing key
        :raises SPSDKValueError: Unsupported feature
        :raises SPSDKValueError: Unavailable item in feature
        :return: Value from the feature
        """
        if feature not in self.features:
            raise SPSDKValueError(f"Unsupported feature: '{feature}'")
        db_dict = self.features[feature]

        if isinstance(key, list):
            while len(key) > 1:
                act_key = key.pop(0)
                if act_key not in db_dict or not isinstance(db_dict[act_key], dict):
                    raise SPSDKValueError(f"Non-existing nested group: '{act_key}'")
                db_dict = db_dict[act_key]
            key = key[0]

        assert isinstance(key, str)
        val = db_dict.get(key, default)

        if val is None:
            raise SPSDKValueError(f"Unavailable item '{key}' in feature '{feature}'")
        return val

    def get_bool(
        self, feature: str, key: Union[List[str], str], default: Optional[bool] = None
    ) -> bool:
        """Get Boolean value.

        :param feature: Feature name
        :param key: Item key or key path in list like ['grp1', 'grp2', 'key']
        :param default: Default value in case of missing key
        :return: Boolean value from the feature
        """
        val = self.get_value(feature, key, default)
        return value_to_bool(val)

    def get_int(
        self, feature: str, key: Union[List[str], str], default: Optional[int] = None
    ) -> int:
        """Get Integer value.

        :param feature: Feature name
        :param key: Item key or key path in list like ['grp1', 'grp2', 'key']
        :param default: Default value in case of missing key
        :return: Integer value from the feature
        """
        val = self.get_value(feature, key, default)
        return value_to_int(val)

    def get_str(
        self, feature: str, key: Union[List[str], str], default: Optional[str] = None
    ) -> str:
        """Get String value.

        :param feature: Feature name
        :param key: Item key or key path in list like ['grp1', 'grp2', 'key']
        :param default: Default value in case of missing key
        :return: String value from the feature
        """
        val = self.get_value(feature, key, default)
        assert isinstance(val, str)
        return val

    def get_list(
        self, feature: str, key: Union[List[str], str], default: Optional[List] = None
    ) -> List[Any]:
        """Get List value.

        :param feature: Feature name
        :param key: Item key or key path in list like ['grp1', 'grp2', 'key']
        :param default: Default value in case of missing key
        :return: List value from the feature
        """
        val = self.get_value(feature, key, default)
        assert isinstance(val, list)
        return val

    def get_dict(
        self, feature: str, key: Union[List[str], str], default: Optional[Dict] = None
    ) -> Dict:
        """Get Dictionary value.

        :param feature: Feature name
        :param key: Item key or key path in list like ['grp1', 'grp2', 'key']
        :param default: Default value in case of missing key
        :return: Dictionary value from the feature
        """
        val = self.get_value(feature, key, default)
        assert isinstance(val, dict)
        return val

    def get_file_path(
        self,
        feature: str,
        key: Union[List[str], str],
        default: Optional[str] = None,
        just_standard_lib: bool = False,
    ) -> str:
        """Get File path value.

        :param feature: Feature name
        :param key: Item key or key path in list like ['grp1', 'grp2', 'key']
        :param default: Default value in case of missing key
        :param just_standard_lib: Use just standard library files (no restricted data, neither addons), defaults False.
        :return: File path value from the feature
        """
        file_name = self.get_str(feature, key, default)
        return self.device.create_file_path(file_name, just_standard_lib)


class Revisions(List[Features]):
    """List of device revisions."""

    def revision_names(self, append_latest: bool = False) -> List[str]:
        """Get list of revisions.

        :param append_latest: Add to list also "latest" string
        :return: List of all supported device version.
        """
        ret = [rev.name for rev in self]
        if append_latest:
            ret.append("latest")
        return ret

    def get(self, name: Optional[str] = None) -> Features:
        """Get the revision by its name.

        If name is not specified, or equal to 'latest', then the latest revision is returned.

        :param name: The revision name.
        :return: The Revision object.
        """
        if name is None or name == "latest":
            return self.get_latest()
        return self.get_by_name(name)

    def get_by_name(self, name: str) -> Features:
        """Get the required revision.

        :param name: Required revision name
        :raises SPSDKValueError: Incase of invalid device or revision value.
        :return: The Revision object.
        """
        revision = find_first(self, lambda rev: rev.name == name)
        if not revision:
            raise SPSDKValueError(f"Requested revision {name} is not supported.")
        return revision

    def get_latest(self) -> Features:
        """Get latest revision for device.

        :raises SPSDKValueError: Incase of there is no latest revision defined.
        :return: The Features object.
        """
        revision = find_first(self, lambda rev: rev.is_latest)
        if not revision:
            raise SPSDKValueError("No latest revision has been defined.")
        return revision


class UsbId:
    """Usb identifier for given device."""

    def __init__(self, vid: Optional[int] = None, pid: Optional[int] = None) -> None:
        """Constructor of USB ID class.

        :param vid: USB Vid
        :param pid: USB Pid
        """
        self.vid = vid
        self.pid = pid

    def __eq__(self, obj: Any) -> bool:
        return isinstance(obj, self.__class__) and self.vid == obj.vid and self.pid == obj.pid

    def update(self, usb_config: Dict) -> None:
        """Update the object from configuration."""
        self.vid = usb_config.get("vid", self.vid)
        self.pid = usb_config.get("pid", self.pid)

    @classmethod
    def load(cls, usb_config: Dict) -> Self:
        """Load from configuration."""
        return cls(vid=usb_config.get("vid", None), pid=usb_config.get("pid", None))

    def is_valid(self) -> bool:
        """Returns True if all the properties are set, False otherwise."""
        return self.vid is not None and self.pid is not None


class Bootloader:
    """Bootloader."""

    def __init__(
        self,
        protocol: Optional[str],
        interfaces: List,
        usb_id: UsbId,
        protocol_params: Dict,
    ) -> None:
        """Constructor of bootloader class.

        :param protocol: Protocol name
        :param interfaces: List of supported interfaces
        :param usb_id: Usb ID
        :param params: Protocol parameters
        """
        if protocol and protocol not in ["mboot", "sdp", "sdps"]:
            raise SPSDKValueError(f"Invalid protocol value: {protocol}")
        self.protocol = protocol
        self.interfaces = interfaces
        self.usb_id = usb_id
        self.protocol_params = protocol_params

    @classmethod
    def load(cls, config: Dict) -> Self:
        """Load from configuration."""
        return cls(
            protocol=config.get("protocol", None),
            interfaces=config.get("interfaces", []),
            usb_id=UsbId.load(config.get("usb", {})),
            protocol_params=config.get("protocol_params", {}),
        )

    def update(self, config: Dict) -> None:
        """Update the object from configuration."""
        self.protocol = config.get("protocol", self.protocol)
        self.interfaces = config.get("interfaces", self.interfaces)
        self.protocol_params = config.get("protocol_params", self.protocol_params)
        self.usb_id.update(config.get("usb", {}))


class IspCfg:
    """ISP configuration."""

    def __init__(self, rom: Bootloader, flashloader: Bootloader) -> None:
        """Constructor of ISP config class.

        :param rom: ROM object
        :param flashloader: Flashloader object
        """
        self.rom = rom
        self.flashloader = flashloader

    @classmethod
    def load(cls, config: Dict) -> Self:
        """Load from configuration."""
        return cls(
            rom=Bootloader.load(config.get("rom", {})),
            flashloader=Bootloader.load(config.get("flashloader", {})),
        )

    def update(self, config: Dict) -> None:
        """Update the object from configuration."""
        self.rom.update(config.get("rom", {}))
        self.flashloader.update(config.get("flashloader", {}))

    def is_protocol_supported(self, protocol: str) -> bool:
        """Returns true is any of interfaces supports given protocol."""
        return self.rom.protocol == protocol or self.flashloader.protocol == protocol

    def get_usb_ids(self, protocol: str) -> List[UsbId]:
        """Get the usb params for interfaces supporting given protocol."""
        usb_ids = []
        if self.rom.protocol == protocol and self.rom.usb_id.is_valid():
            usb_ids.append(self.rom.usb_id)
        if self.flashloader.protocol == protocol and self.flashloader.usb_id.is_valid():
            usb_ids.append(self.flashloader.usb_id)
        return usb_ids


class DeviceInfo:
    """Device information dataclass."""

    def __init__(
        self,
        use_in_doc: bool,
        purpose: str,
        web: str,
        memory_map: Dict[str, Dict[str, Union[int, bool]]],
        isp: IspCfg,
    ) -> None:
        """Constructor of device information class.

        :param purpose: String description of purpose of MCU (in fact the device group)
        :param web: Web page with device info
        :param memory_map: Basic memory map of device
        :param isp: Information regarding ISP mode
        """
        self.use_in_doc = use_in_doc
        self.purpose = purpose
        self.web = web
        self.memory_map = memory_map
        self.isp = isp

    def __repr__(self) -> str:
        return f"DeviceInfo({self.purpose})"

    @classmethod
    def load(cls, config: Dict[str, Any], defaults: Dict[str, Any]) -> Self:
        """Loads the device from folder.

        :param config: The name of device.
        :param defaults: Device data defaults.
        :return: The Device object.
        """
        data = deepcopy(defaults)
        deep_update(data, config)
        return cls(
            use_in_doc=bool(data.get("use_in_doc", True)),
            purpose=data["purpose"],
            web=data["web"],
            memory_map=data["memory_map"],
            isp=IspCfg.load(data["isp"]),
        )

    def update(self, config: Dict[str, Any]) -> None:
        """Updates Device info by new configuration.

        :param config: The new Device Info configuration
        """
        self.use_in_doc = bool(config.get("use_in_doc", self.use_in_doc))
        self.purpose = config.get("purpose", self.purpose)
        self.web = config.get("web", self.web)
        self.memory_map = config.get("memory_map", self.memory_map)
        self.isp.update(config.get("isp", {}))


class Device:
    """Device dataclass represents a single device."""

    def __init__(
        self,
        name: str,
        db: "Database",
        latest_rev: str,
        info: DeviceInfo,
        device_alias: Optional["Device"] = None,
        revisions: Revisions = Revisions(),
    ) -> None:
        """Constructor of SPSDK Device.

        :param name: Device name
        :param db: Database parent object
        :param latest_rev: latest revision name
        :param device_alias: Device alias, defaults to None
        :param revisions: Device revisions, defaults to Revisions()
        """
        self.name = name
        self.db = db
        self.latest_rev = latest_rev
        self.device_alias = device_alias
        self.revisions = revisions
        self.info = info

    def get_copy(self, new_name: Optional[str] = None) -> "Device":
        """Get copy of self.

        :param new_name: Optionally the copy could has a new name.
        :returns: Copy of self.
        """
        name = new_name or self.name
        ret = Device(
            name=name,
            db=self.db,
            latest_rev=self.latest_rev,
            info=deepcopy(self.info),
            device_alias=self.device_alias,
        )
        # copy all revisions
        revisions = Revisions()
        for features in self.revisions:
            revisions.append(
                Features(
                    name=features.name,
                    is_latest=features.is_latest,
                    device=ret,
                    features=deepcopy(features.features),
                )
            )
        ret.revisions = revisions
        return ret

    def __repr__(self) -> str:
        return f"Device({self.name})"

    def __lt__(self, other: "Device") -> bool:
        """Less than comparison based on name."""
        return self.name < other.name

    @property
    def features_list(self) -> List[str]:
        """Get the list of device features."""
        return [str(k) for k in self.revisions.get().features.keys()]

    @staticmethod
    def _load_alias(name: str, db: "Database", dev_cfg: Dict[str, Any]) -> "Device":
        """Loads the device from folder.

        :param name: The name of device.
        :param db: Database parent object.
        :param dev_cfg: Already loaded configuration.
        :return: The Device object.
        """
        dev_alias_name = dev_cfg["alias"]
        # Let get() function raise exception in case that device not exists in database
        ret = db.devices.get(dev_alias_name).get_copy(name)
        ret.device_alias = db.devices.get(dev_alias_name)
        dev_features: Dict[str, Dict] = dev_cfg.get("features", {})
        dev_revisions: Dict[str, Dict] = dev_cfg.get("revisions", {})
        assert isinstance(dev_features, Dict)
        assert isinstance(dev_revisions, Dict)
        ret.latest_rev = dev_cfg.get("latest", ret.latest_rev)
        # First of all update general changes in features
        if dev_features:
            for rev in ret.revisions:
                deep_update(rev.features, dev_features)

        for rev_name, rev_updates in dev_revisions.items():
            try:
                dev_rev = ret.revisions.get_by_name(rev_name)
            except SPSDKValueError as exc:
                # In case of newly defined revision, there must be defined alias
                alias_rev = rev_updates.get("alias")
                if not alias_rev:
                    raise SPSDKError(
                        f"There is missing alias key in new revision ({rev_name}) of aliased device {ret.name}"
                    ) from exc
                dev_rev = deepcopy(ret.revisions.get_by_name(alias_rev))
                dev_rev.name = rev_name
                dev_rev.is_latest = bool(ret.latest_rev == rev_name)
                ret.revisions.append(dev_rev)

            # Update just same rev
            rev_specific_features = rev_updates.get("features")
            if rev_specific_features:
                deep_update(dev_rev.features, rev_specific_features)

        if "info" in dev_cfg:
            ret.info.update(dev_cfg["info"])

        return ret

    @staticmethod
    def load(name: str, db: "Database") -> "Device":
        """Loads the device from folder.

        :param name: The name of device.
        :param db: Base database object.
        :return: The Device object.
        """
        dev_cfg = load_configuration(
            db.get_data_file_path(os.path.join("devices", name, "database.yaml"))
        )

        # Update database by addons data
        if db.addons_data_path:
            addons_db_path = os.path.join(db.addons_data_path, "devices", name, "database.yaml")
            if os.path.exists(addons_db_path):
                dev_cfg.update(load_configuration(addons_db_path))

        dev_alias_name = dev_cfg.get("alias")
        if dev_alias_name:
            return Device._load_alias(name=name, db=db, dev_cfg=dev_cfg)

        dev_features: Dict[str, Dict] = dev_cfg["features"]
        features_defaults: Dict[str, Dict] = deepcopy(db._defaults["features"])

        dev_info = DeviceInfo.load(dev_cfg["info"], db._defaults["info"])

        # Get defaults and update them by device specific data set
        for feature_name in dev_features:
            deep_update(features_defaults[feature_name], dev_features[feature_name])
            dev_features[feature_name] = features_defaults[feature_name]

        revisions = Revisions()
        dev_revisions: Dict[str, Dict] = dev_cfg["revisions"]
        latest: str = dev_cfg["latest"]
        if latest not in dev_revisions:
            raise SPSDKError(
                f"The latest revision defined in database for {name} is not in supported revisions"
            )

        ret = Device(name=name, db=db, info=dev_info, latest_rev=latest, device_alias=None)

        for rev, rev_updates in dev_revisions.items():
            features = deepcopy(dev_features)
            rev_specific_features = rev_updates.get("features")
            if rev_specific_features:
                deep_update(features, rev_specific_features)
            revisions.append(
                Features(name=rev, is_latest=bool(rev == latest), features=features, device=ret)
            )

        ret.revisions = revisions

        return ret

    def create_file_path(self, file_name: str, just_standard_lib: bool = False) -> str:
        """Create File path value for this device.

        :param file_name: File name to be enriched by device path
        :param just_standard_lib: Use just standard library files (no restricted data, neither addons), defaults False.
        :return: File path value for the device
        """
        path = self.db.get_data_file_path(
            os.path.join("devices", self.name, file_name),
            exc_enabled=False,
            just_standard_lib=just_standard_lib,
        )
        if not os.path.exists(path) and self.device_alias:
            path = self.device_alias.create_file_path(file_name)

        if not os.path.exists(path):
            raise SPSDKValueError(f"Non existing file ({file_name}) in database")
        return path


class Devices(List[Device]):
    """List of devices."""

    def get(self, name: str) -> Device:
        """Return database device structure.

        :param name: String Key with device name.
        :raises SPSDKErrorMissingDevice: In case the device with given name does not exist
        :return: Dictionary device configuration structure or None:
        """
        dev = find_first(self, lambda dev: dev.name == name)
        if not dev:
            raise SPSDKErrorMissingDevice(f"The device with name {name} is not in the database.")
        return dev

    @property
    def devices_names(self) -> List[str]:
        """Get the list of devices names."""
        return [dev.name for dev in self]

    def feature_items(self, feature: str, key: str) -> Iterator[Tuple[str, str, Any]]:
        """Iter the whole database for the feature items.

        :return: Tuple of Device name, revision name and items value.
        """
        for device in self:
            if not feature in device.features_list:
                continue
            for rev in device.revisions:
                value = rev.features[feature].get(key)
                if value is None:
                    raise SPSDKValueError(f"Missing item '{key}' in feature '{feature}'!")
                yield (device.name, rev.name, value)

    def load(self, db: "Database", devices_path: str) -> None:
        """Loads the devices from SPSDK database path.

        :param db: The parent database object.
        :param devices_path: The devices path.
        """
        uncompleted_aliases: List[os.DirEntry] = []
        for dev in os.scandir(devices_path):
            # Omit already loaded devices (used for multiple calls of this method (restricted data))
            if dev.name in self.devices_names:
                continue

            if dev.is_dir():
                try:
                    try:
                        self.append(Device.load(name=dev.name, db=db))
                    except SPSDKErrorMissingDevice:
                        uncompleted_aliases.append(dev)
                except SPSDKError as exc:
                    logger.error(
                        f"Failed loading device '{dev.name}' into SPSDK database. Details:\n{str(exc)}"
                    )
        while uncompleted_aliases:
            prev_len = len(uncompleted_aliases)
            for dev in copy(uncompleted_aliases):
                try:
                    self.append(Device.load(name=dev.name, db=db))
                    uncompleted_aliases.remove(dev)
                except SPSDKErrorMissingDevice:
                    pass
            if prev_len == len(uncompleted_aliases):
                raise SPSDKError("Cannot load all alias devices in database.")


class Database:
    """Class that helps manage used databases in SPSDK."""

    def __init__(
        self,
        path: str,
        restricted_data_path: Optional[str] = None,
        addons_data_path: Optional[str] = None,
    ) -> None:
        """Register Configuration class constructor.

        :param path: The path to the base database.
        :param restricted_data_path: The path to the restricted data database.
        :param addons_data_path: The path to the addons data database.
        """
        self._cfg_cache: Dict[str, Dict[str, Any]] = {}
        self.path = path
        self.restricted_data_path = restricted_data_path
        self.addons_data_path = addons_data_path
        self._defaults = load_configuration(
            self.get_common_data_file_path("database_defaults.yaml")
        )
        self._devices = Devices()
        self._devices.load(self, os.path.join(path, "devices"))
        if restricted_data_path:
            self._devices.load(self, os.path.join(restricted_data_path, "devices"))

        # optional Database hash that could be used for identification of consistency
        self.db_hash = bytes()

    @property
    def devices(self) -> Devices:
        """Get the list of devices stored in the database."""
        return self._devices

    def get_feature_list(self, dev_name: Optional[str] = None) -> List[str]:
        """Get features list.

        If device is not used, the whole list of SPSDK features is returned

        :param dev_name: Device name, defaults to None
        :returns: List of features.
        """
        if dev_name:
            return self.devices.get(dev_name).features_list

        default_features: Dict[str, Dict] = self._defaults["features"]
        return [str(k) for k in default_features.keys()]

    def get_defaults(self, feature: str) -> Dict[str, Any]:
        """Gets feature defaults.

        :param feature: Feature name
        :return: Dictionary with feature defaults.
        """
        features = self._defaults["features"]
        if feature not in features:
            raise SPSDKValueError(f"Invalid feature requested: {feature}")

        return deepcopy(features[feature])

    def get_device_features(
        self,
        device: str,
        revision: str = "latest",
    ) -> Features:
        """Get device features database.

        :param device: The device name.
        :param revision: The revision of the silicon.
        :raises SPSDKValueError: Unsupported feature
        :return: The feature data.
        """
        dev = self.devices.get(device)
        return dev.revisions.get(revision)

    def get_data_file_path(
        self, path: str, exc_enabled: bool = True, just_standard_lib: bool = False
    ) -> str:
        """Get data file path.

        The method counts also with restricted data source and any other addons.

        :param path: Relative path in data folder
        :param exc_enabled: Exception enabled in case of non existing file.
        :param just_standard_lib: Use just standard library files (no restricted data, neither addons), defaults False.
        :raises SPSDKValueError: Non existing file path.
        :return: Final absolute path to data file.
        """
        # 1. Prepare normal data file
        normal_path = os.path.join(self.path, path)

        # 2. Try to get restricted data file
        if self.restricted_data_path and not just_standard_lib:
            restr_path = os.path.join(self.restricted_data_path, path)
            if os.path.exists(restr_path):
                return os.path.abspath(restr_path)

        if not os.path.exists(normal_path):
            # 3. If Normal nor Restricted file exists give chance of addons
            if self.addons_data_path and not just_standard_lib:
                addons_path = os.path.join(self.addons_data_path, path)
                if os.path.exists(addons_path):
                    return os.path.abspath(addons_path)

            # 4. In case that the file doesn't exist and exception is allowed, raise exception
            if exc_enabled:
                raise SPSDKValueError(f"The requested data file doesn't exists: {path}")

        # 5. Return normal path if exist or not
        return os.path.abspath(normal_path)

    def get_schema_file(self, feature: str) -> Dict[str, Any]:
        """Get JSON Schema file name for the requested feature.

        :param feature: Requested feature.
        :return: Loaded dictionary of JSON Schema file.
        """
        path = self.get_data_file_path(os.path.join("jsonschemas", f"sch_{feature}.yaml"))
        return DatabaseManager().db.load_db_cfg_file(path)

    def get_common_data_file_path(self, path: str) -> str:
        """Get common data file path.

        The method counts also with restricted data source and any other addons.

        :param path: Relative path in common data folder
        :raises SPSDKValueError: Non existing file path.
        :return: Final absolute path to data file.
        """
        return self.get_data_file_path(os.path.join("common", path))

    def load_db_cfg_file(self, filename: str) -> Dict[str, Any]:
        """Return load database config file (JSON/YAML). Use SingleTon behavior.

        :param filename: Path to config file.
        :raises SPSDKError: Invalid config file.
        :return: Loaded file in dictionary.
        """
        abs_path = os.path.abspath(filename)
        if abs_path not in self._cfg_cache:
            try:
                cfg = load_configuration(abs_path)
            except SPSDKError as exc:
                raise SPSDKError(f"Invalid configuration file. {str(exc)}") from exc
            self._cfg_cache[abs_path] = cfg

        return deepcopy(self._cfg_cache[abs_path])

    def get_devices_with_feature(
        self, feature: str, sub_keys: Optional[List[str]] = None
    ) -> List[str]:
        """Get the list of all device names that supports requested feature.

        :param feature: Name of feature
        :param sub_keys: Optional sub keys to specify the nested dictionaries that feature needs to has to be counted
        :returns: List of devices that supports requested feature.
        """

        def check_sub_keys(d: dict, sub_keys: List[str]) -> bool:
            key = sub_keys.pop(0)
            if not key in d:
                return False

            if len(sub_keys) == 0:
                return True

            nested = d[key]
            if not isinstance(nested, dict):
                return False
            return check_sub_keys(nested, sub_keys)

        devices = []
        for device in self.devices:
            if feature in device.features_list:
                if sub_keys and not check_sub_keys(
                    device.revisions.get_latest().features[feature], copy(sub_keys)
                ):
                    continue
                devices.append(device.name)

        devices.sort()
        return devices

    def __hash__(self) -> int:
        """Hash function of the database."""
        return hash(len(self._cfg_cache))


class DatabaseManager:
    """Main SPSDK database manager."""

    _instance = None
    _db: Optional[Database] = None
    _db_hash: int = 0
    _db_cache_file_name = ""

    @staticmethod
    def get_cache_filename() -> Tuple[str, str]:
        """Get database cache folder and file name.

        :return: Tuple of cache path and database file name.
        """
        data_folder = SPSDK_DATA_FOLDER.lower()
        cache_name = (
            "db_"
            + get_hash(data_folder.encode(), algorithm=EnumHashAlgorithm.SHA1)[:6].hex()
            + ".cache"
        )
        cache_path = platformdirs.user_cache_dir(appname="spsdk", version=spsdk.SPSDK_VERSION_BASE)
        return (cache_path, os.path.join(cache_path, cache_name))

    @staticmethod
    def clear_cache() -> None:
        """Clear SPSDK cache."""
        path, _ = DatabaseManager.get_cache_filename()
        if not os.path.exists(path):
            logger.debug(f"Cache dir '{path}' does not exist, nothing to clear.")
            return
        shutil.rmtree(path)

    @staticmethod
    def get_restricted_data() -> Optional[str]:
        """Get restricted data folder, if applicable.

        :return: Optional restricted data folder.
        """
        if SPSDK_RESTRICTED_DATA_FOLDER is None:
            return None

        try:
            rd_version: str = load_configuration(
                os.path.join(SPSDK_RESTRICTED_DATA_FOLDER, "metadata.yaml")
            )["version"]
        except SPSDKError:
            logger.error("The Restricted data has invalid folder of METADATA")
            return None
        major, minor = rd_version.split(".", maxsplit=2)
        if int(major) != version.major or int(minor) != version.minor:
            logger.error(
                f"The restricted data version is no equal to SPSDK current version: {rd_version} != {str(version)}"
            )
            return None
        database_path = os.path.join(SPSDK_RESTRICTED_DATA_FOLDER, "data")
        if not os.path.exists(database_path):
            logger.error(f"The restricted data doesn't contains data folder: {database_path}")
            return None
        return database_path

    @classmethod
    def _get_database(cls) -> Database:
        """Get database and count with cache."""
        restricted_data = DatabaseManager.get_restricted_data()

        if SPSDK_CACHE_DISABLED:
            DatabaseManager.clear_cache()
            return Database(SPSDK_DATA_FOLDER, restricted_data, SPSDK_ADDONS_DATA_FOLDER)

        db_hash = DatabaseManager.get_db_hash(
            [SPSDK_DATA_FOLDER, restricted_data, SPSDK_ADDONS_DATA_FOLDER]
        )
        logger.debug(f"Current database finger print hash: {db_hash.hex()}")
        if os.path.exists(cls._db_cache_file_name):
            try:
                with open(cls._db_cache_file_name, mode="rb") as f:
                    loaded_db = pickle.load(f)
                    assert isinstance(loaded_db, Database)
                    if db_hash == loaded_db.db_hash:
                        logger.debug(f"Loaded database from cache: {cls._db_cache_file_name}")
                        return loaded_db
                    # if the hash is not same clear cache and make a new one
                    logger.debug(
                        f"Existing cached DB ({cls._db_cache_file_name}) has invalid hash. It will be erased."
                    )
                DatabaseManager.clear_cache()
            except Exception as exc:
                logger.debug(f"Cannot load database cache: {str(exc)}")

        db = Database(SPSDK_DATA_FOLDER, restricted_data, SPSDK_ADDONS_DATA_FOLDER)
        db.db_hash = db_hash
        try:
            os.makedirs(cls._db_cache_folder_name, exist_ok=True)
            with open(cls._db_cache_file_name, mode="wb") as f:
                pickle.dump(db, f, pickle.HIGHEST_PROTOCOL)
                logger.debug(f"Created database cache: {cls._db_cache_file_name}")
        except Exception as exc:
            logger.debug(f"Cannot store database cache: {str(exc)}")
        return db

    def __new__(cls) -> Self:
        """Manage SPSDK Database as a singleton class.

        :return: SPSDK_Database object
        """
        if cls._instance:
            return cls._instance
        spsdk_logger.install()
        cls._instance = super(DatabaseManager, cls).__new__(cls)
        cls._db_cache_folder_name, cls._db_cache_file_name = DatabaseManager.get_cache_filename()
        cls._db = cls._instance._get_database()
        cls._db_hash = hash(cls._db)
        return cls._instance

    @staticmethod
    def get_db_hash(paths: List[Optional[str]]) -> bytes:
        """Get the real databases hash."""

        def hash_file(file: str) -> None:
            stat = os.stat(file)
            hash_obj.update_int(stat.st_mtime_ns)
            hash_obj.update_int(stat.st_ctime_ns)
            hash_obj.update_int(stat.st_size)

        hash_obj = Hash(EnumHashAlgorithm.SHA1)
        if os.path.exists(__file__):
            hash_file(__file__)  # Add to hash also this source file itself if exists
        for path in paths:
            if path is None:
                continue
            for root, dirs, files in os.walk(path):
                for _dir in dirs:
                    hash_obj.update(DatabaseManager.get_db_hash([os.path.join(root, _dir)]))
                for file in files:
                    if os.path.splitext(file)[1] in [".json", ".yaml"]:
                        hash_file(os.path.join(root, file))

        return hash_obj.finalize()

    @property
    def db(self) -> Database:
        """Get Database."""
        db = type(self)._db
        assert isinstance(db, Database)
        return db

    # """List all SPSDK supported features"""
    FUSES = "fuses"
    COMM_BUFFER = "comm_buffer"
    # BLHOST = "blhost"
    CERT_BLOCK = "cert_block"
    DAT = "dat"
    MBI = "mbi"
    HAB = "hab"
    AHAB = "ahab"
    SIGNED_MSG = "signed_msg"
    PFR = "pfr"
    IFR = "ifr"
    BOOTABLE_IMAGE = "bootable_image"
    FCB = "fcb"
    XMCD = "xmcd"
    BEE = "bee"
    IEE = "iee"
    OTFAD = "otfad"
    SB21 = "sb21"
    SB31 = "sb31"
    SBX = "sbx"
    SHADOW_REGS = "shadow_regs"
    DEVHSM = "devhsm"
    TP = "tp"
    TZ = "tz"
    ELE = "ele"
    MEMCFG = "memcfg"
    WPC = "wpc"
    SIGNING = "signing"
    EL2GO_TP = "el2go_tp"


@atexit.register
def on_delete() -> None:
    """Delete method of SPSDK database.

    The exit method is used to update cache in case it has been changed.
    """
    if SPSDK_CACHE_DISABLED:
        return
    if DatabaseManager._db_hash != hash(DatabaseManager._db):
        try:
            with open(DatabaseManager._db_cache_file_name, mode="wb") as f:
                pickle.dump(DatabaseManager().db, f, pickle.HIGHEST_PROTOCOL)
        except (FileNotFoundError, ValueError):
            pass


def get_db(
    device: str,
    revision: str = "latest",
) -> Features:
    """Get device feature database.

    :param device: The device name.
    :param revision: The revision of the silicon.
    :return: The feature data.
    """
    return DatabaseManager().db.get_device_features(device, revision)


def get_device(device: str) -> Device:
    """Get device database object.

    :param device: The device name.
    :return: The device data.
    """
    return DatabaseManager().db.devices.get(device)


def get_families(feature: str, sub_keys: Optional[List[str]] = None) -> List[str]:
    """Get the list of all family names that supports requested feature.

    :param feature: Name of feature
    :param sub_keys: Optional sub keys to specify the nested dictionaries that feature needs to has to be counted
    :returns: List of devices that supports requested feature.
    """
    return DatabaseManager().db.get_devices_with_feature(feature, sub_keys)


def get_schema_file(feature: str) -> Dict[str, Any]:
    """Get JSON Schema file name for the requested feature.

    :param feature: Requested feature.
    :return: Loaded dictionary of JSON Schema file.
    """
    return DatabaseManager().db.get_schema_file(feature)


def get_common_data_file_path(path: str) -> str:
    """Get common data file path.

    The method counts also with restricted data source and any other addons.

    :param path: Relative path in common data folder
    :raises SPSDKValueError: Non existing file path.
    :return: Final absolute path to data file.
    """
    return DatabaseManager().db.get_common_data_file_path(path)


def get_whole_db() -> Database:
    """Get loaded main Database."""
    return DatabaseManager().db
