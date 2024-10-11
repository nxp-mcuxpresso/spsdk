#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Utils for DevHSM."""

import logging
import os
from inspect import isclass
from typing import Optional, Type, Union

from spsdk.exceptions import SPSDKError
from spsdk.sbfile.devhsm.devhsm import DevHsm
from spsdk.sbfile.sb31.devhsm import DevHsmSB31
from spsdk.sbfile.sbx.devhsm import DevHsmSBx
from spsdk.utils.database import DatabaseManager, get_db
from spsdk.utils.misc import find_dir, find_file, load_configuration

logger = logging.getLogger(__name__)


def get_devhsm_class(family: str) -> Type[Union["DevHsmSB31", "DevHsmSBx"]]:
    """Get name of DevHsm class based on family.

    :param family: name of the family
    :raises SPSDKError: If the class is not found
    :return: name of the class that supports given family
    """
    devhsm_cls = get_db(family, "latest").get_str(DatabaseManager.DEVHSM, "devhsm_class")
    try:
        obj = globals()[devhsm_cls]
    except KeyError as exc:
        raise SPSDKError(f"Class for {family} is unknown") from exc
    if isclass(obj) and issubclass(obj, DevHsm) and obj is not DevHsm:
        assert isinstance(obj, type(DevHsmSB31)) or isinstance(obj, type(DevHsmSBx))
        return obj
    raise SPSDKError(f"Class {obj} is not supported.")


class DevHSMConfig:
    """Helper class for nxpdevhsm app configuration."""

    _params_map = {
        "config": "config",
        "oem_share_input": "oemRandomShare",
        "enc_oem_master_share": "oemEncMasterShare",
        "key": "containerKeyBlobEncryptionKey",
        "output": "containerOutputFile",
        "workspace": "workspace",
        "family": "family",
        "initial_reset": "initialReset",
        "final_reset": "finalReset",
        "buffer_address": "bufferAddress",
    }

    def __init__(
        self,
        config: Optional[str] = None,
        oem_share_input: Optional[str] = None,
        enc_oem_master_share: Optional[str] = None,
        key: Optional[str] = None,
        output: Optional[str] = None,
        workspace: Optional[str] = None,
        family: Optional[str] = None,
        initial_reset: Optional[bool] = None,
        final_reset: Optional[bool] = None,
        buffer_address: Optional[int] = None,
    ) -> None:
        """Take all the user inputs."""
        self.config = config
        self.config_path = os.path.dirname(config) if config else None
        self.config_data = (
            load_configuration(config, [self.config_path] if self.config_path else None)
            if config
            else None
        )
        self.oem_share_input = oem_share_input
        self.enc_oem_master_share = enc_oem_master_share
        self.key = key
        self.output = output
        self.workspace = workspace
        self.family = family
        self.initial_reset = initial_reset
        self.final_reset = final_reset
        self.buffer_address = buffer_address
        self._process_params()

    def _process_params(self) -> None:
        for param, config_key in self._params_map.items():
            if param in ["config", "config_data"]:
                continue
            value = getattr(self, param)
            if value is None:
                config_value = self.config_data.get(config_key) if self.config_data else None

                # handle paths to files
                # if a path is defined in a config file, try to find the file using config file's location
                if (
                    param in ["oem_share_input", "enc_oem_master_share"]
                    and config_value is not None
                ):
                    config_value = find_file(
                        file_path=config_value,
                        search_paths=[self.config_path] if self.config_path else None,
                    )

                # output doesn't have to exist yet
                if param == "output" and config_value is not None:
                    config_value = find_file(
                        file_path=config_value,
                        search_paths=[self.config_path] if self.config_path else None,
                        raise_exc=False,
                    )

                # workspace doesn't have to exist yet
                if param == "workspace" and config_value is not None:
                    existing_path = find_dir(
                        dir_path=config_value,
                        search_paths=[self.config_path] if self.config_path else None,
                        raise_exc=False,
                    )
                    if existing_path:
                        config_value = existing_path
                    else:
                        config_value = os.path.join(
                            self.config_path if self.config_path else "", config_value
                        )

                # if reset's are not set via CMD nor via config file, use defaults
                if param == "initial_reset" and config_value is None:
                    config_value = False
                if param == "final_reset" and config_value is None:
                    config_value = True

                logger.debug(f"setting {param} to {config_value}")
                setattr(self, param, config_value)

            else:
                logger.warning(
                    f"Option '{param}' is deprecated. Instead please use '{config_key}' in config file. "
                )
