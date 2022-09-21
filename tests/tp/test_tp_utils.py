#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Tests for Trust provisioning utilities."""
import pytest
import yaml

import spsdk.tp.adapters as TPA
import spsdk.tp.utils as TPU
from spsdk.apps.tp_utils import print_device_table
from spsdk.tp.tp_intf import SPSDKTpError, TpDevInterface


def test_get_devices():
    """Test  get TP devices list."""
    assert TPU.get_tp_device_types() == list(TPA.TP_DEVICES.keys())


def test_get_targets():
    """Test  get TP targets list."""
    assert TPU.get_tp_target_types() == list(TPA.TP_TARGETS.keys())


def test_get_device_class():
    """Test  get TP device class."""
    assert TPU.get_tp_device_class("scard") == TPA.TpDevSmartCard


def test_get_target_class():
    """Test  get TP target class."""
    assert TPU.get_tp_target_class("blhost") == TPA.TpTargetBlHost


def test_print_table():
    """Test print device table."""

    class TpIntfDescExtended(TPU.TpIntfDescription):
        """Test inherited class for TP Interface description."""

        def __init__(self) -> None:
            super().__init__(
                name="Interface Name",
                intf=TpDevInterface,
                description="Interface Description",
                settings=None,
            )
            self.test_header = "Test Value"

    dev_desc_list = [TpIntfDescExtended()]

    dev_desc_list_str = print_device_table(dev_desc_list)

    assert "Interface Name" in dev_desc_list_str
    assert "Interface Description" in dev_desc_list_str


def test_print_table_empty():
    """Test print device table."""
    dev_desc_list_str = print_device_table([])

    assert "Nothing to print - empty interface list!" in dev_desc_list_str


def test_oem_cert_size_ok(data_dir):
    config_file = f"{data_dir}/small_oem_cert_config.yaml"
    with open(config_file) as f:
        config_data = yaml.safe_load(f)

    cert = TPA.TpDevSmartCard._create_oem_cert_template(
        config_data=config_data, config_dir=data_dir
    )
    assert len(cert) < 1000


def test_oem_cert_size_bad(data_dir):
    config_file = f"{data_dir}/big_oem_cert_config.yaml"
    with open(config_file) as f:
        config_data = yaml.safe_load(f)
    with pytest.raises(SPSDKTpError) as f:
        TPA.TpDevSmartCard._create_oem_cert_template(config_data=config_data, config_dir=data_dir)
