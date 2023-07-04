#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import os
import shutil

import pytest
import yaml

from spsdk.tp.adapters.tpdev_model import TpDevSwModel
from spsdk.tp.data_container import AuthenticationType, Container, PayloadType
from spsdk.tp.exceptions import SPSDKTpError
from spsdk.tp.tp_intf import TpIntfDescription
from spsdk.utils.misc import load_binary, use_working_directory


def test_get_connected_devices(data_dir):
    devices = TpDevSwModel.get_connected_devices({"config_file": f"{data_dir}/reader_config.yaml"})
    assert len(devices) == 2
    for device in devices:
        assert isinstance(device, TpIntfDescription)


def test_get_challenge(data_dir):
    cfg = TpIntfDescription(
        "card2",
        TpDevSwModel,
        description=".",
        settings={"config_file": f"{data_dir}/card2/config.yaml"},
    )
    device = TpDevSwModel(cfg)
    challenge_data = device.get_challenge()

    container = Container.parse(challenge_data)
    assert len(container._entries) == 1
    challenge_entries = container.get_entries(PayloadType.NXP_EPH_CHALLENGE_DATA_RND)
    assert len(challenge_entries) == 1
    assert len(challenge_entries[0].payload) == 16


def test_get_challenge_invalid_device(data_dir):
    cfg = TpIntfDescription(
        "card1",
        TpDevSwModel,
        description=".",
        settings={"config_file": f"{data_dir}/card1/config.yaml"},
    )
    device = TpDevSwModel(cfg)
    with pytest.raises(SPSDKTpError):
        device.get_challenge()


def test_auth_response(data_dir, tmpdir):
    src_dir = f"{data_dir}/card2"
    for file in os.listdir(src_dir):
        shutil.copy(f"{src_dir}/{file}", tmpdir)

    with use_working_directory(tmpdir):
        cfg = TpIntfDescription(
            "card2",
            TpDevSwModel,
            description=".",
            settings={"config_file": f"{tmpdir}/config.yaml"},
        )
        device = TpDevSwModel(cfg)
        # need to reuse edh keys for repeatability
        device.config.reuse_edh_keys = True

        challenge_data = load_binary(f"{data_dir}/challenge.bin")
        challenge_cont = Container.parse(challenge_data)

        device.challenge = challenge_cont.get_entry(
            payload_type=PayloadType.NXP_EPH_CHALLENGE_DATA_RND
        ).payload

        tp_response = load_binary(f"{data_dir}/tp_response.bin")

        prov_data = device.authenticate_response(tp_response)
        prov_container = Container.parse(prov_data)
        assert len(prov_container) > 2

        auth_entry = prov_container.get_entry(AuthenticationType.ECDSA_256)
        assert auth_entry


def test_auth_response_invalid_device(data_dir):
    cfg = TpIntfDescription(
        "card1",
        TpDevSwModel,
        description=".",
        settings={"config_file": f"{data_dir}/card1/config.yaml"},
    )
    device = TpDevSwModel(cfg)
    with pytest.raises(SPSDKTpError):
        device.authenticate_response(bytes(100))


def test_prepare(data_dir, tmpdir):
    shutil.copy(f"{data_dir}/card1/config.yaml", f"{tmpdir}/config.yaml")
    cfg = TpIntfDescription(
        "card1", TpDevSwModel, description=".", settings={"config_file": f"{tmpdir}/config.yaml"}
    )
    device = TpDevSwModel(cfg)
    assert not device.config.is_ready

    device.prepare()
    assert device.config.is_ready


def test_upload(data_dir, tmpdir):
    shutil.copy(f"{data_dir}/card2/config.yaml", f"{tmpdir}/config.yaml")
    cfg = TpIntfDescription(
        "card2", TpDevSwModel, description=".", settings={"config_file": f"{tmpdir}/config.yaml"}
    )
    device = TpDevSwModel(cfg)
    with open(f"{data_dir}/example_data.yaml") as f:
        config_data = yaml.safe_load(f)
    device.upload_manufacturing(config_data, data_dir)
    device.upload(config_data, data_dir)
    assert len(device.config.data) > 0
    assert len(os.listdir(tmpdir)) > 1
