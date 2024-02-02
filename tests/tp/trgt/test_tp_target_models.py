#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import os
import shutil

import pytest

from spsdk.tp.adapters.tptarget_model import TpTargetSwModel
from spsdk.tp.data_container import Container, PayloadType
from spsdk.tp.data_container.data_container import DataEntry
from spsdk.tp.exceptions import SPSDKTpError
from spsdk.tp.tp_intf import TpIntfDescription
from spsdk.utils.misc import load_binary, use_working_directory


@pytest.fixture
def sample_challenge() -> bytes:
    challenge_container = Container()
    challenge_container.add_entry(
        DataEntry(
            payload=bytes(range(128)), payload_type=PayloadType.NXP_EPH_CHALLENGE_DATA_RND.tag
        )
    )
    return challenge_container.export()


def test_get_connected_targets(data_dir):
    devices = TpTargetSwModel.get_connected_targets(
        {"config_file": f"{data_dir}/target_config.yaml"}
    )
    assert len(devices) == 1
    for device in devices:
        assert isinstance(device, TpIntfDescription)


def test_prove_genuinity_set_data(data_dir, tmpdir):
    src_dir = f"{data_dir}/target1"
    for file in os.listdir(src_dir):
        shutil.copy(f"{src_dir}/{file}", tmpdir)

    with use_working_directory(tmpdir):
        config = TpIntfDescription(
            name="target1",
            intf=TpTargetSwModel,
            description=".",
            settings={"config_file": f"{tmpdir}/config.yaml"},
        )

        target = TpTargetSwModel(config)
        # need to reuse edh keys for repeatability
        target.config.reuse_edh_keys = True

        challenge = load_binary(f"{data_dir}/challenge.bin")
        challenge_bytes = (
            Container.parse(challenge)
            .get_entry(payload_type=PayloadType.NXP_EPH_CHALLENGE_DATA_RND)
            .payload
        )
        tp_response_data = target.prove_genuinity_challenge(challenge)

        tp_response = Container.parse(tp_response_data)
        challenge_entry = tp_response.get_entry(PayloadType.NXP_EPH_CHALLENGE_DATA_RND)
        assert challenge_entry.payload == challenge_bytes

        wrapped_data = load_binary(f"{data_dir}/wrap_data.bin")
        assert target.set_wrapped_data(wrapped_data) is None


def test_set_wrapped_data_invalid(data_dir, sample_challenge):
    device = TpTargetSwModel(
        TpTargetSwModel.get_connected_targets({"config_file": f"{data_dir}/target_config.yaml"})[0]
    )
    with pytest.raises(SPSDKTpError):
        device.set_wrapped_data(sample_challenge)


# def test_reset_load(data_dir):
#     device = TpTargetSwModel(
#         TpTargetSwModel.get_connected_targets({"config_file": f"{data_dir}/target_config.yaml"})[0]
#     )
#     device.config.is_ready = True
#     device.reset_device()
#     assert not device.config.is_ready
#     device.load_sb_file(bytes(10))
#     assert device.config.is_ready
