#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Tests for Trust provisioning functionality."""
import shutil

from spsdk.tp.adapters import TpDevSwModel, TpTargetSwModel
from spsdk.tp.adapters.tpdev_model import TpDevSwModelConfig
from spsdk.tp.tphost import TrustProvisioningHost
from spsdk.utils.misc import use_working_directory


def test_basic_authentication(data_dir, tmpdir):
    """Test the basic authentication functionality. Test MUST pass without any exception."""
    dest_dir = f"{tmpdir}/data"
    # in Python 3.6 the destination folder MUST NOT exist, thus we need a subfolder
    shutil.copytree(data_dir, dest_dir)
    with use_working_directory(dest_dir):
        cfg = TpDevSwModelConfig(config_file=f"{dest_dir}/card1/config.yaml")
        tp_dev = TpDevSwModel(cfg)

        tp_target = TpTargetSwModel(
            TpTargetSwModel.get_connected_targets(
                {"config_file": f"{dest_dir}/target_config.yaml"}
            )[0]
        )
        tp_host = TrustProvisioningHost(tp_dev, tp_target, info_print=lambda x: None)
        tp_host.do_provisioning(family="lpc55s6x", audit_log="audit_log.yaml", timeout=0)
