#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk.image.commands import CmdCheckData, CmdWriteData, EnumCheckOps, EnumWriteOps
from spsdk.image.segments import SegCSF


@pytest.fixture(scope="module")
def ref_csf_obj():
    # Prepare reference CSF object
    obj = SegCSF(enabled=True)
    obj.append_command(CmdWriteData(ops=EnumWriteOps.WRITE_VALUE, data=((0x30340004, 0x4F400005),)))
    obj.append_command(
        CmdCheckData(ops=EnumCheckOps.ALL_CLEAR, address=0x307900C4, mask=0x00000001, count=10)
    )
    return obj


@pytest.mark.skip
def test_txt_parser():
    pass


@pytest.mark.skip
def test_bin_parser():
    pass
