#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

from spsdk.image.commands import CmdInstallKey, EnumAlgorithm, EnumCertFormat, EnumInsKey
from spsdk.image.segments import CmdNop


def test_install_key_cmd_base():
    cmd = CmdInstallKey()
    assert cmd.flags == EnumInsKey.CLR
    assert cmd.certificate_format == EnumCertFormat.SRK
    assert cmd.hash_algorithm == EnumAlgorithm.ANY
    assert cmd.source_index == 0
    assert cmd.target_index == 0
    assert cmd.cmd_data_location == 0
    assert cmd.size == 12

    cmd.flags = EnumInsKey.MID
    assert cmd._header.param == EnumInsKey.MID


def test_install_key_cmd_repr():
    cmd = CmdInstallKey()
    representation = repr(cmd)
    req_strings = ["CmdInstallKey"]
    for req_string in req_strings:
        assert (
            req_string in representation
        ), f"string {req_string} is not in the output: {representation}"


def test_install_key_cmd_equality():
    cmd = CmdInstallKey()
    nop = CmdNop()
    cmd_other = CmdInstallKey(flags=EnumInsKey.CID)

    assert cmd != nop
    assert cmd == cmd
    assert cmd != cmd_other


def test_install_key_cmd_export_parse():
    cmd = CmdInstallKey()
    data = cmd.export()
    assert len(data) == 12
    assert len(data) == cmd.size
    assert cmd == CmdInstallKey.parse(data)


def test_install_key_cmd_info():
    cmd = CmdInstallKey()
    output = str(cmd)
    req_strings = [
        'Command "Install Key',
        "Flag",
        "CertFormat",
        "Algorithm",
        "SrcKeyIdx",
        "TgtKeyIdx",
        "Location",
    ]

    for req_string in req_strings:
        assert req_string in output, f"string {req_string} is not in the output: {output}"
