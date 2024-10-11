#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""ELE message tests."""
from spsdk.ele.ele_message import EleMessageGetInfo, EleMessageReadCommonFuse, EleMessageWriteFuse
from spsdk.utils.misc import value_to_bytes, value_to_int


def test_ele_write_fuse():
    msg = EleMessageWriteFuse(128 * 32, 32, False, 0x4E219CB1)
    assert msg.bit_length == 32
    assert msg.bit_position == 4096
    assert value_to_int(msg.export()) == 0x0603D61700102000B19C214E
    msg.decode_response(value_to_bytes(0x0603D6E1D600000080000000))
    assert msg.status == 0xD6
    assert msg.indication == 0
    assert msg.abort_code == 0
    assert msg.processed_idx == 128


def test_ele_read_fuse():
    msg = EleMessageReadCommonFuse(128)
    assert value_to_int(msg.export()) == 0x0602971780000000
    msg.decode_response(value_to_bytes(0x060397E1D6000000B19C214E))
    assert msg.indication == 0
    assert msg.status == 214
    assert msg.abort_code == 0


def test_ele_get_info():
    msg = EleMessageGetInfo()
    # Real response from MX93
    response_data = b"""\xda\x01\\\x00\x00\x93\x00\xa0\x10\x00\x04\x00\xf2\xa6\x01v\xff0DG\
        x9b\xf0g\x99s\xc6\x97\x91\x05c\xdbm\xf68\x8e\xc7\xf5\xb2\xbb\xa5!\
            x10\xbe\xbd\xfa\x03\x02\xb6\xe3\xa3\x94\x93\xe0<|\x9b\xe7\
                xab\x86\x86\xa5Bc\x13}\x893\xfa\xe8\x02\xab\x15}uZ\x84(\xef\xe1\xfaT\x7f\tM\xd5*{\xf7v=\
                    xa1\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                    x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                        x00\x00\x10\x00\x90\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                            x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                        x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                            x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                                x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                                    x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                                        x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                                    x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                                        x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"""
    msg.decode_response_data(response_data)
    assert msg.info_cmd == 0xDA
    assert msg.info_version == 1
    assert msg.info_length == 92
    assert msg.info_soc_id == 0x9300
