#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import os
from unittest.mock import MagicMock

import pytest

from spsdk.tp.data_container import AuditLog, AuditLogCounter, AuditLogRecord
from spsdk.tp.exceptions import SPSDKTpError
from spsdk.tp.tphost import TrustProvisioningHost


def test_validate(data_dir):
    log_file = f"{data_dir}/tp_audit_log.db"
    key_file = f"{data_dir}/oem_log_puk.pub"

    TrustProvisioningHost.verify_extract_log(
        audit_log=log_file, audit_log_key=key_file, info_print=lambda x: None
    )


def test_create(data_dir, tmpdir):
    log_file = f"{tmpdir}/audit_log.db"
    with open(f"{data_dir}/x_wrapped_data.bin", "rb") as f:
        container_data = f.read()

    assert not os.path.isfile(log_file)

    tp_dev = MagicMock()
    tp_dev.descriptor.get_id = MagicMock(return_value="fake-id")

    tp = TrustProvisioningHost(tpdev=tp_dev, tptarget=None, info_print=lambda x: None)
    tp.create_audit_log_record(data=container_data, audit_log=log_file)

    assert os.path.isfile(log_file)


def test_save_load(data_dir, tmpdir):
    with open(f"{data_dir}/x_wrapped_data.bin", "rb") as f:
        container_data = f.read()

    log_file = f"{tmpdir}/audit_log.db"

    record = AuditLogRecord.from_data(container_data)
    record.save(log_file, "fake-id")
    record.save(log_file, "fake-id")
    record.save(log_file, "fake-id")

    log = AuditLog.load(log_file)
    assert len(log) == 3
    # check if all records are the same
    assert log[0] == log[1] == log[2]


def test_get_properties(data_dir):
    prop = AuditLog.properties(f"{data_dir}/tp_audit_log.db")
    assert prop.tp_device_id == "1234"


def test_invalid_signature(data_dir, tmpdir):
    log = AuditLog.load(f"{data_dir}/tp_audit_log.db")
    # invalidate signature of first record
    log[0] = log[0]._replace(signature=bytes(64))

    new_log_file = f"{tmpdir}/audit_log.db"
    log.save(new_log_file, "fake-id")

    with pytest.raises(SPSDKTpError, match="signature"):
        TrustProvisioningHost.verify_extract_log(
            audit_log=new_log_file,
            audit_log_key=f"{data_dir}/oem_log_puk.pub",
            info_print=lambda x: None,
        )


def test_invalid_chain(data_dir, tmpdir):
    log = AuditLog.load(f"{data_dir}/tp_audit_log.db")
    # delete second record thus invalidate the chain
    del log[1]

    new_log_file = f"{tmpdir}/audit_log.db"
    log.save(new_log_file, "fake-id")

    with pytest.raises(SPSDKTpError, match="chain"):
        TrustProvisioningHost.verify_extract_log(
            audit_log=new_log_file,
            audit_log_key=f"{data_dir}/oem_log_puk.pub",
            info_print=lambda x: None,
        )


def test_tp_counter():
    c0 = AuditLogCounter()
    c1 = AuditLogCounter(check_count=1, nxp_count=2, oem_count=3)

    c2 = c0 + c1
    c0 += c1

    assert c2.check_count == 1
    assert c2.nxp_count == 2
    assert c2.oem_count == 3
    assert c0 == c2

    assert str(c1).count("1") == 1
    assert str(c1).count("2") == 1
    assert str(c1).count("3") == 1


def tets_tp_counter_partial_update():
    c0 = AuditLogCounter()
    c0.check_count = 1
    c1 = AuditLogCounter(oem_count=3)

    c0 += c1
    assert c0.check_count == 1
    assert c0.nxp_count == 0
    assert c0.oem_count == 3
