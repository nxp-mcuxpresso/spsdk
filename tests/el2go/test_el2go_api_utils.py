#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for spsdk/el2go/api_utils.py coverage."""

import base64
import os
import shutil
from typing import Any
from unittest.mock import patch

import pytest

from spsdk.el2go.api_utils import (
    BAD_STATES,
    NO_DATA_STATES,
    OK_STATES,
    WAIT_STATES,
    DispatchMethod,
    EL2GODomain,
    EL2GOTPClient,
    GenStatus,
    JobStatus,
    ProvisioningMethod,
)
from spsdk.el2go.client import EL2GOApiResponse
from spsdk.exceptions import SPSDKError
from spsdk.utils.config import Config
from spsdk.utils.misc import use_working_directory

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")


def _make_client(tmpdir: str) -> EL2GOTPClient:
    """Load an EL2GOTPClient from the standard test config."""
    work_dir = str(tmpdir)
    shutil.copytree(DATA_DIR, work_dir, dirs_exist_ok=True)
    with use_working_directory(work_dir):
        config_data = Config.create_from_file("test_config.yml")
        return EL2GOTPClient.load_from_config(config_data=config_data)


# ---------------------------------------------------------------------------
# Enum / constant tests
# ---------------------------------------------------------------------------


def test_gen_status_values() -> None:
    assert GenStatus.GENERATION_COMPLETED.value[0] == "GENERATION_COMPLETED"
    assert GenStatus.GENERATION_FAILED.value[0] == "GENERATION_FAILED"
    assert GenStatus.GENERATION_TRIGGERED.value[0] == "GENERATION_TRIGGERED"
    assert GenStatus.PROVISIONING_COMPLETED.value[0] == "PROVISIONING_COMPLETED"
    assert GenStatus.PROVISIONING_FAILED.value[0] == "PROVISIONING_FAILED"
    assert GenStatus.GENERATION_ON_CONNECTION.value[0] == "GENERATION_ON_CONNECTION"


def test_job_status_values() -> None:
    assert JobStatus.JOB_TRIGGERED.value[0] == "JOB_TRIGGERED"
    assert JobStatus.JOB_COMPLETED.value[0] == "JOB_COMPLETED"
    assert JobStatus.JOB_FAILED.value[0] == "JOB_FAILED"


def test_ok_states_contain_completed() -> None:
    assert "GENERATION_COMPLETED" in OK_STATES
    assert "JOB_COMPLETED" in OK_STATES
    assert "PROVISIONING_COMPLETED" in OK_STATES


def test_bad_states_contain_failed() -> None:
    assert "GENERATION_FAILED" in BAD_STATES
    assert "PROVISIONING_FAILED" in BAD_STATES
    assert "JOB_FAILED" in BAD_STATES


def test_wait_states_contain_triggered() -> None:
    assert "GENERATION_TRIGGERED" in WAIT_STATES
    assert "JOB_TRIGGERED" in WAIT_STATES
    assert "JOB_PROCESSING" in WAIT_STATES


def test_no_data_states() -> None:
    assert "GENERATION_ON_CONNECTION" in NO_DATA_STATES


def test_provisioning_method_enum() -> None:
    assert ProvisioningMethod.DISPATCH_FW == "dispatch_fw"
    assert ProvisioningMethod.FW_USER_CONFIG == "fw_user_config"
    assert ProvisioningMethod.FW_DATA_SPLIT == "fw_data_split"
    assert ProvisioningMethod.OEM_APP == "oem_app"


def test_dispatch_method_enum() -> None:
    assert DispatchMethod.WRITE_RESET == "write_reset"
    assert DispatchMethod.NONE == "none"


def test_el2go_domain_enum() -> None:
    assert EL2GODomain.MATTER == "MATTER"
    assert EL2GODomain.RTP == "RTP"


# ---------------------------------------------------------------------------
# calculate_jobs (classmethod – no instance needed)
# ---------------------------------------------------------------------------


def test_calculate_jobs_exact_fit() -> None:
    result = EL2GOTPClient.calculate_jobs(500, max_job_size=500)
    assert result == [500]


def test_calculate_jobs_two_jobs() -> None:
    result = EL2GOTPClient.calculate_jobs(600, max_job_size=500)
    assert len(result) == 2
    assert sum(result) == 600


def test_calculate_jobs_remainder_distributed() -> None:
    result = EL2GOTPClient.calculate_jobs(999, max_job_size=500)
    assert len(result) == 2
    assert sum(result) == 999
    # sizes should differ by at most 1
    assert abs(result[0] - result[1]) <= 1


def test_calculate_jobs_single_device() -> None:
    result = EL2GOTPClient.calculate_jobs(1, max_job_size=500)
    assert result == [1]


def test_calculate_jobs_large() -> None:
    result = EL2GOTPClient.calculate_jobs(1500, max_job_size=500)
    assert len(result) == 3
    assert sum(result) == 1500


# ---------------------------------------------------------------------------
# split_uuids_to_jobs (classmethod – no instance needed)
# ---------------------------------------------------------------------------


def test_split_uuids_to_jobs_single_job() -> None:
    uuids = [str(i) for i in range(5)]
    jobs = EL2GOTPClient.split_uuids_to_jobs(uuids, max_job_size=10)
    assert len(jobs) == 1
    assert jobs[0] == uuids


def test_split_uuids_to_jobs_two_jobs() -> None:
    uuids = [str(i) for i in range(600)]
    jobs = EL2GOTPClient.split_uuids_to_jobs(uuids, max_job_size=500)
    assert len(jobs) == 2
    assert sum(len(j) for j in jobs) == 600


def test_split_uuids_to_jobs_all_items_preserved() -> None:
    uuids = [f"uuid-{i}" for i in range(750)]
    jobs = EL2GOTPClient.split_uuids_to_jobs(uuids, max_job_size=500)
    flat = [u for job in jobs for u in job]
    assert flat == uuids


# ---------------------------------------------------------------------------
# _make_device_id_list (instance method, needs client)
# ---------------------------------------------------------------------------


def test_make_device_id_list_string(tmpdir: Any) -> None:
    client = _make_client(tmpdir)
    result = client._make_device_id_list("device-001")
    assert result == ["device-001"]


def test_make_device_id_list_already_list(tmpdir: Any) -> None:
    client = _make_client(tmpdir)
    ids = ["dev-001", "dev-002"]
    result = client._make_device_id_list(ids)
    assert result == ids


# ---------------------------------------------------------------------------
# _sanitize_domains
# ---------------------------------------------------------------------------


def test_sanitize_domains_valid(tmpdir: Any) -> None:
    client = _make_client(tmpdir)
    result = client._sanitize_domains(["rtp", "matter"])
    assert "RTP" in result
    assert "MATTER" in result


def test_sanitize_domains_invalid_raises(tmpdir: Any) -> None:
    client = _make_client(tmpdir)
    with pytest.raises(SPSDKError):
        client._sanitize_domains(["invalid_domain"])


def test_sanitize_domains_not_list_raises(tmpdir: Any) -> None:
    client = _make_client(tmpdir)
    with pytest.raises(SPSDKError):
        client._sanitize_domains("RTP")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# serialize_provisionings / _serialize_single_provisioning
# ---------------------------------------------------------------------------


def test_serialize_provisionings_empty(tmpdir: Any) -> None:
    client = _make_client(tmpdir)
    result = client.serialize_provisionings([])  # type: ignore[arg-type]
    assert result == b""


def test_serialize_single_generation_completed(tmpdir: Any) -> None:
    client = _make_client(tmpdir)
    apdu_bytes = b"\x01\x02\x03\x04"
    provisioning = {
        "rtpProvisionings": [
            {
                "state": GenStatus.GENERATION_COMPLETED.value[0],
                "provisioningId": "prov-001",
                "apdus": {"createApdu": {"apdu": base64.b64encode(apdu_bytes).decode()}},
            }
        ]
    }
    result = client._serialize_single_provisioning(provisioning)
    assert result == apdu_bytes


def test_serialize_single_provisioning_completed(tmpdir: Any) -> None:
    client = _make_client(tmpdir)
    apdu_bytes = b"\xde\xad\xbe\xef"
    provisioning = {
        "rtpProvisionings": [
            {
                "state": GenStatus.PROVISIONING_COMPLETED.value[0],
                "provisioningId": "prov-002",
                "apdus": {"createApdu": {"apdu": base64.b64encode(apdu_bytes).decode()}},
            }
        ]
    }
    result = client._serialize_single_provisioning(provisioning)
    assert result == apdu_bytes


def test_serialize_single_on_connection_no_data(tmpdir: Any) -> None:
    client = _make_client(tmpdir)
    provisioning = {
        "rtpProvisionings": [
            {
                "state": GenStatus.GENERATION_ON_CONNECTION.value[0],
                "provisioningId": "prov-003",
            }
        ]
    }
    result = client._serialize_single_provisioning(provisioning)
    assert result == b""


def test_serialize_multiple_provisionings(tmpdir: Any) -> None:
    client = _make_client(tmpdir)
    apdu1 = b"\x01\x02"
    apdu2 = b"\x03\x04"
    provisionings = [
        {
            "rtpProvisionings": [
                {
                    "state": GenStatus.GENERATION_COMPLETED.value[0],
                    "provisioningId": "prov-001",
                    "apdus": {"createApdu": {"apdu": base64.b64encode(apdu1).decode()}},
                }
            ]
        },
        {
            "rtpProvisionings": [
                {
                    "state": GenStatus.GENERATION_COMPLETED.value[0],
                    "provisioningId": "prov-002",
                    "apdus": {"createApdu": {"apdu": base64.b64encode(apdu2).decode()}},
                }
            ]
        },
    ]
    result = client.serialize_provisionings(provisionings)  # type: ignore[arg-type]
    assert result == apdu1 + apdu2


# ---------------------------------------------------------------------------
# response_handling
# ---------------------------------------------------------------------------


def test_response_handling_ok(tmpdir: Any) -> None:
    client = _make_client(tmpdir)
    client.headers["EL2G-Correlation-ID"] = "test-id"
    response = EL2GOApiResponse(status_code=200, json_body={})
    # should not raise
    client.response_handling(response, "/some/url")


def test_response_handling_error_raises(tmpdir: Any) -> None:
    from spsdk.el2go.client import SPSDKHTTPClientError

    client = _make_client(tmpdir)
    client.headers["EL2G-Correlation-ID"] = "test-id"
    response = EL2GOApiResponse(status_code=404, json_body={"error": "not found"})
    with pytest.raises(SPSDKHTTPClientError):
        client.response_handling(response, "/some/url")


def test_response_handling_500_raises(tmpdir: Any) -> None:
    from spsdk.el2go.client import SPSDKHTTPClientError

    client = _make_client(tmpdir)
    client.headers["EL2G-Correlation-ID"] = "test-id"
    response = EL2GOApiResponse(status_code=500, json_body={"error": "server error"})
    with pytest.raises(SPSDKHTTPClientError):
        client.response_handling(response, "/api/test")


# ---------------------------------------------------------------------------
# get_generation_status
# ---------------------------------------------------------------------------


def test_get_generation_status_empty_content_returns_wait(tmpdir: Any) -> None:
    client = _make_client(tmpdir)
    client.headers["EL2G-Correlation-ID"] = "test-id"
    mock_response = EL2GOApiResponse(status_code=200, json_body={"content": []})
    with patch.object(client, "_handle_el2go_request", return_value=mock_response):
        status = client.get_generation_status("some-device")
    assert status in WAIT_STATES


def test_get_generation_status_completed_returns_ok(tmpdir: Any) -> None:
    client = _make_client(tmpdir)
    client.headers["EL2G-Correlation-ID"] = "test-id"
    mock_response = EL2GOApiResponse(
        status_code=200,
        json_body={"content": [{"provisioningState": "GENERATION_COMPLETED"}]},
    )
    with patch.object(client, "_handle_el2go_request", return_value=mock_response):
        status = client.get_generation_status("some-device")
    assert status in OK_STATES


def test_get_generation_status_triggered_returns_wait(tmpdir: Any) -> None:
    client = _make_client(tmpdir)
    client.headers["EL2G-Correlation-ID"] = "test-id"
    mock_response = EL2GOApiResponse(
        status_code=200,
        json_body={"content": [{"provisioningState": "GENERATION_TRIGGERED"}]},
    )
    with patch.object(client, "_handle_el2go_request", return_value=mock_response):
        status = client.get_generation_status("some-device")
    assert status in WAIT_STATES


def test_get_generation_status_failed_raises(tmpdir: Any) -> None:
    client = _make_client(tmpdir)
    client.headers["EL2G-Correlation-ID"] = "test-id"
    mock_response = EL2GOApiResponse(
        status_code=200,
        json_body={"content": [{"provisioningState": "GENERATION_FAILED"}]},
    )
    with patch.object(client, "_handle_el2go_request", return_value=mock_response):
        with pytest.raises(SPSDKError):
            client.get_generation_status("some-device")


# ---------------------------------------------------------------------------
# use_* properties
# ---------------------------------------------------------------------------


def test_use_dispatch_fw_property(tmpdir: Any) -> None:
    client = _make_client(tmpdir)
    # rw61x uses dispatch_fw provisioning method per database
    assert isinstance(client.use_dispatch_fw, bool)


def test_use_data_split_property(tmpdir: Any) -> None:
    client = _make_client(tmpdir)
    assert isinstance(client.use_data_split, bool)


def test_use_user_config_property(tmpdir: Any) -> None:
    client = _make_client(tmpdir)
    assert isinstance(client.use_user_config, bool)


def test_use_oem_app_property(tmpdir: Any) -> None:
    client = _make_client(tmpdir)
    assert isinstance(client.use_oem_app, bool)


def test_use_dispatch_reset_property(tmpdir: Any) -> None:
    client = _make_client(tmpdir)
    assert isinstance(client.use_dispatch_reset, bool)


def test_use_dispatch_write_property(tmpdir: Any) -> None:
    client = _make_client(tmpdir)
    assert isinstance(client.use_dispatch_write, bool)


def test_use_dispatch_sb_file_property(tmpdir: Any) -> None:
    client = _make_client(tmpdir)
    assert isinstance(client.use_dispatch_sb_file, bool)


# ---------------------------------------------------------------------------
# oem_provisioning_config_path / oem_provisioning_config_filename separation
# ---------------------------------------------------------------------------


def _make_client_with_oem_config(tmpdir: Any, extra_config: dict) -> EL2GOTPClient:
    """Load client with additional OEM provisioning config keys merged in."""
    work_dir = str(tmpdir)
    shutil.copytree(DATA_DIR, work_dir, dirs_exist_ok=True)
    with use_working_directory(work_dir):
        config_data = Config.create_from_file("test_config.yml")
        config_data.update(extra_config)
        return EL2GOTPClient.load_from_config(config_data=config_data)


def test_oem_provisioning_config_not_set(tmpdir: Any) -> None:
    """When neither OEM config key is set, filename and binary are None/empty."""
    client = _make_client(tmpdir)
    assert client.oem_provisioning_config_filename is None
    assert client.oem_provisioning_config_bin == b""


def test_oem_provisioning_config_new_path(tmpdir: Any) -> None:
    """New oem_provisioning_config_path sets bin and derives filename from basename."""
    work_dir = str(tmpdir)
    shutil.copytree(DATA_DIR, work_dir, dirs_exist_ok=True)
    config_file = os.path.join(work_dir, "oem_conf.yaml")
    with open(config_file, "wb") as f:
        f.write(b"oem: data")
    with use_working_directory(work_dir):
        config_data = Config.create_from_file("test_config.yml")
        config_data["oem_provisioning_config_path"] = "oem_conf.yaml"
        client = EL2GOTPClient.load_from_config(config_data=config_data)
    assert client.oem_provisioning_config_filename == "oem_conf.yaml"
    assert client.oem_provisioning_config_bin == b"oem: data"


def test_oem_provisioning_config_path_with_explicit_filename(tmpdir: Any) -> None:
    """When both path and filename are set, the explicit filename is used on device."""
    work_dir = str(tmpdir)
    shutil.copytree(DATA_DIR, work_dir, dirs_exist_ok=True)
    config_file = os.path.join(work_dir, "oem_conf.yaml")
    with open(config_file, "wb") as f:
        f.write(b"oem: data")
    with use_working_directory(work_dir):
        config_data = Config.create_from_file("test_config.yml")
        config_data["oem_provisioning_config_path"] = "oem_conf.yaml"
        config_data["oem_provisioning_config_filename"] = "my_device_name.yaml"
        client = EL2GOTPClient.load_from_config(config_data=config_data)
    assert client.oem_provisioning_config_filename == "my_device_name.yaml"
    assert client.oem_provisioning_config_bin == b"oem: data"


def test_oem_provisioning_config_path_basename_extracted(tmpdir: Any) -> None:
    """Basename of an absolute path is used as device filename when no explicit name."""
    work_dir = str(tmpdir)
    shutil.copytree(DATA_DIR, work_dir, dirs_exist_ok=True)
    config_file = os.path.join(work_dir, "subdir", "oem_conf.yaml")
    os.makedirs(os.path.dirname(config_file), exist_ok=True)
    with open(config_file, "wb") as f:
        f.write(b"nested: config")
    with use_working_directory(work_dir):
        config_data = Config.create_from_file("test_config.yml")
        config_data["oem_provisioning_config_path"] = os.path.join("subdir", "oem_conf.yaml")
        client = EL2GOTPClient.load_from_config(config_data=config_data)
    assert client.oem_provisioning_config_filename == "oem_conf.yaml"
    assert client.oem_provisioning_config_bin == b"nested: config"


def test_oem_provisioning_config_backward_compat_deprecated(tmpdir: Any) -> None:
    """Old configs using oem_provisioning_config_filename as host path still work with warning."""
    work_dir = str(tmpdir)
    shutil.copytree(DATA_DIR, work_dir, dirs_exist_ok=True)
    config_file = os.path.join(work_dir, "config.yaml")
    with open(config_file, "wb") as f:
        f.write(b"legacy: config")
    with use_working_directory(work_dir):
        config_data = Config.create_from_file("test_config.yml")
        config_data["oem_provisioning_config_filename"] = "config.yaml"
        client = EL2GOTPClient.load_from_config(config_data=config_data)
    # Backward compat: basename of old value used as device filename
    assert client.oem_provisioning_config_filename == "config.yaml"
    assert client.oem_provisioning_config_bin == b"legacy: config"


def test_oem_provisioning_config_backward_compat_path_stripped(tmpdir: Any) -> None:
    """Old config with a path in oem_provisioning_config_filename: device name = basename only."""
    work_dir = str(tmpdir)
    shutil.copytree(DATA_DIR, work_dir, dirs_exist_ok=True)
    subdir = os.path.join(work_dir, "configs")
    os.makedirs(subdir, exist_ok=True)
    config_file = os.path.join(subdir, "my_config.yaml")
    with open(config_file, "wb") as f:
        f.write(b"old: style")
    with use_working_directory(work_dir):
        config_data = Config.create_from_file("test_config.yml")
        config_data["oem_provisioning_config_filename"] = os.path.join("configs", "my_config.yaml")
        client = EL2GOTPClient.load_from_config(config_data=config_data)
    # Device filename must be just the basename, not the full path
    assert client.oem_provisioning_config_filename == "my_config.yaml"
    assert client.oem_provisioning_config_bin == b"old: style"
