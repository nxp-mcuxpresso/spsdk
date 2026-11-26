#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for the EdgeLock 2GO HTTP client."""

from unittest.mock import patch

import pytest
import requests

from spsdk.el2go.client import EL2GOClient
from spsdk.utils.http_client import SPSDKHTTPClientError


def _mock_response(status_code: int, reason: str, content: bytes) -> requests.Response:
    """Create a 'requests.Response' instance with given status, reason and body."""
    response = requests.Response()
    response.status_code = status_code
    response.reason = reason
    response._content = content
    response.url = "https://api.edgelock2go.com/test"
    return response


@pytest.mark.parametrize(
    "status_code,reason",
    [
        (401, "Unauthorized"),
        (404, "Not Found"),
        (422, "Unprocessable Entity"),
        (500, "Server Error"),
    ],
)
def test_handle_el2go_request_raises_for_json_error_response(status_code: int, reason: str) -> None:
    """Test that an EL2GO error with a valid JSON body still raises an SPSDK HTTP error.

    This is a regression test: previously the code only raised when the error response
    body failed to parse as JSON. A valid JSON error body (e.g. a standard EL2GO error
    payload) was incorrectly swallowed and a normal-looking response was returned instead.
    """
    response = _mock_response(status_code, reason, b'{"message": "' + reason.encode() + b'"}')

    client = EL2GOClient(api_key="ABCD")
    with patch.object(client.session, "request", return_value=response):
        with pytest.raises(SPSDKHTTPClientError) as exc_info:
            client._handle_el2go_request(client.Method.GET, "/test")

    assert exc_info.value.status_code == status_code
    assert exc_info.value.response == {"message": reason}


def test_handle_el2go_request_raises_for_non_json_error_response() -> None:
    """Test that an EL2GO error with a non-JSON body still raises an SPSDK HTTP error."""
    response = _mock_response(401, "Unauthorized", b"<html>Unauthorized</html>")

    client = EL2GOClient(api_key="ABCD")
    with patch.object(client.session, "request", return_value=response):
        with pytest.raises(SPSDKHTTPClientError) as exc_info:
            client._handle_el2go_request(client.Method.GET, "/test")

    assert exc_info.value.status_code == 401
    assert exc_info.value.response == {}


def test_handle_el2go_request_returns_error_response_when_exceptions_disabled() -> None:
    """Test that an EL2GO error response is returned (not raised) when exceptions are disabled."""
    response = _mock_response(401, "Unauthorized", b'{"message": "Unauthorized"}')

    client = EL2GOClient(api_key="ABCD", raise_exceptions=False)
    with patch.object(client.session, "request", return_value=response):
        result = client._handle_el2go_request(client.Method.GET, "/test")

    assert result.status_code == 401
    assert result.json_body == {"message": "Unauthorized"}


def test_handle_el2go_request_returns_non_json_error_response_when_exceptions_disabled() -> None:
    """Test that a non-JSON EL2GO error response is returned with an empty body when disabled."""
    response = _mock_response(401, "Unauthorized", b"<html>Unauthorized</html>")

    client = EL2GOClient(api_key="ABCD", raise_exceptions=False)
    with patch.object(client.session, "request", return_value=response):
        result = client._handle_el2go_request(client.Method.GET, "/test")

    assert result.status_code == 401
    assert result.json_body == {}


def test_handle_el2go_request_ok_response() -> None:
    """Test that a successful EL2GO response is returned as-is."""
    response = _mock_response(200, "OK", b'{"content": []}')

    client = EL2GOClient(api_key="ABCD")
    with patch.object(client.session, "request", return_value=response):
        result = client._handle_el2go_request(client.Method.GET, "/test")

    assert result.status_code == 200
    assert result.json_body == {"content": []}
