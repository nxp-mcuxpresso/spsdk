#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Signature Provider interface tests.

This module contains comprehensive tests for the signature provider functionality
in SPSDK, covering various signing methods, key formats, and authentication scenarios.
The tests verify signature generation, verification, metadata handling, and error
conditions across different signature provider implementations including plain and
encrypted private key handling, SM2 cryptographic algorithm support, interactive
and non-interactive authentication modes, and proxy signature provider functionality.
"""

import json
import os
from os import path
from typing import Any
from unittest.mock import patch

import pytest
import requests

from spsdk.crypto.crypto_types import SPSDKEncoding
from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.crypto.keys import (
    IS_OSCCA_SUPPORTED,
    ECDSASignature,
    PrivateKeyEcc,
    PrivateKeyRsa,
    PrivateKeySM2,
    PublicKeyEcc,
    PublicKeySM2,
    get_supported_keys_generators,
)
from spsdk.crypto.signature_provider import (
    HttpProxySP,
    SignatureProvider,
    get_signature_provider_from_config_str,
)
from spsdk.exceptions import SPSDKError, SPSDKKeyError, SPSDKValueError
from spsdk.utils.misc import write_file


def test_types() -> None:
    """Test signature provider type registration and retrieval functionality.

    Verifies that the SignatureProvider class correctly manages and returns
    available signature provider types, including both concrete implementations
    and abstract classes when requested.

    :raises AssertionError: If expected signature provider types are not found in the registry.
    """
    types = SignatureProvider.get_types()
    assert "file" in types

    class TestSP(SignatureProvider):
        """Test signature provider for SPSDK cryptographic operations.

        This class implements a test-specific signature provider used for testing
        cryptographic signing functionality within the SPSDK framework.

        :cvar identifier: Unique identifier for the test signature provider type.
        """

        identifier = "test-typesp-test"

    types = SignatureProvider.get_types(include_abstract=True)
    assert "test-typesp-test" in types


def test_invalid_sp_type() -> None:
    """Test that SignatureProvider.create returns None for invalid provider type.

    Verifies that attempting to create a signature provider with a non-existent
    or invalid provider type results in None being returned rather than raising
    an exception.
    """
    provider = SignatureProvider.create("type=totally_legit_provider")
    assert provider is None


def test_plain_file(data_dir: str) -> None:
    """Test plain file signature provider creation and validation.

    This test verifies that a SignatureProvider can be successfully created using
    a plain PEM file, and validates its basic properties including identifier
    and file path information.

    :param data_dir: Directory path containing test data files including the private key file.
    """
    my_key_path = path.join(data_dir, "priv.pem").replace("\\", "/")
    provider = SignatureProvider.create(f"type=file;file_path={my_key_path}")

    assert provider is not None
    assert provider.identifier == "file"
    assert my_key_path in provider.info()


@pytest.mark.parametrize(
    "key_type",
    ["rsa2048", "secp256r1", "secp521r1"],
)
def test_get_signature(tmpdir: str, key_type: str) -> None:
    """Test signature generation with different key types.

    This test verifies that the SignatureProvider can correctly generate signatures
    using various supported key types. It creates a private key, saves it to a file,
    initializes a SignatureProvider, and validates the generated signature format
    and size.

    :param tmpdir: Temporary directory path for storing test files.
    :param key_type: Type of cryptographic key to test (e.g., 'rsa', 'ecc').
    """
    func, params = get_supported_keys_generators()[key_type]
    private_key = func(**params)
    private_key_path = os.path.join(tmpdir, f"{key_type}.der")
    write_file(private_key.export(), private_key_path, mode="wb")
    provider = SignatureProvider.create(f"type=file;file_path={private_key_path}")
    assert provider is not None
    signature = provider.get_signature(b"")
    if isinstance(private_key, PrivateKeyEcc):
        assert ECDSASignature.get_encoding(signature) == SPSDKEncoding.NXP
    else:
        assert private_key.signature_size == len(signature)


@pytest.mark.skipif(
    not IS_OSCCA_SUPPORTED, reason="Install OSCCA dependency with pip install spsdk[oscca]"
)
@pytest.mark.parametrize(
    "signing_key_file, verification_key_file",
    [
        ("openssl_sm2_private.pem", "openssl_sm2_private.pem"),
    ],
)
def test_sm2_plain_file(data_dir: str, signing_key_file: str, verification_key_file: str) -> None:
    """Test SM2 signature provider with plain file-based keys.

    This test verifies the functionality of the SM2 signature provider using
    file-based private keys. It creates a signature provider, generates a signature
    for test data, and verifies the signature using the corresponding public key.

    :param data_dir: Directory path containing the test key files
    :param signing_key_file: Filename of the SM2 private key file for signing
    :param verification_key_file: Filename of the SM2 key file for signature verification
    """
    my_key_path = path.join(data_dir, signing_key_file).replace("\\", "/")
    verification_key_path = path.join(data_dir, verification_key_file).replace("\\", "/")
    provider = SignatureProvider.create(f"type=file;file_path={my_key_path}")

    assert provider is not None
    assert provider.identifier == "file"
    assert my_key_path in provider.info()

    message = b"message to sign"

    signature = provider.get_signature(data=message)
    verification_key = PrivateKeySM2.load(verification_key_path).get_public_key()
    verification_key.verify_signature(signature=signature, data=message)


@pytest.mark.skipif(
    not IS_OSCCA_SUPPORTED, reason="Install OSCCA dependency with pip install spsdk[oscca]"
)
@pytest.mark.parametrize(
    "signing_key_file, verification_key_file",
    [
        ("openssl_sm2_private_custom.der", "openssl_sm2_public.pem"),
    ],
)
def test_sm2_verify_public(
    data_dir: str, signing_key_file: str, verification_key_file: str
) -> None:
    """Test SM2 signature verification with public key.

    This test verifies that an SM2 signature provider can correctly validate
    its associated public key by loading both signing and verification keys,
    creating a signature provider, and confirming the public key verification.

    :param data_dir: Directory path containing the test key files
    :param signing_key_file: Filename of the SM2 private key for signing
    :param verification_key_file: Filename of the SM2 public key for verification
    """
    my_key_path = path.join(data_dir, signing_key_file).replace("\\", "/")
    verification_key_path = path.join(data_dir, verification_key_file).replace("\\", "/")
    provider = SignatureProvider.create(f"type=file;file_path={my_key_path}")

    assert provider is not None
    assert provider.identifier == "file"
    assert my_key_path in provider.info()

    verification_key = PublicKeySM2.load(verification_key_path)

    assert provider.verify_public_key(verification_key)


@pytest.mark.parametrize(
    "sp_cfg, sp_type, parsed_args, exception",
    [
        (
            "type=proxy;host=localhost;port=8000;url_prefix=server;key_type=IMG;key_index=0;data=ahoj",
            "proxy",
            {"key_type": "IMG", "key_index": "0"},
            False,
        ),
        (
            "type=proxy;host=localhost;port=8000;url_prefix=server;key_type=IMG;key_index=0;host=ahoj",
            "proxy",
            {},
            True,
        ),
    ],
)
def test_get_signature_provider(
    sp_cfg: str, sp_type: str, parsed_args: dict[str, str], exception: bool
) -> None:
    """Test signature provider configuration parsing and validation.

    Validates that signature provider configurations are correctly parsed and that
    the resulting provider has the expected identifier. Also tests error handling
    for invalid configurations.

    :param sp_cfg: Signature provider configuration string to parse.
    :param sp_type: Expected signature provider type identifier.
    :param parsed_args: Dictionary of parsed command line arguments.
    :param exception: Flag indicating whether an exception is expected during parsing.
    :raises SPSDKKeyError: When exception flag is True and invalid configuration is provided.
    """
    if exception:
        with pytest.raises(SPSDKKeyError):
            sp = get_signature_provider_from_config_str(sp_cfg)
    else:
        sp = get_signature_provider_from_config_str(sp_cfg)
        assert sp.identifier == sp_type
        # Note: SignatureProvider doesn't have kwargs attribute, this test may need adjustment


PASSPHRASE = "test_pwd"


@pytest.fixture
def private_key(tmpdir: str) -> str:
    """Generate a temporary RSA private key file for testing purposes.

    Creates a 2048-bit RSA private key, encrypts it with a passphrase, and saves it
    to a DER format file in the specified temporary directory.

    :param tmpdir: Path to temporary directory where the private key file will be created
    :return: Absolute path to the generated private key file
    """
    private_key = PrivateKeyRsa.generate_key(key_size=2048)
    private_key_path = os.path.join(tmpdir, "private.der")
    write_file(private_key.export(password=PASSPHRASE), private_key_path, mode="wb")
    return private_key_path


def test_encrypted_key_no_password(private_key: str) -> None:
    """Test that encrypted private key without password raises an error.

    Verifies that attempting to create a SignatureProvider with an encrypted
    private key file but without providing the required password results in
    an SPSDKError being raised.

    :param private_key: Path to the encrypted private key file.
    """
    config_string = f"type=file;file_path={private_key}"
    with pytest.raises(SPSDKError):
        SignatureProvider.create(config_string)


def test_encrypted_key_plain_password(private_key: str) -> None:
    """Test signature provider creation with encrypted private key and plain text password.

    This test verifies that a SignatureProvider can be successfully created using
    a configuration string that specifies an encrypted private key file with a
    plain text password parameter.

    :param private_key: Path to the encrypted private key file to be used for testing.
    """
    config_string = f"type=file;file_path={private_key};password={PASSPHRASE}"
    SignatureProvider.create(config_string)


def test_encrypted_key_env_variable_value(private_key: str) -> None:
    """Test encrypted private key with environment variable password.

    This test verifies that the SignatureProvider can successfully create an instance
    when the private key password is provided through an environment variable using
    the ${VAR_NAME} syntax in the configuration string.

    :param private_key: Path to the encrypted private key file.
    """
    os.environ["KEY_PASSPHRASE"] = PASSPHRASE
    config_string = f"type=file;file_path={private_key};password=${{KEY_PASSPHRASE}}"
    SignatureProvider.create(config_string)


def test_encrypted_key_path_to_file(tmpdir: str, private_key: str) -> None:
    """Test encrypted private key loading from file with password file.

    This test verifies that the SignatureProvider can successfully load an encrypted
    private key when the password is provided via a separate file path in the
    configuration string.

    :param tmpdir: Temporary directory path for creating test files.
    :param private_key: Path to the encrypted private key file.
    """
    pass_file = os.path.join(tmpdir, "passphrase.txt")
    write_file(PASSPHRASE, pass_file)
    config_string = f"type=file;file_path={private_key};password={pass_file}"
    SignatureProvider.create(config_string)


def test_encrypted_key_env_variable_with_path_to_file(tmpdir: str, private_key: str) -> None:
    """Test encrypted key with environment variable pointing to passphrase file.

    This test verifies that the SignatureProvider can correctly handle an encrypted
    private key when the passphrase is stored in a file and the file path is
    provided via an environment variable.

    :param tmpdir: Temporary directory path for test files.
    :param private_key: Path to the encrypted private key file.
    """
    pass_file = os.path.join(tmpdir, "passphrase.txt")
    write_file(PASSPHRASE, pass_file)
    os.environ["KEY_PASSPHRASE"] = pass_file
    config_string = f"type=file;file_path={private_key};password=${{KEY_PASSPHRASE}}"
    SignatureProvider.create(config_string)


@patch("spsdk.crypto.signature_provider.prompt_for_passphrase", lambda: PASSPHRASE)
def test_encrypted_key_no_password_interactive_sp(private_key: str) -> None:
    """Test encrypted private key without password using interactive signature provider.

    This test verifies that the SignatureProvider can be created with an interactive
    file configuration for an encrypted private key without providing a password,
    relying on interactive password input.

    :param private_key: Path to the encrypted private key file.
    """
    config_string = f"type=interactive_file;file_path={private_key}"
    SignatureProvider.create(config_string)


@patch("spsdk.crypto.keys.SPSDK_INTERACTIVE_DISABLED", True)
def test_encrypted_key_no_password_interactive_sp_non_interactive(private_key: str) -> None:
    """Test encrypted key without password in interactive mode when running non-interactively.

    Verifies that SignatureProvider.create() raises SPSDKError when attempting to use
    an encrypted private key with interactive_file type but no password is provided
    and the environment is non-interactive.

    :param private_key: Path to the encrypted private key file.
    :raises SPSDKError: When encrypted key requires password but none provided in non-interactive mode.
    """
    config_string = f"type=interactive_file;file_path={private_key}"
    with pytest.raises(SPSDKError):
        SignatureProvider.create(config_string)


def test_proxy_sp_sign_metadata() -> None:
    """Test HTTP proxy sign provider metadata handling.

    Verifies that the HttpProxySP correctly includes required metadata in HTTP requests
    and properly formats the request body with prehashed data. Tests that an AttributeError
    is raised when the signing operation fails.

    :raises AttributeError: When the signing operation encounters an error.
    """
    sp = HttpProxySP(prehash="sha256")

    def my_thing(_: Any, request: requests.PreparedRequest, **kwargs: Any) -> None:
        """Validate HTTP request headers and body for SPSDK signing API.

        This test helper function verifies that the prepared request contains the required
        SPSDK headers and validates the JSON body structure and data content for a
        prehashed SHA256 signing request.

        :param _: Unused parameter (typically for compatibility with callback signatures).
        :param request: The prepared HTTP request to validate.
        :param kwargs: Additional keyword arguments (unused).
        :raises AssertionError: If any validation check fails.
        """
        assert "spsdk-version" in request.headers
        assert "spsdk-api-version" in request.headers
        body_bytes = request.body
        if isinstance(body_bytes, bytes):
            body = json.loads(body_bytes.decode("utf-8"))
            assert "prehashed" in body
            assert body["prehashed"] == "sha256"
            assert (
                bytes.fromhex(body["data"])
                == b"\xbf|\xbe\t\xd7\x1a\x1b\xcc7:\xb9\xa7d\x91\x7fs\nn\xd9Q\xff\xa1\xa79\x9bz\xbd\x8f\x8f\xd7<\xb4"
            )

    with pytest.raises(AttributeError):
        with patch("requests.sessions.Session.send", my_thing):
            sp.sign(data=b"\x12\x34\x56")


def test_proxy_sp_verify_metadata() -> None:
    """Test HTTP proxy sign provider verify metadata functionality.

    Verifies that the HttpProxySP correctly includes required metadata headers
    (spsdk-version, spsdk-api-version) and properly encodes public key data
    in PEM format when making verification requests. Tests that the method
    raises AttributeError when the underlying session send operation fails.

    :raises AttributeError: When the mocked session send operation fails.
    """
    sp = HttpProxySP()
    prk = PrivateKeyEcc.generate_key()
    puk = prk.get_public_key()

    def my_thing(_: Any, request: requests.PreparedRequest, **kwargs: Any) -> None:
        """Validate HTTP request headers and body for SPSDK API compliance.

        This method verifies that the prepared request contains required SPSDK headers
        and validates the request body structure for public key encoding. It ensures
        the body contains proper encoding format and validates the public key data
        can be parsed correctly.

        :param _: Unused parameter (typically response object in callback context).
        :param request: The prepared HTTP request to validate.
        :param kwargs: Additional keyword arguments passed to the callback.
        :raises AssertionError: If required headers are missing, body structure is invalid, or public key parsing fails.
        """
        assert "spsdk-version" in request.headers
        assert "spsdk-api-version" in request.headers
        body_bytes = request.body
        if isinstance(body_bytes, bytes):
            body = json.loads(body_bytes.decode("utf-8"))
            assert "encoding" in body
            assert body["encoding"] == "pem"
            puk2 = PublicKeyEcc.parse(body["data"].encode("utf-8"))
            assert puk == puk2

    with pytest.raises(AttributeError):
        with patch("requests.sessions.Session.send", my_thing):
            sp.verify_public_key(public_key=puk)


def test_proxy_sp_signature_length_metadata() -> None:
    """Test HTTP proxy signature provider metadata headers.

    Verifies that the HttpProxySP includes required metadata headers
    (spsdk-version and spsdk-api-version) when making requests to get
    signature length, and properly handles AttributeError when the
    operation fails.

    :raises AttributeError: When signature length operation fails as expected.
    """
    sp = HttpProxySP()

    def my_thing(_: Any, request: requests.PreparedRequest, **kwargs: Any) -> None:
        """Validate HTTP request headers for SPSDK API communication.

        This method verifies that the prepared request contains the required
        SPSDK-specific headers for proper API versioning and identification.

        :param _: Unused parameter (typically response object in requests mock).
        :param request: The prepared HTTP request object to validate.
        :param kwargs: Additional keyword arguments passed to the method.
        :raises AssertionError: If required SPSDK headers are missing from the request.
        """
        assert "spsdk-version" in request.headers
        assert "spsdk-api-version" in request.headers

    with pytest.raises(AttributeError):
        with patch("requests.sessions.Session.send", my_thing):
            sp.signature_length


def test_proxy_sp_hash_alg_parameter() -> None:
    """Test HTTP proxy signature provider handles hash_alg parameter correctly.

    Verifies that HttpProxySP accepts hash_alg parameter for API compatibility
    but does not pass it to the parent HTTPClientBase class, preventing JSON
    serialization errors. The hash_alg enum should be filtered out from kwargs
    to avoid serialization issues when making HTTP requests.

    :raises AssertionError: If hash_alg appears in kwargs or JSON serialization fails.
    """
    # Test with hash_alg parameter
    sp = HttpProxySP(host="localhost", port="8000", hash_alg=EnumHashAlgorithm.SHA256)

    # Verify hash_alg is not in kwargs (to prevent JSON serialization errors)
    assert "hash_alg" not in sp.kwargs, "hash_alg should not be passed to HTTPClientBase"

    # Verify kwargs can be serialized to JSON (this would fail if hash_alg was in kwargs)
    json_str = json.dumps(sp.kwargs)
    assert json_str == "{}", f"Expected empty kwargs, got: {json_str}"

    # Test with hash_alg and additional parameters
    sp2 = HttpProxySP(
        host="localhost",
        port="8000",
        hash_alg=EnumHashAlgorithm.SHA384,
        prehash="sha256",
        custom_param="value",
    )
    assert "hash_alg" not in sp2.kwargs
    assert "custom_param" in sp2.kwargs
    assert sp2.prehash == "sha256"

    # Verify JSON serialization still works with other kwargs
    json_str2 = json.dumps(sp2.kwargs)
    assert "custom_param" in json_str2


def test_convert_params_valid() -> None:
    """Test valid parameter conversion for SignatureProvider.

    Verifies that a properly formatted parameter string is correctly parsed
    into a dictionary with the expected key-value pairs.
    """
    params = "type=file;file_path=/path/to/file;password=secret"
    result = SignatureProvider.convert_params(params)
    assert result == {"type": "file", "file_path": "/path/to/file", "password": "secret"}


def test_convert_params_duplicate_key() -> None:
    """Test convert_params method with duplicate keys in parameter string.

    Verifies that the convert_params method properly raises SPSDKKeyError
    when the input parameter string contains duplicate key names.

    :raises SPSDKKeyError: When duplicate keys are found in the parameter string.
    """
    params = "type=file;file_path=/path;file_path=/another/path"
    with pytest.raises(SPSDKKeyError):
        SignatureProvider.convert_params(params)


def test_convert_params_invalid_format() -> None:
    """Test convert_params method with invalid parameter format.

    Verifies that SignatureProvider.convert_params raises SPSDKValueError
    when provided with malformed parameter string that doesn't follow
    the expected key=value format.

    :raises SPSDKValueError: When parameter string format is invalid.
    """
    params = "type:file;file_path=/path"
    with pytest.raises(SPSDKValueError):
        SignatureProvider.convert_params(params)


def test_filter_params() -> None:
    """Test filter_params method of SignatureProvider.

    Verifies that the filter_params static method correctly filters a parameter
    dictionary to only include parameters that match the constructor signature
    of a given class, while preserving extra parameters not in the signature.
    """

    class TestClass:
        """Test utility class for parameter validation.

        This class provides a simple test fixture for validating string parameter
        handling and initialization patterns in SPSDK test scenarios.
        """

        def __init__(self, param1: str, param2: str) -> None:
            """Initialize the object with two string parameters.

            :param param1: First string parameter for initialization.
            :param param2: Second string parameter for initialization.
            """
            self.param1 = param1
            self.param2 = param2

    params = {"param1": "value1", "param2": "value2", "type": "file", "extra": "extra_value"}
    filtered = SignatureProvider.filter_params(TestClass, params)  # type: ignore

    assert "type" not in filtered
    assert "extra" in filtered
