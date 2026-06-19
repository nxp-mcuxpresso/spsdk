#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Additional tests for spsdk/utils/misc.py to improve branch coverage."""

import os
from typing import Any
from unittest.mock import patch

import pytest

from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.utils.misc import (
    BinaryPattern,
    Endianness,
    SecretManager,
    align_block_iso7816,
    check_range,
    clean_up_file_name,
    deprecated,
    file_extension,
    find_dir,
    find_file,
    get_abs_path,
    get_hash,
    get_key_by_val,
    get_printable_path,
    load_hex_string,
    numberify_version,
    sanitize_version,
    split_data,
    swap32,
    swap_endianness,
    use_working_directory,
    write_file,
)

# ---------------------------------------------------------------------------
# Endianness
# ---------------------------------------------------------------------------


def test_endianness_values() -> None:
    """Test that Endianness.values() returns expected list."""
    vals = Endianness.values()
    assert "big" in vals
    assert "little" in vals


# ---------------------------------------------------------------------------
# BinaryPattern
# ---------------------------------------------------------------------------


def test_binary_pattern_invalid() -> None:
    """Test that BinaryPattern raises SPSDKValueError for unknown patterns."""
    with pytest.raises(SPSDKValueError):
        BinaryPattern("not_a_valid_pattern")


def test_binary_pattern_inc_block() -> None:
    """Test that BinaryPattern 'inc' produces incrementing bytes."""
    bp = BinaryPattern("inc")
    block = bp.get_block(4)
    assert block == bytes([0, 1, 2, 3])


def test_binary_pattern_pattern_property_special() -> None:
    """Test that BinaryPattern.pattern returns string name for special patterns."""
    bp = BinaryPattern("rand")
    assert bp.pattern == "rand"

    bp2 = BinaryPattern("zeros")
    assert bp2.pattern == "zeros"


def test_binary_pattern_pattern_property_numeric() -> None:
    """Test that BinaryPattern.pattern returns hex string for numeric patterns."""
    bp = BinaryPattern("255")
    assert bp.pattern == "0xff"


# ---------------------------------------------------------------------------
# clean_up_file_name
# ---------------------------------------------------------------------------


def test_clean_up_file_name_removes_invalid_chars() -> None:
    """Test that clean_up_file_name removes all invalid Windows file-name chars."""
    dirty = 'file<>:"|?*\\name.txt'
    cleaned = clean_up_file_name(dirty)
    for ch in '<>:"|?*\\':
        assert ch not in cleaned
    assert "file" in cleaned
    assert "name.txt" in cleaned


# ---------------------------------------------------------------------------
# load_file / write_file
# ---------------------------------------------------------------------------


def test_write_file_creates_parent_directory(tmpdir: Any) -> None:
    """Test that write_file creates missing parent directories.

    :param tmpdir: Pytest tmpdir fixture.
    """
    nested_path = os.path.join(str(tmpdir), "new_dir", "sub", "output.txt")
    write_file("hello", nested_path)
    assert os.path.exists(nested_path)


def test_write_file_no_overwrite_increments_counter(tmpdir: Any) -> None:
    """Test that write_file increments counter when overwrite=False and file exists.

    :param tmpdir: Pytest tmpdir fixture.
    """
    path = os.path.join(str(tmpdir), "file.txt")
    write_file("first", path)
    # Write again with overwrite=False – should create file_1.txt
    write_file("second", path, overwrite=False)
    path_1 = os.path.join(str(tmpdir), "file_1.txt")
    assert os.path.exists(path_1)
    assert open(path_1, encoding="utf-8").read() == "second"


def test_write_file_no_overwrite_multiple_existing(tmpdir: Any) -> None:
    """Test that write_file increments counter past existing numbered files.

    :param tmpdir: Pytest tmpdir fixture.
    """
    path = os.path.join(str(tmpdir), "file.bin")
    # Pre-create file and file_1
    write_file(b"a", path, mode="wb")
    write_file(b"b", os.path.join(str(tmpdir), "file_1.bin"), mode="wb")
    # Third write should produce file_2.bin
    write_file(b"c", path, mode="wb", overwrite=False)
    path_2 = os.path.join(str(tmpdir), "file_2.bin")
    assert os.path.exists(path_2)


# ---------------------------------------------------------------------------
# file_extension
# ---------------------------------------------------------------------------


def test_file_extension_sparse() -> None:
    """Test that file_extension maps 'sparse' to '.simg'."""
    assert file_extension("sparse") == ".simg"


def test_file_extension_unknown_defaults_to_bin() -> None:
    """Test that file_extension uses '.bin' for unknown format strings."""
    assert file_extension("xyz") == ".bin"


def test_file_extension_no_dot() -> None:
    """Test that file_extension omits the dot when add_dot=False."""
    assert file_extension("hex", add_dot=False) == "hex"


def test_file_extension_srec() -> None:
    """Test that file_extension correctly handles 'srec'."""
    assert file_extension("srec") == ".srec"


# ---------------------------------------------------------------------------
# get_abs_path
# ---------------------------------------------------------------------------


def test_get_abs_path_relative() -> None:
    """Test that get_abs_path converts relative paths correctly."""
    result = get_abs_path("file.txt", base_dir="/some/dir")
    assert result.endswith("file.txt")
    assert "some" in result


# ---------------------------------------------------------------------------
# _find_path / find_file / find_dir
# ---------------------------------------------------------------------------


def test_find_path_abs_not_found(tmpdir: Any) -> None:
    """Test that _find_path raises SPSDKError for non-existent absolute path."""
    abs_path = os.path.join(str(tmpdir), "nonexistent.txt")
    with pytest.raises(SPSDKError):
        find_file(abs_path)


def test_find_path_abs_not_found_no_raise(tmpdir: Any) -> None:
    """Test that find_file returns empty string when raise_exc=False and abs path missing.

    :param tmpdir: Pytest tmpdir fixture.
    """
    abs_path = os.path.join(str(tmpdir), "nonexistent.txt")
    result = find_file(abs_path, raise_exc=False)
    assert result == ""


def test_find_file_search_paths_skip_empty(tmpdir: Any) -> None:
    """Test that find_file skips empty strings in search_paths.

    :param tmpdir: Pytest tmpdir fixture.
    """
    real_file = os.path.join(str(tmpdir), "real.txt")
    open(real_file, "w", encoding="utf-8").close()
    result = find_file("real.txt", search_paths=["", str(tmpdir)])
    assert result.endswith("real.txt")


def test_find_file_use_cwd_true(tmpdir: Any) -> None:
    """Test that find_file finds a file in the current working directory.

    :param tmpdir: Pytest tmpdir fixture.
    """
    real_file = os.path.join(str(tmpdir), "cwd_file.txt")
    open(real_file, "w", encoding="utf-8").close()
    with use_working_directory(str(tmpdir)):
        result = find_file("cwd_file.txt", use_cwd=True)
    assert result.endswith("cwd_file.txt")


def test_find_file_not_found_no_raise(tmpdir: Any) -> None:
    """Test that find_file with raise_exc=False returns '' if not found anywhere.

    :param tmpdir: Pytest tmpdir fixture.
    """
    result = find_file(
        "absolutely_nonexistent.txt",
        use_cwd=False,
        search_paths=[str(tmpdir)],
        raise_exc=False,
    )
    assert result == ""


def test_find_dir_existing(tmpdir: Any) -> None:
    """Test that find_dir returns the path to an existing directory.

    :param tmpdir: Pytest tmpdir fixture.
    """
    sub_dir = os.path.join(str(tmpdir), "mydir")
    os.makedirs(sub_dir)
    result = find_dir(sub_dir)
    assert os.path.isdir(result)


# ---------------------------------------------------------------------------
# swap32
# ---------------------------------------------------------------------------


def test_swap32_out_of_range_negative() -> None:
    """Test swap32 raises SPSDKError for negative input."""
    with pytest.raises(SPSDKError, match="Incorrect number"):
        swap32(-1)


def test_swap32_out_of_range_too_large() -> None:
    """Test swap32 raises SPSDKError for value exceeding 32-bit range."""
    with pytest.raises(SPSDKError, match="Incorrect number"):
        swap32(0x1_0000_0000)


def test_swap32_valid() -> None:
    """Test swap32 correctly swaps byte order."""
    assert swap32(0x01020304) == 0x04030201


# ---------------------------------------------------------------------------
# swap_endianness
# ---------------------------------------------------------------------------


def test_swap_endianness_unsupported_word_size() -> None:
    """Test swap_endianness raises SPSDKError for unsupported word sizes."""
    with pytest.raises(SPSDKError, match="Unsupported word size"):
        swap_endianness(b"\x00\x01\x02", word_size=3)


def test_swap_endianness_data_not_multiple_of_word_size() -> None:
    """Test swap_endianness raises SPSDKError when data length is not multiple of word_size."""
    with pytest.raises(SPSDKError, match="not a multiple"):
        swap_endianness(b"\x00\x01\x02", word_size=4)


def test_swap_endianness_16bit() -> None:
    """Test swap_endianness works for 16-bit word size."""
    result = swap_endianness(bytes([0x01, 0x02]), word_size=2)
    assert result == bytes([0x02, 0x01])


def test_swap_endianness_64bit() -> None:
    """Test swap_endianness works for 64-bit word size."""
    data = bytes(range(8))
    result = swap_endianness(data, word_size=8)
    assert len(result) == 8
    assert result == bytes(reversed(data))


# ---------------------------------------------------------------------------
# check_range
# ---------------------------------------------------------------------------


def test_check_range_out_of_range() -> None:
    """Test check_range returns False when start > x > end (inverted range)."""
    # When start > end and x is between them, the unusual branch is taken
    assert check_range(5, start=10, end=3) is False


def test_check_range_in_range() -> None:
    """Test check_range returns True for a value within the specified range."""
    assert check_range(5, start=0, end=10) is True


# ---------------------------------------------------------------------------
# align_block_iso7816
# ---------------------------------------------------------------------------


def test_align_block_iso7816_exactly_aligned() -> None:
    """Test align_block_iso7816 always adds at least one block of padding.

    When input is already aligned, ISO 7816-4 mandates a full padding block is added.
    """
    data = bytes(16)
    result = align_block_iso7816(data, alignment=16)
    assert len(result) == 32
    assert result[16] == 0x80


def test_align_block_iso7816_partial() -> None:
    """Test align_block_iso7816 pads to the next block boundary."""
    data = bytes(13)
    result = align_block_iso7816(data, alignment=16)
    assert len(result) == 16
    assert result[13] == 0x80


# ---------------------------------------------------------------------------
# sanitize_version / numberify_version
# ---------------------------------------------------------------------------


def test_sanitize_version_fewer_parts() -> None:
    """Test sanitize_version pads short version strings with '.0'."""
    assert sanitize_version("1.2") == "1.2.0"


def test_sanitize_version_more_parts() -> None:
    """Test sanitize_version truncates long version strings."""
    assert sanitize_version("1.2.3.4") == "1.2.3"


def test_numberify_version_fewer_parts() -> None:
    """Test numberify_version handles version strings with fewer parts."""
    v = numberify_version("1.2")
    assert v == 1_002_000


# ---------------------------------------------------------------------------
# get_key_by_val
# ---------------------------------------------------------------------------


def test_get_key_by_val_not_found() -> None:
    """Test get_key_by_val raises SPSDKValueError when value is not in dict."""
    d: dict = {"a": ["x", "y"], "b": ["z"]}
    with pytest.raises(SPSDKValueError):
        get_key_by_val("missing", d)


def test_get_key_by_val_found() -> None:
    """Test get_key_by_val returns correct key for existing value."""
    d: dict = {"a": ["x", "y"], "b": ["z"]}
    assert get_key_by_val("X", d) == "a"


# ---------------------------------------------------------------------------
# split_data
# ---------------------------------------------------------------------------


def test_split_data_basic() -> None:
    """Test split_data yields correct chunks from a byte sequence."""
    chunks = list(split_data(bytes(range(10)), 3))
    assert len(chunks) == 4
    assert chunks[-1] == bytes([9])


# ---------------------------------------------------------------------------
# get_hash
# ---------------------------------------------------------------------------


def test_get_hash_from_string() -> None:
    """Test get_hash works when given a plain string input."""
    h = get_hash("hello")
    assert isinstance(h, str)
    assert len(h) == 8


def test_get_hash_from_bytes() -> None:
    """Test get_hash works when given bytes input."""
    h = get_hash(b"hello")
    assert isinstance(h, str)
    assert len(h) == 8


# ---------------------------------------------------------------------------
# get_printable_path
# ---------------------------------------------------------------------------


def test_get_printable_path_jupyter() -> None:
    """Test get_printable_path returns relative posix path inside Jupyter env."""
    with patch.dict("os.environ", {"JUPYTER_SPSDK": "1"}):
        result = get_printable_path(os.getcwd())
        assert result == "."


def test_get_printable_path_normal() -> None:
    """Test get_printable_path returns original path outside Jupyter env."""
    path = "/some/path/file.txt"
    with patch.dict("os.environ", {}, clear=True):
        os.environ.pop("JUPYTER_SPSDK", None)
        result = get_printable_path(path)
    assert result == path


# ---------------------------------------------------------------------------
# SecretManager
# ---------------------------------------------------------------------------


def test_secret_manager_key_not_found() -> None:
    """Test SecretManager.get_secret raises ValueError for missing key."""
    mgr = SecretManager()
    # Use a dict with an unrelated key to trigger the "not found" branch
    mgr._secrets = {"some_other_key": "value"}  # pylint: disable=protected-access
    with pytest.raises(ValueError, match="not found"):
        mgr.get_secret("nonexistent_key_xyz")


def test_secret_manager_load_secrets_no_file() -> None:
    """Test SecretManager._load_secrets initialises empty dict when file is absent."""
    mgr = SecretManager()
    mgr._secrets = None  # pylint: disable=protected-access
    original_path = mgr.secrets_path
    mgr.secrets_path = "/nonexistent/path/secrets.yaml"
    mgr._load_secrets()  # pylint: disable=protected-access
    assert mgr._secrets == {}  # pylint: disable=protected-access
    mgr.secrets_path = original_path


# ---------------------------------------------------------------------------
# deprecated decorator
# ---------------------------------------------------------------------------


def test_deprecated_decorator_warns() -> None:
    """Test that the deprecated decorator emits a DeprecationWarning."""

    @deprecated("Use new_func instead.")
    def old_func() -> int:
        """Old function.

        :return: Always 42.
        """
        return 42

    with pytest.warns(DeprecationWarning, match="old_func"):
        result = old_func()
    assert result == 42


# ---------------------------------------------------------------------------
# load_hex_string edge cases
# ---------------------------------------------------------------------------


def test_load_hex_string_none_returns_random() -> None:
    """Test load_hex_string returns random bytes when source is None."""
    result = load_hex_string(None, 8)
    assert len(result) == 8


def test_load_hex_string_bytes_source() -> None:
    """Test load_hex_string accepts bytes directly."""
    src = bytes([0x01, 0x02, 0x03, 0x04])
    result = load_hex_string(src, 4)
    assert result == src


def test_load_hex_string_int_source() -> None:
    """Test load_hex_string accepts an integer directly."""
    result = load_hex_string(0xDEADBEEF, 4)
    assert result == bytes([0xDE, 0xAD, 0xBE, 0xEF])


def test_load_hex_string_hex_str_without_prefix() -> None:
    """Test load_hex_string accepts hex string without 0x prefix."""
    result = load_hex_string("AABBCCDD", 4)
    assert result == bytes([0xAA, 0xBB, 0xCC, 0xDD])


# ---------------------------------------------------------------------------
# load_hex_string – file-based branches
# ---------------------------------------------------------------------------


def test_load_hex_string_binary_file(tmpdir: Any) -> None:
    """Test load_hex_string reads raw bytes from a binary file.

    :param tmpdir: Pytest tmpdir fixture.
    """
    binary_path = os.path.join(str(tmpdir), "data.bin")
    write_file(bytes([0x11, 0x22, 0x33, 0x44]), binary_path, mode="wb")
    result = load_hex_string(binary_path, 4)
    assert result == bytes([0x11, 0x22, 0x33, 0x44])


def test_load_hex_string_invalid_string_source() -> None:
    """Test load_hex_string raises SPSDKError for an invalid hex string source."""
    with pytest.raises(SPSDKError, match="Invalid key input"):
        load_hex_string("ZZZZZZ", 4)


def test_load_hex_string_size_mismatch_file(tmpdir: Any) -> None:
    """Test load_hex_string raises SPSDKError when file content produces wrong size.

    :param tmpdir: Pytest tmpdir fixture.
    """
    hex_path = os.path.join(str(tmpdir), "key.txt")
    write_file("AABBCCDDEE", hex_path)  # 5 bytes
    with pytest.raises(SPSDKError, match="size"):
        load_hex_string(hex_path, 4)  # Expects 4 bytes


# ---------------------------------------------------------------------------
# value_to_int – default branch
# ---------------------------------------------------------------------------


def test_value_to_int_with_default_on_invalid() -> None:
    """Test value_to_int returns default value when conversion fails."""
    from spsdk.utils.misc import value_to_int

    result = value_to_int("not_a_number", default=99)
    assert result == 99


def test_value_to_int_empty_string_with_default() -> None:
    """Test value_to_int returns default value for empty string input."""
    from spsdk.utils.misc import value_to_int

    result = value_to_int("", default=0)
    assert result == 0


# ---------------------------------------------------------------------------
# load_configuration – various error branches
# ---------------------------------------------------------------------------


def test_load_configuration_binary_file_raises(tmpdir: Any) -> None:
    """Test load_configuration raises SPSDKNotTextFileError for binary files.

    :param tmpdir: Pytest tmpdir fixture.
    """
    from spsdk.exceptions import SPSDKNotTextFileError

    binary_path = os.path.join(str(tmpdir), "config.yaml")
    write_file(bytes([0x80, 0x81, 0xFF, 0xFE]), binary_path, mode="wb")
    with pytest.raises(SPSDKNotTextFileError, match="not a text file"):
        from spsdk.utils.misc import load_configuration

        load_configuration(binary_path)


def test_load_configuration_file_not_found() -> None:
    """Test load_configuration raises SPSDKError when file does not exist."""
    from spsdk.utils.misc import load_configuration

    with pytest.raises(SPSDKError, match="Can't load configuration file"):
        load_configuration("/nonexistent/path/config.yaml")


def test_load_configuration_yaml_list_raises(tmpdir: Any) -> None:
    """Test load_configuration raises SPSDKError when YAML root is a list not a dict.

    :param tmpdir: Pytest tmpdir fixture.
    """
    from spsdk.utils.misc import load_configuration

    path = os.path.join(str(tmpdir), "list.yaml")
    write_file("- item1\n- item2\n", path)
    with pytest.raises(SPSDKError, match="Invalid configuration file"):
        load_configuration(path)


# ---------------------------------------------------------------------------
# _determine_primary_parsing_error branches
# ---------------------------------------------------------------------------


def test_determine_primary_parsing_error_no_errors() -> None:
    """Test _determine_primary_parsing_error returns None when no errors provided."""
    from spsdk.utils.misc import _determine_primary_parsing_error  # type: ignore[attr-defined]

    result = _determine_primary_parsing_error("content", None, None)
    assert result is None


def test_determine_primary_parsing_error_json_only() -> None:
    """Test _determine_primary_parsing_error returns json error when only json error given."""
    from spsdk.utils.misc import _determine_primary_parsing_error  # type: ignore[attr-defined]

    json_err = ValueError("json error")
    result = _determine_primary_parsing_error("content", json_err, None)
    assert result is json_err


def test_determine_primary_parsing_error_yaml_only() -> None:
    """Test _determine_primary_parsing_error returns yaml error when only yaml error given."""
    from spsdk.utils.misc import _determine_primary_parsing_error  # type: ignore[attr-defined]

    yaml_err = ValueError("yaml error")
    result = _determine_primary_parsing_error("content", None, yaml_err)
    assert result is yaml_err


def test_determine_primary_parsing_error_both_json_content() -> None:
    """Test _determine_primary_parsing_error prefers json error for JSON-like content."""
    from spsdk.utils.misc import _determine_primary_parsing_error  # type: ignore[attr-defined]

    json_err = ValueError("j")
    yaml_err = ValueError("y")
    result = _determine_primary_parsing_error('{"bad": json}', json_err, yaml_err)
    assert result is json_err


def test_determine_primary_parsing_error_both_yaml_content() -> None:
    """Test _determine_primary_parsing_error prefers yaml error for non-JSON content."""
    from spsdk.utils.misc import _determine_primary_parsing_error  # type: ignore[attr-defined]

    json_err = ValueError("j")
    yaml_err = ValueError("y")
    result = _determine_primary_parsing_error("key: value", json_err, yaml_err)
    assert result is yaml_err


# ---------------------------------------------------------------------------
# SecretManager – _load_secrets with existing file
# ---------------------------------------------------------------------------


def test_secret_manager_load_secrets_existing_file(tmpdir: Any) -> None:
    """Test SecretManager._load_secrets loads secrets from an existing YAML file.

    :param tmpdir: Pytest tmpdir fixture.
    """
    import yaml as _yaml

    secrets_path = os.path.join(str(tmpdir), "secrets.yaml")
    with open(secrets_path, "w", encoding="utf-8") as f:
        _yaml.dump({"my_secret": "s3cr3t"}, f)

    mgr = SecretManager()
    mgr._secrets = None  # pylint: disable=protected-access
    original = mgr.secrets_path
    mgr.secrets_path = secrets_path
    mgr._load_secrets()  # pylint: disable=protected-access
    assert mgr._secrets == {"my_secret": "s3cr3t"}  # pylint: disable=protected-access
    mgr.secrets_path = original


# ---------------------------------------------------------------------------
# get_abs_path – relative path branch
# ---------------------------------------------------------------------------


def test_get_abs_path_relative_no_base() -> None:
    """Test get_abs_path converts relative path using current working directory."""
    result = get_abs_path("relative/file.txt")
    assert os.path.isabs(result)
    assert result.endswith("relative/file.txt")


# ---------------------------------------------------------------------------
# align_block_iso7816 – already-aligned data gets full extra block
# ---------------------------------------------------------------------------


def test_align_block_iso7816_zero_remainder_adds_full_block() -> None:
    """Test align_block_iso7816 padding_len==alignment case: adds full padding block.

    When len(data) % alignment == 0, padding_len would be 0, which is adjusted
    to alignment, so a full block of padding is appended.
    """
    data = bytes(32)  # Already a multiple of 16
    result = align_block_iso7816(data, alignment=16)
    assert len(result) == 48  # 32 + 16
    assert result[32] == 0x80  # First byte of padding is 0x80
