#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Unit tests for UniversalBinaryFile class.

This module provides comprehensive test coverage for the UniversalBinaryFile
class, testing all supported formats (BIN, SPARSE, SREC, HEX) and operations.
"""

import os
from typing import Any

import pytest

from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.utils.binary_image import BinaryImage
from spsdk.utils.misc import load_binary, write_file
from spsdk.utils.sparse_image import SparseImage
from spsdk.utils.universal_binary_file import UniversalBinaryFile


@pytest.fixture(name="test_binary_file")
def test_binary_file_fixture(tmpdir: Any) -> str:
    """Create a test binary file.

    :param tmpdir: Temporary directory fixture.
    :return: Path to created binary file.
    """
    file_path = os.path.join(tmpdir, "test.bin")
    # Create 1KB file with incrementing pattern
    data = bytes([i % 256 for i in range(1024)])
    write_file(data, file_path, "wb")
    return file_path


@pytest.fixture(name="test_sparse_file")
def test_sparse_file_fixture(tmpdir: Any) -> str:
    """Create a test SPARSE file.

    :param tmpdir: Temporary directory fixture.
    :return: Path to created SPARSE file.
    """
    file_path = os.path.join(tmpdir, "test.simg")

    # Create a binary image with mixed content
    binary_data = bytearray(4096)
    # First 1KB: incrementing pattern
    binary_data[0:1024] = bytes([i % 256 for i in range(1024)])
    # Next 1KB: zeros (will become DONT_CARE chunk)
    binary_data[1024:2048] = b"\x00" * 1024
    # Next 1KB: 0xAA pattern (will become FILL chunk)
    binary_data[2048:3072] = b"\xaa" * 1024
    # Last 1KB: random data
    binary_data[3072:4096] = bytes([(i * 7) % 256 for i in range(1024)])

    # Create sparse image
    sparse = SparseImage(block_size=4096, calculate_crc=True)
    sparse.from_binary(bytes(binary_data))
    sparse.save_to_file(file_path)

    return file_path


@pytest.fixture(name="test_hex_file")
def test_hex_file_fixture(tmpdir: Any) -> str:
    """Create a test Intel HEX file.

    :param tmpdir: Temporary directory fixture.
    :return: Path to created HEX file.
    """
    file_path = os.path.join(tmpdir, "test.hex")

    # Create binary image
    data = bytes([i % 256 for i in range(512)])
    binary_image = BinaryImage(name="test", binary=data, offset=0x1000)

    # Save as HEX
    binary_image.save_binary_image(file_path, file_format="HEX")

    return file_path


@pytest.fixture(name="test_srec_file")
def test_srec_file_fixture(tmpdir: Any) -> str:
    """Create a test SREC file.

    :param tmpdir: Temporary directory fixture.
    :return: Path to created SREC file.
    """
    file_path = os.path.join(tmpdir, "test.srec")

    # Create binary image
    data = bytes([i % 256 for i in range(512)])
    binary_image = BinaryImage(name="test", binary=data, offset=0x2000)

    # Save as SREC
    binary_image.save_binary_image(file_path, file_format="SREC")

    return file_path


class TestUniversalBinaryFileBasic:
    """Basic functionality tests for UniversalBinaryFile."""

    def test_basic_init(self) -> None:
        """Test basic initialization without parameters."""
        ubf = UniversalBinaryFile()
        assert ubf.path is None
        assert ubf.mode == "rb"
        assert ubf.format_type == "BIN"
        assert not ubf.is_open

    def test_open_binary_file(self, test_binary_file: str) -> None:
        """Test opening binary file.

        :param test_binary_file: Path to test binary file.
        """
        ubf = UniversalBinaryFile()
        ubf.open(test_binary_file, "rb")
        assert ubf.path == test_binary_file
        assert ubf.mode == "rb"
        assert ubf.format_type == "BIN"
        assert ubf.is_open
        ubf.close()

    def test_open_sparse_file(self, test_sparse_file: str) -> None:
        """Test opening SPARSE file.

        :param test_sparse_file: Path to test SPARSE file.
        """
        ubf = UniversalBinaryFile()
        ubf.open(test_sparse_file, "rb")
        assert ubf.format_type == "SPARSE"
        assert ubf.is_open
        ubf.close()

    def test_open_hex_file(self, test_hex_file: str) -> None:
        """Test opening Intel HEX file.

        :param test_hex_file: Path to test HEX file.
        """
        ubf = UniversalBinaryFile()
        ubf.open(test_hex_file, "rb")
        assert ubf.format_type == "HEX"
        assert ubf.is_open
        ubf.close()

    def test_open_srec_file(self, test_srec_file: str) -> None:
        """Test opening SREC file.

        :param test_srec_file: Path to test SREC file.
        """
        ubf = UniversalBinaryFile()
        ubf.open(test_srec_file, "rb")
        assert ubf.format_type == "SREC"
        assert ubf.is_open
        ubf.close()

    def test_open_nonexistent_file_read_mode(self, tmpdir: Any) -> None:
        """Test opening non-existent file in read mode.

        :param tmpdir: Temporary directory fixture.
        """
        file_path = os.path.join(tmpdir, "nonexistent.bin")
        ubf = UniversalBinaryFile()
        with pytest.raises(SPSDKValueError, match="File not found"):
            ubf.open(file_path, "rb")

    def test_open_nonexistent_file_write_mode(self, tmpdir: Any) -> None:
        """Test opening non-existent file in write mode.

        :param tmpdir: Temporary directory fixture.
        """
        file_path = os.path.join(tmpdir, "new.bin")
        ubf = UniversalBinaryFile()
        ubf.open(file_path, "wb")
        assert ubf.format_type == "BIN"  # Default to BIN for new files
        assert ubf.is_open
        ubf.close()

    def test_open_invalid_mode(self, test_binary_file: str) -> None:
        """Test opening with invalid mode.

        :param test_binary_file: Path to test binary file.
        """
        ubf = UniversalBinaryFile()
        with pytest.raises(SPSDKError, match="Invalid file mode"):
            ubf.open(test_binary_file, "invalid")

    def test_repr(self, test_binary_file: str) -> None:
        """Test string representation.

        :param test_binary_file: Path to test binary file.
        """
        ubf = UniversalBinaryFile()
        ubf.open(test_binary_file, "rb")
        repr_str = repr(ubf)
        assert "UniversalBinaryFile" in repr_str
        assert test_binary_file in repr_str
        assert "BIN" in repr_str
        assert "open" in repr_str
        ubf.close()

    def test_repr_closed(self) -> None:
        """Test string representation of closed file."""
        ubf = UniversalBinaryFile()
        repr_str = repr(ubf)
        assert "UniversalBinaryFile" in repr_str
        assert "closed" in repr_str


class TestUniversalBinaryFileOpenClose:
    """Test open and close operations."""

    def test_open_close_binary(self, test_binary_file: str) -> None:
        """Test open and close for binary file.

        :param test_binary_file: Path to test binary file.
        """
        ubf = UniversalBinaryFile()
        assert not ubf.is_open

        ubf.open(test_binary_file, "rb")
        assert ubf.is_open
        assert ubf.position == 0

        ubf.close()
        assert not ubf.is_open

    def test_open_close_sparse(self, test_sparse_file: str) -> None:
        """Test open and close for SPARSE file.

        :param test_sparse_file: Path to test SPARSE file.
        """
        ubf = UniversalBinaryFile()
        ubf.open(test_sparse_file, "rb")
        assert ubf.is_open
        assert ubf._sparse_reader is not None

        ubf.close()
        assert not ubf.is_open
        assert ubf._sparse_reader is None

    def test_open_close_hex(self, test_hex_file: str) -> None:
        """Test open and close for HEX file.

        :param test_hex_file: Path to test HEX file.
        """
        ubf = UniversalBinaryFile()
        ubf.open(test_hex_file, "rb")
        assert ubf.is_open
        assert ubf._binary_image is not None

        ubf.close()
        assert not ubf.is_open

    def test_open_already_open(self, test_binary_file: str) -> None:
        """Test opening already open file.

        :param test_binary_file: Path to test binary file.
        """
        ubf = UniversalBinaryFile()
        ubf.open(test_binary_file, "rb")

        with pytest.raises(SPSDKError, match="File already open"):
            ubf.open(test_binary_file, "rb")

        ubf.close()

    def test_close_already_closed(self, test_binary_file: str) -> None:
        """Test closing already closed file.

        :param test_binary_file: Path to test binary file.
        """
        ubf = UniversalBinaryFile()
        ubf.open(test_binary_file, "rb")
        ubf.close()

        # Should not raise, just log warning
        ubf.close()

    def test_context_manager_binary(self, test_binary_file: str) -> None:
        """Test context manager with binary file.

        :param test_binary_file: Path to test binary file.
        """
        ubf = UniversalBinaryFile()
        with ubf.open(test_binary_file, "rb") as f:
            assert f.is_open
            data = f.read(10)
            assert len(data) == 10

        assert not ubf.is_open

    def test_context_manager_sparse(self, test_sparse_file: str) -> None:
        """Test context manager with SPARSE file.

        :param test_sparse_file: Path to test SPARSE file.
        """
        ubf = UniversalBinaryFile()
        with ubf.open(test_sparse_file, "rb") as f:
            assert f.is_open
            data = f.read(10)
            assert len(data) == 10

        assert not ubf.is_open

    def test_context_manager_not_opened(self) -> None:
        """Test context manager without opening file first."""
        ubf = UniversalBinaryFile()
        with pytest.raises(SPSDKError, match="File must be opened before entering context"):
            with ubf:
                pass


class TestUniversalBinaryFileRead:
    """Test read operations."""

    def test_read_binary_full(self, test_binary_file: str) -> None:
        """Test reading entire binary file.

        :param test_binary_file: Path to test binary file.
        """
        reference = load_binary(test_binary_file)

        ubf = UniversalBinaryFile()
        with ubf.open(test_binary_file, "rb") as f:
            data = f.read()
            assert data == reference

    def test_read_binary_partial(self, test_binary_file: str) -> None:
        """Test reading partial binary file.

        :param test_binary_file: Path to test binary file.
        """
        reference = load_binary(test_binary_file)

        ubf = UniversalBinaryFile()
        with ubf.open(test_binary_file, "rb") as f:
            data = f.read(100)
            assert len(data) == 100
            assert data == reference[:100]

    def test_read_sparse_full(self, test_sparse_file: str) -> None:
        """Test reading entire SPARSE file.

        :param test_sparse_file: Path to test SPARSE file.
        """
        # Load reference data
        sparse = SparseImage.load_from_file(test_sparse_file)
        reference = sparse.to_binary()

        ubf = UniversalBinaryFile()
        with ubf.open(test_sparse_file, "rb") as f:
            data = f.read()
            assert data == reference

    def test_read_sparse_partial(self, test_sparse_file: str) -> None:
        """Test reading partial SPARSE file.

        :param test_sparse_file: Path to test SPARSE file.
        """
        sparse = SparseImage.load_from_file(test_sparse_file)
        reference = sparse.to_binary()

        ubf = UniversalBinaryFile()
        with ubf.open(test_sparse_file, "rb") as f:
            f.seek(100)
            data = f.read(200)
            assert len(data) == 200
            assert data == reference[100:300]

    def test_read_hex_full(self, test_hex_file: str) -> None:
        """Test reading entire HEX file.

        :param test_hex_file: Path to test HEX file.
        """
        # Load reference
        binary_image = BinaryImage.load_binary_image(test_hex_file)
        reference = binary_image.export()

        ubf = UniversalBinaryFile()
        with ubf.open(test_hex_file, "rb") as f:
            data = f.read()
            assert data == reference

    def test_read_hex_partial(self, test_hex_file: str) -> None:
        """Test reading partial HEX file.

        :param test_hex_file: Path to test HEX file.
        """
        binary_image = BinaryImage.load_binary_image(test_hex_file)
        reference = binary_image.export()

        ubf = UniversalBinaryFile()
        with ubf.open(test_hex_file, "rb") as f:
            f.seek(50)
            data = f.read(100)
            assert len(data) == 100
            assert data == reference[50:150]

    def test_read_srec_full(self, test_srec_file: str) -> None:
        """Test reading entire SREC file.

        :param test_srec_file: Path to test SREC file.
        """
        binary_image = BinaryImage.load_binary_image(test_srec_file)
        reference = binary_image.export()

        ubf = UniversalBinaryFile()
        with ubf.open(test_srec_file, "rb") as f:
            data = f.read()
            assert data == reference

    def test_read_without_open(self) -> None:
        """Test reading without opening file."""
        ubf = UniversalBinaryFile()

        with pytest.raises(SPSDKError, match="File not open"):
            ubf.read()

    def test_read_write_only_mode(self, tmpdir: Any) -> None:
        """Test reading in write-only mode.

        :param tmpdir: Temporary directory fixture.
        """
        file_path = os.path.join(tmpdir, "test.bin")

        ubf = UniversalBinaryFile()
        with ubf.open(file_path, "wb") as f:
            with pytest.raises(SPSDKError, match="not opened for reading"):
                f.read()

    def test_read_sequential(self, test_binary_file: str) -> None:
        """Test sequential reads.

        :param test_binary_file: Path to test binary file.
        """
        reference = load_binary(test_binary_file)

        ubf = UniversalBinaryFile()
        with ubf.open(test_binary_file, "rb") as f:
            data1 = f.read(100)
            data2 = f.read(100)
            data3 = f.read(100)

            assert data1 == reference[0:100]
            assert data2 == reference[100:200]
            assert data3 == reference[200:300]
            assert f.tell() == 300


class TestUniversalBinaryFileWrite:
    """Test write operations."""

    def test_write_binary_new_file(self, tmpdir: Any) -> None:
        """Test writing to new binary file.

        :param tmpdir: Temporary directory fixture.
        """
        file_path = os.path.join(tmpdir, "new.bin")
        test_data = b"Hello, World!"

        ubf = UniversalBinaryFile()
        with ubf.open(file_path, "wb") as f:
            bytes_written = f.write(test_data)
            assert bytes_written == len(test_data)

        # Verify file was created
        assert os.path.exists(file_path)
        assert load_binary(file_path) == test_data

    def test_write_binary_modify(self, test_binary_file: str) -> None:
        """Test modifying binary file.

        :param test_binary_file: Path to test binary file.
        """
        original = load_binary(test_binary_file)
        test_data = b"MODIFIED"

        ubf = UniversalBinaryFile()
        with ubf.open(test_binary_file, "r+b") as f:
            f.seek(10)
            f.write(test_data)

        # Verify modification
        modified = load_binary(test_binary_file)
        assert modified[:10] == original[:10]
        assert modified[10 : 10 + len(test_data)] == test_data
        assert modified[10 + len(test_data) :] == original[10 + len(test_data) :]

    def test_write_sparse_modify(self, test_sparse_file: str) -> None:
        """Test modifying SPARSE file.

        :param test_sparse_file: Path to test SPARSE file.
        """
        # Get original data
        sparse_original = SparseImage.load_from_file(test_sparse_file)
        original = sparse_original.to_binary()

        test_data = b"SPARSE_MOD"

        ubf = UniversalBinaryFile()
        with ubf.open(test_sparse_file, "r+b") as f:
            f.seek(100)
            f.write(test_data)

        # Verify modification
        sparse_modified = SparseImage.load_from_file(test_sparse_file)
        modified = sparse_modified.to_binary()

        assert modified[:100] == original[:100]
        assert modified[100 : 100 + len(test_data)] == test_data
        assert modified[100 + len(test_data) :] == original[100 + len(test_data) :]

    def test_write_hex_modify(self, test_hex_file: str) -> None:
        """Test modifying HEX file.

        :param test_hex_file: Path to test HEX file.
        """
        # Get original data
        original_image = BinaryImage.load_binary_image(test_hex_file)
        original = original_image.export()

        test_data = b"HEX_MODIFY"

        ubf = UniversalBinaryFile()
        with ubf.open(test_hex_file, "r+b") as f:
            f.seek(50)
            f.write(test_data)

        # Verify modification
        modified_image = BinaryImage.load_binary_image(test_hex_file)
        modified = modified_image.export()

        assert modified[:50] == original[:50]
        assert modified[50 : 50 + len(test_data)] == test_data

    def test_write_srec_modify(self, test_srec_file: str) -> None:
        """Test modifying SREC file.

        :param test_srec_file: Path to test SREC file.
        """
        original_image = BinaryImage.load_binary_image(test_srec_file)
        original = original_image.export()

        test_data = b"SREC_MOD"

        ubf = UniversalBinaryFile()
        with ubf.open(test_srec_file, "r+b") as f:
            f.seek(50)
            f.write(test_data)

        # Verify modification
        modified_image = BinaryImage.load_binary_image(test_srec_file)
        modified = modified_image.export()

        assert modified[:50] == original[:50]
        assert modified[50 : 50 + len(test_data)] == test_data

    def test_write_without_open(self) -> None:
        """Test writing without opening file."""
        ubf = UniversalBinaryFile()

        with pytest.raises(SPSDKError, match="File not open"):
            ubf.write(b"test")

    def test_write_read_only_mode(self, test_binary_file: str) -> None:
        """Test writing in read-only mode.

        :param test_binary_file: Path to test binary file.
        """
        ubf = UniversalBinaryFile()
        with ubf.open(test_binary_file, "rb") as f:
            with pytest.raises(SPSDKError, match="not opened for writing"):
                f.write(b"test")

    def test_write_expand_hex_file(self, test_hex_file: str) -> None:
        """Test writing beyond current file size in HEX file.

        :param test_hex_file: Path to test HEX file.
        """
        original_image = BinaryImage.load_binary_image(test_hex_file)
        original_size = len(original_image)

        test_data = b"EXPAND"

        ubf = UniversalBinaryFile()
        with ubf.open(test_hex_file, "r+b") as f:
            # Write beyond current size
            f.seek(original_size + 100)
            f.write(test_data)

        # Verify expansion
        modified_image = BinaryImage.load_binary_image(test_hex_file)
        modified = modified_image.export()

        assert len(modified) >= original_size + 100 + len(test_data)
        assert modified[original_size + 100 : original_size + 100 + len(test_data)] == test_data


class TestUniversalBinaryFileSeek:
    """Test seek operations."""

    def test_seek_absolute_binary(self, test_binary_file: str) -> None:
        """Test absolute seek in binary file.

        :param test_binary_file: Path to test binary file.
        """
        ubf = UniversalBinaryFile()
        with ubf.open(test_binary_file, "rb") as f:
            pos = f.seek(100, 0)
            assert pos == 100
            assert f.tell() == 100

    def test_seek_relative_binary(self, test_binary_file: str) -> None:
        """Test relative seek in binary file.

        :param test_binary_file: Path to test binary file.
        """
        ubf = UniversalBinaryFile()
        with ubf.open(test_binary_file, "rb") as f:
            f.seek(100, 0)
            pos = f.seek(50, 1)
            assert pos == 150
            assert f.tell() == 150

    def test_seek_from_end_binary(self, test_binary_file: str) -> None:
        """Test seek from end in binary file.

        :param test_binary_file: Path to test binary file.
        """
        file_size = os.path.getsize(test_binary_file)

        ubf = UniversalBinaryFile()
        with ubf.open(test_binary_file, "rb") as f:
            pos = f.seek(-100, 2)
            assert pos == file_size - 100
            assert f.tell() == file_size - 100

    def test_seek_sparse(self, test_sparse_file: str) -> None:
        """Test seek in SPARSE file.

        :param test_sparse_file: Path to test SPARSE file.
        """
        ubf = UniversalBinaryFile()
        with ubf.open(test_sparse_file, "rb") as f:
            f.seek(500)
            assert f.tell() == 500

            data = f.read(100)
            assert len(data) == 100
            assert f.tell() == 600

    def test_seek_hex(self, test_hex_file: str) -> None:
        """Test seek in HEX file.

        :param test_hex_file: Path to test HEX file.
        """
        ubf = UniversalBinaryFile()
        with ubf.open(test_hex_file, "rb") as f:
            f.seek(100)
            assert f.tell() == 100

            data = f.read(50)
            assert len(data) == 50
            assert f.tell() == 150

    def test_seek_negative_position(self, test_binary_file: str) -> None:
        """Test seeking to negative position.

        :param test_binary_file: Path to test binary file.
        """
        ubf = UniversalBinaryFile()
        with ubf.open(test_binary_file, "rb") as f:
            with pytest.raises(SPSDKValueError, match="Negative seek position"):
                f.seek(-100, 0)

    def test_seek_invalid_whence(self, test_binary_file: str) -> None:
        """Test seek with invalid whence value.

        :param test_binary_file: Path to test binary file.
        """
        ubf = UniversalBinaryFile()
        with ubf.open(test_binary_file, "rb") as f:
            with pytest.raises(SPSDKValueError, match="Invalid whence value"):
                f.seek(0, 99)

    def test_seek_without_open(self) -> None:
        """Test seeking without opening file."""
        ubf = UniversalBinaryFile()

        with pytest.raises(SPSDKError, match="File not open"):
            ubf.seek(0)


class TestUniversalBinaryFileUtility:
    """Test utility methods."""

    def test_tell_binary(self, test_binary_file: str) -> None:
        """Test tell method with binary file.

        :param test_binary_file: Path to test binary file.
        """
        ubf = UniversalBinaryFile()
        with ubf.open(test_binary_file, "rb") as f:
            assert f.tell() == 0

            f.read(100)
            assert f.tell() == 100

            f.seek(500)
            assert f.tell() == 500

    def test_flush_binary(self, tmpdir: Any) -> None:
        """Test flush method with binary file.

        :param tmpdir: Temporary directory fixture.
        """
        file_path = os.path.join(tmpdir, "test.bin")

        ubf = UniversalBinaryFile()
        with ubf.open(file_path, "wb") as f:
            f.write(b"test data")
            f.flush()  # Should not raise

    def test_flush_hex(self, test_hex_file: str) -> None:
        """Test flush method with HEX file.

        :param test_hex_file: Path to test HEX file.
        """
        ubf = UniversalBinaryFile()
        with ubf.open(test_hex_file, "r+b") as f:
            f.flush()  # Should be no-op for HEX

    def test_readable_binary(self, test_binary_file: str) -> None:
        """Test readable method.

        :param test_binary_file: Path to test binary file.
        """
        ubf = UniversalBinaryFile()
        with ubf.open(test_binary_file, "rb") as f:
            assert f.readable()

        ubf2 = UniversalBinaryFile()
        with ubf2.open(test_binary_file, "r+b") as f:
            assert f.readable()

    def test_writable_binary(self, tmpdir: Any) -> None:
        """Test writable method.

        :param tmpdir: Temporary directory fixture.
        """
        file_path = os.path.join(tmpdir, "test.bin")

        ubf = UniversalBinaryFile()
        with ubf.open(file_path, "wb") as f:
            assert f.writable()

    def test_seekable_binary(self, test_binary_file: str) -> None:
        """Test seekable method.

        :param test_binary_file: Path to test binary file.
        """
        ubf = UniversalBinaryFile()
        with ubf.open(test_binary_file, "rb") as f:
            assert f.seekable()

    def test_not_readable_write_mode(self, tmpdir: Any) -> None:
        """Test readable returns False in write-only mode.

        :param tmpdir: Temporary directory fixture.
        """
        file_path = os.path.join(tmpdir, "test.bin")

        ubf = UniversalBinaryFile()
        with ubf.open(file_path, "wb") as f:
            assert not f.readable()

    def test_not_writable_read_mode(self, test_binary_file: str) -> None:
        """Test writable returns False in read-only mode.

        :param test_binary_file: Path to test binary file.
        """
        ubf = UniversalBinaryFile()
        with ubf.open(test_binary_file, "rb") as f:
            assert not f.writable()


class TestUniversalBinaryFileComplexScenarios:
    """Test complex usage scenarios."""

    def test_read_write_cycle_binary(self, tmpdir: Any) -> None:
        """Test complete read-modify-write cycle with binary file.

        :param tmpdir: Temporary directory fixture.
        """
        file_path = os.path.join(tmpdir, "test.bin")
        original_data = bytes([i % 256 for i in range(1024)])

        # Write initial data
        ubf = UniversalBinaryFile()
        with ubf.open(file_path, "wb") as f:
            f.write(original_data)

        # Read and modify
        ubf2 = UniversalBinaryFile()
        with ubf2.open(file_path, "r+b") as f:
            # Read first 100 bytes
            data1 = f.read(100)
            assert data1 == original_data[:100]

            # Seek and modify
            f.seek(200)
            f.write(b"MODIFIED")

            # Read after modification
            f.seek(200)
            data2 = f.read(8)
            assert data2 == b"MODIFIED"

        # Verify final state
        final_data = load_binary(file_path)
        assert final_data[:200] == original_data[:200]
        assert final_data[200:208] == b"MODIFIED"
        assert final_data[208:] == original_data[208:]

    def test_read_write_cycle_hex(self, tmpdir: Any) -> None:
        """Test complete read-modify-write cycle with HEX file.

        :param tmpdir: Temporary directory fixture.
        """
        file_path = os.path.join(tmpdir, "test.hex")
        original_data = bytes([i % 256 for i in range(512)])

        # Create initial HEX file
        binary_image = BinaryImage(name="test", binary=original_data, offset=0x1000)
        binary_image.save_binary_image(file_path, file_format="HEX")

        # Read and modify
        ubf = UniversalBinaryFile()
        with ubf.open(file_path, "r+b") as f:
            # Read first 100 bytes
            data1 = f.read(100)
            assert data1 == original_data[:100]

            # Seek and modify
            f.seek(200)
            f.write(b"HEX_MOD")

        # Verify final state
        modified_image = BinaryImage.load_binary_image(file_path)
        modified_data = modified_image.export()

        assert modified_data[:200] == original_data[:200]
        assert modified_data[200:207] == b"HEX_MOD"
