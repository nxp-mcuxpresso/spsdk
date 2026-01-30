#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for Android SPARSE image format utilities."""

import os
import struct

import pytest

from spsdk.exceptions import SPSDKError, SPSDKParsingError, SPSDKValueError
from spsdk.utils.sparse_image import SparseChunk, SparseChunkType, SparseImage, SparseImageHeader


def test_sparse_header_export_parse() -> None:
    """Test sparse image header export and parse operations."""
    header = SparseImageHeader(
        block_size=4096,
        total_blocks=100,
        total_chunks=5,
        image_checksum=0x12345678,
    )

    # Export and parse
    data = header.export()
    assert len(data) == SparseImageHeader.HEADER_SIZE

    parsed_header = SparseImageHeader.parse(data)
    assert parsed_header.magic == SparseImageHeader.MAGIC
    assert parsed_header.block_size == 4096
    assert parsed_header.total_blocks == 100
    assert parsed_header.total_chunks == 5
    assert parsed_header.image_checksum == 0x12345678


def test_sparse_header_invalid_magic() -> None:
    """Test sparse header parsing with invalid magic number."""
    invalid_data = b"\x00" * SparseImageHeader.HEADER_SIZE

    with pytest.raises(SPSDKParsingError, match="Invalid sparse image magic"):
        SparseImageHeader.parse(invalid_data)


def test_sparse_header_insufficient_data() -> None:
    """Test sparse header parsing with insufficient data."""
    with pytest.raises(SPSDKParsingError, match="Insufficient data"):
        SparseImageHeader.parse(b"\x00" * 10)


def test_sparse_chunk_raw() -> None:
    """Test RAW chunk creation and export."""
    data = b"Hello World!" * 100
    chunk = SparseChunk(
        SparseChunkType.RAW,
        chunk_blocks=1,
        total_size=SparseImageHeader.CHUNK_HEADER_SIZE + len(data),
        data=data,
    )

    exported = chunk.export()
    assert len(exported) == SparseImageHeader.CHUNK_HEADER_SIZE + len(data)


def test_sparse_chunk_fill() -> None:
    """Test FILL chunk creation and export."""
    fill_value = b"\xaa\xbb\xcc\xdd"
    chunk = SparseChunk(
        SparseChunkType.FILL,
        chunk_blocks=10,
        total_size=SparseImageHeader.CHUNK_HEADER_SIZE + 4,
        data=fill_value,
    )

    exported = chunk.export()
    assert len(exported) == SparseImageHeader.CHUNK_HEADER_SIZE + 4


def test_sparse_chunk_dont_care() -> None:
    """Test DONT_CARE chunk creation and export."""
    chunk = SparseChunk(
        SparseChunkType.DONT_CARE,
        chunk_blocks=5,
        total_size=SparseImageHeader.CHUNK_HEADER_SIZE,
    )

    exported = chunk.export()
    assert len(exported) == SparseImageHeader.CHUNK_HEADER_SIZE


def test_sparse_image_invalid_block_size() -> None:
    """Test sparse image creation with invalid block size."""
    with pytest.raises(SPSDKValueError, match="Block size must be a power of 2"):
        SparseImage(block_size=1000)

    with pytest.raises(SPSDKValueError, match="Block size must be a power of 2"):
        SparseImage(block_size=0)


def test_sparse_image_from_binary_zeros() -> None:
    """Test creating sparse image from zero-filled binary data."""
    data = b"\x00" * (4096 * 10)  # 10 blocks of zeros
    sparse = SparseImage(block_size=4096)
    sparse.from_binary(data)

    assert sparse.header is not None
    assert sparse.header.total_blocks == 10
    assert len(sparse.chunks) == 1
    assert sparse.chunks[0].chunk_type == SparseChunkType.DONT_CARE
    assert sparse.chunks[0].chunk_blocks == 10


def test_sparse_image_from_binary_fill_pattern() -> None:
    """Test creating sparse image from data with fill pattern."""
    fill_value = b"\xaa\xbb\xcc\xdd"
    data = fill_value * (4096 // 4 * 5)  # 5 blocks of repeated pattern
    sparse = SparseImage(block_size=4096)
    sparse.from_binary(data)

    assert sparse.header is not None
    assert len(sparse.chunks) == 1
    assert sparse.chunks[0].chunk_type == SparseChunkType.FILL
    assert sparse.chunks[0].data == fill_value


def test_sparse_image_from_binary_raw() -> None:
    """Test creating sparse image from raw binary data."""
    data = bytes(range(256)) * 16  # Non-repeating pattern
    sparse = SparseImage(block_size=4096)
    sparse.from_binary(data)

    assert sparse.header is not None
    assert len(sparse.chunks) == 1
    assert sparse.chunks[0].chunk_type == SparseChunkType.RAW


def test_sparse_image_from_binary_mixed() -> None:
    """Test creating sparse image from mixed data types."""
    # Create mixed data: zeros, fill pattern, raw data
    zeros = b"\x00" * 4096
    fill = b"\xff\xff\xff\xff" * (4096 // 4)
    raw = bytes(range(256)) * 16

    data = zeros + fill + raw + zeros

    sparse = SparseImage(block_size=4096)
    sparse.from_binary(data)

    assert sparse.header is not None
    assert sparse.header.total_blocks == 4
    assert len(sparse.chunks) == 4

    # Verify chunk types
    assert sparse.chunks[0].chunk_type == SparseChunkType.DONT_CARE
    assert sparse.chunks[1].chunk_type == SparseChunkType.FILL
    assert sparse.chunks[2].chunk_type == SparseChunkType.RAW
    assert sparse.chunks[3].chunk_type == SparseChunkType.DONT_CARE


def test_sparse_image_roundtrip() -> None:
    """Test sparse image creation and reconstruction."""
    # Create test data
    original_data = b"\x00" * 4096 + b"\xaa" * 4096 + bytes(range(256)) * 16

    # Convert to sparse
    sparse = SparseImage(block_size=4096)
    sparse.from_binary(original_data)

    # Convert back to binary
    reconstructed = sparse.to_binary()

    # Verify data matches (accounting for alignment)
    assert reconstructed[: len(original_data)] == original_data


def test_sparse_image_export_parse() -> None:
    """Test sparse image export and parse operations."""
    data = b"\x00" * 4096 + b"\xff" * 4096

    # Create sparse image
    sparse = SparseImage(block_size=4096)
    sparse.from_binary(data)

    # Export to binary format
    exported = sparse.export()

    # Parse back
    parsed = SparseImage.parse(exported)

    assert parsed.header is not None
    assert parsed.header.block_size == 4096
    assert len(parsed.chunks) == len(sparse.chunks)


def test_sparse_image_file_operations(tmpdir: str) -> None:
    """Test sparse image file save and load operations."""
    data = b"\x00" * 4096 + b"\xff" * 4096

    sparse = SparseImage(block_size=4096)
    sparse.from_binary(data)

    # Save to file
    output_path = os.path.join(tmpdir, "test.sparse")
    sparse.save_to_file(output_path)

    assert os.path.isfile(output_path)

    # Load from file
    loaded = SparseImage.load_from_file(output_path)

    assert loaded.header is not None
    assert loaded.header.block_size == 4096
    assert len(loaded.chunks) == len(sparse.chunks)


def test_sparse_image_get_info() -> None:
    """Test sparse image information string generation."""
    data = b"\x00" * 4096 + b"\xff" * 4096

    sparse = SparseImage(block_size=4096)
    sparse.from_binary(data)

    # Test with colors disabled for easier assertion
    info = sparse.get_info(no_color=True)

    assert "Sparse Image Information" in info
    assert "Block Size:   4096 bytes" in info
    assert "Total Blocks: 2" in info
    assert "Total Chunks: 2" in info
    assert "Image Size:   8192 bytes" in info
    assert "DONT_CARE" in info
    assert "FILL" in info
    assert "Fill value: 0xFFFFFFFF" in info


def test_sparse_image_no_header_error() -> None:
    """Test error handling when no header is available."""
    sparse = SparseImage(block_size=4096)

    with pytest.raises(SPSDKError, match="No sparse image header"):
        sparse.export()

    with pytest.raises(SPSDKError, match="No sparse image header"):
        sparse.to_binary()


def test_sparse_chunk_parse_invalid_type() -> None:
    """Test parsing chunk with invalid type."""
    # Create invalid chunk data with unknown type
    invalid_data = b"\xff\xff\x00\x00\x01\x00\x00\x00\x10\x00\x00\x00"

    with pytest.raises(SPSDKParsingError, match="Unknown chunk type"):
        SparseChunk.parse(invalid_data, 0)


def test_sparse_chunk_parse_insufficient_data() -> None:
    """Test parsing chunk with insufficient data."""
    # Not enough data for chunk header
    with pytest.raises(SPSDKParsingError, match="Insufficient data"):
        SparseChunk.parse(b"\x00" * 5, 0)


def test_sparse_chunk_parse_raw_insufficient_data() -> None:
    """Test parsing RAW chunk with insufficient data."""
    # Create RAW chunk header but not enough data
    chunk_header = struct.pack(
        "<HHII",
        SparseChunkType.RAW,
        0,
        1,  # 1 block
        SparseImageHeader.CHUNK_HEADER_SIZE + 100,  # Claims 100 bytes of data
    )

    with pytest.raises(SPSDKParsingError, match="Insufficient data for RAW chunk"):
        SparseChunk.parse(chunk_header + b"\x00" * 50, 0)  # Only 50 bytes provided


def test_sparse_chunk_parse_fill_insufficient_data() -> None:
    """Test parsing FILL chunk with insufficient data."""
    # Create FILL chunk header but not enough data
    chunk_header = struct.pack(
        "<HHII",
        SparseChunkType.FILL,
        0,
        1,
        SparseImageHeader.CHUNK_HEADER_SIZE + 4,
    )

    with pytest.raises(SPSDKParsingError, match="Insufficient data for FILL chunk"):
        SparseChunk.parse(chunk_header + b"\x00" * 2, 0)  # Only 2 bytes instead of 4


def test_sparse_image_to_binary_missing_raw_data() -> None:
    """Test error when RAW chunk is missing data."""
    sparse = SparseImage(block_size=4096)
    sparse.header = SparseImageHeader(block_size=4096, total_blocks=1, total_chunks=1)

    # Create RAW chunk without data
    chunk = SparseChunk(
        SparseChunkType.RAW,
        chunk_blocks=1,
        total_size=SparseImageHeader.CHUNK_HEADER_SIZE + 4096,
        data=None,
    )
    sparse.chunks.append(chunk)

    with pytest.raises(SPSDKError, match="RAW chunk missing data"):
        sparse.to_binary()


def test_sparse_image_to_binary_invalid_fill_data() -> None:
    """Test error when FILL chunk has invalid fill value."""
    sparse = SparseImage(block_size=4096)
    sparse.header = SparseImageHeader(block_size=4096, total_blocks=1, total_chunks=1)

    # Create FILL chunk with wrong size data
    chunk = SparseChunk(
        SparseChunkType.FILL,
        chunk_blocks=1,
        total_size=SparseImageHeader.CHUNK_HEADER_SIZE + 4,
        data=b"\xff\xff",  # Only 2 bytes instead of 4
    )
    sparse.chunks.append(chunk)

    with pytest.raises(SPSDKError, match="FILL chunk missing or invalid fill value"):
        sparse.to_binary()


def test_sparse_image_parse_invalid_header_size() -> None:
    """Test parsing sparse image with invalid header size."""
    # Create header with wrong header size field
    invalid_header = struct.pack(
        "<IHHHHIIII",
        SparseImageHeader.MAGIC,
        1,  # major version
        0,  # minor version
        100,  # Wrong header size
        SparseImageHeader.CHUNK_HEADER_SIZE,
        4096,
        10,
        1,
        0,
    )

    with pytest.raises(SPSDKParsingError, match="Invalid header size"):
        SparseImageHeader.parse(invalid_header)


def test_sparse_image_parse_invalid_chunk_header_size() -> None:
    """Test parsing sparse image with invalid chunk header size."""
    # Create header with wrong chunk header size field
    invalid_header = struct.pack(
        "<IHHHHIIII",
        SparseImageHeader.MAGIC,
        1,  # major version
        0,  # minor version
        SparseImageHeader.HEADER_SIZE,
        100,  # Wrong chunk header size
        4096,
        10,
        1,
        0,
    )

    with pytest.raises(SPSDKParsingError, match="Invalid chunk header size"):
        SparseImageHeader.parse(invalid_header)


def test_sparse_image_large_file(tmpdir: str) -> None:
    """Test sparse image with larger file containing multiple chunk types."""
    # Create a larger test file with various patterns
    data = bytearray()

    # Add 10 blocks of zeros
    data.extend(b"\x00" * (4096 * 10))

    # Add 5 blocks of fill pattern
    data.extend(b"\xde\xad\xbe\xef" * (4096 // 4 * 5))

    # Add 3 blocks of random data
    data.extend(bytes(range(256)) * (4096 // 256 * 3))

    # Add 7 blocks of different fill pattern
    data.extend(b"\xca\xfe\xba\xbe" * (4096 // 4 * 7))

    # Add 5 more blocks of zeros
    data.extend(b"\x00" * (4096 * 5))

    # Convert to sparse
    sparse = SparseImage(block_size=4096)
    sparse.from_binary(bytes(data))

    # Verify structure
    assert sparse.header is not None
    assert sparse.header.total_blocks == 30
    assert len(sparse.chunks) == 5

    # Save and reload
    output_path = os.path.join(tmpdir, "large_test.sparse")
    sparse.save_to_file(output_path)

    loaded = SparseImage.load_from_file(output_path)

    # Verify loaded image
    assert loaded.header is not None
    assert loaded.header.total_blocks == 30
    assert len(loaded.chunks) == 5

    # Verify data integrity
    reconstructed = loaded.to_binary()
    assert reconstructed == bytes(data)


def test_sparse_image_compression_ratio() -> None:
    """Test that sparse format achieves good compression for sparse data."""
    # Create highly sparse data (mostly zeros with some data)
    data = bytearray(4096 * 100)  # 100 blocks of zeros

    # Add small amount of actual data
    data[4096 * 10 : 4096 * 10 + 1024] = b"\xff" * 1024
    data[4096 * 50 : 4096 * 50 + 2048] = b"\xaa" * 2048

    # Convert to sparse
    sparse = SparseImage(block_size=4096)
    sparse.from_binary(bytes(data))

    # Export both formats
    raw_size = len(data)
    sparse_size = len(sparse.export())

    # Sparse format should be significantly smaller
    assert sparse_size < raw_size / 2  # At least 50% compression


def test_sparse_image_no_chunks_error() -> None:
    """Test error when trying to convert sparse image with no chunks."""
    sparse = SparseImage(block_size=4096)
    sparse.header = SparseImageHeader(block_size=4096, total_blocks=1, total_chunks=0)

    with pytest.raises(SPSDKError, match="No chunks available"):
        sparse.to_binary()


def test_sparse_chunk_repr() -> None:
    """Test string representation of sparse chunk."""
    chunk = SparseChunk(
        SparseChunkType.RAW,
        chunk_blocks=5,
        total_size=100,
        data=b"test",
    )

    repr_str = repr(chunk)
    assert "SparseChunk" in repr_str
    assert "RAW" in repr_str
    assert "blocks=5" in repr_str


def test_sparse_image_repr() -> None:
    """Test string representation of sparse image."""
    sparse = SparseImage(block_size=4096)

    repr_str = repr(sparse)
    assert "SparseImage" in repr_str
    assert "block_size=4096" in repr_str
    assert "chunks=0" in repr_str


def test_sparse_header_repr() -> None:
    """Test string representation of sparse header."""
    header = SparseImageHeader(block_size=4096, total_blocks=10, total_chunks=3)

    repr_str = repr(header)
    assert "SparseImageHeader" in repr_str
    assert "block_size=4096" in repr_str
    assert "total_blocks=10" in repr_str
    assert "total_chunks=3" in repr_str


def test_sparse_image_empty_data() -> None:
    """Test creating sparse image from empty data."""
    sparse = SparseImage(block_size=4096)
    sparse.from_binary(b"")

    assert sparse.header is not None
    assert sparse.header.total_blocks == 0
    assert len(sparse.chunks) == 0


def test_sparse_image_single_byte() -> None:
    """Test creating sparse image from single byte (will be aligned to block size)."""
    sparse = SparseImage(block_size=4096)
    sparse.from_binary(b"\xff")

    assert sparse.header is not None
    assert sparse.header.total_blocks == 1

    # Reconstruct and verify
    reconstructed = sparse.to_binary()
    assert reconstructed[0] == 0xFF
    assert len(reconstructed) == 4096


def test_sparse_image_unaligned_data() -> None:
    """Test that unaligned data is properly aligned to block size."""
    # Create data that's not aligned to block size
    data = b"\xaa" * 5000  # Not a multiple of 4096

    sparse = SparseImage(block_size=4096)
    sparse.from_binary(data)

    # Should be aligned up
    assert sparse.header is not None
    assert sparse.header.total_blocks == 2  # 5000 bytes needs 2 blocks

    # Verify reconstruction
    reconstructed = sparse.to_binary()
    assert reconstructed[:5000] == data
    assert len(reconstructed) == 8192  # 2 blocks


def test_sparse_image_load_file_error(tmpdir: str) -> None:
    """Test error handling when loading non-existent file."""
    non_existent = os.path.join(tmpdir, "does_not_exist.sparse")

    with pytest.raises(SPSDKError, match="Cannot load sparse image"):
        SparseImage.load_from_file(non_existent)


def test_sparse_image_crc32_chunk() -> None:
    """Test handling of CRC32 chunk type."""
    sparse = SparseImage(block_size=4096)
    sparse.header = SparseImageHeader(block_size=4096, total_blocks=1, total_chunks=2)

    # Add a RAW chunk
    raw_chunk = SparseChunk(
        SparseChunkType.RAW,
        chunk_blocks=1,
        total_size=SparseImageHeader.CHUNK_HEADER_SIZE + 4096,
        data=b"\xff" * 4096,
    )
    sparse.chunks.append(raw_chunk)

    # Add a CRC32 chunk
    crc_chunk = SparseChunk(
        SparseChunkType.CRC32,
        chunk_blocks=0,
        total_size=SparseImageHeader.CHUNK_HEADER_SIZE + 4,
        data=b"\x12\x34\x56\x78",
    )
    sparse.chunks.append(crc_chunk)

    # Should not raise error and CRC32 chunk should not affect output
    output = sparse.to_binary()
    assert len(output) == 4096
    assert output == b"\xff" * 4096


def test_sparse_image_with_crc_creation() -> None:
    """Test creating sparse image with CRC calculation."""
    data = b"\xff" * 4096 + b"\x00" * 4096

    # Create sparse image with CRC
    sparse = SparseImage(block_size=4096, calculate_crc=True)
    sparse.from_binary(data)

    # Verify header has CRC
    assert sparse.header is not None
    assert sparse.header.image_checksum != 0

    # Verify CRC32 chunk was added
    crc_chunks = [c for c in sparse.chunks if c.chunk_type == SparseChunkType.CRC32]
    assert len(crc_chunks) == 1

    # Validate CRC
    assert sparse.validate_crc() is True


def test_sparse_image_crc_validation_success() -> None:
    """Test CRC validation with correct checksum."""
    data = b"\xaa" * 8192

    # Create sparse image with CRC
    sparse = SparseImage(block_size=4096, calculate_crc=True)
    sparse.from_binary(data)

    # Export and re-parse
    exported = sparse.export()
    parsed = SparseImage.parse(exported, validate_crc=True)

    # Should not raise exception
    assert parsed.validate_crc() is True


def test_sparse_image_crc_validation_failure() -> None:
    """Test CRC validation with incorrect checksum."""
    data = b"\xbb" * 4096

    # Create sparse image with CRC
    sparse = SparseImage(block_size=4096, calculate_crc=True)
    sparse.from_binary(data)

    # Corrupt the header CRC
    if sparse.header:
        sparse.header.image_checksum = 0x12345678

    # Validation should fail
    assert sparse.validate_crc() is False


def test_sparse_image_load_with_crc_validation(tmpdir: str) -> None:
    """Test loading sparse image file with CRC validation."""
    data = b"\xcc" * 8192

    # Create and save sparse image with CRC
    sparse = SparseImage(block_size=4096, calculate_crc=True)
    sparse.from_binary(data)

    output_path = os.path.join(tmpdir, "test_crc.sparse")
    sparse.save_to_file(output_path)

    # Load with CRC validation enabled
    loaded = SparseImage.load_from_file(output_path, validate_crc=True)

    assert loaded.header is not None
    assert loaded.header.image_checksum != 0
    assert loaded.validate_crc() is True


def test_sparse_image_load_with_corrupted_crc(tmpdir: str) -> None:
    """Test loading sparse image file with corrupted CRC."""
    data = b"\xdd" * 4096

    # Create and save sparse image with CRC
    sparse = SparseImage(block_size=4096, calculate_crc=True)
    sparse.from_binary(data)

    output_path = os.path.join(tmpdir, "test_corrupted.sparse")
    sparse.save_to_file(output_path)

    # Load the file and corrupt both CRCs
    with open(output_path, "rb") as f:
        file_data = bytearray(f.read())

    # Corrupt the image_checksum field in header (offset 24, 4 bytes)
    file_data[24:28] = struct.pack("<I", 0xDEADBEEF)

    # Find and corrupt the CRC32 chunk
    # Parse the sparse image structure
    offset = SparseImageHeader.HEADER_SIZE
    header = SparseImageHeader.parse(bytes(file_data))

    for _ in range(header.total_chunks):
        chunk_type, _, _, total_size = struct.unpack("<HHII", file_data[offset : offset + 12])

        if chunk_type == SparseChunkType.CRC32:
            # Corrupt the CRC32 chunk data (offset + 12 bytes for chunk header)
            file_data[offset + 12 : offset + 16] = struct.pack("<I", 0xDEADBEEF)
            break

        offset += total_size

    with open(output_path, "wb") as f:
        f.write(file_data)

    # Loading with CRC validation should fail
    with pytest.raises(SPSDKError, match="CRC validation failed"):
        SparseImage.load_from_file(output_path, validate_crc=True)


def test_sparse_image_load_without_crc_validation(tmpdir: str) -> None:
    """Test loading sparse image file without CRC validation."""
    data = b"\xee" * 4096

    # Create and save sparse image with CRC
    sparse = SparseImage(block_size=4096, calculate_crc=True)
    sparse.from_binary(data)

    output_path = os.path.join(tmpdir, "test_no_validation.sparse")
    sparse.save_to_file(output_path)

    # Manually corrupt the CRC in the file
    with open(output_path, "rb") as f:
        file_data = bytearray(f.read())

    # Corrupt the image_checksum field in header
    file_data[24:28] = b"\xff\xff\xff\xff"

    with open(output_path, "wb") as f:
        f.write(file_data)

    # Loading without CRC validation should succeed
    loaded = SparseImage.load_from_file(output_path, validate_crc=False)

    assert loaded.header is not None
    # But manual validation should fail
    assert loaded.validate_crc() is False


def test_sparse_image_crc_chunk_mismatch() -> None:
    """Test CRC validation when CRC32 chunk doesn't match header."""
    data = b"\xab" * 4096

    # Create sparse image with CRC
    sparse = SparseImage(block_size=4096, calculate_crc=True)
    sparse.from_binary(data)

    # Find and corrupt the CRC32 chunk
    for chunk in sparse.chunks:
        if chunk.chunk_type == SparseChunkType.CRC32:
            chunk.data = b"\x00\x00\x00\x00"
            break

    # Validation should fail
    assert sparse.validate_crc() is False


def test_sparse_image_no_crc_information() -> None:
    """Test validation when no CRC information is available."""
    data = b"\xba" * 4096

    # Create sparse image without CRC
    sparse = SparseImage(block_size=4096, calculate_crc=False)
    sparse.from_binary(data)

    # Should return True when no CRC info available
    assert sparse.validate_crc() is True


def test_sparse_image_crc_with_mixed_chunks() -> None:
    """Test CRC calculation and validation with mixed chunk types."""
    # Create mixed data: zeros, fill pattern, raw data
    zeros = b"\x00" * 4096
    fill = b"\xff\xff\xff\xff" * (4096 // 4)
    raw = bytes(range(256)) * 16

    data = zeros + fill + raw

    # Create sparse image with CRC
    sparse = SparseImage(block_size=4096, calculate_crc=True)
    sparse.from_binary(data)

    # Verify CRC is calculated
    assert sparse.header is not None
    assert sparse.header.image_checksum != 0

    # Validate CRC
    assert sparse.validate_crc() is True

    # Export, parse, and validate again
    exported = sparse.export()
    parsed = SparseImage.parse(exported, validate_crc=True)

    assert parsed.validate_crc() is True


def test_sparse_image_crc_roundtrip() -> None:
    """Test CRC preservation through export/parse cycle."""
    data = b"\x55" * 8192

    # Create sparse image with CRC
    original = SparseImage(block_size=4096, calculate_crc=True)
    original.from_binary(data)

    original_crc = original.header.image_checksum if original.header else 0

    # Export and parse
    exported = original.export()
    parsed = SparseImage.parse(exported, validate_crc=True)

    # CRC should be preserved
    assert parsed.header is not None
    assert parsed.header.image_checksum == original_crc
    assert parsed.validate_crc() is True


def test_sparse_image_get_info_with_crc() -> None:
    """Test get_info includes CRC information."""
    data = b"\x77" * 4096

    # Create sparse image with CRC
    sparse = SparseImage(block_size=4096, calculate_crc=True)
    sparse.from_binary(data)

    info = sparse.get_info()

    assert "Image CRC32:" in info
    assert "CRC32" in info  # CRC32 chunk should be listed


def test_sparse_image_validate_crc_no_header() -> None:
    """Test CRC validation fails when no header is available."""
    sparse = SparseImage(block_size=4096)

    with pytest.raises(SPSDKError, match="No sparse image header"):
        sparse.validate_crc()


def test_sparse_image_crc_with_large_file(tmpdir: str) -> None:
    """Test CRC calculation and validation with larger file."""
    # Create a larger test file
    data = bytearray()
    data.extend(b"\x00" * (4096 * 10))
    data.extend(b"\xde\xad\xbe\xef" * (4096 // 4 * 5))
    data.extend(bytes(range(256)) * (4096 // 256 * 3))

    # Create sparse image with CRC
    sparse = SparseImage(block_size=4096, calculate_crc=True)
    sparse.from_binary(bytes(data))

    # Verify CRC
    assert sparse.header is not None
    assert sparse.header.image_checksum != 0
    assert sparse.validate_crc() is True

    # Save and reload with validation
    output_path = os.path.join(tmpdir, "large_crc.sparse")
    sparse.save_to_file(output_path)

    loaded = SparseImage.load_from_file(output_path, validate_crc=True)
    assert loaded.validate_crc() is True


def test_sparse_image_crc_empty_data() -> None:
    """Test CRC calculation with empty data."""
    sparse = SparseImage(block_size=4096, calculate_crc=True)
    sparse.from_binary(b"")

    assert sparse.header is not None
    assert sparse.header.total_blocks == 0
    # CRC of empty data should be 0 (CRC32 of empty bytes)
    # The actual CRC32 of empty data is 0
    assert sparse.header.image_checksum == 0

    # But we should still have a CRC32 chunk
    crc_chunks = [c for c in sparse.chunks if c.chunk_type == SparseChunkType.CRC32]
    assert len(crc_chunks) == 1


def test_sparse_image_parse_crc_chunk_insufficient_data() -> None:
    """Test parsing CRC32 chunk with insufficient data."""
    # Create CRC32 chunk header but not enough data
    chunk_header = struct.pack(
        "<HHII",
        SparseChunkType.CRC32,
        0,
        0,
        SparseImageHeader.CHUNK_HEADER_SIZE + 4,
    )

    with pytest.raises(SPSDKParsingError, match="Insufficient data for CRC32 chunk"):
        SparseChunk.parse(chunk_header + b"\x00" * 2, 0)


def test_sparse_image_crc_only_header_checksum() -> None:
    """Test CRC validation with only header checksum (no CRC32 chunk)."""
    data = b"\x99" * 4096

    # Create sparse image with CRC
    sparse = SparseImage(block_size=4096, calculate_crc=True)
    sparse.from_binary(data)

    # Remove CRC32 chunk
    sparse.chunks = [c for c in sparse.chunks if c.chunk_type != SparseChunkType.CRC32]

    # Update header chunk count
    if sparse.header:
        sparse.header.total_chunks = len(sparse.chunks)

    # Validation should still work with header checksum
    assert sparse.validate_crc() is True


def test_sparse_image_crc_only_chunk_checksum() -> None:
    """Test CRC validation with only CRC32 chunk (no header checksum)."""
    data = b"\x88" * 4096

    # Create sparse image with CRC
    sparse = SparseImage(block_size=4096, calculate_crc=True)
    sparse.from_binary(data)

    original_crc = 0
    # Clear header checksum but keep CRC32 chunk
    if sparse.header:
        original_crc = sparse.header.image_checksum
        sparse.header.image_checksum = 0

    # Find CRC32 chunk and verify it has the correct value
    crc_chunk = None
    for chunk in sparse.chunks:
        if chunk.chunk_type == SparseChunkType.CRC32:
            crc_chunk = chunk
            break

    assert crc_chunk is not None
    assert crc_chunk.data is not None
    chunk_crc = struct.unpack("<I", crc_chunk.data)[0]
    assert chunk_crc == original_crc

    # Validation should work with CRC32 chunk
    assert sparse.validate_crc() is True
