#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Android SPARSE image format utilities.

This module provides functionality for handling Android fastboot's sparse image format,
enabling conversion between sparse and raw binary formats. The sparse format is used
to efficiently store and transfer images with large regions of repeated data or holes.

The implementation is based on the Android sparse image format specification:
https://android.googlesource.com/platform/system/core/+/master/libsparse/sparse_format.h
"""

import logging
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import BinaryIO, Optional

import colorama
from typing_extensions import Self

from spsdk.crypto.crc import CrcAlg, from_crc_algorithm
from spsdk.exceptions import SPSDKError, SPSDKParsingError, SPSDKValueError
from spsdk.utils.misc import align_block, write_file

logger = logging.getLogger(__name__)


SPARSE_DEFAULT_BLOCK_SIZE = 4096  # Default block size for sparse images


class SparseChunkType(IntEnum):
    """Sparse image chunk types.

    Defines the different types of chunks that can appear in a sparse image format.
    Each chunk type represents a different way of encoding data blocks.
    """

    RAW = 0xCAC1  # Raw data chunk
    FILL = 0xCAC2  # Fill chunk (repeated 4-byte value)
    DONT_CARE = 0xCAC3  # Don't care chunk (hole/skip)
    CRC32 = 0xCAC4  # CRC32 chunk


class SparseImageHeader:
    """Android SPARSE image file header.

    This class represents the main header of a sparse image file, containing
    metadata about the image structure, block sizes, and chunk information.

    :cvar MAGIC: Magic number identifying sparse image format (0xED26FF3A).
    :cvar MAJOR_VERSION: Major version of sparse format (1).
    :cvar MINOR_VERSION: Minor version of sparse format (0).
    :cvar HEADER_SIZE: Size of the sparse header structure in bytes (28).
    :cvar CHUNK_HEADER_SIZE: Size of each chunk header in bytes (12).
    """

    MAGIC = 0xED26FF3A
    MAJOR_VERSION = 1
    MINOR_VERSION = 0
    HEADER_SIZE = 28
    CHUNK_HEADER_SIZE = 12

    def __init__(
        self,
        block_size: int = SPARSE_DEFAULT_BLOCK_SIZE,
        total_blocks: int = 0,
        total_chunks: int = 0,
        image_checksum: int = 0,
    ) -> None:
        """Initialize sparse image header.

        :param block_size: Size of each block in bytes, defaults to 4096.
        :param total_blocks: Total number of blocks in the output image.
        :param total_chunks: Number of chunks in the sparse image.
        :param image_checksum: CRC32 checksum of the original image.
        """
        self.magic = self.MAGIC
        self.major_version = self.MAJOR_VERSION
        self.minor_version = self.MINOR_VERSION
        self.file_hdr_sz = self.HEADER_SIZE
        self.chunk_hdr_sz = self.CHUNK_HEADER_SIZE
        self.block_size = block_size
        self.total_blocks = total_blocks
        self.total_chunks = total_chunks
        self.image_checksum = image_checksum

    def __repr__(self) -> str:
        """Get string representation of the header.

        :return: String representation with key header information.
        """
        return (
            f"<SparseImageHeader magic=0x{self.magic:08X} "
            f"block_size={self.block_size} "
            f"total_blocks={self.total_blocks} "
            f"total_chunks={self.total_chunks}>"
        )

    def export(self) -> bytes:
        """Export header to binary format.

        :return: Binary representation of the sparse image header.
        """
        return struct.pack(
            "<IHHHHIIII",
            self.magic,
            self.major_version,
            self.minor_version,
            self.file_hdr_sz,
            self.chunk_hdr_sz,
            self.block_size,
            self.total_blocks,
            self.total_chunks,
            self.image_checksum,
        )

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse header from binary data.

        :param data: Binary data containing the sparse image header.
        :raises SPSDKParsingError: Invalid header magic or size.
        :return: Parsed SparseImageHeader instance.
        """
        if len(data) < cls.HEADER_SIZE:
            raise SPSDKParsingError(
                f"Insufficient data for sparse header: {len(data)} < {cls.HEADER_SIZE}"
            )

        (
            magic,
            major_version,
            minor_version,
            file_hdr_sz,
            chunk_hdr_sz,
            block_size,
            total_blocks,
            total_chunks,
            image_checksum,
        ) = struct.unpack("<IHHHHIIII", data[: cls.HEADER_SIZE])

        if magic != cls.MAGIC:
            raise SPSDKParsingError(f"Invalid sparse image magic: 0x{magic:08X}")

        if file_hdr_sz != cls.HEADER_SIZE:
            raise SPSDKParsingError(f"Invalid header size: {file_hdr_sz}")

        if chunk_hdr_sz != cls.CHUNK_HEADER_SIZE:
            raise SPSDKParsingError(f"Invalid chunk header size: {chunk_hdr_sz}")

        header = cls(
            block_size=block_size,
            total_blocks=total_blocks,
            total_chunks=total_chunks,
            image_checksum=image_checksum,
        )
        header.major_version = major_version
        header.minor_version = minor_version

        return header


class SparseChunk:
    """Sparse image chunk representation.

    This class represents a single chunk in a sparse image, which can be raw data,
    a fill pattern, or a don't-care region.
    """

    def __init__(
        self,
        chunk_type: SparseChunkType,
        chunk_blocks: int,
        total_size: int,
        data: Optional[bytes] = None,
    ) -> None:
        """Initialize sparse chunk.

        :param chunk_type: Type of the chunk (RAW, FILL, DONT_CARE, CRC32).
        :param chunk_blocks: Number of blocks this chunk represents.
        :param total_size: Total size of chunk data in bytes.
        :param data: Optional chunk data (for RAW and FILL chunks).
        """
        self.chunk_type = chunk_type
        self.chunk_blocks = chunk_blocks
        self.total_size = total_size
        self.data = data

    def __repr__(self) -> str:
        """Get string representation of the chunk.

        :return: String representation with chunk type and size information.
        """
        return (
            f"<SparseChunk type={self.chunk_type.name} "
            f"blocks={self.chunk_blocks} "
            f"size={self.total_size}>"
        )

    def export(self) -> bytes:
        """Export chunk header and data to binary format.

        :return: Binary representation of chunk header and data.
        """
        header = struct.pack(
            "<HHII",
            self.chunk_type,
            0,  # Reserved field
            self.chunk_blocks,
            self.total_size,
        )
        if self.data:
            return header + self.data
        return header

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> tuple[Self, int]:
        """Parse chunk from binary data.

        :param data: Binary data containing the chunk.
        :param offset: Offset in data where chunk starts.
        :raises SPSDKParsingError: Invalid chunk data.
        :return: Tuple of (parsed SparseChunk instance, bytes consumed).
        """
        if len(data) - offset < SparseImageHeader.CHUNK_HEADER_SIZE:
            raise SPSDKParsingError("Insufficient data for chunk header")

        chunk_type, _, chunk_blocks, total_size = struct.unpack(
            "<HHII", data[offset : offset + SparseImageHeader.CHUNK_HEADER_SIZE]
        )

        offset += SparseImageHeader.CHUNK_HEADER_SIZE
        chunk_data = None
        bytes_consumed = SparseImageHeader.CHUNK_HEADER_SIZE

        try:
            chunk_type_enum = SparseChunkType(chunk_type)
        except ValueError as e:
            raise SPSDKParsingError(f"Unknown chunk type: 0x{chunk_type:04X}") from e

        if chunk_type_enum == SparseChunkType.RAW:
            data_size = total_size - SparseImageHeader.CHUNK_HEADER_SIZE
            if len(data) - offset < data_size:
                raise SPSDKParsingError("Insufficient data for RAW chunk")
            chunk_data = data[offset : offset + data_size]
            bytes_consumed += data_size

        elif chunk_type_enum == SparseChunkType.FILL:
            if len(data) - offset < 4:
                raise SPSDKParsingError("Insufficient data for FILL chunk")
            chunk_data = data[offset : offset + 4]
            bytes_consumed += 4

        elif chunk_type_enum == SparseChunkType.CRC32:
            if len(data) - offset < 4:
                raise SPSDKParsingError("Insufficient data for CRC32 chunk")
            chunk_data = data[offset : offset + 4]
            bytes_consumed += 4

        return cls(chunk_type_enum, chunk_blocks, total_size, chunk_data), bytes_consumed


@dataclass
class ChunkBuilderContext:
    """Context for building sparse chunks across multiple data blocks.

    This class maintains state between multiple calls to add_binary_chunks,
    allowing proper detection and merging of consecutive fill/zero blocks.
    """

    # Current chunk being built
    current_chunk_type: Optional[SparseChunkType] = None
    current_fill_value: Optional[bytes] = None
    current_blocks: int = 0
    current_data: bytearray = field(default_factory=bytearray)

    # Total blocks processed
    total_blocks: int = 0

    def reset(self) -> None:
        """Reset context to initial state."""
        self.current_chunk_type = None
        self.current_fill_value = None
        self.current_blocks = 0
        self.current_data.clear()
        self.total_blocks = 0

    def has_pending_chunk(self) -> bool:
        """Check if there's a pending chunk to be finalized."""
        return self.current_chunk_type is not None


class SparseImage:
    """Android SPARSE image format handler.

    This class provides functionality to create, parse, and convert between
    sparse and raw binary image formats. It integrates with SPSDK's BinaryImage
    class for seamless image manipulation.
    """

    def __init__(
        self, block_size: int = SPARSE_DEFAULT_BLOCK_SIZE, calculate_crc: bool = False
    ) -> None:
        """Initialize sparse image handler.

        :param block_size: Block size in bytes, defaults to 4096.
        :param calculate_crc: If True, calculate and add CRC32 checksum when creating sparse images.
        :raises SPSDKValueError: Invalid block size (must be power of 2).
        """
        if block_size <= 0 or (block_size & (block_size - 1)) != 0:
            raise SPSDKValueError(f"Block size must be a power of 2: {block_size}")

        self.block_size = block_size
        self.calculate_crc = calculate_crc
        self.header: Optional[SparseImageHeader] = None
        self.chunks: list[SparseChunk] = []

    def __repr__(self) -> str:
        """Get string representation of the sparse image.

        :return: String representation with header and chunk information.
        """
        return f"<SparseImage block_size={self.block_size} chunks={len(self.chunks)}>"

    def _calculate_image_crc32(self, data: bytes) -> int:
        """Calculate CRC32 checksum of the image data.

        :param data: Raw binary data to calculate CRC for.
        :return: CRC32 checksum value.
        """
        crc_obj = from_crc_algorithm(CrcAlg.CRC32)
        return crc_obj.calculate(data)

    def _finalize_pending_chunk(self, context: ChunkBuilderContext) -> None:
        """Finalize and append the pending chunk from context.

        :param context: Chunk builder context containing pending chunk data.
        """
        if not context.has_pending_chunk():
            return

        if context.current_chunk_type == SparseChunkType.DONT_CARE:
            chunk = SparseChunk(
                SparseChunkType.DONT_CARE,
                context.current_blocks,
                SparseImageHeader.CHUNK_HEADER_SIZE,
            )
        elif context.current_chunk_type == SparseChunkType.FILL:
            chunk = SparseChunk(
                SparseChunkType.FILL,
                context.current_blocks,
                SparseImageHeader.CHUNK_HEADER_SIZE + 4,
                context.current_fill_value,
            )
        elif context.current_chunk_type == SparseChunkType.RAW:
            chunk = SparseChunk(
                SparseChunkType.RAW,
                context.current_blocks,
                SparseImageHeader.CHUNK_HEADER_SIZE + len(context.current_data),
                bytes(context.current_data),
            )
        else:
            return

        self.chunks.append(chunk)

    def _add_binary_chunks(self, data: bytes, context: ChunkBuilderContext) -> None:
        """Process binary data and add chunks using provided context.

        This method can be called multiple times with different data blocks.
        It maintains state in the context parameter to properly merge consecutive
        fill/zero blocks across multiple invocations.

        :param data: Raw binary data to convert to chunks (must be block-aligned).
        :param context: Chunk builder context for maintaining state between calls.
        :raises SPSDKValueError: Data length is not aligned to block size.
        """
        if len(data) == 0:
            return

        # Ensure data is block-aligned
        if len(data) % self.block_size != 0:
            raise SPSDKValueError(
                f"Data length {len(data)} is not aligned to block size {self.block_size}"
            )

        i = 0
        is_fill = False
        while i < len(data):
            block_data = data[i : i + self.block_size]
            if self.block_size > 4:
                fill_value = block_data[:4]
                is_fill = all(
                    block_data[j : j + 4] == fill_value for j in range(0, len(block_data), 4)
                )

            if is_fill:
                # Determine chunk type (DONT_CARE for zeros, FILL for other patterns)
                if fill_value == b"\x00" * 4:
                    chunk_type = SparseChunkType.DONT_CARE
                else:
                    chunk_type = SparseChunkType.FILL

                # Check if we can continue the current chunk
                if context.current_chunk_type == chunk_type and (
                    chunk_type == SparseChunkType.DONT_CARE
                    or context.current_fill_value == fill_value
                ):
                    # Continue current chunk
                    context.current_blocks += 1
                else:
                    # Finalize previous chunk and start new one
                    self._finalize_pending_chunk(context)
                    context.current_chunk_type = chunk_type
                    context.current_fill_value = (
                        fill_value if chunk_type == SparseChunkType.FILL else None
                    )
                    context.current_blocks = 1
            else:
                # RAW data block
                if context.current_chunk_type == SparseChunkType.RAW:
                    # Continue current RAW chunk
                    context.current_data.extend(block_data)
                    context.current_blocks += 1
                else:
                    # Finalize previous chunk and start new RAW chunk
                    self._finalize_pending_chunk(context)
                    context.current_chunk_type = SparseChunkType.RAW
                    context.current_data = bytearray(block_data)
                    context.current_blocks = 1

            context.total_blocks += 1
            i += self.block_size

    def from_binary(self, data: bytes) -> None:
        """Create sparse image from raw binary data.

        The method analyzes the input binary data and creates an optimized sparse
        representation by detecting repeated patterns and zero-filled regions.

        :param data: Raw binary data to convert to sparse format.
        """
        self.chunks.clear()

        # Calculate CRC32 of original data if requested
        image_checksum = 0
        if self.calculate_crc:
            image_checksum = self._calculate_image_crc32(data)
            logger.debug(f"Calculated image CRC32: 0x{image_checksum:08X}")

        # Align data to block size
        aligned_data = align_block(data, self.block_size)

        # Create context and process binary data
        context = ChunkBuilderContext()
        self._add_binary_chunks(aligned_data, context)

        # Finalize any pending chunk
        self.finalize_sparse_image(context, image_checksum)

    def to_binary(self) -> bytes:
        """Convert sparse image to raw binary data.

        :raises SPSDKError: No header or chunks available.
        :return: Raw binary data reconstructed from sparse format.
        """
        if not self.header:
            raise SPSDKError("No sparse image header available")

        if not self.chunks:
            raise SPSDKError("No chunks available in sparse image")

        output = bytearray(self.header.total_blocks * self.block_size)
        offset = 0

        for chunk in self.chunks:
            chunk_size = chunk.chunk_blocks * self.block_size

            if chunk.chunk_type == SparseChunkType.RAW:
                if not chunk.data:
                    raise SPSDKError("RAW chunk missing data")
                output[offset : offset + len(chunk.data)] = chunk.data
                offset += chunk_size

            elif chunk.chunk_type == SparseChunkType.FILL:
                if not chunk.data or len(chunk.data) != 4:
                    raise SPSDKError("FILL chunk missing or invalid fill value")
                fill_value = chunk.data
                for i in range(0, chunk_size, 4):
                    output[offset + i : offset + i + 4] = fill_value
                offset += chunk_size

            elif chunk.chunk_type == SparseChunkType.DONT_CARE:
                # Already zero-filled, just advance offset
                offset += chunk_size

            elif chunk.chunk_type == SparseChunkType.CRC32:
                # CRC32 chunks don't contribute to output data
                pass

        return bytes(output)

    def validate_crc(self) -> bool:
        """Validate CRC32 checksum of the sparse image.

        Reconstructs the binary data and compares its CRC32 with the stored checksum
        in the header and/or CRC32 chunk.

        :raises SPSDKError: No header available.
        :return: True if CRC validation passes, False otherwise.
        """
        if not self.header:
            raise SPSDKError("No sparse image header available")

        # Find CRC32 chunk if present
        crc_chunk = None
        for chunk in self.chunks:
            if chunk.chunk_type == SparseChunkType.CRC32:
                crc_chunk = chunk
                break

        # If no CRC information available, consider it valid
        if self.header.image_checksum == 0 and crc_chunk is None:
            logger.debug("No CRC information available in sparse image")
            return True

        # Reconstruct binary data
        binary_data = self.to_binary()

        # Calculate CRC32 of reconstructed data
        calculated_crc = self._calculate_image_crc32(binary_data)

        # Validate against header checksum
        if self.header.image_checksum != 0:
            if calculated_crc != self.header.image_checksum:
                logger.error(
                    f"Header CRC mismatch: calculated=0x{calculated_crc:08X}, "
                    f"expected=0x{self.header.image_checksum:08X}"
                )
                return False
            logger.debug(f"Header CRC validation passed: 0x{calculated_crc:08X}")

        # Validate against CRC32 chunk
        if crc_chunk and crc_chunk.data:
            chunk_crc = struct.unpack("<I", crc_chunk.data)[0]
            if calculated_crc != chunk_crc:
                logger.error(
                    f"CRC32 chunk mismatch: calculated=0x{calculated_crc:08X}, "
                    f"expected=0x{chunk_crc:08X}"
                )
                return False
            logger.debug(f"CRC32 chunk validation passed: 0x{calculated_crc:08X}")

        return True

    def export(self) -> bytes:
        """Export sparse image to binary format.

        :raises SPSDKError: No header available.
        :return: Complete sparse image in binary format.
        """
        if not self.header:
            raise SPSDKError("No sparse image header available")

        output = bytearray()
        output.extend(self.header.export())

        for chunk in self.chunks:
            output.extend(chunk.export())

        return bytes(output)

    @classmethod
    def parse(cls, data: bytes, validate_crc: bool = True) -> Self:
        """Parse sparse image from binary data.

        :param data: Binary data containing sparse image.
        :param validate_crc: If True, validate CRC32 checksum after parsing.
        :raises SPSDKParsingError: Invalid sparse image format.
        :raises SPSDKError: CRC validation failed.
        :return: Parsed SparseImage instance.
        """
        header = SparseImageHeader.parse(data)

        sparse_image = cls(block_size=header.block_size)
        sparse_image.header = header

        offset = SparseImageHeader.HEADER_SIZE

        for _ in range(header.total_chunks):
            chunk, consumed = SparseChunk.parse(data, offset)
            sparse_image.chunks.append(chunk)
            offset += consumed

        # Validate CRC if requested
        if validate_crc:
            if not sparse_image.validate_crc():
                raise SPSDKError("CRC validation failed for sparse image")

        return sparse_image

    @classmethod
    def load_from_file(cls, path: str, validate_crc: bool = True) -> Self:
        """Load sparse image from file.

        :param path: Path to the sparse image file.
        :param validate_crc: If True, validate CRC32 checksum after loading.
        :raises SPSDKError: File cannot be loaded or CRC validation failed.
        :return: Parsed SparseImage instance.
        """
        try:
            with open(path, "rb") as f:
                data = f.read()
        except Exception as e:
            raise SPSDKError(f"Cannot load sparse image from {path}: {e}") from e

        return cls.parse(data, validate_crc=validate_crc)

    def save_to_file(self, path: str) -> None:
        """Save sparse image to file.

        :param path: Path where to save the sparse image.
        """
        data = self.export()
        write_file(data, path, mode="wb")

    def get_info(self, no_color: bool = False) -> str:
        """Get human-readable information about the sparse image.

        :param no_color: Disable color output in the information display.
        :return: Formatted string with sparse image details.
        """
        if not self.header:
            return "No sparse image header available"

        info = []
        info.append("Sparse Image Information:")
        info.append(f"  Block Size:   {self.header.block_size} bytes")
        info.append(f"  Total Blocks: {self.header.total_blocks}")
        info.append(f"  Total Chunks: {self.header.total_chunks}")
        info.append(f"  Image Size:   {self.header.total_blocks * self.header.block_size} bytes")

        if self.header.image_checksum != 0:
            info.append(f"  Image CRC32:  0x{self.header.image_checksum:08X}")

        info.append("\nChunks:")

        # Find the maximum width needed for chunk type names
        max_type_width = max((len(chunk.chunk_type.name) for chunk in self.chunks), default=10)

        # Find the maximum width needed for block counts
        max_blocks_width = max((len(str(chunk.chunk_blocks)) for chunk in self.chunks), default=5)

        for i, chunk in enumerate(self.chunks):
            chunk_size = chunk.chunk_blocks * self.header.block_size

            # Color codes for different chunk types (only if colors are enabled)
            if no_color:
                color = ""
                color_reset = ""
            else:
                color_reset = colorama.Style.RESET_ALL
                if chunk.chunk_type == SparseChunkType.RAW:
                    color = colorama.Fore.GREEN
                elif chunk.chunk_type == SparseChunkType.FILL:
                    color = colorama.Fore.YELLOW
                elif chunk.chunk_type == SparseChunkType.DONT_CARE:
                    color = colorama.Fore.CYAN
                elif chunk.chunk_type == SparseChunkType.CRC32:
                    color = colorama.Fore.MAGENTA
                else:
                    color = ""
                    color_reset = ""

            # Format chunk index with padding
            chunk_index = f"[{i:3d}]"

            # Format chunk type with padding and color
            chunk_type_str = f"{color}{chunk.chunk_type.name:<{max_type_width}}{color_reset}"

            if chunk.chunk_type == SparseChunkType.CRC32 and chunk.data:
                crc_value = struct.unpack("<I", chunk.data)[0]
                info.append(f"  {chunk_index} {chunk_type_str}: CRC32=0x{crc_value:08X}")
            else:
                # Format blocks with padding
                blocks_str = f"{chunk.chunk_blocks:>{max_blocks_width}}"
                info.append(
                    f"  {chunk_index} {chunk_type_str}: "
                    f"{blocks_str} blocks ({chunk_size:>10,} bytes)"
                )

                # Add data preview for FILL chunks
                if chunk.chunk_type == SparseChunkType.FILL and chunk.data:
                    fill_value = struct.unpack("<I", chunk.data)[0]
                    info.append(f"         {'':>{max_type_width}}  Fill value: 0x{fill_value:08X}")

        return "\n".join(info)

    def finalize_sparse_image(
        self, context: ChunkBuilderContext, image_checksum: Optional[int] = None
    ) -> None:
        """Finalize the sparse image creation process.

        This method completes the sparse image by finalizing any pending chunks,
        optionally adding a CRC32 chunk, and creating the header. It's designed
        to be called after one or more calls to _add_binary_chunks().

        :param context: Chunk builder context containing the current state.
        :param image_checksum: Pre-calculated CRC32 checksum of the original image data.
                            If 0 and calculate_crc is True, no CRC chunk is added.
        """
        # Finalize any pending chunk
        self._finalize_pending_chunk(context)

        total_blocks = context.total_blocks

        # Add CRC32 chunk if requested and checksum is provided
        if self.calculate_crc and image_checksum is not None:
            crc_data = struct.pack("<I", image_checksum)
            crc_chunk = SparseChunk(
                SparseChunkType.CRC32,
                0,
                SparseImageHeader.CHUNK_HEADER_SIZE + 4,
                crc_data,
            )
            self.chunks.append(crc_chunk)
        else:
            image_checksum = 0

        # Create header
        self.header = SparseImageHeader(
            block_size=self.block_size,
            total_blocks=total_blocks,
            total_chunks=len(self.chunks),
            image_checksum=image_checksum,
        )


class SparseImageReader:
    """Efficient reader for sparse images with random access support.

    This class provides efficient random access to sparse image data without
    loading the entire image into memory. It maintains an index of chunks
    and their corresponding offsets in both the sparse file and the output
    binary image.
    """

    def __init__(self, file_path: str, validate_header: bool = True) -> None:
        """Initialize sparse image reader with file context.

        :param file_path: Path to the sparse image file.
        :param validate_header: If True, validate header during initialization.
        :raises SPSDKError: Invalid sparse image file.
        """
        self.file_path = file_path
        self.file_handle: Optional[BinaryIO] = None
        self.header: Optional[SparseImageHeader] = None
        self.chunk_index: list[ChunkIndexEntry] = []

        # Open file and parse header
        self._open_and_parse_header(validate_header)

    def _open_and_parse_header(self, validate_header: bool) -> None:
        """Open file and parse sparse image header and build chunk index.

        :param validate_header: If True, validate header structure.
        :raises SPSDKError: Cannot open file or invalid header.
        """
        try:
            self.file_handle = open(self.file_path, "rb")
        except Exception as e:
            raise SPSDKError(f"Cannot open sparse image file {self.file_path}: {e}") from e

        # Read and parse header
        header_data = self.file_handle.read(SparseImageHeader.HEADER_SIZE)
        self.header = SparseImageHeader.parse(header_data)

        if validate_header:
            if self.header.magic != SparseImageHeader.MAGIC:
                raise SPSDKError("Invalid sparse image magic number")

        # Build chunk index for efficient random access
        self._build_chunk_index()

    def _build_chunk_index(self) -> None:
        """Build index of chunks with their file and output offsets.

        This creates a lookup table that maps output binary offsets to
        chunk locations in the sparse file for efficient random access.
        """
        if not self.header or not self.file_handle:
            raise SPSDKError("Header not initialized")

        file_offset = SparseImageHeader.HEADER_SIZE
        output_offset = 0

        for _ in range(self.header.total_chunks):
            # Read chunk header
            self.file_handle.seek(file_offset)
            chunk_header_data = self.file_handle.read(SparseImageHeader.CHUNK_HEADER_SIZE)

            chunk_type, _, chunk_blocks, total_size = struct.unpack("<HHII", chunk_header_data)

            try:
                chunk_type_enum = SparseChunkType(chunk_type)
            except ValueError as e:
                raise SPSDKParsingError(f"Unknown chunk type: 0x{chunk_type:04X}") from e

            # Calculate output size for this chunk
            output_size = chunk_blocks * self.header.block_size

            # Create index entry
            entry = ChunkIndexEntry(
                chunk_type=chunk_type_enum,
                file_offset=file_offset,
                output_offset=output_offset,
                chunk_blocks=chunk_blocks,
                total_size=total_size,
                output_size=output_size,
            )

            self.chunk_index.append(entry)

            # Update offsets
            file_offset += total_size
            output_offset += output_size

    def read(self, offset: int, size: int) -> bytes:
        """Read data from sparse image at specified offset.

        This method efficiently reads data from the sparse image without
        loading the entire image into memory. It handles chunk boundaries
        and different chunk types transparently.

        :param offset: Offset in the final binary image (not sparse file offset).
        :param size: Number of bytes to read.
        :raises SPSDKError: Invalid offset or size, or file not open.
        :return: Requested data as bytes.
        """
        if not self.header or not self.file_handle:
            raise SPSDKError("Sparse image not properly initialized")

        # Validate parameters
        total_image_size = self.header.total_blocks * self.header.block_size
        if offset < 0 or offset >= total_image_size:
            raise SPSDKValueError(f"Offset {offset} out of range (0-{total_image_size - 1})")

        if size <= 0:
            raise SPSDKValueError(f"Size must be positive, got {size}")

        # Adjust size if it exceeds image bounds
        if offset + size > total_image_size:
            size = total_image_size - offset
            logger.warning(f"Read size adjusted to {size} bytes to fit within image bounds")

        result = bytearray()
        bytes_remaining = size
        current_offset = offset

        # Find starting chunk
        chunk_idx = self._find_chunk_for_offset(current_offset)

        while bytes_remaining > 0 and chunk_idx < len(self.chunk_index):
            entry = self.chunk_index[chunk_idx]

            # Calculate position within this chunk
            chunk_start = entry.output_offset
            chunk_end = chunk_start + entry.output_size

            # Skip if current offset is beyond this chunk
            if current_offset >= chunk_end:
                chunk_idx += 1
                continue

            # Calculate how much to read from this chunk
            offset_in_chunk = current_offset - chunk_start
            bytes_available = chunk_end - current_offset
            bytes_to_read = min(bytes_remaining, bytes_available)

            # Read data based on chunk type
            chunk_data = self._read_chunk_data(entry, offset_in_chunk, bytes_to_read)
            result.extend(chunk_data)

            # Update counters
            bytes_remaining -= bytes_to_read
            current_offset += bytes_to_read
            chunk_idx += 1

        return bytes(result)

    def _find_chunk_for_offset(self, offset: int) -> int:
        """Find chunk index that contains the given output offset.

        Uses binary search for efficient lookup.

        :param offset: Offset in the output binary image.
        :return: Index of the chunk containing this offset.
        """
        left, right = 0, len(self.chunk_index) - 1

        while left <= right:
            mid = (left + right) // 2
            entry = self.chunk_index[mid]

            if offset < entry.output_offset:
                right = mid - 1
            elif offset >= entry.output_offset + entry.output_size:
                left = mid + 1
            else:
                return mid

        # If not found, return the next chunk
        return left

    def _read_chunk_data(self, entry: "ChunkIndexEntry", offset_in_chunk: int, size: int) -> bytes:
        """Read data from a specific chunk.

        :param entry: Chunk index entry.
        :param offset_in_chunk: Offset within the chunk's output data.
        :param size: Number of bytes to read.
        :return: Chunk data as bytes.
        """
        if not self.file_handle:
            raise SPSDKError("File handle not available")

        if entry.chunk_type == SparseChunkType.RAW:
            # Read directly from file
            data_offset = entry.file_offset + SparseImageHeader.CHUNK_HEADER_SIZE + offset_in_chunk
            self.file_handle.seek(data_offset)
            return self.file_handle.read(size)

        if entry.chunk_type == SparseChunkType.FILL:
            # Read fill value and repeat
            fill_offset = entry.file_offset + SparseImageHeader.CHUNK_HEADER_SIZE
            self.file_handle.seek(fill_offset)
            fill_value = self.file_handle.read(4)

            # Generate filled data
            result = bytearray()
            current_pos = offset_in_chunk

            while len(result) < size:
                # Calculate position within 4-byte fill pattern
                pattern_offset = current_pos % 4
                bytes_from_pattern = min(4 - pattern_offset, size - len(result))

                result.extend(fill_value[pattern_offset : pattern_offset + bytes_from_pattern])
                current_pos += bytes_from_pattern

            return bytes(result)

        if entry.chunk_type == SparseChunkType.DONT_CARE:
            # Return zeros
            return bytes(size)

        if entry.chunk_type == SparseChunkType.CRC32:
            # CRC32 chunks don't contribute to output
            return b""

        raise SPSDKError(f"Unsupported chunk type: {entry.chunk_type}")

    def modify(self, offset: int, data: bytes, update_crc: bool = True) -> None:
        """Modify data in sparse image at specified offset.

        This method allows in-place modification of RAW chunks in the sparse image.
        Attempts to modify data in FILL, DONT_CARE, or CRC32 chunks will raise an
        exception. After modification, the CRC32 checksum is automatically updated
        if present and update_crc is True.

        :param offset: Offset in the final binary image where modification starts.
        :param data: Data to write at the specified offset.
        :param update_crc: If True, update CRC32 checksum after modification.
        :raises SPSDKError: Invalid offset, file not open, or attempting to modify non-RAW chunk.
        :raises SPSDKValueError: Offset out of range or modification spans non-RAW chunks.
        """
        if not self.header or not self.file_handle:
            raise SPSDKError("Sparse image not properly initialized")

        # Validate offset
        total_image_size = self.header.total_blocks * self.header.block_size
        if offset < 0 or offset >= total_image_size:
            raise SPSDKValueError(f"Offset {offset} out of range (0-{total_image_size - 1})")

        if len(data) == 0:
            return  # Nothing to modify

        # Check if modification exceeds image bounds
        if offset + len(data) > total_image_size:
            raise SPSDKValueError(
                f"Modification at offset {offset} with size {len(data)} exceeds image bounds"
            )

        # Find all chunks affected by this modification
        affected_chunks = self._find_affected_chunks(offset, len(data))

        # Validate that all affected chunks are RAW type
        for chunk_idx, chunk_offset, chunk_size in affected_chunks:
            entry = self.chunk_index[chunk_idx]
            if entry.chunk_type != SparseChunkType.RAW:
                raise SPSDKError(
                    f"Cannot modify {entry.chunk_type.name} chunk at output offset "
                    f"0x{entry.output_offset:08X}. Only RAW chunks can be modified."
                )

        # Close the file handle temporarily to reopen in read-write mode
        self.file_handle.close()

        try:
            # Reopen file in read-write mode
            self.file_handle = open(self.file_path, "r+b")

            # Perform modifications
            bytes_written = 0
            for chunk_idx, chunk_offset, chunk_size in affected_chunks:
                entry = self.chunk_index[chunk_idx]

                # Calculate file position for this chunk's data
                file_offset = entry.file_offset + SparseImageHeader.CHUNK_HEADER_SIZE + chunk_offset

                # Write data to file
                self.file_handle.seek(file_offset)
                chunk_data = data[bytes_written : bytes_written + chunk_size]
                self.file_handle.write(chunk_data)
                bytes_written += chunk_size

                logger.debug(
                    f"Modified RAW chunk at file offset 0x{file_offset:08X}, "
                    f"size {chunk_size} bytes"
                )

            # Update CRC if requested and available
            if update_crc and (self.header.image_checksum != 0 or self._has_crc_chunk()):
                self._update_crc()

            # Flush changes to disk
            self.file_handle.flush()

        except Exception as e:
            # Reopen in read-only mode on error
            self.file_handle.close()
            self.file_handle = open(self.file_path, "rb")
            raise SPSDKError(f"Failed to modify sparse image: {e}") from e

        # Reopen in read-only mode after successful modification
        self.file_handle.close()
        self.file_handle = open(self.file_path, "rb")

    def _find_affected_chunks(self, offset: int, size: int) -> list[tuple[int, int, int]]:
        """Find all chunks affected by a modification operation.

        :param offset: Offset in the output binary image.
        :param size: Size of the modification in bytes.
        :return: List of tuples (chunk_index, offset_in_chunk, size_in_chunk).
        """
        affected = []
        bytes_remaining = size
        current_offset = offset

        # Find starting chunk
        chunk_idx = self._find_chunk_for_offset(current_offset)

        while bytes_remaining > 0 and chunk_idx < len(self.chunk_index):
            entry = self.chunk_index[chunk_idx]

            # Calculate position within this chunk
            chunk_start = entry.output_offset
            chunk_end = chunk_start + entry.output_size

            # Skip if current offset is beyond this chunk
            if current_offset >= chunk_end:
                chunk_idx += 1
                continue

            # Calculate how much data affects this chunk
            offset_in_chunk = current_offset - chunk_start
            bytes_available = chunk_end - current_offset
            bytes_in_chunk = min(bytes_remaining, bytes_available)

            affected.append((chunk_idx, offset_in_chunk, bytes_in_chunk))

            # Update counters
            bytes_remaining -= bytes_in_chunk
            current_offset += bytes_in_chunk
            chunk_idx += 1

        return affected

    def _has_crc_chunk(self) -> bool:
        """Check if sparse image has a CRC32 chunk.

        :return: True if CRC32 chunk exists, False otherwise.
        """
        for entry in self.chunk_index:
            if entry.chunk_type == SparseChunkType.CRC32:
                return True
        return False

    def _update_crc(self) -> None:
        """Update CRC32 checksum in header and/or CRC32 chunk.

        This method recalculates the CRC32 of the entire reconstructed binary
        and updates both the header checksum and CRC32 chunk if present.

        :raises SPSDKError: Failed to update CRC.
        """
        if not self.header or not self.file_handle:
            raise SPSDKError("Cannot update CRC: sparse image not initialized")

        logger.debug("Recalculating CRC32 checksum after modification")

        # Read entire image to calculate CRC
        total_size = self.header.total_blocks * self.header.block_size

        # Read in chunks to avoid loading entire image into memory at once
        chunk_size = 1024 * 1024  # 1MB chunks
        crc_obj = from_crc_algorithm(CrcAlg.CRC32)

        offset = 0
        while offset < total_size:
            size = min(chunk_size, total_size - offset)
            data = self.read(offset=offset, size=size)
            crc_obj.update(data)
            offset += size

        new_crc = crc_obj.finalize()
        logger.debug(f"New CRC32: 0x{new_crc:08X}")

        # Update header checksum if it was non-zero
        if self.header.image_checksum != 0:
            self.header.image_checksum = new_crc

            # Write updated header to file
            self.file_handle.seek(0)
            self.file_handle.write(self.header.export())
            logger.debug("Updated CRC32 in header")

        # Update CRC32 chunk if present
        for entry in self.chunk_index:
            if entry.chunk_type == SparseChunkType.CRC32:
                crc_data = struct.pack("<I", new_crc)
                crc_offset = entry.file_offset + SparseImageHeader.CHUNK_HEADER_SIZE
                self.file_handle.seek(crc_offset)
                self.file_handle.write(crc_data)
                logger.debug("Updated CRC32 chunk")
                break

    def __enter__(self) -> Self:
        """Enter context manager.

        :return: Self instance for context manager usage.
        """
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # type: ignore
        """Exit context manager and close file.

        :param exc_type: Exception type if an exception occurred.
        :param exc_val: Exception value if an exception occurred.
        :param exc_tb: Exception traceback if an exception occurred.
        """
        self.close()

    def close(self) -> None:
        """Close the sparse image file."""
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None

    def get_total_size(self) -> int:
        """Get total size of the output binary image.

        :return: Total size in bytes.
        """
        if not self.header:
            raise SPSDKError("Header not initialized")
        return self.header.total_blocks * self.header.block_size

    def __repr__(self) -> str:
        """Get string representation.

        :return: String representation with file path and size info.
        """
        if self.header:
            return (
                f"<SparseImageReader file='{self.file_path}' "
                f"size={self.get_total_size()} chunks={len(self.chunk_index)}>"
            )
        return f"<SparseImageReader file='{self.file_path}' (not initialized)>"


@dataclass
class ChunkIndexEntry:
    """Index entry for efficient chunk lookup.

    This dataclass stores metadata about a chunk's location in both
    the sparse file and the output binary image.
    """

    chunk_type: SparseChunkType
    file_offset: int  # Offset in the sparse file where chunk header starts
    output_offset: int  # Offset in the output binary where this chunk's data starts
    chunk_blocks: int  # Number of blocks in this chunk
    total_size: int  # Total size of chunk in sparse file (header + data)
    output_size: int  # Size of chunk data in output binary
