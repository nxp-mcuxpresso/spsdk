#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Universal binary file handler with support for multiple formats.

This module provides a unified file-like interface for working with different
binary file formats including Binary, SPARSE, SREC, and Intel HEX formats.
"""

import logging
import os
from typing import IO, Optional

from typing_extensions import Self

from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.utils.binary_image import BinaryImage
from spsdk.utils.sparse_image import SparseImageReader

logger = logging.getLogger(__name__)


class UniversalBinaryFile:
    """Universal binary file handler supporting multiple formats.

    This class provides a file-like interface that works transparently across
    different binary file formats: BIN, SPARSE, SREC, and Intel HEX.

    Supported formats and their handling:
    - BIN: Direct file operations (most efficient)
    - SPARSE: Uses SparseImageReader for efficient random access
    - SREC/HEX: Loads entire file into memory, writes back on close

    Example usage:
        f = UniversalBinaryFile()
        f.open("firmware.hex", "r+b")
        f.seek(0x1000)
        data = f.read(256)
        f.seek(0x2000)
        f.write(b"\\x00" * 128)
        f.close()

        # Or with context manager:
        with UniversalBinaryFile().open("firmware.hex", "r+b") as f:
            f.seek(0x1000)
            data = f.read(256)
    """

    def __init__(self) -> None:
        """Initialize universal binary file handler.

        Creates an uninitialized file handler. Call open() to open a file.
        """
        self.path: Optional[str] = None
        self.mode: str = "rb"
        self.position = 0
        self.format_type: str = "BIN"  # Default format
        self.is_open = False

        # Format-specific handlers
        self._file_handle: Optional[IO] = None  # For BIN format
        self._sparse_reader: Optional[SparseImageReader] = None  # For SPARSE format
        self._binary_image: Optional[BinaryImage] = None  # For SREC/HEX formats
        self._modified = False  # Track if SREC/HEX has been modified

    def _validate_mode(self, mode: str) -> bool:
        """Validate file access mode.

        :param mode: File mode string to validate.
        :return: True if mode is valid, False otherwise.
        """
        valid_modes = ["rb", "r+b", "wb", "w+b", "ab", "a+b"]
        return mode in valid_modes

    def open(self, path: str, mode: str = "rb") -> Self:
        """Open the file for access.

        Initializes the appropriate handler based on the detected file format.

        :param path: Path to the binary file.
        :param mode: File access mode ('rb', 'r+b', 'wb', etc.).
        :raises SPSDKError: File already open, invalid mode, or cannot be opened.
        :raises SPSDKValueError: File not found or inaccessible.
        :return: Self for method chaining.
        """
        if self.is_open:
            raise SPSDKError(f"File already open: {self.path}")

        # Validate mode
        if not self._validate_mode(mode):
            raise SPSDKError(f"Invalid file mode: {mode}")

        # Check if file exists for read modes
        if "r" in mode or "+" in mode:
            if not os.path.exists(path):
                raise SPSDKValueError(f"File not found: {path}")

        # Store path and mode
        self.path = path
        self.mode = mode

        # Auto-detect format for existing files
        if os.path.exists(path):
            self.format_type = BinaryImage.detect_file_format(path)
            logger.debug(f"Detected file format: {self.format_type} for {path}")
        else:
            # For new files, default to BIN format
            self.format_type = "BIN"
            logger.debug(f"New file will be created as BIN format: {path}")

        try:
            if self.format_type == "BIN":
                self._open_binary()
            elif self.format_type == "SPARSE":
                self._open_sparse()
            elif self.format_type in ("SREC", "HEX", "ELF"):
                self._open_text_format()
            else:
                raise SPSDKError(f"Unsupported file format: {self.format_type}")

            self.is_open = True
            self.position = 0
            logger.debug(
                f"Opened file: {self.path} (format: {self.format_type}, mode: {self.mode})"
            )

        except Exception as e:
            # Reset state on failure
            self.path = None
            self.mode = "rb"
            raise SPSDKError(f"Failed to open file {path}: {e}") from e

        return self

    def _open_binary(self) -> None:
        """Open file in binary format (direct file access)."""
        assert self.path is not None
        self._file_handle = open(  # pylint: disable=unspecified-encoding
            self.path, self.mode, encoding=None
        )

    def _open_sparse(self) -> None:
        """Open file in SPARSE format using SparseImageReader."""
        assert self.path is not None
        if "w" in self.mode:
            raise SPSDKError("Write-only mode not supported for SPARSE format")

        # For read-only or read-write modes
        self._sparse_reader = SparseImageReader(self.path, validate_header=True)

    def _open_text_format(self) -> None:
        """Open file in SREC or Intel HEX format (load into memory)."""
        assert self.path is not None
        if "w" in self.mode and "+" not in self.mode:
            # Write-only mode - create empty BinaryImage
            self._binary_image = BinaryImage(name=os.path.basename(self.path), size=0)
        else:
            # Read or read-write mode - load existing file
            self._binary_image = BinaryImage.load_binary_image(self.path)
            # Join all sub-images into a single binary block for easier modification
            self._binary_image.join_images()

        self._modified = False

    def close(self) -> None:
        """Close the file and save changes if necessary.

        For SREC/HEX formats, writes the modified content back to the file.

        :raises SPSDKError: File not open or error during close.
        """
        if not self.is_open:
            logger.warning(f"Attempting to close already closed file: {self.path}")
            return

        try:
            if self.format_type == "BIN":
                self._close_binary()
            elif self.format_type == "SPARSE":
                self._close_sparse()
            elif self.format_type in ("SREC", "HEX", "ELF"):
                self._close_text_format()

            self.is_open = False
            logger.debug(f"Closed file: {self.path}")

        except Exception as e:
            raise SPSDKError(f"Failed to close file {self.path}: {e}") from e
        finally:
            # Reset state after closing
            self.path = None
            self.mode = "rb"
            self.position = 0

    def _close_binary(self) -> None:
        """Close binary format file."""
        if self._file_handle:
            self._file_handle.close()
            self._file_handle = None

    def _close_sparse(self) -> None:
        """Close SPARSE format file."""
        if self._sparse_reader:
            self._sparse_reader.close()
            self._sparse_reader = None

    def _close_text_format(self) -> None:
        """Close SREC/HEX format file and write back if modified."""
        assert self.path is not None
        if self._binary_image and self._modified:
            # Determine output format based on original format
            format_map = {
                "SREC": "SREC",
                "HEX": "HEX",
                "ELF": "BIN",  # ELF is read-only, save as BIN
            }
            output_format = format_map.get(self.format_type, "BIN")

            # Save the modified image back to file
            self._binary_image.save_binary_image(self.path, file_format=output_format)
            logger.debug(f"Saved modified {self.format_type} file as {output_format}: {self.path}")

        self._binary_image = None
        self._modified = False

    def seek(self, offset: int, whence: int = 0) -> int:
        """Set the file position.

        :param offset: Offset in bytes.
        :param whence: Reference point (0=start, 1=current, 2=end).
        :raises SPSDKError: File not open.
        :raises SPSDKValueError: Invalid whence value or negative position.
        :return: New absolute position.
        """
        if not self.is_open:
            raise SPSDKError("File not open")

        if whence == 0:  # Absolute position
            new_position = offset
        elif whence == 1:  # Relative to current position
            new_position = self.position + offset
        elif whence == 2:  # Relative to end
            file_size = self.get_file_size()
            new_position = file_size + offset
        else:
            raise SPSDKValueError(f"Invalid whence value: {whence}")

        if new_position < 0:
            raise SPSDKValueError(f"Negative seek position: {new_position}")

        # For binary format, use native seek
        if self.format_type == "BIN" and self._file_handle:
            self._file_handle.seek(offset, whence)
            self.position = self._file_handle.tell()
        else:
            # For other formats, just update internal position
            self.position = new_position

        return self.position

    def get_file_size(self) -> int:
        """Get the total size of the file.

        :return: File size in bytes.
        """
        if self.format_type == "BIN" and self._file_handle:
            current_pos = self._file_handle.tell()
            self._file_handle.seek(0, 2)  # Seek to end
            size = self._file_handle.tell()
            self._file_handle.seek(current_pos)  # Restore position
            return size
        if self.format_type == "SPARSE" and self._sparse_reader:
            return self._sparse_reader.get_total_size()
        if self.format_type in ("SREC", "HEX", "ELF") and self._binary_image:
            # Return size of binary data
            if self._binary_image.binary:
                return len(self._binary_image.binary)
            return len(self._binary_image)
        return 0

    def read(self, size: int = -1) -> bytes:
        """Read bytes from the current position.

        :param size: Number of bytes to read (-1 for all remaining).
        :raises SPSDKError: File not open or not readable.
        :return: Bytes read from file.
        """
        if not self.is_open:
            raise SPSDKError("File not open")

        if "r" not in self.mode and "+" not in self.mode:
            raise SPSDKError("File not opened for reading")

        # Handle read all
        if size == -1:
            size = self.get_file_size() - self.position

        if size <= 0:
            return b""

        data = b""

        if self.format_type == "BIN" and self._file_handle:
            data = self._file_handle.read(size)
            self.position = self._file_handle.tell()

        elif self.format_type == "SPARSE" and self._sparse_reader:
            data = self._sparse_reader.read(offset=self.position, size=size)
            self.position += len(data)

        elif self.format_type in ("SREC", "HEX", "ELF") and self._binary_image:
            # Get the binary data (either from binary field or export)
            if self._binary_image.binary:
                binary_data = self._binary_image.binary
            else:
                binary_data = self._binary_image.export()

            end_pos = min(self.position + size, len(binary_data))
            data = binary_data[self.position : end_pos]
            self.position = end_pos

        return data

    def write(self, data: bytes) -> int:
        """Write bytes at the current position.

        :param data: Bytes to write.
        :raises SPSDKError: File not open or not writable.
        :return: Number of bytes written.
        """
        if not self.is_open:
            raise SPSDKError("File not open")

        if "w" not in self.mode and "+" not in self.mode and "a" not in self.mode:
            raise SPSDKError("File not opened for writing")

        if len(data) == 0:
            return 0

        bytes_written = 0

        if self.format_type == "BIN" and self._file_handle:
            bytes_written = self._file_handle.write(data)
            self.position = self._file_handle.tell()

        elif self.format_type == "SPARSE" and self._sparse_reader:
            # Use modify method from SparseImageReader
            self._sparse_reader.modify(offset=self.position, data=data, update_crc=True)
            bytes_written = len(data)
            self.position += bytes_written

        elif self.format_type in ("SREC", "HEX", "ELF") and self._binary_image:
            # Modify the in-memory BinaryImage
            # First, ensure the image is large enough
            required_size = self.position + len(data)

            # Get current binary data
            if self._binary_image.binary:
                binary_data = bytearray(self._binary_image.binary)
            else:
                binary_data = bytearray(self._binary_image.export())

            # Expand if necessary
            if len(binary_data) < required_size:
                # Extend with zeros or pattern
                padding_size = required_size - len(binary_data)
                if self._binary_image.pattern:
                    padding = self._binary_image.pattern.get_block(padding_size)
                else:
                    padding = b"\x00" * padding_size
                binary_data.extend(padding)

            # Write the data
            binary_data[self.position : self.position + len(data)] = data

            # Update the binary image
            self._binary_image.binary = bytes(binary_data)
            self._binary_image.size = len(binary_data)

            bytes_written = len(data)
            self.position += bytes_written
            self._modified = True

        return bytes_written

    def tell(self) -> int:
        """Get the current file position.

        :return: Current position in bytes.
        """
        return self.position

    def __enter__(self) -> Self:
        """Enter context manager.

        Note: The file must be opened using open() before entering the context,
        or the context manager will raise an error. This differs from the standard
        file object behavior where you can use 'with open(path) as f:'.

        For this class, use: 'with UniversalBinaryFile().open(path, mode) as f:'

        :raises SPSDKError: If file is not already open.
        :return: Self instance for context manager usage.
        """
        if not self.is_open:
            raise SPSDKError(
                "File must be opened before entering context. "
                "Use: with UniversalBinaryFile().open(path, mode) as f:"
            )
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # type: ignore
        """Exit context manager and close file.

        Automatically closes the file when exiting the context, even if an exception occurred.
        For SREC/HEX formats, this will save any modifications made during the context.

        :param exc_type: Exception type if an exception occurred.
        :param exc_val: Exception value if an exception occurred.
        :param exc_tb: Exception traceback if an exception occurred.
        """
        if self.is_open:
            self.close()

    def __repr__(self) -> str:
        """Get string representation.

        :return: String representation with file path and format info.
        """
        status = "open" if self.is_open else "closed"
        return f"<UniversalBinaryFile path='{self.path}' format={self.format_type} mode={self.mode} status={status}>"

    def flush(self) -> None:
        """Flush write buffers.

        For binary files, flushes the underlying file handle.
        For other formats, this is a no-op as changes are written on close.
        """
        if not self.is_open:
            return

        if self.format_type == "BIN" and self._file_handle:
            self._file_handle.flush()

    def readable(self) -> bool:
        """Check if file is readable.

        :return: True if file is open and readable.
        """
        return self.is_open and ("r" in self.mode or "+" in self.mode)

    def writable(self) -> bool:
        """Check if file is writable.

        :return: True if file is open and writable.
        """
        return self.is_open and ("w" in self.mode or "+" in self.mode or "a" in self.mode)

    def seekable(self) -> bool:
        """Check if file is seekable.

        :return: True if file is open (all formats support seeking).
        """
        return self.is_open
