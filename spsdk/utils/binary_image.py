#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK binary image utilities and visualization tools.

This module provides functionality for handling binary images, including
color picking utilities and binary image processing capabilities for SPSDK
applications.
"""

import logging
import math
import os
import re
import sys
import textwrap
from typing import Any, Optional

import colorama
from typing_extensions import Self

from spsdk.exceptions import SPSDKError, SPSDKOverlapError, SPSDKValueError
from spsdk.utils.config import Config
from spsdk.utils.database import get_schema_file
from spsdk.utils.misc import (
    BinaryPattern,
    align,
    align_block,
    find_file,
    format_value,
    get_printable_path,
    size_fmt,
    write_file,
)
from spsdk.utils.schema_validator import CommentedConfig

logger = logging.getLogger(__name__)


class ColorPicker:
    """Color picker utility for cycling through predefined terminal colors.

    This class provides a simple mechanism to sequentially select different
    colors from a predefined list, useful for colorizing terminal output
    with distinct colors for different elements.

    :cvar COLORS: List of available colorama foreground colors for selection.
    """

    COLORS = [
        colorama.Fore.LIGHTBLACK_EX,
        colorama.Fore.BLUE,
        colorama.Fore.GREEN,
        colorama.Fore.CYAN,
        colorama.Fore.YELLOW,
        colorama.Fore.MAGENTA,
        colorama.Fore.WHITE,
        colorama.Fore.LIGHTBLUE_EX,
        colorama.Fore.LIGHTCYAN_EX,
        colorama.Fore.LIGHTGREEN_EX,
        colorama.Fore.LIGHTMAGENTA_EX,
        colorama.Fore.LIGHTWHITE_EX,
        colorama.Fore.LIGHTYELLOW_EX,
    ]

    def __init__(self) -> None:
        """Initialize ColorPicker with default settings.

        Sets the color index to the total number of available colors in the COLORS collection.
        """
        self.index = len(self.COLORS)

    def get_color(self, unwanted_color: Optional[str] = None) -> str:
        """Get next color from the color list.

        The method cycles through available colors and skips any unwanted color
        if specified. When reaching the end of the color list, it wraps around
        to the beginning.

        :param unwanted_color: Color that should be omitted from selection.
        :return: Selected color string.
        """
        self.index += 1
        if self.index >= len(ColorPicker.COLORS):
            self.index = 0
        if unwanted_color and ColorPicker.COLORS[self.index] == unwanted_color:
            return self.get_color(unwanted_color)
        return ColorPicker.COLORS[self.index]


class BinaryImage:
    """Binary image representation and manipulation utility.

    This class provides functionality for creating, managing, and manipulating binary images
    with support for hierarchical sub-images, alignment, patterns, and memory layout operations.
    It serves as a foundation for building complex binary structures used in embedded systems
    and firmware development.

    :cvar MINIMAL_DRAW_WIDTH: Minimum width for image visualization output.
    """

    MINIMAL_DRAW_WIDTH = 30

    def __init__(
        self,
        name: str,
        size: int = 0,
        offset: int = 0,
        description: Optional[str] = None,
        binary: Optional[bytes] = None,
        pattern: Optional[BinaryPattern] = None,
        alignment: int = 1,
        parent: Optional["BinaryImage"] = None,
        execution_start_address: Optional[int] = None,
    ) -> None:
        """Initialize a new BinaryImage instance.

        Creates a binary image object that can contain binary data, patterns, or sub-images.
        The image can be part of a hierarchical structure with parent-child relationships.

        :param name: Name identifier for the image.
        :param size: Size of the image in bytes, will be aligned according to alignment parameter.
        :param offset: Byte offset position within the parent image.
        :param description: Human-readable description of the image purpose.
        :param binary: Raw binary data content for the image.
        :param pattern: Binary pattern to fill the image with.
        :param alignment: Byte alignment requirement for the image size.
        :param parent: Parent BinaryImage object in the hierarchy.
        :param execution_start_address: Memory address where execution should start.
        """
        self.name = name
        self.description = description
        self.offset = offset
        self._size = align(size, alignment)
        self.binary = binary
        self.pattern = pattern
        self.alignment = alignment
        self.parent = parent
        self.execution_start_address = execution_start_address

        if parent:
            assert isinstance(parent, BinaryImage)
        self.sub_images: list["BinaryImage"] = []

    @property
    def size(self) -> int:
        """Get the size of the binary image.

        :return: Size of the binary image in bytes.
        """
        return len(self)

    @size.setter
    def size(self, value: int) -> None:
        """Set the size property value.

        The size value is automatically aligned to the object's alignment requirements.

        :param value: The size value to set in bytes.
        """
        self._size = align(value, self.alignment)

    def add_image(self, image: "BinaryImage") -> None:
        """Add new sub image to the binary image container.

        The method inserts the sub-image at the correct position based on its offset,
        maintaining the sorted order of sub-images within the container. The added
        image's parent reference is automatically set to this container.

        :param image: Binary image object to be added as a sub-image.
        """
        image.parent = self
        for i, child in enumerate(self.sub_images):
            if image.offset < child.offset:
                self.sub_images.insert(i, image)
                return
        self.sub_images.append(image)

    def append_image(self, image: "BinaryImage") -> None:
        """Append new sub image at the end of the parent.

        This function uses the size of the parent as an offset for the new appended image.

        :param image: Binary image object to append.
        """
        image.offset = len(self)
        self.add_image(image)

    def find_sub_image(self, name: str) -> "BinaryImage":
        """Find sub image by its name.

        :param name: Name of sub image to search for.
        :raises SPSDKValueError: The sub image with requested name doesn't exist.
        :return: Sub Image object with the specified name.
        """
        for sub_image in self.sub_images:
            if name == sub_image.name:
                return sub_image
        raise SPSDKValueError(f"Sub image {name} in {self.name} doesn't exists")

    def join_images(self) -> None:
        """Join all sub images into main binary block.

        This method exports all sub-images into a single binary representation,
        clears the sub-images collection, and updates the main binary data with
        the consolidated result.
        """
        binary = self.export()
        self.sub_images.clear()
        self.binary = binary

    @property
    def image_name(self) -> str:
        """Get image name including all parent names.

        The method constructs a hierarchical path by concatenating parent image names
        with the current image name using '=>' as separator.

        :return: Full hierarchical image name with parent chain.
        """
        if self.parent:
            return self.parent.image_name + "=>" + self.name
        return self.name

    @property
    def absolute_address(self) -> int:
        """Get image absolute address relative to base parent.

        Calculates the absolute address by traversing up the parent hierarchy
        and accumulating offsets from the base parent.

        :return: Absolute address relative to base parent.
        """
        if self.parent:
            return self.parent.absolute_address + self.offset
        return self.offset

    def aligned_start(self, alignment: int = 4) -> int:
        """Calculate aligned start address based on specified alignment.

        The method performs floor division to align the absolute address to the nearest
        lower boundary that is divisible by the alignment value.

        :param alignment: The alignment value in bytes, defaults to 4.
        :return: Floor-aligned absolute address.
        """
        return math.floor(self.absolute_address / alignment) * alignment

    def get_image_by_absolute_address(self, address: int) -> "BinaryImage":
        """Get Binary Image object that contains the provided absolute address.

        :param address: Absolute address to image
        :raises SPSDKValueError: Exception when the address doesn't fit into address space
        :return: Binary image object that contains the data.
        """
        for sub_image in self.sub_images:
            try:
                return sub_image.get_image_by_absolute_address(address=address - self.offset)
            except SPSDKValueError:
                pass

        if address < self.offset or address > (self.offset + len(self)):
            raise SPSDKValueError(
                f"The address 0x{address:08X} doesn't fit into {self.name} image."
            )
        return self

    def aligned_length(self, alignment: int = 4) -> int:
        """Calculate aligned length for memory erasing operations.

        The method computes the total length needed when considering alignment requirements
        for both start and end addresses, typically used for flash memory operations.

        :param alignment: Memory alignment boundary in bytes, defaults to 4
        :return: Total aligned length in bytes from aligned start to aligned end
        """
        end_address = self.absolute_address + len(self)
        aligned_end = math.ceil(end_address / alignment) * alignment
        aligned_len = aligned_end - self.aligned_start(alignment)
        return aligned_len

    def __str__(self) -> str:
        """Get string representation of the binary image.

        Provides detailed information about the binary image including name, memory
        addresses, size, alignment, execution start address, pattern, and description.

        :return: Formatted string with comprehensive image information.
        """
        size = len(self)
        execution_start_address = (
            hex(self.execution_start_address)
            if self.execution_start_address is not None
            else "Not defined"
        )
        ret = ""
        ret += f"Name:      {self.image_name}\n"
        ret += f"Starts:    {hex(self.absolute_address)}\n"
        ret += f"Ends:      {hex(self.absolute_address+ size-1)}\n"
        ret += f"Size:      {self._get_size_line(size)}\n"
        ret += f"Alignment: {size_fmt(self.alignment)}\n"
        ret += f"Execution Start Address: {execution_start_address}\n"
        if self.pattern:
            ret += f"Pattern:{self.pattern.pattern}\n"
        if self.description:
            ret += self.description + "\n"
        return ret

    def __repr__(self) -> str:
        """Return string representation of the BinaryImage object.

        Provides a formatted string containing the image name, size in bytes, and absolute address
        in hexadecimal format for debugging and logging purposes.

        :return: String representation in format "<BinaryImage name (size B) at 0x(address)>".
        """
        return f"<BinaryImage {self.name} ({len(self)} B) at 0x{self.absolute_address:08X}>"

    def validate(self) -> None:
        """Validate binary image structure and detect overlaps.

        Performs comprehensive validation of the binary image including:
        - Checks that image offset is non-negative
        - Verifies that image size is non-negative
        - Recursively validates all sub-images
        - Ensures sub-images fit within parent image boundaries
        - Detects overlapping sub-images at the same level

        :raises SPSDKValueError: When image offset or size is negative.
        :raises SPSDKOverlapError: When sub-image exceeds parent boundaries or overlaps with sibling.
        """
        if self.offset < 0:
            raise SPSDKValueError(
                f"Image offset of {self.image_name} cannot be in negative numbers."
            )
        if len(self) < 0:
            raise SPSDKValueError(f"Image size of {self.image_name} cannot be in negative numbers.")
        for image in self.sub_images:
            image.validate()
            begin = image.offset
            end = begin + len(image) - 1
            # Check if it fits inside the parent image
            if end >= len(self):
                raise SPSDKOverlapError(
                    f"The image '{image.name}' doesn't fit into '{self.name}' parent image."
                )
            # Check if it doesn't overlap any other sibling image
            for sibling in self.sub_images:
                if sibling != image:
                    sibling_begin = sibling.offset
                    sibling_end = sibling_begin + len(sibling) - 1
                    if end < sibling_begin or begin > sibling_end:
                        continue

                    raise SPSDKOverlapError(
                        f"The image overlap error:\n"
                        f"{str(image)}\n"
                        "overlaps the:\n"
                        f"{str(sibling)}\n"
                    )

    def _get_size_line(self, size: int) -> str:
        """Get string of formatted size line.

        The method formats the size into a human-readable string. For sizes >= 1024 bytes,
        it includes both formatted size and comma-separated byte count.

        :param size: Size in bytes to format.
        :return: Formatted size line string.
        """
        if size >= 1024:
            real_size = ",".join(re.findall(".{1,3}", (str(len(self)))[::-1]))[::-1]
            return f"Size: {size_fmt(len(self))}; {real_size} B"

        return f"Size: {size_fmt(len(self))}"

    def get_min_draw_width(self, include_sub_images: bool = True) -> int:
        """Get minimal width of table for draw function.

        The method calculates the minimum character width needed to properly display
        the binary image table, considering the image name, size information, and
        optionally any sub-images with their borders.

        :param include_sub_images: Include sub-images in width calculation, defaults to True
        :return: Minimal width in characters.
        """
        widths = [
            self.MINIMAL_DRAW_WIDTH,
            len(f"+==-0x0000_0000= {self.name} =+"),
            len(f"|{self._get_size_line(self.size)}|"),
        ]
        if include_sub_images:
            for child in self.sub_images:
                widths.append(child.get_min_draw_width() + 2)  # +2 means add vertical borders
        return max(widths)

    def draw(
        self,
        include_sub_images: bool = True,
        width: int = 0,
        color: str = "",
        no_color: bool = False,
        use_unicode: bool = True,
    ) -> str:
        """Draw the image into ASCII/Unicode graphics representation.

        Creates a visual representation of the binary image with address information,
        size details, description, and optionally includes sub-images in a structured
        box-drawing format.

        :param include_sub_images: Include also sub images into output, defaults to True
        :param width: Fixed width of table, 0 means autosize
        :param color: Color of this block, empty string means automatic color
        :param no_color: Disable adding colors into output
        :param use_unicode: Use Unicode box drawing characters instead of ASCII, defaults to True
        :raises SPSDKValueError: In case of invalid width or text longer than specified width
        :return: ASCII/Unicode art representation of binary image
        """
        use_unicode &= os.name != "nt" or (sys.stdout.isatty() and sys.stderr.isatty())
        if use_unicode:
            # Unicode box drawing characters
            top_left = "┌"
            top_right = "┐"
            bottom_left = "└"
            bottom_right = "┘"
            horizontal = "─"
            vertical = "│"
        else:
            # ASCII characters
            top_left = top_right = bottom_left = bottom_right = "+"
            horizontal = "="
            vertical = "|"

        def _get_centered_line(text: str) -> str:
            """Get centered line with text formatted for binary image display.

            Creates a formatted line with the given text centered between vertical borders,
            padded with spaces to match the specified width.

            :param text: Text to be centered in the line.
            :raises SPSDKValueError: Text is longer than the available width.
            :return: Formatted string with centered text and vertical borders.
            """
            text_len = len(text)
            spaces = width - text_len - 2
            if spaces < 0:
                raise SPSDKValueError(
                    f"Binary Image Draw: Text is longer than width ({text_len} > {width})"
                )
            padding_l = int(spaces / 2)
            padding_r = int(spaces - padding_l)
            return color + f"{vertical}{' '*padding_l}{text}{' '*padding_r}{vertical}\n"

        def wrap_block(inner: str) -> str:
            """Wrap text block with colored vertical borders.

            Adds colored vertical border characters to the beginning and end of each line
            in the input text block, creating a bordered text display.

            :param inner: Input text block to be wrapped with borders.
            :return: Text block with colored vertical borders added to each line.
            """
            wrapped_block = ""
            lines = inner.splitlines(keepends=False)
            for line in lines:
                wrapped_block += color + vertical + line + color + vertical + "\n"
            return wrapped_block

        if no_color:
            color = ""
        else:
            color_picker = ColorPicker()
            try:
                self.validate()
                color = color or color_picker.get_color()
            except SPSDKError:
                color = colorama.Fore.RED

        block = "" if self.parent else "\n"
        min_width = self.get_min_draw_width(include_sub_images)
        if not width and self.parent is None:
            width = min_width

        if width < min_width:
            raise SPSDKValueError(
                f"Binary Image Draw: Width is to short ({width} < minimal width: {min_width})"
            )

        # - Title line
        addr_formatted = format_value(self.absolute_address, 32)
        header = f"{top_left}{horizontal}{horizontal}{addr_formatted}{horizontal} {self.name} {horizontal}"
        block += color + f"{header}{horizontal*(width-len(header)-1)}{top_right}\n"  # - Size
        block += _get_centered_line(self._get_size_line(len(self)))
        # - Description
        if self.description:
            for line in textwrap.wrap(
                self.description,
                width=width - 2,
                fix_sentence_endings=True,
            ):
                block += _get_centered_line(line)
        # - Pattern
        if self.pattern:
            block += _get_centered_line(f"Pattern: {self.pattern.pattern}")
        # - Inner blocks
        if include_sub_images:
            next_free_space = 0
            for child in self.sub_images:
                # If the images doesn't comes one by one place empty line
                if child.offset != next_free_space:
                    block += _get_centered_line(f"Gap: {size_fmt(child.offset-next_free_space)}")
                next_free_space = child.offset + len(child)
                inner_block = child.draw(
                    include_sub_images=include_sub_images,
                    width=width - 2,
                    color="" if no_color else color_picker.get_color(color),
                    no_color=no_color,
                    use_unicode=use_unicode,  # Pass the Unicode flag to child images
                )
                block += wrap_block(inner_block)

        # - Closing line
        end_address = self.absolute_address + len(self) - 1
        footer = f"{bottom_left}{horizontal}{horizontal}{format_value(end_address, 32)}{horizontal}{horizontal}"
        block += color + f"{footer}{horizontal*(width-len(footer)-1)}{bottom_right}\n"

        if self.parent is None:
            block += "\n" + "" if no_color else colorama.Fore.RESET
        return block

    def update_offsets(self) -> None:
        """Update offsets from the sub images into main offset value begin offsets.

        This method normalizes the offset values by adjusting all sub-image offsets relative to the
        minimum offset found among them, and updates the main image offset accordingly. The minimum
        offset among sub-images becomes the new base (0), and the main offset is increased by this
        minimum value.
        """
        min_offset = self.min_offset
        for image in self.sub_images:
            image.offset -= min_offset
        self.offset += min_offset

    @property
    def min_offset(self) -> int:
        """Get the offset of the first subimage in the binary image.

        Calculates the minimum offset among all sub images. If no sub images exist,
        returns 0 as the default offset.

        :return: Minimum offset value from all sub images, or 0 if no sub images exist.
        """
        offsets = []
        for image in self.sub_images:
            offsets.append(image.offset)
        return min(offsets) if len(offsets) else 0

    def __len__(self) -> int:
        """Get length of image.

        If internal member size is not set (is zero), the size is computed from sub-images.
        The final size is aligned according to the image alignment requirements.

        :return: Size of image in bytes.
        """
        if self._size:
            return self._size
        max_size = len(self.binary) if self.binary else 0
        for image in self.sub_images:
            size = image.offset + len(image)
            max_size = max(size, max_size)
        return align(max_size, self.alignment)

    def export(self) -> bytes:
        """Export the binary image as a byte array.

        The method handles various scenarios including direct binary export, empty images,
        pattern-filled images, and recursive export of sub-images. Sub-images are merged
        into the parent image at their specified offsets with proper alignment.

        :raises SPSDKValueError: When sub-image cannot be merged into parent image due to
            size or offset conflicts.
        :return: Byte array representation of the complete binary image with all
            sub-images merged and proper alignment applied.
        """
        if self.binary and len(self) == len(self.binary) and len(self.sub_images) == 0:
            return self.binary

        # Handle empty binary case - if length is 0 and no sub-images, return empty bytes
        if len(self) == 0 and len(self.sub_images) == 0 and self.size == 0:
            return b""

        if self.pattern:
            ret = bytearray(self.pattern.get_block(len(self)))
        else:
            ret = bytearray(len(self))

        if self.binary:
            binary_view = memoryview(self.binary)
            ret[: len(self.binary)] = binary_view

        for image in self.sub_images:
            try:
                image_data = image.export()
                ret_slice = memoryview(ret)[image.offset : image.offset + len(image_data)]
                image_data_view = memoryview(image_data)
                ret_slice[:] = image_data_view
            except ValueError as e:
                # Catch memoryview assignment errors and provide a more helpful message
                raise SPSDKValueError(
                    f"Cannot merge sub-image '{image.name}' into parent image '{self.name}'."
                ) from e
        return align_block(ret, self.alignment, self.pattern)

    def post_export(self, output_path: str) -> list[str]:
        """Perform post export steps like saving the script files.

        The method iterates through all sub-images and calls their post_export methods
        if available, collecting all generated files from the export process.

        :param output_path: Path to the output directory where files will be saved.
        :return: List of paths to all generated files during the post-export process.
        """
        generated_files = []

        for image in self.sub_images:
            if hasattr(image, "post_export"):
                sub_files = image.post_export(output_path)
                generated_files.extend(sub_files)

        return generated_files

    @staticmethod
    def get_validation_schemas() -> list[dict[str, Any]]:
        """Get validation schemas list to check a supported configuration.

        :return: List of validation schema dictionaries for binary image configuration.
        """
        return [get_schema_file("binary")]

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Create Binary Image object from configuration data.

        The method processes configuration options to initialize a Binary Image with
        specified name, size, pattern, and alignment. It also handles optional regions
        containing binary files or binary blocks that are added as sub-images.

        :param config: Configuration object containing binary image description with
                       optional regions for binary files and blocks.
        :return: Initialized Binary Image object with all configured sub-images.
        """
        name = config.get_str("name", "Base Image")
        size = config.get_int("size", 0)
        pattern = BinaryPattern(config.get("pattern", "zeros"))
        alignment = config.get_int("alignment", 1)
        ret = cls(name=name, size=size, pattern=pattern, alignment=alignment)
        if "regions" in config:
            regions = config.get_list_of_configs("regions")
            for i, region in enumerate(regions):
                if "binary_file" in region:
                    binary_file = region.get_config("binary_file")
                    offset = binary_file.get_int("offset") if "offset" in binary_file else None
                    name = binary_file.get_str("name", binary_file["path"])
                    ret.add_image(
                        BinaryImage.load_binary_image(
                            binary_file["path"],
                            name=name,
                            offset=offset,
                            pattern=pattern,
                            search_paths=config.search_paths,
                            parent_image=ret,
                        )
                    )
                if "binary_block" in region:
                    binary_block = region.get_config("binary_block")
                    size = binary_block.get_int("size")
                    offset = binary_block.get_int("offset", ret.aligned_length(ret.alignment))
                    name = binary_block.get_str("name", f"Binary block(#{i})")
                    pattern = BinaryPattern(binary_block.get("pattern"))
                    ret.add_image(BinaryImage(name, size, offset, pattern=pattern))
        return ret

    def save_binary_image(
        self,
        path: str,
        file_format: str = "BIN",
    ) -> None:
        """Save binary data file.

        The method supports multiple output formats including binary, Intel HEX, and Motorola S-record
        formats. For non-binary formats, it handles empty binaries and uses execution start address
        if available.

        :param path: Path to the output file.
        :param file_format: Format of saved file ('BIN', 'HEX', 'S19', 'SREC'), defaults to 'BIN'.
        :raises SPSDKValueError: The file format is invalid.
        """
        file_format = file_format.upper()
        if file_format.upper() not in ("BIN", "HEX", "S19", "SREC"):
            raise SPSDKValueError(f"Invalid input file format: {file_format}")

        if file_format == "BIN":
            data = bytes()
            if self.offset:
                data += (
                    self.pattern.get_block(self.offset) if self.pattern else b"\x00" * self.offset
                )
            data += self.export()
            write_file(data, path, mode="wb")
            return

        # Special handling for empty binary to SREC/HEX conversion
        if file_format in ("HEX", "S19", "SREC"):
            exported_data = self.export()
            # Only check for the specific problematic case: completely empty binary with no offset
            # and no meaningful content that could be converted
            if (
                len(exported_data) == 0
                and self.offset == 0
                and not self.binary
                and len(self.sub_images) == 0
                and (not self.pattern or self.pattern.pattern == "zeros")
                and not self.execution_start_address  # Add this condition
            ):
                # For empty files loaded from disk, we should still allow conversion
                # Create a minimal valid HEX/S19 file
                pass  # Continue with the conversion process

        def add_into_binary(bin_image: BinaryImage) -> None:
            """Add binary image data into the binary file.

            Recursively processes the binary image and its sub-images, adding their content
            to the binary file at the specified addresses. Handles both direct binary data
            and pattern-generated data.

            :param bin_image: Binary image object containing data to be added.
            """
            address = bin_image.absolute_address
            if bin_image.binary:
                bin_file.add_binary(bin_image.binary, address=address, overwrite=True)

            elif bin_image.pattern and not bin_image.sub_images:
                bin_file.add_binary(
                    bin_image.pattern.get_block(len(bin_image)),
                    address=address,
                    overwrite=True,
                )

            for sub_image in bin_image.sub_images:
                add_into_binary(sub_image)

        # import bincopy only if needed to save startup time
        import bincopy  # pylint: disable=import-outside-toplevel

        bin_file = bincopy.BinFile()
        bin_file.execution_start_address = self.execution_start_address
        add_into_binary(self)

        if file_format == "HEX":
            write_file(bin_file.as_ihex(), path)
            return

        # And final supported format is....... Yes, S record from MOTOROLA
        write_file(bin_file.as_srec(), path)

    @staticmethod
    def get_config_template() -> str:
        """Generate configuration template for binary image.

        The method creates a template configuration that can be used to define
        binary merge operations with proper validation schemas.

        :return: Template string to create binary merge configuration.
        """
        return CommentedConfig(
            "Binary Image Configuration template.", BinaryImage.get_validation_schemas()
        ).get_template()

    @staticmethod
    def load_binary_image(
        path: str,
        name: Optional[str] = None,
        size: int = 0,
        offset: Optional[int] = None,
        description: Optional[str] = None,
        pattern: Optional[BinaryPattern] = None,
        search_paths: Optional[list[str]] = None,
        alignment: int = 1,
        load_bin: bool = True,
        parent_image: Optional["BinaryImage"] = None,
    ) -> "BinaryImage":
        """Load binary data file into BinaryImage object.

        Supported formats are ELF, HEX, SREC and plain binary. The method automatically
        detects the file format and loads it accordingly. If format detection fails,
        it can fallback to binary loading if enabled.

        :param path: Path to the binary file to load.
        :param name: Name of the image, defaults to file name if not provided.
        :param size: Expected image size in bytes, defaults to 0 for auto-detection.
        :param offset: Additional image offset in parent image, defaults to None.
        :param description: Text description of the image, defaults to auto-generated.
        :param pattern: Optional binary pattern to apply to the image.
        :param search_paths: List of paths where to search for the file.
        :param alignment: Alignment requirement for the result image in bytes.
        :param load_bin: Load as binary if other format loading fails.
        :param parent_image: Optional parent image reference for offset computation.
        :raises SPSDKError: The binary file cannot be loaded or accessed.
        :return: Binary data represented as BinaryImage object.
        """
        path = find_file(path, search_paths=search_paths)
        try:
            with open(path, "rb") as f:
                data = f.read(4)
        except Exception as e:
            raise SPSDKError(f"Error loading file: {str(e)}") from e

        # import bincopy only if needed to save startup time
        import bincopy  # pylint: disable=import-outside-toplevel
        from bincopy import _Segment

        bin_file = bincopy.BinFile()
        try:
            if data == b"\x7fELF":
                bin_file.add_elf_file(path)
                logger.debug(f"Loading file as ELF: {path}")
            else:
                try:
                    bin_file.add_file(path)
                    logger.debug(f"Loading file as HEX/SREC: {path}")
                except (UnicodeDecodeError, bincopy.UnsupportedFileFormatError) as e:
                    if load_bin:
                        bin_file.add_binary_file(path)
                        logger.debug(f"Loading file as binary: {path}")
                    else:
                        raise SPSDKError("Cannot load file as ELF, HEX or SREC") from e
        except Exception as e:
            raise SPSDKError(f"Error loading file: {str(e)}") from e

        img_name = name or os.path.basename(path)
        img_size = size or 0
        img_descr = description or f"The image loaded from: {get_printable_path(path)}"

        used_offset = offset
        if used_offset is None:
            if parent_image:
                used_offset = parent_image.aligned_length(parent_image.alignment)
                logger.warning(
                    f"Using parent image aligned size(0x{used_offset:08X}) as a offset for {img_descr}. "
                    "Use 'offset: 0' in configuration, if this is not desired."
                )
            else:
                used_offset = 0  # bin_file.minimum_address

        bin_image = BinaryImage(
            name=img_name,
            size=img_size,
            offset=used_offset,
            description=img_descr,
            pattern=pattern,
            alignment=alignment,
            execution_start_address=bin_file.execution_start_address,
        )

        for i, segment in enumerate(bin_file.segments):
            assert isinstance(segment, _Segment)
            bin_image.add_image(
                BinaryImage(
                    name=f"Segment {i}",
                    size=len(segment.data),
                    offset=segment.address,
                    pattern=pattern,
                    binary=segment.data,
                    parent=bin_image,
                    alignment=alignment,
                )
            )
        # Optimize offsets in image
        bin_image.update_offsets()
        return bin_image
