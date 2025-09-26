#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module to keep additional utilities for binary images."""

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
    """Simple class to get each time when ask different color from list."""

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
        """Constructor of ColorPicker."""
        self.index = len(self.COLORS)

    def get_color(self, unwanted_color: Optional[str] = None) -> str:
        """Get new color from list.

        :param unwanted_color: Color that should be omitted.
        :return: Color
        """
        self.index += 1
        if self.index >= len(ColorPicker.COLORS):
            self.index = 0
        if unwanted_color and ColorPicker.COLORS[self.index] == unwanted_color:
            return self.get_color(unwanted_color)
        return ColorPicker.COLORS[self.index]


class BinaryImage:
    """Binary Image class."""

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
        """Binary Image class constructor.

        :param name: Name of Image.
        :param size: Image size.
        :param offset: Image offset in parent image, defaults to 0
        :param description: Text description of image, defaults to None
        :param binary: Optional binary content.
        :param pattern: Optional binary pattern.
        :param alignment: Optional alignment of result image
        :param parent: Handle to parent object, defaults to None
        :param execution_start_address: Execution start address, defaults to None
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
        """Size property."""
        return len(self)

    @size.setter
    def size(self, value: int) -> None:
        """Size property setter."""
        self._size = align(value, self.alignment)

    def add_image(self, image: "BinaryImage") -> None:
        """Add new sub image information.

        :param image: Image object.
        """
        image.parent = self
        for i, child in enumerate(self.sub_images):
            if image.offset < child.offset:
                self.sub_images.insert(i, image)
                return
        self.sub_images.append(image)

    def append_image(self, image: "BinaryImage") -> None:
        """Append new sub image at the end of the parent.

        This function use the size of the parent as a offset for new appended image.

        :param image: Image object.
        """
        image.offset = len(self)
        self.add_image(image)

    def find_sub_image(self, name: str) -> "BinaryImage":
        """Find sub image by its name.

        :param name: Name of sub image
        :raises SPSDKValueError: The sub image with requested name doesn't exists
        :return: Sub Image object
        """
        for sub_image in self.sub_images:
            if name == sub_image.name:
                return sub_image
        raise SPSDKValueError(f"Sub image {name} in {self.name} doesn't exists")

    def join_images(self) -> None:
        """Join all sub images into main binary block."""
        binary = self.export()
        self.sub_images.clear()
        self.binary = binary

    @property
    def image_name(self) -> str:
        """Image name including all parents.

        :return: Full Image name
        """
        if self.parent:
            return self.parent.image_name + "=>" + self.name
        return self.name

    @property
    def absolute_address(self) -> int:
        """Image absolute address relative to base parent.

        :return: Absolute address relative to base parent
        """
        if self.parent:
            return self.parent.absolute_address + self.offset
        return self.offset

    def aligned_start(self, alignment: int = 4) -> int:
        """Returns aligned start address.

        :param alignment: The alignment value, defaults to 4.
        :return: Floor alignment address.
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
        """Returns aligned length for erasing purposes.

        :param alignment: The alignment value, defaults to 4.
        :return: Ceil alignment length.
        """
        end_address = self.absolute_address + len(self)
        aligned_end = math.ceil(end_address / alignment) * alignment
        aligned_len = aligned_end - self.aligned_start(alignment)
        return aligned_len

    def __str__(self) -> str:
        """Provides information about image.

        :return: String information about Image.
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
        return f"<BinaryImage {self.name} ({len(self)} B) at 0x{self.absolute_address:08X}>"

    def validate(self) -> None:
        """Validate if the images doesn't overlaps each other."""
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
        """Get string of size line.

        :param size: Size in bytes
        :return: Formatted size line.
        """
        if size >= 1024:
            real_size = ",".join(re.findall(".{1,3}", (str(len(self)))[::-1]))[::-1]
            return f"Size: {size_fmt(len(self))}; {real_size} B"

        return f"Size: {size_fmt(len(self))}"

    def get_min_draw_width(self, include_sub_images: bool = True) -> int:
        """Get minimal width of table for draw function.

        :param include_sub_images: Include also sub images into, defaults to True
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
        """Draw the image into the ASCII/Unicode graphics.

        :param include_sub_images: Include also sub images into, defaults to True
        :param width: Fixed width of table, 0 means autosize.
        :param color: Color of this block, None means automatic color.
        :param no_color: Disable adding colors into output.
        :param use_unicode: Use Unicode box drawing characters instead of ASCII, defaults to True
        :raises SPSDKValueError: In case of invalid width.
        :return: ASCII/Unicode art representation of image.
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
        """Update offsets from the sub images into main offset value begin offsets."""
        min_offset = self.min_offset
        for image in self.sub_images:
            image.offset -= min_offset
        self.offset += min_offset

    @property
    def min_offset(self) -> int:
        """Offset of first subimage."""
        offsets = []
        for image in self.sub_images:
            offsets.append(image.offset)
        return min(offsets) if len(offsets) else 0

    def __len__(self) -> int:
        """Get length of image.

        If internal member size is not set(is zero) the size is computed from sub images.
        :return: Size of image.
        """
        if self._size:
            return self._size
        max_size = len(self.binary) if self.binary else 0
        for image in self.sub_images:
            size = image.offset + len(image)
            max_size = max(size, max_size)
        return align(max_size, self.alignment)

    def export(self) -> bytes:
        """Export represented binary image.

        :return: Byte array of binary image.
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

        :param output_path: Path to the output directory
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

        :return: Validation schemas.
        """
        return [get_schema_file("binary")]

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Converts the configuration option into an Binary Image object.

        :param config: Description of binary image.
        :return: Initialized Binary Image.
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

        :param path: Path to the file.
        :param file_format: Format of saved file ('BIN', 'HEX', 'S19'), defaults to 'BIN'.
        :raises SPSDKValueError: The file format is invalid.
        """
        file_format = file_format.upper()
        if file_format.upper() not in ("BIN", "HEX", "S19"):
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
        if file_format in ("HEX", "S19"):
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
        """Generate configuration template.

        :return: Template to create binary merge.
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
        # pylint: disable=missing-param-doc
        r"""Load binary data file.

        Supported formats are ELF, HEX, SREC and plain binary

        :param path: Path to the file.
        :param name: Name of Image, defaults to file name.
        :param size: Image size, defaults to 0.
        :param offset: Additional image offset in parent image, defaults to None
        :param description: Text description of image, defaults to None
        :param pattern: Optional binary pattern.
        :param search_paths: List of paths where to search for the file, defaults to None
        :param alignment: Optional alignment of result image
        :param load_bin: Load as binary in case of every other format load fails
        :param parent_image: Optional parent image reference, it will be used to compute optional offset
        :raises SPSDKError: The binary file cannot be loaded.
        :return: Binary data represented in BinaryImage class.
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
