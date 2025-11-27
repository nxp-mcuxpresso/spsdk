#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK documentation image generation utilities.

This module provides functionality for automatically generating visual documentation
images for SPSDK applications and APIs. It creates composite images showing the
structure and relationships of SPSDK components for Sphinx documentation.
"""

import math
import os
from typing import Any, Optional

from PIL import Image, ImageDraw, ImageFont

from spsdk.apps.spsdk_apps import main as spsdk_main

IMG_PATH = os.path.join(os.path.abspath("."), "_static/images/")
IMG_APPS_PATH = os.path.join(IMG_PATH, "spsdk-architecture-apps.png")
IMG_APIS_PATH = os.path.join(IMG_PATH, "spsdk-architecture-apis.png")
IMG_ARCHITECTURE_PATH = os.path.join(IMG_PATH, "spsdk-architecture.png")

IMG_FONT_PATH = os.path.join(os.path.abspath("."), "_static/fonts/Poppins-Regular.ttf")

SHOW_IMG = False


class ImgTable:
    """SPSDK Documentation Table Image Generator.

    This class creates table-like images for documentation purposes, rendering
    structured data in a visual table format with customizable styling and layout.
    The generator supports configurable dimensions, colors, fonts, and automatic
    row calculation for optimal table presentation.
    """

    def __init__(
        self,
        table_list: list[str],
        header_text: str,
        x_count: int = 3,
        y_count: Optional[int] = None,
        rect_width: int = 300,
        rect_height: int = 100,
        offset: int = 10,
        table_font_size: int = 30,
        header_font_size: int = 45,
        header_width: int = 100,
        bg_color: tuple[int, int, int] = (67, 126, 180),
        fill_color: str = "white",
        outline_color: str = "black",
        font: str = "Helvetica",
    ) -> None:
        """Initialize ImgTable with table data and rendering configuration.

        Creates a table image generator with specified layout, styling, and content parameters.
        Automatically calculates row count if not provided and validates table capacity.

        :param table_list: List of strings to be displayed in table cells.
        :param header_text: Header text displayed on the left side of the table.
        :param x_count: Number of columns in the table.
        :param y_count: Number of rows in the table. If None, calculated automatically.
        :param rect_width: Width of each table cell rectangle in pixels.
        :param rect_height: Height of each table cell rectangle in pixels.
        :param offset: Spacing between table cell rectangles in pixels.
        :param table_font_size: Font size for text within table cells.
        :param header_font_size: Font size for header text.
        :param header_width: Width of the header section in pixels.
        :param bg_color: Background color as RGB tuple.
        :param fill_color: Fill color for table cells and text.
        :param outline_color: Border color for table cell rectangles.
        :param font: Font name or path to font file for text rendering.
        """
        self.table_list = table_list
        self.header_text = header_text
        self.x_count = x_count
        self.y_count = y_count or math.ceil(len(table_list) / x_count)
        self.rect_width = rect_width
        self.rect_height = rect_height
        self.offset = offset
        self.table_font_size = table_font_size
        self.header_font_size = header_font_size
        self.header_width = header_width
        self.bg_color = bg_color
        self.fill_color = fill_color
        self.outline_color = outline_color
        self.font = font

        if len(table_list) > self.x_count * self.y_count:
            print(
                f"Warning: {header_text} table list is larger than the size of the table,"
                f"size {self.x_count * self.y_count}, required {len(table_list)}"
            )

        self.img, self.draw = self._get_img()
        self.header_img, self.header_draw = self._get_header_img()

        self.table_text_font = ImageFont.truetype(self.font, self.table_font_size)
        self.header_text_font = ImageFont.truetype(self.font, self.header_font_size)

        self._draw_img()

    def _get_img(self) -> tuple[Image.Image, ImageDraw.ImageDraw]:
        """Create Image and ImageDraw objects for table generation.

        Creates a new RGB image with dimensions calculated based on table parameters
        and returns both the image object and its associated drawing context.

        :return: tuple containing the PIL Image object and ImageDraw object for rendering the table.
        """
        img = Image.new(
            "RGB",
            (
                self.x_count * self.rect_width + self.offset + self.header_width,
                self.y_count * self.rect_height + self.offset,
            ),
            self.bg_color,
        )

        draw = ImageDraw.Draw(img)

        return img, draw

    def _get_header_img(self) -> tuple[Image.Image, ImageDraw.ImageDraw]:
        """Create header image and drawing context for application visualization.

        This method initializes a new RGB image with calculated dimensions based on
        the rectangle count and header width, along with its corresponding drawing
        context for rendering header elements.

        :return: tuple containing the header Image object and its ImageDraw context.
        """
        img_header = Image.new(
            "RGB", (self.y_count * self.rect_height + self.offset, self.header_width), self.bg_color
        )
        draw_header = ImageDraw.Draw(img_header)

        return img_header, draw_header

    def _create_table(self) -> None:
        """Create a visual table by drawing rectangles with command text.

        The method iterates through the sorted table list and draws rectangular cells
        in a grid layout. Each cell contains centered text representing a command name.
        The table is drawn with specified colors, fonts, and positioning based on
        the configured grid dimensions and styling properties.

        :raises IndexError: When the grid position exceeds available commands in the table list.
        """
        sorted_list = sorted(self.table_list)
        for i in range(self.y_count):
            for j in range(self.x_count):
                try:
                    command = sorted_list[i * self.x_count + j]
                except IndexError:
                    return

                x1 = j * self.rect_width + self.offset + self.header_width
                y1 = i * self.rect_height + self.offset
                x2 = self.rect_width + j * self.rect_width + self.header_width
                y2 = self.rect_height + i * self.rect_height

                self.draw.rectangle(
                    [(x1, y1), (x2, y2)],
                    fill=self.fill_color,
                    outline=self.outline_color,
                )

                text_w = self.draw.textlength(command, font=self.table_text_font)
                text_h = self.table_font_size

                text_offset_x = (self.rect_width - text_w) / 2
                text_offset_y = (self.rect_height - text_h) / 2

                self.draw.text(
                    (x1 + text_offset_x, y1 + text_offset_y),
                    command,
                    fill=self.bg_color,
                    align="center",
                    font=self.table_text_font,
                )

    def _create_header(self) -> None:
        """Create and draw the header section of the image.

        This method draws a rectangular header with background fill and outline, then centers
        the header text within the rectangle. The header dimensions are calculated based on
        the grid layout and offset values.

        :raises AttributeError: If required drawing objects or fonts are not initialized.
        :raises ValueError: If calculated dimensions result in invalid rectangle coordinates.
        """
        header_h = self.y_count * self.rect_height + self.offset

        x1 = y1 = self.offset
        x2 = y2 = header_h - self.offset

        self.header_draw.rectangle(
            [(x1, y1), (x2, y2)],
            fill=self.fill_color,
            outline=self.outline_color,
        )

        text_w = self.draw.textlength(self.header_text, font=self.header_text_font)

        text_offset_x = (x2 - x1 - text_w) / 2 + self.offset

        self.header_draw.text(
            (text_offset_x, self.header_width / 2 - self.offset),
            self.header_text,
            font=self.header_text_font,
            fill=self.bg_color,
        )

    def _draw_img(self) -> None:
        """Draw the complete image by combining table and header components.

        This method orchestrates the image creation process by first generating
        the data table and header components, then rotating the header 90 degrees
        and compositing it with the main image.

        :raises AttributeError: If header_img or img attributes are not properly initialized.
        :raises PIL.UnidentifiedImageError: If image operations fail due to corrupted image data.
        """
        self._create_table()
        self._create_header()

        rotated_img_apps_header = self.header_img.rotate(90, expand=1)
        Image.Image.paste(self.img, rotated_img_apps_header, (0, 0))

    def show(self) -> None:
        """Show image in separate window.

        Displays the image using the default system image viewer in a new window.
        This method provides a convenient way to visually inspect the generated image.

        :raises SPSDKError: If the image cannot be displayed or no default viewer is available.
        """
        self.img.show()

    def save(self, path: str) -> None:
        """Save image to provided path.

        :param path: Absolute or relative file path where the image will be saved.
        :raises OSError: If the file cannot be written to the specified path.
        :raises ValueError: If the path is invalid or the image format is not supported.
        """
        self.img.save(path)


def get_spsdk_apps() -> list[str]:
    """Get list of all SPSDK applications.

    Retrieves all available SPSDK command-line applications by accessing the main
    commands registry and filtering out utility commands and general commands
    that are not application-specific.

    :return: List of SPSDK application names.
    """
    commands = spsdk_main.commands
    commands.pop("utils")  # remove utils group commands
    if "get-families" in commands:
        commands.pop("get-families")  # remove general get-families
    return list(commands.keys())


def concat_img(im1: Image.Image, im2: Image.Image, im3: Image.Image) -> Image.Image:
    """Concatenate three images vertically into a single image.

    The method creates a new RGB image with combined height and pastes the input images
    one below another in the order: im1 (top), im2 (middle), im3 (bottom).

    :param im1: First image to be placed at the top.
    :param im2: Second image to be placed in the middle.
    :param im3: Third image to be placed at the bottom.
    :return: New concatenated image with combined height of all input images.
    """
    dst = Image.new("RGB", (im1.width, im1.height + im2.height + im3.height))
    dst.paste(im1, (0, 0))
    dst.paste(im2, (0, im1.height))
    dst.paste(im3, (0, im1.height + im2.height))
    return dst


def main() -> None:
    """Generate documentation images for SPSDK architecture components.

    This function creates visual documentation by generating images that represent
    the SPSDK architecture including APIs, applications, and tools. The images
    are created as tables and combined into an architecture overview diagram.

    :raises OSError: When unable to create output directory or save images.
    :raises SPSDKError: When SPSDK apps discovery fails.
    """
    print("Generating pictures for documentation")
    # gets list of SPSDK apps
    apps_list = get_spsdk_apps()
    # list of APIs
    apis_list = [
        "Shadow Registers",
        "Protected Flash Region",
        "Crypto",
        "Master Boot Image",
        "Secure Binary File",
        "EdgeLock Enclave",
        "Image",
        "Debug Authentication",
        "Mboot Protocol",
        "SDP(S) Protocol",
        "Debuggers",
        "DK6",
        "DICE",
        "EdgeLock 2GO",
        "Fuses",
        "SHE",
        "LPC programming",
        "WPC",
        "UBoot",
        "Memory Configuration",
    ]

    tools_list = ["MCUXpresso SEC tool", "Mass production tools", "3rd party tools"]

    # sort list if needed
    apis_list.sort()

    # create instance of img classes
    img_api = ImgTable(
        table_list=apis_list, header_text="APIs Modules", table_font_size=25, font=IMG_FONT_PATH
    )
    img_apps = ImgTable(apps_list, "Applications", font=IMG_FONT_PATH)
    img_tools = ImgTable(
        tools_list, "Tools", table_font_size=25, rect_height=150, font=IMG_FONT_PATH
    )

    # create architecture image by concatenating them
    img_architecture = concat_img(img_tools.img, img_apps.img, img_api.img)

    # show images
    if SHOW_IMG:
        img_api.show()
        img_apps.show()
        img_tools.show()
        img_architecture.show()

    # save them
    os.makedirs(IMG_PATH, exist_ok=True)
    img_apps.save(IMG_APPS_PATH)
    img_api.save(IMG_APIS_PATH)
    img_architecture.save(IMG_ARCHITECTURE_PATH)
    print("Generation done")


def setup(app: Any) -> None:
    """Setup Sphinx extension for generating application images.

    Initializes the generate_apps_img extension by calling the main function
    to generate application images for documentation.

    :param app: Sphinx application instance.
    """
    main()


if __name__ == "__main__":
    main()
