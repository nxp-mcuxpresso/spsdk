#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Script for creation of image with all SPSDK apps"""
import math
import os
from typing import List, Optional, Tuple

from PIL import Image, ImageDraw, ImageFont

from spsdk.apps.spsdk_apps import main as spsdk_main

IMG_PATH = os.path.join(os.path.abspath("."), "_static/images/")
IMG_APPS_PATH = os.path.join(IMG_PATH, "spsdk-architecture-apps.png")
IMG_APIS_PATH = os.path.join(IMG_PATH, "spsdk-architecture-apis.png")
IMG_ARCHITECTURE_PATH = os.path.join(IMG_PATH, "spsdk-architecture.png")

IMG_FONT_PATH = os.path.join(os.path.abspath("."), "_static/fonts/Poppins-Regular.ttf")

SHOW_IMG = False


class ImgTable:
    """Class for generating table like images for the purpose of documentation"""

    def __init__(
        self,
        table_list: List[str],
        header_text: str,
        x_count: int = 3,
        y_count: Optional[int] = None,
        rect_width: int = 300,
        rect_height: int = 100,
        offset: int = 10,
        table_font_size: int = 30,
        header_font_size: int = 45,
        header_width: int = 100,
        bg_color: Tuple[int, int, int] = (67, 126, 180),
        fill_color: str = "white",
        outline_color: str = "black",
        font: str = "Helvetica",
    ) -> None:
        """Constructor for the ImgTable

        :param table_list: list of string that will be printed
        :param header_text: text of header on the left side
        :param x_count: count of columns in the table, defaults to 2
        :param y_count: count of rows in the table, defaults to 4
        :param rect_width: width of the rectangle with text, defaults to 600
        :param rect_height: height of the rectangle with text, defaults to 200
        :param offset: space between rectangles, defaults to 20
        :param table_font_size: font size of for the text in table, defaults to 60
        :param header_font_size: header font size, defaults to 90
        :param header_width: width of the header, defaults to 200
        :param bg_color: background color, defaults to (67, 126, 180)
        :param fill_color: fill/text color, defaults to "white"
        :param outline_color: outline color, defaults to "black"
        :param font: font, path to font file or name, defaults to "Helvetica"
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

    def _get_img(self) -> Tuple[Image.Image, ImageDraw.Draw]:
        """Returns Image and Draw for table.

        :return: tuple of Image and Draw
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

    def _get_header_img(self) -> Tuple[Image.Image, ImageDraw.Draw]:
        """Returns header Image and Draw.

        :return: tuple of Image and Draw
        """
        img_header = Image.new(
            "RGB", (self.y_count * self.rect_height + self.offset, self.header_width), self.bg_color
        )
        draw_header = ImageDraw.Draw(img_header)

        return img_header, draw_header

    def _create_table(self):
        """Draws rectangle as table"""
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

    def _create_header(self):
        """Draws header."""
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

    def _draw_img(self):
        """Draws the whole image with table and header"""
        self._create_table()
        self._create_header()

        rotated_img_apps_header = self.header_img.rotate(90, expand=1)
        Image.Image.paste(self.img, rotated_img_apps_header, (0, 0))

    def show(self):
        """Shows image in separate window"""
        self.img.show()

    def save(self, path: str):
        """Save image to provided path

        :param path: path where the image will be saved
        """
        self.img.save(path)


def get_spsdk_apps() -> List[str]:
    """Gets list of all SPSDK apps.

    :return: list of all SPSDK apps
    """
    commands = spsdk_main.commands
    commands.pop("utils")  # remove utils group commands
    if "get-families" in commands:
        commands.pop("get-families")  # remove general get-families
    return list(commands.keys())


def concat_img(im1: Image.Image, im2: Image.Image, im3: Image.Image) -> Image.Image:
    """Concatenate images vertically

    :param im1: image 1
    :param im2: image 2
    :param im3: image 3
    :return: Concatenated image
    """
    dst = Image.new("RGB", (im1.width, im1.height + im2.height + im3.height))
    dst.paste(im1, (0, 0))
    dst.paste(im2, (0, im1.height))
    dst.paste(im3, (0, im1.height + im2.height))
    return dst


def main():
    """Main function."""
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
        "AHAB + ELE",
        "Debug Authentication",
        "Mboot Protocol",
        "SDP(S) Protocol",
        "Debuggers",
        "Trust Provisioning",
        "DK6",
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


def setup(app):
    main()


if __name__ == "__main__":
    main()
