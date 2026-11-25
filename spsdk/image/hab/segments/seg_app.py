#!/usr/bin/env python
#
# Copyright 2025-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK HAB Application segment implementation.

This module provides functionality for handling Application segments
in the High Assurance Boot (HAB) container format used by NXP MCUs.
"""

import logging
import os
from struct import calcsize, unpack_from

from typing_extensions import Self

from spsdk.exceptions import SPSDKParsingError
from spsdk.image.hab.hab_header import Header
from spsdk.image.hab.segments.seg_ivt import HabSegmentIvt
from spsdk.image.hab.segments.segment import HabSegmentBase, HabSegmentEnum
from spsdk.image.hab.utils import (
    get_app_image,
    get_initial_load_size,
    get_ivt_offset_from_cfg,
    get_reset_vector,
)
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import align_block, write_file
from spsdk.utils.verifier import Verifier

logger = logging.getLogger(__name__)
UNKNOWN_FAMILY = FamilyRevision("unknown")
# Boot Data Table format (start address, length, plugin flag)
BDT_FORMAT = "<3L"


class HabSegmentApp(HabSegmentBase):
    """HAB Application Segment representation.

    This class manages application binary data within HAB (High Assurance Boot) segments,
    providing functionality to load, parse, and export application code for secure boot
    operations.

    :cvar SEGMENT_IDENTIFIER: HAB segment type identifier for application segments.
    """

    SEGMENT_IDENTIFIER = HabSegmentEnum.APP

    def __init__(self, binary: bytes) -> None:
        """Initialize XMCD HAB segment.

        Creates a new XMCD HAB segment instance with the provided application binary data.

        :param binary: Application binary data to be stored in the segment.
        """
        self.binary = binary

    def __repr__(self) -> str:
        """Return string representation of APP HAB segment.

        :return: String identifier for the APP HAB segment.
        """
        return "APP HAB segment"

    def __str__(self) -> str:
        """Get info of App Segment as a string.

        Returns a formatted string containing information about the CSF APP segment,
        including its binary data length and offset position.

        :return: Formatted string with segment information.
        """
        info = "CSF APP segment"
        info += f" Length:                      {len(self.binary)}\n"
        info += f" Offset:                      {self.offset}\n"
        return info

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load the APP HAB segment from HAB configuration.

        The method creates an APP segment by extracting the application binary from the
        configuration, applying alignment if required based on flags, and setting the
        appropriate offset based on initial load size and IVT offset.

        :param config: HAB configuration object containing application and segment settings.
        :return: Instance of APP HAB segment with configured binary data and offset.
        """
        options = config.get_config("options")
        app_bin = get_app_image(config).export()
        if (options["flags"] & 0xF) >> 3:
            app_bin = align_block(app_bin, 16)
        offset = get_initial_load_size(config) - get_ivt_offset_from_cfg(config)
        segment = cls(app_bin)
        segment.offset = offset
        return segment

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the Feature.

        The method generates configuration data for the APP segment, including the application
        binary file. The binary data is saved to a file in the specified data path.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        ret_cfg = Config()

        # Save the application binary to a file
        filename = "application.bin"
        write_file(
            data=self.binary,
            path=os.path.join(data_path, filename),
            mode="wb",
        )

        ret_cfg["inputImageFile"] = filename

        return ret_cfg

    def export(self) -> bytes:
        """Export object into bytes array.

        :return: Raw binary block of segment
        """
        return self.binary

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision = UNKNOWN_FAMILY) -> Self:
        """Parse APP segment block from image binary.

        The method extracts the application segment from HAB container data by first parsing
        the IVT segment and then determining the correct application offset from known possible
        offsets, validating the Cortex-M reset vector (Thumb state execution). When no Cortex-M
        vector table is found, or the IVT entry point is a non-Thumb (even) address inside the
        image other than the found vector table (e.g. Cortex-A based i.MX6 / i.MX8M images),
        the application offset is taken from the IVT entry point. Without CSF, the application end is limited
        by the image length stored in the Boot Data Table.

        :param data: Binary data of HAB container to be parsed.
        :param family: Family revision information for parsing context.
        :raises SPSDKParsingError: When application offset could not be found.
        :return: Instance of APP HAB segment with parsed binary data and offset.
        """
        ivt = HabSegmentIvt.parse(data)
        min_offset = cls._get_headers_end(data, ivt)
        offset = cls._find_cortex_m_app_offset(data, ivt, min_offset)
        entry_offset = ivt.app_address - ivt.ivt_address
        if (
            offset is not None
            and offset != entry_offset
            and not ivt.app_address % 2
            and min_offset <= entry_offset < len(data)
        ):
            # Cortex-M entry point is the Thumb reset handler (odd address) or the vector table
            # itself; an even entry point elsewhere inside the image is a Cortex-A entry point
            # and application data only resemble a vector table
            logger.debug(
                f"Ignoring the vector table candidate at {offset:#x}, the IVT entry point "
                f"{ivt.app_address:#x} is not a Thumb address"
            )
            offset = None
        if offset is not None:
            end = ivt.csf_address - ivt.ivt_address if ivt.csf_address > 0 else len(data)
        else:
            offset, end = cls._get_entry_point_app_range(data, ivt, min_offset)
        binary = data[offset:end]
        segment = cls(binary)
        segment.offset = offset
        return segment

    @staticmethod
    def _get_headers_end(data: bytes, ivt: HabSegmentIvt) -> int:
        """Get the end offset of HAB headers (IVT, BDT and DCD) preceding the application.

        :param data: Binary data of HAB container.
        :param ivt: Parsed IVT segment of the HAB container.
        :raises SPSDKParsingError: When the Boot Data Table is out of the input data.
        :return: Lowest possible application offset relative to IVT.
        """
        bdt_offset = ivt.bdt_address - ivt.ivt_address
        min_offset = bdt_offset + calcsize(BDT_FORMAT)
        if min_offset > len(data):
            raise SPSDKParsingError("Boot Data Table is out of the input data")
        if ivt.dcd_address:
            dcd_offset = ivt.dcd_address - ivt.ivt_address
            if dcd_offset + Header.SIZE <= len(data):
                min_offset = max(min_offset, dcd_offset + Header.parse(data[dcd_offset:]).length)
        return min_offset

    @staticmethod
    def _find_cortex_m_app_offset(data: bytes, ivt: HabSegmentIvt, min_offset: int) -> int | None:
        """Find application offset by looking for a Cortex-M vector table.

        Searches through predefined offset values to find the correct application start position
        by validating the reset vector at each offset. The reset vector must be non-zero, within
        the expected address range, and have the least significant bit set for Thumb execution.

        :param data: Binary data of HAB container.
        :param ivt: Parsed IVT segment of the HAB container.
        :param min_offset: Lowest possible application offset (end of HAB headers).
        :return: Application offset or None if no Cortex-M vector table has been found.
        """
        known_offsets = [0x100, 0x400, 0xC00, 0x1000, 0x2000]
        for offset in known_offsets:
            if offset < min_offset:
                logger.debug(f"The offset {offset:#x} overlaps the HAB headers")
                continue
            logger.debug(f"Testing the potential application on offset {offset}")
            reset_vector = get_reset_vector(data[offset:])
            if reset_vector == 0:
                logger.debug("The reset vector cannot be 0x0")
                continue
            # there are some cases where the reset vector and the entrypoint address are not same
            # reset vector inside the given range is accepted
            range_start = ivt.app_address - 0x400
            range_end = ivt.app_address + len(data)
            if reset_vector not in range(range_start, range_end):
                logger.debug(
                    f"The reset vector {reset_vector:#x} is not inside the range "
                    f"{range_start:#x}:{range_end:#x}"
                )
                continue
            if not reset_vector % 2:
                logger.debug(
                    "The least significant bit is not set to 1, indicating Thumb state execution"
                )
                continue
            return offset
        return None

    @staticmethod
    def _get_entry_point_app_range(
        data: bytes, ivt: HabSegmentIvt, min_offset: int
    ) -> tuple[int, int]:
        """Get application range from the IVT entry point and the Boot Data Table.

        Used for images without Cortex-M vector table (e.g. Cortex-A based i.MX6 and i.MX8M
        images), where the IVT entry point points directly to the first application instruction.
        The application ends at the CSF (if present) or at the image end defined by the BDT
        length, limited by the size of the input data.

        :param data: Binary data of HAB container.
        :param ivt: Parsed IVT segment of the HAB container.
        :param min_offset: Lowest possible application offset (end of HAB headers).
        :raises SPSDKParsingError: When application offset could not be found.
        :return: Tuple of application start and end offsets relative to IVT.
        """
        offset = ivt.app_address - ivt.ivt_address
        if not min_offset <= offset < len(data):
            raise SPSDKParsingError("Application offset could not be found")
        logger.debug(f"Using the IVT entry point offset {offset:#x} as application offset")
        if ivt.csf_address:
            end = ivt.csf_address - ivt.ivt_address
        else:
            # Boot Data Table items: image start address, image length, plugin flag
            app_start, app_length, _ = unpack_from(
                BDT_FORMAT, data, ivt.bdt_address - ivt.ivt_address
            )
            # The BDT image length is counted from the image start (IVT offset included)
            end = app_length - (ivt.ivt_address - app_start)
        if not offset < end <= len(data):
            end = len(data)
        return offset, end

    @property
    def size(self) -> int:
        """Get size of the segment.

        :return: Size of the segment in bytes.
        """
        return len(self.binary)

    def verify(self) -> Verifier:
        """Verify App segment data.

        Creates a verifier object to validate the application segment, including
        the binary data and offset information.

        :return: Verifier object containing validation records for the application segment.
        """
        ret = Verifier("Application segment")
        ret.add_record_bytes("Application binary", self.binary)
        ret.add_record_range("Application offset", self.offset)
        return ret
