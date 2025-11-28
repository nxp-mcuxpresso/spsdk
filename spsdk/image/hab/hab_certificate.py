#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""High Assurance Boot (HAB) Certificate module.

This module provides functionality for handling HAB certificates used in NXP's secure boot process.
It allows creating, parsing, and exporting HAB certificate structures that combine headers
with X.509 certificates according to the HAB protocol specifications.
"""
from typing_extensions import Self

from spsdk.crypto.certificate import Certificate
from spsdk.crypto.crypto_types import SPSDKEncoding
from spsdk.image.hab.hab_header import Header, SegmentTag
from spsdk.utils.abstract import BaseClass


class HabCertificate(BaseClass):
    """High Assurance Boot (HAB) Certificate structure.

    This class represents a HAB certificate used in NXP's secure boot process.
    The certificate is formatted according to the HAB protocol specifications
    and consists of a header and certificate data sections for secure authentication.
    """

    def __init__(self, certificate: Certificate, version: int = 0x40) -> None:
        """Initialize the HAB certificate structure.

        :param certificate: Certificate object to be embedded in the structure.
        :param version: HAB version in format 0xMN where M is major and N is minor version,
            defaults to 0x40 (4.0).
        """
        self._header = Header(tag=SegmentTag.CRT.tag, param=version)
        self.cert = certificate
        self._header.length = self.size

    @property
    def size(self) -> int:
        """Calculate the total size of the Certificate structure in bytes.

        The method computes the combined size of the certificate header and the DER-encoded
        certificate data.

        :return: Size of the certificate structure including header and certificate data.
        """
        return self._header.SIZE + len(self.cert.export(SPSDKEncoding.DER))

    def __len__(self) -> int:
        """Return the size of the Certificate structure.

        :return: Size in bytes.
        """
        return self.size

    def __repr__(self) -> str:
        """Return a string representation of the Certificate for debugging.

        :return: String with version and size information.
        """
        return f"Certificate <Ver: {self._header.version_major}.{self._header.version_minor}, Size: {self.size}>"

    def __str__(self) -> str:
        """Return a human-readable string representation of the Certificate.

        Creates a formatted string containing certificate version and size information
        with decorative separators for better readability.

        :return: Formatted string with certificate details including version and size.
        """
        msg = "-" * 60 + "\n"
        msg += (
            f"Certificate (Ver: {self._header.version_major:X}.{self._header.version_minor:X}, "
            f"Size: {self.size})\n"
        )
        msg += "-" * 60 + "\n"
        return msg

    def export(self) -> bytes:
        """Export the complete HAB certificate structure.

        This method combines the header and certificate data into a binary format
        that can be used in the secure boot process.

        :return: Complete HAB certificate as bytes.
        """
        self._header.length = self.size
        raw_data = self._header.export()
        raw_data += self.cert.export(SPSDKEncoding.DER)
        return raw_data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse a HAB certificate from binary data.

        This method creates a new HabCertificate instance by parsing the provided binary data,
        extracting the header information and certificate structure.

        :param data: Binary data containing a HAB certificate structure
        :raises ValueError: If the data doesn't contain a valid HAB certificate structure
        :return: New HabCertificate instance created from the provided data
        """
        header = Header.parse(data, SegmentTag.CRT.tag)
        return cls(Certificate.parse(data[Header.SIZE : header.length]), header.param)
