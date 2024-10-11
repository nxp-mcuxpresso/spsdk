#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Customer-specific Signature Provider."""

import math
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import rsa

from spsdk import crypto
from spsdk.crypto.keys import PrivateKeyRsa  # type: ignore
from spsdk.crypto.signature_provider import SignatureProvider
from spsdk.utils.misc import find_file


class SuperAwesomeSP(SignatureProvider):
    """Signature Provider based on a remote signing service."""

    # identifier of this signature provider; used in yaml configuration file
    identifier = "file_no_verify"

    def __init__(self, file_path: str, search_paths: Optional[list[str]] = None) -> None:
        """Initialize the plain file signature provider.

        :param file_path: Path to private file
        :param search_paths: List of paths where to search for the file, defaults to None
        :raises SPSDKError: Invalid Private Key
        """
        self.file_path = find_file(file_path=file_path, search_paths=search_paths)
        self.private_key = PrivateKeyRsa.load(self.file_path)

    @property
    def signature_length(self) -> int:
        """Return length of the signature."""
        return self.private_key.signature_size

    def sign(self, data: bytes) -> bytes:
        """Return the signature for data."""

        signature = self.private_key.sign(data=data)
        return signature
