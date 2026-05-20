#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Integration submodule for LMS."""

import importlib.util
from typing import Optional, Union

from typing_extensions import Literal

IS_LMS_SUPPORTED = importlib.util.find_spec("pyhsslms") is not None

if IS_LMS_SUPPORTED:
    # pylint: disable=import-error
    import pyhsslms
    from pyhsslms import LmsPrivateKey, LmsPublicKey
    from pyhsslms.pyhsslms import lmots_params, lms_params

    from spsdk.exceptions import SPSDKError

    class LMSParams:
        """LMS key parameter set."""

        def __init__(
            self,
            hash_length: Literal[32, 24],
            height: Literal[5, 10, 15, 20, 25],
            w: Literal[1, 2, 4, 8],
            hash_alg: str = "sha256",  # Literal["sha256", "shake", "shake256"],
            seed: Optional[bytes] = None,
            i: Optional[bytes] = None,
            q: int = 0,
        ):
            """Initialize LMS parameter set."""
            self.hash_alg = hash_alg
            if self.hash_alg == "shake256":
                self.hash_alg = "shake"
            self.hash_length = hash_length
            self.height = height
            self.w = w
            self.seed = seed
            self.i = i
            self.q = q

        def __repr__(self) -> str:
            """Object description in string format."""
            return f"H={self.hash_alg}, n={self.hash_length}, h={self.height}, w={self.w}"

        def get_lmots_param(self) -> bytes:
            """Get the LMOTS parameter based on the current configuration."""
            return getattr(pyhsslms, f"lmots_{self.hash_alg}_n{self.hash_length}_w{self.w}")

        def get_lms_param(self) -> bytes:
            """Get the LMS parameter based on the current configuration."""
            return getattr(pyhsslms, f"lms_{self.hash_alg}_m{self.hash_length}_h{self.height}")

        @classmethod
        def from_params(cls, lms_param: int, lmots_param: int) -> "LMSParams":
            """Create LMSParams from LMS and LMOTS parameters."""
            lms_type = lms_param.to_bytes(4, "big")
            alg1, m, h = lms_params[lms_type]
            lmots_type = lmots_param.to_bytes(4, "big")
            alg2, n, _p, w, _ls = lmots_params[lmots_type]
            if alg1 != alg2:
                raise SPSDKError("Hash algorithm mismatch between LMS and LMOTS parameters")
            if m != n:
                raise SPSDKError("Hash length mismatch between LMS and LMOTS parameters")
            return LMSParams(hash_alg=alg1, hash_length=m, height=h, w=w)

        @classmethod
        def from_data(cls, data: bytes) -> "LMSParams":
            """Create LMSParams from raw key data."""
            if len(data) < 8:
                raise SPSDKError("Insufficient data for LMS parameters extraction")

            lms_type = int.from_bytes(data[:4], "big")
            lmots_type = int.from_bytes(data[4:8], "big")

            return cls.from_params(lms_type, lmots_type)

        def get_private_key_length(self) -> int:
            """Get the length of the private key based on current parameters."""
            #  4 bytes for LMS type
            #  4 bytes for LMOTS type
            #  hash_length bytes for seed
            # 16 bytes for I (identifier)
            #  4 bytes for leaf index (q)
            return 4 + 4 + self.hash_length + 16 + 4

        def get_public_key_length(self) -> int:
            """Get the length of the public key based on current parameters."""
            #  4 bytes for LMS type
            #  4 bytes for LMOTS type
            # 16 bytes for I (identifier)
            #  hash_length bytes for public key root
            return 4 + 4 + 16 + self.hash_length

        def generate_private_key(self) -> LmsPrivateKey:
            """Generate a new LMS private key with current parameters."""
            lmots_param = self.get_lmots_param()
            lms_param = self.get_lms_param()
            return LmsPrivateKey(
                lms_type=lms_param, lmots_type=lmots_param, SEED=self.seed, I=self.i, q=self.q
            )

        @classmethod
        def from_key(cls, key: Union[LmsPublicKey, LmsPrivateKey]) -> "LMSParams":
            """Create LMSParams from an existing LMS private key."""
            alg1, m, h = lms_params[key.lms_type]
            alg2, n, _p, w, _ls = lmots_params[key.lmots_type]

            if alg1 != alg2:
                raise SPSDKError("Hash algorithm mismatch between LMS and LMOTS parameters")
            if m != n:
                raise SPSDKError("Hash length mismatch between LMS and LM-OTS parameters")

            init_params = {
                "hash_alg": alg1,
                "hash_length": m,
                "height": h,
                "w": w,
                "i": key.I,
            }
            if isinstance(key, LmsPrivateKey):
                init_params["seed"] = key.SEED
                init_params["q"] = key.q

            return LMSParams(**init_params)

        @staticmethod
        def calc_signature_length(key: Union[LmsPublicKey, LmsPrivateKey]) -> int:
            """Calculate signature length for given key."""
            _alg1, m, h = lms_params[key.lms_type]
            _alg2, n, p, _w, _ls = lmots_params[key.lmots_type]

            lmots_sig_size = 4 + n * (p + 1)
            size = 4 + lmots_sig_size + 4 + h * m
            return size
