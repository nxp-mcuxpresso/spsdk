#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""OpenSSL implementation Hash algorithms."""

# Used security modules

from cryptography.hazmat.primitives import hashes

from spsdk.exceptions import SPSDKError
from spsdk.utils.easy_enum import Enum


class EnumHashAlgorithm(Enum):
    """Hash algorithm enum."""

    SHA1 = (0, "sha1", "SHA1")
    SHA256 = (1, "sha256", "SHA256")
    SHA384 = (2, "sha384", "SHA384")
    SHA512 = (3, "sha512", "SHA512")
    MD5 = (4, "md5", "MD5")
    SM3 = (5, "sm3", "SM3")


def get_hash_algorithm(algorithm: EnumHashAlgorithm) -> hashes.HashAlgorithm:
    """For specified name return hashes algorithm instance.

    :param algorithm: Algorithm type enum
    :return: instance of algorithm class
    :raises SPSDKError: If algorithm not found
    """
    algorithm_name = EnumHashAlgorithm.name(algorithm)
    algo_cls = getattr(hashes, algorithm_name.upper(), None)  # hack: get class object by name
    if algo_cls is None:
        raise SPSDKError(
            f"Unsupported algorithm: hashes.{algorithm_name}".format(name=algorithm_name.upper())
        )

    return algo_cls()  # pylint: disable=not-callable


def get_hash_length(algorithm: EnumHashAlgorithm) -> int:
    """For specified name return hash binary length.

    :param algorithm: Algorithm type enum
    :return: Hash length
    :raises SPSDKError: If algorithm not found
    """
    return get_hash_algorithm(algorithm).digest_size


def get_hash(data: bytes, algorithm: EnumHashAlgorithm = EnumHashAlgorithm.SHA256) -> bytes:
    """Return a HASH from input data with specified algorithm.

    :param data: Input data in bytes
    :param algorithm: Algorithm type enum
    :return: Hash-ed bytes
    :raises SPSDKError: If algorithm not found
    """
    hash_obj = hashes.Hash(get_hash_algorithm(algorithm))
    hash_obj.update(data)
    return hash_obj.finalize()
