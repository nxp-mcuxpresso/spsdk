#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

from spsdk.crypto.rng import random_bytes


def test_random_bytes():
    random = random_bytes(16)
    assert isinstance(random, bytes)
    assert len(random) == 16
    assert random != random_bytes(16)
