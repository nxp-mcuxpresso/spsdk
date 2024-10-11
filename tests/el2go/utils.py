#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

from functools import wraps
from unittest.mock import patch


def mock_time_sleep(func):
    @wraps(func)
    def decorator(*args, **kwargs):
        with patch("time.sleep"):
            return func(*args, **kwargs)

    return decorator
