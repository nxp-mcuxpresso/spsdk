#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


"""SPSDK certificate to public key extraction utility for testing.

This module provides functionality for extracting public keys from X.509 certificates
in the SPSDK testing context. It serves as a test data utility for validating
certificate and public key operations in secure boot scenarios.
"""

from spsdk.crypto.certificate import Certificate

cert = Certificate.load("keys_and_certs/root_k0_signed_cert0_noca.der.cert")
cert.get_public_key().save("keys_and_cers/root_k0_public_key.pub")
