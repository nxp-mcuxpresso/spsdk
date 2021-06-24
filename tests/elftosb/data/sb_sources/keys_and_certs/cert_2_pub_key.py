#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

from spsdk.crypto import load_certificate, save_rsa_public_key

cert = load_certificate("keys_and_certs/root_k0_signed_cert0_noca.der.cert")
pub_key = cert.public_key()
save_rsa_public_key(pub_key, "keys_and_cers/root_k0_public_key.pub")
