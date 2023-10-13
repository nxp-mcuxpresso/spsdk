#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


from spsdk.crypto.certificate import Certificate

cert = Certificate.load("keys_and_certs/root_k0_signed_cert0_noca.der.cert")
cert.get_public_key().save("keys_and_cers/root_k0_public_key.pub")
