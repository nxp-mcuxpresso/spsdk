#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Trust Provisioning HOST application support."""

import logging
from typing import Callable, Optional

from spsdk.tp.tp_intf import TpDevInterface
from spsdk.utils.misc import Timeout

logger = logging.getLogger(__name__)


class TrustProvisioningConfig:
    """Trust provisioning support in none trusted environment."""

    def __init__(
        self,
        tpdev: TpDevInterface,
        info_print: Callable[[str], None],
    ) -> None:
        """Trust Provisioning Host support class.

        :param tpdev: [description]
        :param info_print: [description]
        """
        self.tpdev = tpdev
        self.info_print = info_print

    def upload(
        self, user_config: dict, user_config_dir: Optional[str] = None, timeout: int = 60
    ) -> None:
        """Upload the user data into the provisioning device."""
        try:
            loc_timeout = Timeout(timeout=timeout, units="s")
            logger.debug("Opening TP device")
            self.tpdev.open()

            self.info_print("Upload provisioning data to TP target")
            self.tpdev.upload(config_data=user_config, config_dir=user_config_dir)

            self.info_print(
                f"TP device personalization ended correctly in {loc_timeout.get_consumed_time_ms()} ms."
            )
        except:
            self.info_print(
                f"TP device personalization FAILED in {loc_timeout.get_consumed_time_ms()} ms."
            )
            raise
        finally:
            logger.debug("Closing TP device")
            self.tpdev.close()

    def setup(self, timeout: int = 60) -> None:
        """Setup the provisioning device."""
        try:
            loc_timeout = Timeout(timeout=timeout, units="s")
            logger.debug("Opening TP device")
            self.tpdev.open()

            self.info_print("Setting up the TP device")
            self.tpdev.setup()
            self.info_print(
                f"TP device setup ended correctly in {loc_timeout.get_consumed_time_ms()} ms."
            )
        except:
            self.info_print(f"TP device setup FAILED in {loc_timeout.get_consumed_time_ms()} ms.")
            raise
        finally:
            logger.debug("Closing TP device")
            self.tpdev.close()

    def seal(self, timeout: int = 60) -> None:
        """Seal the provisioning device."""
        try:
            loc_timeout = Timeout(timeout=timeout, units="s")
            logger.debug("Opening TP device")
            self.tpdev.open()

            self.info_print("Sealing the smart card")

            self.tpdev.seal()
            self.info_print(
                f"TP device sealing ended correctly in {loc_timeout.get_consumed_time_ms()} ms."
            )
        except:
            self.info_print(f"TP device sealing FAILED in {loc_timeout.get_consumed_time_ms()} ms.")
            raise
        finally:
            logger.debug("Closing TP device")
            self.tpdev.close()

    def get_counters(self, timeout: int = 60) -> None:
        """Seal the provisioning device."""
        try:
            loc_timeout = Timeout(timeout=timeout, units="s")
            logger.debug("Opening TP device")
            self.tpdev.open()

            self.info_print("Retrieving counters from TP Device.")

            self.info_print(f"Current provisioning counter: {self.tpdev.get_prov_counter():,}")
            self.info_print(f"Provisioning attempts left  : {self.tpdev.get_prov_remainder():,}")
            self.info_print(
                f"TP device counters retrieval ended correctly in {loc_timeout.get_consumed_time_ms()} ms."
            )
        except:
            self.info_print(
                f"TP device counters retrieval FAILED in {loc_timeout.get_consumed_time_ms()} ms."
            )
            raise
        finally:
            logger.debug("Closing TP device")
            self.tpdev.close()
