#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Trust Provisioning HOST application support."""
import base64
import concurrent.futures
import logging
import math
import multiprocessing
import os
import secrets
import struct
import time
from functools import partial
from typing import Callable, Optional, Sequence

from spsdk.crypto.crypto_types import SPSDKEncoding
from spsdk.crypto.keys import PublicKeyEcc
from spsdk.crypto.utils import extract_public_key
from spsdk.exceptions import SPSDKError
from spsdk.tp.adapters.tptarget_blhost import TpTargetBlHost
from spsdk.tp.adapters.utils import detect_new_usb_path, get_current_usb_paths, update_usb_path
from spsdk.tp.data_container import (
    AuditLog,
    AuditLogCounter,
    AuditLogRecord,
    Container,
    DataEntry,
    PayloadType,
)
from spsdk.tp.exceptions import SPSDKTpError
from spsdk.tp.tp_intf import TpDevInterface, TpTargetInterface
from spsdk.utils.database import DatabaseManager, Features, get_db
from spsdk.utils.misc import Timeout, write_file

logger = logging.getLogger(__name__)

REOPEN_WAIT_TIME = 0.3
ALLOW_ARBITRARY_START = True


class TrustProvisioningHost:
    """Trust provisioning support in none trusted environment."""

    def __init__(
        self,
        tpdev: TpDevInterface,
        tptarget: TpTargetInterface,
        info_print: Callable[[str], None],
    ) -> None:
        """Trust Provisioning Host support class.

        :param tpdev: TP device instance
        :param tptarget: TP target instance
        :param info_print: Method for printing messages
        """
        self.tpdev = tpdev
        self.tptarget = tptarget
        self.info_print = info_print

    def load_provisioning_fw(
        self,
        prov_fw: bytes,
        family: str,
        timeout: int = 60,
        skip_test: bool = True,
        keep_target_open: bool = True,
        skip_usb_enumeration: bool = False,
    ) -> None:
        """Method loads the provisioning firmware into device.

        :param prov_fw: Provisioning Firmware data
        :param family: Chip family
        :param timeout: Timeout for loading provisioning firmware operation in seconds.
        :param skip_test: Skip test for checking that OEM Provisioning Firmware booted-up
        :param keep_target_open: Keep target device open
        :param skip_usb_enumeration: Skip USB enumeration after loading the Provisioning firmware
        :raises SPSDKTpError: The Provisioning firmware doesn't boot
        """
        db = get_db(family, "latest")
        try:
            if not self.tptarget.is_open:
                self.tptarget.open()
            self.info_print("1.1.Step - Updating CFPA page")
            self.update_cfpa_page(family=family, database=db)
            self.info_print("1.2.Step - Erase memory for provisioning firmware")
            self.erase_memory(database=db)
            self.info_print("1.3.Step - Loading OEM provisioning firmware")
        except SPSDKError as e:
            self.tptarget.close()
            raise SPSDKTpError(f"Unable to prepare the MCU: {e}") from e

        try:
            if self.tptarget.uses_usb:
                initial_usb_set = get_current_usb_paths()
            else:
                initial_usb_set = None

            self.tptarget.load_sb_file(prov_fw, timeout)
            # Need to reset the connection due to re-init on the MCU side
            self.tptarget.close()

            if self.tptarget.uses_usb and not skip_usb_enumeration:
                assert isinstance(self.tptarget, TpTargetBlHost)
                new_usb_path = detect_new_usb_path(initial_set=initial_usb_set)
                update_usb_path(self.tptarget, new_usb_path=new_usb_path)

            logger.info(f"Waiting for {REOPEN_WAIT_TIME} seconds for the ProvFW to boot up.")
            time.sleep(REOPEN_WAIT_TIME)

            if not skip_test:
                self.info_print("1.4.Step - Checking whether provisioning firmware booted.")
                self.tptarget.open()
                if not self.tptarget.check_provisioning_firmware():
                    raise SPSDKError("Provisioning firmware did not boot properly")

            if keep_target_open and not self.tptarget.is_open:
                self.tptarget.open()

        except SPSDKError as e:
            self.tptarget.close()
            raise SPSDKTpError(
                f"Can't load/connect to the TrustProvisioning Firmware. Error: {e}\n"
                "Please make sure your device supports TrustProvisioning."
            ) from e

    def update_cfpa_page(self, family: str, database: Features) -> None:
        """Update CFPA page according to chip family."""
        if not database.get_bool(DatabaseManager.TP, "need_cfpa_update"):
            logger.info("CFPA update not required")
            return

        cfpa_address = database.get_int(DatabaseManager.PFR, ["cfpa", "address"])
        cfpa_size = database.get_int(DatabaseManager.PFR, ["cfpa", "size"])
        cfpa_version_offset = database.get_int(DatabaseManager.TP, "version_offset")
        cfpa_revoke_offset = database.get_int(DatabaseManager.TP, "revoke_offset")

        # change bytes to bytearray to make it writeable
        cfpa_data = bytearray(self.tptarget.read_memory(cfpa_address, cfpa_size))

        # CFPA REVOKE field update
        if database.get_bool(DatabaseManager.TP, "need_revoke_update"):
            cfpa_revoke: int = struct.unpack_from("<L", cfpa_data, offset=cfpa_revoke_offset)[0]
            if cfpa_revoke & 0x55 == 0x55:
                logger.info("RKTH_REVOKE is already set, no need to update CFPA")
                return
            # just set required bits (in case user already set other bits)
            cfpa_revoke |= 0x55
            struct.pack_into("<L", cfpa_data, cfpa_revoke_offset, cfpa_revoke)
        else:
            raise SPSDKTpError(f"Don't know how to update CFPA for {family}")

        # cfpa update is a generic thing for all families
        cfpa_version: int = struct.unpack_from("<L", cfpa_data, offset=cfpa_version_offset)[0]
        cfpa_version += 1
        struct.pack_into("<L", cfpa_data, cfpa_version_offset, cfpa_version)

        self.tptarget.write_memory(cfpa_address, data=bytes(cfpa_data))
        logger.info("CFPA update completed")

    def erase_memory(self, database: Features) -> None:
        """Erase part(s) of flash memory if needed."""
        if not database.get_bool(DatabaseManager.TP, "erase_memory"):
            logger.info("Erasing memory is not needed")
            return

        start = database.get_int(DatabaseManager.TP, "erase_memory_start")
        length = database.get_int(DatabaseManager.TP, "erase_memory_length")

        self.tptarget.erase_memory(address=start, length=length)
        logger.info("Erasing memory completed")

    def do_provisioning(
        self,
        family: str,
        audit_log: str,
        prov_fw: Optional[bytes] = None,
        product_fw: Optional[bytes] = None,
        timeout: int = 60,
        save_debug_data: bool = False,
    ) -> None:
        """Do provisioning process.

        :param family: Chip family
        :param audit_log: Path to audit log
        :param prov_fw: Use own provisioning firmware, defaults to None
        :param product_fw: Load also the final product application, defaults to None
        :param timeout: The timeout of operation is seconds.
        :param save_debug_data: Save transmitted data in CWD for debugging purposes
        :raises SPSDKTpError: Device family is not supported
        :raises SPSDKTpError: Error during trust-provisioning operation
        """
        try:
            loc_timeout = Timeout(timeout, "s")
            logger.debug("Opening TP DEVICE interface")
            self.tpdev.open()
            audit_log_dirname = os.path.dirname(os.path.abspath(audit_log))

            if os.path.isfile(audit_log):
                self.info_print("0.Step - Check Audit Log ownership")
                self.tpdev.check_log_owner(audit_log)

            elif not os.path.exists(audit_log_dirname):
                self.info_print(" - Creating directory for the audit log")
                os.makedirs(audit_log_dirname)

            logger.debug("Opening TP TARGET interface")
            self.tptarget.open()

            self.info_print("1.Step - Provide to target provisioning firmware if needed.")
            if prov_fw:
                self.load_provisioning_fw(
                    prov_fw=prov_fw,
                    family=family,
                    timeout=loc_timeout.get_rest_time_ms(True),
                    skip_test=True,
                    keep_target_open=True,
                    skip_usb_enumeration=False,
                )

            self.info_print("2.Step - Get the initial challenge from TP device.")
            challenge = self.tpdev.get_challenge(timeout=loc_timeout.get_rest_time_ms(True))

            logger.info(f"TP Challenge:\n{Container.parse(challenge)}")
            if save_debug_data:
                write_file(challenge, "x_challenge.bin", "wb")

            self.info_print("3.Step - Prove a genuinity in TP target.")
            tp_data = self.tptarget.prove_genuinity_challenge(
                challenge, timeout=loc_timeout.get_rest_time_ms(True)
            )

            logger.info(f"TP Response:\n{Container.parse(tp_data)}")
            if save_debug_data:
                write_file(tp_data, "x_tp_response.bin", "wb")

            self.info_print("4.Step - Authenticate TP response from TP target.")
            wrapped_data = self.tpdev.authenticate_response(
                tp_data, timeout=loc_timeout.get_rest_time_ms(True)
            )

            logger.info(f"TP ISP WRAPPED DATA:\n{Container.parse(wrapped_data)}")
            if save_debug_data:
                write_file(wrapped_data, "x_wrapped_data.bin", "wb")

            self.info_print("5.Step - Create Audit Log record.")
            self.create_audit_log_record(wrapped_data, audit_log)

            self.info_print("6.Step - Set the wrapped data from the TP device to target.")
            self.tptarget.set_wrapped_data(wrapped_data, timeout=loc_timeout.get_rest_time_ms(True))

            self.info_print("7.Step - The target is provisioned, commencing Reset.")
            self.tptarget.reset_device()

            if product_fw:
                self.info_print("8.Step - Loading customer application.")
                logger.info(f"Waiting for {REOPEN_WAIT_TIME} seconds for the ROM to boot up.")
                time.sleep(REOPEN_WAIT_TIME)
                self.tptarget.open()
                self.tptarget.load_sb_file(product_fw, timeout=loc_timeout.get_rest_time_ms(True))

            self.info_print(
                f"Trust provisioning process ends correctly in {loc_timeout.get_consumed_time_ms()} ms."
            )
        except:
            self.info_print(
                f"Trust provisioning process FAILED in {loc_timeout.get_consumed_time_ms()} ms."
            )
            raise
        finally:
            self.tpdev.close()
            self.tptarget.close()

    def create_audit_log_record(self, data: bytes, audit_log: str) -> None:
        """Create an audit log record out of data representing ISP_WRAP_DATA container."""
        logger.info(f"Using log file {audit_log}")
        record = AuditLogRecord.from_data(container_data=data)
        record.save(audit_log, str(self.tpdev.descriptor.get_id()))

    @staticmethod
    def verify_extract_log(
        audit_log: str,
        audit_log_key: str,
        destination: Optional[str] = None,
        skip_nxp: bool = False,
        skip_oem: bool = False,
        cert_index: Optional[int] = None,
        encoding: SPSDKEncoding = SPSDKEncoding.PEM,
        max_processes: Optional[int] = None,
        info_print: Callable[[str], None] = lambda x: None,
        force_rewrite: bool = True,
    ) -> AuditLogCounter:
        """Verifying audit log with given key (public/private).

        :param audit_log: Path to audit log
        :param audit_log_key: Path to public/private key for verification
        :param destination: Path to destination directory for extracted certificates
        :param skip_nxp: Skip extracting the NXP Devattest certificates
        :param skip_oem: Skip extracting the OEM x509 Devattest certificates
        :param cert_index: Select single OEM certificate to extract, default None = all certificates
        :param encoding: Certificate encoding, defaults to SPSDK_Encoding.PEM
        :param max_processes: Maximum number od parallel process to use, defaults to CPU count
        :param info_print: Method for printing messages
        :param force_rewrite: Skip checking for empty destination directory and rewrite existing content
        :raises SPSDKTpError: Audit log record or chain is invalid
        """
        try:
            loc_timeout = Timeout(timeout=0, units="s")
            info_print(f"Verifying the Audit log: {audit_log}")
            logger.info(f"Extracting public key from {audit_log_key}")

            log_key = extract_public_key(audit_log_key)
            assert isinstance(log_key, PublicKeyEcc)
            # PublicKey can't be passed to other processes we have serialize it
            log_key_data = log_key.export()

            if destination:
                os.makedirs(destination, exist_ok=True)

            # create partial method to save typing later, because readability counts
            store_certificate_method = partial(
                _extract_certificates,
                destination_dir=destination,
                skip_nxp=skip_nxp,
                skip_oem=skip_oem,
                cert_index=cert_index,
                encoding=encoding,
                force_rewrite=force_rewrite,
            )

            logger.info("Start loading audit log")
            log_record_count = AuditLog.record_count(audit_log)
            info_print(f"Found {log_record_count} record(s) in the audit log.")
            _, first_record = next(AuditLog.records(audit_log))
            if first_record.prod_counter_int != 1:
                logger.warning(
                    f"First record in audit log has PROV_COUNTER = {first_record.prod_counter_int} (Expecting 1)"
                )

            logger.info("Start verifying")
            verify_time = Timeout(timeout=0)
            summary_counter = AuditLogCounter()
            if log_record_count < 100 or max_processes == 1:
                logger.info("Using own process for verification")
                summary_counter = _verify_extract_chain(
                    audit_log=audit_log,
                    log_slice=slice(0, log_record_count),
                    public_key_data=log_key_data,
                    store_cert_method=store_certificate_method,
                )
            else:
                # using parallel execution
                process_count = max_processes or multiprocessing.cpu_count()
                logger.info(f"Using {process_count} processes for verification")
                log_slices = _get_log_slices(log_record_count, process_count=process_count)
                with concurrent.futures.ProcessPoolExecutor(max_workers=process_count) as executor:
                    future_to_slice = {
                        executor.submit(
                            _verify_extract_chain,
                            audit_log=audit_log,
                            log_slice=log_slice,
                            public_key_data=log_key_data,
                            store_cert_method=store_certificate_method,
                        ): log_slice
                        for log_slice in log_slices
                    }
                    for future in concurrent.futures.as_completed(future_to_slice):
                        summary_counter += future.result()
            logger.info(f"Verification completed in {verify_time.get_consumed_time_ms()} ms.")
            info_print(
                f"Audit log verification successfully finished in {loc_timeout.get_consumed_time_ms()} ms."
            )
            info_print(str(summary_counter))
            return summary_counter
        except:
            info_print(f"Audit log verification FAILED in {loc_timeout.get_consumed_time_ms()} ms.")
            raise

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

    def check_audit_log_owner(self, audit_log: str, timeout: int = 60) -> None:
        """Check if this TP Device's ID is present in the audit log."""
        try:
            loc_timeout = Timeout(timeout=timeout, units="s")
            logger.debug("Opening TP device")
            self.tpdev.open()

            self.info_print(f"Checking ownership of audit log: {audit_log}")
            tp_device_id = self.tpdev.descriptor.get_id()
            logger.debug(f"TP Device ID: {tp_device_id}")
            audit_log_id = AuditLog.properties(audit_log).tp_device_id
            logger.debug(f"Audit log ID: {audit_log_id}")
            if tp_device_id != audit_log_id:
                raise SPSDKTpError(
                    f"TP Device ID and Audit Log ID differ! "
                    f"TP Device ID: {tp_device_id}, Audit Log ID: {audit_log_id}"
                )
            self.info_print(f"TP Device ID and Audit Log ID are the same: {tp_device_id}")
            self.info_print(
                f"Checking ownership of audit log ended correctly in {loc_timeout.get_consumed_time_ms()} ms."
            )
        except:
            self.info_print(
                f"Checking ownership of audit log FAILED in {loc_timeout.get_consumed_time_ms()} ms."
            )
            raise
        finally:
            logger.debug("Closing TP device")
            self.tpdev.close()

    def get_tp_response(
        self,
        response_file: str,
        timeout: int = 60,
        challenge: Optional[bytes] = None,
        oem_key_flags: int = 0,
        save_debug_data: bool = False,
    ) -> None:
        """Retrieve TP_RESPONSE from the target.

        :param response_file: Path where to store TP_RESPONSE
        :param timeout: The timeout of operation is seconds, defaults to 60
        :param challenge: Challenge for the response, defaults to None
        :param oem_key_flags: OEM Key flags used for generating the response, defaults to 0
        :param save_debug_data: Save transmitted data in CWD for debugging purposes
        :raises SPSDKTpError: Failure to retrieve the response
        """
        try:
            loc_timeout = Timeout(timeout=timeout, units="s")
            logger.debug("Opening TP target")
            self.tptarget.open()

            challenge = challenge or secrets.token_bytes(16)
            if len(challenge) != 16:
                raise SPSDKTpError("Challenge has to be 16B long")

            challenge_container = Container()
            challenge_container.add_entry(
                DataEntry(
                    payload=challenge,
                    payload_type=PayloadType.NXP_EPH_CHALLENGE_DATA_RND.tag,
                    extra=oem_key_flags,
                )
            )
            logger.info(f"TP Challenge:\n{challenge_container}")

            if save_debug_data:
                with open("x_challenge.bin", "wb") as f:
                    f.write(challenge_container.export())

            tp_response = self.tptarget.prove_genuinity_challenge(
                challenge=challenge_container.export(),
                timeout=loc_timeout.get_rest_time_ms(raise_exc=True),
            )
            logger.info(f"TP Response:\n{Container.parse(tp_response)}")

            write_file(data=tp_response, path=response_file, mode="wb")
            self.info_print(f"TP_RESPONSE stored to {response_file}.")
            self.info_print(
                f"Retrieving TP_RESPONSE ends correctly in {loc_timeout.get_consumed_time_ms()} ms."
            )
        except:
            self.info_print(
                f"Retrieving TP_RESPONSE failed in {loc_timeout.get_consumed_time_ms()} ms."
            )
            raise
        finally:
            logger.debug("Closing TP target")
            self.tptarget.close()


def _get_log_slices(log_length: int, process_count: int) -> Sequence[slice]:
    """Create list of slices for slicing the audit log depending on process count."""
    chunk_size = math.ceil(log_length / process_count)
    slices = [slice(i, i + chunk_size) for i in range(0, log_length, chunk_size)]
    logger.debug(f"Audit log split into slices: {slices}")
    return slices


def _verify_extract_chain(
    audit_log: str,
    public_key_data: bytes,
    store_cert_method: Callable[[AuditLogRecord], AuditLogCounter],
    log_slice: slice,
) -> AuditLogCounter:
    """Verify content of AuditLog and optionally store certificates."""
    counter = AuditLogCounter()

    # if the current slice is not at the begging of file
    # we have to fetch previous record for chain verification
    # if the current slice is the first one in log, the starting hash should be 0

    public_key = PublicKeyEcc.parse(public_key_data)

    start = log_slice.start
    fetch_previous = False
    if start != 0:
        start -= 1
        fetch_previous = True

    records = AuditLog.records(audit_log, id_slice=(start, log_slice.stop))
    if fetch_previous:
        previous_hash = next(records)[1].new_hash()
    else:
        previous_hash = bytes(32)

    for i, record in records:
        if not record.is_valid(public_key):
            raise SPSDKTpError(f"Log entry #{i} has an invalid signature!")
        if record.start_hash != previous_hash:
            if ALLOW_ARBITRARY_START and (i == 1):
                pass
            else:
                raise SPSDKTpError(f"Audit log chain is broken between records #{i - 1} - #{i}")
        previous_hash = record.new_hash()
        counter.check_count += 1
        counter += store_cert_method(record)
    return counter


def _extract_certificates(
    log_record: AuditLogRecord,
    destination_dir: Optional[str] = None,
    skip_nxp: bool = False,
    skip_oem: bool = False,
    cert_index: Optional[int] = None,
    encoding: SPSDKEncoding = SPSDKEncoding.PEM,
    force_rewrite: bool = True,
) -> AuditLogCounter:
    """Extract certificates from the audit log into destination_dir.

    :param audit_log: Path to audit log
    :param destination_dir: Path to destination directory
    :param skip_nxp: Skip extracting the NXP Devattest certificates
    :param skip_oem: Skip extracting the OEM x509 Devattest certificates
    :param info_print: Method for printing messages
    :param encoding: Certificate encoding, defaults to SPSDK_Encoding.PEM
    :raises SPSDKTpError: Destination directory doesn't exist
    :return: Number of generated NXP and OEM certificates
    """
    counter = AuditLogCounter()
    if not destination_dir:
        return counter
    if not os.path.isdir(destination_dir):
        raise SPSDKTpError(f"Directory {destination_dir} doesn't exist.")
    if not skip_nxp:
        nxp_id_name = f"device_{log_record.prod_counter_int:06}_identity_cert.bin"
        _write_cert_data(log_record.nxp_id_cert, nxp_id_name, destination_dir, force_rewrite)
        counter.nxp_count += 1
    if not skip_oem:
        for idx, oem_cert in enumerate(log_record.oem_id_certs):
            if cert_index and cert_index != idx:
                continue
            if not oem_cert:
                continue
            oem_id_name = f"device_{log_record.prod_counter_int:06}_device_cert_{idx}.cer"
            cert_data = _encode_cert_data(cert_data=oem_cert, encoding=encoding)
            _write_cert_data(cert_data, oem_id_name, destination_dir, force_rewrite)
            counter.oem_count += 1
    return counter


def _write_cert_data(cert_data: bytes, name: str, path: str, force_rewrite: bool = True) -> None:
    """Write certificate data into a file.

    :param cert_data: Certificate data
    :param name: Name of the certificate file
    :param path: Destination directory
    :param force_rewrite: Rewrite existing certificates
    :raises SPSDKTpError: Certificate already exists and force_rewrite is disabled
    """
    logger.debug(f"Writing {name}")
    destination = os.path.join(path, name)
    if os.path.exists(destination) and not force_rewrite:
        raise SPSDKTpError(
            f"{destination} already exists! To rewrite existing files use --force-rewrite flag."
        )
    write_file(cert_data, destination, mode="wb")


def _encode_cert_data(cert_data: bytes, encoding: SPSDKEncoding = SPSDKEncoding.PEM) -> bytes:
    """Encode certificate data with given encoding.

    :param cert_data: Certificate binary data (DER)
    :param encoding: Output encoding, defaults to SPSDK_Encoding.PEM
    :raises SPSDKTpError: Unsupported encoding
    :return: Encoded certificate data
    """
    if encoding == SPSDKEncoding.DER:
        return cert_data
    if encoding == SPSDKEncoding.PEM:
        data = base64.b64encode(cert_data)
        lines = [data[i : i + 64] for i in range(0, len(data), 64)]
        lines.insert(0, b"-----BEGIN CERTIFICATE-----")
        lines.append(b"-----END CERTIFICATE-----")
        return b"\n".join(lines)
    raise SPSDKTpError(f"Unsupported encoding: {encoding}")
