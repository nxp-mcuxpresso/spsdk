#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK SDA (Secure Debug Access) Authentication Module.

This module provides SDA authentication for HSE-based devices.

HSE supports two debug authentication modes (HSE_DEBUG_AUTH_MODE_ATTR_ID):
- PASSWORD (0x0): Password/Token Mode - static authentication using pre-shared token
- CHALLENGE_RESPONSE (0x1): Challenge/Response Mode - dynamic authentication using ADKP key

Password Mode:
In password mode, the device is authenticated using a pre-configured 128-bit password.
The password is written directly to the first 4 KEYRESPn registers without any challenge/response.
This mode is simpler but less secure than challenge/response mode.

Challenge/Response Mode with ADKP Diversification:
The ADKP (Application Debug Key/Password) can be optionally diversified with the device's
UID before being written to secure NVM. This allows provisioning a device-dependent debug
key while using ADKP as a master debug key.

When ADKP diversification is enabled (HSE_EXTEND_CUST_SECURITY_POLICY_ATTR_ID.enableADKm):
- Host provisions a master ADKP via HSE_APP_DEBUG_KEY_ATTR_ID
- HSE internally derives: actual_ADKP = derive(master_ADKP, UID)
- For authentication, the host must also derive the same device-specific key

This module supports both authentication modes:
1. Direct ADKP: Use the ADKP key directly (diversification disabled)
2. Diversified ADKP: Derive device-specific key from master ADKP and UID (diversification enabled)
"""

import struct
from typing import Callable

from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.crypto.symmetric import aes_ecb_encrypt
from spsdk.dat.debug_mailbox import logger
from spsdk.debuggers.debug_probe import DebugProbe
from spsdk.exceptions import SPSDKError
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision, get_db, get_families
from spsdk.utils.spsdk_enum import SpsdkEnum


class DebugAuthMode(SpsdkEnum):
    """HSE Debug Authentication Mode enumeration.

    Defines the authentication modes supported by HSE (Hardware Security Engine)
    for application debug authorization. This determines whether debug access
    requires a static password or dynamic challenge-response authentication.
    """

    PASSWORD = (0x0, "password", "Password-based debug authorization (static token)")
    CHALLENGE_RESPONSE = (
        0x1,
        "challenge-response",
        "Challenge-response based debug authorization (dynamic)",
    )


class SdaAuthentication:
    """SDA (Secure Debug Access) Authentication for HSE-based devices.

    This class handles both Password Mode and Challenge/Response Mode authentication
    for devices using SDA AP with HSE (Hardware Security Engine).

    Password Mode Prerequisites:
    - Device must be provisioned with HSE_DEBUG_AUTH_MODE_ATTR_ID = PASSWORD (0x0)
    - ADKP (Application Debug Key/Password) must be registered in the device

    Challenge/Response Mode Prerequisites:
    - Device must be provisioned with HSE_DEBUG_AUTH_MODE_ATTR_ID = CHALLENGE_RESPONSE (0x1)
    - ADKP (Application Debug Key/Password) must be registered in the device

    ADKP Diversification (Challenge/Response Mode only):
    The ADKP can be optionally diversified with the device's UID. When enabled:
    - Device stores: actual_ADKP = derive(master_ADKP, UID)
    - For authentication, provide master_ADKP and set use_diversification=True
    - The class will automatically derive the device-specific key

    The authentication uses SDA AP registers:
    - KEYCHALn (0x10-0x2C): 256-bit challenge from HSE (8 x 32-bit registers) [CR mode only]
    - KEYRESPn (0x40-0x5C): Response/password to HSE (8 x 32-bit registers)
    - UID0/UID1 (0x70, 0x74): Device unique ID (64 bits)
    - AUTHCTL (0x04): Authentication control (trigger via HSEAUTHREQ bit)
    - AUTHSTTS (0x00): Authentication status (check APPDBGEN/SYSDBGEN bits)
    - DBGENCTRL (0x80): Debug enable control (set GDBGEN/CDBGEN bits)

    Password Mode authentication flow:
    1. Write 128-bit password to KEYRESPn registers (0x40-0x4C, first 4 registers)
    2. Trigger authentication by setting AUTHCTL.HSEAUTHREQ
    3. Enable debug by setting DBGENCTRL.GDBGEN and DBGENCTRL.CDBGEN
    4. Verify authentication by checking AUTHSTTS.APPDBGEN and AUTHSTTS.SYSDBGEN

    Challenge/Response authentication flow:
    1. Read 256-bit challenge from KEYCHALn registers
    2. Read 64-bit UID from UID0/UID1 registers
    3. If diversification enabled, derive device-specific ADKP from master ADKP and UID
    4. Compute response using AES-ECB
    5. Write 256-bit response to KEYRESPn registers
    6. Trigger authentication by setting AUTHCTL.HSEAUTHREQ
    7. Enable debug by setting DBGENCTRL.GDBGEN and DBGENCTRL.CDBGEN
    8. Verify authentication by checking AUTHSTTS.APPDBGEN and AUTHSTTS.SYSDBGEN
    """

    FEATURE = DatabaseManager.DAT
    SUB_FEATURE = "sda"

    # SDA AP Register addresses
    AUTHSTTS_ADDR = 0x00  # Authentication Status
    AUTHCTL_ADDR = 0x04  # Authentication Control
    KEYCHAL_BASE = (
        0x10  # Key Challenge base (8 registers: 0x10, 0x14, 0x18, 0x1C, 0x20, 0x24, 0x28, 0x2C)
    )
    KEYRESP_BASE = (
        0x40  # Key Response base (8 registers: 0x40, 0x44, 0x48, 0x4C, 0x50, 0x54, 0x58, 0x5C)
    )
    UID0_ADDR = 0x70  # Unique ID low 32 bits
    UID1_ADDR = 0x74  # Unique ID high 32 bits
    DBGENCTRL_ADDR = 0x80  # Debug Enable Control
    IDR_ADDR = 0xFC  # Identification Register

    # Expected values
    SDA_AP_IDR = 0x001C0040
    AUTH_SUCCESS_MASK = 0x60000000  # APPDBGEN (bit 30) | SYSDBGEN (bit 29)

    # Control bits
    AUTHCTL_HSEAUTHREQ = 0x00000001  # Bit 0: HSE Authentication Request
    DBGENCTRL_GDBGEN = 0x00000010  # Bit 4: Global Debug Enable
    DBGENCTRL_CDBGEN = 0x10000000  # Bit 28: Core Debug Enable

    def __init__(self, family: FamilyRevision, debug_probe: DebugProbe):
        """Initialize SDA Authentication.

        :param family: Device family and revision.
        :param debug_probe: Debug probe instance for communication.
        :raises SPSDKError: If SDA AP verification fails.
        """
        self.family = family
        self._db = get_db(family)
        self.debug_probe = debug_probe
        self.sda_ap_index = self._db.get_int(self.FEATURE, "sda_ap_index", 7)

        # Verify SDA AP is accessible
        if not self.verify_sda_ap():
            raise SPSDKError("SDA AP verification failed - cannot access SDA AP")

    @classmethod
    def get_supported_families(cls, include_predecessors: bool = False) -> list[FamilyRevision]:
        """Get supported families for the feature.

        Retrieves a list of family revisions that are supported by this feature class,
        optionally including predecessor families.

        :param include_predecessors: Whether to include predecessor families in the result.
        :return: List of supported family revisions for this feature.
        """
        return get_families(
            feature=cls.FEATURE,
            sub_feature=cls.SUB_FEATURE,
            include_predecessors=include_predecessors,
        )

    def verify_sda_ap(self) -> bool:
        """Verify SDA AP is accessible and has correct IDR.

        Reads the SDA AP IDR register and verifies it matches the expected value.
        This is used both before and after authentication to ensure SDA AP access.

        :return: True if SDA AP IDR is correct, False otherwise.
        """
        try:
            idr = self._read_reg(self.IDR_ADDR)
            is_valid = idr == self.SDA_AP_IDR
            if is_valid:
                logger.info(f"Reading SDA AP ID Register succeeded. (IDR=0x{idr:08X})")
            else:
                logger.error(
                    f"Reading SDA AP ID Register failed. "
                    f"Expected 0x{self.SDA_AP_IDR:08X}, got 0x{idr:08X}"
                )
            return is_valid
        except SPSDKError as e:
            logger.error(f"Reading SDA AP ID Register failed: {e}")
            return False

    def get_challenge(self) -> bytes:
        """Read authentication challenge from device.

        Reads 256-bit challenge from KEYCHALn registers (0x10-0x2C).
        The challenge is read as 8 x 32-bit words and converted to bytes
        with proper endianness handling (little-endian per word).

        :return: Challenge as 32 bytes (256 bits).
        :raises SPSDKError: If SDA AP verification fails.
        """
        # Read 8 challenge words (KEYCHALn registers)
        challenge_words = []
        for n in range(8):
            key_val = self._read_reg(self.KEYCHAL_BASE + n * 4)
            challenge_words.append(key_val)
            logger.debug(f"KEYCHAL{n} (0x{self.KEYCHAL_BASE + n * 4:02X}): 0x{key_val:08X}")

        logger.debug("Reading SDA AP KEYCHALn registers succeeded.")
        # Convert words to bytes with little-endian byte order
        challenge = struct.pack("<8I", *challenge_words)
        logger.info(f"Challenge (256-bit): {challenge.hex()}")
        return challenge

    def get_uid(self) -> bytes:
        """Read device unique ID from device.

        Reads 64-bit UID from UID0/UID1 registers (0x70, 0x74).

        :return: UID as 8 bytes (64 bits).
        :raises SPSDKError: If reading UID registers fails.
        """
        # Read UID (64 bits from UID0 and UID1)
        uid0 = self._read_reg(self.UID0_ADDR)
        uid1 = self._read_reg(self.UID1_ADDR)
        uid_int = (uid1 << 32) | uid0
        uid = bytes.fromhex(f"{uid_int:016x}")
        logger.debug("Reading SDA AP UID0 and UID1 succeeded.")
        logger.info(f"Device UID (64-bit): {uid.hex()}")
        if len(uid) != 8:
            raise SPSDKError(f"UID must be 8 bytes (64 bits), got {len(uid)}")
        return uid

    @classmethod
    def compute_response_aes_ecb(cls, challenge: bytes, adkp_key: bytes) -> bytes:
        """Compute dynamic authentication response using AES-ECB.

        :param challenge: 256-bit (32 bytes) challenge from device.
        :param adkp_key: 128-bit (16 bytes) ADKP key for AES encryption.
        :return: 256-bit (32 bytes) response.
        :raises SPSDKError: If parameters are invalid.
        """
        if len(challenge) != 32:
            raise SPSDKError(f"Challenge must be 32 bytes (256 bits), got {len(challenge)}")

        if len(adkp_key) != 16:
            raise SPSDKError(f"ADKP key must be 16 bytes (128 bits), got {len(adkp_key)}")

        logger.info("Computing response using AES-128-ECB")
        logger.debug(f"ADKP Key: {adkp_key.hex()}")
        logger.debug(f"Challenge: {challenge.hex()}")

        # AES-ECB encryption of 256-bit challenge with 128-bit key
        # Split into two 128-bit blocks
        block1 = challenge[0:16]  # First 128 bits
        block2 = challenge[16:32]  # Second 128 bits

        # Encrypt both blocks
        response_block1 = aes_ecb_encrypt(key=adkp_key, plain_data=block1)
        response_block2 = aes_ecb_encrypt(key=adkp_key, plain_data=block2)

        response = response_block1 + response_block2
        logger.info("Computing response succeeded.")
        logger.debug(f"Response (256-bit): {response.hex()}")

        return response

    def authenticate(
        self, adkp_key: bytes, auth_type: DebugAuthMode = DebugAuthMode.CHALLENGE_RESPONSE
    ) -> None:
        """Perform SDA authentication using the specified authentication mode.

        This method dispatches to the appropriate authentication method based on the
        auth_type parameter. It supports both Challenge/Response and Password modes.

        :param adkp_key: 128-bit (16 bytes) ADKP cryptographic key.
                        For Challenge/Response mode: can be master ADKP (if diversification used)
                        or device-specific ADKP (if no diversification).
                        For Password mode: the pre-shared password/token.
        :param auth_type: Authentication mode to use (CHALLENGE_RESPONSE or PASSWORD).
                         Defaults to CHALLENGE_RESPONSE.
        :raises SPSDKError: If authentication fails or auth_type is not supported.
        """
        auth_types: dict[DebugAuthMode, Callable[[bytes], None]] = {
            DebugAuthMode.CHALLENGE_RESPONSE: self.authenticate_challenge,
            DebugAuthMode.PASSWORD: self.authenticate_password,
        }
        auth_method = auth_types.get(auth_type)
        if auth_method is None:
            raise SPSDKError(f"Unsupported authentication type: {auth_type}")
        auth_method(adkp_key)

    def authenticate_challenge(self, adkp_key: bytes, use_diversification: bool = False) -> None:
        """Perform complete SDA authentication flow.

        This is the main entry point that performs the full authentication:
        1. Verify SDA AP access
        2. Read challenge and UID
        3. Compute response using AES-ECB
        4. Write response and trigger authentication
        5. Verify authentication success

        :param adkp_key: 128-bit (16 bytes) ADKP cryptographic key.
        :param use_diversification: If True, derive device-specific ADKP from master ADKP and UID.
                                   If False, use adkp_key directly.
        :raises SPSDKError: If authentication fails at any step.
        """
        logger.info("Starting SDA Authentication (Challenge/Response Mode)")

        # Get challenge and UID
        challenge = self.get_challenge()
        if use_diversification:
            logger.debug(
                "ADKP Diversification is enabled. Deriving device-specific ADKP from master ADKP and UID"
            )
            uid = self.get_uid()
            adkp_key = self.derive_adkp_from_uid(adkp_key, uid)
        else:
            logger.debug(
                "ADKP Diversification id disabled. Using ADKP key directly (no diversification)"
            )

        # Compute response
        response = self.compute_response_aes_ecb(challenge, adkp_key)

        # Write response to KEYRESPn registers (all 8 registers for 256-bit response)
        self._write_keyresp_registers(response, num_registers=8)

        # Trigger authentication and verify
        self._trigger_authentication_and_verify()

        logger.info("SDA Authentication succeeded.")

    def authenticate_password(self, adkp_key: bytes) -> None:
        """Perform SDA authentication using Password Mode.

        This method performs password-based authentication:
        1. Verify SDA AP access
        2. Write 128-bit password to first 4 KEYRESPn registers
        3. Trigger authentication and verify success

        :param adkp_key: 128-bit (16 bytes) ADKP cryptographic key.
        :raises SPSDKError: If authentication fails.
        """
        if len(adkp_key) != 16:
            raise SPSDKError(f"Password must be 16 bytes (128 bits), got {len(adkp_key)}")

        logger.info("Starting SDA Authentication (Password Mode)")

        # Write password to KEYRESPn registers (first 4 registers for 128-bit password)
        self._write_keyresp_registers(adkp_key, num_registers=4)

        # Trigger authentication and verify
        self._trigger_authentication_and_verify()

        logger.info("SDA Password Authentication succeeded.")

    def _trigger_authentication_and_verify(self) -> None:
        """Trigger authentication and verify success.

        Common method for triggering authentication and verifying the result.
        This includes:
        1. Setting AUTHCTL.HSEAUTHREQ to trigger authentication
        2. Setting DBGENCTRL.GDBGEN and DBGENCTRL.CDBGEN to enable debug
        3. Verifying SDA AP is still accessible
        4. Checking AUTHSTTS for authentication success

        :raises SPSDKError: If authentication fails.
        """
        # Trigger authentication by setting AUTHCTL.HSEAUTHREQ
        logger.info("Triggering authentication by setting AUTHCTL.HSEAUTHREQ")
        self._write_reg(self.AUTHCTL_ADDR, self.AUTHCTL_HSEAUTHREQ)
        logger.info("Writing SDA AP AUTHCTL.HSEAUTHREQ succeeded.")

        # Enable debug by setting DBGENCTRL.GDBGEN and DBGENCTRL.CDBGEN
        logger.info("Enabling debug by setting DBGENCTRL.GDBGEN and DBGENCTRL.CDBGEN")
        dbgenctrl_value = self.DBGENCTRL_GDBGEN | self.DBGENCTRL_CDBGEN
        self._write_reg(self.DBGENCTRL_ADDR, dbgenctrl_value)
        logger.info("Writing SDA AP DBGENCTRL.GDBGEN and DBGENCTRL.CDBGEN succeeded.")

        # Verify SDA AP is still accessible (if wrong password/response, this will fail)
        if not self.verify_sda_ap():
            raise SPSDKError(
                "SDA AP verification failed after authentication - "
                "wrong password or response provided"
            )

        # Check authentication status
        logger.info("Checking authentication status")
        authstts = self._read_reg(self.AUTHSTTS_ADDR)
        logger.debug(f"AUTHSTTS: 0x{authstts:08X}")

        # Check if APPDBGEN (bit 30) and SYSDBGEN (bit 29) are set
        if (authstts & self.AUTH_SUCCESS_MASK) != self.AUTH_SUCCESS_MASK:
            appdbgen = (authstts >> 30) & 1
            sysdbgen = (authstts >> 29) & 1
            raise SPSDKError(
                f"Checking Assertion of SDA AP AUTHSTTS.APPDBGEN and AUTHSTTS.SYSDBGEN failed. "
                f"AUTHSTTS=0x{authstts:08X} (APPDBGEN={appdbgen}, SYSDBGEN={sysdbgen})"
            )

        logger.info(
            "Checking Assertion of SDA AP AUTHSTTS.APPDBGEN and AUTHSTTS.SYSDBGEN succeeded."
        )

    def _write_keyresp_registers(self, data: bytes, num_registers: int = 8) -> None:
        """Write data to KEYRESPn registers.

        Common method for writing password (4 registers) or response (8 registers)
        to KEYRESPn registers with verification.

        :param data: Data to write (16 bytes for password, 32 bytes for response).
        :param num_registers: Number of registers to write (4 for password, 8 for response).
        :raises SPSDKError: If write verification fails.
        """
        expected_length = num_registers * 4
        if len(data) != expected_length:
            raise SPSDKError(
                f"Data must be {expected_length} bytes for {num_registers} registers, got {len(data)}"
            )

        logger.info(f"Writing data to {num_registers} KEYRESPn registers")

        # Convert data bytes to 32-bit words (little-endian)
        data_words = struct.unpack(f"<{num_registers}I", data)

        # Write to KEYRESPn registers
        for n in range(num_registers):
            addr = self.KEYRESP_BASE + n * 4
            value = data_words[n]
            self._write_reg(addr, value)
            logger.debug(f"KEYRESP{n} (0x{addr:02X}): 0x{value:08X}")

            # Verify write
            read_value = self._read_reg(addr)
            if read_value != value:
                raise SPSDKError(
                    f"Failed to write KEYRESP{n}. Expected 0x{value:08X}, got 0x{read_value:08X}"
                )

        logger.info("Writing SDA AP KEYRESPn registers succeeded.")

    def derive_adkp_from_uid(self, adkp_key: bytes, uid: bytes) -> bytes:
        """Derive device-specific ADKP from master ADKP and UID.

        This implements the HSE firmware's internal derivation when ADKP diversification
        is enabled (HSE_EXTEND_CUST_SECURITY_POLICY_ATTR_ID.enableADKm).

        :param adkp_key: 128-bit (16 bytes) master ADKP key.
        :param uid: 64-bit (8 bytes) device unique ID.
        :return: 128-bit (16 bytes) derived device-specific ADKP.
        :raises SPSDKError: If parameters are invalid.
        """
        if len(adkp_key) != 16:
            raise SPSDKError(f"Master ADKP must be 16 bytes (128 bits), got {len(adkp_key)}")

        if len(uid) != 8:
            raise SPSDKError(f"UID must be 8 bytes (64 bits), got {len(uid)}")

        hash_adkp = get_hash(adkp_key, EnumHashAlgorithm.SHA256)
        logger.debug(f"SHA256(adkp_key)[0:16]: {hash_adkp.hex()}")

        hash_uid = get_hash(uid, EnumHashAlgorithm.SHA256)
        logger.debug(f"SHA256(UID)[0:16]: {hash_uid.hex()}")
        derived_adkp = aes_ecb_encrypt(hash_adkp, hash_uid)
        # Take first 128 bits (should already be 16 bytes from AES-128)
        derived_adkp = derived_adkp[:16]

        logger.info("Deriving device-specific ADKP succeeded.")
        logger.debug(f"Derived ADKP: {derived_adkp.hex()}")

        return derived_adkp

    def _read_reg(self, addr: int) -> int:
        """Read SDA AP register.

        :param addr: Register address (offset within SDA AP).
        :return: Register value (32-bit).
        :raises SPSDKError: If read fails.
        """
        self.debug_probe.connect()
        full_addr = self.debug_probe.get_coresight_ap_address(
            access_port=self.sda_ap_index, address=addr
        )
        return self.debug_probe.coresight_reg_read_safe(addr=full_addr)

    def _write_reg(self, addr: int, data: int) -> None:
        """Write SDA AP register.

        :param addr: Register address (offset within SDA AP).
        :param data: Data value (32-bit).
        :raises SPSDKError: If write fails.
        """
        self.debug_probe.connect()
        full_addr = self.debug_probe.get_coresight_ap_address(
            access_port=self.sda_ap_index, address=addr
        )
        self.debug_probe.coresight_reg_write_safe(addr=full_addr, data=data)
