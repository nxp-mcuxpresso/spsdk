#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Secure Installer Eraser utility.

This module provides functionality for erasing the Secure Installer from flash memory
on NXP MCU devices that support this feature. The Secure Installer erasing frees up
flash space for application code.
"""

import logging
from enum import Enum

from spsdk.exceptions import SPSDKError
from spsdk.mboot.commands import CommandTag
from spsdk.mboot.error_codes import StatusCode
from spsdk.mboot.exceptions import McuBootCommandError
from spsdk.mboot.mcuboot import McuBoot
from spsdk.mboot.properties import AvailableCommandsValue, PropertyTag, parse_property_value
from spsdk.pfr.pfr import CMPA
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision, get_db, get_families
from spsdk.utils.registers import Register, Registers

logger = logging.getLogger(__name__)


class SIStatus(Enum):
    """Status of the Secure Installer on the device."""

    PRESENT_VALID = "present_valid"
    PRESENT_CORRUPTED = "present_corrupted"
    ERASED = "erased"
    UNKNOWN = "unknown"


def get_supported_families() -> list[FamilyRevision]:
    """Get families supporting Secure Installer erasure.

    :return: List of supported family revisions.
    """
    families: list[FamilyRevision] = []
    for family in get_families(feature=DatabaseManager.PFR):
        db = get_db(family)
        try:
            db.get_int(DatabaseManager.PFR, ["cmpa", "delete_installer_magic"])
            db.get_int(DatabaseManager.PFR, ["cmpa", "delete_installer_offset"])
            db.get_int(DatabaseManager.PFR, ["cmpa", "address"])
        except (KeyError, ValueError):
            continue
        families.append(family)
    return families


class SecureInstallerEraser:
    """Utility for erasing Secure Installer from NXP MCU devices.

    This class provides a simple interface to erase the Secure Installer from devices
    that support this feature. The process involves:
    1. Writing a magic value (DELETE_INSTALLER_MAGIC) to CMPA_BASE + delete_installer_offset
    2. Resetting the device to apply the change

    The device is automatically reset after the magic value is written.
    """

    #: Number of bytes of flash to read when probing for SI presence.
    SI_PROBE_LENGTH = 4

    #: Length of the SI erase token in bytes (4 x 32-bit words).
    ERASE_TOKEN_LENGTH = 16

    @staticmethod
    def _is_erase_token_blank(token_data: bytes) -> bool:
        """Return ``True`` when the erase-token field carries no valid token.

        A device-unique erase token is derived by the ROM from device-specific
        data through a hardware key, so a valid token is never all identical bytes.
        An unprogrammed
        CMPA erase-token region reads back as a single repeated fill byte — ``0xFF``
        on some parts, ``0x00`` on others. Both cases mean the ROM has
        not written a token yet, i.e. the Secure Installer has not been erased.

        :param token_data: Raw erase-token bytes as read from CMPA.
        :return: ``True`` if the token is blank (all ``0x00`` or all ``0xFF``).
        """
        return all(b == 0x00 for b in token_data) or all(b == 0xFF for b in token_data)

    def __init__(self, mboot: McuBoot, family: FamilyRevision) -> None:
        """Initialize SecureInstallerEraser.

        :param mboot: McuBoot instance for device communication
        :param family: Device family revision
        :raises SPSDKError: If the device does not support Secure Installer erasure
        """
        self.mboot = mboot
        self.family = family
        self.db = get_db(family)

        # Verify device supports Secure Installer erase metadata.
        try:
            self.delete_installer_magic: int = self.db.get_int(
                DatabaseManager.PFR, ["cmpa", "delete_installer_magic"]
            )
            self.delete_installer_offset: int = self.db.get_int(
                DatabaseManager.PFR, ["cmpa", "delete_installer_offset"]
            )
        except (KeyError, ValueError) as e:
            raise SPSDKError(
                f"Device family {family} does not support Secure Installer erasure. "
                "This feature is only available for devices with Secure Installer support."
            ) from e

        self.cmpa_address: int = self.db.get_int(DatabaseManager.PFR, ["cmpa", "address"])
        self.erase_token_offset: int = self.db.get_int(
            DatabaseManager.PFR, ["cmpa", "erase_token_offset"]
        )
        self.si_probe_address: int = self.db.get_int(
            DatabaseManager.PFR, ["cmpa", "si_probe_address"]
        )
        # CMPA header marker is optional in the DB. When defined, the ROM gates the
        # DELETE_INSTALLER_MAGIC request on the upper 16 bits at CMPA+0 matching this
        # value.
        try:
            self.cmpa_header_marker: int | None = self.db.get_int(
                DatabaseManager.PFR, ["cmpa", "cmpa_header_marker"]
            )
        except (KeyError, ValueError):
            self.cmpa_header_marker = None

    def check_si_status(self) -> tuple[SIStatus, bool]:
        """Check the status of the Secure Installer on the device.

        Detection order matches the ROM state machine:

        1. **Erase token** at ``CMPA + erase_token_offset`` (16 bytes). The ROM only
           ever writes this field after a successful erase. When the field is not
           blank (a blank token reads
           back as all ``0x00`` or all ``0xFF``, depending on the part) we therefore
           know the ROM has already accepted a DELETE_INSTALLER_MAGIC request. Writing
           the magic a second time would cause a cumulative write to the same flash
           phrase and brick the device, so this is also the cumulative-write-brick
           guard required by the ROM design.
        2. **Available commands** (``blhost get-property 7``). If ``receive-sb-file``
           is reported, the boot loader passed every SI integrity check and exposed
           the SI command set → SI is present and valid.
        3. **Probe of the SI flash region** at :py:attr:`si_probe_address`. If the
           read fails with a memory-range-invalid status it means the SI region is
           inside a reserved region or has been hidden by
           the ROM — both happen only when the SI exists. Combined with a missing
           ``receive-sb-file`` this maps to "SI present but corrupted" (an SI
           integrity check failed in the ROM).

        :return: Tuple of (SIStatus, erase_token_programmed). The boolean is
                 ``True`` whenever the erase-token field is not blank (blank reads
                 back as all ``0x00`` or all ``0xFF``); callers must treat this as a
                 hard "do not re-issue the magic" condition.
        """
        # --- Step 1: inspect the SI erase token (authoritative ROM-side signal). ---
        erase_token_programmed = self._is_erase_token_programmed()

        # --- Step 2: query available commands (blhost get-property 7). ---
        receive_sb_available = self._is_receive_sb_available()

        if receive_sb_available:
            # ROM only exposes receive-sb-file when SI is fully validated. Token must
            # logically be blank in this case; if it isn't, the device is in an
            # inconsistent state and we must not write the magic again.
            if erase_token_programmed:
                logger.warning(
                    "SI reports receive-sb-file AND the erase token is programmed. "
                    "Treating as ERASED to prevent cumulative-write brick."
                )
                return SIStatus.ERASED, True
            logger.info("SI status: present and valid (receive-sb-file available)")
            return SIStatus.PRESENT_VALID, False

        if erase_token_programmed:
            # On a 512 K devices the SI region is reopened as customer flash;
            # on smaller devices it is hidden. Either way the
            # ROM treats the device as erased.
            logger.info("SI status: erased (erase token in CMPA is not blank)")
            return SIStatus.ERASED, True

        # --- Step 3: probe the SI flash region. ---
        logger.info(
            f"Probing SI region at 0x{self.si_probe_address:08X} "
            f"({self.SI_PROBE_LENGTH} bytes)…"
        )
        probe_data, probe_status = self._read_memory(self.si_probe_address, self.SI_PROBE_LENGTH)

        if probe_data is None and probe_status == StatusCode.MEMORY_RANGE_INVALID.tag:
            logger.info("SI status: present but corrupted (memory range invalid on probe)")
            return SIStatus.PRESENT_CORRUPTED, False

        if probe_data is not None:
            # The probe succeeded, receive-sb-file is missing AND the erase token
            # is blank. The ROM never lets all three be true on a device with a
            # working SI, so this is "no SI present" (e.g. unsupported device).
            logger.warning(
                "SI probe succeeded but receive-sb-file is missing and erase token "
                "is blank — Secure Installer does not appear to be present on this device."
            )
            return SIStatus.UNKNOWN, False

        logger.warning(f"SI status: unknown (probe read failed with status 0x{probe_status:08X})")
        return SIStatus.UNKNOWN, False

    def _is_receive_sb_available(self) -> bool:
        """Return ``True`` if ``ReceiveSBFile`` is reported by ``get-property 7``.

        :return: ``True`` when the bitmask returned by ``AVAILABLE_COMMANDS``
                 includes the ReceiveSBFile command, ``False`` otherwise (also on
                 communication errors).
        """
        try:
            raw_values = self.mboot.get_property(PropertyTag.AVAILABLE_COMMANDS)
        except Exception:  # pylint: disable=broad-except
            logger.debug("Could not retrieve available commands property.", exc_info=True)
            return False
        if not raw_values:
            return False
        props = parse_property_value(PropertyTag.AVAILABLE_COMMANDS, raw_values)
        if not isinstance(props, AvailableCommandsValue):
            return False
        return CommandTag.RECEIVE_SB_FILE.tag in props

    def _read_memory(self, address: int, length: int) -> tuple[bytes | None, int]:
        """Read memory and return both data and status code.

        :param address: Start address to read.
        :param length: Number of bytes to read.
        :return: Tuple with read data, if any, and the command status code.
        """
        try:
            data = self.mboot.read_memory(address, length)
            return data, self.mboot.status_code
        except McuBootCommandError as exc:
            logger.debug(
                f"ReadMemory failed at 0x{address:08X} with status 0x{exc.error_value:08X}.",
                exc_info=True,
            )
            return None, exc.error_value

    def _is_erase_token_programmed(self) -> bool:
        """Check whether the SI erase token in CMPA has been written (not blank).

        On read failure the method returns ``True`` ("assume programmed") so that
        callers default to the safe path of refusing to re-issue the magic. The
        ROM writes this field exactly once after a successful erase; a successful
        read showing a non-blank token (not all ``0x00`` and not all ``0xFF``)
        therefore proves the SI was already erased, and a failed read leaves us with
        no positive proof of safety.

        :return: ``True`` if the erase-token field holds a valid (non-blank) token,
                 or if the read failed (safe default).
        """
        erase_token_address = self.cmpa_address + self.erase_token_offset
        # Erase token is 4 × 32-bit words = 16 bytes
        token_data, _ = self._read_memory(erase_token_address, self.ERASE_TOKEN_LENGTH)
        if token_data is None:
            logger.warning(
                f"Could not read SI erase token at 0x{erase_token_address:08X}. "
                "Treating token as already-programmed to prevent cumulative-write brick."
            )
            return True
        return not self._is_erase_token_blank(token_data)

    def read_erase_token(self) -> tuple[bytes, bool]:
        """Read the device-unique SI erase token from CMPA.

        The ROM programs this 16-byte token into ``CMPA + erase_token_offset`` after
        it completes a Secure Installer erase. The value is **device-unique** — it is
        derived by the ROM from device-specific data via a hardware key
        and is re-validated by the ROM on every boot. It must therefore be preserved
        verbatim in CMPA; writing a blank or foreign token re-locks the freed flash
        region.

        :return: Tuple of ``(token_bytes, programmed)``. ``token_bytes`` is the raw
                 16-byte token exactly as stored in flash (little-endian words);
                 ``programmed`` is ``True`` when the token is not blank (a blank token
                 reads back as all ``0x00`` or all ``0xFF``, depending on the part).
        :raises SPSDKError: If the erase token cannot be read from the device.
        """
        erase_token_address = self.cmpa_address + self.erase_token_offset
        token_data, status = self._read_memory(erase_token_address, self.ERASE_TOKEN_LENGTH)
        if token_data is None or len(token_data) < self.ERASE_TOKEN_LENGTH:
            raise SPSDKError(
                f"Unable to read SI erase token at 0x{erase_token_address:08X} "
                f"(status 0x{status:08X})."
            )
        token_data = token_data[: self.ERASE_TOKEN_LENGTH]
        programmed = not self._is_erase_token_blank(token_data)
        return token_data, programmed

    def erase_token_as_registers(self, token_data: bytes) -> dict[str, int]:
        """Interpret a 16-byte erase token as the CMPA erase-token registers.

        The token is parsed through the CMPA register model, so the register names,
        offsets and endianness are taken from the device database rather than being
        re-derived here. This matters across families, which may name these registers
        ``SI_ERASE_TOKEN0..3`` or ``ERASE_TOKEN0..3`` (both at ``erase_token_offset``),
        so the naming is always taken from the database. The returned mapping can
        be pasted directly into the ``settings`` section of a CMPA configuration to
        preserve the token across a ``pfr write``.

        :param token_data: Raw 16-byte token as returned by :meth:`read_erase_token`.
        :raises SPSDKError: If ``token_data`` is not exactly 16 bytes long, or the CMPA
            register model declares no registers in the erase-token region.
        :return: Ordered mapping ``{"<ERASE_TOKEN reg name>": <int>, ...}``.
        """
        if len(token_data) != self.ERASE_TOKEN_LENGTH:
            raise SPSDKError(
                f"Erase token must be {self.ERASE_TOKEN_LENGTH} bytes, got {len(token_data)}."
            )
        # Let the CMPA register model interpret the token so the register names,
        # offsets and endianness come from the device database instead of being
        # re-derived here. Place the raw token at its known offset inside a blank
        # CMPA page and parse it back through the model.
        cmpa = CMPA(self.family)
        page = bytearray(b"\xff" * cmpa.registers_size)
        page[self.erase_token_offset : self.erase_token_offset + self.ERASE_TOKEN_LENGTH] = (
            token_data
        )
        cmpa.registers.parse(bytes(page))
        return {
            reg.name: reg.get_value()
            for reg in _leaf_erase_token_registers(cmpa.registers, self.erase_token_offset)
        }

    def _is_cmpa_header_valid(self) -> bool:
        """Verify the CMPA header marker matches the value expected by the ROM.

        The ROM gates both the erase request and the erase-token validation on the
        upper 16 bits of the CMPA header word at ``CMPA + 0`` matching a
        family-specific value from the database. When the marker
        is missing, writing DELETE_INSTALLER_MAGIC is silently ignored by the ROM.

        When the family database does not declare a header marker (e.g. parts
        where it has not been verified), this method
        returns ``True`` to preserve the existing behavior.

        :return: ``True`` if the header marker matches or is not enforced for
                 this family, ``False`` otherwise.
        """
        if self.cmpa_header_marker is None:
            return True
        header_data, _ = self._read_memory(self.cmpa_address, 4)
        if header_data is None or len(header_data) < 4:
            logger.warning(
                f"Could not read CMPA header marker at 0x{self.cmpa_address:08X}. "
                "Assuming invalid to prevent silently-ignored magic write."
            )
            return False
        header = int.from_bytes(header_data, byteorder="little")
        marker = (header & 0xFFFF0000) >> 16
        return marker == self.cmpa_header_marker

    def _verify_delete_installer_field_blank(self, target_address: int, magic_bytes: bytes) -> None:
        """Verify the DELETE_INSTALLER word (CMPA+0xE0) has no committed value yet.

        This is distinct from :meth:`_is_erase_token_programmed` which checks the
        ERASE_TOKEN field (CMPA+0xD0). The field is treated as blank when it reads
        all ``0xFF`` (erased flash) or all ``0x00`` (the CMPA template programs this
        field to zero on some parts) - the ROM only checks whether it equals
        DELETE_INSTALLER_MAGIC, so both mean "not the magic yet". A field already
        holding the magic, or an unexpected partial value, is rejected here.

        :param target_address: Absolute address of the DELETE_INSTALLER word
                               (= ``cmpa_address + delete_installer_offset``).
        :param magic_bytes: DELETE_INSTALLER_MAGIC bytes about to be programmed.
        :raises SPSDKError: If the word cannot be read or is already programmed.
        """
        token_data, _ = self._read_memory(target_address, len(magic_bytes))
        if token_data is None:
            raise SPSDKError(
                f"Unable to read DELETE_INSTALLER field at 0x{target_address:08X}. "
                "Aborting to avoid a cumulative write."
            )
        token_data = token_data[: len(magic_bytes)]
        # Blank reads back as all 0xFF (erased) or all 0x00 (CMPA template default).
        if all(b == 0xFF for b in token_data) or all(b == 0x00 for b in token_data):
            return

        token_value = int.from_bytes(token_data, byteorder="little")
        if token_data == magic_bytes:
            raise SPSDKError(
                f"DELETE_INSTALLER field at 0x{target_address:08X} already contains "
                f"DELETE_INSTALLER_MAGIC (0x{self.delete_installer_magic:08X}). "
                "Reset the device to let ROM process the Secure Installer erasure."
            )
        raise SPSDKError(
            f"DELETE_INSTALLER field at 0x{target_address:08X} is not blank "
            f"(current value: 0x{token_value:08X}). Aborting to avoid a cumulative write."
        )

    def erase(self, reset: bool = True) -> None:
        """Erase the Secure Installer from the device.

        Programs DELETE_INSTALLER_MAGIC at ``CMPA + delete_installer_offset`` and
        optionally resets the device. Two paths mirror the ROM-side erase conditions:

        * **Valid CMPA present** - the magic is written in place. If that phrase was
          already programmed by a prior full CMPA write (it now only *reads* ``0xFF``
          but re-programming raises a cumulative-write error), the erase falls back
          to a CMPA sector rewrite that preserves the current settings, co-programs
          the magic and leaves the ERASE_TOKEN phrase erased for the ROM. A non-blank
          ERASE_TOKEN aborts (the ROM already accepted a previous erase).
        * **Blank CMPA** (e.g. after a full flash erase) - the ROM ignores the magic
          without a CMPA header, so a default CMPA is provisioned carrying the magic
          (ERASE_TOKEN phrase left erased). A CMPA that is not confirmed blank is
          refused so an unexpected/partial CMPA is never clobbered.

        :param reset: If True, reset the device after writing the magic value.
        :raises SPSDKError: If any of the safety preconditions fail or the
                            mboot operation reports an error.
        """
        try:
            # Calculate the target address
            target_address = self.cmpa_address + self.delete_installer_offset

            # Prepare the magic value as 4 bytes (32-bit)
            magic_bytes = self.delete_installer_magic.to_bytes(4, byteorder="little")

            if self._is_cmpa_header_valid():
                # A valid CMPA is present: program the magic in place, falling back
                # to a CMPA sector rewrite when the DELETE_INSTALLER phrase is no
                # longer erased (any prior full CMPA write leaves it programmed - it
                # still reads back as 0xFF but the flash controller rejects a
                # re-program with a cumulative-write error).
                self._erase_with_valid_cmpa(target_address, magic_bytes)
            else:
                # No valid CMPA header (e.g. after a full flash erase). The ROM
                # ignores the magic without a CMPA, so one must exist first; when the
                # CMPA is entirely blank we provision a default one carrying the magic.
                self._erase_with_blank_cmpa(magic_bytes)

            if reset:
                logger.info("Resetting device to apply changes")
                # The ROM performs the actual SI erase (flash erase + device-unique
                # erase-token programming) on the reboot that follows this reset; it
                # takes longer than the reopen timeout and the device may not re-enter
                # ISP. Do not reopen (mirrors blhost's `reset` command) - the caller
                # re-establishes communication after the device has restarted.
                if not self.mboot.reset(reopen=False):
                    raise SPSDKError(
                        f"Failed to reset device after writing DELETE_INSTALLER_MAGIC. "
                        f"Error: {self.mboot.status_string}"
                    )
                logger.info("Device reset successfully")

        except SPSDKError:
            raise
        except Exception as e:
            raise SPSDKError(f"Unexpected error during Secure Installer erasure: {e!s}") from e

    def _erase_with_valid_cmpa(self, target_address: int, magic_bytes: bytes) -> None:
        """Program DELETE_INSTALLER_MAGIC when a valid CMPA header is present.

        Applies the ROM-side guards, attempts the in-place write, and falls back to a
        CMPA sector rewrite on a cumulative-write error.

        :param target_address: Absolute DELETE_INSTALLER address
                               (= ``cmpa_address + delete_installer_offset``).
        :param magic_bytes: DELETE_INSTALLER_MAGIC little-endian bytes.
        :raises SPSDKError: If a guard fails or the mboot operation reports an error.
        """
        # ROM has already accepted a previous erase request -> do not re-issue.
        if self._is_erase_token_programmed():
            raise SPSDKError(
                f"ERASE_TOKEN at 0x{self.cmpa_address + self.erase_token_offset:08X} "
                "is not blank. The Secure Installer was already erased by ROM "
                "(or the token phrase was partially programmed). Writing "
                "DELETE_INSTALLER_MAGIC now would cause a cumulative write to the "
                "ERASE_TOKEN flash phrase and brick the device. Aborting."
            )

        # DELETE_INSTALLER phrase itself must read blank.
        self._verify_delete_installer_field_blank(target_address, magic_bytes)

        logger.info(
            f"Writing DELETE_INSTALLER_MAGIC (0x{self.delete_installer_magic:08X}) "
            f"to address 0x{target_address:08X}"
        )
        if self._write_delete_installer_magic(target_address, magic_bytes):
            logger.info("DELETE_INSTALLER_MAGIC written successfully")
        else:
            logger.warning(
                "DELETE_INSTALLER flash phrase is not erased (cumulative-write). "
                "Falling back to a CMPA sector rewrite to program "
                "DELETE_INSTALLER_MAGIC while keeping the ERASE_TOKEN phrase erased."
            )
            self._program_magic_via_cmpa_rewrite(magic_bytes)

    def _erase_with_blank_cmpa(self, magic_bytes: bytes) -> None:
        """Provision a default CMPA carrying the magic when the CMPA is blank.

        The ROM ignores DELETE_INSTALLER_MAGIC without a valid CMPA header. When the
        entire CMPA reads back blank (all ``0xFF``, e.g. after a full flash erase) a
        default CMPA - with the ROM header marker - is generated, given the magic and
        programmed while leaving the ERASE_TOKEN phrase erased. When the CMPA is not
        confirmed blank the erase is refused so an unexpected/partially written CMPA
        is never clobbered.

        :param magic_bytes: DELETE_INSTALLER_MAGIC little-endian bytes.
        :raises SPSDKError: If the CMPA is not confirmed blank, or a step fails.
        """
        cmpa = CMPA(self.family)
        cmpa_size = cmpa.binary_size
        current, _ = self._read_memory(self.cmpa_address, cmpa_size)
        # A blank CMPA reads back as all 0xFF (erased flash) or all 0x00 (some parts
        # read/store an unprovisioned CMPA as zeros); neither carries a valid header.
        is_blank = (
            current is not None
            and len(current) >= cmpa_size
            and (
                all(b == 0xFF for b in current[:cmpa_size])
                or all(b == 0x00 for b in current[:cmpa_size])
            )
        )
        if not is_blank:
            raise SPSDKError(
                f"CMPA header marker at 0x{self.cmpa_address:08X} is not "
                f"0x{self.cmpa_header_marker:04X}. The ROM will silently ignore the "
                "DELETE_INSTALLER_MAGIC request. Program a valid CMPA first "
                "(e.g. with `pfr write` / `pfr erase-cmpa` followed by a write)."
            )
        logger.warning(
            f"CMPA at 0x{self.cmpa_address:08X} is blank; provisioning a default CMPA "
            "carrying DELETE_INSTALLER_MAGIC (ERASE_TOKEN phrase left erased for the ROM)."
        )
        self._program_magic_via_cmpa_rewrite(magic_bytes, base_image=bytes(cmpa.export()))

    def _write_delete_installer_magic(self, target_address: int, magic_bytes: bytes) -> bool:
        """Attempt the in-place DELETE_INSTALLER_MAGIC write.

        :param target_address: Absolute DELETE_INSTALLER address
                               (= ``cmpa_address + delete_installer_offset``).
        :param magic_bytes: DELETE_INSTALLER_MAGIC little-endian bytes.
        :return: ``True`` when the magic was written in place; ``False`` when the
            DELETE_INSTALLER flash phrase is not erased (cumulative-write) and the
            caller must fall back to a CMPA sector rewrite.
        :raises SPSDKError: On any other write failure.
        """
        try:
            if self.mboot.write_memory(target_address, magic_bytes):
                return True
            if self.mboot.status_code == StatusCode.MEMORY_CUMULATIVE_WRITE.tag:
                return False
            raise SPSDKError(
                f"Failed to write DELETE_INSTALLER_MAGIC to device. "
                f"Error: {self.mboot.status_string}"
            )
        except McuBootCommandError as exc:
            if exc.error_value == StatusCode.MEMORY_CUMULATIVE_WRITE.tag:
                return False
            raise

    def _resolve_rewrite_base_image(self, base_image: bytes | None, cmpa_size: int) -> bytearray:
        """Return the CMPA image to reprogram, capturing device state when needed.

        :param base_image: Caller-supplied CMPA image, or ``None`` to read the device.
        :param cmpa_size: Expected CMPA size in bytes.
        :return: Mutable CMPA image of ``cmpa_size`` bytes.
        :raises SPSDKError: If the device CMPA cannot be read or the image is too small.
        """
        if base_image is None:
            # Snapshot the current CMPA so existing settings are preserved verbatim.
            current, _ = self._read_memory(self.cmpa_address, cmpa_size)
            if current is None or len(current) < cmpa_size:
                raise SPSDKError(
                    f"Unable to read the current CMPA at 0x{self.cmpa_address:08X} "
                    "for the Secure Installer rewrite recovery."
                )
            return bytearray(current[:cmpa_size])
        if len(base_image) < cmpa_size:
            raise SPSDKError("Base CMPA image is too small for the Secure Installer rewrite.")
        return bytearray(base_image[:cmpa_size])

    def _program_magic_via_cmpa_rewrite(
        self, magic_bytes: bytes, base_image: bytes | None = None
    ) -> None:
        """Program DELETE_INSTALLER_MAGIC by erasing and reprogramming the CMPA sector.

        A prior full CMPA write programs every CMPA flash phrase (even blank ones
        read back as ``0xFF``), so the DELETE_INSTALLER phrase can no longer be
        written in place and the ROM could not program the ERASE_TOKEN phrase
        either. This method erases the CMPA sector and reprograms it with
        DELETE_INSTALLER_MAGIC at ``delete_installer_offset`` while skipping (leaving
        erased) the 16-byte ERASE_TOKEN phrase, which the ROM needs erased to store
        its device-unique token.

        The base image is either the current CMPA read back from the device (to
        preserve existing settings when recovering an already-programmed CMPA) or a
        caller-supplied image (e.g. a generated default CMPA when provisioning blank
        flash). The chunk boundaries are flash-phrase aligned so programming never
        touches the skipped ERASE_TOKEN phrase, and the result is read back and
        verified before the caller resets the device.

        :param magic_bytes: DELETE_INSTALLER_MAGIC little-endian bytes.
        :param base_image: Optional CMPA image to program. When ``None`` the current
            CMPA is read back and preserved; when provided it is used as the base.
        :raises SPSDKError: If any read/erase/write/verify step fails, or the CMPA
            layout is not flash-phrase aligned.
        """
        cmpa = CMPA(self.family)
        cmpa_size = cmpa.binary_size
        tok = self.erase_token_offset
        di = self.delete_installer_offset
        token_phrase_end = tok + self.ERASE_TOKEN_LENGTH

        # The reprogram is phrase-granular and skips the ERASE_TOKEN phrase, so the
        # ERASE_TOKEN offset must be phrase aligned, the DELETE_INSTALLER magic must
        # fit inside a single phrase, and DELETE_INSTALLER must live outside the
        # skipped ERASE_TOKEN phrase (otherwise the magic would be skipped too).
        if (
            tok % self.ERASE_TOKEN_LENGTH != 0
            or (di % self.ERASE_TOKEN_LENGTH) + len(magic_bytes) > self.ERASE_TOKEN_LENGTH
            or tok <= di < token_phrase_end
        ):
            raise SPSDKError(
                "CMPA ERASE_TOKEN/DELETE_INSTALLER layout is not compatible with a "
                "phrase-aligned CMPA rewrite for Secure Installer erasure."
            )

        image = self._resolve_rewrite_base_image(base_image, cmpa_size)

        # Set DELETE_INSTALLER_MAGIC and force the ERASE_TOKEN phrase blank (it is
        # skipped during programming so the ROM finds it erased).
        image[di : di + len(magic_bytes)] = magic_bytes
        image[tok : tok + self.ERASE_TOKEN_LENGTH] = b"\xff" * self.ERASE_TOKEN_LENGTH

        logger.warning(
            f"Erasing CMPA sector at 0x{self.cmpa_address:08X} and programming "
            "DELETE_INSTALLER_MAGIC (ERASE_TOKEN phrase left erased for the ROM). "
            "Do not power off the device."
        )
        if not self.mboot.flash_erase_region(self.cmpa_address, cmpa_size):
            raise SPSDKError(
                f"Failed to erase CMPA sector at 0x{self.cmpa_address:08X}. "
                f"Error: {self.mboot.status_string}"
            )

        # Program everything before the ERASE_TOKEN phrase (includes the header).
        if tok > 0:
            self._program_cmpa_chunk(self.cmpa_address, bytes(image[:tok]))
        # Program everything after the ERASE_TOKEN phrase (includes DELETE_INSTALLER).
        after = tok + self.ERASE_TOKEN_LENGTH
        if after < cmpa_size:
            self._program_cmpa_chunk(self.cmpa_address + after, bytes(image[after:]))

        self._verify_cmpa_rewrite(magic_bytes)
        logger.info("CMPA rewrite complete; DELETE_INSTALLER_MAGIC programmed.")

    def _program_cmpa_chunk(self, address: int, data: bytes) -> None:
        """Write one CMPA chunk to freshly-erased flash, raising on failure.

        :param address: Absolute flash address (flash-phrase aligned).
        :param data: Phrase-aligned data to program.
        :raises SPSDKError: If the write reports a failure.
        """
        try:
            if not self.mboot.write_memory(address, data):
                raise SPSDKError(
                    f"Failed to program CMPA chunk at 0x{address:08X}. "
                    f"Error: {self.mboot.status_string}"
                )
        except McuBootCommandError as exc:
            raise SPSDKError(f"Failed to program CMPA chunk at 0x{address:08X}: {exc}") from exc

    def _verify_cmpa_rewrite(self, magic_bytes: bytes) -> None:
        """Read back the CMPA and confirm the rewrite landed correctly before reset.

        Confirms the header marker is valid, DELETE_INSTALLER_MAGIC is present and
        the ERASE_TOKEN phrase reads blank. The last check catches an accidental
        programming of the token phrase, which would stop the ROM from completing
        the erase.

        :param magic_bytes: DELETE_INSTALLER_MAGIC little-endian bytes.
        :raises SPSDKError: If any post-rewrite check fails.
        """
        if not self._is_cmpa_header_valid():
            raise SPSDKError(
                "CMPA header marker is invalid after the rewrite; aborting before "
                "reset. Reprogram the CMPA before retrying."
            )
        di_addr = self.cmpa_address + self.delete_installer_offset
        di_data, _ = self._read_memory(di_addr, len(magic_bytes))
        if di_data is None or di_data[: len(magic_bytes)] != magic_bytes:
            raise SPSDKError(
                f"DELETE_INSTALLER_MAGIC is not present at 0x{di_addr:08X} after the "
                "rewrite; aborting before reset."
            )
        tok_addr = self.cmpa_address + self.erase_token_offset
        tok_data, _ = self._read_memory(tok_addr, self.ERASE_TOKEN_LENGTH)
        if tok_data is None or not all(b == 0xFF for b in tok_data):
            raise SPSDKError(
                f"ERASE_TOKEN phrase at 0x{tok_addr:08X} is not blank after the "
                "rewrite; aborting before reset to avoid an incomplete ROM erase."
            )

    def get_device_info(self) -> dict[str, str]:
        """Get information about the Secure Installer erasure configuration.

        :return: Dictionary containing device configuration information
        """
        info = {
            "family": str(self.family),
            "cmpa_address": f"0x{self.cmpa_address:08x}",
            "delete_installer_magic": f"0x{self.delete_installer_magic:08x}",
            "delete_installer_offset": f"0x{self.delete_installer_offset:02X}",
            "erase_token_offset": f"0x{self.erase_token_offset:02X}",
            "si_probe_address": f"0x{self.si_probe_address:08x}",
            "target_address": f"0x{self.cmpa_address + self.delete_installer_offset:08x}",
        }
        if self.cmpa_header_marker is not None:
            info["cmpa_header_marker"] = f"0x{self.cmpa_header_marker:04X}"
        return info


def get_erase_token_register_names(family: FamilyRevision) -> list[str]:
    """Return the CMPA erase-token register names for a family.

    The names are resolved from the family CMPA register model within the erase-token
    region declared by ``pfr.cmpa.erase_token_offset`` (16 bytes). Callers therefore do
    not need to know the per-family naming, which may be ``SI_ERASE_TOKEN0..3`` or
    ``ERASE_TOKEN0..3`` (modeled as sub-registers of a 128-bit ``ERASE_TOKEN`` group).

    :param family: Device family revision.
    :raises SPSDKError: If the family does not declare an erase-token region, or the
        CMPA register model has no registers inside it.
    :return: Ordered list of the four 32-bit erase-token register names.
    """
    db = get_db(family)
    try:
        offset = db.get_int(DatabaseManager.PFR, ["cmpa", "erase_token_offset"])
    except (KeyError, ValueError) as exc:
        raise SPSDKError(
            f"Device family {family} does not declare a Secure Installer erase-token "
            "region (pfr.cmpa.erase_token_offset)."
        ) from exc
    return [reg.name for reg in _leaf_erase_token_registers(CMPA(family).registers, offset)]


def _leaf_erase_token_registers(registers: Registers, offset: int) -> list[Register]:
    """Return the leaf erase-token registers in the 16-byte region, sorted by offset.

    Group sub-registers are included and group parents dropped, so both the flat
    (``SI_ERASE_TOKEN0..3``) and grouped (``ERASE_TOKEN`` with ``ERASE_TOKEN0..3``
    sub-registers) layouts resolve to the four 32-bit words.

    :param registers: CMPA register collection to scan.
    :param offset: Start offset of the erase-token region.
    :raises SPSDKError: If no registers fall inside the region.
    :return: Sorted list of leaf registers in ``[offset, offset + 16)``.
    """
    end = offset + SecureInstallerEraser.ERASE_TOKEN_LENGTH
    regs = sorted(
        (
            reg
            for reg in registers.get_registers(include_group_regs=True)
            if not reg.has_group_registers() and offset <= reg.offset < end
        ),
        key=lambda reg: reg.offset,
    )
    if not regs:
        raise SPSDKError(
            f"CMPA register model declares no registers in the erase-token "
            f"region (offset {offset:#x})."
        )
    return regs
