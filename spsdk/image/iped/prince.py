#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Pure-Python implementation of the PRINCE lightweight block cipher.

This module provides a software implementation of the PRINCE cipher used by
NXP IPED (Inline PRINCE Encryption/Decryption) hardware for CTR and GCM modes.
It serves as a drop-in replacement for the C++ ``iped-offline-tool`` shared library.

The PRINCE cipher operates on 64-bit blocks with a 128-bit key (split into k0, k1).
This implementation supports:
- 12-round PRINCE encryption/decryption
- CTR mode with address-based counter
- GCM mode with GHASH authentication

Performance note: This pure-Python implementation is significantly slower than
the C++ backend. For large data (>1MB), the C++ backend is recommended.
"""

import logging

logger = logging.getLogger(__name__)

# PRINCE constants
_ALPHA = 0xC0AC29B7C97C50DD
_BETA = 0x3F84D5B5B5470917
_MASK64 = 0xFFFFFFFFFFFFFFFF

# S-box derived from ID_CFG_PRINCE_CORE_SBOX_VALUE_T0 = 0xBF32AC916780E5D4
_SBOX_T0 = [0xB, 0xF, 0x3, 0x2, 0xA, 0xC, 0x9, 0x1, 0x6, 0x7, 0x8, 0x0, 0xE, 0x5, 0xD, 0x4]
_SBOX_T1 = [0xB, 0xF, 0x3, 0x2, 0xA, 0xC, 0x9, 0x1, 0x6, 0x7, 0x8, 0x0, 0xE, 0x5, 0xD, 0x4]

# Inverse S-box derived from ID_CFG_PRINCE_CORE_INV_SBOX_VALUE_T0 = 0xB732FD89A6405EC1
_SBOX_INV_T0 = [0xB, 0x7, 0x3, 0x2, 0xF, 0xD, 0x8, 0x9, 0xA, 0x6, 0x4, 0x0, 0x5, 0xE, 0xC, 0x1]
_SBOX_INV_T1 = [0xB, 0x7, 0x3, 0x2, 0xF, 0xD, 0x8, 0x9, 0xA, 0x6, 0x4, 0x0, 0x5, 0xE, 0xC, 0x1]

# Pre-computed 16-bit matrices M0 and M1 for M' layer
_M16_0 = [
    0x0111,
    0x2220,
    0x4404,
    0x8088,
    0x1011,
    0x0222,
    0x4440,
    0x8808,
    0x1101,
    0x2022,
    0x0444,
    0x8880,
    0x1110,
    0x2202,
    0x4044,
    0x0888,
]
_M16_1 = [
    0x1110,
    0x2202,
    0x4044,
    0x0888,
    0x0111,
    0x2220,
    0x4404,
    0x8088,
    0x1011,
    0x0222,
    0x4440,
    0x8808,
    0x1101,
    0x2022,
    0x0444,
    0x8880,
]

# Round constants for 12-round PRINCE
_RC = [
    0x0000000000000000,
    0x13198A2E03707344,
    0xA4093822299F31D0,
    0x082EFA98EC4E6C89,
    0x452821E638D01377,
    0xBE5466CF34E90C6C,
]
# rc[6..11] = rc[5-i] ^ ALPHA for non-PRINCE_V2
_RC_FULL: list[int] = []


def _init_round_constants() -> list[int]:
    """Initialize full round constants array for 12 rounds."""
    rc = list(_RC) + [0] * 6
    for i in range(6):
        rc[11 - i] = rc[i] ^ _ALPHA
    return rc


_RC_FULL = _init_round_constants()


def _get_round_constant(rnd: int, nb_rounds: int) -> int:
    """Get round constant for given round index and effective number of rounds.

    The PRINCE cipher uses round constants that depend on the total number of
    effective rounds. For standard 12-round operation the pre-computed table is used.
    For double encryption (22 effective rounds), constants are computed dynamically.

    :param rnd: Round index.
    :param nb_rounds: Effective number of rounds.
    :return: 64-bit round constant.
    """
    if nb_rounds == 12:
        return _RC_FULL[rnd]
    # Dynamic computation for arbitrary effective round count
    # Base constants indexed by condition threshold
    base_rc = {
        0: 0x0000000000000000,
        1: 0x13198A2E03707344,
        2: 0xA4093822299F31D0,
        3: 0x082EFA98EC4E6C89,
        4: 0x452821E638D01377,
        5: 0xBE5466CF34E90C6C,
        6: 0x0F6D6FF383F44239,
        7: 0x1339B2EB3B52EC6F,
        8: 0x1A60320AD6A100C6,
        9: 0x8E7D44EC5716F2B8,
        10: 0x214B7BF3D1F0CFC8,
    }
    # Thresholds for activation (from C++: if (nb_rounds > X) rc[idx] = ...)
    thresholds = {3: 6, 4: 8, 5: 10, 6: 12, 7: 14, 8: 16, 9: 18, 10: 20}

    rc = [0] * (nb_rounds + 1)
    # Always set first 3
    for i in range(min(3, nb_rounds + 1)):
        rc[i] = base_rc[i]
    # Conditionally set higher indices
    for idx, thresh in thresholds.items():
        if nb_rounds > thresh and idx < len(rc):
            rc[idx] = base_rc[idx]
    # Generate second half: rc[nb_rounds-1-i] = rc[i] ^ ALPHA
    for i in range(nb_rounds // 2):
        idx = nb_rounds - 1 - i
        if idx < len(rc):
            rc[idx] = (rc[i] ^ _ALPHA) & _MASK64
    return rc[rnd] if rnd < len(rc) else 0


def _gf2_mat_mult16(val: int, mat: list[int]) -> int:
    """GF(2) matrix-vector multiply over 16 bits."""
    out = 0
    for i in range(16):
        if (val >> i) & 1:
            out ^= mat[i]
    return out


def _s_layer(s_in: int, round_index: int) -> int:
    """Apply S-box substitution layer."""
    s_out = 0
    sbox = _SBOX_T0 if (round_index - 1) % 2 == 0 else _SBOX_T1
    for i in range(16):
        shift = i * 4
        nibble = (s_in >> shift) & 0xF
        s_out |= sbox[nibble] << shift
    return s_out


def _s_inv_layer(s_in: int, round_index: int) -> int:
    """Apply inverse S-box substitution layer."""
    s_out = 0
    sbox = _SBOX_INV_T0 if (round_index - 1) % 2 == 0 else _SBOX_INV_T1
    for i in range(16):
        shift = i * 4
        nibble = (s_in >> shift) & 0xF
        s_out |= sbox[nibble] << shift
    return s_out


def _m_prime_layer(m_in: int) -> int:
    """Apply M' linear layer (matrix multiplication)."""
    chunk0 = _gf2_mat_mult16((m_in >> 0) & 0xFFFF, _M16_0)
    chunk1 = _gf2_mat_mult16((m_in >> 16) & 0xFFFF, _M16_1)
    chunk2 = _gf2_mat_mult16((m_in >> 32) & 0xFFFF, _M16_1)
    chunk3 = _gf2_mat_mult16((m_in >> 48) & 0xFFFF, _M16_0)
    return (chunk3 << 48) | (chunk2 << 32) | (chunk1 << 16) | chunk0


def _shift_rows(val: int, inverse: bool) -> int:
    """Apply shift rows permutation."""
    row_mask = 0xF000F000F000F000
    out = 0
    for i in range(4):
        row = val & (row_mask >> (4 * i))
        shift = i * 16 if inverse else 64 - i * 16
        out |= ((row >> shift) | (row << (64 - shift))) & _MASK64
    return out


def _m_layer(m_in: int) -> int:
    """Apply M layer = M' + shift rows."""
    return _shift_rows(_m_prime_layer(m_in), False)


def _m_inv_layer(m_in: int) -> int:
    """Apply M^-1 layer = inverse shift rows + M'."""
    return _m_prime_layer(_shift_rows(m_in, True))


def _k0_to_k0_prime(k0: int) -> int:
    """Compute K0' from K0: ror1(K0) XOR (K0 >> 63)."""
    k0_ror1 = ((k0 >> 1) | (k0 << 63)) & _MASK64
    return k0_ror1 ^ (k0 >> 63)


def _prince_round(nb_rounds: int, round_input: int, round_index: int, k1: int) -> int:
    """One forward round of PRINCE cipher."""
    s_out = _s_layer(round_input, round_index)
    m_out = _m_layer(s_out)
    return (m_out ^ k1 ^ _get_round_constant(round_index, nb_rounds)) & _MASK64


def _prince_core(core_input: int, k1: int, nb_rounds: int, conf: int) -> int:
    """PRINCE core function (non-PRINCE_V2 path, 12 rounds)."""
    nb_rounds_eff = nb_rounds * (conf + 1) - 2 if conf != 0 else nb_rounds

    round_input = (core_input ^ k1 ^ _get_round_constant(0, nb_rounds_eff)) & _MASK64

    # Forward rounds
    for rnd in range(1, nb_rounds_eff // 2):
        if rnd < nb_rounds // 2:
            round_index = rnd
        else:
            round_index = rnd - (nb_rounds // 2 - 1)
        s_out = _s_layer(round_input, round_index)
        m_out = _m_layer(s_out)
        round_input = (m_out ^ k1 ^ _get_round_constant(rnd, nb_rounds_eff)) & _MASK64

    # Middle round
    middle_s = _s_layer(round_input, 2)
    middle_m = _m_prime_layer(middle_s)
    round_input = _s_inv_layer(middle_m, 2)

    # Backward rounds
    for rnd in range(nb_rounds_eff // 2 + 2, nb_rounds_eff + 1):
        if rnd < nb_rounds_eff // 2 + nb_rounds // 2 + 1:
            round_index = rnd - 1 if conf == 0 else rnd - 2
        else:
            round_index = rnd - nb_rounds // 2 + 1

        m_inv_in = (round_input ^ k1 ^ _get_round_constant(rnd - 2, nb_rounds_eff)) & _MASK64
        s_inv_in = _m_inv_layer(m_inv_in)
        round_input = _s_inv_layer(s_inv_in, nb_rounds_eff - round_index)

    core_output = (
        round_input ^ k1 ^ _get_round_constant(nb_rounds_eff - 1, nb_rounds_eff)
    ) & _MASK64
    return core_output


def prince_enc_dec(
    data: int, enc_k0: int, enc_k1: int, decrypt: bool, nb_rounds: int = 12, conf: int = 0
) -> int:
    """Top-level PRINCE encrypt/decrypt on a 64-bit block.

    :param data: 64-bit input data block.
    :param enc_k0: Upper 64 bits of 128-bit key.
    :param enc_k1: Lower 64 bits of 128-bit key.
    :param decrypt: True for decryption, False for encryption.
    :param nb_rounds: Number of rounds (default 12).
    :param conf: Configuration (default 0).
    :return: 64-bit output data block.
    """
    k1 = (enc_k1 ^ _ALPHA) & _MASK64 if decrypt else enc_k1
    k0_prime = _k0_to_k0_prime(enc_k0)
    k0 = k0_prime if decrypt else enc_k0
    k0_out = enc_k0 if decrypt else k0_prime

    core_input = (data ^ k0) & _MASK64
    core_output = _prince_core(core_input, k1, nb_rounds, conf)
    return (core_output ^ k0_out) & _MASK64


def _ctr_prince_mem_enc(
    data: int,
    iv: int,
    address: int,
    key0: int,
    key1: int,
    conf: int = 0,
    nb_rounds: int = 12,
    mode: int = 5,
) -> int:
    """PRINCE CTR mode encryption for a single 8-byte block.

    :param data: 64-bit plaintext/ciphertext block.
    :param iv: 64-bit initialization vector.
    :param address: 32-bit address (lower bits used).
    :param key0: 64-bit key part 0.
    :param key1: 64-bit key part 1.
    :param conf: Double encryption config (0 or 1).
    :param nb_rounds: Number of PRINCE rounds.
    :param mode: CTR mode selector (0 or 5).
    :return: 64-bit encrypted/decrypted block.
    """
    address_const = 0x67696F66
    sh_address = (address << 32) & _MASK64
    expanded_address = ((((~address) ^ mode) << 32) & _MASK64) | (
        ((sh_address >> 32) ^ address_const) & 0xFFFFFFFF
    )
    expanded_address &= _MASK64

    prince_in = _prince_round(12, expanded_address, 1, iv)
    prince_out = prince_enc_dec(prince_in, key0, key1, False, nb_rounds, conf)
    return (prince_out ^ data) & _MASK64


def _ghash_mul(x: int, y: int) -> int:
    """GF(2^64) multiplication used in PRINCE-GCM (reduction polynomial x^64 + x^4 + x^3 + x + 1).

    :param x: 64-bit operand.
    :param y: 64-bit operand.
    :return: 64-bit product in GF(2^64).
    """
    r_const = 0x1B
    x_next = x & _MASK64
    z = 0
    for i in range(64):
        if (y >> i) & 1:
            z ^= x_next
        if (x_next >> 63) & 1:
            x_next = ((x_next << 1) ^ r_const) & _MASK64
        else:
            x_next = (x_next << 1) & _MASK64
    return z


class PrinceError(Exception):
    """Exception raised by the PRINCE Python backend."""


class PrinceCipher:
    """Pure-Python PRINCE cipher implementation compatible with iped-offline-tool.

    This class provides the same interface as the C++ ``IPED`` class from
    ``iped-offline-tool``, enabling encryption/decryption of data blocks using
    the PRINCE cipher in CTR or GCM mode.

    :param key: 128-bit encryption key (bytes or int).
    :param address: Starting memory address for CTR counter.
    :param iv: 64-bit initialization vector.
    :param use_gcm: Whether to use GCM mode (True) or CTR mode (False).
    :param aad: Additional authenticated data for GCM (64-bit).
    :param tag: Initial authentication tag for GCM verification.
    :param double_encrypt: Enable double encryption path.
    """

    BLOCK_SIZE = 8
    KEY_SIZE = 16

    def __init__(
        self,
        key: int | bytes,
        address: int | bytes,
        iv: int | bytes,
        use_gcm: bool = False,
        aad: int | bytes | None = None,
        tag: int | bytes = 0,
        double_encrypt: bool = False,
    ) -> None:
        """Initialize PRINCE cipher context."""
        if isinstance(key, int):
            key = key.to_bytes(length=self.KEY_SIZE, byteorder="big")
        if len(key) != self.KEY_SIZE:
            raise PrinceError(f"Invalid key length. Expected {self.KEY_SIZE}B, got {len(key)}B.")
        self.key = key
        self.key0 = int.from_bytes(key[: self.BLOCK_SIZE], byteorder="big")
        self.key1 = int.from_bytes(key[self.BLOCK_SIZE :], byteorder="big")

        self.iv = iv if isinstance(iv, int) else int.from_bytes(iv, byteorder="big")
        if self.iv.bit_length() > 64:
            raise PrinceError(f"IV is too big. Expecting up to {self.BLOCK_SIZE}B.")

        self.next_address = (
            address if isinstance(address, int) else int.from_bytes(address, byteorder="big")
        )
        self.double_encrypt = 1 if double_encrypt else 0

        self.mode = 1 if use_gcm else 0
        if use_gcm:
            if aad is None:
                raise PrinceError("GCM encryption requires AAD (Additional Authentication Data)")
            self.aad = aad if isinstance(aad, int) else int.from_bytes(aad, byteorder="big")
        else:
            self.aad = 0
        self.tag = tag if isinstance(tag, int) else int.from_bytes(tag, byteorder="big")

    def is_gcm(self) -> bool:
        """Check if GCM mode is enabled.

        :return: True if GCM mode.
        """
        return self.mode == 1

    def encrypt(self, data: bytes | int, address: int | None = None) -> bytes:
        """Encrypt data using PRINCE cipher.

        :param data: Data to encrypt (bytes or 64-bit int for single block).
        :param address: Optional override for starting address.
        :return: Encrypted data bytes.
        """
        if isinstance(data, int):
            data = data.to_bytes(length=8, byteorder="big")
        return self._transaction(decrypt=False, data=data, address=address)

    def decrypt(self, data: bytes | int, address: int | None = None) -> bytes:
        """Decrypt data using PRINCE cipher.

        :param data: Data to decrypt (bytes or 64-bit int for single block).
        :param address: Optional override for starting address.
        :return: Decrypted data bytes.
        """
        if isinstance(data, int):
            data = data.to_bytes(length=8, byteorder="big")
        return self._transaction(decrypt=True, data=data, address=address)

    def _transaction(self, decrypt: bool, data: bytes, address: int | None = None) -> bytes:
        """Execute encryption/decryption transaction.

        :param decrypt: True for decryption.
        :param data: Input data.
        :param address: Starting address (uses self.next_address if None).
        :return: Output data bytes.
        """
        address = address if address is not None else self.next_address
        n_blocks = (len(data) + self.BLOCK_SIZE - 1) // self.BLOCK_SIZE
        padded_size = n_blocks * self.BLOCK_SIZE
        data = data.ljust(padded_size, b"\x00")

        conf = self.double_encrypt
        nb_rounds = 12

        if self.is_gcm():
            return self._gcm_transaction(
                decrypt=decrypt,
                data=data,
                address=address,
                n_blocks=n_blocks,
                padded_size=padded_size,
                conf=conf,
                nb_rounds=nb_rounds,
            )

        # CTR mode - process block by block
        mode_in = 5  # CTR with GCM hardware enabled
        result = bytearray()
        for i in range(n_blocks):
            block = int.from_bytes(data[8 * i : 8 * (i + 1)], byteorder="big")
            block_addr = address + 8 * i
            out = _ctr_prince_mem_enc(
                block, self.iv, block_addr, self.key0, self.key1, conf, nb_rounds, mode_in
            )
            result.extend(out.to_bytes(8, "big"))

        self.next_address = address + padded_size
        return bytes(result)

    def _gcm_transaction(
        self,
        decrypt: bool,
        data: bytes,
        address: int,
        n_blocks: int,
        padded_size: int,
        conf: int,
        nb_rounds: int,
    ) -> bytes:
        """Execute GCM mode transaction.

        :param decrypt: True for decryption.
        :param data: Padded input data.
        :param address: Starting address.
        :param n_blocks: Number of 8-byte blocks.
        :param padded_size: Total padded data size.
        :param conf: Double encryption config.
        :param nb_rounds: PRINCE rounds.
        :return: Output data bytes.
        """
        mode_in = 2  # GCM mode

        # GCM init: compute H and ctr0
        h_op = prince_enc_dec(0, self.key0, self.key1, False, nb_rounds, conf)
        ctr0_inp = 0x616C62616C756365
        ctr0_prince_in = _prince_round(12, ctr0_inp, 1, self.iv)
        ctr0_op = prince_enc_dec(ctr0_prince_in, self.key0, self.key1, False, nb_rounds, conf)
        auth_tag = (ctr0_op ^ _ghash_mul(h_op, self.aad)) & _MASK64

        # Process blocks
        o_data_list: list[int] = []
        for i in range(n_blocks):
            block = int.from_bytes(data[8 * i : 8 * (i + 1)], byteorder="big")
            block_addr = address + 8 * i
            o_block = _ctr_prince_mem_enc(
                block, self.iv, block_addr, self.key0, self.key1, conf, nb_rounds, mode_in
            )
            o_data_list.append(o_block)

            prev_tag = (auth_tag ^ ctr0_op) & _MASK64
            data_to_ghash = block if decrypt else o_block
            auth_tag = (ctr0_op ^ _ghash_mul(h_op, (data_to_ghash ^ prev_tag) & _MASK64)) & _MASK64

        # Finalize: len_a_c hash
        data_width = 64
        counter = n_blocks * 64
        len_a_c = (data_width << 33) | counter
        prev_tag = (auth_tag ^ ctr0_op) & _MASK64
        auth_tag = (ctr0_op ^ _ghash_mul(h_op, (len_a_c ^ prev_tag) & _MASK64)) & _MASK64

        self.tag = auth_tag
        self.next_address = address + padded_size
        return b"".join(o.to_bytes(8, "big") for o in o_data_list)


def _get_native_backend() -> type | None:
    """Try to import the native C++ PRINCE backend (spsdk-iped package).

    Performs a known-answer test to verify the library produces correct results
    on the current platform.

    :return: The native IPED class or None if not available/broken.
    """
    try:
        from spsdk_iped import (  # type: ignore[import-not-found] # pylint: disable=import-outside-toplevel,import-error # noqa: E501
            IPED,
        )

        # Known-answer test: CTR encrypt 8 zero bytes with key=0, iv=0, addr=0
        # Result must match the Python backend's output
        result = IPED(key=0, address=0, iv=0).encrypt(b"\x00" * 8)
        expected = _ctr_prince_mem_enc(0, 0, 0, 0, 0, 0, 12, 5).to_bytes(8, "big")
        if result != expected:
            logger.warning("Native PRINCE backend failed verification, using pure-Python")
            return None
        return IPED
    except Exception:  # pylint: disable=broad-except
        return None


_BACKEND_CACHE: dict[str, type | None] = {}


def get_prince_cipher(
    key: int | bytes,
    address: int | bytes,
    iv: int | bytes,
    use_gcm: bool = False,
    aad: int | bytes | None = None,
    tag: int | bytes = 0,
    double_encrypt: bool = False,
) -> "PrinceCipher":
    """Create a PRINCE cipher instance using the fastest available backend.

    If the ``spsdk-iped`` package is installed, uses the C++ backend (~150x faster).
    Otherwise falls back to the pure-Python implementation.

    :param key: 128-bit encryption key (bytes or int).
    :param address: Starting memory address for CTR counter.
    :param iv: 64-bit initialization vector.
    :param use_gcm: Whether to use GCM mode (True) or CTR mode (False).
    :param aad: Additional authenticated data for GCM (64-bit).
    :param tag: Initial authentication tag for GCM verification.
    :param double_encrypt: Enable double encryption path.
    :return: PRINCE cipher instance (native or pure-Python).
    """
    if "native" not in _BACKEND_CACHE:
        _BACKEND_CACHE["native"] = _get_native_backend()
        if _BACKEND_CACHE["native"]:
            logger.info("Using native C++ PRINCE backend (spsdk-iped)")
        else:
            logger.debug("Native PRINCE backend not available, using pure-Python")

    native_cls = _BACKEND_CACHE["native"]
    if native_cls is not None:
        return native_cls(  # type: ignore[return-value]
            key=key,
            address=address,
            iv=iv,
            use_gcm=use_gcm,
            aad=aad,
            tag=tag,
            double_encrypt=double_encrypt,
        )

    return PrinceCipher(
        key=key,
        address=address,
        iv=iv,
        use_gcm=use_gcm,
        aad=aad,
        tag=tag,
        double_encrypt=double_encrypt,
    )
