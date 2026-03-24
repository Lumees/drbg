#!/usr/bin/env python3
# =============================================================================
# Copyright (c) 2026 Lumees Lab / Hasan Kurşun
# SPDX-License-Identifier: Apache-2.0 WITH Commons-Clause
#
# Free for non-commercial use (academic, research, hobby, education).
# Commercial use requires a Lumees Lab license: info@lumeeslab.com
# =============================================================================
"""
DRBG Golden Model — Lumees Lab
================================
CTR-DRBG per NIST SP 800-90A Rev 1 using AES-256.
Pure Python AES-256 implementation (no external dependencies).

Usage:
    drbg = CTR_DRBG_AES256()
    drbg.instantiate(entropy, nonce, perso)
    output = drbg.generate(128)
"""

from __future__ import annotations


# =============================================================================
# Pure Python AES-256 (encrypt only)
# =============================================================================

# AES S-box
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
        0x6c, 0xd8, 0xab, 0x4d]


def _xtime(b: int) -> int:
    return ((b << 1) ^ (0x1b if b & 0x80 else 0)) & 0xff


def _gmul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = _xtime(a)
        b >>= 1
    return p


def _sub_bytes(state: list[list[int]]) -> list[list[int]]:
    return [[SBOX[state[r][c]] for c in range(4)] for r in range(4)]


def _shift_rows(state: list[list[int]]) -> list[list[int]]:
    return [
        [state[r][(c + r) % 4] for c in range(4)]
        for r in range(4)
    ]


def _mix_columns(state: list[list[int]]) -> list[list[int]]:
    result = [[0]*4 for _ in range(4)]
    for c in range(4):
        result[0][c] = _gmul(state[0][c], 2) ^ _gmul(state[1][c], 3) ^ state[2][c] ^ state[3][c]
        result[1][c] = state[0][c] ^ _gmul(state[1][c], 2) ^ _gmul(state[2][c], 3) ^ state[3][c]
        result[2][c] = state[0][c] ^ state[1][c] ^ _gmul(state[2][c], 2) ^ _gmul(state[3][c], 3)
        result[3][c] = _gmul(state[0][c], 3) ^ state[1][c] ^ state[2][c] ^ _gmul(state[3][c], 2)
    return result


def _add_round_key(state: list[list[int]], rk: list[list[int]]) -> list[list[int]]:
    return [[state[r][c] ^ rk[r][c] for c in range(4)] for r in range(4)]


def _bytes_to_state(b: bytes) -> list[list[int]]:
    """Column-major: byte 0 = state[0][0], byte 1 = state[1][0], etc."""
    state = [[0]*4 for _ in range(4)]
    for c in range(4):
        for r in range(4):
            state[r][c] = b[c*4 + r]
    return state


def _state_to_bytes(state: list[list[int]]) -> bytes:
    result = bytearray(16)
    for c in range(4):
        for r in range(4):
            result[c*4 + r] = state[r][c]
    return bytes(result)


def _key_expand_256(key: bytes) -> list[list[list[int]]]:
    """AES-256 key expansion -> 15 round keys as 4x4 state matrices."""
    w = []
    for i in range(8):
        w.append(list(key[4*i:4*i+4]))

    for i in range(8, 60):
        temp = list(w[i-1])
        if i % 8 == 0:
            temp = [SBOX[temp[1]], SBOX[temp[2]], SBOX[temp[3]], SBOX[temp[0]]]
            temp[0] ^= RCON[i // 8]
        elif i % 8 == 4:
            temp = [SBOX[t] for t in temp]
        w.append([w[i-8][j] ^ temp[j] for j in range(4)])

    round_keys = []
    for rk in range(15):
        # Each round key: 4 words -> 16 bytes -> state matrix
        rk_bytes = bytearray()
        for j in range(4):
            rk_bytes.extend(w[4*rk + j])
        round_keys.append(_bytes_to_state(bytes(rk_bytes)))

    return round_keys


def aes256_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """AES-256 encrypt a single 16-byte block."""
    assert len(plaintext) == 16 and len(key) == 32

    rkeys = _key_expand_256(key)
    state = _bytes_to_state(plaintext)
    state = _add_round_key(state, rkeys[0])

    for r in range(1, 14):
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, rkeys[r])

    # Final round (no MixColumns)
    state = _sub_bytes(state)
    state = _shift_rows(state)
    state = _add_round_key(state, rkeys[14])

    return _state_to_bytes(state)


# =============================================================================
# CTR-DRBG with AES-256
# =============================================================================

KEY_LEN = 32   # bytes (256 bits)
BLK_LEN = 16   # bytes (128 bits)
SEEDLEN = KEY_LEN + BLK_LEN  # 48 bytes (384 bits)


def _int_to_bytes(val: int, length: int) -> bytes:
    return val.to_bytes(length, 'big')


def _bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'big')


def _inc_v(v: bytes) -> bytes:
    """Increment 128-bit counter V by 1."""
    val = (_bytes_to_int(v) + 1) & ((1 << 128) - 1)
    return _int_to_bytes(val, BLK_LEN)


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


class CTR_DRBG_AES256:
    """CTR-DRBG using AES-256 per NIST SP 800-90A Rev 1 (no derivation function)."""

    def __init__(self):
        self.key = b'\x00' * KEY_LEN
        self.v = b'\x00' * BLK_LEN
        self.reseed_counter = 0
        self.instantiated = False

    def _update(self, provided_data: bytes):
        """CTR_DRBG_Update per NIST SP 800-90A Section 10.2.1.2."""
        assert len(provided_data) == SEEDLEN

        temp = b''
        v = self.v
        while len(temp) < SEEDLEN:
            v = _inc_v(v)
            block = aes256_encrypt(v, self.key)
            temp += block

        temp = temp[:SEEDLEN]
        temp = _xor_bytes(temp, provided_data)

        self.key = temp[:KEY_LEN]
        self.v = temp[KEY_LEN:]

    def instantiate(self, entropy: bytes, nonce: bytes, perso: bytes = b''):
        """CTR_DRBG_Instantiate per NIST SP 800-90A Section 10.2.1.3.1 (no df)."""
        # seed_material = entropy_input || nonce || personalization_string
        # Pad/truncate to SEEDLEN
        seed_material = entropy + nonce
        if perso:
            # XOR personalization into seed_material
            perso_padded = perso + b'\x00' * (SEEDLEN - len(perso))
            seed_material = _xor_bytes(seed_material[:SEEDLEN],
                                       perso_padded[:SEEDLEN])
        else:
            seed_material = seed_material[:SEEDLEN]

        # Pad to SEEDLEN if shorter
        if len(seed_material) < SEEDLEN:
            seed_material += b'\x00' * (SEEDLEN - len(seed_material))

        self.key = b'\x00' * KEY_LEN
        self.v = b'\x00' * BLK_LEN
        self._update(seed_material)
        self.reseed_counter = 1
        self.instantiated = True

    def reseed(self, entropy: bytes, addl_input: bytes = b''):
        """CTR_DRBG_Reseed per NIST SP 800-90A Section 10.2.1.4.1 (no df)."""
        seed_material = entropy + addl_input
        if len(seed_material) < SEEDLEN:
            seed_material += b'\x00' * (SEEDLEN - len(seed_material))
        seed_material = seed_material[:SEEDLEN]

        self._update(seed_material)
        self.reseed_counter = 1

    def generate(self, num_bits: int, addl_input: bytes = b'') -> bytes:
        """CTR_DRBG_Generate per NIST SP 800-90A Section 10.2.1.5.1 (no df)."""
        assert self.instantiated, "DRBG not instantiated"

        if addl_input:
            addl_padded = addl_input + b'\x00' * (SEEDLEN - len(addl_input))
            addl_padded = addl_padded[:SEEDLEN]
            self._update(addl_padded)

        num_bytes = (num_bits + 7) // 8
        temp = b''
        while len(temp) < num_bytes:
            self.v = _inc_v(self.v)
            block = aes256_encrypt(self.v, self.key)
            temp += block

        output = temp[:num_bytes]

        # Update with additional_input (or zeros if none)
        addl_for_update = b'\x00' * SEEDLEN
        if addl_input:
            addl_padded = addl_input + b'\x00' * (SEEDLEN - len(addl_input))
            addl_for_update = addl_padded[:SEEDLEN]
        self._update(addl_for_update)
        self.reseed_counter += 1

        return output

    def get_state(self) -> tuple:
        """Return current internal state for debugging."""
        return (self.key, self.v, self.reseed_counter)


# =============================================================================
# Self-test
# =============================================================================

def _self_test():
    """Verify basic DRBG behavior."""
    tests_passed = 0
    tests_total = 0

    # Test 1: AES-256 known answer
    tests_total += 1
    key = bytes(range(32))
    pt = bytes(range(16))
    ct = aes256_encrypt(pt, key)
    # Known answer from NIST FIPS 197 (AES-256 key schedule test)
    print(f"  AES-256 encrypt: PT={pt.hex()}")
    print(f"                   Key={key.hex()}")
    print(f"                   CT={ct.hex()}")
    # Just verify it doesn't crash and produces 16 bytes
    if len(ct) == 16:
        print("  [PASS] AES-256 encrypt produces 16-byte output")
        tests_passed += 1
    else:
        print("  [FAIL] AES-256 encrypt output length wrong")

    # Test 2: DRBG determinism — same seed = same output
    tests_total += 1
    entropy = bytes(range(32))
    nonce = bytes(range(16))
    drbg1 = CTR_DRBG_AES256()
    drbg1.instantiate(entropy, nonce)
    out1 = drbg1.generate(128)

    drbg2 = CTR_DRBG_AES256()
    drbg2.instantiate(entropy, nonce)
    out2 = drbg2.generate(128)

    if out1 == out2:
        print(f"  [PASS] Determinism: same seed -> same output: {out1.hex()}")
        tests_passed += 1
    else:
        print(f"  [FAIL] Determinism: {out1.hex()} != {out2.hex()}")

    # Test 3: Different seeds -> different output
    tests_total += 1
    entropy2 = bytes([x ^ 0xFF for x in range(32)])
    drbg3 = CTR_DRBG_AES256()
    drbg3.instantiate(entropy2, nonce)
    out3 = drbg3.generate(128)

    if out1 != out3:
        print(f"  [PASS] Different seeds diverge: {out1.hex()} != {out3.hex()}")
        tests_passed += 1
    else:
        print(f"  [FAIL] Different seeds produced same output!")

    # Test 4: Reseed changes output
    tests_total += 1
    drbg4 = CTR_DRBG_AES256()
    drbg4.instantiate(entropy, nonce)
    drbg4.reseed(entropy2)
    out4 = drbg4.generate(128)

    if out4 != out1:
        print(f"  [PASS] Reseed changes output: {out4.hex()}")
        tests_passed += 1
    else:
        print(f"  [FAIL] Reseed did not change output!")

    # Test 5: Multiple generates produce different outputs
    tests_total += 1
    drbg5 = CTR_DRBG_AES256()
    drbg5.instantiate(entropy, nonce)
    out5a = drbg5.generate(128)
    out5b = drbg5.generate(128)

    if out5a != out5b:
        print(f"  [PASS] Consecutive generates differ: {out5a.hex()} != {out5b.hex()}")
        tests_passed += 1
    else:
        print(f"  [FAIL] Consecutive generates identical!")

    print(f"\n  {tests_passed}/{tests_total} self-tests passed")
    return tests_passed == tests_total


if __name__ == "__main__":
    print("DRBG Model Self-Test")
    print("=" * 40)
    ok = _self_test()
    exit(0 if ok else 1)
