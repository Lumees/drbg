#!/usr/bin/env python3
# =============================================================================
# Copyright (c) 2026 Lumees Lab / Hasan Kurşun
# SPDX-License-Identifier: Apache-2.0 WITH Commons-Clause
#
# Free for non-commercial use (academic, research, hobby, education).
# Commercial use requires a Lumees Lab license: info@lumeeslab.com
# =============================================================================
"""
DRBG UART Hardware Regression Test
=====================================
Runs on Arty A7-100T via litex_server + RemoteClient.
Requires: litex_server --uart --uart-port /dev/ttyUSB1 --uart-baudrate 115200
"""

import os
import sys
import time

from litex.tools.litex_client import RemoteClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../model'))
from drbg_model import CTR_DRBG_AES256

PASS_COUNT = 0
FAIL_COUNT = 0


class DRBGClient:
    def __init__(self, host='localhost', tcp_port=1234, csr_csv=None):
        self.client = RemoteClient(host=host, port=tcp_port, csr_csv=csr_csv)
        self.client.open()

    def close(self):
        self.client.close()

    def _w(self, reg: str, val: int):
        getattr(self.client.regs, f"drbg_{reg}").write(val & 0xFFFFFFFF)

    def _r(self, reg: str) -> int:
        return int(getattr(self.client.regs, f"drbg_{reg}").read())

    def write_entropy(self, entropy: bytes):
        """Write 32-byte entropy to ENTROPY[0..7] registers."""
        assert len(entropy) == 32
        for i in range(8):
            word = int.from_bytes(entropy[i*4:(i+1)*4], 'little')
            self._w(f"entropy{i}", word)

    def write_nonce(self, nonce: bytes):
        """Write 16-byte nonce to NONCE[0..3] registers."""
        assert len(nonce) == 16
        for i in range(4):
            word = int.from_bytes(nonce[i*4:(i+1)*4], 'little')
            self._w(f"nonce{i}", word)

    def instantiate(self):
        self._w("ctrl", 0x01)

    def reseed(self):
        self._w("ctrl", 0x02)

    def generate(self):
        self._w("ctrl", 0x04)

    def status(self) -> dict:
        s = self._r("status")
        return {"ready": bool(s & 1), "busy": bool(s & 2), "need_reseed": bool(s & 4)}

    def wait_ready(self, timeout=5.0) -> bool:
        t0 = time.time()
        while time.time() - t0 < timeout:
            if self.status()["ready"]:
                return True
            time.sleep(0.01)
        return False

    def read_output(self) -> bytes:
        """Read 128-bit output as bytes."""
        words = []
        for i in range(4):
            words.append(self._r(f"output{i}"))
        out = b''
        for w in words:
            out += w.to_bytes(4, 'little')
        return out

    def version(self) -> int:
        return self._r("version")

    def info(self) -> dict:
        v = self._r("info")
        return {"BLK_LEN": v & 0xFF, "KEY_LEN_BYTES": (v >> 8) & 0xFF}


def check(name, condition, detail=""):
    global PASS_COUNT, FAIL_COUNT
    if condition:
        print(f"  [PASS] {name}")
        PASS_COUNT += 1
    else:
        print(f"  [FAIL] {name}  {detail}")
        FAIL_COUNT += 1


# ── Tests ────────────────────────────────────────────────────────────────────

def test_version(dut: DRBGClient):
    print("\n[T01] Version / Info registers")
    ver = dut.version()
    check("VERSION == 0x00010000", ver == 0x00010000, f"got 0x{ver:08X}")
    info = dut.info()
    check("INFO.BLK_LEN == 128", info["BLK_LEN"] == 128, f"got {info['BLK_LEN']}")
    check("INFO.KEY_LEN_BYTES == 32", info["KEY_LEN_BYTES"] == 32,
          f"got {info['KEY_LEN_BYTES']}")


def test_instantiate_generate(dut: DRBGClient):
    print("\n[T02] Instantiate + Generate")
    entropy = bytes(range(32))
    nonce = bytes(range(16))

    model = CTR_DRBG_AES256()
    model.instantiate(entropy, nonce)
    expected = model.generate(128)

    dut.write_entropy(entropy)
    dut.write_nonce(nonce)
    dut.instantiate()
    dut.wait_ready()
    dut.generate()
    dut.wait_ready()
    got = dut.read_output()

    check("Output matches model", got == expected,
          f"got {got.hex()} expected {expected.hex()}")


def test_determinism(dut: DRBGClient):
    print("\n[T03] Determinism (same seed = same output)")
    entropy = bytes([0xAA] * 32)
    nonce = bytes([0xBB] * 16)

    dut.write_entropy(entropy)
    dut.write_nonce(nonce)
    dut.instantiate()
    dut.wait_ready()
    dut.generate()
    dut.wait_ready()
    out1 = dut.read_output()

    # Re-instantiate with same seed
    dut.instantiate()
    dut.wait_ready()
    dut.generate()
    dut.wait_ready()
    out2 = dut.read_output()

    check("Same seed same output", out1 == out2,
          f"out1={out1.hex()} out2={out2.hex()}")


def test_different_seeds(dut: DRBGClient):
    print("\n[T04] Different seeds produce different outputs")
    entropy1 = bytes(range(32))
    entropy2 = bytes([x ^ 0xFF for x in range(32)])
    nonce = bytes(range(16))

    dut.write_entropy(entropy1)
    dut.write_nonce(nonce)
    dut.instantiate()
    dut.wait_ready()
    dut.generate()
    dut.wait_ready()
    out1 = dut.read_output()

    dut.write_entropy(entropy2)
    dut.instantiate()
    dut.wait_ready()
    dut.generate()
    dut.wait_ready()
    out2 = dut.read_output()

    check("Different seeds diverge", out1 != out2,
          f"out1={out1.hex()} out2={out2.hex()}")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    csr_csv = os.path.join(os.path.dirname(__file__),
                           'build/digilent_arty/csr.csv')
    if not os.path.exists(csr_csv):
        csr_csv = None

    dut = DRBGClient(csr_csv=csr_csv)

    try:
        print("=" * 60)
        print("DRBG UART Hardware Regression")
        print("=" * 60)

        test_version(dut)
        test_instantiate_generate(dut)
        test_determinism(dut)
        test_different_seeds(dut)

        print("\n" + "=" * 60)
        total = PASS_COUNT + FAIL_COUNT
        print(f"Result: {PASS_COUNT}/{total} PASS  {FAIL_COUNT}/{total} FAIL")
        print("=" * 60)
        sys.exit(0 if FAIL_COUNT == 0 else 1)

    finally:
        dut.close()


if __name__ == "__main__":
    main()
