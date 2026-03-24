# =============================================================================
# Copyright (c) 2026 Lumees Lab / Hasan Kurşun
# SPDX-License-Identifier: Apache-2.0 WITH Commons-Clause
#
# Free for non-commercial use (academic, research, hobby, education).
# Commercial use requires a Lumees Lab license: info@lumeeslab.com
# =============================================================================
"""
DRBG IP — Directed cocotb tests for drbg_top
==============================================
CTR-DRBG with AES-256 per NIST SP 800-90A Rev 1.
"""

import os
import sys
import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, ClockCycles, Timer

# Add model to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../model'))
from drbg_model import CTR_DRBG_AES256


async def reset_dut(dut):
    """Assert reset for 10 cycles, then release."""
    dut.rst_n.value = 0
    dut.instantiate_i.value = 0
    dut.reseed_i.value = 0
    dut.generate_i.value = 0
    dut.entropy_i.value = 0
    dut.nonce_i.value = 0
    dut.perso_i.value = 0
    dut.addl_i.value = 0
    await ClockCycles(dut.clk, 10)
    dut.rst_n.value = 1
    await ClockCycles(dut.clk, 2)


def bytes_to_int(b: bytes) -> int:
    """Convert bytes (big-endian) to integer."""
    return int.from_bytes(b, 'big')


def int_to_bytes(val: int, length: int) -> bytes:
    """Convert integer to bytes (big-endian)."""
    return val.to_bytes(length, 'big')


async def wait_ready(dut, timeout=5000):
    """Wait for ready_o to assert."""
    for _ in range(timeout):
        await RisingEdge(dut.clk)
        if dut.ready_o.value == 1:
            return True
    return False


async def wait_done(dut, timeout=5000):
    """Wait for done_o pulse."""
    for _ in range(timeout):
        await RisingEdge(dut.clk)
        if dut.done_o.value == 1:
            return True
    return False


async def do_instantiate(dut, entropy_int, nonce_int, perso_int=0):
    """Trigger instantiation and wait for ready."""
    dut.entropy_i.value = entropy_int
    dut.nonce_i.value = nonce_int
    dut.perso_i.value = perso_int
    await RisingEdge(dut.clk)
    dut.instantiate_i.value = 1
    await RisingEdge(dut.clk)
    dut.instantiate_i.value = 0
    ok = await wait_ready(dut)
    assert ok, "Instantiate timed out waiting for ready"


async def do_generate(dut, addl_int=0):
    """Trigger generate and return 128-bit output."""
    dut.addl_i.value = addl_int
    await RisingEdge(dut.clk)
    dut.generate_i.value = 1
    await RisingEdge(dut.clk)
    dut.generate_i.value = 0
    ok = await wait_done(dut)
    assert ok, "Generate timed out waiting for done"
    output = int(dut.data_o.value) & ((1 << 128) - 1)
    # Wait for ready before returning
    await wait_ready(dut)
    return output


async def do_reseed(dut, entropy_int, addl_int=0):
    """Trigger reseed and wait for ready."""
    dut.entropy_i.value = entropy_int
    dut.addl_i.value = addl_int
    await RisingEdge(dut.clk)
    dut.reseed_i.value = 1
    await RisingEdge(dut.clk)
    dut.reseed_i.value = 0
    ok = await wait_ready(dut)
    assert ok, "Reseed timed out waiting for ready"


# ── Tests ────────────────────────────────────────────────────────────────────

@cocotb.test()
async def test_version(dut):
    """T01: Version register reads 0x00010000."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    ver = int(dut.version_o.value)
    dut._log.info(f"[T01] VERSION = 0x{ver:08X}")
    assert ver == 0x00010000, f"Version mismatch: 0x{ver:08X}"


@cocotb.test()
async def test_instantiate_generate(dut):
    """T02: Instantiate with known seed, generate matches Python model."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    entropy = bytes(range(32))
    nonce = bytes(range(16))

    entropy_int = bytes_to_int(entropy)
    nonce_int = bytes_to_int(nonce)

    # Python golden model
    model = CTR_DRBG_AES256()
    model.instantiate(entropy, nonce)
    expected_bytes = model.generate(128)
    expected = bytes_to_int(expected_bytes)

    # DUT
    await do_instantiate(dut, entropy_int, nonce_int)
    got = await do_generate(dut)

    dut._log.info(f"[T02] Expected: 0x{expected:032X}")
    dut._log.info(f"[T02] Got:      0x{got:032X}")
    assert got == expected, f"Generate mismatch: 0x{got:032X} != 0x{expected:032X}"


@cocotb.test()
async def test_reseed(dut):
    """T03: Reseed changes the DRBG state; output matches model after reseed."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    entropy1 = bytes(range(32))
    nonce = bytes(range(16))
    entropy2 = bytes([x ^ 0xFF for x in range(32)])

    # Python model
    model = CTR_DRBG_AES256()
    model.instantiate(entropy1, nonce)
    model.reseed(entropy2)
    expected_bytes = model.generate(128)
    expected = bytes_to_int(expected_bytes)

    # DUT
    await do_instantiate(dut, bytes_to_int(entropy1), bytes_to_int(nonce))
    await do_reseed(dut, bytes_to_int(entropy2))
    got = await do_generate(dut)

    dut._log.info(f"[T03] After reseed expected: 0x{expected:032X}")
    dut._log.info(f"[T03] After reseed got:      0x{got:032X}")
    assert got == expected, f"Reseed mismatch: 0x{got:032X} != 0x{expected:032X}"


@cocotb.test()
async def test_determinism(dut):
    """T04: Same seed produces same output (determinism)."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    entropy = bytes([0xAA] * 32)
    nonce = bytes([0xBB] * 16)
    entropy_int = bytes_to_int(entropy)
    nonce_int = bytes_to_int(nonce)

    # First instantiation + generate
    await do_instantiate(dut, entropy_int, nonce_int)
    out1 = await do_generate(dut)

    # Reset and repeat with same seed
    await reset_dut(dut)
    await do_instantiate(dut, entropy_int, nonce_int)
    out2 = await do_generate(dut)

    dut._log.info(f"[T04] Run 1: 0x{out1:032X}")
    dut._log.info(f"[T04] Run 2: 0x{out2:032X}")
    assert out1 == out2, f"Determinism failed: 0x{out1:032X} != 0x{out2:032X}"


@cocotb.test()
async def test_different_seeds_diverge(dut):
    """T05: Different seeds produce different outputs."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    entropy1 = bytes(range(32))
    entropy2 = bytes([x ^ 0xFF for x in range(32)])
    nonce = bytes(range(16))

    # First seed
    await do_instantiate(dut, bytes_to_int(entropy1), bytes_to_int(nonce))
    out1 = await do_generate(dut)

    # Reset with different seed
    await reset_dut(dut)
    await do_instantiate(dut, bytes_to_int(entropy2), bytes_to_int(nonce))
    out2 = await do_generate(dut)

    dut._log.info(f"[T05] Seed 1: 0x{out1:032X}")
    dut._log.info(f"[T05] Seed 2: 0x{out2:032X}")
    assert out1 != out2, f"Different seeds should produce different outputs!"
