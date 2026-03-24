# =============================================================================
# Copyright (c) 2026 Lumees Lab / Hasan Kurşun
# SPDX-License-Identifier: Apache-2.0 WITH Commons-Clause
#
# Free for non-commercial use (academic, research, hobby, education).
# Commercial use requires a Lumees Lab license: info@lumeeslab.com
# =============================================================================
"""
DRBG LiteX Module
===================
Directly instantiates drbg_top.sv and wires it to LiteX CSR registers.

CSR registers:
  ctrl          [0]=instantiate [1]=reseed [2]=generate (self-clearing)
  status        [0]=ready [1]=busy [2]=need_reseed (RO)
  entropy0..7   256-bit entropy input
  nonce0..3     128-bit nonce input
  output0..3    128-bit generated output (RO)
  reseed_ctr    48-bit reseed counter (RO)
  info          [7:0]=BLK_LEN [15:8]=KEY_LEN/8 (RO)
  version       IP version (RO)
"""

from migen import *
from litex.soc.interconnect.csr import *

import os

DRBG_RTL_DIR = os.path.join(os.path.dirname(__file__), '../rtl')


class DRBG(Module, AutoCSR):
    def __init__(self, platform):
        # ── Platform sources ─────────────────────────────────────────────
        for f in ['drbg_pkg.sv', 'drbg_core.sv', 'drbg_top.sv']:
            platform.add_source(os.path.join(DRBG_RTL_DIR, f))

        # ── CSR registers (RW) ───────────────────────────────────────────
        self.ctrl     = CSRStorage(8,  name="ctrl",
                                   description="[0]=instantiate [1]=reseed [2]=generate")
        self.entropy0 = CSRStorage(32, name="entropy0", description="Entropy[31:0]")
        self.entropy1 = CSRStorage(32, name="entropy1", description="Entropy[63:32]")
        self.entropy2 = CSRStorage(32, name="entropy2", description="Entropy[95:64]")
        self.entropy3 = CSRStorage(32, name="entropy3", description="Entropy[127:96]")
        self.entropy4 = CSRStorage(32, name="entropy4", description="Entropy[159:128]")
        self.entropy5 = CSRStorage(32, name="entropy5", description="Entropy[191:160]")
        self.entropy6 = CSRStorage(32, name="entropy6", description="Entropy[223:192]")
        self.entropy7 = CSRStorage(32, name="entropy7", description="Entropy[255:224]")
        self.nonce0   = CSRStorage(32, name="nonce0", description="Nonce[31:0]")
        self.nonce1   = CSRStorage(32, name="nonce1", description="Nonce[63:32]")
        self.nonce2   = CSRStorage(32, name="nonce2", description="Nonce[95:64]")
        self.nonce3   = CSRStorage(32, name="nonce3", description="Nonce[127:96]")

        # ── CSR registers (RO) ───────────────────────────────────────────
        self.status   = CSRStatus(8,  name="status",
                                  description="[0]=ready [1]=busy [2]=need_reseed")
        self.output0  = CSRStatus(32, name="output0", description="Output[31:0]")
        self.output1  = CSRStatus(32, name="output1", description="Output[63:32]")
        self.output2  = CSRStatus(32, name="output2", description="Output[95:64]")
        self.output3  = CSRStatus(32, name="output3", description="Output[127:96]")
        self.reseed_ctr = CSRStatus(32, name="reseed_ctr",
                                    description="Reseed counter [31:0]")
        self.info     = CSRStatus(32, name="info",
                                  description="[7:0]=BLK_LEN [15:8]=KEY_LEN/8")
        self.version  = CSRStatus(32, name="version", description="IP version")

        # ── Constant outputs ─────────────────────────────────────────────
        self.comb += self.info.status.eq((32 << 8) | 128)

        # ── Core signals ─────────────────────────────────────────────────
        instantiate_pulse = Signal()
        reseed_pulse      = Signal()
        generate_pulse    = Signal()
        ready_sig         = Signal()
        busy_sig          = Signal()
        done_sig          = Signal()
        need_reseed_sig   = Signal()
        data_out          = Signal(128)
        reseed_ctr_sig    = Signal(48)
        version_sig       = Signal(32)

        # Entropy and nonce packed
        entropy_sig = Signal(256)
        nonce_sig   = Signal(128)

        self.comb += [
            entropy_sig.eq(Cat(
                self.entropy0.storage, self.entropy1.storage,
                self.entropy2.storage, self.entropy3.storage,
                self.entropy4.storage, self.entropy5.storage,
                self.entropy6.storage, self.entropy7.storage,
            )),
            nonce_sig.eq(Cat(
                self.nonce0.storage, self.nonce1.storage,
                self.nonce2.storage, self.nonce3.storage,
            )),
        ]

        # Control pulses
        self.comb += [
            instantiate_pulse.eq(self.ctrl.re & self.ctrl.storage[0]),
            reseed_pulse.eq(self.ctrl.re & self.ctrl.storage[1]),
            generate_pulse.eq(self.ctrl.re & self.ctrl.storage[2]),
        ]

        # Status
        self.comb += [
            self.status.status[0].eq(ready_sig),
            self.status.status[1].eq(busy_sig),
            self.status.status[2].eq(need_reseed_sig),
        ]

        # Latch output on done
        out_latched = Signal(128)
        self.sync += If(done_sig, out_latched.eq(data_out))
        self.comb += [
            self.output0.status.eq(out_latched[0:32]),
            self.output1.status.eq(out_latched[32:64]),
            self.output2.status.eq(out_latched[64:96]),
            self.output3.status.eq(out_latched[96:128]),
        ]

        self.comb += self.reseed_ctr.status.eq(reseed_ctr_sig[:32])

        # IRQ on done
        self.irq = Signal()
        done_prev = Signal()
        self.sync += done_prev.eq(done_sig)
        self.comb += self.irq.eq(done_sig & ~done_prev)

        # Tie-off unused wide inputs
        perso_zero = Signal(128, reset=0)
        addl_zero  = Signal(128, reset=0)

        # ── DRBG top instance ────────────────────────────────────────────
        self.specials += Instance("drbg_top",
            i_clk            = ClockSignal(),
            i_rst_n          = ~ResetSignal(),
            i_instantiate_i  = instantiate_pulse,
            i_reseed_i       = reseed_pulse,
            i_generate_i     = generate_pulse,
            i_entropy_i      = entropy_sig,
            i_nonce_i        = nonce_sig,
            i_perso_i        = perso_zero,
            i_addl_i         = addl_zero,
            o_ready_o        = ready_sig,
            o_busy_o         = busy_sig,
            o_done_o         = done_sig,
            o_need_reseed_o  = need_reseed_sig,
            o_data_o         = data_out,
            o_reseed_ctr_o   = reseed_ctr_sig,
            o_version_o      = version_sig,
        )

        self.comb += self.version.status.eq(version_sig)
