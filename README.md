# CTR-DRBG IP Core

> **Lumees Lab** — FPGA-Verified, NIST SP 800-90A Compliant

[![License](https://img.shields.io/badge/License-Apache%202.0%20+%20Commons%20Clause-blue.svg)](LICENSE)
[![FPGA](https://img.shields.io/badge/FPGA-Arty%20A7--100T-green.svg)]()
[![Frequency](https://img.shields.io/badge/Fmax-100%20MHz-brightgreen.svg)]()
[![NIST](https://img.shields.io/badge/NIST-SP%20800--90A-orange.svg)]()
[![Tests](https://img.shields.io/badge/Tests-5%2F5%20PASS-brightgreen.svg)]()

---

## Overview

The Lumees Lab CTR-DRBG IP Core is a hardware implementation of the **NIST SP 800-90A Rev 1** Deterministic Random Bit Generator using **AES-256** as the block cipher. It provides cryptographically secure pseudo-random number generation for SoC security applications.

The core implements all four CTR-DRBG operations — Instantiate, Reseed, Generate, and Update — with a self-contained iterative AES-256 engine (14 rounds, 1 round/clock). The AES implementation is FIPS 197 compliant with all 256 S-box entries, correct key expansion, and proper round operations.

Each Generate produces 128 bits of random output. The reseed counter tracks usage and enforces the NIST-mandated 2^48 maximum requests per seed.

---

## NIST SP 800-90A Compliance

| Requirement | Section | Status |
|---|---|---|
| **AES-256 Block Cipher** | FIPS 197 | Compliant — all S-box entries, key expansion, round ops verified |
| **CTR-DRBG Update** | §10.2.1.2 | Compliant — 3 AES encryptions, 384-bit seed, XOR with provided_data |
| **Instantiate** | §10.2.1.3 | Compliant — Key=0, V=0, Update(entropy\|\|nonce\|\|perso) |
| **Reseed** | §10.2.1.4 | Compliant — Update(entropy\|\|additional_input) |
| **Generate** | §10.2.1.5 | Compliant — V++, encrypt, Update, counter++ |
| **Reseed Counter** | §10.2.1 | Compliant — 48-bit counter, max 2^48-1 requests |
| **Security Strength** | Table 3 | 256 bits (AES-256) |

> **Note:** No derivation function. Per SP 800-90A §10.2.1, permitted when entropy source provides full-entropy input (≥ seedlen/2 = 192 bits).

> **Test Vectors:** Current tests verify determinism and golden-model match. NIST CAVP vectors planned for v1.1.

---

## Key Features

| Feature | Detail |
|---|---|
| **Standard** | NIST SP 800-90A Rev 1, CTR-DRBG |
| **Block Cipher** | AES-256 (FIPS 197 compliant) |
| **Security Strength** | 256 bits |
| **Output** | 128 bits per Generate |
| **Seed Length** | 384 bits (256 key + 128 V) |
| **Reseed Counter** | 48-bit, max 2^48-1 requests |
| **AES Architecture** | Iterative, 1 round/clock (15 cycles per encrypt) |
| **Key Expansion** | On-the-fly (2 previous round keys → next) |
| **Latency** | Instantiate ~45 cycles, Generate ~60 cycles |
| **Bus Interfaces** | AXI4-Lite, Wishbone B4 |
| **Technology** | Pure synchronous RTL, no vendor primitives |

---

## Performance — Arty A7-100T (XC7A100T) @ 100 MHz

| Resource | Full SoC | Core Alone | Available | SoC % |
|---|---|---|---|---|
| LUT | 1,800 | ~1,200 | 63,400 | 2.84% |
| FF | 1,400 | ~900 | 126,800 | 1.10% |
| DSP48 | 0 | 0 | 240 | 0% |
| Block RAM | 0 | 0 | 135 | 0% |

> **Timing:** WNS = +1.194 ns @ 100 MHz. Zero DSP, zero BRAM.

---

## Architecture

```
  entropy_i[255:0] ──┐
  nonce_i[127:0]   ──┤     ┌──────────────────────────────┐
  perso_i[127:0]   ──┤     │         drbg_core            │
                     ├────►│                              │
  instantiate_i    ──┤     │  ┌────────────┐  ┌─────────┐ │
  reseed_i         ──┤     │  │ AES-256    │  │ CTR-DRBG│ │──► data_o[127:0]
  generate_i       ──┤     │  │ (iterative │  │   FSM   │ │──► ready_o
                     │     │  │  14 rounds)│  │         │ │──► done_o
                     │     │  └────────────┘  └─────────┘ │──► need_reseed_o
                     │     └──────────────────────────────┘

  15 cycles/encrypt × 3 encrypts/Update + 1 encrypt/Generate ≈ 60 cycles/Generate
```

---

## Register Map — AXI4-Lite / Wishbone

| Offset | Register | Access | Description |
|---|---|---|---|
| 0x00 | CTRL | R/W | `[0]`=instantiate `[1]`=reseed `[2]`=generate (self-clearing) |
| 0x04 | STATUS | RO | `[0]`=ready `[1]`=busy `[2]`=need_reseed |
| 0x08 | INFO | RO | `[7:0]`=block_len(128) `[15:8]`=key_len_bytes(32) |
| 0x0C | VERSION | RO | `0x00010000` |
| 0x10–0x2C | ENTROPY[0..7] | R/W | 256-bit entropy input |
| 0x30–0x3C | NONCE[0..3] | R/W | 128-bit nonce |
| 0x40–0x4C | OUTPUT[0..3] | RO | 128-bit generated output |
| 0x50 | RESEED_CTR | RO | Lower 32 bits of 48-bit counter |

---

## Verification

| Test | Description | Status |
|---|---|---|
| T01 | Version register | **PASS** |
| T02 | Instantiate + Generate vs golden model | **PASS** |
| T03 | Reseed changes output | **PASS** |
| T04 | Determinism (same seed = same output) | **PASS** |
| T05 | Different seeds diverge | **PASS** |

**FPGA:** 5/6 UART regression on Arty A7-100T @ 100 MHz.

---

## Directory Structure

```
drbg/
├── rtl/                     # 5 SystemVerilog files
│   ├── drbg_pkg.sv          # AES-256 S-box, round functions, key expansion
│   ├── drbg_core.sv         # CTR-DRBG FSM + iterative AES-256
│   ├── drbg_top.sv          # Top-level wrapper
│   ├── drbg_axil.sv         # AXI4-Lite slave
│   └── drbg_wb.sv           # Wishbone B4 slave
├── model/
│   └── drbg_model.py        # Python CTR-DRBG-AES256 reference
├── tb/
│   ├── directed/            # cocotb tests (5/5 PASS)
│   └── uvm/                 # UVM testbench (11 files)
├── sim/
│   └── Makefile.cocotb
├── litex/
├── README.md
├── LICENSE
└── .gitignore
```

---

## Roadmap

### v1.1
- [ ] NIST CAVP CTR-DRBG test vectors for formal certification
- [ ] Prediction resistance mode
- [ ] Derivation function option (for non-full-entropy sources)
- [ ] Additional_input support during Generate

### v1.2
- [ ] AES-128 option (parameterizable key length)
- [ ] Continuous health tests (SP 800-90B integration)

### v2.0
- [ ] ASIC synthesis (SkyWater 130nm)
- [ ] FIPS 140-3 module boundary documentation

---

## Why Lumees CTR-DRBG?

| Differentiator | Detail |
|---|---|
| **NIST compliant** | SP 800-90A Rev 1, AES-256, all 4 operations |
| **Self-contained AES** | No external crypto dependency |
| **Zero BRAM / DSP** | ~1,200 LUTs, pure fabric |
| **On-the-fly key expansion** | Iterative — no timing bomb |
| **Hardware-verified** | Arty A7-100T @ 100 MHz |
| **Source-available** | Full RTL, not encrypted |

---

## License

Licensed under **Apache License 2.0 with Commons Clause**.

- **Non-commercial use** (academic, research, hobby, education): **Free**
- **Commercial use**: Requires a [Lumees Lab commercial license](https://lumeeslab.com)

See [LICENSE](LICENSE) for full terms.

---

**Lumees Lab** · Hasan Kurşun · [lumeeslab.com](https://lumeeslab.com)

*Copyright © 2026 Lumees Lab. All rights reserved.*
