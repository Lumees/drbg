// =============================================================================
// Copyright (c) 2026 Lumees Lab / Hasan Kurşun
// SPDX-License-Identifier: Apache-2.0 WITH Commons-Clause
//
// Licensed under the Apache License 2.0 with Commons Clause restriction.
// You may use this file freely for non-commercial purposes (academic,
// research, hobby, education, personal projects).
//
// COMMERCIAL USE requires a separate license from Lumees Lab.
// Contact: info@lumeeslab.com · https://lumeeslab.com
// =============================================================================
// DRBG IP — Top-level wrapper with start/busy/done flow control
// =============================================================================
// Wraps drbg_core with a simplified control interface.
// =============================================================================

`timescale 1ns/1ps

import drbg_pkg::*;

module drbg_top (
  input  logic                clk,
  input  logic                rst_n,

  // ── Control ─────────────────────────────────────────────────────────────
  input  logic                instantiate_i,
  input  logic                reseed_i,
  input  logic                generate_i,

  // ── Seed material ───────────────────────────────────────────────────────
  input  logic [255:0]        entropy_i,
  input  logic [127:0]        nonce_i,
  input  logic [127:0]        perso_i,
  input  logic [127:0]        addl_i,

  // ── Status ──────────────────────────────────────────────────────────────
  output logic                ready_o,
  output logic                busy_o,
  output logic                done_o,          // pulse when generate completes
  output logic                need_reseed_o,

  // ── Output ──────────────────────────────────────────────────────────────
  output logic [127:0]        data_o,
  output logic [47:0]         reseed_ctr_o,

  // ── Info ────────────────────────────────────────────────────────────────
  output logic [31:0]         version_o
);

  assign version_o = IP_VERSION;

  // Core signals
  logic core_valid;

  drbg_core u_core (
    .clk            (clk),
    .rst_n          (rst_n),
    .instantiate_i  (instantiate_i),
    .reseed_i       (reseed_i),
    .generate_i     (generate_i),
    .entropy_i      (entropy_i),
    .nonce_i        (nonce_i),
    .perso_i        (perso_i),
    .addl_i         (addl_i),
    .ready_o        (ready_o),
    .busy_o         (busy_o),
    .valid_o        (core_valid),
    .need_reseed_o  (need_reseed_o),
    .data_o         (data_o),
    .reseed_ctr_o   (reseed_ctr_o)
  );

  // done_o mirrors valid_o from the core
  assign done_o = core_valid;

endmodule : drbg_top
