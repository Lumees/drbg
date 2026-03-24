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
// DRBG UVM Testbench — Virtual Interface
// =============================================================================

`timescale 1ns/1ps

interface drbg_if (input logic clk, input logic rst_n);

  import drbg_pkg::*;

  // ── DUT ports ─────────────────────────────────────────────────────────
  logic                instantiate_i;
  logic                reseed_i;
  logic                generate_i;
  logic [KEY_LEN-1:0]  entropy_i;
  logic [BLK_LEN-1:0]  nonce_i;
  logic [BLK_LEN-1:0]  perso_i;
  logic [BLK_LEN-1:0]  addl_i;
  logic                ready_o;
  logic                busy_o;
  logic                done_o;
  logic                need_reseed_o;
  logic [BLK_LEN-1:0]  data_o;
  logic [47:0]         reseed_ctr_o;
  logic [31:0]         version_o;

  // ── Driver clocking block ─────────────────────────────────────────────
  clocking driver_cb @(posedge clk);
    default input  #1step
            output #1step;

    output instantiate_i;
    output reseed_i;
    output generate_i;
    output entropy_i;
    output nonce_i;
    output perso_i;
    output addl_i;
    input  ready_o;
    input  busy_o;
    input  done_o;
    input  need_reseed_o;
    input  data_o;
    input  reseed_ctr_o;
    input  version_o;
  endclocking : driver_cb

  // ── Monitor clocking block ────────────────────────────────────────────
  clocking monitor_cb @(posedge clk);
    default input #1step;

    input instantiate_i;
    input reseed_i;
    input generate_i;
    input entropy_i;
    input nonce_i;
    input perso_i;
    input addl_i;
    input ready_o;
    input busy_o;
    input done_o;
    input need_reseed_o;
    input data_o;
    input reseed_ctr_o;
    input version_o;
  endclocking : monitor_cb

  // ── Modports ──────────────────────────────────────────────────────────
  modport driver_mp  (clocking driver_cb,  input clk, input rst_n);
  modport monitor_mp (clocking monitor_cb, input clk, input rst_n);

endinterface : drbg_if
