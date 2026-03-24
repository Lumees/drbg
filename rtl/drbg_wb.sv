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
// DRBG IP — Wishbone B4 Classic Interface Wrapper
// =============================================================================
// Same register map as drbg_axil.sv.
//
//  Offset  Name          Access  Description
//  0x00    CTRL          W       [0]=instantiate [1]=reseed [2]=generate
//  0x04    STATUS        RO      [0]=ready [1]=busy [2]=need_reseed
//  0x08    INFO          RO      [7:0]=BLK_LEN(128) [15:8]=KEY_LEN/8(32)
//  0x0C    VERSION       RO      IP_VERSION
//  0x10-0x2C ENTROPY[0..7] RW    256-bit entropy
//  0x30-0x3C NONCE[0..3]   RW    128-bit nonce
//  0x40-0x4C OUTPUT[0..3]  RO    128-bit output
//  0x50    RESEED_CTR    RO      Reseed counter [31:0]
//  0x54    RESEED_CTR_HI RO      Reseed counter [47:32]
// =============================================================================

`timescale 1ns/1ps

import drbg_pkg::*;

module drbg_wb (
  // Wishbone system
  input  logic        CLK_I,
  input  logic        RST_I,

  // Wishbone slave
  input  logic [31:0] ADR_I,
  input  logic [31:0] DAT_I,
  output logic [31:0] DAT_O,
  input  logic        WE_I,
  input  logic [3:0]  SEL_I,
  input  logic        STB_I,
  input  logic        CYC_I,
  output logic        ACK_O,
  output logic        ERR_O,
  output logic        RTY_O,

  // Interrupt
  output logic        irq
);

  assign ERR_O = 1'b0;
  assign RTY_O = 1'b0;

  // ── Configuration registers ───────────────────────────────────────────
  logic [255:0] reg_entropy;
  logic [127:0] reg_nonce;

  // ── Core signals ──────────────────────────────────────────────────────
  logic          top_instantiate, top_reseed, top_generate;
  logic          top_ready, top_busy, top_done, top_need_reseed;
  logic [127:0]  top_data;
  logic [47:0]   top_reseed_ctr;
  logic [31:0]   top_version;

  drbg_top u_drbg (
    .clk            (CLK_I),
    .rst_n          (~RST_I),
    .instantiate_i  (top_instantiate),
    .reseed_i       (top_reseed),
    .generate_i     (top_generate),
    .entropy_i      (reg_entropy),
    .nonce_i        (reg_nonce),
    .perso_i        (128'd0),
    .addl_i         (128'd0),
    .ready_o        (top_ready),
    .busy_o         (top_busy),
    .done_o         (top_done),
    .need_reseed_o  (top_need_reseed),
    .data_o         (top_data),
    .reseed_ctr_o   (top_reseed_ctr),
    .version_o      (top_version)
  );

  // ── Latch output on done ──────────────────────────────────────────────
  logic [127:0] out_latched;
  always_ff @(posedge CLK_I) begin
    if (RST_I)
      out_latched <= '0;
    else if (top_done)
      out_latched <= top_data;
  end

  // ── IRQ: pulse on done rising edge ────────────────────────────────────
  logic done_prev;
  always_ff @(posedge CLK_I) begin
    if (RST_I) done_prev <= 1'b0;
    else       done_prev <= top_done;
  end
  assign irq = top_done & ~done_prev;

  // ── Bus logic ─────────────────────────────────────────────────────────
  always_ff @(posedge CLK_I) begin
    if (RST_I) begin
      ACK_O            <= 1'b0;
      DAT_O            <= '0;
      reg_entropy      <= '0;
      reg_nonce        <= '0;
      top_instantiate  <= 1'b0;
      top_reseed       <= 1'b0;
      top_generate     <= 1'b0;
    end else begin
      ACK_O           <= 1'b0;
      top_instantiate <= 1'b0;
      top_reseed      <= 1'b0;
      top_generate    <= 1'b0;

      if (CYC_I && STB_I && !ACK_O) begin
        ACK_O <= 1'b1;

        if (WE_I) begin
          unique case (ADR_I[7:2])
            6'h00: begin  // CTRL
              if (DAT_I[0]) top_instantiate <= 1'b1;
              if (DAT_I[1]) top_reseed      <= 1'b1;
              if (DAT_I[2]) top_generate    <= 1'b1;
            end
            6'h04: reg_entropy[ 31:  0] <= DAT_I;
            6'h05: reg_entropy[ 63: 32] <= DAT_I;
            6'h06: reg_entropy[ 95: 64] <= DAT_I;
            6'h07: reg_entropy[127: 96] <= DAT_I;
            6'h08: reg_entropy[159:128] <= DAT_I;
            6'h09: reg_entropy[191:160] <= DAT_I;
            6'h0A: reg_entropy[223:192] <= DAT_I;
            6'h0B: reg_entropy[255:224] <= DAT_I;
            6'h0C: reg_nonce[ 31:  0] <= DAT_I;
            6'h0D: reg_nonce[ 63: 32] <= DAT_I;
            6'h0E: reg_nonce[ 95: 64] <= DAT_I;
            6'h0F: reg_nonce[127: 96] <= DAT_I;
            default: ;
          endcase
        end else begin
          unique case (ADR_I[7:2])
            6'h00: DAT_O <= 32'h0;
            6'h01: DAT_O <= {29'd0, top_need_reseed, top_busy, top_ready};
            6'h02: DAT_O <= {16'd0, 8'd32, 8'd128};
            6'h03: DAT_O <= top_version;
            6'h04: DAT_O <= reg_entropy[ 31:  0];
            6'h05: DAT_O <= reg_entropy[ 63: 32];
            6'h06: DAT_O <= reg_entropy[ 95: 64];
            6'h07: DAT_O <= reg_entropy[127: 96];
            6'h08: DAT_O <= reg_entropy[159:128];
            6'h09: DAT_O <= reg_entropy[191:160];
            6'h0A: DAT_O <= reg_entropy[223:192];
            6'h0B: DAT_O <= reg_entropy[255:224];
            6'h0C: DAT_O <= reg_nonce[ 31:  0];
            6'h0D: DAT_O <= reg_nonce[ 63: 32];
            6'h0E: DAT_O <= reg_nonce[ 95: 64];
            6'h0F: DAT_O <= reg_nonce[127: 96];
            6'h10: DAT_O <= out_latched[ 31:  0];
            6'h11: DAT_O <= out_latched[ 63: 32];
            6'h12: DAT_O <= out_latched[ 95: 64];
            6'h13: DAT_O <= out_latched[127: 96];
            6'h14: DAT_O <= top_reseed_ctr[31:0];
            6'h15: DAT_O <= {16'd0, top_reseed_ctr[47:32]};
            default: DAT_O <= 32'hDEAD_BEEF;
          endcase
        end
      end
    end
  end

endmodule : drbg_wb
