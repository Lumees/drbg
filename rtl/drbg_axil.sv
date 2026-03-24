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
// DRBG IP — AXI4-Lite Interface Wrapper
// =============================================================================
// Register map (32-bit word address, 4-byte aligned):
//
//  Offset  Name          Access  Description
//  0x00    CTRL          R/W     [0]=instantiate [1]=reseed [2]=generate (self-clearing)
//  0x04    STATUS        RO      [0]=ready [1]=busy [2]=need_reseed
//  0x08    INFO          RO      [7:0]=BLK_LEN(128) [15:8]=KEY_LEN/8(32)
//  0x0C    VERSION       RO      IP_VERSION
//  0x10    ENTROPY[0]    R/W     Entropy bits [31:0]
//  0x14    ENTROPY[1]    R/W     Entropy bits [63:32]
//  0x18    ENTROPY[2]    R/W     Entropy bits [95:64]
//  0x1C    ENTROPY[3]    R/W     Entropy bits [127:96]
//  0x20    ENTROPY[4]    R/W     Entropy bits [159:128]
//  0x24    ENTROPY[5]    R/W     Entropy bits [191:160]
//  0x28    ENTROPY[6]    R/W     Entropy bits [223:192]
//  0x2C    ENTROPY[7]    R/W     Entropy bits [255:224]
//  0x30    NONCE[0]      R/W     Nonce bits [31:0]
//  0x34    NONCE[1]      R/W     Nonce bits [63:32]
//  0x38    NONCE[2]      R/W     Nonce bits [95:64]
//  0x3C    NONCE[3]      R/W     Nonce bits [127:96]
//  0x40    OUTPUT[0]     RO      Output bits [31:0]
//  0x44    OUTPUT[1]     RO      Output bits [63:32]
//  0x48    OUTPUT[2]     RO      Output bits [95:64]
//  0x4C    OUTPUT[3]     RO      Output bits [127:96]
//  0x50    RESEED_CTR    RO      Reseed counter [31:0] (lower 32 bits)
//  0x54    RESEED_CTR_HI RO      Reseed counter [47:32]
//
// irq: single-cycle output pulse when done transitions 0→1.
// =============================================================================

`timescale 1ns/1ps

import drbg_pkg::*;

module drbg_axil (
  input  logic        clk,
  input  logic        rst_n,

  // AXI4-Lite Slave
  input  logic [31:0] s_axil_awaddr,
  input  logic        s_axil_awvalid,
  output logic        s_axil_awready,
  input  logic [31:0] s_axil_wdata,
  input  logic [3:0]  s_axil_wstrb,
  input  logic        s_axil_wvalid,
  output logic        s_axil_wready,
  output logic [1:0]  s_axil_bresp,
  output logic        s_axil_bvalid,
  input  logic        s_axil_bready,
  input  logic [31:0] s_axil_araddr,
  input  logic        s_axil_arvalid,
  output logic        s_axil_arready,
  output logic [31:0] s_axil_rdata,
  output logic [1:0]  s_axil_rresp,
  output logic        s_axil_rvalid,
  input  logic        s_axil_rready,

  // Interrupt — single-cycle pulse when done
  output logic        irq
);

  // ── Internal registers ──────────────────────────────────────────────────
  logic [255:0]  reg_entropy;
  logic [127:0]  reg_nonce;

  // ── Core instance ───────────────────────────────────────────────────────
  logic          core_instantiate;
  logic          core_reseed;
  logic          core_generate;
  logic          core_ready;
  logic          core_busy;
  logic          core_done;
  logic          core_need_reseed;
  logic [127:0]  core_data;
  logic [47:0]   core_reseed_ctr;
  logic [31:0]   core_version;

  drbg_top u_drbg (
    .clk            (clk),
    .rst_n          (rst_n),
    .instantiate_i  (core_instantiate),
    .reseed_i       (core_reseed),
    .generate_i     (core_generate),
    .entropy_i      (reg_entropy),
    .nonce_i        (reg_nonce),
    .perso_i        (128'd0),        // personalization via nonce regs
    .addl_i         (128'd0),        // additional input not used via regs
    .ready_o        (core_ready),
    .busy_o         (core_busy),
    .done_o         (core_done),
    .need_reseed_o  (core_need_reseed),
    .data_o         (core_data),
    .reseed_ctr_o   (core_reseed_ctr),
    .version_o      (core_version)
  );

  // ── Latch output on done ────────────────────────────────────────────────
  logic [127:0] reg_output;
  logic         reg_done;

  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      reg_output <= '0;
      reg_done   <= 1'b0;
    end else begin
      if (core_done) begin
        reg_output <= core_data;
        reg_done   <= 1'b1;
      end
      // Clear done when a new command is issued
      if (core_instantiate || core_reseed || core_generate)
        reg_done <= 1'b0;
    end
  end

  // ── IRQ: pulse on done ────────────────────────────────────────────────
  logic done_prev;
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      done_prev <= 1'b0;
      irq       <= 1'b0;
    end else begin
      done_prev <= core_done;
      irq       <= core_done & ~done_prev;
    end
  end

  // ── AXI4-Lite write path ──────────────────────────────────────────────
  logic [7:0]  wr_addr;
  logic [31:0] wdata_lat;
  logic        aw_active, w_active;

  assign s_axil_awready = !aw_active;
  assign s_axil_wready  = !w_active;
  assign s_axil_bresp   = 2'b00;

  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      aw_active        <= 1'b0;
      w_active         <= 1'b0;
      wr_addr          <= '0;
      wdata_lat        <= '0;
      s_axil_bvalid    <= 1'b0;
      reg_entropy      <= '0;
      reg_nonce        <= '0;
      core_instantiate <= 1'b0;
      core_reseed      <= 1'b0;
      core_generate    <= 1'b0;
    end else begin
      // AXI4-Lite write handshake
      if (s_axil_awvalid && s_axil_awready) begin
        wr_addr   <= s_axil_awaddr[9:2];
        aw_active <= 1'b1;
      end
      if (s_axil_wvalid && s_axil_wready) begin
        wdata_lat <= s_axil_wdata;
        w_active  <= 1'b1;
      end
      if (s_axil_bvalid && s_axil_bready)
        s_axil_bvalid <= 1'b0;

      // Default: deassert command pulses
      core_instantiate <= 1'b0;
      core_reseed      <= 1'b0;
      core_generate    <= 1'b0;

      // Process write
      if (aw_active && w_active) begin
        aw_active     <= 1'b0;
        w_active      <= 1'b0;
        s_axil_bvalid <= 1'b1;

        unique case (wr_addr)
          // CTRL (0x00)
          8'h00: begin
            if (wdata_lat[0]) core_instantiate <= 1'b1;
            if (wdata_lat[1]) core_reseed      <= 1'b1;
            if (wdata_lat[2]) core_generate    <= 1'b1;
          end
          // ENTROPY[0..7] (0x10..0x2C -> word 0x04..0x0B)
          8'h04: reg_entropy[ 31:  0] <= wdata_lat;
          8'h05: reg_entropy[ 63: 32] <= wdata_lat;
          8'h06: reg_entropy[ 95: 64] <= wdata_lat;
          8'h07: reg_entropy[127: 96] <= wdata_lat;
          8'h08: reg_entropy[159:128] <= wdata_lat;
          8'h09: reg_entropy[191:160] <= wdata_lat;
          8'h0A: reg_entropy[223:192] <= wdata_lat;
          8'h0B: reg_entropy[255:224] <= wdata_lat;
          // NONCE[0..3] (0x30..0x3C -> word 0x0C..0x0F)
          8'h0C: reg_nonce[ 31:  0] <= wdata_lat;
          8'h0D: reg_nonce[ 63: 32] <= wdata_lat;
          8'h0E: reg_nonce[ 95: 64] <= wdata_lat;
          8'h0F: reg_nonce[127: 96] <= wdata_lat;
          default: ;
        endcase
      end
    end
  end

  // ── AXI4-Lite read path ───────────────────────────────────────────────
  assign s_axil_rresp = 2'b00;

  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      s_axil_arready <= 1'b1;
      s_axil_rvalid  <= 1'b0;
      s_axil_rdata   <= '0;
    end else begin
      if (s_axil_arvalid && s_axil_arready) begin
        s_axil_arready <= 1'b0;
        s_axil_rvalid  <= 1'b1;
        unique case (s_axil_araddr[9:2])
          8'h00: s_axil_rdata <= 32'h0;  // CTRL (write-only commands)
          8'h01: s_axil_rdata <= {29'd0, core_need_reseed, core_busy, core_ready};
          8'h02: s_axil_rdata <= {16'd0, 8'd32, 8'd128};  // INFO: KEY_LEN/8, BLK_LEN
          8'h03: s_axil_rdata <= core_version;
          // ENTROPY readback
          8'h04: s_axil_rdata <= reg_entropy[ 31:  0];
          8'h05: s_axil_rdata <= reg_entropy[ 63: 32];
          8'h06: s_axil_rdata <= reg_entropy[ 95: 64];
          8'h07: s_axil_rdata <= reg_entropy[127: 96];
          8'h08: s_axil_rdata <= reg_entropy[159:128];
          8'h09: s_axil_rdata <= reg_entropy[191:160];
          8'h0A: s_axil_rdata <= reg_entropy[223:192];
          8'h0B: s_axil_rdata <= reg_entropy[255:224];
          // NONCE readback
          8'h0C: s_axil_rdata <= reg_nonce[ 31:  0];
          8'h0D: s_axil_rdata <= reg_nonce[ 63: 32];
          8'h0E: s_axil_rdata <= reg_nonce[ 95: 64];
          8'h0F: s_axil_rdata <= reg_nonce[127: 96];
          // OUTPUT (0x40..0x4C -> word 0x10..0x13)
          8'h10: s_axil_rdata <= reg_output[ 31:  0];
          8'h11: s_axil_rdata <= reg_output[ 63: 32];
          8'h12: s_axil_rdata <= reg_output[ 95: 64];
          8'h13: s_axil_rdata <= reg_output[127: 96];
          // RESEED_CTR (0x50 -> word 0x14)
          8'h14: s_axil_rdata <= core_reseed_ctr[31:0];
          8'h15: s_axil_rdata <= {16'd0, core_reseed_ctr[47:32]};
          default: s_axil_rdata <= 32'hDEAD_BEEF;
        endcase
      end
      if (s_axil_rvalid && s_axil_rready) begin
        s_axil_rvalid  <= 1'b0;
        s_axil_arready <= 1'b1;
      end
    end
  end

endmodule : drbg_axil
