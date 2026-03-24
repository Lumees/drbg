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
// DRBG IP — Core: CTR-DRBG state machine + iterative AES-256 encryptor
// =============================================================================
// Implements CTR-DRBG per NIST SP 800-90A Rev 1 with AES-256.
//
// Internal state: Key (256 bits) + V (128 bits)
// Operations: Instantiate, Reseed, Generate
//
// The AES-256 engine is iterative (14 rounds, 1 round per clock cycle).
// Each AES encryption takes 15 cycles (1 initial + 14 rounds).
// =============================================================================

`timescale 1ns/1ps

import drbg_pkg::*;

module drbg_core (
  input  logic                clk,
  input  logic                rst_n,

  // ── Control ─────────────────────────────────────────────────────────────
  input  logic                instantiate_i,   // pulse: start instantiation
  input  logic                reseed_i,        // pulse: start reseed
  input  logic                generate_i,      // pulse: generate 128-bit output

  // ── Entropy / seed material ─────────────────────────────────────────────
  input  logic [255:0]        entropy_i,       // 256-bit entropy input
  input  logic [127:0]        nonce_i,         // 128-bit nonce (instantiate only)
  input  logic [127:0]        perso_i,         // 128-bit personalization (instantiate)
  input  logic [127:0]        addl_i,          // 128-bit additional input (generate/reseed)

  // ── Status ──────────────────────────────────────────────────────────────
  output logic                ready_o,         // DRBG ready for commands
  output logic                busy_o,          // operation in progress
  output logic                valid_o,         // output data valid (pulse)
  output logic                need_reseed_o,   // reseed counter exceeded

  // ── Output ──────────────────────────────────────────────────────────────
  output logic [127:0]        data_o,          // 128-bit generated output
  output logic [47:0]         reseed_ctr_o     // reseed counter value
);

  // ═════════════════════════════════════════════════════════════════════════
  // Internal AES-256 iterative encryptor
  // ═════════════════════════════════════════════════════════════════════════
  logic [255:0]  aes_key;
  logic [127:0]  aes_pt;
  logic          aes_start;
  logic [127:0]  aes_ct;
  logic          aes_done;

  // AES round state
  logic [127:0]  aes_state;
  logic [3:0]    aes_round;     // 0..14
  logic          aes_active;

  // On-the-fly key expansion: track two previous round-key halves
  logic [127:0]  rk_prev2, rk_prev1;  // rkeys[round-2], rkeys[round-1]
  logic [127:0]  rk_current;           // current round key for this cycle
  logic [127:0]  rk_next;              // next round key (combinational)

  // Compute next round key from the two previous halves
  assign rk_next = aes256_next_rkey(rk_prev2, rk_prev1, {28'd0, aes_round} + 1);

  // AES iterative engine with on-the-fly key expansion
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      aes_state  <= '0;
      aes_round  <= '0;
      aes_active <= 1'b0;
      aes_done   <= 1'b0;
      aes_ct     <= '0;
      rk_prev2   <= '0;
      rk_prev1   <= '0;
      rk_current <= '0;
    end else begin
      aes_done <= 1'b0;

      if (aes_start && !aes_active) begin
        // Cycle 0: Initial AddRoundKey with rkeys[0] = key[255:128]
        // Set up rk_prev2/rk_prev1 for computing rkeys[2] on next step
        aes_state  <= aes_pt ^ aes_key[255:128];
        rk_prev2   <= aes_key[255:128];  // rkeys[0]
        rk_prev1   <= aes_key[127:0];    // rkeys[1]
        rk_current <= aes_key[127:0];    // rkeys[1] used in round 1
        aes_round  <= 4'd1;
        aes_active <= 1'b1;
      end else if (aes_active) begin
        if (aes_round < 4'd14) begin
          // Rounds 1..13: full round using rk_current
          aes_state  <= enc_round(aes_state, rk_current);
          aes_round  <= aes_round + 4'd1;
          // Advance key expansion: shift window
          rk_prev2   <= rk_prev1;
          rk_prev1   <= rk_next;
          rk_current <= rk_next;
        end else begin
          // Round 14: final round using rk_current
          aes_ct     <= enc_final_round(aes_state, rk_current);
          aes_done   <= 1'b1;
          aes_active <= 1'b0;
          aes_round  <= '0;
        end
      end
    end
  end

  // ═════════════════════════════════════════════════════════════════════════
  // CTR-DRBG State Machine
  // ═════════════════════════════════════════════════════════════════════════
  typedef enum logic [3:0] {
    S_IDLE        = 4'd0,
    S_INST_BDF0   = 4'd1,   // Block_Cipher_df step 0 (simplified: use entropy directly)
    S_UPDATE_V1   = 4'd2,   // Update: encrypt V
    S_UPDATE_WAIT1= 4'd3,
    S_UPDATE_V2   = 4'd4,   // Update: encrypt V+1
    S_UPDATE_WAIT2= 4'd5,
    S_UPDATE_V3   = 4'd6,   // Update: encrypt V+2 (for seedlen=384, need 3 blocks)
    S_UPDATE_WAIT3= 4'd7,
    S_UPDATE_FIN  = 4'd8,   // Finalize update: XOR and write new Key/V
    S_GEN_ENC     = 4'd9,   // Generate: encrypt V
    S_GEN_WAIT    = 4'd10,
    S_GEN_UPD     = 4'd11,  // Generate: call Update with additional_input
    S_READY       = 4'd12
  } fsm_state_t;

  fsm_state_t     state;
  drbg_state_t    drbg;           // Current Key/V state
  logic [47:0]    reseed_ctr;
  logic [127:0]   gen_output;     // generated block

  // Update temporary storage
  logic [127:0]   upd_blk0, upd_blk1, upd_blk2;
  logic [BLK_LEN-1:0] upd_v;     // working V for update
  logic [SEEDLEN-1:0] upd_provided_data;

  // Is this a generate-update or instantiate/reseed-update?
  logic           update_for_gen;
  logic [127:0]   gen_addl_lat;   // latched additional input for generate

  assign ready_o       = (state == S_READY);
  assign busy_o        = (state != S_IDLE) && (state != S_READY);
  assign need_reseed_o = (reseed_ctr >= 48'hFFFF_FFFF_FFFF);  // 2^48-1 per NIST SP 800-90A §10.2.1
  assign reseed_ctr_o  = reseed_ctr;

  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      state            <= S_IDLE;
      drbg             <= '0;
      reseed_ctr       <= '0;
      gen_output       <= '0;
      valid_o          <= 1'b0;
      data_o           <= '0;
      aes_start        <= 1'b0;
      aes_key          <= '0;
      aes_pt           <= '0;
      upd_blk0         <= '0;
      upd_blk1         <= '0;
      upd_blk2         <= '0;
      upd_v            <= '0;
      upd_provided_data<= '0;
      update_for_gen   <= 1'b0;
      gen_addl_lat     <= '0;
    end else begin
      aes_start <= 1'b0;
      valid_o   <= 1'b0;

      unique case (state)

        // ── IDLE: not yet instantiated ──────────────────────────────────
        S_IDLE: begin
          if (instantiate_i) begin
            // seed_material = entropy || nonce || personalization_string
            // For CTR-DRBG without derivation function (simplified):
            // provided_data = entropy[255:0] || (nonce ^ perso) padded to 384 bits
            upd_provided_data <= {entropy_i, nonce_i ^ perso_i};
            // Start with Key=0, V=0
            drbg.key <= '0;
            drbg.v   <= '0;
            upd_v    <= 128'd1;  // V starts at 0, first increment = 1
            aes_key  <= '0;
            aes_pt   <= 128'd1;  // V+1 = 1 (V=0 initially)
            aes_start<= 1'b1;
            state    <= S_UPDATE_WAIT1;
          end
        end

        // ── UPDATE step 1: wait for AES(Key, V+1) ──────────────────────
        S_UPDATE_WAIT1: begin
          if (aes_done) begin
            upd_blk0  <= aes_ct;
            // V+2
            aes_pt    <= upd_v + 128'd1;
            aes_key   <= drbg.key;
            aes_start <= 1'b1;
            state     <= S_UPDATE_WAIT2;
          end
        end

        // ── UPDATE step 2: wait for AES(Key, V+2) ──────────────────────
        S_UPDATE_WAIT2: begin
          if (aes_done) begin
            upd_blk1  <= aes_ct;
            // V+3
            aes_pt    <= upd_v + 128'd2;
            aes_key   <= drbg.key;
            aes_start <= 1'b1;
            state     <= S_UPDATE_WAIT3;
          end
        end

        // ── UPDATE step 3: wait for AES(Key, V+3) ──────────────────────
        S_UPDATE_WAIT3: begin
          if (aes_done) begin
            upd_blk2 <= aes_ct;
            state    <= S_UPDATE_FIN;
          end
        end

        // ── UPDATE finalize: XOR concatenated blocks with provided_data ─
        S_UPDATE_FIN: begin
          // temp = upd_blk0 || upd_blk1 || upd_blk2 = 384 bits
          // new_key = temp[383:128] ^ provided_data[383:128]
          // new_v   = temp[127:0]   ^ provided_data[127:0]
          drbg.key <= {upd_blk0, upd_blk1} ^ upd_provided_data[383:128];
          drbg.v   <= upd_blk2 ^ upd_provided_data[127:0];

          if (update_for_gen) begin
            // After generate update, output is ready
            data_o  <= gen_output;
            valid_o <= 1'b1;
            reseed_ctr <= reseed_ctr + 48'd1;
            update_for_gen <= 1'b0;
            state   <= S_READY;
          end else begin
            // Instantiate or reseed complete
            reseed_ctr <= 48'd1;
            state      <= S_READY;
          end
        end

        // ── READY: waiting for commands ─────────────────────────────────
        S_READY: begin
          if (generate_i) begin
            gen_addl_lat <= addl_i;
            // V = V + 1
            upd_v <= drbg.v + 128'd1;
            // Encrypt the incremented V
            aes_key   <= drbg.key;
            aes_pt    <= drbg.v + 128'd1;
            aes_start <= 1'b1;
            state     <= S_GEN_WAIT;
          end else if (reseed_i) begin
            // Reseed: provided_data = entropy || additional_input (padded)
            upd_provided_data <= {entropy_i, addl_i};
            upd_v    <= drbg.v + 128'd1;
            aes_key  <= drbg.key;
            aes_pt   <= drbg.v + 128'd1;
            aes_start<= 1'b1;
            state    <= S_UPDATE_WAIT1;
          end else if (instantiate_i) begin
            // Re-instantiate
            upd_provided_data <= {entropy_i, nonce_i ^ perso_i};
            drbg.key <= '0;
            drbg.v   <= '0;
            upd_v    <= 128'd1;
            aes_key  <= '0;
            aes_pt   <= 128'd1;
            aes_start<= 1'b1;
            state    <= S_UPDATE_WAIT1;
          end
        end

        // ── GENERATE: wait for AES encrypt of V ────────────────────────
        S_GEN_WAIT: begin
          if (aes_done) begin
            gen_output <= aes_ct;
            // Now run Update(additional_input)
            // provided_data for update: pad addl_i to seedlen
            // If addl_i is zero, provided_data = 0
            upd_provided_data <= {gen_addl_lat, 256'd0};
            // Update uses the current key/V (V already incremented)
            drbg.v   <= upd_v;  // commit incremented V
            upd_v    <= upd_v + 128'd1;
            aes_key  <= drbg.key;
            aes_pt   <= upd_v + 128'd1;
            aes_start<= 1'b1;
            update_for_gen <= 1'b1;
            state    <= S_UPDATE_WAIT1;
          end
        end

        default: state <= S_IDLE;

      endcase
    end
  end

endmodule : drbg_core
