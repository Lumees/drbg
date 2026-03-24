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
// DRBG UVM Testbench — Sequence Item
// =============================================================================
// Represents one DRBG operation (instantiate, reseed, or generate).
// =============================================================================

`ifndef DRBG_SEQ_ITEM_SV
`define DRBG_SEQ_ITEM_SV

`include "uvm_macros.svh"

class drbg_seq_item extends uvm_sequence_item;

  import drbg_pkg::*;

  `uvm_object_utils_begin(drbg_seq_item)
    `uvm_field_int (op,           UVM_ALL_ON | UVM_DEC)
    `uvm_field_int (entropy,      UVM_ALL_ON | UVM_HEX)
    `uvm_field_int (nonce,        UVM_ALL_ON | UVM_HEX)
    `uvm_field_int (perso,        UVM_ALL_ON | UVM_HEX)
    `uvm_field_int (addl_input,   UVM_ALL_ON | UVM_HEX)
    `uvm_field_int (expected_out, UVM_ALL_ON | UVM_HEX)
    `uvm_field_int (actual_out,   UVM_ALL_ON | UVM_HEX)
  `uvm_object_utils_end

  // ── Operation type ────────────────────────────────────────────────────
  typedef enum int {
    OP_INSTANTIATE = 0,
    OP_RESEED      = 1,
    OP_GENERATE    = 2
  } op_t;

  // ── Stimulus fields ───────────────────────────────────────────────────
  rand int                   op;
  rand logic [KEY_LEN-1:0]   entropy;
  rand logic [BLK_LEN-1:0]   nonce;
  rand logic [BLK_LEN-1:0]   perso;
  rand logic [BLK_LEN-1:0]   addl_input;

  // ── Response fields ───────────────────────────────────────────────────
  logic [BLK_LEN-1:0]        expected_out;
  logic [BLK_LEN-1:0]        actual_out;

  // ── Constraints ───────────────────────────────────────────────────────
  constraint c_op {
    op inside {0, 1, 2};
  }

  // ── Constructor ───────────────────────────────────────────────────────
  function new(string name = "drbg_seq_item");
    super.new(name);
  endfunction : new

  // Short printable summary
  function string convert2string();
    string op_name;
    case (op)
      0: op_name = "INST";
      1: op_name = "RESEED";
      2: op_name = "GEN";
      default: op_name = "???";
    endcase
    return $sformatf("DRBG | op=%s | entropy=%h | nonce=%h | exp=%h act=%h",
      op_name, entropy, nonce, expected_out, actual_out);
  endfunction : convert2string

endclass : drbg_seq_item

`endif // DRBG_SEQ_ITEM_SV
