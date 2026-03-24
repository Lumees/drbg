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
// DRBG UVM Testbench — Sequences
// =============================================================================

`ifndef DRBG_SEQUENCES_SV
`define DRBG_SEQUENCES_SV

`include "uvm_macros.svh"

// ============================================================================
// Base sequence
// ============================================================================
class drbg_base_seq extends uvm_sequence #(drbg_seq_item);

  import drbg_pkg::*;

  `uvm_object_utils(drbg_base_seq)

  uvm_analysis_port #(drbg_seq_item) ap_context;

  function new(string name = "drbg_base_seq");
    super.new(name);
  endfunction : new

  task send_fixed_item(drbg_seq_item item);
    start_item(item);
    finish_item(item);
    if (ap_context != null)
      ap_context.write(item);
  endtask : send_fixed_item

  virtual task body();
    `uvm_warning("SEQ", "drbg_base_seq::body() called — override in derived class")
  endtask : body

endclass : drbg_base_seq


// ============================================================================
// Directed sequence: instantiate + generate with known seed
// ============================================================================
class drbg_directed_seq extends drbg_base_seq;

  `uvm_object_utils(drbg_directed_seq)

  function new(string name = "drbg_directed_seq");
    super.new(name);
  endfunction : new

  virtual task body();
    drbg_seq_item item;

    // ── Instantiate ─────────────────────────────────────────────────────
    item = drbg_seq_item::type_id::create("inst_item");
    item.op      = 0;  // OP_INSTANTIATE
    item.entropy = 256'h000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f;
    item.nonce   = 128'h000102030405060708090a0b0c0d0e0f;
    item.perso   = '0;
    `uvm_info("SEQ_DIR", "Instantiating with sequential entropy", UVM_MEDIUM)
    send_fixed_item(item);

    // ── Generate 1 ──────────────────────────────────────────────────────
    item = drbg_seq_item::type_id::create("gen_item1");
    item.op         = 2;  // OP_GENERATE
    item.addl_input = '0;
    `uvm_info("SEQ_DIR", "Generate #1", UVM_MEDIUM)
    send_fixed_item(item);

    // ── Generate 2 (consecutive, should produce different output) ───────
    item = drbg_seq_item::type_id::create("gen_item2");
    item.op         = 2;  // OP_GENERATE
    item.addl_input = '0;
    `uvm_info("SEQ_DIR", "Generate #2", UVM_MEDIUM)
    send_fixed_item(item);

  endtask : body

endclass : drbg_directed_seq


// ============================================================================
// Reseed sequence: instantiate, reseed, generate
// ============================================================================
class drbg_reseed_seq extends drbg_base_seq;

  `uvm_object_utils(drbg_reseed_seq)

  function new(string name = "drbg_reseed_seq");
    super.new(name);
  endfunction : new

  virtual task body();
    drbg_seq_item item;

    // Instantiate
    item = drbg_seq_item::type_id::create("inst_item");
    item.op      = 0;
    item.entropy = 256'hAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA;
    item.nonce   = 128'hBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB;
    item.perso   = '0;
    `uvm_info("SEQ_RESEED", "Instantiating", UVM_MEDIUM)
    send_fixed_item(item);

    // Reseed
    item = drbg_seq_item::type_id::create("reseed_item");
    item.op      = 1;
    item.entropy = 256'hCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC;
    item.addl_input = '0;
    `uvm_info("SEQ_RESEED", "Reseeding", UVM_MEDIUM)
    send_fixed_item(item);

    // Generate
    item = drbg_seq_item::type_id::create("gen_item");
    item.op         = 2;
    item.addl_input = '0;
    `uvm_info("SEQ_RESEED", "Generating after reseed", UVM_MEDIUM)
    send_fixed_item(item);

  endtask : body

endclass : drbg_reseed_seq


// ============================================================================
// Random sequence
// ============================================================================
class drbg_random_seq extends drbg_base_seq;

  `uvm_object_utils(drbg_random_seq)

  int unsigned num_generates = 10;

  function new(string name = "drbg_random_seq");
    super.new(name);
  endfunction : new

  virtual task body();
    drbg_seq_item item;

    // Random instantiate
    item = drbg_seq_item::type_id::create("rand_inst");
    item.op = 0;
    start_item(item);
    if (!item.randomize() with { op == 0; })
      `uvm_fatal("SEQ_RAND", "Failed to randomise instantiate item")
    finish_item(item);
    if (ap_context != null) ap_context.write(item);

    // Random generates
    repeat (num_generates) begin
      item = drbg_seq_item::type_id::create("rand_gen");
      item.op = 2;
      start_item(item);
      if (!item.randomize() with { op == 2; })
        `uvm_fatal("SEQ_RAND", "Failed to randomise generate item")
      finish_item(item);
      if (ap_context != null) ap_context.write(item);
    end

    `uvm_info("SEQ_RAND",
      $sformatf("Completed %0d random generates", num_generates),
      UVM_MEDIUM)
  endtask : body

endclass : drbg_random_seq

`endif // DRBG_SEQUENCES_SV
