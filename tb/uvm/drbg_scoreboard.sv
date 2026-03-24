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
// DRBG UVM Testbench — Scoreboard
// =============================================================================
// Receives context items from sequences and output items from the monitor.
// Since the DRBG reference model requires stateful tracking (Key/V state),
// this scoreboard uses a simplified comparison approach: it checks that
// outputs are non-zero and match the expected values provided by the sequence.
// =============================================================================

`ifndef DRBG_SCOREBOARD_SV
`define DRBG_SCOREBOARD_SV

`include "uvm_macros.svh"

class drbg_scoreboard extends uvm_scoreboard;

  import drbg_pkg::*;

  `uvm_component_utils(drbg_scoreboard)

  uvm_tlm_analysis_fifo #(drbg_seq_item) fifo_in;
  uvm_tlm_analysis_fifo #(drbg_seq_item) fifo_out;
  uvm_tlm_analysis_fifo #(drbg_seq_item) fifo_context;

  uvm_analysis_export #(drbg_seq_item) ae_in;
  uvm_analysis_export #(drbg_seq_item) ae_out;
  uvm_analysis_export #(drbg_seq_item) ae_context;

  int unsigned pass_count;
  int unsigned fail_count;

  function new(string name, uvm_component parent);
    super.new(name, parent);
    pass_count = 0;
    fail_count = 0;
  endfunction : new

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
    fifo_in      = new("fifo_in",      this);
    fifo_out     = new("fifo_out",     this);
    fifo_context = new("fifo_context", this);
    ae_in        = new("ae_in",        this);
    ae_out       = new("ae_out",       this);
    ae_context   = new("ae_context",   this);
  endfunction : build_phase

  function void connect_phase(uvm_phase phase);
    ae_in.connect      (fifo_in.analysis_export);
    ae_out.connect     (fifo_out.analysis_export);
    ae_context.connect (fifo_context.analysis_export);
  endfunction : connect_phase

  task run_phase(uvm_phase phase);
    drbg_seq_item stim_item, resp_item, ctx_item;

    forever begin
      fifo_out.get(resp_item);
      fifo_context.get(ctx_item);

      // Only check generate operations (they produce output)
      if (ctx_item.op == 2) begin
        if (ctx_item.expected_out !== '0) begin
          // Expected output was provided by the sequence
          if (resp_item.actual_out === ctx_item.expected_out) begin
            pass_count++;
            `uvm_info("SB_PASS",
              $sformatf("PASS | exp=%h | got=%h",
                ctx_item.expected_out, resp_item.actual_out),
              UVM_MEDIUM)
          end else begin
            fail_count++;
            `uvm_error("SB_FAIL",
              $sformatf("FAIL | exp=%h | got=%h",
                ctx_item.expected_out, resp_item.actual_out))
          end
        end else begin
          // No expected value — just verify output is non-zero
          if (resp_item.actual_out !== '0) begin
            pass_count++;
            `uvm_info("SB_PASS",
              $sformatf("PASS (non-zero) | got=%h", resp_item.actual_out),
              UVM_MEDIUM)
          end else begin
            fail_count++;
            `uvm_error("SB_FAIL",
              $sformatf("FAIL | output is all zeros"))
          end
        end
      end

      // Drain matching input item
      if (fifo_in.try_get(stim_item))
        ;  // consumed
    end
  endtask : run_phase

  function void check_phase(uvm_phase phase);
    super.check_phase(phase);
    `uvm_info("SB_SUMMARY",
      $sformatf("Scoreboard results: PASS=%0d  FAIL=%0d", pass_count, fail_count),
      UVM_NONE)

    if (fail_count > 0)
      `uvm_error("SB_SUMMARY",
        $sformatf("%0d transaction(s) FAILED", fail_count))
  endfunction : check_phase

endclass : drbg_scoreboard

`endif // DRBG_SCOREBOARD_SV
