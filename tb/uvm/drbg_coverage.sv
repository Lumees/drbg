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
// DRBG UVM Testbench — Functional Coverage Collector
// =============================================================================

`ifndef DRBG_COVERAGE_SV
`define DRBG_COVERAGE_SV

`include "uvm_macros.svh"

class drbg_coverage extends uvm_subscriber #(drbg_seq_item);

  import drbg_pkg::*;

  `uvm_component_utils(drbg_coverage)

  int          cov_op;
  int unsigned cov_entropy_pattern;   // 0=all_zero, 1=all_one, 2=other
  int unsigned cov_nonce_pattern;

  covergroup cg_drbg;
    option.per_instance = 1;
    option.name         = "cg_drbg";
    option.comment      = "DRBG operation and seed coverage";

    cp_op: coverpoint cov_op {
      bins instantiate = {0};
      bins reseed      = {1};
      bins generate    = {2};
    }

    cp_entropy: coverpoint cov_entropy_pattern {
      bins all_zero = {0};
      bins all_one  = {1};
      bins other    = {2};
    }

    cp_nonce: coverpoint cov_nonce_pattern {
      bins all_zero = {0};
      bins all_one  = {1};
      bins other    = {2};
    }

    cx_op_entropy: cross cp_op, cp_entropy;
  endgroup : cg_drbg

  function new(string name, uvm_component parent);
    super.new(name, parent);
    cg_drbg = new();
  endfunction : new

  function void write(drbg_seq_item t);
    cov_op = t.op;

    if (t.entropy === '0)
      cov_entropy_pattern = 0;
    else if (t.entropy === {KEY_LEN{1'b1}})
      cov_entropy_pattern = 1;
    else
      cov_entropy_pattern = 2;

    if (t.nonce === '0)
      cov_nonce_pattern = 0;
    else if (t.nonce === {BLK_LEN{1'b1}})
      cov_nonce_pattern = 1;
    else
      cov_nonce_pattern = 2;

    cg_drbg.sample();

    `uvm_info("COV",
      $sformatf("Sampled: op=%0d entropy_pat=%0d nonce_pat=%0d",
        cov_op, cov_entropy_pattern, cov_nonce_pattern),
      UVM_DEBUG)
  endfunction : write

  function void report_phase(uvm_phase phase);
    `uvm_info("COV_REPORT",
      $sformatf("cg_drbg coverage: %.2f%%", cg_drbg.get_coverage()),
      UVM_NONE)
  endfunction : report_phase

endclass : drbg_coverage

`endif // DRBG_COVERAGE_SV
