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
// DRBG UVM Testbench — Top-level Module
// =============================================================================
// Instantiates:
//   - drbg_top DUT
//   - Clock generator (10 ns period = 100 MHz)
//   - Reset sequence (active-low, deassert after 10 cycles)
//   - drbg_if virtual interface
//   - UVM config_db registration
//   - run_test() kick-off
//
// Simulation plusargs:
//   +UVM_TESTNAME=<test>   (e.g., drbg_directed_test, drbg_random_test)
// =============================================================================

`timescale 1ns/1ps

`include "uvm_macros.svh"

import uvm_pkg::*;
import drbg_pkg::*;

// Include all testbench files in order of dependency
`include "drbg_seq_item.sv"
`include "drbg_if.sv"
`include "drbg_driver.sv"
`include "drbg_monitor.sv"
`include "drbg_scoreboard.sv"
`include "drbg_coverage.sv"
`include "drbg_agent.sv"
`include "drbg_env.sv"
`include "drbg_sequences.sv"
`include "drbg_tests.sv"

module drbg_tb_top;

  // ---------------------------------------------------------------------------
  // Clock and reset
  // ---------------------------------------------------------------------------
  logic clk;
  logic rst_n;

  // 10 ns period -> 100 MHz
  initial clk = 1'b0;
  always #5ns clk = ~clk;

  // Reset: assert for 10 cycles, then release
  initial begin
    rst_n = 1'b0;
    repeat (10) @(posedge clk);
    @(negedge clk);
    rst_n = 1'b1;
    `uvm_info("TB_TOP", "Reset deasserted", UVM_MEDIUM)
  end

  // ---------------------------------------------------------------------------
  // Virtual interface instantiation
  // ---------------------------------------------------------------------------
  drbg_if dut_if (.clk(clk), .rst_n(rst_n));

  // ---------------------------------------------------------------------------
  // DUT instantiation
  // ---------------------------------------------------------------------------
  drbg_top dut (
    .clk            (clk),
    .rst_n          (rst_n),
    .instantiate_i  (dut_if.instantiate_i),
    .reseed_i       (dut_if.reseed_i),
    .generate_i     (dut_if.generate_i),
    .entropy_i      (dut_if.entropy_i),
    .nonce_i        (dut_if.nonce_i),
    .perso_i        (dut_if.perso_i),
    .addl_i         (dut_if.addl_i),
    .ready_o        (dut_if.ready_o),
    .busy_o         (dut_if.busy_o),
    .done_o         (dut_if.done_o),
    .need_reseed_o  (dut_if.need_reseed_o),
    .data_o         (dut_if.data_o),
    .reseed_ctr_o   (dut_if.reseed_ctr_o),
    .version_o      (dut_if.version_o)
  );

  // ---------------------------------------------------------------------------
  // UVM config_db: register virtual interface
  // ---------------------------------------------------------------------------
  initial begin
    uvm_config_db #(virtual drbg_if)::set(
      null,
      "uvm_test_top.*",
      "vif",
      dut_if
    );

    `uvm_info("TB_TOP",
      "DRBG DUT instantiated, vif registered in config_db",
      UVM_MEDIUM)
  end

  // ---------------------------------------------------------------------------
  // Simulation timeout watchdog
  // ---------------------------------------------------------------------------
  initial begin
    #10ms;
    `uvm_fatal("WATCHDOG", "Simulation timeout — check for protocol deadlock")
  end

  // ---------------------------------------------------------------------------
  // Start UVM test
  // ---------------------------------------------------------------------------
  initial begin
    run_test();
  end

endmodule : drbg_tb_top
