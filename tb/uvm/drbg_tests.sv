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
// DRBG UVM Testbench — Tests
// =============================================================================
// Test hierarchy:
//
//   drbg_base_test      — builds env, prints topology
//     drbg_directed_test — known-seed instantiate + generate
//     drbg_reseed_test   — instantiate + reseed + generate
//     drbg_random_test   — random instantiate + N random generates
// =============================================================================

`ifndef DRBG_TESTS_SV
`define DRBG_TESTS_SV

`include "uvm_macros.svh"

// ============================================================================
// Base test
// ============================================================================
class drbg_base_test extends uvm_test;

  import drbg_pkg::*;

  `uvm_component_utils(drbg_base_test)

  drbg_env env;

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction : new

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
    env = drbg_env::type_id::create("env", this);
  endfunction : build_phase

  function void start_of_simulation_phase(uvm_phase phase);
    `uvm_info("TEST", "=== DRBG UVM Testbench ===", UVM_NONE)
    `uvm_info("TEST", "UVM component topology:", UVM_MEDIUM)
    uvm_top.print_topology();
  endfunction : start_of_simulation_phase

  function void connect_seq_context(drbg_base_seq seq);
    seq.ap_context = env.ap_context;
  endfunction : connect_seq_context

  virtual task run_phase(uvm_phase phase);
    `uvm_warning("TEST", "drbg_base_test::run_phase — no sequences run")
  endtask : run_phase

  function void report_phase(uvm_phase phase);
    uvm_report_server svr;
    svr = uvm_report_server::get_server();
    if (svr.get_severity_count(UVM_FATAL) + svr.get_severity_count(UVM_ERROR) > 0)
      `uvm_info("TEST", "*** TEST FAILED ***", UVM_NONE)
    else
      `uvm_info("TEST", "*** TEST PASSED ***", UVM_NONE)
  endfunction : report_phase

endclass : drbg_base_test


// ============================================================================
// Directed test
// ============================================================================
class drbg_directed_test extends drbg_base_test;

  `uvm_component_utils(drbg_directed_test)

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction : new

  virtual task run_phase(uvm_phase phase);
    drbg_directed_seq dir_seq;

    phase.raise_objection(this, "drbg_directed_test started");

    dir_seq = drbg_directed_seq::type_id::create("dir_seq");
    connect_seq_context(dir_seq);

    `uvm_info("DIR_TEST", "Running directed DRBG sequences", UVM_MEDIUM)
    dir_seq.start(env.agent.sequencer);

    #5000ns;
    phase.drop_objection(this, "drbg_directed_test complete");
  endtask : run_phase

endclass : drbg_directed_test


// ============================================================================
// Reseed test
// ============================================================================
class drbg_reseed_test extends drbg_base_test;

  `uvm_component_utils(drbg_reseed_test)

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction : new

  virtual task run_phase(uvm_phase phase);
    drbg_reseed_seq reseed_seq;

    phase.raise_objection(this, "drbg_reseed_test started");

    reseed_seq = drbg_reseed_seq::type_id::create("reseed_seq");
    connect_seq_context(reseed_seq);

    `uvm_info("RESEED_TEST", "Running reseed DRBG sequence", UVM_MEDIUM)
    reseed_seq.start(env.agent.sequencer);

    #5000ns;
    phase.drop_objection(this, "drbg_reseed_test complete");
  endtask : run_phase

endclass : drbg_reseed_test


// ============================================================================
// Random test
// ============================================================================
class drbg_random_test extends drbg_base_test;

  `uvm_component_utils(drbg_random_test)

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction : new

  virtual task run_phase(uvm_phase phase);
    drbg_random_seq rand_seq;

    phase.raise_objection(this, "drbg_random_test started");

    rand_seq = drbg_random_seq::type_id::create("rand_seq");
    connect_seq_context(rand_seq);
    rand_seq.num_generates = 20;

    `uvm_info("RAND_TEST", "Running 20 random DRBG generates", UVM_MEDIUM)
    rand_seq.start(env.agent.sequencer);

    #10000ns;
    phase.drop_objection(this, "drbg_random_test complete");
  endtask : run_phase

endclass : drbg_random_test

`endif // DRBG_TESTS_SV
