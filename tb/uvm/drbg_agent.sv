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
// DRBG UVM Testbench — Agent
// =============================================================================

`ifndef DRBG_AGENT_SV
`define DRBG_AGENT_SV

`include "uvm_macros.svh"

class drbg_agent extends uvm_agent;

  import drbg_pkg::*;

  `uvm_component_utils(drbg_agent)

  drbg_driver                     driver;
  drbg_monitor                    monitor;
  uvm_sequencer #(drbg_seq_item)  sequencer;

  virtual drbg_if vif;

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction : new

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);

    if (!uvm_config_db #(virtual drbg_if)::get(this, "", "vif", vif))
      `uvm_fatal("NOVIF", "drbg_agent: cannot get virtual interface")

    monitor = drbg_monitor::type_id::create("monitor", this);

    if (get_is_active() == UVM_ACTIVE) begin
      driver    = drbg_driver::type_id::create("driver",    this);
      sequencer = uvm_sequencer #(drbg_seq_item)::type_id::create("sequencer", this);
    end
  endfunction : build_phase

  function void connect_phase(uvm_phase phase);
    uvm_config_db #(virtual drbg_if)::set(this, "driver",  "vif", vif);
    uvm_config_db #(virtual drbg_if)::set(this, "monitor", "vif", vif);

    if (get_is_active() == UVM_ACTIVE) begin
      driver.seq_item_port.connect(sequencer.seq_item_export);
    end
  endfunction : connect_phase

  function void start_of_simulation_phase(uvm_phase phase);
    `uvm_info("AGENT",
      $sformatf("drbg_agent is %s",
        (get_is_active() == UVM_ACTIVE) ? "ACTIVE" : "PASSIVE"),
      UVM_MEDIUM)
  endfunction : start_of_simulation_phase

endclass : drbg_agent

`endif // DRBG_AGENT_SV
