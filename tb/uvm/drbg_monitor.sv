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
// DRBG UVM Testbench — Monitor
// =============================================================================

`ifndef DRBG_MONITOR_SV
`define DRBG_MONITOR_SV

`include "uvm_macros.svh"

class drbg_monitor extends uvm_monitor;

  import drbg_pkg::*;

  `uvm_component_utils(drbg_monitor)

  uvm_analysis_port #(drbg_seq_item) ap_in;
  uvm_analysis_port #(drbg_seq_item) ap_out;

  virtual drbg_if vif;

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction : new

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
    ap_in  = new("ap_in",  this);
    ap_out = new("ap_out", this);

    if (!uvm_config_db #(virtual drbg_if)::get(this, "", "vif", vif))
      `uvm_fatal("NOVIF", "drbg_monitor: cannot get virtual interface")
  endfunction : build_phase

  task run_phase(uvm_phase phase);
    fork
      monitor_input();
      monitor_output();
    join
  endtask : run_phase

  task monitor_input();
    drbg_seq_item item;
    forever begin
      @(vif.monitor_cb);
      if (vif.monitor_cb.instantiate_i === 1'b1) begin
        item = drbg_seq_item::type_id::create("mon_in_inst");
        item.op      = 0;  // OP_INSTANTIATE
        item.entropy = vif.monitor_cb.entropy_i;
        item.nonce   = vif.monitor_cb.nonce_i;
        item.perso   = vif.monitor_cb.perso_i;
        `uvm_info("MON_IN", $sformatf("Instantiate: entropy=%h", item.entropy), UVM_HIGH)
        ap_in.write(item);
      end else if (vif.monitor_cb.reseed_i === 1'b1) begin
        item = drbg_seq_item::type_id::create("mon_in_reseed");
        item.op        = 1;  // OP_RESEED
        item.entropy   = vif.monitor_cb.entropy_i;
        item.addl_input = vif.monitor_cb.addl_i;
        `uvm_info("MON_IN", $sformatf("Reseed: entropy=%h", item.entropy), UVM_HIGH)
        ap_in.write(item);
      end else if (vif.monitor_cb.generate_i === 1'b1) begin
        item = drbg_seq_item::type_id::create("mon_in_gen");
        item.op        = 2;  // OP_GENERATE
        item.addl_input = vif.monitor_cb.addl_i;
        `uvm_info("MON_IN", "Generate requested", UVM_HIGH)
        ap_in.write(item);
      end
    end
  endtask : monitor_input

  task monitor_output();
    drbg_seq_item item;
    forever begin
      @(vif.monitor_cb);
      if (vif.monitor_cb.done_o === 1'b1) begin
        item = drbg_seq_item::type_id::create("mon_out_item");
        item.actual_out = vif.monitor_cb.data_o;
        `uvm_info("MON_OUT", $sformatf("Output: data=%h", item.actual_out), UVM_HIGH)
        ap_out.write(item);
      end
    end
  endtask : monitor_output

endclass : drbg_monitor

`endif // DRBG_MONITOR_SV
