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
// DRBG UVM Testbench — Driver
// =============================================================================

`ifndef DRBG_DRIVER_SV
`define DRBG_DRIVER_SV

`include "uvm_macros.svh"

class drbg_driver extends uvm_driver #(drbg_seq_item);

  import drbg_pkg::*;

  `uvm_component_utils(drbg_driver)

  virtual drbg_if vif;
  localparam int TIMEOUT = 10000;

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction : new

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
    if (!uvm_config_db #(virtual drbg_if)::get(this, "", "vif", vif))
      `uvm_fatal("NOVIF", "drbg_driver: cannot get virtual interface")
  endfunction : build_phase

  task run_phase(uvm_phase phase);
    drbg_seq_item req, rsp;

    // Initialize outputs
    vif.driver_cb.instantiate_i <= 1'b0;
    vif.driver_cb.reseed_i      <= 1'b0;
    vif.driver_cb.generate_i    <= 1'b0;
    vif.driver_cb.entropy_i     <= '0;
    vif.driver_cb.nonce_i       <= '0;
    vif.driver_cb.perso_i       <= '0;
    vif.driver_cb.addl_i        <= '0;

    @(posedge vif.clk);
    wait (vif.rst_n === 1'b1);
    @(posedge vif.clk);

    forever begin
      seq_item_port.get_next_item(req);
      `uvm_info("DRV", $sformatf("Driving: %s", req.convert2string()), UVM_HIGH)

      rsp = drbg_seq_item::type_id::create("rsp");
      rsp.copy(req);

      case (req.op)
        0: drive_instantiate(req, rsp);  // OP_INSTANTIATE
        1: drive_reseed(req, rsp);       // OP_RESEED
        2: drive_generate(req, rsp);     // OP_GENERATE
      endcase

      seq_item_port.item_done(rsp);
    end
  endtask : run_phase

  task drive_instantiate(drbg_seq_item req, drbg_seq_item rsp);
    @(vif.driver_cb);
    vif.driver_cb.entropy_i     <= req.entropy;
    vif.driver_cb.nonce_i       <= req.nonce;
    vif.driver_cb.perso_i       <= req.perso;
    vif.driver_cb.instantiate_i <= 1'b1;
    @(vif.driver_cb);
    vif.driver_cb.instantiate_i <= 1'b0;

    // Wait for ready
    wait_ready();
    `uvm_info("DRV", "Instantiate complete", UVM_HIGH)
  endtask : drive_instantiate

  task drive_reseed(drbg_seq_item req, drbg_seq_item rsp);
    @(vif.driver_cb);
    vif.driver_cb.entropy_i <= req.entropy;
    vif.driver_cb.addl_i    <= req.addl_input;
    vif.driver_cb.reseed_i  <= 1'b1;
    @(vif.driver_cb);
    vif.driver_cb.reseed_i  <= 1'b0;

    wait_ready();
    `uvm_info("DRV", "Reseed complete", UVM_HIGH)
  endtask : drive_reseed

  task drive_generate(drbg_seq_item req, drbg_seq_item rsp);
    @(vif.driver_cb);
    vif.driver_cb.addl_i     <= req.addl_input;
    vif.driver_cb.generate_i <= 1'b1;
    @(vif.driver_cb);
    vif.driver_cb.generate_i <= 1'b0;

    // Wait for done
    wait_done();
    rsp.actual_out = vif.driver_cb.data_o;

    // Wait for ready
    wait_ready();
    `uvm_info("DRV", $sformatf("Generate output: %h", rsp.actual_out), UVM_HIGH)
  endtask : drive_generate

  task wait_ready();
    int cnt = 0;
    while (!vif.driver_cb.ready_o) begin
      @(vif.driver_cb);
      cnt++;
      if (cnt >= TIMEOUT)
        `uvm_fatal("DRV_TIMEOUT", "ready_o never asserted")
    end
  endtask : wait_ready

  task wait_done();
    int cnt = 0;
    @(vif.driver_cb);
    while (!vif.driver_cb.done_o) begin
      @(vif.driver_cb);
      cnt++;
      if (cnt >= TIMEOUT)
        `uvm_fatal("DRV_TIMEOUT", "done_o never asserted")
    end
  endtask : wait_done

endclass : drbg_driver

`endif // DRBG_DRIVER_SV
