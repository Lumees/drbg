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
// DRBG IP — Package: types, parameters, AES-256 primitives
// =============================================================================
// CTR-DRBG per NIST SP 800-90A Rev 1 using AES-256 as the block cipher.
// Self-contained AES-256 encrypt primitives (no external AES IP dependency).
// =============================================================================

`timescale 1ns/1ps

package drbg_pkg;

  // ── Parameters ─────────────────────────────────────────────────────────────
  localparam int KEY_LEN       = 256;          // AES-256 key bits
  localparam int BLK_LEN       = 128;          // AES block bits
  localparam int SEEDLEN       = KEY_LEN + BLK_LEN; // 384 bits
  localparam int N_ROUNDS      = 14;           // AES-256 rounds
  localparam int MAX_REQ_BITS  = 48;           // reseed counter width
  localparam int IP_VERSION    = 32'h0001_0000;

  // ── DRBG state type ────────────────────────────────────────────────────────
  typedef struct packed {
    logic [KEY_LEN-1:0] key;
    logic [BLK_LEN-1:0] v;
  } drbg_state_t;

  // ── AES state type: 4x4 byte matrix [row][col] ────────────────────────────
  typedef logic [0:3][0:3][7:0] aes_state_t;

  // ── AES Forward S-box (FIPS 197) ──────────────────────────────────────────
  function automatic logic [7:0] sbox_fwd(input logic [7:0] x);
    logic [7:0] lut [0:255];
    lut[  0]=8'h63; lut[  1]=8'h7c; lut[  2]=8'h77; lut[  3]=8'h7b;
    lut[  4]=8'hf2; lut[  5]=8'h6b; lut[  6]=8'h6f; lut[  7]=8'hc5;
    lut[  8]=8'h30; lut[  9]=8'h01; lut[ 10]=8'h67; lut[ 11]=8'h2b;
    lut[ 12]=8'hfe; lut[ 13]=8'hd7; lut[ 14]=8'hab; lut[ 15]=8'h76;
    lut[ 16]=8'hca; lut[ 17]=8'h82; lut[ 18]=8'hc9; lut[ 19]=8'h7d;
    lut[ 20]=8'hfa; lut[ 21]=8'h59; lut[ 22]=8'h47; lut[ 23]=8'hf0;
    lut[ 24]=8'had; lut[ 25]=8'hd4; lut[ 26]=8'ha2; lut[ 27]=8'haf;
    lut[ 28]=8'h9c; lut[ 29]=8'ha4; lut[ 30]=8'h72; lut[ 31]=8'hc0;
    lut[ 32]=8'hb7; lut[ 33]=8'hfd; lut[ 34]=8'h93; lut[ 35]=8'h26;
    lut[ 36]=8'h36; lut[ 37]=8'h3f; lut[ 38]=8'hf7; lut[ 39]=8'hcc;
    lut[ 40]=8'h34; lut[ 41]=8'ha5; lut[ 42]=8'he5; lut[ 43]=8'hf1;
    lut[ 44]=8'h71; lut[ 45]=8'hd8; lut[ 46]=8'h31; lut[ 47]=8'h15;
    lut[ 48]=8'h04; lut[ 49]=8'hc7; lut[ 50]=8'h23; lut[ 51]=8'hc3;
    lut[ 52]=8'h18; lut[ 53]=8'h96; lut[ 54]=8'h05; lut[ 55]=8'h9a;
    lut[ 56]=8'h07; lut[ 57]=8'h12; lut[ 58]=8'h80; lut[ 59]=8'he2;
    lut[ 60]=8'heb; lut[ 61]=8'h27; lut[ 62]=8'hb2; lut[ 63]=8'h75;
    lut[ 64]=8'h09; lut[ 65]=8'h83; lut[ 66]=8'h2c; lut[ 67]=8'h1a;
    lut[ 68]=8'h1b; lut[ 69]=8'h6e; lut[ 70]=8'h5a; lut[ 71]=8'ha0;
    lut[ 72]=8'h52; lut[ 73]=8'h3b; lut[ 74]=8'hd6; lut[ 75]=8'hb3;
    lut[ 76]=8'h29; lut[ 77]=8'he3; lut[ 78]=8'h2f; lut[ 79]=8'h84;
    lut[ 80]=8'h53; lut[ 81]=8'hd1; lut[ 82]=8'h00; lut[ 83]=8'hed;
    lut[ 84]=8'h20; lut[ 85]=8'hfc; lut[ 86]=8'hb1; lut[ 87]=8'h5b;
    lut[ 88]=8'h6a; lut[ 89]=8'hcb; lut[ 90]=8'hbe; lut[ 91]=8'h39;
    lut[ 92]=8'h4a; lut[ 93]=8'h4c; lut[ 94]=8'h58; lut[ 95]=8'hcf;
    lut[ 96]=8'hd0; lut[ 97]=8'hef; lut[ 98]=8'haa; lut[ 99]=8'hfb;
    lut[100]=8'h43; lut[101]=8'h4d; lut[102]=8'h33; lut[103]=8'h85;
    lut[104]=8'h45; lut[105]=8'hf9; lut[106]=8'h02; lut[107]=8'h7f;
    lut[108]=8'h50; lut[109]=8'h3c; lut[110]=8'h9f; lut[111]=8'ha8;
    lut[112]=8'h51; lut[113]=8'ha3; lut[114]=8'h40; lut[115]=8'h8f;
    lut[116]=8'h92; lut[117]=8'h9d; lut[118]=8'h38; lut[119]=8'hf5;
    lut[120]=8'hbc; lut[121]=8'hb6; lut[122]=8'hda; lut[123]=8'h21;
    lut[124]=8'h10; lut[125]=8'hff; lut[126]=8'hf3; lut[127]=8'hd2;
    lut[128]=8'hcd; lut[129]=8'h0c; lut[130]=8'h13; lut[131]=8'hec;
    lut[132]=8'h5f; lut[133]=8'h97; lut[134]=8'h44; lut[135]=8'h17;
    lut[136]=8'hc4; lut[137]=8'ha7; lut[138]=8'h7e; lut[139]=8'h3d;
    lut[140]=8'h64; lut[141]=8'h5d; lut[142]=8'h19; lut[143]=8'h73;
    lut[144]=8'h60; lut[145]=8'h81; lut[146]=8'h4f; lut[147]=8'hdc;
    lut[148]=8'h22; lut[149]=8'h2a; lut[150]=8'h90; lut[151]=8'h88;
    lut[152]=8'h46; lut[153]=8'hee; lut[154]=8'hb8; lut[155]=8'h14;
    lut[156]=8'hde; lut[157]=8'h5e; lut[158]=8'h0b; lut[159]=8'hdb;
    lut[160]=8'he0; lut[161]=8'h32; lut[162]=8'h3a; lut[163]=8'h0a;
    lut[164]=8'h49; lut[165]=8'h06; lut[166]=8'h24; lut[167]=8'h5c;
    lut[168]=8'hc2; lut[169]=8'hd3; lut[170]=8'hac; lut[171]=8'h62;
    lut[172]=8'h91; lut[173]=8'h95; lut[174]=8'he4; lut[175]=8'h79;
    lut[176]=8'he7; lut[177]=8'hc8; lut[178]=8'h37; lut[179]=8'h6d;
    lut[180]=8'h8d; lut[181]=8'hd5; lut[182]=8'h4e; lut[183]=8'ha9;
    lut[184]=8'h6c; lut[185]=8'h56; lut[186]=8'hf4; lut[187]=8'hea;
    lut[188]=8'h65; lut[189]=8'h7a; lut[190]=8'hae; lut[191]=8'h08;
    lut[192]=8'hba; lut[193]=8'h78; lut[194]=8'h25; lut[195]=8'h2e;
    lut[196]=8'h1c; lut[197]=8'ha6; lut[198]=8'hb4; lut[199]=8'hc6;
    lut[200]=8'he8; lut[201]=8'hdd; lut[202]=8'h74; lut[203]=8'h1f;
    lut[204]=8'h4b; lut[205]=8'hbd; lut[206]=8'h8b; lut[207]=8'h8a;
    lut[208]=8'h70; lut[209]=8'h3e; lut[210]=8'hb5; lut[211]=8'h66;
    lut[212]=8'h48; lut[213]=8'h03; lut[214]=8'hf6; lut[215]=8'h0e;
    lut[216]=8'h61; lut[217]=8'h35; lut[218]=8'h57; lut[219]=8'hb9;
    lut[220]=8'h86; lut[221]=8'hc1; lut[222]=8'h1d; lut[223]=8'h9e;
    lut[224]=8'he1; lut[225]=8'hf8; lut[226]=8'h98; lut[227]=8'h11;
    lut[228]=8'h69; lut[229]=8'hd9; lut[230]=8'h8e; lut[231]=8'h94;
    lut[232]=8'h9b; lut[233]=8'h1e; lut[234]=8'h87; lut[235]=8'he9;
    lut[236]=8'hce; lut[237]=8'h55; lut[238]=8'h28; lut[239]=8'hdf;
    lut[240]=8'h8c; lut[241]=8'ha1; lut[242]=8'h89; lut[243]=8'h0d;
    lut[244]=8'hbf; lut[245]=8'he6; lut[246]=8'h42; lut[247]=8'h68;
    lut[248]=8'h41; lut[249]=8'h99; lut[250]=8'h2d; lut[251]=8'h0f;
    lut[252]=8'hb0; lut[253]=8'h54; lut[254]=8'hbb; lut[255]=8'h16;
    return lut[x];
  endfunction

  // ── GF(2^8) arithmetic ────────────────────────────────────────────────────
  function automatic logic [7:0] xtime(input logic [7:0] b);
    return {b[6:0], 1'b0} ^ (b[7] ? 8'h1b : 8'h00);
  endfunction

  function automatic logic [7:0] gmul(input logic [7:0] b, input logic [7:0] m);
    logic [7:0] result, p;
    result = 8'h00;
    p = b;
    for (int i = 0; i < 8; i++) begin
      if (m[i]) result ^= p;
      p = xtime(p);
    end
    return result;
  endfunction

  // ── Round constant Rcon ───────────────────────────────────────────────────
  function automatic logic [7:0] rcon(input int i);
    logic [7:0] lut [1:14];
    lut[1]  = 8'h01; lut[2]  = 8'h02; lut[3]  = 8'h04; lut[4]  = 8'h08;
    lut[5]  = 8'h10; lut[6]  = 8'h20; lut[7]  = 8'h40; lut[8]  = 8'h80;
    lut[9]  = 8'h1b; lut[10] = 8'h36; lut[11] = 8'h6c; lut[12] = 8'hd8;
    lut[13] = 8'hab; lut[14] = 8'h4d;
    return lut[i];
  endfunction

  // ── State packing / unpacking ─────────────────────────────────────────────
  function automatic aes_state_t bytes_to_state(input logic [127:0] d);
    aes_state_t s;
    for (int c = 0; c < 4; c++)
      for (int r = 0; r < 4; r++)
        s[r][c] = d[127 - 8*(c*4 + r) -: 8];
    return s;
  endfunction

  function automatic logic [127:0] state_to_bytes(input aes_state_t s);
    logic [127:0] d;
    for (int c = 0; c < 4; c++)
      for (int r = 0; r < 4; r++)
        d[127 - 8*(c*4 + r) -: 8] = s[r][c];
    return d;
  endfunction

  // ── AES round operations (encrypt only) ───────────────────────────────────
  function automatic aes_state_t sub_bytes(input aes_state_t s);
    aes_state_t r;
    for (int row = 0; row < 4; row++)
      for (int col = 0; col < 4; col++)
        r[row][col] = sbox_fwd(s[row][col]);
    return r;
  endfunction

  function automatic aes_state_t shift_rows(input aes_state_t s);
    aes_state_t r;
    for (int col = 0; col < 4; col++) r[0][col] = s[0][(col    ) % 4];
    for (int col = 0; col < 4; col++) r[1][col] = s[1][(col + 1) % 4];
    for (int col = 0; col < 4; col++) r[2][col] = s[2][(col + 2) % 4];
    for (int col = 0; col < 4; col++) r[3][col] = s[3][(col + 3) % 4];
    return r;
  endfunction

  function automatic aes_state_t mix_columns(input aes_state_t s);
    aes_state_t r;
    for (int c = 0; c < 4; c++) begin
      r[0][c] = gmul(s[0][c],8'h02) ^ gmul(s[1][c],8'h03) ^ s[2][c]             ^ s[3][c];
      r[1][c] = s[0][c]             ^ gmul(s[1][c],8'h02) ^ gmul(s[2][c],8'h03) ^ s[3][c];
      r[2][c] = s[0][c]             ^ s[1][c]             ^ gmul(s[2][c],8'h02) ^ gmul(s[3][c],8'h03);
      r[3][c] = gmul(s[0][c],8'h03) ^ s[1][c]             ^ s[2][c]             ^ gmul(s[3][c],8'h02);
    end
    return r;
  endfunction

  function automatic aes_state_t add_round_key(input aes_state_t s, input logic [127:0] rk);
    return bytes_to_state(state_to_bytes(s) ^ rk);
  endfunction

  // Full encryption round (SubBytes + ShiftRows + MixColumns + AddRoundKey)
  function automatic logic [127:0] enc_round(input logic [127:0] data, input logic [127:0] rk);
    aes_state_t s;
    s = bytes_to_state(data);
    s = sub_bytes(s);
    s = shift_rows(s);
    s = mix_columns(s);
    s = add_round_key(s, rk);
    return state_to_bytes(s);
  endfunction

  // Final encryption round (no MixColumns)
  function automatic logic [127:0] enc_final_round(input logic [127:0] data, input logic [127:0] rk);
    aes_state_t s;
    s = bytes_to_state(data);
    s = sub_bytes(s);
    s = shift_rows(s);
    s = add_round_key(s, rk);
    return state_to_bytes(s);
  endfunction

  // ── AES-256 single-step key expansion ─────────────────────────────────────
  // Given two consecutive 128-bit round-key halves (prev2, prev1) and the
  // round-key index being generated (rk_idx = 2..14), produce the next
  // 128-bit round key.  rk_idx must be >= 2.
  //
  //  rk_idx even  →  word offset = 4*rk_idx, i%8==0  →  RotWord+SubWord+Rcon
  //  rk_idx odd   →  word offset = 4*rk_idx, i%8==4  →  SubWord only
  function automatic logic [127:0] aes256_next_rkey(
    input logic [127:0] prev2,      // rkeys[rk_idx-2]
    input logic [127:0] prev1,      // rkeys[rk_idx-1]
    input int           rk_idx      // index of the key being generated (2..14)
  );
    logic [3:0][31:0] p2, p1, nk;
    logic [31:0] temp;

    // Unpack: word 0 is MSB
    p2 = prev2;
    p1 = prev1;

    // Transform the last word of prev1 (p1[0] = LSB word = w[4*(rk_idx-1)+3])
    temp = p1[0];
    if (rk_idx % 2 == 0) begin
      // Even rk_idx → i%8==0 → RotWord + SubWord + Rcon
      temp = {sbox_fwd(temp[23:16]), sbox_fwd(temp[15:8]),
              sbox_fwd(temp[7:0]),   sbox_fwd(temp[31:24])};
      temp[31:24] = temp[31:24] ^ rcon(rk_idx / 2);
    end else begin
      // Odd rk_idx → i%8==4 → SubWord only
      temp = {sbox_fwd(temp[31:24]), sbox_fwd(temp[23:16]),
              sbox_fwd(temp[15:8]),  sbox_fwd(temp[7:0])};
    end

    // Generate 4 new words: nk[3]=MSB word, nk[0]=LSB word
    nk[3] = p2[3] ^ temp;
    nk[2] = p2[2] ^ nk[3];
    nk[1] = p2[1] ^ nk[2];
    nk[0] = p2[0] ^ nk[1];

    return nk;
  endfunction

  // ── AES-256 key expansion (all 15 round keys from 256-bit key) ────────────
  // Returns 15 x 128-bit round keys packed as [15*128-1:0]
  function automatic logic [14:0][127:0] aes256_key_expand(input logic [255:0] key);
    logic [14:0][127:0] rkeys;
    logic [59:0][31:0] w;  // 60 words for AES-256

    // Initial 8 words from the 256-bit key
    for (int i = 0; i < 8; i++)
      w[i] = key[255 - 32*i -: 32];

    for (int i = 8; i < 60; i++) begin
      logic [31:0] temp;
      temp = w[i-1];
      if (i % 8 == 0) begin
        // RotWord + SubWord + Rcon
        temp = {sbox_fwd(temp[23:16]), sbox_fwd(temp[15:8]),
                sbox_fwd(temp[7:0]),   sbox_fwd(temp[31:24])};
        temp[31:24] = temp[31:24] ^ rcon(i / 8);
      end else if (i % 8 == 4) begin
        // SubWord only
        temp = {sbox_fwd(temp[31:24]), sbox_fwd(temp[23:16]),
                sbox_fwd(temp[15:8]),  sbox_fwd(temp[7:0])};
      end
      w[i] = w[i-8] ^ temp;
    end

    // Pack into 15 round keys
    for (int rk = 0; rk < 15; rk++)
      rkeys[rk] = {w[4*rk], w[4*rk+1], w[4*rk+2], w[4*rk+3]};

    return rkeys;
  endfunction

  // ── Full AES-256 encrypt (combinational — used by iterative wrapper) ──────
  function automatic logic [127:0] aes256_encrypt_block(
    input logic [127:0] plaintext,
    input logic [255:0] key
  );
    logic [14:0][127:0] rkeys;
    logic [127:0] state;

    rkeys = aes256_key_expand(key);

    // Initial AddRoundKey
    state = plaintext ^ rkeys[0];

    // Rounds 1..13
    for (int r = 1; r < 14; r++)
      state = enc_round(state, rkeys[r]);

    // Final round 14
    state = enc_final_round(state, rkeys[14]);

    return state;
  endfunction

endpackage : drbg_pkg
