--
-- MEMSEC - Framework for building transparent memory encryption and authentication solutions.
-- Copyright (C) 2017 Graz University of Technology, IAIK <mario.werner@iaik.tugraz.at>
--
-- This file is part of MEMSEC.
--
-- MEMSEC is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- MEMSEC is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with MEMSEC.  If not, see <http://www.gnu.org/licenses/>.
--

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;
use work.memsec_pkg.all;

package memsec_functions is
  function zeros (constant WIDTH      : natural) return std_logic_vector;
  function ones (constant WIDTH       : natural) return std_logic_vector;
  function mask (constant ONES_WIDTH  : natural; constant WIDTH : natural) return std_logic_vector;
  function dynamic_mask (ONES_WIDTH   : natural; constant WIDTH : natural) return std_logic_vector;
  function to_meta_address (address   : std_logic_vector) return AddressType;
  function to_std_logic (constant val : boolean) return std_logic;

  function log2_ceil(constant value : integer) return integer;
  function max(constant left        : integer; constant right : integer) return integer;
  function min(constant left        : integer; constant right : integer) return integer;
  function reverse_bit_order (a     : std_logic_vector) return std_logic_vector;
  function change_endianess(vec     : std_logic_vector) return std_logic_vector;

  function hamming_weight(a : natural) return integer;
  function offset_width(a   : natural; b : natural) return integer;

  function slice_bits(data : std_logic_vector; width_a : natural; width_b : natural) return std_logic_vector;
  function set_bits(data   : std_logic_vector; bits : std_logic_vector; width_a : natural; width_b : natural) return std_logic_vector;
end package;

package body memsec_functions is

  function max(constant left  : integer;
               constant right : integer)
    return integer is
    variable vRet : integer;
  begin
    vRet := left;
    if right > left then
      vRet := right;
    end if;
    return vRet;
  end max;

  function min(constant left  : integer;
               constant right : integer)
    return integer is
    variable vRet : integer;
  begin
    vRet := left;
    if right < left then
      vRet := right;
    end if;
    return vRet;
  end min;

  function zeros (
    constant WIDTH : natural)
    return std_logic_vector is
    variable x : std_logic_vector(WIDTH-1 downto 0);
  begin
    x := (others => '0');
    return x;
  end zeros;

  function ones (
    constant WIDTH : natural)
    return std_logic_vector is
  begin
    return not(zeros(WIDTH));
  end ones;

  function mask (
    constant ONES_WIDTH : natural;
    constant WIDTH      : natural)
    return std_logic_vector is
  begin
    return zeros(WIDTH-ONES_WIDTH) & ones(ONES_WIDTH);
  end mask;

  function dynamic_mask (
    ONES_WIDTH     : natural;
    constant WIDTH : natural)
    return std_logic_vector is
    variable x : std_logic_vector(WIDTH-1 downto 0);
  begin
    x := std_logic_vector(to_unsigned(2**ONES_WIDTH - 1, WIDTH));
    return x;
  end dynamic_mask;

  function to_meta_address (
    address : std_logic_vector)
    return AddressType is
    variable res : AddressType;
  begin
    res                              := (others => '0');
    res(address'length - 1 downto 0) := address;
    return res;
  end to_meta_address;

  function to_std_logic(
    constant val : boolean)
    return std_logic is
  begin
    if val then
      return '1';
    else
      return '0';
    end if;
  end to_std_logic;

  function log2_ceil(
    constant value : integer)
    return integer is
  begin
    if (value <= 1) then
      return 0;
    elsif (value = 2) then
      return 1;
    elsif (value mod 2 = 0) then
      return 1 + log2_ceil(value/2);
    else
      return 1 + log2_ceil((value+1)/2);
    end if;
  end log2_ceil;

  function reverse_bit_order (a : std_logic_vector)
    return std_logic_vector is
    variable result : std_logic_vector(a'range);
    alias aa        : std_logic_vector(a'reverse_range) is a;
  begin
    for i in aa'range loop
      result(i) := aa(i);
    end loop;
    return result;
  end reverse_bit_order;

  function change_endianess(vec : std_logic_vector) return std_logic_vector is
    variable vRet      : std_logic_vector(vec'range);
    constant cNumBytes : natural := vec'length / 8;
  begin
    for i in 0 to cNumBytes-1 loop
      for j in 7 downto 0 loop
        vRet(8*i + j) := vec(8*(cNumBytes-1-i) + j);
      end loop;  -- j
    end loop;  -- i
    return vRet;
  end change_endianess;

  function hamming_weight(a : natural) return integer is
    variable vector : std_logic_vector(log2_ceil(a)-1 downto 0);
    variable hw     : integer;
  begin
    hw     := 0;
    vector := std_logic_vector(to_unsigned(a, log2_ceil(a)));
    for i in 0 to log2_ceil(a)-1 loop
      if vector(i) = '1' then
        hw := hw + 1;
      end if;
    end loop;
    return hw;
  end hamming_weight;

  function offset_width(a : natural; b : natural) return integer is
  begin
    if a > b then
      return log2_ceil(a/b);
    elsif a = b then
      return 0;
    else
      return log2_ceil(b/a);
    end if;
  end offset_width;

  function slice_bits(data : std_logic_vector; width_a : natural; width_b : natural) return std_logic_vector is
    variable bits : std_logic_vector(offset_width(width_a, width_b)-1 downto 0);
  begin
    bits := (others => '0');
    if width_a > width_b then
      bits := data(log2_ceil(width_a)-1 downto log2_ceil(width_b));
    elsif width_b > width_a then
      bits := data(log2_ceil(width_b)-1 downto log2_ceil(width_a));
    end if;
    return bits;
  end slice_bits;

  function set_bits(data : std_logic_vector; bits : std_logic_vector; width_a : natural; width_b : natural) return std_logic_vector is
    variable output : std_logic_vector(data'length-1 downto 0);
  begin
    output := data;
    if width_a > width_b then
      output(log2_ceil(width_a)-1 downto log2_ceil(width_b)) := bits;
    elsif width_b > width_a then
      output(log2_ceil(width_b)-1 downto log2_ceil(width_a)) := bits;
    end if;
    return output;
  end set_bits;
end package body;
