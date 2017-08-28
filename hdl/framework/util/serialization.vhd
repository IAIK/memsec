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
use work.memsec_functions.all;

--! Serializes a standard logic vector into a smaller vectors.
--!
--! Address offsets to shift the first block as well as a last signal to
--! terminate the final block early are supported.
entity serialization is
  generic(
    IN_DATA_WIDTH  : integer := 64;  --! has to be (1,2,4,8,...) * OUT_DATA_WIDTH
    OUT_DATA_WIDTH : integer := 32;
    REGISTERED     : boolean := false
    );
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    in_last         : in  std_logic;
    in_data         : in  std_logic_vector(IN_DATA_WIDTH - 1 downto 0);
    in_field_offset : in  std_logic_vector(log2_ceil(IN_DATA_WIDTH/OUT_DATA_WIDTH)-1 downto 0);
    in_field_len    : in  std_logic_vector(log2_ceil(IN_DATA_WIDTH/OUT_DATA_WIDTH)-1 downto 0);
    in_valid        : in  std_logic;
    in_ready        : out std_logic;

    -- output with handshake signals
    out_data         : out std_logic_vector(OUT_DATA_WIDTH - 1 downto 0);
    out_field_offset : out std_logic_vector(log2_ceil(IN_DATA_WIDTH/OUT_DATA_WIDTH)-1 downto 0);
    out_last         : out std_logic;
    out_valid        : out std_logic;
    out_ready        : in  std_logic
    );
end serialization;

architecture arch_imp of serialization is
  constant FIELD_ADDR_WIDTH : integer := log2_ceil(IN_DATA_WIDTH/OUT_DATA_WIDTH);
  constant LAST_FIELD_ADDR  : integer := IN_DATA_WIDTH/OUT_DATA_WIDTH - 1;

  -- potentially registered input signals
  signal last         : std_logic;
  signal data         : std_logic_vector(IN_DATA_WIDTH - 1 downto 0);
  signal valid        : std_logic;
  signal ready        : std_logic;
  signal field_addr   : std_logic_vector(in_field_offset'length-1 downto 0);
  signal field_offset : std_logic_vector(in_field_offset'length-1 downto 0);
  signal field_len    : std_logic_vector(in_field_len'length-1 downto 0);

  -- internal registers
  signal fieldxDP, fieldxDN : std_logic_vector(FIELD_ADDR_WIDTH - 1 downto 0);

  -- datapath signals
  signal last_block : std_logic;

begin

  data_reg : entity work.register_stage
    generic map(
      WIDTH      => IN_DATA_WIDTH,
      REGISTERED => REGISTERED
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_data  => in_data,
      in_valid => in_valid,
      in_ready => in_ready,

      out_data  => data,
      out_valid => valid,
      out_ready => ready
      );

  offset_reg : entity work.register_stage
    generic map(
      WIDTH      => in_field_offset'length,
      REGISTERED => REGISTERED
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_data  => in_field_offset,
      in_valid => in_valid,
      in_ready => open,                 -- data_reg handles the synchronization

      out_data  => field_offset,
      out_valid => open,                -- data_reg handles the synchronization
      out_ready => ready
      );

  len_reg : entity work.register_stage
    generic map(
      WIDTH      => in_field_len'length,
      REGISTERED => REGISTERED
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_data  => in_field_len,
      in_valid => in_valid,
      in_ready => open,                 -- data_reg handles the synchronization

      out_data  => field_len,
      out_valid => open,                -- data_reg handles the synchronization
      out_ready => ready
      );


  last_reg : entity work.register_stage
    generic map(
      WIDTH      => 1,
      REGISTERED => REGISTERED
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_data(0) => in_last,
      in_valid   => in_valid,
      in_ready   => open,               -- data_reg handles the synchronization

      out_data(0) => last,
      out_valid   => open,              -- data_reg handles the synchronization
      out_ready   => ready
      );

  regs : process(clk) is
  begin
    if rising_edge(clk) then
      if resetn = '0' then
        fieldxDP <= (others => '0');
      else
        fieldxDP <= fieldxDN;
      end if;
    end if;
  end process regs;

  p_slice_data : process(valid, fieldxDP, data, field_offset) is
    variable field_addr_u : unsigned(field_addr'length-1 downto 0);
    variable field        : integer range 0 to LAST_FIELD_ADDR;
    variable shifted_data : std_logic_vector(IN_DATA_WIDTH - 1 downto 0);
  begin
    field_addr <= (others => '0');
    out_data   <= (others => '0');

    if valid = '1' then
      field_addr_u := unsigned(fieldxDP) + unsigned(field_offset);
      field_addr   <= std_logic_vector(field_addr_u);
      field        := to_integer(field_addr_u);
      shifted_data := std_logic_vector(unsigned(data) srl (field*OUT_DATA_WIDTH));
      out_data     <= shifted_data(OUT_DATA_WIDTH-1 downto 0);
    end if;
  end process p_slice_data;

  last_block <= '1' when fieldxDP = field_len else '0';

  p_update_field_reg : process(fieldxDP, valid, out_ready, fieldxDP, last_block) is
  begin
    fieldxDN <= fieldxDP;
    ready    <= '0';

    if valid = '1' and out_ready = '1' then
      fieldxDN <= std_logic_vector(unsigned(fieldxDP)+1);
      if last_block = '1' then
        ready <= '1';
      end if;
    end if;
  end process p_update_field_reg;

  out_valid        <= valid;
  out_field_offset <= field_addr;
  out_last         <= last and last_block;
end arch_imp;
