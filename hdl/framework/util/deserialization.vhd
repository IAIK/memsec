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

--! Deserializes a standard logic vector into a possibly wider vector.
--!
--! Address offsets to shift the first block as well as a last signal to
--! terminate the final block early are supported.
entity deserialization is
  generic(
    IN_DATA_WIDTH  : integer := 32;
    OUT_DATA_WIDTH : integer := 64;    --! has to be (1,2,4,8,...) * IN_DATA_WIDTH
    REGISTERED     : boolean := false  --! option to cut the critical path
    );
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    -- The field offset at which the first in_data block should be placed. All
    -- subsequent in_data blocks will be placed in the ascending fields. This
    -- input is only sampled after a reset or if the previous block has ended
    -- with a last signal.
    --
    -- For example, an offset of 1 in a 32 to 64 conversion places the first
    -- in_data block in the top 32 bits and immediately returns the resulting
    -- out_data. 
    in_field_start_offset : in std_logic_vector(log2_ceil(OUT_DATA_WIDTH/IN_DATA_WIDTH) - 1 downto 0);

    -- Signals that the current transaction is over and that the output should
    -- be generated immediately. The output bits which are missing are zero.
    in_last  : in  std_logic;
    in_data  : in  std_logic_vector(IN_DATA_WIDTH - 1 downto 0);
    in_valid : in  std_logic;
    in_ready : out std_logic;

    -- output with handshake signals
    out_data         : out std_logic_vector(OUT_DATA_WIDTH - 1 downto 0);
    out_last         : out std_logic;
    out_field_offset : out std_logic_vector(log2_ceil(OUT_DATA_WIDTH/IN_DATA_WIDTH) - 1 downto 0);
    out_field_len    : out std_logic_vector(log2_ceil(OUT_DATA_WIDTH/IN_DATA_WIDTH) - 1 downto 0);
    out_valid        : out std_logic;
    out_ready        : in  std_logic
    );
end deserialization;

architecture arch_imp of deserialization is
  constant FIELD_ADDR_WIDTH : integer := log2_ceil(OUT_DATA_WIDTH/IN_DATA_WIDTH);
  constant LAST_FIELD_ADDR  : integer := OUT_DATA_WIDTH/IN_DATA_WIDTH - 1;

  signal fieldxDP, fieldxDN             : std_logic_vector(FIELD_ADDR_WIDTH - 1 downto 0);
  signal dataxDP, dataxDN               : std_logic_vector(OUT_DATA_WIDTH - 1 downto 0);
  signal runningxDP, runningxDN         : std_logic;
  signal completexDP, completexDN       : std_logic;
  signal lastxDP, lastxDN               : std_logic;
  signal fieldOffsetxDP, fieldOffsetxDN : std_logic_vector(log2_ceil(OUT_DATA_WIDTH/IN_DATA_WIDTH) - 1 downto 0);
  signal fieldLenxDP, fieldLenxDN       : std_logic_vector(log2_ceil(OUT_DATA_WIDTH/IN_DATA_WIDTH) - 1 downto 0);

  -- datapath signals
  signal combined_data : std_logic_vector(OUT_DATA_WIDTH - 1 downto 0);
  signal field_addr    : std_logic_vector(FIELD_ADDR_WIDTH - 1 downto 0);
  signal in_ack        : std_logic;
  signal out_ack       : std_logic;
  signal field_offset  : std_logic_vector(log2_ceil(OUT_DATA_WIDTH/IN_DATA_WIDTH) - 1 downto 0);
  signal field_len     : std_logic_vector(log2_ceil(OUT_DATA_WIDTH/IN_DATA_WIDTH) - 1 downto 0);
  signal field_len_inc : std_logic_vector(log2_ceil(OUT_DATA_WIDTH/IN_DATA_WIDTH) - 1 downto 0);

  signal in_readyxS  : std_logic;
  signal out_validxS : std_logic;

  -- control signals
  signal use_new_field_addr : std_logic;
  signal update_data_reg    : std_logic;
  signal new_block          : std_logic;
  signal reset_field        : std_logic;
  signal reset_field_info   : std_logic;
begin

  regs : process(clk) is
  begin
    if rising_edge(clk) then
      if resetn = '0' then
        fieldxDP       <= (others => '0');
        dataxDP        <= (others => '0');
        runningxDP     <= '0';
        completexDP    <= '0';
        lastxDP        <= '0';
        fieldOffsetxDP <= (others => '0');
        fieldLenxDP    <= (others => '0');
      else
        fieldxDP       <= fieldxDN;
        dataxDP        <= dataxDN;
        runningxDP     <= runningxDN;
        completexDP    <= completexDN;
        lastxDP        <= lastxDN;
        fieldOffsetxDP <= fieldOffsetxDN;
        fieldLenxDP    <= fieldLenxDN;
      end if;
    end if;
  end process regs;

  field_addr    <= fieldxDP       when use_new_field_addr = '0' else in_field_start_offset;
  field_offset  <= fieldOffsetxDP when use_new_field_addr = '0' else in_field_start_offset;
  field_len     <= fieldLenxDP;
  field_len_inc <= std_logic_vector(unsigned(fieldLenxDP)+1);
  in_ack        <= in_readyxS and in_valid;
  out_ack       <= out_validxS and out_ready;

  p_combine_data : process(dataxDP, field_addr, in_data, new_block) is
    variable field        : integer range 0 to LAST_FIELD_ADDR;
    variable shifted_data : std_logic_vector(OUT_DATA_WIDTH - 1 downto 0);
  begin
    combined_data <= (others => '0');

    field        := to_integer(unsigned(field_addr));
    shifted_data := zeros(OUT_DATA_WIDTH - IN_DATA_WIDTH) & in_data;
    shifted_data := std_logic_vector(unsigned(shifted_data) sll (field*IN_DATA_WIDTH));

    combined_data <= dataxDP or shifted_data;
    if new_block = '1' then
      combined_data <= shifted_data;
    end if;
  end process p_combine_data;

  p_update_data_reg : process(combined_data, dataxDP, field_addr, lastxDP, in_last,
                              use_new_field_addr, in_field_start_offset, reset_field_info,
                              update_data_reg, reset_field, fieldOffsetxDP, fieldLenxDP,
                              field_len, field_len_inc) is
  begin
    fieldxDN       <= field_addr;
    dataxDN        <= dataxDP;
    lastxDN        <= lastxDP;
    fieldOffsetxDN <= fieldOffsetxDP;
    fieldLenxDN    <= fieldLenxDP;
    if reset_field = '1' then
      fieldxDN    <= (others => '0');
      fieldLenxDN <= (others => '0');
    end if;
    if update_data_reg = '1' then
      dataxDN     <= combined_data;
      fieldxDN    <= std_logic_vector(unsigned(field_addr)+1);
      fieldLenxDN <= field_len_inc;
      lastxDN     <= in_last;
    end if;
    if reset_field_info = '1' then
      fieldOffsetxDN <= (others => '0');
      fieldLenxDN    <= (others => '0');
    end if;
    if use_new_field_addr = '1' then
      fieldOffsetxDN <= std_logic_vector(in_field_start_offset);
    end if;
  end process p_update_data_reg;

  control : process(combined_data, completexDP, dataxDP, field_addr, in_last, out_ack, in_ack,
                    in_readyxS, in_valid, out_ready, out_validxS, runningxDP, lastxDP,
                    fieldOffsetxDP, fieldLenxDP, field_len, field_offset) is
    variable field          : integer range 0 to LAST_FIELD_ADDR;
    variable block_complete : boolean;
  begin
    runningxDN  <= runningxDP;
    completexDN <= completexDP;

    out_data         <= (others => '0');
    in_readyxS       <= '0';
    out_validxS      <= '0';
    out_last         <= '0';
    out_field_offset <= (others => '0');
    out_field_len    <= (others => '0');

    new_block          <= '0';
    use_new_field_addr <= '0';
    update_data_reg    <= '0';
    reset_field        <= '0';
    reset_field_info   <= '0';

    field          := 0;
    block_complete := false;

    -- start new block when the output has been acknowledged
    if REGISTERED and out_ack = '1' then
      completexDN      <= '0';
      reset_field_info <= '1';
    end if;

    -- end current transaction when the input has been acknowledged with in_last
    if in_ack = '1' and in_last = '1' then
      runningxDN <= '0';
    end if;

    -- start a new transaction if none is running
    if in_valid = '1' and runningxDP = '0' then
      use_new_field_addr <= '1';
      new_block          <= '1';
      if in_last = '0' then
        runningxDN <= '1';
      end if;
    end if;

    -- process new data from the input
    if in_valid = '1' and (completexDP = '0' or out_ack = '1') then
      -- evaluate if the block is complete

      field          := to_integer(unsigned(field_addr));
      block_complete := field = LAST_FIELD_ADDR or in_last = '1';

      if field = 0 then
        new_block <= '1';
      end if;

      -- process the combined data depending on REGISTERED
      -- if REGISTERED is true : everything has to be placed into the register
      -- if REGISTERED is false: everything but the last block has to be registered
      if REGISTERED then
        update_data_reg <= '1';
        in_readyxS      <= '1';

        if block_complete then
          completexDN <= '1';
        end if;
      else
        if not(block_complete) then
          update_data_reg <= '1';
          in_readyxS      <= '1';
        end if;
      end if;
    end if;

    -- output data directly from the register in REGISTERED mode
    if REGISTERED then
      out_data         <= dataxDP;
      out_validxS      <= completexDP;
      out_last         <= lastxDP;
      out_field_offset <= fieldOffsetxDP;
      out_field_len    <= fieldLenxDP;
    elsif REGISTERED = false and block_complete then
      out_data         <= combined_data;
      out_validxS      <= '1';
      out_last         <= in_last;
      out_field_offset <= field_offset;
      out_field_len    <= field_len;
      -- if output is not REGISTERED it has to be acknowledged to the input
      if out_ack = '1' then
        in_readyxS  <= '1';
        reset_field <= '1';
      end if;
    end if;
  end process control;

  in_ready  <= in_readyxS;
  out_valid <= out_validxS;

end arch_imp;
