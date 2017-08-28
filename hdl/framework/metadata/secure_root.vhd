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

--! Implements a configurable number of secure roots for the tree modes.
--!
--! Returns the current value for the requested root. Additionally, when a root
--! update has been requested, also the new root is returned. As update
--! function, either a counter or random updates can be configured.
entity secure_root is
  generic(
    ROOT_WIDTH  : integer := DATASTREAM_DATA_WIDTH;
    TREE_ROOTS  : integer := 1;
    USE_COUNTER : boolean := true
    );
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    root_number       : in  std_logic_vector(log2_ceil(TREE_ROOTS)-1 downto 0);
    root_update       : in  std_logic;
    root_number_valid : in  std_logic;
    root_number_ready : out std_logic;

    root       : out std_logic_vector(ROOT_WIDTH-1 downto 0);
    root_valid : out std_logic;
    root_ready : in  std_logic;

    root_next       : out std_logic_vector(ROOT_WIDTH-1 downto 0);
    root_next_valid : out std_logic;
    root_next_ready : in  std_logic;

    random         : in  std_logic_vector(ROOT_WIDTH-1 downto 0);
    random_valid   : in  std_logic;
    random_ready   : out std_logic;
    random_request : out std_logic
    );
end secure_root;

architecture behavioral of secure_root is
  constant ROOT_NUMBER_WIDTH                        : integer := log2_ceil(TREE_ROOTS);
  signal combined_input, delayed_input              : std_logic_vector(ROOT_NUMBER_WIDTH downto 0);
  signal combined_input_valid, combined_input_ready : std_logic;
  signal delayed_input_valid, delayed_input_ready   : std_logic;

  signal read_root : std_logic_vector(ROOT_WIDTH-1 downto 0);

  signal root_nextxS : std_logic_vector(ROOT_WIDTH-1 downto 0);

  signal read_number_valid, read_number_ready : std_logic;
  signal write_root_valid, write_root_ready   : std_logic;
  signal read_root_valid, read_root_ready     : std_logic;

  signal sync_read_root_valid, sync_read_root_ready               : std_logic;
  signal sync_root_next_to_reg_valid, sync_root_next_to_reg_ready : std_logic;
  signal sync_root_valid, sync_root_ready                         : std_logic;

  signal write_transfer : std_logic;
begin

  write_transfer <= read_root_valid and delayed_input_valid and delayed_input(ROOT_NUMBER_WIDTH);

  comb : process(delayed_input, delayed_input_valid, read_root, read_root_valid,
                 sync_read_root_ready, write_transfer, random, random_valid, sync_root_next_to_reg_ready) is
    variable vRootNext : std_logic_vector(ROOT_WIDTH-1 downto 0);
  begin
    random_request <= '0';
    random_ready   <= '0';

    root_nextxS <= (others => '0');

    -- skip the root update in RAM and the output of the next root on read transfers
    if USE_COUNTER then
      sync_read_root_valid <= read_root_valid and delayed_input_valid;
    else
      sync_read_root_valid <= read_root_valid and delayed_input_valid and
                              (not(write_transfer) or random_valid);
    end if;

    read_root_ready     <= sync_read_root_ready;
    delayed_input_ready <= sync_read_root_ready;

    if write_transfer = '1' then
      -- write transfer -> update root nonce and write back
      if USE_COUNTER then
        vRootNext := std_logic_vector(unsigned(read_root)+1);
        if vRootNext = zeros(ROOT_WIDTH) then
          vRootNext(0) := '1';
        end if;
        root_nextxS <= vRootNext;
      else
        random_request <= read_root_valid and delayed_input_valid;
        random_ready   <= sync_root_next_to_reg_ready;
        root_nextxS    <= random;
      end if;
    end if;
  end process comb;

  input_synchronizer : entity work.ready_synchronizer
    generic map(
      OUT_WIDTH => 2
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_valid => root_number_valid,
      in_ready => root_number_ready,

      out_valid(0)  => read_number_valid,
      out_valid(1)  => combined_input_valid,
      out_active(0) => '1',
      out_active(1) => '1',
      out_ready(0)  => read_number_ready,
      out_ready(1)  => combined_input_ready
      );

  -- the root update flag is stored in the MSB
  combined_input <= root_update & root_number;
  input_delay_reg : entity work.register_stage
    generic map(
      WIDTH => ROOT_NUMBER_WIDTH+1
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_data  => combined_input,
      in_valid => combined_input_valid,
      in_ready => combined_input_ready,

      out_data  => delayed_input,
      out_valid => delayed_input_valid,
      out_ready => delayed_input_ready
      );

  ram : entity work.xilinx_TDP_RAM_synchronized
    generic map(
      ADDR_WIDTH => ROOT_NUMBER_WIDTH,
      DATA_WIDTH => ROOT_WIDTH,
      ENTRIES    => TREE_ROOTS
      )
    port map (
      clk    => clk,
      resetn => resetn,

      addra => root_number,
      dina  => (others => '0'),
      wea   => '0',
      vina  => read_number_valid,
      rina  => read_number_ready,

      douta => read_root,
      vouta => read_root_valid,
      routa => read_root_ready,

      addrb => delayed_input(ROOT_NUMBER_WIDTH-1 downto 0),
      dinb  => root_nextxS,
      web   => '1',
      vinb  => write_root_valid,
      rinb  => write_root_ready,

      doutb => open,
      voutb => open,
      routb => '1'
      );

  synchronizer : entity work.ready_synchronizer
    generic map(
      OUT_WIDTH => 3
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_valid => sync_read_root_valid,
      in_ready => sync_read_root_ready,

      out_valid(0)  => sync_root_valid,
      out_valid(1)  => sync_root_next_to_reg_valid,
      out_valid(2)  => write_root_valid,
      out_active(0) => '1',
      out_active(1) => write_transfer,
      out_active(2) => write_transfer,
      out_ready(0)  => sync_root_ready,
      out_ready(1)  => sync_root_next_to_reg_ready,
      out_ready(2)  => write_root_ready
      );

  root_output_reg : entity work.register_stage
    generic map(
      WIDTH => ROOT_WIDTH
      )
    port map(
      clk    => clk,
      resetn => resetn,

      in_data  => read_root,
      in_valid => sync_root_valid,
      in_ready => sync_root_ready,

      out_data  => root,
      out_valid => root_valid,
      out_ready => root_ready
      );

  root_next_output_reg : entity work.register_stage
    generic map(
      WIDTH => ROOT_WIDTH
      )
    port map(
      clk    => clk,
      resetn => resetn,

      in_data  => root_nextxS,
      in_valid => sync_root_next_to_reg_valid,
      in_ready => sync_root_next_to_reg_ready,

      out_data  => root_next,
      out_valid => root_next_valid,
      out_ready => root_next_ready
      );

end behavioral;
