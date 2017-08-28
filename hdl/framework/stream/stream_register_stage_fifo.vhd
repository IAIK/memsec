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

--! FIFO for the internal stream type with two elements.
--!
--! The primary purpose of this two element FIFO is to provide an alternative
--! two the register stage which cuts the critical path in forward and backward
--! direction without loosing a cycle.
entity stream_register_stage_fifo is
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    in_data  : in  StreamType;
    in_valid : in  std_logic;
    in_ready : out std_logic;

    out_data  : out StreamType;
    out_valid : out std_logic;
    out_ready : in  std_logic
    );
end stream_register_stage_fifo;

architecture arch_imp of stream_register_stage_fifo is
  signal left_input, left_output, right_input, right_output                         : StreamType;
  signal left_input_valid, right_input_valid, left_output_valid, right_output_valid : std_logic;
  signal left_input_ready, right_input_ready, left_output_ready, right_output_ready : std_logic;

  signal leftInputxDP, leftInputxDN, leftOutputxDP, leftOutputxDN : std_logic;
begin

  regs : process(clk) is
  begin
    if rising_edge(clk) then
      if resetn = '0' then
        leftInputxDP  <= '0';
        leftOutputxDP <= '0';
      else
        leftInputxDP  <= leftInputxDN;
        leftOutputxDP <= leftOutputxDN;
      end if;
    end if;
  end process regs;

  comb : process(in_data, in_valid, out_ready, leftInputxDP, leftOutputxDP,
                 right_output, right_output_valid, left_output, left_output_valid,
                 left_input_ready, right_input_ready) is
  begin
    leftInputxDN  <= leftInputxDP;
    leftOutputxDN <= leftOutputxDP;

    right_output_ready <= '0';
    left_output_ready  <= '0';

    -- output
    if leftOutputxDP = '1' then
      out_data          <= left_output;
      out_data.valid    <= left_output_valid;
      out_valid         <= left_output_valid;
      left_output_ready <= out_ready;
      if out_ready = '1' and left_output_valid = '1' then
        leftOutputxDN <= '0';
      end if;
    else
      out_data           <= right_output;
      out_data.valid     <= right_output_valid;
      out_valid          <= right_output_valid;
      right_output_ready <= out_ready;
      if out_ready = '1' and right_output_valid = '1' then
        leftOutputxDN <= '1';
      end if;
    end if;

    -- input
    left_input        <= StreamType_default;
    right_input       <= StreamType_default;
    left_input_valid  <= '0';
    right_input_valid <= '0';

    if leftInputxDP = '1' then
      left_input       <= in_data;
      left_input_valid <= in_valid;
      in_ready         <= left_input_ready;
      if left_input_ready = '1' then
        leftInputxDN <= '0';
      end if;
    else
      right_input       <= in_data;
      right_input_valid <= in_valid;
      in_ready          <= right_input_ready;
      if right_input_ready = '1' then
        leftInputxDN <= '1';
      end if;
    end if;
  end process comb;


  left : entity work.stream_register_stage
    generic map (
      REGISTERED   => true,
      READY_BYPASS => false
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_data  => left_input,
      in_valid => left_input_valid,
      in_ready => left_input_ready,

      out_data  => left_output,
      out_valid => left_output_valid,
      out_ready => left_output_ready
      );

  right : entity work.stream_register_stage
    generic map (
      REGISTERED   => true,
      READY_BYPASS => false
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_data  => right_input,
      in_valid => right_input_valid,
      in_ready => right_input_ready,

      out_data  => right_output,
      out_valid => right_output_valid,
      out_ready => right_output_ready
      );
end arch_imp;
