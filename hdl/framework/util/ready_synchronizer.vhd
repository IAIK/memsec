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

--! Synchronization block for the standard valid and ready handshake signals.
--!
--! This block ensures that all consumers have acknowledged the reception of the
--! block before the next one is accepted.
entity ready_synchronizer is
  generic(
    OUT_WIDTH : integer := 1
    );
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    in_valid : in  std_logic;
    in_ready : out std_logic;

    out_valid  : out std_logic_vector(OUT_WIDTH-1 downto 0);
    out_active : in  std_logic_vector(OUT_WIDTH-1 downto 0);
    out_ready  : in  std_logic_vector(OUT_WIDTH-1 downto 0)
    );
end ready_synchronizer;

architecture arch_imp of ready_synchronizer is
  signal ackxDP, ackxDN               : std_logic_vector(OUT_WIDTH-1 downto 0);
  signal out_activexSP, out_activexSN : std_logic_vector(OUT_WIDTH-1 downto 0);

  signal in_readyxS  : std_logic;
  signal out_validxS : std_logic_vector(OUT_WIDTH-1 downto 0);
  signal out_readyxS : std_logic_vector(OUT_WIDTH-1 downto 0);
begin
  regs : process(clk) is
  begin
    if rising_edge(clk) then
      if resetn = '0' then
        out_activexSP <= (others => '0');
        ackxDP        <= (others => '0');
      else
        out_activexSP <= out_activexSN;
        ackxDP        <= ackxDN;
      end if;
    end if;
  end process regs;

  control : process(ackxDP, in_valid, out_validxS, out_readyxS, out_activexSP, out_active) is
    variable out_ack : std_logic_vector(OUT_WIDTH-1 downto 0);

    variable ackxV : std_logic_vector(OUT_WIDTH-1 downto 0);
  begin
    ackxV := ackxDP;

    if out_active /= out_activexSP then
      --ackxV := (others => '0');
      ackxV := ackxV and out_active and out_activexSP;
    end if;

    in_readyxS  <= '0';
    out_validxS <= (others => '0');

    -- helper signals 
    out_ack := out_validxS and out_readyxS;

    -- generate the valid outputs
    if in_valid = '1' then
      out_validxS <= not(ackxV);
    end if;

    -- process ack signals from the output
    for I in 0 to OUT_WIDTH - 1 loop
      if out_ack(I) = '1' then
        ackxV(I) := '1';
      end if;
    end loop;

    -- send ack to the input when all outputs have been acknowledged
    if ackxV = ones(OUT_WIDTH) then
      in_readyxS <= '1';
      ackxV      := (others => '0');
    end if;

    ackxDN        <= ackxV;
    out_activexSN <= out_active;
  end process control;

  in_ready    <= in_readyxS;
  out_valid   <= out_active and out_validxS;
  out_readyxS <= not(out_active) or out_ready;
end arch_imp;
