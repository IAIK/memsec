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

--! Simple register stage for the internal stream type.
--!
--! Enabling the READY_BYPASS permits to operate the register without
--! introducing idle cycles. However, as a consequence, a critical path across
--! the ready line is not prevented.
entity stream_register_stage is
  generic(
    READY_BYPASS : boolean := true;  --! permit to directly write the register when the output is read
    REGISTERED   : boolean := true
    );
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
end stream_register_stage;

architecture arch_imp of stream_register_stage is
  signal dataxDP, dataxDN   : StreamType;
  signal validxDP, validxDN : std_logic;

begin
  regs : process(clk) is
  begin
    if rising_edge(clk) then
      if resetn = '0' then
        dataxDP  <= StreamType_default;
        validxDP <= '0';
      else
        dataxDP  <= dataxDN;
        validxDP <= validxDN;
      end if;
    end if;
  end process regs;

  control : process(dataxDP, in_data, in_valid, out_ready, validxDP) is
  begin
    dataxDN  <= dataxDP;
    validxDN <= validxDP;

    in_ready  <= out_ready;
    out_valid <= in_valid;
    out_data  <= in_data;

    if REGISTERED then
      in_ready <= '0';

      -- reset the register when it was read
      if validxDP = '1' and out_ready = '1' then
        dataxDN  <= StreamType_default;
        validxDN <= '0';
      end if;

      -- set the register when it was empty or when it is currently read
      if in_valid = '1' and (validxDP = '0' or (READY_BYPASS and out_ready = '1')) then
        dataxDN  <= in_data;
        validxDN <= '1';
        in_ready <= '1';
      end if;

      out_valid <= validxDP;
      out_data  <= dataxDP;
    end if;
  end process control;
end arch_imp;
