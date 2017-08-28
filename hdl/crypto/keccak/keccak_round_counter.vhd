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

entity keccak_round_counter is
  generic (
    SUBTRAHEND : integer := 1;
    BITWIDTH   : integer := 5);
  port (
    ClkxCI           : in  std_logic;
    EnableCounterxSI : in  std_logic;
    RstxRBI          : in  std_logic;
    CounterZeroxSO   : out std_logic;
    CounterValuexDO  : out std_logic_vector(BITWIDTH-1 downto 0);
    ResetValuexDI    : in  std_logic_vector(BITWIDTH-1 downto 0);
    SyncResetxSI     : in  std_logic
    );
end keccak_round_counter;

architecture arch_reg of keccak_round_counter is
  signal QxDP, QxDN : std_logic_vector(BITWIDTH-1 downto 0) := (others => '0');
begin
  SequProc : process(RstxRBI, ClkxCI)
  begin  -- process SequProc
    if RstxRBI = '0' then               -- asynchronous reset (active low)
      QxDP <= (others => '0');
    elsif rising_edge(ClkxCI) then
      QxDP <= QxDN;
    end if;
  end process SequProc;
  CounterValuexDO <= QxDP;

  CombProc : process (QxDP, SyncResetxSI, EnableCounterxSI, ResetValuexDI)
    variable new_value : std_logic_vector(BITWIDTH -1 downto 0);
  begin  -- process CombProc
    new_value := std_logic_vector(unsigned(QxDP) - SUBTRAHEND);

    QxDN <= QxDP;
    if EnableCounterxSI = '1' then
      QxDN <= new_value;
    end if;
    if SyncResetxSI = '1' then
      QxDN <= ResetValuexDI;
    end if;

    if unsigned(QxDP) = 0 then
      CounterZeroxSO <= '1';
    else
      CounterZeroxSO <= '0';
    end if;
  end process CombProc;
end arch_reg;
