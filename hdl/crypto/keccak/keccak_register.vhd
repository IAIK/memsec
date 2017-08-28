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

entity keccak_register is
  generic (
    BITWIDTH : integer := 16);
  port (
    ClkxCI    : in  std_logic;
    DxDI      : in  std_logic_vector(BITWIDTH-1 downto 0);
    EnablexSI : in  std_logic;
    RstxRBI   : in  std_logic;
    QxDO      : out std_logic_vector(BITWIDTH-1 downto 0)
    );

end keccak_register;

architecture arch_reg of keccak_register is
  signal Q_tmp : std_logic_vector(BITWIDTH-1 downto 0) := (others => '0');
begin
  SequProc : process
  begin  -- process SequProc
    wait until rising_edge(ClkxCI);
    if RstxRBI = '0' then               -- synchronous reset (active low)
      Q_tmp <= (others => '0');
    elsif EnablexSI = '1' then
      Q_tmp <= DxDI;
    end if;
  end process SequProc;

  QxDO <= Q_tmp;

end arch_reg;
