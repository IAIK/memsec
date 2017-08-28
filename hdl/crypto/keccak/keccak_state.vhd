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
use work.keccak_package.all;

entity keccak_state is
  generic (
    RATE     : integer := 80;
    BITWIDTH : integer := 16);
  port (
    ClkxCI             : in  std_logic;
    DxDI               : in  LaneArray;
    Enable_RatexSI     : in  std_logic;
    Enable_CapacityxSI : in  std_logic;
    RstxRBI            : in  std_logic;
    QxDO               : out LaneArray);
end keccak_state;

architecture gen of keccak_state is
begin
  G1 : for i in 24 downto 0 generate
    reg_rate : if i < RATE/BITWIDTH generate
      keccak_rate : entity work.keccak_register
        generic map (
          BITWIDTH => BITWIDTH)
        port map (
          ClkxCI    => ClkxCI,
          DxDI      => DxDI(i),
          EnablexSI => Enable_RatexSI,
          RstxRBI   => RstxRBI,
          QxDO      => QxDO(i));
    end generate reg_rate;

    reg_capacity : if i >= RATE/BITWIDTH generate
      keccak_capacity : entity work.keccak_register
        generic map (
          BITWIDTH => BITWIDTH)
        port map (
          ClkxCI    => ClkxCI,
          DxDI      => DxDI(i),
          EnablexSI => Enable_CapacityxSI,
          RstxRBI   => RstxRBI,
          QxDO      => QxDO(i));
    end generate reg_capacity;
  end generate G1;
end gen;
