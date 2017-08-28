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

entity keccak_round_iota is
  port (
    StatexDI     : in  Lane;
    StatexDO     : out Lane;
    RoundNrxDI   : in  std_logic_vector(4 downto 0);
    CfgRoundsxDI : in  std_logic_vector(4 downto 0)
    );
end keccak_round_iota;

architecture impl of keccak_round_iota is
begin
  iota : process (StatexDI, RoundNrxDI, CfgRoundsxDI)
    variable currentLane : Lane;
    variable roundAsInt  : integer;
    variable iota_index  : integer range 0 to 19;
    type lut_type is array (0 to 19) of std_logic_vector(4 downto 0);
    constant lut : lut_type := (
      0  => "00001", 1 => "11010", 2 => "11110", 3 => "10000", 4 => "11111",
      5  => "00001", 6 => "11001", 7 => "10101", 8 => "01110", 9 => "01100",
      10 => "10101", 11 => "00110", 12 => "11111", 13 => "01111", 14 => "11101",
      15 => "10011", 16 => "10010", 17 => "01000", 18 => "10110", 19 => "00110");
  begin
    roundAsInt := to_integer(unsigned(RoundNrxDI));
    if roundAsInt > (to_integer(unsigned(CfgRoundsxDI))-1) then
      iota_index := 0;
    else
      iota_index := to_integer(unsigned(CfgRoundsxDI))-1-roundAsInt;
    end if;

    currentLane := StatexDI;

    currentLane(1 downto 0) := currentLane(1 downto 0) xor lut(iota_index)(1 downto 0);
    currentLane(3)          := currentLane(3) xor lut(iota_index)(2);
    if log2Ceil(LANE_BITWIDTH) > 2 then
      currentLane(7) := currentLane(7) xor lut(iota_index)(3);
    end if;
    if log2Ceil(LANE_BITWIDTH) > 3 then
      currentLane(15) := currentLane(15) xor lut(iota_index)(4);
    end if;

    StatexDO <= currentLane;
  end process iota;
end impl;
