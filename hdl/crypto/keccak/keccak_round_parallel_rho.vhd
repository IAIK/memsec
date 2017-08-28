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

entity keccak_round_parallel_rho is
  port (
    StatexDI : in  LaneArray;
    StatexDO : out LaneArray);
end keccak_round_parallel_rho;

architecture impl of keccak_round_parallel_rho is
begin
  rho : process (StatexDI)
    type offset_array is array (0 to 24) of integer;
    variable offset       : offset_array;
    variable currentState : LaneArray;
  begin
    offset(0)  := 0 mod LANE_BITWIDTH;
    offset(1)  := 1 mod LANE_BITWIDTH;
    offset(2)  := 14 mod LANE_BITWIDTH;
    offset(3)  := 12 mod LANE_BITWIDTH;
    offset(4)  := 11 mod LANE_BITWIDTH;
    offset(5)  := 4 mod LANE_BITWIDTH;
    offset(6)  := 12 mod LANE_BITWIDTH;
    offset(7)  := 6 mod LANE_BITWIDTH;
    offset(8)  := 7 mod LANE_BITWIDTH;
    offset(9)  := 4 mod LANE_BITWIDTH;
    offset(10) := 3 mod LANE_BITWIDTH;
    offset(11) := 10 mod LANE_BITWIDTH;
    offset(12) := 11 mod LANE_BITWIDTH;
    offset(13) := 9 mod LANE_BITWIDTH;
    offset(14) := 7 mod LANE_BITWIDTH;
    offset(15) := 9 mod LANE_BITWIDTH;
    offset(16) := 13 mod LANE_BITWIDTH;
    offset(17) := 15 mod LANE_BITWIDTH;
    offset(18) := 5 mod LANE_BITWIDTH;
    offset(19) := 8 mod LANE_BITWIDTH;
    offset(20) := 2 mod LANE_BITWIDTH;
    offset(21) := 2 mod LANE_BITWIDTH;
    offset(22) := 13 mod LANE_BITWIDTH;
    offset(23) := 8 mod LANE_BITWIDTH;
    offset(24) := 14 mod LANE_BITWIDTH;

    currentState := StatexDI;

    for N in 1 to 24 loop
      currentState(N) := currentState(N)((LANE_BITWIDTH-1-offset(N)) downto 0) & currentState(N)(LANE_BITWIDTH-1 downto (LANE_BITWIDTH-1 - offset(N)+1));
    end loop;

    StatexDO <= currentState;
  end process rho;
end impl;
