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

entity keccak_round_parallel_theta is
  port (
    StatexDI : in  LaneArray;
    StatexDO : out LaneArray);
end keccak_round_parallel_theta;

architecture impl of keccak_round_parallel_theta is
begin
  theta : process (StatexDI)
    variable thetaXorxD        : Plane;
    variable thetaXorShiftedxD : Plane;
    variable currentState      : LaneArray;
  begin
    currentState := StatexDI;

    --THETA
    --xoring planes and shifting help plane
    for i in 0 to 4 loop
      thetaXorxD(i)        := currentState(i) xor currentState(i+5) xor currentState(i+10) xor currentState(i+15) xor currentState(i+20);
      thetaXorShiftedxD(i) := thetaXorxD(i)(LANE_BITWIDTH-2 downto 0) & thetaXorxD(i)(LANE_BITWIDTH-1);
    end loop;
    --xoring with actual state
    for i in 0 to 24 loop
      currentState(i) := thetaXorxD((i-1) mod 5) xor thetaXorShiftedxD((i+1) mod 5) xor currentState(i);
    end loop;  -- i

    StatexDO <= currentState;
  end process theta;
end impl;
