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

entity keccak_round_parallel_pi is
  port (
    StatexDI : in  LaneArray;
    StatexDO : out LaneArray);
end keccak_round_parallel_pi;

architecture impl of keccak_round_parallel_pi is
begin
  pi : process (StatexDI)
    variable currentState : LaneArray;
    variable tempState    : LaneArray;
    variable pi_index     : integer := 0;
  begin
    currentState := StatexDI;

    for y in 0 to 4 loop
      for x in 0 to 4 loop
        pi_index            := ((2*x+3*y) mod 5)*5 + y;
        tempState(pi_index) := currentState(x+5*y);
      end loop;
    end loop;

    StatexDO <= tempState;
  end process pi;
end impl;
