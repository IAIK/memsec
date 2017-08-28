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

entity keccak_round_parallel_chi is
  port (
    StatexDI : in  LaneArray;
    StatexDO : out LaneArray);
end keccak_round_parallel_chi;

architecture impl of keccak_round_parallel_chi is
begin
  chi : process (StatexDI)
    variable currentState : LaneArray;
    variable tempState    : LaneArray;
  begin
    currentState := StatexDI;

    for y in 0 to 4 loop
      for x in 0 to 4 loop
        tempState(x + y*5) := currentState(x + y*5) xor ((not (currentState((x+1) mod 5 + 5*y))) and currentState((x+2) mod 5 + 5*y));
      end loop;
    end loop;

    StatexDO <= tempState;
  end process chi;
end impl;
