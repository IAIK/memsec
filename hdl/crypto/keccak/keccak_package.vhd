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

package keccak_package is
  constant LANE_BITWIDTH : integer := 16;

  subtype Lane is std_logic_vector(LANE_BITWIDTH-1 downto 0);
  type LaneArray is array (24 downto 0) of Lane;
  type Plane is array (4 downto 0) of Lane;

  type ParallelCtoD is record  -- Interface from controller to datapath
    loadState           : std_logic;
    enableStateRate     : std_logic;
    enableStateCapacity : std_logic;
    selectXoredBlock    : std_logic;
    enableRoundCounter  : std_logic;
  end record;

  type ParallelDtoC is record    -- Interface from datapath to controller
    permutate_done : std_logic;  -- all permutation rounds are done
  end record;

  function log2Ceil(i : natural) return integer;
end keccak_package;

package body keccak_package is
  function log2Ceil(i : natural) return integer is
    variable temp    : integer := i;
    variable ret_val : integer := 0;
    variable prev    : integer;
    variable ceil    : integer := 0;
  begin
    while temp > 1 loop
      ret_val := ret_val + 1;
      prev    := temp;
      temp    := temp / 2;

      if temp*2 /= prev then
        ceil := 1;
      end if;
    end loop;
    ret_val := ret_val + ceil;

    return ret_val;
  end function;
end package body;
