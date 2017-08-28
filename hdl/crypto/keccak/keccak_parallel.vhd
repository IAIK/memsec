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

entity keccak_parallel is
  generic(
    UNROLLED_ROUNDS : integer := 1;
    ROUNDS          : integer := 18;
    RATE            : integer := 80);
  port (
    ClkxCI           : in  std_logic;   -- system clock
    RstxRBI          : in  std_logic;   -- synchronous reset (active low)
    -- Data signals
    BlockxDO         : out std_logic_vector(RATE-1 downto 0);  -- output block
    BlockxDI         : in  std_logic_vector(RATE-1 downto 0);  -- input block
    IVxDI            : in  std_logic_vector(25*LANE_BITWIDTH-1 downto 0);  -- initial vector
    -- Control signals
    StartInitxSI     : in  std_logic;   -- load IV into current state
    StartAbsorbxSI   : in  std_logic;   -- absorb the input block
    StartSqueezexSI  : in  std_logic;   -- absorb the input block
    PermutateDonexSO : out std_logic);  -- calculation is in progress
end keccak_parallel;

architecture impl of keccak_parallel is
  signal CtoD : ParallelCtoD;
  signal DtoC : ParallelDtoC;

  signal StatexS : LaneArray;

  function Vec2LaneArray(vec : std_logic_vector) return LaneArray is
    variable result : LaneArray;
  begin
    for i in 0 to 24 loop
      result(i) := vec((i+1)*LANE_BITWIDTH-1 downto i*LANE_BITWIDTH);
    end loop;
    return result;
  end function;

begin
  datapath : entity work.keccak_parallel_datapath
    generic map(
      UNROLLED_ROUNDS => UNROLLED_ROUNDS,
      RATE            => RATE,
      ROUNDS          => ROUNDS
      )
    port map (
      ClkxCI     => ClkxCI,
      RstxRBI    => RstxRBI,
      -- Data signals
      BlockxDO   => BlockxDO,
      BlockxDI   => BlockxDI,
      IVxDI      => Vec2LaneArray(IVxDI),
      -- Internal control signals
      ControlxSI => CtoD,
      StatusxSO  => DtoC);

  controller : entity work.keccak_parallel_control
    port map (
      ClkxCI           => ClkxCI,
      RstxRBI          => RstxRBI,
      -- External control signals
      StartInitxSI     => StartInitxSI,
      StartAbsorbxSI   => StartAbsorbxSI,
      StartSqueezexSI  => StartSqueezexSI,
      PermutateDonexSO => PermutateDonexSO,
      -- Internal control signals
      ControlxSO       => CtoD,
      StatusxSI        => DtoC);
end impl;
