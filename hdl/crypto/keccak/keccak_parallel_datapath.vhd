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

entity keccak_parallel_datapath is
  generic(
    UNROLLED_ROUNDS : integer := 1;
    RATE            : integer := 80;
    ROUNDS          : integer := 18
    );
  port (
    ClkxCI     : in  std_logic;         -- system clock
    RstxRBI    : in  std_logic;         -- synchronous reset (active low)
    -- Data signals
    BlockxDO   : out std_logic_vector(RATE-1 downto 0);  -- output block
    BlockxDI   : in  std_logic_vector(RATE-1 downto 0);  -- input block
    IVxDI      : in  LaneArray;         -- initial state
    -- Control signals
    ControlxSI : in  ParallelCtoD;  -- control signals from the controller to the datapath
    StatusxSO  : out ParallelDtoC);  -- status signals from the datapath to the controller
end keccak_parallel_datapath;

architecture impl of keccak_parallel_datapath is
  signal StatexDP         : LaneArray;
  signal StatexDN         : LaneArray;
  signal RoundCountxD     : std_logic_vector(log2Ceil(ROUNDS)-1 downto 0);
  signal SyncCounterReset : std_logic;

  type PermutationStatesType is array (0 to UNROLLED_ROUNDS) of LaneArray;
  type RoundCountType is array (0 to UNROLLED_ROUNDS-1) of std_logic_vector(log2Ceil(ROUNDS)-1 downto 0);

  signal PermutationStatexD : PermutationStatesType;
  signal RoundCountsxD      : RoundCountType;
begin
  state1 : entity work.keccak_state
    generic map (
      RATE     => RATE,
      BITWIDTH => LANE_BITWIDTH)
    port map (
      ClkxCI             => ClkxCI,
      DxDI               => StatexDN,
      Enable_RatexSI     => ControlxSI.enableStateRate,
      Enable_CapacityxSI => ControlxSI.enableStateCapacity,
      RstxRBI            => RstxRBI,
      QxDO               => StatexDP);

  keccak_round_counter_1 : entity work.keccak_round_counter
    generic map (
      BITWIDTH   => log2Ceil(ROUNDS),
      SUBTRAHEND => UNROLLED_ROUNDS
      )
    port map (
      ClkxCI           => ClkxCI,
      EnableCounterxSI => ControlxSI.enableRoundCounter,
      RstxRBI          => RstxRBI,
      CounterZeroxSO   => StatusxSO.permutate_done,
      CounterValuexDO  => RoundCountxD,
      SyncResetxSI     => SyncCounterReset,
      ResetValuexDI    => std_logic_vector(to_unsigned(ROUNDS-UNROLLED_ROUNDS, log2Ceil(ROUNDS)))
      );

  SyncCounterReset <= not ControlxSI.enableRoundCounter;

  next_state : process (StatexDP, ControlxSI.selectXoredBlock, IVxDI,
                        ControlxSI.loadState, BlockxDI, PermutationStatexD(UNROLLED_ROUNDS))
    variable nextState : LaneArray;
  begin
    nextState := PermutationStatexD(UNROLLED_ROUNDS);

    if ControlxSI.loadState = '1' then
      nextState := IVxDI;
    end if;

    if ControlxSI.selectXoredBlock = '1' then
      -- xor rate
      for N in RATE/LANE_BITWIDTH - 1 downto 0 loop
        nextState(N) := StatexDP(N) xor BlockxDI((N+1)*LANE_BITWIDTH-1 downto N*LANE_BITWIDTH);
      end loop;
    end if;

    StatexDN <= nextState;
  end process next_state;

  outBlock : process (StatexDP)
    variable v_rate : std_logic_vector(RATE-1 downto 0);
  begin
    v_rate := (others => '0');
    for i in RATE/LANE_BITWIDTH -1 downto 0 loop
      v_rate((i+1)*LANE_BITWIDTH-1 downto i*LANE_BITWIDTH) := StatexDP(i);
    end loop;
    BlockxDO <= v_rate;
  end process outBlock;

  PermutationStatexD(0) <= StatexDP;
  round_instances :
  for i in 0 to UNROLLED_ROUNDS-1 generate
    round : entity work.keccak_round_parallel
      generic map(BITWIDTH => log2Ceil(ROUNDS))
      port map(StatexDI     => PermutationStatexD(i),
               StatexDO     => PermutationStatexD(i+1),
               CfgRoundsxDI => std_logic_vector(to_unsigned(ROUNDS, log2Ceil(ROUNDS))),
               RoundNrxDI   => RoundCountsxD(i));

    RoundCountsxD(i) <= std_logic_vector(unsigned(RoundCountxD)+UNROLLED_ROUNDS-1-i);
  end generate round_instances;
end impl;
