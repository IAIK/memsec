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
use work.keccak_package.all;
use ieee.numeric_std.all;

entity keccak_parallel_control is
  port (
    ClkxCI           : in  std_logic;
    RstxRBI          : in  std_logic;
    -- External control signals
    StartInitxSI     : in  std_logic;
    StartAbsorbxSI   : in  std_logic;
    StartSqueezexSI  : in  std_logic;
    PermutateDonexSO : out std_logic;
    -- Internal control signals
    ControlxSO       : out ParallelCtoD;
    StatusxSI        : in  ParallelDtoC
    );
end keccak_parallel_control;

architecture behavior of keccak_parallel_control is
  type STATE_TYPE is (IDLE, PERMUTATE);
  signal CurrentStatexS, NextStatexS        : STATE_TYPE;
  signal PermutateDonexSP, PermutateDonexSN : std_logic;
begin
  comb : process(CurrentStatexS, StartInitxSI, StartAbsorbxSI,
                 StartSqueezexSI, StatusxSI.permutate_done, PermutateDonexSP)
  begin
    NextStatexS                    <= CurrentStatexS;
    ControlxSO.selectXoredBlock    <= '0';
    ControlxSO.loadState           <= '0';
    ControlxSO.enableStateRate     <= '0';
    ControlxSO.enableStateCapacity <= '0';
    ControlxSO.enableRoundCounter  <= '0';
    PermutateDonexSN               <= PermutateDonexSP;
    PermutateDonexSO               <= PermutateDonexSP;

    case CurrentStatexS is
      when IDLE =>
        PermutateDonexSN <= '0';
        if StartInitxSI = '1' then
          ControlxSO.selectXoredBlock    <= '0';
          ControlxSO.loadState           <= '1';
          ControlxSO.enableStateRate     <= '1';
          ControlxSO.enableStateCapacity <= '1';
          NextStatexS                    <= PERMUTATE;
        elsif StartAbsorbxSI = '1' then
          ControlxSO.selectXoredBlock    <= '1';
          ControlxSO.loadState           <= '0';
          ControlxSO.enableStateRate     <= '1';
          ControlxSO.enableStateCapacity <= '0';
          NextStatexS                    <= PERMUTATE;
        elsif StartSqueezexSI = '1' then
          ControlxSO.selectXoredBlock    <= '0';
          ControlxSO.loadState           <= '0';
          ControlxSO.enableStateRate     <= '0';
          ControlxSO.enableStateCapacity <= '0';
          NextStatexS                    <= PERMUTATE;
        else
          NextStatexS <= IDLE;
        end if;

      when PERMUTATE =>
        ControlxSO.selectXoredBlock    <= '0';
        ControlxSO.loadState           <= '0';
        ControlxSO.enableStateRate     <= '1';
        ControlxSO.enableStateCapacity <= '1';
        ControlxSO.enableRoundCounter  <= '1';
        NextStatexS                    <= PERMUTATE;
        if StatusxSI.permutate_done = '1' then
          ControlxSO.enableRoundCounter <= '0';
          PermutateDonexSN              <= '1';
          NextStatexS                   <= IDLE;
        end if;

    end case;
  end process;

  sync : process
  begin
    wait until rising_edge(ClkxCI);
    if RstxRBI = '0' then
      CurrentStatexS   <= IDLE;
      PermutateDonexSP <= '0';
    else
      CurrentStatexS   <= NextStatexS;
      PermutateDonexSP <= PermutateDonexSN;
    end if;
  end process;
end behavior;
