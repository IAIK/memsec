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

entity keccak_round_parallel is
  generic (
    BITWIDTH : integer := 5);
  port (
    StatexDI     : in  LaneArray;
    StatexDO     : out LaneArray;
    CfgRoundsxDI : in  std_logic_vector(BITWIDTH-1 downto 0);
    RoundNrxDI   : in  std_logic_vector(BITWIDTH-1 downto 0));
end keccak_round_parallel;

architecture impl of keccak_round_parallel is
  signal StateAfterTheta : LaneArray;
  signal StateAfterRho   : LaneArray;
  signal StateAfterPi    : LaneArray;
  signal StateAfterChi   : LaneArray;
  signal StateAfterIota  : LaneArray;
begin
  theta : entity work.keccak_round_parallel_theta
    port map (
      StatexDI => StatexDI,
      StatexDO => StateAfterTheta);

  rho : entity work.keccak_round_parallel_rho
    port map (
      StatexDI => StateAfterTheta,
      StatexDO => StateAfterRho);

  pi : entity work.keccak_round_parallel_pi
    port map (
      StatexDI => StateAfterRho,
      StatexDO => StateAfterPi);

  chi : entity work.keccak_round_parallel_chi
    port map (
      StatexDI => StateAfterPi,
      StatexDO => StateAfterChi);

  iota : entity work.keccak_round_iota
    port map (
      StatexDI     => StateAfterChi(0),
      StatexDO     => StateAfterIota(0),
      RoundNrxDI   => RoundNrxDI,
      CfgRoundsxDI => CfgRoundsxDI);
  StateAfterIota(24 downto 1) <= StateAfterChi(24 downto 1);

  StatexDO <= StateAfterIota;
end impl;
