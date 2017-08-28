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

entity aes128_hs is
  port(
    ClkxCI        : in  std_logic;
    RstxRBI       : in  std_logic;
    KeyxDI        : in  std_logic_vector(127 downto 0);
    DataxDI       : in  std_logic_vector(127 downto 0);
    DataxDO       : out std_logic_vector(127 downto 0);
    EncryptxSI    : in  std_logic;

    in_ready      : out std_logic;
    in_valid      : in  std_logic;
    out_ready     : in  std_logic;
    out_valid     : out std_logic
  );
end aes128_hs;

--! @FIXME replace with real implementation for aes128_hs
architecture nop of aes128_hs is
begin
  data_reg : entity work.register_stage
    generic map(
      WIDTH      => 128,
      REGISTERED => true
      )
    port map (
      clk    => ClkxCI,
      resetn => RstxRBI,

      in_data  => DataxDI,
      in_valid => in_valid,
      in_ready => in_ready,

      out_data  => DataxDO,
      out_valid => out_valid,
      out_ready => out_ready
      );
end nop;
