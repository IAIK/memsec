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
use work.memsec_pkg.all;

--! Simple register stage for the internal stream type with configurable register count.
entity stream_multi_register_stage is
  generic(
    REGISTERS : integer := 1
    );
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    in_data  : in  StreamType;
    in_valid : in  std_logic;
    in_ready : out std_logic;

    out_data  : out StreamType;
    out_valid : out std_logic;
    out_ready : in  std_logic
    );
end stream_multi_register_stage;

architecture arch_imp of stream_multi_register_stage is
  type HandshakeArrayType is array (REGISTERS downto 0) of std_logic;

  signal streams        : StreamArrayType(REGISTERS downto 0);
  signal readys, valids : HandshakeArrayType;
begin
  streams(0) <= in_data;
  valids(0)  <= in_valid;
  in_ready   <= readys(0);

  regs : for I in 0 to REGISTERS-1 generate
    r : entity work.stream_register_stage
      port map (
        clk    => clk,
        resetn => resetn,

        in_data  => streams(I),
        in_valid => valids(I),
        in_ready => readys(I),

        out_data  => streams(I+1),
        out_valid => valids(I+1),
        out_ready => readys(I+1)
        );
  end generate regs;

  out_data          <= streams(REGISTERS);
  out_valid         <= valids(REGISTERS);
  readys(REGISTERS) <= out_ready;
end arch_imp;
