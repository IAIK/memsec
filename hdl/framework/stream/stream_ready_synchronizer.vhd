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

--! Synchronization block for the internal stream type.
--!
--! This block ensures that all consumers have acknowledged the reception of the
--! block before the next one is accepted.
entity stream_ready_synchronizer is
  generic(
    OUT_WIDTH : integer := 2;
    REGISTERS : integer := 0
    );
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    s_request       : in  StreamType;
    s_request_ready : out std_logic;

    m_requests        : out StreamArrayType(OUT_WIDTH-1 downto 0);
    m_requests_active : in  std_logic_vector(OUT_WIDTH-1 downto 0);
    m_requests_ready  : in  std_logic_vector(OUT_WIDTH-1 downto 0)
    );
end stream_ready_synchronizer;

architecture arch_imp of stream_ready_synchronizer is
  signal reg_stream     : StreamType;
  signal reg_ready      : std_logic;
  signal readys, valids : std_logic_vector(OUT_WIDTH-1 downto 0);
begin

  reg_stage : entity work.stream_multi_register_stage
    generic map(
      REGISTERS => REGISTERS
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_data  => s_request,
      in_valid => s_request.valid,
      in_ready => s_request_ready,

      out_data  => reg_stream,
      out_valid => open,
      out_ready => reg_ready
      );

  synchronization : entity work.ready_synchronizer
    generic map(
      OUT_WIDTH => OUT_WIDTH
      )
    port map(
      clk    => clk,
      resetn => resetn,

      in_ready => reg_ready,
      in_valid => reg_stream.valid,

      out_ready  => readys,
      out_active => m_requests_active,
      out_valid  => valids
      );

  io : process(reg_stream, valids, m_requests_ready) is
  begin
    for I in 0 to OUT_WIDTH-1 loop
      m_requests(I)       <= reg_stream;
      m_requests(I).valid <= valids(I);
      readys(I)           <= m_requests_ready(I);
    end loop;
  end process io;

end arch_imp;
