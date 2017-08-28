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
use work.memsec_functions.all;

--! Clears the full transaction when the first nonce/key block is zero.
--!
--! Using a zero nonce to identify uninitialized memory permits to lazily
--! bootstrap the AE modes.
entity stream_request_zero_initializer is
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    s_request       : in  StreamType;
    s_request_ready : out std_logic;

    m_request       : out StreamType;
    m_request_ready : in  std_logic
    );
end stream_request_zero_initializer;

architecture behavioral of stream_request_zero_initializer is
  signal initRequestxDP, initRequestxDN : std_logic;
  signal inRequestxDP, inRequestxDN     : std_logic;
  signal request_ready                  : std_logic;
begin

  regs : process(clk) is
  begin
    if rising_edge(clk) then
      if resetn = '0' then
        initRequestxDP <= '0';
        inRequestxDP   <= '0';
      else
        initRequestxDP <= initRequestxDN;
        inRequestxDP   <= inRequestxDN;
      end if;
    end if;
  end process regs;

  comb : process(s_request, m_request_ready, request_ready, initRequestxDP, inRequestxDP) is
  begin
    initRequestxDN <= initRequestxDP;
    inRequestxDN   <= inRequestxDP;

    m_request     <= StreamType_default;
    request_ready <= '0';

    if s_request.valid = '1' then
      m_request     <= s_request;
      request_ready <= m_request_ready;

      if inRequestxDP = '0' then
        inRequestxDN   <= '1';
        initRequestxDN <= to_std_logic(unsigned(s_request.data) = 0);
      end if;

      if request_ready = '1' and unsigned(s_request.block_len) = 0 then
        inRequestxDN <= '0';
      end if;

      if inRequestxDP = '1' and initRequestxDP = '1' then
        m_request.data  <= (others => '0');
        m_request.error <= '0';
      end if;
    end if;
  end process comb;

  s_request_ready <= request_ready;

end behavioral;
