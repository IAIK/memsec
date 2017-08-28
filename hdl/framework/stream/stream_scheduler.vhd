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

--! Simple scheduler which forwards the slave ports to the master in a round robin manner.
entity stream_scheduler is
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    s_request_1       : in  StreamType;
    s_request_1_ready : out std_logic;

    s_request_2       : in  StreamType;
    s_request_2_ready : out std_logic;

    m_request       : out StreamType;
    m_request_ready : in  std_logic
    );
end stream_scheduler;

architecture arch_imp of stream_scheduler is
  signal last_1xDP, last_1xDN : std_logic;

begin

  regs : process(clk) is
  begin
    if rising_edge(clk) then
      if resetn = '0' then
        last_1xDP <= '0';
      else
        last_1xDP <= last_1xDN;
      end if;
    end if;
  end process regs;

  work : process(s_request_1, s_request_2, m_request_ready, last_1xDP) is
    variable request_1 : std_logic;
  begin
    m_request         <= StreamType_default;
    s_request_1_ready <= '0';
    s_request_2_ready <= '0';

    last_1xDN <= last_1xDP;

    request_1 := '0';

    -- by default, requests 1 is always forwarded when valid
    if s_request_1.valid = '1' then
      m_request         <= s_request_1;
      s_request_1_ready <= m_request_ready;
      if s_request_1.last_request = '1' then
        request_1 := '1';
      end if;
    end if;

    -- requests 2 is forwarded when it is valid and no request 1 should
    -- be performed, or when the last request was already a request 1
    if s_request_2.valid = '1' and
      (s_request_1.valid = '0' or last_1xDP = '1') then
      m_request         <= s_request_2;
      s_request_2_ready <= m_request_ready;
      s_request_1_ready <= '0';
      request_1         := '0';
    end if;

    if m_request_ready = '1' then
      last_1xDN <= request_1;
    end if;
  end process work;

end arch_imp;
