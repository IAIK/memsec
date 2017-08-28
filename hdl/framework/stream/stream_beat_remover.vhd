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

--! Drops a configurable amount of beats in each transaction.
entity stream_beat_remover is
  generic(
    DROP_POSITION : integer := 0;
    DROP_COUNT    : integer := 1
    );
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    s_request       : in  StreamType;
    s_request_ready : out std_logic;

    m_request       : out StreamType;
    m_request_ready : in  std_logic
    );
end stream_beat_remover;

architecture behavioral of stream_beat_remover is
  signal BlockCounterxDP, BlockCounterxDN : std_logic_vector(s_request.len'length-1 downto 0);
  signal request_ready                    : std_logic;
begin

  regs : process(clk) is
  begin
    if rising_edge(clk) then
      if resetn = '0' then
        BlockCounterxDP <= (others => '0');
      else
        BlockCounterxDP <= BlockCounterxDN;
      end if;
    end if;
  end process regs;

  comb : process(s_request, m_request_ready, request_ready, BlockCounterxDP) is
    variable vBlockCounter : integer;
  begin
    BlockCounterxDN <= BlockCounterxDP;

    -- forward request by default
    m_request     <= s_request;
    request_ready <= m_request_ready;

    vBlockCounter                                       := to_integer(unsigned(BlockCounterxDP));
    -- drop the input block if the drop position is reached
    if vBlockCounter >= DROP_POSITION and vBlockCounter <= (DROP_POSITION+DROP_COUNT-1) then
      m_request     <= StreamType_default;
      request_ready <= '1';
    end if;

    if s_request.valid = '1' and request_ready = '1' then
      if unsigned(s_request.block_len) = 0 then
        BlockCounterxDN <= (others => '0');
      else
        BlockCounterxDN <= std_logic_vector(unsigned(BlockCounterxDP) + 1);
      end if;
    end if;
  end process comb;

  s_request_ready <= request_ready;

end behavioral;
