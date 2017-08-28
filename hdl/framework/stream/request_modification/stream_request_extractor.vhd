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

--! Extracts the original request from the stream.
--!
--! The data beats as well as all metadata of all data and tree requests are
--! discarded such that every data transaction is reported only once.
entity stream_request_extractor is
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    s_request       : in  StreamType;
    s_request_ready : out std_logic;

    m_request       : out StreamType;
    m_request_ready : in  std_logic
    );
end stream_request_extractor;

architecture arch_imp of stream_request_extractor is
  signal reqxDP, reqxDN                 : StreamType;
  signal output_ackxDBP, output_ackxDBN : std_logic;
  signal input_ackxDBP, input_ackxDBN   : std_logic;

  signal request_ready : std_logic;
  signal output_req    : StreamType;
begin

  regs : process(clk) is
  begin
    if rising_edge(clk) then
      if resetn = '0' then
        reqxDP         <= StreamType_default;
        input_ackxDBP  <= '0';
        output_ackxDBP <= '0';
      else
        reqxDP         <= reqxDN;
        input_ackxDBP  <= input_ackxDBN;
        output_ackxDBP <= output_ackxDBN;
      end if;
    end if;
  end process regs;

  work : process(input_ackxDBP, m_request_ready, output_ackxDBP,
                 output_req.valid, request_ready, reqxDP, s_request) is
  begin
    reqxDN         <= reqxDP;
    input_ackxDBN  <= input_ackxDBP;
    output_ackxDBN <= output_ackxDBP;

    output_req    <= StreamType_default;
    request_ready <= '0';

    if reqxDP.valid = '1' and output_ackxDBP = '1' then
      output_req <= reqxDP;
    end if;

    -- Register is empty.
    -- Write the new data into the register and forward the new request
    -- directly from the input.
    if s_request.valid = '1' and s_request.request_type = REQ_TYPE_DATA and input_ackxDBP = '0' and output_ackxDBP = '0' then
      reqxDN         <= s_request;
      output_req     <= s_request;
      request_ready  <= '1';
      output_ackxDBN <= '1';
      input_ackxDBN  <= '1';
    elsif s_request.valid = '1' and s_request.request_type /= REQ_TYPE_DATA then
      request_ready <= '1';
    end if;

    -- remember if the output request has been acknowledged
    if output_req.valid = '1' and m_request_ready = '1' then
      output_ackxDBN <= '0';
    end if;

    -- remember if the input request has been acknowledged
    if s_request.valid = '1' and request_ready = '1' and to_integer(unsigned(s_request.block_len)) = 0 and s_request.last_request = '1' then
      input_ackxDBN <= '0';
    end if;

    -- acknowledged all requests at the input until the end has been reached
    if s_request.valid = '1' and reqxDP.valid = '1' and input_ackxDBP = '1' then
      request_ready <= '1';
    end if;
  end process work;

  s_request_ready <= request_ready;

  sanitize : process(output_req) is
  begin
    m_request               <= output_req;
    m_request.virt_address  <= (others => '0');
    m_request.block_address <= (others => '0');
    m_request.block_len     <= (others => '0');
    m_request.data          <= (others => '0');
    m_request.len           <= (others => '0');  -- the request splitter cuts the original len and it is not used
    m_request.metadata      <= '0';
  end process sanitize;

end arch_imp;
