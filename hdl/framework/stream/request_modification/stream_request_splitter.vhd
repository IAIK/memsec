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

--! Split a transaction into multiple consecutive requests.
entity stream_request_splitter is
  generic(
    DATA_BLOCK_SIZE : integer := 32 --! Size of one data block in the virtual address space in byte.
    );
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    s_request       : in  StreamType;
    s_request_ready : out std_logic;

    m_request       : out StreamType;
    m_request_ready : in  std_logic
    );
end stream_request_splitter;

architecture behavioral of stream_request_splitter is
  constant BLOCK_LEN         : integer := DATA_BLOCK_SIZE / (DATASTREAM_DATA_WIDTH/8);
  constant PADDING_BIT_COUNT : integer := log2_ceil(DATASTREAM_DATA_WIDTH/8);
  constant ALIGNMENT_BIT     : integer := log2_ceil(DATA_BLOCK_SIZE);

  signal VBlockCounterxDP, VBlockCounterxDN : std_logic_vector(s_request.block_len'length-1 downto 0);
  signal RemainingLenxDP, RemainingLenxDN   : std_logic_vector(s_request.len'length+1 downto 0);
begin

  regs : process(clk) is
  begin
    if rising_edge(clk) then
      if resetn = '0' then
        RemainingLenxDP  <= (others => '0');
        VBlockCounterxDP <= (others => '0');
      else
        RemainingLenxDP  <= RemainingLenxDN;
        VBlockCounterxDP <= VBlockCounterxDN;
      end if;
    end if;
  end process regs;

  comb : process(s_request, m_request_ready, VBlockCounterxDP, RemainingLenxDP) is
    variable virt_address  : std_logic_vector(ADDRESS_WIDTH-1 downto 0);
    variable len           : unsigned(s_request.len'length + 1 downto 0);
    variable len_bytes     : unsigned(s_request.len'length + 1 downto 0);
    variable offset        : unsigned(s_request.len'length + 1 downto 0);
    variable remaining_len : unsigned(s_request.len'length + 1 downto 0);
  begin
    VBlockCounterxDN <= VBlockCounterxDP;
    RemainingLenxDN  <= RemainingLenxDP;

    offset        := unsigned(zeros(offset'length - ALIGNMENT_BIT)) & unsigned(s_request.block_address(ALIGNMENT_BIT-1 downto 0));
    virt_address  := std_logic_vector(unsigned(s_request.block_address) + unsigned(zeros(ADDRESS_WIDTH-VBlockCounterxDP'length-PADDING_BIT_COUNT) & VBlockCounterxDP & zeros(PADDING_BIT_COUNT)) - offset);
    len_bytes     := "00" & unsigned(s_request.len);
    len_bytes     := (len_bytes sll to_integer(unsigned(s_request.size))) or unsigned(dynamic_mask(to_integer(unsigned(s_request.size)), len_bytes'length));
    remaining_len := unsigned(RemainingLenxDP);
    if VBlockCounterxDP = zeros(VBlockCounterxDP'length) then
      if s_request.burst = "01" then
        remaining_len := offset + len_bytes;
      else
        remaining_len := len_bytes;
      end if;
    end if;

    s_request_ready <= '0';

    m_request              <= s_request;
    m_request.last_request <= '0';

    -- Adapt addresses of requests
    if s_request.burst = "01" then
      m_request.address       <= virt_address;
      m_request.block_address <= virt_address;
      len                     := to_unsigned(DATA_BLOCK_SIZE-1, len'length);

      if VBlockCounterxDP = zeros(VBlockCounterxDP'length) then
        -- First or a single block
        m_request.address       <= s_request.address;
        m_request.block_address <= s_request.address;
        if to_integer(remaining_len) < DATA_BLOCK_SIZE then
          -- only 1 subrequest 
          len := len_bytes;
        else
          -- several subrequests
          len := to_unsigned(DATA_BLOCK_SIZE-1, len'length) - offset(len'length-1 downto 0);
        end if;
      elsif to_integer(remaining_len) < DATA_BLOCK_SIZE then
        -- Last block
        len := remaining_len;
      end if;

      len                 := len srl to_integer(unsigned(s_request.size));
      m_request.len       <= std_logic_vector(len(m_request.len'length-1 downto 0));
      m_request.block_len <= std_logic_vector(len(m_request.len'length-1 downto 0));
    elsif s_request.burst = "10" then
      m_request.block_address <= virt_address;
      len                     := to_unsigned(DATA_BLOCK_SIZE-1, len'length);

      if VBlockCounterxDP = zeros(VBlockCounterxDP'length) then
        -- First or a single block
        m_request.block_address <= s_request.block_address;
        if to_integer(remaining_len) < DATA_BLOCK_SIZE then
          -- only 1 subrequest 
          len := len_bytes;
        end if;
      end if;

      len                 := len srl to_integer(unsigned(s_request.size));
      m_request.block_len <= std_logic_vector(len(m_request.len'length-1 downto 0));
    end if;

    -- Compute next block counter and remaining length
    if to_integer(remaining_len) < DATA_BLOCK_SIZE then
      m_request.last_request <= s_request.last_request;
      if s_request.valid = '1' then
        s_request_ready <= m_request_ready;
        if m_request_ready = '1' then
          VBlockCounterxDN <= (others => '0');
          RemainingLenxDN  <= (others => '0');
        end if;
      end if;
    elsif VBlockCounterxDP = zeros(VBlockCounterxDP'length) then
      if m_request_ready = '1' then
        RemainingLenxDN  <= std_logic_vector(len_bytes - to_unsigned(DATA_BLOCK_SIZE, RemainingLenxDP'length) + offset);
        VBlockCounterxDN <= std_logic_vector(unsigned(VBlockCounterxDP) + to_unsigned(BLOCK_LEN, s_request.block_len'length));
      end if;
    else
      if m_request_ready = '1' then
        RemainingLenxDN  <= std_logic_vector(unsigned(RemainingLenxDP) - to_unsigned(DATA_BLOCK_SIZE, RemainingLenxDP'length));
        VBlockCounterxDN <= std_logic_vector(unsigned(VBlockCounterxDP) + to_unsigned(BLOCK_LEN, s_request.block_len'length));
      end if;
    end if;
  end process comb;

end behavioral;
