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

--! Reorder buffer to implement AXI wrapping bursts.
--!
--! Wrapping bursts are typically issued to speed up cache refills.
--! Unfortunately, processing data out of order is not possible as soon as
--! stronger cryptographic modes are used. Reordering data for small bursts
--! within the pipeline provides a compromise between generality and performance.
entity stream_axi_wrap_burst_cache is
  generic(
    DATASTREAM_WIDTH     : integer := 32;
    CACHE_SIZE           : integer := 256;
    NARROW_BURST_SUPPORT : boolean := false
    );
  port(
    -- Ports of Axi Slave Bus Interface S_AXI
    clk    : in std_logic;
    resetn : in std_logic;

    s_request       : in  StreamType;
    s_request_ready : out std_logic;

    m_request       : out StreamType;
    m_request_ready : in  std_logic
    );
end stream_axi_wrap_burst_cache;

architecture behavioral of stream_axi_wrap_burst_cache is
  constant CACHE_ELEMENTS         : integer := CACHE_SIZE/DATASTREAM_WIDTH;
  constant CACHE_ELEMENTS_BITS    : integer := log2_ceil(CACHE_ELEMENTS);
  constant CACHE_SIZE_BITS        : integer := log2_ceil(CACHE_SIZE/8);
  constant DATASTREAM_WIDTH_BYTES : integer := DATASTREAM_WIDTH/8;
  constant DATASTREAM_WIDTH_BITS  : integer := log2_ceil(DATASTREAM_WIDTH_BYTES);
  type CacheArrayType is array (CACHE_ELEMENTS-1 downto 0) of std_logic_vector(DATASTREAM_WIDTH-1 downto 0);
  type CacheState is array (CACHE_ELEMENTS-1 downto 0) of std_logic;

  signal CachexDP, CachexDN                   : CacheArrayType;
  signal CacheStatexDP, CacheStatexDN         : CacheState;
  signal CachedElementsxDP, CachedElementsxDN : std_logic_vector(CACHE_ELEMENTS_BITS downto 0);
  signal ReadIndexxDP, ReadIndexxDN           : std_logic_vector(CACHE_ELEMENTS_BITS-1 downto 0);
  signal CachingActivexDP, CachingActivexDN   : std_logic;
  signal StreamxDP, StreamxDN                 : StreamType;
  signal CachedReqLenxDP, CachedReqLenxDN     : std_logic_vector(CACHE_ELEMENTS_BITS downto 0);
  signal CacheIdxMaskxDP, CacheIdxMaskxDN     : std_logic_vector(CACHE_ELEMENTS_BITS-1 downto 0);

  signal cache_input, cache_output             : StreamType;
  signal cache_input_ready, cache_output_ready : std_logic;
  signal cached_req_len                        : std_logic_vector(CACHE_ELEMENTS_BITS downto 0);
  signal cache_idx_mask                        : std_logic_vector(CACHE_ELEMENTS_BITS-1 downto 0);

  signal caching_active : std_logic;

  signal s_request_len_bytes : unsigned(s_request.len'length+1 downto 0);
begin

  regs : process(clk) is
  begin
    if rising_edge(clk) then
      if resetn = '0' then
        CachexDP          <= (others => (others => '0'));
        CacheStatexDP     <= (others => '0');
        ReadIndexxDP      <= (others => '0');
        StreamxDP         <= StreamType_default;
        CachingActivexDP  <= '0';
        CachedElementsxDP <= (others => '0');
        CachedReqLenxDP   <= (others => '0');
        CacheIdxMaskxDP   <= (others => '0');
      else
        CachexDP          <= CachexDN;
        CacheStatexDP     <= CacheStatexDN;
        ReadIndexxDP      <= ReadIndexxDN;
        StreamxDP         <= StreamxDN;
        CachingActivexDP  <= CachingActivexDN;
        CachedElementsxDP <= CachedElementsxDN;
        CachedReqLenxDP   <= CachedReqLenxDN;
        CacheIdxMaskxDP   <= CacheIdxMaskxDN;
      end if;
    end if;
  end process regs;

  s_request_len_bytes <= ("00" & unsigned(s_request.len)) sll to_integer(unsigned(s_request.size)) or unsigned(dynamic_mask(to_integer(unsigned(s_request.size)), s_request.len'length+2));

  caching_state : process (CachingActivexDP, CachedReqLenxDP, CacheIdxMaskxDP, s_request, s_request_len_bytes) is
    variable v_request_len : unsigned(s_request.len'length+2 downto 0);
  begin
    caching_active <= CachingActivexDP;
    cached_req_len <= CachedReqLenxDP;
    cache_idx_mask <= CacheIdxMaskxDP;
    if NARROW_BURST_SUPPORT = true then
      v_request_len := unsigned('0' & s_request_len_bytes)+1;
      if CachingActivexDP = '0' then
        cache_idx_mask <= std_logic_vector(s_request_len_bytes(CACHE_SIZE_BITS-1 downto DATASTREAM_WIDTH_BITS));
        cached_req_len <= std_logic_vector(v_request_len(CACHE_SIZE_BITS downto DATASTREAM_WIDTH_BITS));
      end if;
      if s_request.burst = "10" then
        -- burst always have length 2^x, no further check considered!
        caching_active <= '1';
      end if;
    else
      if s_request.burst = "10" and s_request_len_bytes = "000011111" then
        caching_active <= '1';
      end if;
    end if;
  end process caching_state;

  mux : process(s_request, m_request_ready, cache_input, cache_output, cache_input_ready, cache_output_ready, caching_active) is
  begin
    cache_output_ready <= m_request_ready;
    cache_input        <= s_request;
    if caching_active = '1' then
      m_request       <= cache_output;
      s_request_ready <= cache_input_ready;
    else
      m_request       <= s_request;
      s_request_ready <= m_request_ready;
    end if;
  end process mux;

  cache : process (cache_output_ready, cache_input, caching_active, CachexDP, CacheStatexDP, ReadIndexxDP, StreamxDP, CachingActivexDP, CachedElementsxDP,
                   CachedReqLenxDP, cached_req_len, CacheIdxMaskxDP, cache_idx_mask) is
    variable cache_index         : integer;
    variable cache_offset        : unsigned(CACHE_ELEMENTS_BITS-1 downto 0);
    variable read_index          : integer;
    variable read_index_unsigned : unsigned(CACHE_ELEMENTS_BITS-1 downto 0);
    variable virt_address        : integer;
    variable cache_ready         : std_logic;
    variable cache_filled        : std_logic;
  begin
    ReadIndexxDN      <= ReadIndexxDP;
    CachexDN          <= CachexDP;
    CacheStatexDN     <= CacheStatexDP;
    StreamxDN         <= StreamxDP;
    CachingActivexDN  <= CachingActivexDP;
    CachedElementsxDN <= CachedElementsxDP;
    CachedReqLenxDN   <= CachedReqLenxDP;
    CacheIdxMaskxDN   <= CacheIdxMaskxDP;

    cache_input_ready  <= '0';
    cache_output       <= StreamxDP;
    cache_output.valid <= '0';

    if caching_active = '1' and
      ((NARROW_BURST_SUPPORT = true and CachedElementsxDP /= cached_req_len) or
       (NARROW_BURST_SUPPORT = false and to_integer(unsigned(CachedElementsxDP)) /= CACHE_ELEMENTS)) then
      if cache_input.valid = '1' then

        if NARROW_BURST_SUPPORT = false then
          cache_index := to_integer(unsigned(cache_input.virt_address(CACHE_SIZE_BITS-1 downto DATASTREAM_WIDTH_BITS)));
        else
          cache_index := to_integer(unsigned(cache_input.virt_address(CACHE_SIZE_BITS-1 downto DATASTREAM_WIDTH_BITS) and cache_idx_mask));  -- mod cached_req_len
        end if;

        CachingActivexDN <= '1';
        if CachingActivexDP = '0' then
          CachedReqLenxDN        <= cached_req_len;
          CacheIdxMaskxDN        <= cache_idx_mask;
          StreamxDN              <= cache_input;
          StreamxDN.last_request <= '1';
        end if;
        StreamxDN.error <= cache_input.error;

        CachexDN(cache_index)      <= cache_input.data(DATASTREAM_WIDTH-1 downto 0);
        CacheStatexDN(cache_index) <= '1';
        CachedElementsxDN          <= std_logic_vector(unsigned(CachedElementsxDP)+1);

        cache_input_ready <= '1';
      end if;
    end if;

    if CachingActivexDP = '1' then
      cache_offset := unsigned(StreamxDP.address(CACHE_SIZE_BITS-1 downto DATASTREAM_WIDTH_BITS));
      if NARROW_BURST_SUPPORT = false then
        read_index := to_integer(unsigned(ReadIndexxDP)+cache_offset) mod CACHE_ELEMENTS;
      else
        read_index := to_integer(unsigned(std_logic_vector(unsigned(ReadIndexxDP)+cache_offset) and CacheIdxMaskxDP));  -- mod CachedReqLenxDP;        
      end if;

      if CacheStatexDP(read_index) = '1' then
        cache_output.data         <= (DATASTREAM_DATA_WIDTH-1 downto DATASTREAM_WIDTH => '0') & CachexDP(read_index);
        cache_output.virt_address <= (others                                          => '0');
        cache_output.valid        <= '1';
        if cache_output_ready = '1' then
          CacheStatexDN(read_index) <= '0';
          read_index_unsigned       := unsigned(ReadIndexxDP) + 1;
          ReadIndexxDN              <= std_logic_vector(read_index_unsigned);
          if (NARROW_BURST_SUPPORT = false and to_integer(read_index_unsigned) = 0) or
            (NARROW_BURST_SUPPORT = true and to_integer(read_index_unsigned) = to_integer(unsigned(CachedReqLenxDP(CACHE_ELEMENTS_BITS-1 downto 0)))) then
            CachingActivexDN  <= '0';
            ReadIndexxDN      <= (others => '0');
            CachedElementsxDN <= (others => '0');
            CachedReqLenxDN   <= (others => '0');
            CacheIdxMaskxDN   <= (others => '0');
          end if;
        end if;
      end if;
    end if;

  end process cache;

end behavioral;
