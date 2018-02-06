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

--! Filters the internal stream according to the original request.
--!
--! Only blocks which are necessary to answer the original request get
--! forwarded. All other data beats are simply dropped.
entity stream_data_block_filter is
  generic(
    DATASTREAM_OUT_WIDTH : integer := 32;
    REGISTERED           : boolean := false;
    TREE_FILTER          : boolean := false;  -- passthrough tree nodes
    DATA_LEAF_FILTER     : boolean := false;  -- passthrough data leaf nodes
    ERROR_ACCUMULATION   : boolean := false
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
end stream_data_block_filter;

architecture behavioral of stream_data_block_filter is
  constant TRANSLATION_FACTOR      : integer                                     := (DATASTREAM_DATA_WIDTH/DATASTREAM_OUT_WIDTH);
  constant TRANSLATION_FACTOR_BIT  : integer                                     := log2_ceil(TRANSLATION_FACTOR);
  constant DATASTREAM_ADDR_BIT     : integer                                     := log2_ceil(DATASTREAM_DATA_WIDTH/8);
  constant DATASTREAM_OUT_ADDR_BIT : integer                                     := log2_ceil(DATASTREAM_OUT_WIDTH/8);
  constant MAX_COUNTER_VALUE       : unsigned(TRANSLATION_FACTOR_BIT-1 downto 0) := (others => '1');

  type tASizeToMaskLUT is array (0 to 2**2 - 1) of std_logic_vector(1 downto 0);
  constant ASIZE_MASKING_LUT : tASizeToMaskLUT := (
    0 => "11",
    1 => "10",
    2 => "00",
    3 => "00");

  signal out_block                                        : std_logic_vector(DATASTREAM_OUT_WIDTH-1 downto 0);
  signal out_block_addr                                   : std_logic_vector(TRANSLATION_FACTOR_BIT-1 downto 0);
  signal out_block_valid, out_block_ready, out_block_last : std_logic;

  signal in_block                       : std_logic_vector(DATASTREAM_DATA_WIDTH-1 downto 0);
  signal in_block_valid, in_block_ready : std_logic;

  signal start_address : unsigned(ADDRESS_WIDTH-1 downto 0);
  signal end_address   : unsigned(ADDRESS_WIDTH-1 downto 0);

  signal request_ready : std_logic;

  signal StreamxDP, StreamxDN       : StreamType;
  signal InitReadxDBP, InitReadxDBN : std_logic;
  signal ErrorAccxDP, ErrorAccxDN   : std_logic;

  signal delayed_request, filtered_request : StreamType;
  signal filtered_request_ready            : std_logic;
  signal address_exceeded                  : std_logic;
begin

  regs : process(clk) is
  begin
    if rising_edge(clk) then
      if resetn = '0' then
        StreamxDP    <= StreamType_default;
        ErrorAccxDP  <= '0';
        InitReadxDBP <= '0';
      else
        StreamxDP    <= StreamxDN;
        ErrorAccxDP  <= ErrorAccxDN;
        InitReadxDBP <= InitReadxDBN;
      end if;
    end if;
  end process regs;

  data_serialization : entity work.serialization
    generic map(
      IN_DATA_WIDTH  => DATASTREAM_DATA_WIDTH,
      OUT_DATA_WIDTH => DATASTREAM_OUT_WIDTH,
      REGISTERED     => false
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_last         => '1',
      in_data         => in_block,
      in_field_offset => (others => '0'),
      in_field_len    => (others => '1'),
      in_valid        => in_block_valid,
      in_ready        => in_block_ready,

      out_data         => out_block,
      out_field_offset => out_block_addr,
      out_last         => out_block_last,
      out_valid        => out_block_valid,
      out_ready        => out_block_ready
      );

  address_comp : process (s_request, request_ready)
    variable vSize         : unsigned(s_request.size'length-1 downto 0);
    variable vTmp          : std_logic_vector(ADDRESS_WIDTH-1 downto 0);
    variable vStartAddress : unsigned(ADDRESS_WIDTH-1 downto 0);
    variable vEndAddress   : unsigned(ADDRESS_WIDTH-1 downto 0);
    variable vWrapBoundary : unsigned(ADDRESS_WIDTH-1 downto 0);
    variable vLenBytes     : unsigned(s_request.len'length + 1 downto 0);
  begin
    -- Compute start and end address
    vSize                           := shift_left((vSize'left downto 1              => '0') & '1', to_integer(unsigned(s_request.size)));
    vTmp                            := s_request.address(ADDRESS_WIDTH - 1 downto 2) & (s_request.address(1 downto 0) and ASIZE_MASKING_LUT(to_integer(unsigned(s_request.size))));
    vStartAddress                   := unsigned(vTmp);
    assert(unsigned(s_request.size) <= DATASTREAM_OUT_ADDR_BIT);
    vTmp                            := (ADDRESS_WIDTH-1 downto s_request.len'length => '0') & s_request.len;
    vEndAddress                     := vStartAddress + (unsigned(vTmp) sll to_integer(unsigned(s_request.size)));
    start_address                   <= vStartAddress;
    end_address                     <= vEndAddress;

    -- Compute wrap boundary
    vLenBytes := "00" & unsigned(s_request.len);
    vLenBytes := (vLenBytes sll to_integer(unsigned(s_request.size))) or unsigned(dynamic_mask(to_integer(unsigned(s_request.size)), vLenBytes'length));

    vTmp                                    := (others                                      => '1');
    vTmp(s_request.len'length + 1 downto 0) := not(std_logic_vector(vLenBytes));
    vWrapBoundary                           := vStartAddress and unsigned(vTmp);
    vTmp                                    := (ADDRESS_WIDTH-1 downto s_request.len'length => '0') & s_request.len;
    vEndAddress                             := vWrapBoundary + (unsigned(vTmp) sll to_integer(unsigned(s_request.size)));

    if s_request.burst = "10" then
      start_address <= vWrapBoundary;
      end_address   <= vEndAddress;
    end if;
  end process address_comp;

  s_request_ready <= request_ready;

  input_filter : process (s_request, filtered_request_ready, end_address, start_address)
    variable vAddress : unsigned(ADDRESS_WIDTH-1 downto 0);
  begin
    -- Defaults
    request_ready    <= filtered_request_ready;
    filtered_request <= s_request;
    address_exceeded <= '0';

    if (s_request.valid = '1') then
      -- Metadata filter
      if s_request.metadata = '1' then
        if ERROR_ACCUMULATION and to_integer(unsigned(s_request.block_len)) = 0 then
          request_ready <= filtered_request_ready;
        else
          filtered_request.valid <= '0';
          request_ready          <= '1';
        end if;
      end if;
      -- Tree Node Filter
      if TREE_FILTER = true and s_request.request_type = REQ_TYPE_DATA then
        filtered_request.valid <= '0';
        request_ready          <= '1';
      end if;
      -- Data Node Filter
      if DATA_LEAF_FILTER = true and (s_request.request_type = REQ_TYPE_TREE or
                                      s_request.request_type = REQ_TYPE_TREE_ROOT) then
        filtered_request.valid <= '0';
        request_ready          <= '1';
      end if;
      -- Address filter
      if ERROR_ACCUMULATION = false or
        not(to_integer(unsigned(s_request.block_len)) = 0 and s_request.metadata = '1') then
        vAddress                                  := unsigned(s_request.virt_address);
        if (vAddress + (DATASTREAM_DATA_WIDTH/8)) <= start_address then
          filtered_request.valid <= '0';
          request_ready          <= '1';
        end if;
        if vAddress > end_address then
          filtered_request.valid <= '0';
          request_ready          <= '1';
          address_exceeded       <= not(s_request.metadata);
        end if;
      end if;
    end if;
  end process input_filter;

  error_comb : process(filtered_request, delayed_request, s_request, StreamxDP, ErrorAccxDP, InitReadxDBP, address_exceeded, in_block_ready) is
  begin
    -- Register defaults
    StreamxDN    <= StreamxDP;
    ErrorAccxDN  <= ErrorAccxDP;
    InitReadxDBN <= InitReadxDBP;

    in_block_valid <= filtered_request.valid;
    in_block       <= filtered_request.data;

    if ERROR_ACCUMULATION then
      if s_request.valid = '1' then
        ErrorAccxDN <= ErrorAccxDP or s_request.error;  -- errors are accumulated
      end if;
    end if;

    if ERROR_ACCUMULATION and filtered_request.request_type = REQ_TYPE_DATA then
      filtered_request_ready <= in_block_ready;
      delayed_request        <= filtered_request;
      -- Delay stage
      delayed_request        <= StreamxDP;
      if InitReadxDBP = '0' then
        if filtered_request.valid = '1' then
          StreamxDN              <= filtered_request;
          filtered_request_ready <= '1';
          InitReadxDBN           <= '1';
        end if;
      else
        if address_exceeded = '1' then
          delayed_request.valid  <= '0';
          filtered_request_ready <= '1';
        else
          delayed_request.valid <= filtered_request.valid;
          if in_block_ready = '1' then
            StreamxDN <= filtered_request;
          end if;
        end if;
      end if;
      if to_integer(unsigned(s_request.block_len)) = 0 and s_request.metadata = '1' and s_request.valid = '1' then
        delayed_request.valid <= '1';
      end if;

      -- Error and Delay Stage reset
      if to_integer(unsigned(s_request.block_len)) = 0 and s_request.metadata = '1' and s_request.valid = '1' then
        -- the tag information 
        if s_request.last_request = '1' then
          if in_block_ready = '1' then
            ErrorAccxDN <= '0';
          end if;
        end if;
        if in_block_ready = '1' then
          StreamxDN    <= StreamType_default;
          InitReadxDBN <= '0';
        end if;
      end if;

      in_block       <= delayed_request.data;
      in_block_valid <= delayed_request.valid;

    else
      delayed_request        <= filtered_request;
      in_block               <= filtered_request.data;
      in_block_valid         <= filtered_request.valid;
      filtered_request_ready <= in_block_ready;
    end if;

  end process;

  output_filter : process(delayed_request, m_request_ready, out_block, out_block_addr, out_block_last,
                          out_block_valid, out_block_ready, start_address, end_address, ErrorAccxDP)
    variable vOutBlockCounter : std_logic_vector(TRANSLATION_FACTOR_BIT-1 downto 0);
    variable vVirtAddress     : unsigned(ADDRESS_WIDTH-1 downto 0);
    variable vVirtAddressSL   : std_logic_vector(ADDRESS_WIDTH-1 downto 0);
    variable vTmp             : unsigned(ADDRESS_WIDTH-1 downto 0);
  begin
    m_request               <= delayed_request;
    m_request.block_len     <= (others => '0');
    m_request.block_address <= (others => '0');
    m_request.valid         <= out_block_valid;
    m_request.error         <= ErrorAccxDP;

    out_block_ready <= m_request_ready;

    -- Adapt output addresses and lengths
    vOutBlockCounter       := std_logic_vector(MAX_COUNTER_VALUE - unsigned(out_block_addr));
    vVirtAddressSL         := delayed_request.virt_address(delayed_request.virt_address'length-1 downto DATASTREAM_ADDR_BIT) & out_block_addr & (DATASTREAM_OUT_ADDR_BIT-1 downto 0 => '0');
    vVirtAddress           := unsigned(vVirtAddressSL);
    vTmp                   := end_address - vVirtAddress;
    m_request.virt_address <= vVirtAddressSL;

    -- Write output data
    if DATASTREAM_DATA_WIDTH = DATASTREAM_OUT_WIDTH then
      m_request.data <= out_block;
    else
      m_request.data <= ((DATASTREAM_DATA_WIDTH-1) downto DATASTREAM_OUT_WIDTH => '0') & out_block;
    end if;

    -- Filter according to addresses
    if ((vVirtAddress + (DATASTREAM_OUT_WIDTH/8)) <= start_address or
        vVirtAddress > end_address) then
      m_request.valid <= '0';
      out_block_ready <= '1';
    end if;

  end process output_filter;

end behavioral;
