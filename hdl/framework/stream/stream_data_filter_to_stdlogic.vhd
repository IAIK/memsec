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
entity stream_data_filter_to_stdlogic is
  generic(
    DATASTREAM_OUT_WIDTH : integer := 64;
    TREE_FILTER          : boolean := false;
    DATA_LEAF_FILTER     : boolean := false
    );
  port(
    -- Ports of Axi Slave Bus Interface S_AXI
    clk    : in std_logic;
    resetn : in std_logic;

    s_request       : in  StreamType;
    s_request_ready : out std_logic;

    m_request             : out std_logic_vector(DATASTREAM_OUT_WIDTH-1 downto 0);
    m_request_address     : out std_logic_vector(ADDRESS_WIDTH-1 downto 0);
    m_request_is_read     : out std_logic;
    m_request_read_valid  : out std_logic;
    m_request_read_ready  : in  std_logic;
    m_request_write_valid : out std_logic;
    m_request_write_ready : in  std_logic;
    m_request_cache_valid : out std_logic;
    m_request_cache_ready : in  std_logic
    );
end stream_data_filter_to_stdlogic;

architecture structural of stream_data_filter_to_stdlogic is
  signal request : StreamType;

  signal m_request_valid, m_request_ready, req_write_active : std_logic;
  signal request_ready                                      : std_logic;

  signal request_field_offset : std_logic_vector(offset_width(DATASTREAM_DATA_WIDTH, DATASTREAM_OUT_WIDTH)-1 downto 0);
  signal output_field_offset  : std_logic_vector(offset_width(DATASTREAM_DATA_WIDTH, DATASTREAM_OUT_WIDTH)-1 downto 0);
  signal last_input           : std_logic;
begin

  data_filter : entity work.stream_data_block_filter
    generic map (
      DATASTREAM_OUT_WIDTH => DATASTREAM_DATA_WIDTH,
      TREE_FILTER          => TREE_FILTER,
      DATA_LEAF_FILTER     => DATA_LEAF_FILTER
      )
    port map (
      clk    => clk,
      resetn => resetn,

      s_request       => s_request,
      s_request_ready => s_request_ready,

      m_request       => request,
      m_request_ready => request_ready
      );

  request_field_offset <= slice_bits(request.virt_address, DATASTREAM_DATA_WIDTH/8, DATASTREAM_OUT_WIDTH/8);
  last_input           <= '1' when request_field_offset = ones(request_field_offset'length) else '0';

  rate_conversion : entity work.rate_converter
    generic map(
      IN_DATA_WIDTH  => DATASTREAM_DATA_WIDTH,
      OUT_DATA_WIDTH => DATASTREAM_OUT_WIDTH,
      REGISTERED     => false
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_field_offset => request_field_offset,
      in_field_len    => (others => '1'),

      in_last  => last_input,
      in_data  => request.data,
      in_valid => request.valid,
      in_ready => request_ready,

      out_data         => m_request,
      out_last         => open,
      out_field_offset => output_field_offset,
      out_field_len    => open,
      out_valid        => m_request_valid,
      out_ready        => m_request_ready
      );

  m_request_address <= set_bits(request.address, output_field_offset, DATASTREAM_DATA_WIDTH/8, DATASTREAM_OUT_WIDTH/8);
  m_request_is_read <= request.read;

  synchronizer : entity work.ready_synchronizer
    generic map(
      OUT_WIDTH => 3
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_valid => m_request_valid,
      in_ready => m_request_ready,

      out_valid(0)  => m_request_read_valid,
      out_valid(1)  => m_request_write_valid,
      out_valid(2)  => m_request_cache_valid,
      out_active(0) => '1',
      out_active(1) => req_write_active,
      out_active(2) => '1',
      out_ready(0)  => m_request_read_ready,
      out_ready(1)  => m_request_write_ready,
      out_ready(2)  => m_request_cache_ready
      );

  req_write_active <= not(request.read);

end structural;
