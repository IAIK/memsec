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

--! Replaces a data block within a tree memory transaction.
--!
--! Used to update nonces/keys within the data part of the inner tree nodes.
entity stream_treedata_modifier is
  generic(
    METADATA_WIDTH : integer := DATASTREAM_DATA_WIDTH
    );
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    metadata       : in  std_logic_vector(METADATA_WIDTH-1 downto 0);
    metadata_valid : in  std_logic;
    metadata_ready : out std_logic;

    s_request       : in  StreamType;
    s_request_ready : out std_logic;

    m_request       : out StreamType;
    m_request_ready : in  std_logic
    );
end stream_treedata_modifier;

architecture arch_imp of stream_treedata_modifier is
  signal data               : BlockStreamType;
  signal data_address       : AddressType;
  signal data_address_valid : std_logic;
  signal data_ready         : std_logic;

  signal metadata_out                                              : std_logic_vector(DATASTREAM_DATA_WIDTH-1 downto 0);
  signal metadata_out_offset                                       : std_logic_vector(offset_width(DATASTREAM_DATA_WIDTH, METADATA_WIDTH)-1 downto 0);
  signal metadata_out_last, metadata_out_valid, metadata_out_ready : std_logic;
begin

  metadata_rate_converter : entity work.rate_converter
    generic map(
      IN_DATA_WIDTH  => METADATA_WIDTH,
      OUT_DATA_WIDTH => DATASTREAM_DATA_WIDTH,
      REGISTERED     => false
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_field_offset => (others => '0'),
      in_field_len    => (others => '1'),

      in_last  => '1',
      in_data  => metadata,
      in_valid => metadata_valid,
      in_ready => metadata_ready,

      out_data         => metadata_out,
      out_last         => metadata_out_last,
      out_field_offset => metadata_out_offset,
      out_field_len    => open,
      out_valid        => metadata_out_valid,
      out_ready        => metadata_out_ready
      );

  modifier : entity work.stream_data_modifier
    generic map(
      MATCH_TYPE      => 0,             --  virtual addresses should be matched
      IGNORE_METADATA => true,
      IGNORE_TREE_REQ => false,
      IGNORE_DATA_REQ => true
      )
    port map (
      clk    => clk,
      resetn => resetn,

      s_data               => data,
      s_data_address       => data_address,
      s_data_address_valid => data_address_valid,
      s_data_ready         => data_ready,

      s_request       => s_request,
      s_request_ready => s_request_ready,

      m_request       => m_request,
      m_request_ready => m_request_ready
      );

  work : process(data_ready, metadata_out, metadata_out_valid, metadata_out_last,
                 s_request.address, s_request.request_type, s_request.valid,
                 metadata_out_offset) is
  begin
    data               <= BlockStreamType_default;
    metadata_out_ready <= '0';
    data_address       <= (others => '0');
    data_address_valid <= '0';

    if s_request.valid = '1' and (s_request.request_type = REQ_TYPE_TREE_ROOT or s_request.request_type = REQ_TYPE_TREE) then
      data_address_valid <= '1';
      data_address       <= set_bits(s_request.address, metadata_out_offset, DATASTREAM_DATA_WIDTH/8, METADATA_WIDTH/8);
      data.strobes       <= (others => '1');
      data.last          <= metadata_out_last;
      data.valid         <= metadata_out_valid;
      data.data          <= metadata_out;
      metadata_out_ready <= data_ready;
    end if;
  end process work;

end arch_imp;
