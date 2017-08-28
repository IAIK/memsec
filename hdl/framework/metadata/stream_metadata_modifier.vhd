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

--! Replaces the metadata block in a memory transaction.
--!
--! If the current transaction is a tree root, then the root input is
--! used. Otherwise, the metadata input is used to perform the replacement.
entity stream_metadata_modifier is
  generic(
    METADATA_WIDTH : integer := DATASTREAM_DATA_WIDTH
    );
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    metadata       : in  std_logic_vector(METADATA_WIDTH-1 downto 0);
    metadata_valid : in  std_logic;
    metadata_ready : out std_logic;

    root       : in  std_logic_vector(METADATA_WIDTH-1 downto 0);
    root_valid : in  std_logic;
    root_ready : out std_logic;

    s_request       : in  StreamType;
    s_request_ready : out std_logic;

    m_request       : out StreamType;
    m_request_ready : in  std_logic
    );
end stream_metadata_modifier;

architecture arch_imp of stream_metadata_modifier is
  signal data         : BlockStreamType;
  signal data_address : AddressType;
  signal data_ready   : std_logic;

  signal reg_metadata                           : std_logic_vector(DATASTREAM_DATA_WIDTH-1 downto 0);
  signal reg_metadata_offset                    : std_logic_vector(offset_width(DATASTREAM_DATA_WIDTH, METADATA_WIDTH)-1 downto 0);
  signal reg_metadata_valid, reg_metadata_ready : std_logic;
  signal reg_metadata_last                      : std_logic;

  signal root_out                       : std_logic_vector(DATASTREAM_DATA_WIDTH-1 downto 0);
  signal root_out_offset                : std_logic_vector(offset_width(DATASTREAM_DATA_WIDTH, METADATA_WIDTH)-1 downto 0);
  signal root_out_valid, root_out_ready : std_logic;
  signal root_out_last                  : std_logic;
begin

  metadata_rate_converter : entity work.rate_converter
    generic map(
      IN_DATA_WIDTH  => METADATA_WIDTH,
      OUT_DATA_WIDTH => DATASTREAM_DATA_WIDTH,
      REGISTERED     => true
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

      out_data         => reg_metadata,
      out_last         => reg_metadata_last,
      out_field_offset => reg_metadata_offset,
      out_field_len    => open,
      out_valid        => reg_metadata_valid,
      out_ready        => reg_metadata_ready
      );



  root_rate_converter : entity work.rate_converter
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
      in_data  => root,
      in_valid => root_valid,
      in_ready => root_ready,

      out_data         => root_out,
      out_last         => root_out_last,
      out_field_offset => root_out_offset,
      out_field_len    => open,
      out_valid        => root_out_valid,
      out_ready        => root_out_ready
      );


  modifier : entity work.stream_data_modifier
    generic map(
      MATCH_TYPE      => 2,             -- block numbers should be matched
      IGNORE_METADATA => false,
      IGNORE_TREE_REQ => false,
      IGNORE_DATA_REQ => false
      )
    port map (
      clk    => clk,
      resetn => resetn,

      s_data               => data,
      s_data_address       => data_address,
      s_data_address_valid => '1',
      s_data_ready         => data_ready,

      s_request       => s_request,
      s_request_ready => s_request_ready,

      m_request       => m_request,
      m_request_ready => m_request_ready
      );

  work : process(data_ready, reg_metadata, reg_metadata_valid, root_out,
                 root_out_valid, s_request.request_type, s_request.valid,
                 root_out_last, reg_metadata_last,
                 root_out_offset, reg_metadata_offset) is
  begin
    data               <= BlockStreamType_default;
    reg_metadata_ready <= '0';
    root_out_ready     <= '0';
    data_address       <= (others => '0');

    if s_request.valid = '1' then
      data.strobes <= (others => '1');

      if s_request.request_type = REQ_TYPE_TREE_ROOT then
        data.valid     <= root_out_valid;
        data.data      <= root_out;
        data.last      <= root_out_last;
        data_address   <= zeros(ADDRESS_WIDTH-root_out_offset'length) & root_out_offset;
        root_out_ready <= data_ready;
      else
        data.valid         <= reg_metadata_valid;
        data.data          <= reg_metadata;
        data.last          <= reg_metadata_last;
        data_address       <= zeros(ADDRESS_WIDTH-reg_metadata_offset'length) & reg_metadata_offset;
        reg_metadata_ready <= data_ready;
      end if;
    end if;
  end process work;

end arch_imp;
