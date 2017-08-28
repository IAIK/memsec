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

--! [Slave] Merges data received via the AXI write channel into the internal data stream.
entity cpu_write_data is
  generic(
    C_S_AXI_DATA_WIDTH  : integer := 32;
    C_S_AXI_WUSER_WIDTH : integer := 0
    );
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    s_axi_wdata  : in  std_logic_vector(C_S_AXI_DATA_WIDTH - 1 downto 0);
    s_axi_wstrb  : in  std_logic_vector((C_S_AXI_DATA_WIDTH / 8) - 1 downto 0);
    s_axi_wlast  : in  std_logic;
    s_axi_wuser  : in  std_logic_vector(C_S_AXI_WUSER_WIDTH - 1 downto 0);
    s_axi_wvalid : in  std_logic;
    s_axi_wready : out std_logic;

    s_request       : in  StreamType;
    s_request_ready : out std_logic;

    m_request       : out StreamType;
    m_request_ready : in  std_logic
    );
end cpu_write_data;

architecture arch_imp of cpu_write_data is
  signal to_extractor, to_axideser, to_modifier                   : StreamType;
  signal to_extractor_ready, to_axideser_ready, to_modifier_ready : std_logic;

  signal data         : BlockStreamType;
  signal data_address : AddressType;
  signal data_ready   : std_logic;
begin
  synchronizer : entity work.stream_ready_synchronizer
    generic map(
      OUT_WIDTH => 2,
      REGISTERS => 0
      )
    port map (
      clk    => clk,
      resetn => resetn,

      s_request       => s_request,
      s_request_ready => s_request_ready,

      m_requests_ready(0) => to_extractor_ready,
      m_requests_ready(1) => to_modifier_ready,

      m_requests_active(0) => '1',
      m_requests_active(1) => '1',

      m_requests(0) => to_extractor,
      m_requests(1) => to_modifier
      );

  -- extract the original request from the internal data stream by dropping
  -- all the data beats
  extractor : entity work.stream_request_extractor
    port map (
      clk    => clk,
      resetn => resetn,

      s_request       => to_extractor,
      s_request_ready => to_extractor_ready,

      m_request       => to_axideser,
      m_request_ready => to_axideser_ready
      );

  -- decode AXI write channel into stream of aligned data blocks incl. strobes
  -- and address but without narrow transfer support
  deserialization : entity work.axi_deserialization
    generic map(
      ADDR_WIDTH     => ADDRESS_WIDTH,
      IN_DATA_WIDTH  => C_S_AXI_DATA_WIDTH,
      OUT_DATA_WIDTH => DATASTREAM_DATA_WIDTH
      )
    port map (
      clk    => clk,
      resetn => resetn,

      wdata  => s_axi_wdata,
      wstrb  => s_axi_wstrb,
      wlast  => s_axi_wlast,
      wvalid => s_axi_wvalid,
      wready => s_axi_wready,

      s_request       => to_axideser,
      s_request_ready => to_axideser_ready,

      m_data         => data,
      m_data_address => data_address,
      m_data_ready   => data_ready
      );

  -- perform the actual modification of the internal data stream
  modifier : entity work.stream_data_modifier
    generic map(
      MATCH_TYPE      => 0,     -- virtual addresses should be matched
      IGNORE_METADATA => true,  -- don't touch metadata
      IGNORE_TREE_REQ => true,  -- don't touch tree requests
      IGNORE_DATA_REQ => false  -- modify real data
      )
    port map (
      clk    => clk,
      resetn => resetn,

      s_data               => data,
      s_data_address       => data_address,
      s_data_address_valid => data.valid,
      s_data_ready         => data_ready,

      s_request       => to_modifier,
      s_request_ready => to_modifier_ready,

      m_request       => m_request,
      m_request_ready => m_request_ready
      );

end arch_imp;
