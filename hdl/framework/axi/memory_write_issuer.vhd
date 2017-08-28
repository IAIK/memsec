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

--! [Master] Translates requests on the internal stream into AXI write requests.
entity memory_write_issuer is
  generic(
    C_M_AXI_ID_WIDTH     : integer := 6;
    C_M_AXI_ADDR_WIDTH   : integer := 32;
    C_M_AXI_DATA_WIDTH   : integer := 32;
    C_M_AXI_AWUSER_WIDTH : integer := 0;
    IGNORE_METADATA      : boolean := true
    );
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    m_axi_awid    : out std_logic_vector(C_M_AXI_ID_WIDTH - 1 downto 0);
    m_axi_awaddr  : out std_logic_vector(C_M_AXI_ADDR_WIDTH - 1 downto 0);
    m_axi_awlen   : out std_logic_vector(7 downto 0);
    m_axi_awsize  : out std_logic_vector(2 downto 0);
    m_axi_awburst : out std_logic_vector(1 downto 0);
    m_axi_awlock  : out std_logic;
    m_axi_awcache : out std_logic_vector(3 downto 0);
    m_axi_awprot  : out std_logic_vector(2 downto 0);
    m_axi_awqos   : out std_logic_vector(3 downto 0);
    m_axi_awuser  : out std_logic_vector(C_M_AXI_AWUSER_WIDTH - 1 downto 0);
    m_axi_awvalid : out std_logic;
    m_axi_awready : in  std_logic;

    s_request       : in  StreamType;
    s_request_ready : out std_logic;

    m_request       : out StreamType;
    m_request_ready : in  std_logic
    );
end memory_write_issuer;

architecture arch_imp of memory_write_issuer is
  constant LENGTH_SHIFT_WIDTH : integer := log2_ceil(DATASTREAM_DATA_WIDTH/C_M_AXI_DATA_WIDTH);

  -- helper signals for the write address stream
  signal axi_awaddr  : std_logic_vector(C_M_AXI_ADDR_WIDTH - 1 downto 0);
  signal axi_awlen   : std_logic_vector(7 downto 0);
  signal axi_awcache : std_logic_vector(3 downto 0);
  signal axi_awprot  : std_logic_vector(2 downto 0);
  signal axi_awvalid : std_logic;
  signal axi_awqos   : std_logic_vector(3 downto 0);
  signal axi_awlock  : std_logic;

  -- registers to remember the state across multiple beats of the request or transfer
  signal req_sentxDP, req_sentxDN : std_logic;

  signal request_ready                  : std_logic;
  signal req_send_valid, req_send_ready : std_logic;
  signal m_request_valid                : std_logic;
begin

  regs : process(clk) is
  begin
    if rising_edge(clk) then
      if resetn = '0' then
        req_sentxDP <= '0';
      else
        req_sentxDP <= req_sentxDN;
      end if;
    end if;
  end process regs;

  send_addr : process(axi_awvalid, m_axi_awready, req_send_valid, req_sentxDP,
                      request_ready, s_request.block_address, s_request.metadata,
                      s_request.block_len, s_request.cache, s_request.lock,
                      s_request.prot, s_request.qos, s_request.valid) is
    variable ignore_block : std_logic;
  begin
    req_sentxDN <= req_sentxDP;

    axi_awaddr  <= (others => '0');
    axi_awlen   <= (others => '0');
    axi_awcache <= (others => '0');
    axi_awprot  <= (others => '0');
    axi_awqos   <= (others => '0');
    axi_awlock  <= '0';
    axi_awvalid <= '0';

    req_send_ready <= '0';

    ignore_block := to_std_logic(IGNORE_METADATA) and s_request.metadata;

    -- remember when a request has been accepted
    if axi_awvalid = '1' and m_axi_awready = '1' then
      req_sentxDN <= '1';
    end if;

    -- acknowledged beats as long as the request is not finished
    if req_send_valid = '1' and (req_sentxDP = '1' or ignore_block = '1') then
      req_send_ready <= '1';
    end if;

    -- and reset as soon as the request ends
    if s_request.valid = '1' and unsigned(s_request.block_len) = 0 and request_ready = '1' then
      req_sentxDN <= '0';
    end if;

    -- send the address to the memory
    if req_send_valid = '1' and req_sentxDP = '0' and ignore_block = '0' then
      axi_awaddr  <= s_request.block_address;
      axi_awlen   <= s_request.block_len(AXI_LEN_WIDTH-LENGTH_SHIFT_WIDTH-1 downto 0) & ones(LENGTH_SHIFT_WIDTH);
      axi_awcache <= s_request.cache;
      axi_awprot  <= s_request.prot;
      axi_awqos   <= s_request.qos;
      axi_awlock  <= s_request.lock;
      axi_awvalid <= '1';
    end if;
  end process send_addr;

  forward_data : process(m_request_valid, s_request) is
  begin
    m_request       <= s_request;
    m_request.valid <= m_request_valid;
  end process forward_data;

  ready_synchronizer : entity work.ready_synchronizer
    generic map(
      OUT_WIDTH => 2
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_valid => s_request.valid,
      in_ready => request_ready,

      out_valid(0)  => req_send_valid,
      out_valid(1)  => m_request_valid,
      out_active(0) => '1',
      out_active(1) => '1',
      out_ready(0)  => req_send_ready,
      out_ready(1)  => m_request_ready
      );
  s_request_ready <= request_ready;

  -- map to master write address stream
  m_axi_awid    <= (others => '0');  -- the real id does not really matter here;
  m_axi_awaddr  <= axi_awaddr;
  m_axi_awlen   <= axi_awlen;
  m_axi_awsize  <= std_logic_vector(to_unsigned(log2_ceil(C_M_AXI_DATA_WIDTH/8), 3));
  m_axi_awburst <= "01";                -- incremental burst
  m_axi_awlock  <= axi_awlock;
  m_axi_awcache <= axi_awcache;
  m_axi_awprot  <= axi_awprot;
  m_axi_awqos   <= axi_awqos;
  m_axi_awuser  <= (others => '0');     -- no user data support
  m_axi_awvalid <= axi_awvalid;

end arch_imp;
