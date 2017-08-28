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

--! [Master] Translates requests on the internal stream into AXI read requests.
entity memory_read_issuer is
  generic(
    C_M_AXI_ID_WIDTH     : integer := 12;
    C_M_AXI_ADDR_WIDTH   : integer := 32;
    C_M_AXI_DATA_WIDTH   : integer := 32;
    C_M_AXI_ARUSER_WIDTH : integer := 0
    );
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    m_axi_arid    : out std_logic_vector(C_M_AXI_ID_WIDTH - 1 downto 0);
    m_axi_araddr  : out std_logic_vector(C_M_AXI_ADDR_WIDTH - 1 downto 0);
    m_axi_arlen   : out std_logic_vector(7 downto 0);
    m_axi_arsize  : out std_logic_vector(2 downto 0);
    m_axi_arburst : out std_logic_vector(1 downto 0);
    m_axi_arlock  : out std_logic;
    m_axi_arcache : out std_logic_vector(3 downto 0);
    m_axi_arprot  : out std_logic_vector(2 downto 0);
    m_axi_arqos   : out std_logic_vector(3 downto 0);
    m_axi_aruser  : out std_logic_vector(C_M_AXI_ARUSER_WIDTH - 1 downto 0);
    m_axi_arvalid : out std_logic;
    m_axi_arready : in  std_logic;

    s_request       : in  StreamType;
    s_request_ready : out std_logic;

    m_request       : out StreamType;
    m_request_ready : in  std_logic
    );
end memory_read_issuer;

architecture arch_imp of memory_read_issuer is
  constant ASIZE : std_logic_vector(2 downto 0) := std_logic_vector(to_unsigned(log2_ceil(C_M_AXI_DATA_WIDTH/8), 3));

  signal reqxDP, reqxDN             : StreamType;
  signal requestedxDP, requestedxDN : std_logic;

  signal masked_reg : StreamType;

  -- helper signals for the read address stream
  signal axi_araddr  : std_logic_vector(C_M_AXI_ADDR_WIDTH - 1 downto 0);
  signal axi_arlen   : std_logic_vector(7 downto 0);
  signal axi_arcache : std_logic_vector(3 downto 0);
  signal axi_arprot  : std_logic_vector(2 downto 0);
  signal axi_arvalid : std_logic;
  signal axi_arqos   : std_logic_vector(3 downto 0);
  signal axi_arlock  : std_logic;
begin

  regs : process(clk) is
  begin
    if rising_edge(clk) then
      if resetn = '0' then
        reqxDP       <= StreamType_default;
        requestedxDP <= '0';
      else
        reqxDP       <= reqxDN;
        requestedxDP <= requestedxDN;
      end if;
    end if;
  end process regs;

  mask : process(requestedxDP, reqxDP) is
  begin
    masked_reg       <= reqxDP;
    masked_reg.valid <= reqxDP.valid and (requestedxDP or reqxDP.metadata);
  end process mask;
  m_request <= masked_reg;

  work : process(axi_arvalid, m_axi_arready, m_request_ready, masked_reg.valid,
                 requestedxDP, reqxDP, s_request) is
    constant LENGTH_SHIFT_WIDTH : integer := log2_ceil(DATASTREAM_DATA_WIDTH/C_M_AXI_DATA_WIDTH);
    variable bypass             : boolean;
  begin
    reqxDN       <= reqxDP;
    requestedxDN <= requestedxDP;

    s_request_ready <= '0';
    axi_araddr      <= (others => '0');
    axi_arlen       <= (others => '0');
    axi_arcache     <= (others => '0');
    axi_arprot      <= (others => '0');
    axi_arvalid     <= '0';
    axi_arqos       <= (others => '0');
    axi_arlock      <= '0';

    bypass := false;

    if masked_reg.valid = '1' and m_request_ready = '1' then
      reqxDN.valid <= '0';
      requestedxDN <= '0';
      bypass       := true;
    end if;

    -- register is empty
    -- forward the new request directly from the input
    if s_request.valid = '1' and (reqxDP.valid = '0' or bypass) then
      reqxDN          <= s_request;
      s_request_ready <= '1';
      if s_request.metadata = '0' then
        axi_araddr  <= s_request.block_address(C_M_AXI_ADDR_WIDTH-1 downto 0);
        axi_arlen   <= s_request.block_len(AXI_LEN_WIDTH-LENGTH_SHIFT_WIDTH-1 downto 0) & ones(LENGTH_SHIFT_WIDTH);
        axi_arcache <= s_request.cache;
        axi_arprot  <= s_request.prot;
        axi_arqos   <= s_request.qos;
        axi_arlock  <= s_request.lock;
        axi_arvalid <= '1';
      end if;
    -- or make the request from the meta register if it has not been accepted yet
    elsif reqxDP.valid = '1' and reqxDP.metadata = '0' and requestedxDP = '0' then
      axi_araddr  <= reqxDP.block_address(C_M_AXI_ADDR_WIDTH-1 downto 0);
      axi_arlen   <= reqxDP.block_len(AXI_LEN_WIDTH-LENGTH_SHIFT_WIDTH-1 downto 0) & ones(LENGTH_SHIFT_WIDTH);
      axi_arcache <= reqxDP.cache;
      axi_arprot  <= reqxDP.prot;
      axi_arqos   <= reqxDP.qos;
      axi_arlock  <= reqxDP.lock;
      axi_arvalid <= '1';
    end if;

    -- remember if the request has already been accepted
    if axi_arvalid = '1' and m_axi_arready = '1' then
      requestedxDN <= '1';
    end if;
  end process work;

  -- map read address stream
  m_axi_arid    <= (others => '0');  -- the data should arrive in the requested order
  m_axi_araddr  <= axi_araddr;
  m_axi_arlen   <= axi_arlen;
  m_axi_arsize  <= ASIZE;
  m_axi_arburst <= "01";  -- all requests towards the memory are incremental
  m_axi_arlock  <= axi_arlock;
  m_axi_arcache <= axi_arcache;
  m_axi_arprot  <= axi_arprot;
  m_axi_arqos   <= axi_arqos;
  m_axi_aruser  <= (others => '0');     -- no user data support
  m_axi_arvalid <= axi_arvalid;

end arch_imp;
