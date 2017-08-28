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

entity memsec is
  generic(
    -- Parameters of Axi Slave Bus Interface S_AXI
    C_S_AXI_TARGET_SLAVE_BASE_ADDR : std_logic_vector := x"40000000";
    C_S_AXI_ID_WIDTH               : integer          := 12;
    C_S_AXI_DATA_WIDTH             : integer          := 32;
    C_S_AXI_ADDR_WIDTH             : integer          := 32;
    C_S_AXI_AWUSER_WIDTH           : integer          := 0;
    C_S_AXI_ARUSER_WIDTH           : integer          := 0;
    C_S_AXI_WUSER_WIDTH            : integer          := 0;
    C_S_AXI_RUSER_WIDTH            : integer          := 0;
    C_S_AXI_BUSER_WIDTH            : integer          := 0;

    -- Parameters of Axi Master Bus Interface M_AXI
    C_M_AXI_BURST_LEN    : integer := 16;
    C_M_AXI_ID_WIDTH     : integer := 6;
    C_M_AXI_ADDR_WIDTH   : integer := 32;
    C_M_AXI_DATA_WIDTH   : integer := 64;
    C_M_AXI_AWUSER_WIDTH : integer := 0;
    C_M_AXI_ARUSER_WIDTH : integer := 0;
    C_M_AXI_WUSER_WIDTH  : integer := 0;
    C_M_AXI_RUSER_WIDTH  : integer := 0;
    C_M_AXI_BUSER_WIDTH  : integer := 0;

    -- Generic module config
    CRYPTO_CONFIG : integer := 1; -- 0 plain, 1 Ascon, 2 TEC Tree Ascon,
                                  -- 3 Prince ECB, 4 AES ECB,
                                  -- 5 Prince CBC, 6 AES CBC,
                                  -- 7 Prince XTS, 8 AES XTS
                                  -- 9 MEAS, 10 MEAS ECB

    -- Tree specific parameters
    DATA_MEMORY_SIZE     : integer := 256*1024*1024;  --! Size of the protected memory in byte. (virtual address space)
    TREE_ARITY           : integer := 4;              --! Number of elements in one tree node.
    TREE_ROOTS           : integer := 1024;           --! Number of trees which are used to protect the data memory.
    TREE_NODE_CACHE_SIZE : integer := 1024;           --! Number of entries which can be stored in the tree node cache.

    -- Ascon specific parameters
    DATA_BLOCK_SIZE : integer := 64;   --! Size of one block in the virtual address space in byte.

    -- XTS/CBC specific parameters
    BLOCKS_PER_SECTOR : integer := 2;  --! Number of blocks which form a sector in XTS or CBC mode. (req. power of 2)
    DATA_TAG_SIZE     : integer := 16  --! Size of the data tags (for MEAS modes)
    );
  port(
    -- Ports of Axi Slave Bus Interface S_AXI
    s_axi_aclk    : in std_logic;
    s_axi_aresetn : in std_logic;

    s_axi_awid     : in  std_logic_vector(C_S_AXI_ID_WIDTH - 1 downto 0);
    s_axi_awaddr   : in  std_logic_vector(C_S_AXI_ADDR_WIDTH - 1 downto 0);
    s_axi_awlen    : in  std_logic_vector(7 downto 0);
    s_axi_awsize   : in  std_logic_vector(2 downto 0);
    s_axi_awburst  : in  std_logic_vector(1 downto 0);
    s_axi_awlock   : in  std_logic;
    s_axi_awcache  : in  std_logic_vector(3 downto 0);
    s_axi_awprot   : in  std_logic_vector(2 downto 0);
    s_axi_awqos    : in  std_logic_vector(3 downto 0);
    s_axi_awregion : in  std_logic_vector(3 downto 0);
    s_axi_awuser   : in  std_logic_vector(C_S_AXI_AWUSER_WIDTH - 1 downto 0);
    s_axi_awvalid  : in  std_logic;
    s_axi_awready  : out std_logic;
    s_axi_wdata    : in  std_logic_vector(C_S_AXI_DATA_WIDTH - 1 downto 0);
    s_axi_wstrb    : in  std_logic_vector((C_S_AXI_DATA_WIDTH / 8) - 1 downto 0);
    s_axi_wlast    : in  std_logic;
    s_axi_wuser    : in  std_logic_vector(C_S_AXI_WUSER_WIDTH - 1 downto 0);
    s_axi_wvalid   : in  std_logic;
    s_axi_wready   : out std_logic;
    s_axi_bid      : out std_logic_vector(C_S_AXI_ID_WIDTH - 1 downto 0);
    s_axi_bresp    : out std_logic_vector(1 downto 0);
    s_axi_buser    : out std_logic_vector(C_S_AXI_BUSER_WIDTH - 1 downto 0);
    s_axi_bvalid   : out std_logic;
    s_axi_bready   : in  std_logic;

    s_axi_arid     : in  std_logic_vector(C_S_AXI_ID_WIDTH - 1 downto 0);
    s_axi_araddr   : in  std_logic_vector(C_S_AXI_ADDR_WIDTH - 1 downto 0);
    s_axi_arlen    : in  std_logic_vector(7 downto 0);
    s_axi_arsize   : in  std_logic_vector(2 downto 0);
    s_axi_arburst  : in  std_logic_vector(1 downto 0);
    s_axi_arlock   : in  std_logic;
    s_axi_arcache  : in  std_logic_vector(3 downto 0);
    s_axi_arprot   : in  std_logic_vector(2 downto 0);
    s_axi_arqos    : in  std_logic_vector(3 downto 0);
    s_axi_arregion : in  std_logic_vector(3 downto 0);
    s_axi_aruser   : in  std_logic_vector(C_S_AXI_ARUSER_WIDTH - 1 downto 0);
    s_axi_arvalid  : in  std_logic;
    s_axi_arready  : out std_logic;
    s_axi_rid      : out std_logic_vector(C_S_AXI_ID_WIDTH - 1 downto 0);
    s_axi_rdata    : out std_logic_vector(C_S_AXI_DATA_WIDTH - 1 downto 0);
    s_axi_rresp    : out std_logic_vector(1 downto 0);
    s_axi_rlast    : out std_logic;
    s_axi_ruser    : out std_logic_vector(C_S_AXI_RUSER_WIDTH - 1 downto 0);
    s_axi_rvalid   : out std_logic;
    s_axi_rready   : in  std_logic;

    -- Ports of Axi Master Bus Interface M_AXI
    m_axi_aclk    : in std_logic;
    m_axi_aresetn : in std_logic;

    m_axi_awid     : out std_logic_vector(C_M_AXI_ID_WIDTH - 1 downto 0);
    m_axi_awaddr   : out std_logic_vector(C_M_AXI_ADDR_WIDTH - 1 downto 0);
    m_axi_awlen    : out std_logic_vector(7 downto 0);
    m_axi_awsize   : out std_logic_vector(2 downto 0);
    m_axi_awburst  : out std_logic_vector(1 downto 0);
    m_axi_awlock   : out std_logic;
    m_axi_awcache  : out std_logic_vector(3 downto 0);
    m_axi_awprot   : out std_logic_vector(2 downto 0);
    m_axi_awqos    : out std_logic_vector(3 downto 0);
    m_axi_awregion : out std_logic_vector(3 downto 0);
    m_axi_awuser   : out std_logic_vector(C_M_AXI_AWUSER_WIDTH - 1 downto 0);
    m_axi_awvalid  : out std_logic;
    m_axi_awready  : in  std_logic;
    m_axi_wdata    : out std_logic_vector(C_M_AXI_DATA_WIDTH - 1 downto 0);
    m_axi_wstrb    : out std_logic_vector(C_M_AXI_DATA_WIDTH / 8 - 1 downto 0);
    m_axi_wlast    : out std_logic;
    m_axi_wuser    : out std_logic_vector(C_M_AXI_WUSER_WIDTH - 1 downto 0);
    m_axi_wvalid   : out std_logic;
    m_axi_wready   : in  std_logic;
    m_axi_bid      : in  std_logic_vector(C_M_AXI_ID_WIDTH - 1 downto 0);
    m_axi_bresp    : in  std_logic_vector(1 downto 0);
    m_axi_buser    : in  std_logic_vector(C_M_AXI_BUSER_WIDTH - 1 downto 0);
    m_axi_bvalid   : in  std_logic;
    m_axi_bready   : out std_logic;

    m_axi_arid     : out std_logic_vector(C_M_AXI_ID_WIDTH - 1 downto 0);
    m_axi_araddr   : out std_logic_vector(C_M_AXI_ADDR_WIDTH - 1 downto 0);
    m_axi_arlen    : out std_logic_vector(7 downto 0);
    m_axi_arsize   : out std_logic_vector(2 downto 0);
    m_axi_arburst  : out std_logic_vector(1 downto 0);
    m_axi_arlock   : out std_logic;
    m_axi_arcache  : out std_logic_vector(3 downto 0);
    m_axi_arprot   : out std_logic_vector(2 downto 0);
    m_axi_arqos    : out std_logic_vector(3 downto 0);
    m_axi_arregion : out std_logic_vector(3 downto 0);
    m_axi_aruser   : out std_logic_vector(C_M_AXI_ARUSER_WIDTH - 1 downto 0);
    m_axi_arvalid  : out std_logic;
    m_axi_arready  : in  std_logic;
    m_axi_rid      : in  std_logic_vector(C_M_AXI_ID_WIDTH - 1 downto 0);
    m_axi_rdata    : in  std_logic_vector(C_M_AXI_DATA_WIDTH - 1 downto 0);
    m_axi_rresp    : in  std_logic_vector(1 downto 0);
    m_axi_rlast    : in  std_logic;
    m_axi_ruser    : in  std_logic_vector(C_M_AXI_RUSER_WIDTH - 1 downto 0);
    m_axi_rvalid   : in  std_logic;
    m_axi_rready   : out std_logic
    );
end memsec;

architecture arch_imp of memsec is

begin

  plain : if CRYPTO_CONFIG = 0 generate
    memsec : entity work.memsec_block_encryption
      generic map(
        C_S_AXI_ID_WIDTH     => C_S_AXI_ID_WIDTH,
        C_S_AXI_DATA_WIDTH   => C_S_AXI_DATA_WIDTH,
        C_S_AXI_ADDR_WIDTH   => C_S_AXI_ADDR_WIDTH,
        C_S_AXI_ARUSER_WIDTH => C_S_AXI_ARUSER_WIDTH,
        C_S_AXI_AWUSER_WIDTH => C_S_AXI_AWUSER_WIDTH,
        C_S_AXI_WUSER_WIDTH  => C_S_AXI_WUSER_WIDTH,
        C_S_AXI_RUSER_WIDTH  => C_S_AXI_RUSER_WIDTH,
        C_S_AXI_BUSER_WIDTH  => C_S_AXI_BUSER_WIDTH,

        C_M_AXI_ID_WIDTH     => C_M_AXI_ID_WIDTH,
        C_M_AXI_DATA_WIDTH   => C_M_AXI_DATA_WIDTH,
        C_M_AXI_ADDR_WIDTH   => C_M_AXI_ADDR_WIDTH,
        C_M_AXI_ARUSER_WIDTH => C_M_AXI_ARUSER_WIDTH,
        C_M_AXI_AWUSER_WIDTH => C_M_AXI_AWUSER_WIDTH,
        C_M_AXI_WUSER_WIDTH  => C_M_AXI_WUSER_WIDTH,
        C_M_AXI_RUSER_WIDTH  => C_M_AXI_RUSER_WIDTH,
        C_M_AXI_BUSER_WIDTH  => C_M_AXI_BUSER_WIDTH,
        DATA_BLOCK_SIZE      => DATASTREAM_DATA_WIDTH/8,
        CRYPTO_CONFIG        => CRYPTO_PLAIN,
        BLOCKS_PER_SECTOR    => BLOCKS_PER_SECTOR
        )
      port map(
        s_axi_aclk     => s_axi_aclk,
        s_axi_aresetn  => s_axi_aresetn,
        s_axi_awid     => s_axi_awid,
        s_axi_awaddr   => s_axi_awaddr,
        s_axi_awlen    => s_axi_awlen,
        s_axi_awsize   => s_axi_awsize,
        s_axi_awburst  => s_axi_awburst,
        s_axi_awlock   => s_axi_awlock,
        s_axi_awcache  => s_axi_awcache,
        s_axi_awprot   => s_axi_awprot,
        s_axi_awqos    => s_axi_awqos,
        s_axi_awregion => s_axi_awregion,
        s_axi_awuser   => s_axi_awuser,
        s_axi_awvalid  => s_axi_awvalid,
        s_axi_awready  => s_axi_awready,
        s_axi_wdata    => s_axi_wdata,
        s_axi_wstrb    => s_axi_wstrb,
        s_axi_wlast    => s_axi_wlast,
        s_axi_wuser    => s_axi_wuser,
        s_axi_wvalid   => s_axi_wvalid,
        s_axi_wready   => s_axi_wready,
        s_axi_bid      => s_axi_bid,
        s_axi_bresp    => s_axi_bresp,
        s_axi_buser    => s_axi_buser,
        s_axi_bvalid   => s_axi_bvalid,
        s_axi_bready   => s_axi_bready,

        s_axi_arid     => s_axi_arid,
        s_axi_araddr   => s_axi_araddr,
        s_axi_arlen    => s_axi_arlen,
        s_axi_arsize   => s_axi_arsize,
        s_axi_arburst  => s_axi_arburst,
        s_axi_arlock   => s_axi_arlock,
        s_axi_arcache  => s_axi_arcache,
        s_axi_arprot   => s_axi_arprot,
        s_axi_arqos    => s_axi_arqos,
        s_axi_arregion => s_axi_arregion,
        s_axi_aruser   => s_axi_aruser,
        s_axi_arvalid  => s_axi_arvalid,
        s_axi_arready  => s_axi_arready,
        s_axi_rid      => s_axi_rid,
        s_axi_rdata    => s_axi_rdata,
        s_axi_rresp    => s_axi_rresp,
        s_axi_rlast    => s_axi_rlast,
        s_axi_ruser    => s_axi_ruser,
        s_axi_rvalid   => s_axi_rvalid,
        s_axi_rready   => s_axi_rready,

        m_axi_aclk    => m_axi_aclk,
        m_axi_aresetn => m_axi_aresetn,
        m_axi_awid    => m_axi_awid,
        m_axi_awaddr  => m_axi_awaddr,
        m_axi_awlen   => m_axi_awlen,
        m_axi_awsize  => m_axi_awsize,
        m_axi_awburst => m_axi_awburst,
        m_axi_awlock  => m_axi_awlock,
        m_axi_awcache => m_axi_awcache,
        m_axi_awprot  => m_axi_awprot,
        m_axi_awqos   => m_axi_awqos,
        m_axi_awuser  => m_axi_awuser,
        m_axi_awvalid => m_axi_awvalid,
        m_axi_awready => m_axi_awready,
        m_axi_wdata   => m_axi_wdata,
        m_axi_wstrb   => m_axi_wstrb,
        m_axi_wlast   => m_axi_wlast,
        m_axi_wuser   => m_axi_wuser,
        m_axi_wvalid  => m_axi_wvalid,
        m_axi_wready  => m_axi_wready,
        m_axi_bid     => m_axi_bid,
        m_axi_bresp   => m_axi_bresp,
        m_axi_buser   => m_axi_buser,
        m_axi_bvalid  => m_axi_bvalid,
        m_axi_bready  => m_axi_bready,

        m_axi_arid    => m_axi_arid,
        m_axi_araddr  => m_axi_araddr,
        m_axi_arlen   => m_axi_arlen,
        m_axi_arsize  => m_axi_arsize,
        m_axi_arburst => m_axi_arburst,
        m_axi_arlock  => m_axi_arlock,
        m_axi_arcache => m_axi_arcache,
        m_axi_arprot  => m_axi_arprot,
        m_axi_arqos   => m_axi_arqos,
        m_axi_aruser  => m_axi_aruser,
        m_axi_arvalid => m_axi_arvalid,
        m_axi_arready => m_axi_arready,
        m_axi_rid     => m_axi_rid,
        m_axi_rdata   => m_axi_rdata,
        m_axi_rresp   => m_axi_rresp,
        m_axi_rlast   => m_axi_rlast,
        m_axi_ruser   => m_axi_ruser,
        m_axi_rvalid  => m_axi_rvalid,
        m_axi_rready  => m_axi_rready
        );
  end generate plain;

  ascon : if CRYPTO_CONFIG = 1 generate
    memsec : entity work.memsec_ascon
      generic map(
        C_S_AXI_ID_WIDTH     => C_S_AXI_ID_WIDTH,
        C_S_AXI_DATA_WIDTH   => C_S_AXI_DATA_WIDTH,
        C_S_AXI_ADDR_WIDTH   => C_S_AXI_ADDR_WIDTH,
        C_S_AXI_ARUSER_WIDTH => C_S_AXI_ARUSER_WIDTH,
        C_S_AXI_AWUSER_WIDTH => C_S_AXI_AWUSER_WIDTH,
        C_S_AXI_WUSER_WIDTH  => C_S_AXI_WUSER_WIDTH,
        C_S_AXI_RUSER_WIDTH  => C_S_AXI_RUSER_WIDTH,
        C_S_AXI_BUSER_WIDTH  => C_S_AXI_BUSER_WIDTH,

        C_M_AXI_ID_WIDTH     => C_M_AXI_ID_WIDTH,
        C_M_AXI_DATA_WIDTH   => C_M_AXI_DATA_WIDTH,
        C_M_AXI_ADDR_WIDTH   => C_M_AXI_ADDR_WIDTH,
        C_M_AXI_ARUSER_WIDTH => C_M_AXI_ARUSER_WIDTH,
        C_M_AXI_AWUSER_WIDTH => C_M_AXI_AWUSER_WIDTH,
        C_M_AXI_WUSER_WIDTH  => C_M_AXI_WUSER_WIDTH,
        C_M_AXI_RUSER_WIDTH  => C_M_AXI_RUSER_WIDTH,
        C_M_AXI_BUSER_WIDTH  => C_M_AXI_BUSER_WIDTH,

        DATA_BLOCK_SIZE => DATA_BLOCK_SIZE
        )
      port map(
        s_axi_aclk     => s_axi_aclk,
        s_axi_aresetn  => s_axi_aresetn,
        s_axi_awid     => s_axi_awid,
        s_axi_awaddr   => s_axi_awaddr,
        s_axi_awlen    => s_axi_awlen,
        s_axi_awsize   => s_axi_awsize,
        s_axi_awburst  => s_axi_awburst,
        s_axi_awlock   => s_axi_awlock,
        s_axi_awcache  => s_axi_awcache,
        s_axi_awprot   => s_axi_awprot,
        s_axi_awqos    => s_axi_awqos,
        s_axi_awregion => s_axi_awregion,
        s_axi_awuser   => s_axi_awuser,
        s_axi_awvalid  => s_axi_awvalid,
        s_axi_awready  => s_axi_awready,
        s_axi_wdata    => s_axi_wdata,
        s_axi_wstrb    => s_axi_wstrb,
        s_axi_wlast    => s_axi_wlast,
        s_axi_wuser    => s_axi_wuser,
        s_axi_wvalid   => s_axi_wvalid,
        s_axi_wready   => s_axi_wready,
        s_axi_bid      => s_axi_bid,
        s_axi_bresp    => s_axi_bresp,
        s_axi_buser    => s_axi_buser,
        s_axi_bvalid   => s_axi_bvalid,
        s_axi_bready   => s_axi_bready,

        s_axi_arid     => s_axi_arid,
        s_axi_araddr   => s_axi_araddr,
        s_axi_arlen    => s_axi_arlen,
        s_axi_arsize   => s_axi_arsize,
        s_axi_arburst  => s_axi_arburst,
        s_axi_arlock   => s_axi_arlock,
        s_axi_arcache  => s_axi_arcache,
        s_axi_arprot   => s_axi_arprot,
        s_axi_arqos    => s_axi_arqos,
        s_axi_arregion => s_axi_arregion,
        s_axi_aruser   => s_axi_aruser,
        s_axi_arvalid  => s_axi_arvalid,
        s_axi_arready  => s_axi_arready,
        s_axi_rid      => s_axi_rid,
        s_axi_rdata    => s_axi_rdata,
        s_axi_rresp    => s_axi_rresp,
        s_axi_rlast    => s_axi_rlast,
        s_axi_ruser    => s_axi_ruser,
        s_axi_rvalid   => s_axi_rvalid,
        s_axi_rready   => s_axi_rready,

        m_axi_aclk    => m_axi_aclk,
        m_axi_aresetn => m_axi_aresetn,
        m_axi_awid    => m_axi_awid,
        m_axi_awaddr  => m_axi_awaddr,
        m_axi_awlen   => m_axi_awlen,
        m_axi_awsize  => m_axi_awsize,
        m_axi_awburst => m_axi_awburst,
        m_axi_awlock  => m_axi_awlock,
        m_axi_awcache => m_axi_awcache,
        m_axi_awprot  => m_axi_awprot,
        m_axi_awqos   => m_axi_awqos,
        m_axi_awuser  => m_axi_awuser,
        m_axi_awvalid => m_axi_awvalid,
        m_axi_awready => m_axi_awready,
        m_axi_wdata   => m_axi_wdata,
        m_axi_wstrb   => m_axi_wstrb,
        m_axi_wlast   => m_axi_wlast,
        m_axi_wuser   => m_axi_wuser,
        m_axi_wvalid  => m_axi_wvalid,
        m_axi_wready  => m_axi_wready,
        m_axi_bid     => m_axi_bid,
        m_axi_bresp   => m_axi_bresp,
        m_axi_buser   => m_axi_buser,
        m_axi_bvalid  => m_axi_bvalid,
        m_axi_bready  => m_axi_bready,

        m_axi_arid    => m_axi_arid,
        m_axi_araddr  => m_axi_araddr,
        m_axi_arlen   => m_axi_arlen,
        m_axi_arsize  => m_axi_arsize,
        m_axi_arburst => m_axi_arburst,
        m_axi_arlock  => m_axi_arlock,
        m_axi_arcache => m_axi_arcache,
        m_axi_arprot  => m_axi_arprot,
        m_axi_arqos   => m_axi_arqos,
        m_axi_aruser  => m_axi_aruser,
        m_axi_arvalid => m_axi_arvalid,
        m_axi_arready => m_axi_arready,
        m_axi_rid     => m_axi_rid,
        m_axi_rdata   => m_axi_rdata,
        m_axi_rresp   => m_axi_rresp,
        m_axi_rlast   => m_axi_rlast,
        m_axi_ruser   => m_axi_ruser,
        m_axi_rvalid  => m_axi_rvalid,
        m_axi_rready  => m_axi_rready
        );
  end generate ascon;

  tectree_ascon : if CRYPTO_CONFIG = 2 generate
    memsec : entity work.memsec_tectree_ascon
      generic map(
        C_S_AXI_ID_WIDTH     => C_S_AXI_ID_WIDTH,
        C_S_AXI_DATA_WIDTH   => C_S_AXI_DATA_WIDTH,
        C_S_AXI_ADDR_WIDTH   => C_S_AXI_ADDR_WIDTH,
        C_S_AXI_ARUSER_WIDTH => C_S_AXI_ARUSER_WIDTH,
        C_S_AXI_AWUSER_WIDTH => C_S_AXI_AWUSER_WIDTH,
        C_S_AXI_WUSER_WIDTH  => C_S_AXI_WUSER_WIDTH,
        C_S_AXI_RUSER_WIDTH  => C_S_AXI_RUSER_WIDTH,
        C_S_AXI_BUSER_WIDTH  => C_S_AXI_BUSER_WIDTH,

        C_M_AXI_ID_WIDTH     => C_M_AXI_ID_WIDTH,
        C_M_AXI_DATA_WIDTH   => C_M_AXI_DATA_WIDTH,
        C_M_AXI_ADDR_WIDTH   => C_M_AXI_ADDR_WIDTH,
        C_M_AXI_ARUSER_WIDTH => C_M_AXI_ARUSER_WIDTH,
        C_M_AXI_AWUSER_WIDTH => C_M_AXI_AWUSER_WIDTH,
        C_M_AXI_WUSER_WIDTH  => C_M_AXI_WUSER_WIDTH,
        C_M_AXI_RUSER_WIDTH  => C_M_AXI_RUSER_WIDTH,
        C_M_AXI_BUSER_WIDTH  => C_M_AXI_BUSER_WIDTH,

        DATA_BLOCK_SIZE      => DATA_BLOCK_SIZE,
        DATA_MEMORY_SIZE     => DATA_MEMORY_SIZE,
        TREE_ARITY           => TREE_ARITY,
        TREE_ROOTS           => TREE_ROOTS,
        TREE_NODE_CACHE_SIZE => TREE_NODE_CACHE_SIZE
        )
      port map(
        s_axi_aclk     => s_axi_aclk,
        s_axi_aresetn  => s_axi_aresetn,
        s_axi_awid     => s_axi_awid,
        s_axi_awaddr   => s_axi_awaddr,
        s_axi_awlen    => s_axi_awlen,
        s_axi_awsize   => s_axi_awsize,
        s_axi_awburst  => s_axi_awburst,
        s_axi_awlock   => s_axi_awlock,
        s_axi_awcache  => s_axi_awcache,
        s_axi_awprot   => s_axi_awprot,
        s_axi_awqos    => s_axi_awqos,
        s_axi_awregion => s_axi_awregion,
        s_axi_awuser   => s_axi_awuser,
        s_axi_awvalid  => s_axi_awvalid,
        s_axi_awready  => s_axi_awready,
        s_axi_wdata    => s_axi_wdata,
        s_axi_wstrb    => s_axi_wstrb,
        s_axi_wlast    => s_axi_wlast,
        s_axi_wuser    => s_axi_wuser,
        s_axi_wvalid   => s_axi_wvalid,
        s_axi_wready   => s_axi_wready,
        s_axi_bid      => s_axi_bid,
        s_axi_bresp    => s_axi_bresp,
        s_axi_buser    => s_axi_buser,
        s_axi_bvalid   => s_axi_bvalid,
        s_axi_bready   => s_axi_bready,

        s_axi_arid     => s_axi_arid,
        s_axi_araddr   => s_axi_araddr,
        s_axi_arlen    => s_axi_arlen,
        s_axi_arsize   => s_axi_arsize,
        s_axi_arburst  => s_axi_arburst,
        s_axi_arlock   => s_axi_arlock,
        s_axi_arcache  => s_axi_arcache,
        s_axi_arprot   => s_axi_arprot,
        s_axi_arqos    => s_axi_arqos,
        s_axi_arregion => s_axi_arregion,
        s_axi_aruser   => s_axi_aruser,
        s_axi_arvalid  => s_axi_arvalid,
        s_axi_arready  => s_axi_arready,
        s_axi_rid      => s_axi_rid,
        s_axi_rdata    => s_axi_rdata,
        s_axi_rresp    => s_axi_rresp,
        s_axi_rlast    => s_axi_rlast,
        s_axi_ruser    => s_axi_ruser,
        s_axi_rvalid   => s_axi_rvalid,
        s_axi_rready   => s_axi_rready,

        m_axi_aclk    => m_axi_aclk,
        m_axi_aresetn => m_axi_aresetn,
        m_axi_awid    => m_axi_awid,
        m_axi_awaddr  => m_axi_awaddr,
        m_axi_awlen   => m_axi_awlen,
        m_axi_awsize  => m_axi_awsize,
        m_axi_awburst => m_axi_awburst,
        m_axi_awlock  => m_axi_awlock,
        m_axi_awcache => m_axi_awcache,
        m_axi_awprot  => m_axi_awprot,
        m_axi_awqos   => m_axi_awqos,
        m_axi_awuser  => m_axi_awuser,
        m_axi_awvalid => m_axi_awvalid,
        m_axi_awready => m_axi_awready,
        m_axi_wdata   => m_axi_wdata,
        m_axi_wstrb   => m_axi_wstrb,
        m_axi_wlast   => m_axi_wlast,
        m_axi_wuser   => m_axi_wuser,
        m_axi_wvalid  => m_axi_wvalid,
        m_axi_wready  => m_axi_wready,
        m_axi_bid     => m_axi_bid,
        m_axi_bresp   => m_axi_bresp,
        m_axi_buser   => m_axi_buser,
        m_axi_bvalid  => m_axi_bvalid,
        m_axi_bready  => m_axi_bready,

        m_axi_arid    => m_axi_arid,
        m_axi_araddr  => m_axi_araddr,
        m_axi_arlen   => m_axi_arlen,
        m_axi_arsize  => m_axi_arsize,
        m_axi_arburst => m_axi_arburst,
        m_axi_arlock  => m_axi_arlock,
        m_axi_arcache => m_axi_arcache,
        m_axi_arprot  => m_axi_arprot,
        m_axi_arqos   => m_axi_arqos,
        m_axi_aruser  => m_axi_aruser,
        m_axi_arvalid => m_axi_arvalid,
        m_axi_arready => m_axi_arready,
        m_axi_rid     => m_axi_rid,
        m_axi_rdata   => m_axi_rdata,
        m_axi_rresp   => m_axi_rresp,
        m_axi_rlast   => m_axi_rlast,
        m_axi_ruser   => m_axi_ruser,
        m_axi_rvalid  => m_axi_rvalid,
        m_axi_rready  => m_axi_rready
        );
  end generate tectree_ascon;

  prince_ecb : if CRYPTO_CONFIG = 3 generate
    memsec : entity work.memsec_block_encryption
      generic map(
        C_S_AXI_ID_WIDTH     => C_S_AXI_ID_WIDTH,
        C_S_AXI_DATA_WIDTH   => C_S_AXI_DATA_WIDTH,
        C_S_AXI_ADDR_WIDTH   => C_S_AXI_ADDR_WIDTH,
        C_S_AXI_ARUSER_WIDTH => C_S_AXI_ARUSER_WIDTH,
        C_S_AXI_AWUSER_WIDTH => C_S_AXI_AWUSER_WIDTH,
        C_S_AXI_WUSER_WIDTH  => C_S_AXI_WUSER_WIDTH,
        C_S_AXI_RUSER_WIDTH  => C_S_AXI_RUSER_WIDTH,
        C_S_AXI_BUSER_WIDTH  => C_S_AXI_BUSER_WIDTH,

        C_M_AXI_ID_WIDTH     => C_M_AXI_ID_WIDTH,
        C_M_AXI_DATA_WIDTH   => C_M_AXI_DATA_WIDTH,
        C_M_AXI_ADDR_WIDTH   => C_M_AXI_ADDR_WIDTH,
        C_M_AXI_ARUSER_WIDTH => C_M_AXI_ARUSER_WIDTH,
        C_M_AXI_AWUSER_WIDTH => C_M_AXI_AWUSER_WIDTH,
        C_M_AXI_WUSER_WIDTH  => C_M_AXI_WUSER_WIDTH,
        C_M_AXI_RUSER_WIDTH  => C_M_AXI_RUSER_WIDTH,
        C_M_AXI_BUSER_WIDTH  => C_M_AXI_BUSER_WIDTH,

        CRYPTO_CONFIG     => CRYPTO_PRINCE_ECB,
        DATA_BLOCK_SIZE   => max(8, DATASTREAM_DATA_WIDTH/8),
        BLOCKS_PER_SECTOR => BLOCKS_PER_SECTOR
        )
      port map(
        s_axi_aclk     => s_axi_aclk,
        s_axi_aresetn  => s_axi_aresetn,
        s_axi_awid     => s_axi_awid,
        s_axi_awaddr   => s_axi_awaddr,
        s_axi_awlen    => s_axi_awlen,
        s_axi_awsize   => s_axi_awsize,
        s_axi_awburst  => s_axi_awburst,
        s_axi_awlock   => s_axi_awlock,
        s_axi_awcache  => s_axi_awcache,
        s_axi_awprot   => s_axi_awprot,
        s_axi_awqos    => s_axi_awqos,
        s_axi_awregion => s_axi_awregion,
        s_axi_awuser   => s_axi_awuser,
        s_axi_awvalid  => s_axi_awvalid,
        s_axi_awready  => s_axi_awready,
        s_axi_wdata    => s_axi_wdata,
        s_axi_wstrb    => s_axi_wstrb,
        s_axi_wlast    => s_axi_wlast,
        s_axi_wuser    => s_axi_wuser,
        s_axi_wvalid   => s_axi_wvalid,
        s_axi_wready   => s_axi_wready,
        s_axi_bid      => s_axi_bid,
        s_axi_bresp    => s_axi_bresp,
        s_axi_buser    => s_axi_buser,
        s_axi_bvalid   => s_axi_bvalid,
        s_axi_bready   => s_axi_bready,

        s_axi_arid     => s_axi_arid,
        s_axi_araddr   => s_axi_araddr,
        s_axi_arlen    => s_axi_arlen,
        s_axi_arsize   => s_axi_arsize,
        s_axi_arburst  => s_axi_arburst,
        s_axi_arlock   => s_axi_arlock,
        s_axi_arcache  => s_axi_arcache,
        s_axi_arprot   => s_axi_arprot,
        s_axi_arqos    => s_axi_arqos,
        s_axi_arregion => s_axi_arregion,
        s_axi_aruser   => s_axi_aruser,
        s_axi_arvalid  => s_axi_arvalid,
        s_axi_arready  => s_axi_arready,
        s_axi_rid      => s_axi_rid,
        s_axi_rdata    => s_axi_rdata,
        s_axi_rresp    => s_axi_rresp,
        s_axi_rlast    => s_axi_rlast,
        s_axi_ruser    => s_axi_ruser,
        s_axi_rvalid   => s_axi_rvalid,
        s_axi_rready   => s_axi_rready,

        m_axi_aclk    => m_axi_aclk,
        m_axi_aresetn => m_axi_aresetn,
        m_axi_awid    => m_axi_awid,
        m_axi_awaddr  => m_axi_awaddr,
        m_axi_awlen   => m_axi_awlen,
        m_axi_awsize  => m_axi_awsize,
        m_axi_awburst => m_axi_awburst,
        m_axi_awlock  => m_axi_awlock,
        m_axi_awcache => m_axi_awcache,
        m_axi_awprot  => m_axi_awprot,
        m_axi_awqos   => m_axi_awqos,
        m_axi_awuser  => m_axi_awuser,
        m_axi_awvalid => m_axi_awvalid,
        m_axi_awready => m_axi_awready,
        m_axi_wdata   => m_axi_wdata,
        m_axi_wstrb   => m_axi_wstrb,
        m_axi_wlast   => m_axi_wlast,
        m_axi_wuser   => m_axi_wuser,
        m_axi_wvalid  => m_axi_wvalid,
        m_axi_wready  => m_axi_wready,
        m_axi_bid     => m_axi_bid,
        m_axi_bresp   => m_axi_bresp,
        m_axi_buser   => m_axi_buser,
        m_axi_bvalid  => m_axi_bvalid,
        m_axi_bready  => m_axi_bready,

        m_axi_arid    => m_axi_arid,
        m_axi_araddr  => m_axi_araddr,
        m_axi_arlen   => m_axi_arlen,
        m_axi_arsize  => m_axi_arsize,
        m_axi_arburst => m_axi_arburst,
        m_axi_arlock  => m_axi_arlock,
        m_axi_arcache => m_axi_arcache,
        m_axi_arprot  => m_axi_arprot,
        m_axi_arqos   => m_axi_arqos,
        m_axi_aruser  => m_axi_aruser,
        m_axi_arvalid => m_axi_arvalid,
        m_axi_arready => m_axi_arready,
        m_axi_rid     => m_axi_rid,
        m_axi_rdata   => m_axi_rdata,
        m_axi_rresp   => m_axi_rresp,
        m_axi_rlast   => m_axi_rlast,
        m_axi_ruser   => m_axi_ruser,
        m_axi_rvalid  => m_axi_rvalid,
        m_axi_rready  => m_axi_rready
        );
  end generate prince_ecb;

  aes_ecb : if CRYPTO_CONFIG = 4 generate
    memsec : entity work.memsec_block_encryption
      generic map(
        C_S_AXI_ID_WIDTH     => C_S_AXI_ID_WIDTH,
        C_S_AXI_DATA_WIDTH   => C_S_AXI_DATA_WIDTH,
        C_S_AXI_ADDR_WIDTH   => C_S_AXI_ADDR_WIDTH,
        C_S_AXI_ARUSER_WIDTH => C_S_AXI_ARUSER_WIDTH,
        C_S_AXI_AWUSER_WIDTH => C_S_AXI_AWUSER_WIDTH,
        C_S_AXI_WUSER_WIDTH  => C_S_AXI_WUSER_WIDTH,
        C_S_AXI_RUSER_WIDTH  => C_S_AXI_RUSER_WIDTH,
        C_S_AXI_BUSER_WIDTH  => C_S_AXI_BUSER_WIDTH,

        C_M_AXI_ID_WIDTH     => C_M_AXI_ID_WIDTH,
        C_M_AXI_DATA_WIDTH   => C_M_AXI_DATA_WIDTH,
        C_M_AXI_ADDR_WIDTH   => C_M_AXI_ADDR_WIDTH,
        C_M_AXI_ARUSER_WIDTH => C_M_AXI_ARUSER_WIDTH,
        C_M_AXI_AWUSER_WIDTH => C_M_AXI_AWUSER_WIDTH,
        C_M_AXI_WUSER_WIDTH  => C_M_AXI_WUSER_WIDTH,
        C_M_AXI_RUSER_WIDTH  => C_M_AXI_RUSER_WIDTH,
        C_M_AXI_BUSER_WIDTH  => C_M_AXI_BUSER_WIDTH,

        CRYPTO_CONFIG     => CRYPTO_AES_ECB,
        DATA_BLOCK_SIZE   => max(16, DATASTREAM_DATA_WIDTH/8),
        BLOCKS_PER_SECTOR => BLOCKS_PER_SECTOR
        )
      port map(
        s_axi_aclk     => s_axi_aclk,
        s_axi_aresetn  => s_axi_aresetn,
        s_axi_awid     => s_axi_awid,
        s_axi_awaddr   => s_axi_awaddr,
        s_axi_awlen    => s_axi_awlen,
        s_axi_awsize   => s_axi_awsize,
        s_axi_awburst  => s_axi_awburst,
        s_axi_awlock   => s_axi_awlock,
        s_axi_awcache  => s_axi_awcache,
        s_axi_awprot   => s_axi_awprot,
        s_axi_awqos    => s_axi_awqos,
        s_axi_awregion => s_axi_awregion,
        s_axi_awuser   => s_axi_awuser,
        s_axi_awvalid  => s_axi_awvalid,
        s_axi_awready  => s_axi_awready,
        s_axi_wdata    => s_axi_wdata,
        s_axi_wstrb    => s_axi_wstrb,
        s_axi_wlast    => s_axi_wlast,
        s_axi_wuser    => s_axi_wuser,
        s_axi_wvalid   => s_axi_wvalid,
        s_axi_wready   => s_axi_wready,
        s_axi_bid      => s_axi_bid,
        s_axi_bresp    => s_axi_bresp,
        s_axi_buser    => s_axi_buser,
        s_axi_bvalid   => s_axi_bvalid,
        s_axi_bready   => s_axi_bready,

        s_axi_arid     => s_axi_arid,
        s_axi_araddr   => s_axi_araddr,
        s_axi_arlen    => s_axi_arlen,
        s_axi_arsize   => s_axi_arsize,
        s_axi_arburst  => s_axi_arburst,
        s_axi_arlock   => s_axi_arlock,
        s_axi_arcache  => s_axi_arcache,
        s_axi_arprot   => s_axi_arprot,
        s_axi_arqos    => s_axi_arqos,
        s_axi_arregion => s_axi_arregion,
        s_axi_aruser   => s_axi_aruser,
        s_axi_arvalid  => s_axi_arvalid,
        s_axi_arready  => s_axi_arready,
        s_axi_rid      => s_axi_rid,
        s_axi_rdata    => s_axi_rdata,
        s_axi_rresp    => s_axi_rresp,
        s_axi_rlast    => s_axi_rlast,
        s_axi_ruser    => s_axi_ruser,
        s_axi_rvalid   => s_axi_rvalid,
        s_axi_rready   => s_axi_rready,

        m_axi_aclk    => m_axi_aclk,
        m_axi_aresetn => m_axi_aresetn,
        m_axi_awid    => m_axi_awid,
        m_axi_awaddr  => m_axi_awaddr,
        m_axi_awlen   => m_axi_awlen,
        m_axi_awsize  => m_axi_awsize,
        m_axi_awburst => m_axi_awburst,
        m_axi_awlock  => m_axi_awlock,
        m_axi_awcache => m_axi_awcache,
        m_axi_awprot  => m_axi_awprot,
        m_axi_awqos   => m_axi_awqos,
        m_axi_awuser  => m_axi_awuser,
        m_axi_awvalid => m_axi_awvalid,
        m_axi_awready => m_axi_awready,
        m_axi_wdata   => m_axi_wdata,
        m_axi_wstrb   => m_axi_wstrb,
        m_axi_wlast   => m_axi_wlast,
        m_axi_wuser   => m_axi_wuser,
        m_axi_wvalid  => m_axi_wvalid,
        m_axi_wready  => m_axi_wready,
        m_axi_bid     => m_axi_bid,
        m_axi_bresp   => m_axi_bresp,
        m_axi_buser   => m_axi_buser,
        m_axi_bvalid  => m_axi_bvalid,
        m_axi_bready  => m_axi_bready,

        m_axi_arid    => m_axi_arid,
        m_axi_araddr  => m_axi_araddr,
        m_axi_arlen   => m_axi_arlen,
        m_axi_arsize  => m_axi_arsize,
        m_axi_arburst => m_axi_arburst,
        m_axi_arlock  => m_axi_arlock,
        m_axi_arcache => m_axi_arcache,
        m_axi_arprot  => m_axi_arprot,
        m_axi_arqos   => m_axi_arqos,
        m_axi_aruser  => m_axi_aruser,
        m_axi_arvalid => m_axi_arvalid,
        m_axi_arready => m_axi_arready,
        m_axi_rid     => m_axi_rid,
        m_axi_rdata   => m_axi_rdata,
        m_axi_rresp   => m_axi_rresp,
        m_axi_rlast   => m_axi_rlast,
        m_axi_ruser   => m_axi_ruser,
        m_axi_rvalid  => m_axi_rvalid,
        m_axi_rready  => m_axi_rready
        );
  end generate aes_ecb;

  prince_cbc : if CRYPTO_CONFIG = 5 generate
    memsec : entity work.memsec_block_encryption
      generic map(
        C_S_AXI_ID_WIDTH     => C_S_AXI_ID_WIDTH,
        C_S_AXI_DATA_WIDTH   => C_S_AXI_DATA_WIDTH,
        C_S_AXI_ADDR_WIDTH   => C_S_AXI_ADDR_WIDTH,
        C_S_AXI_ARUSER_WIDTH => C_S_AXI_ARUSER_WIDTH,
        C_S_AXI_AWUSER_WIDTH => C_S_AXI_AWUSER_WIDTH,
        C_S_AXI_WUSER_WIDTH  => C_S_AXI_WUSER_WIDTH,
        C_S_AXI_RUSER_WIDTH  => C_S_AXI_RUSER_WIDTH,
        C_S_AXI_BUSER_WIDTH  => C_S_AXI_BUSER_WIDTH,

        C_M_AXI_ID_WIDTH     => C_M_AXI_ID_WIDTH,
        C_M_AXI_DATA_WIDTH   => C_M_AXI_DATA_WIDTH,
        C_M_AXI_ADDR_WIDTH   => C_M_AXI_ADDR_WIDTH,
        C_M_AXI_ARUSER_WIDTH => C_M_AXI_ARUSER_WIDTH,
        C_M_AXI_AWUSER_WIDTH => C_M_AXI_AWUSER_WIDTH,
        C_M_AXI_WUSER_WIDTH  => C_M_AXI_WUSER_WIDTH,
        C_M_AXI_RUSER_WIDTH  => C_M_AXI_RUSER_WIDTH,
        C_M_AXI_BUSER_WIDTH  => C_M_AXI_BUSER_WIDTH,

        CRYPTO_CONFIG     => CRYPTO_PRINCE_CBC,
        DATA_BLOCK_SIZE   => 8*BLOCKS_PER_SECTOR,
        BLOCKS_PER_SECTOR => BLOCKS_PER_SECTOR
        )
      port map(
        s_axi_aclk     => s_axi_aclk,
        s_axi_aresetn  => s_axi_aresetn,
        s_axi_awid     => s_axi_awid,
        s_axi_awaddr   => s_axi_awaddr,
        s_axi_awlen    => s_axi_awlen,
        s_axi_awsize   => s_axi_awsize,
        s_axi_awburst  => s_axi_awburst,
        s_axi_awlock   => s_axi_awlock,
        s_axi_awcache  => s_axi_awcache,
        s_axi_awprot   => s_axi_awprot,
        s_axi_awqos    => s_axi_awqos,
        s_axi_awregion => s_axi_awregion,
        s_axi_awuser   => s_axi_awuser,
        s_axi_awvalid  => s_axi_awvalid,
        s_axi_awready  => s_axi_awready,
        s_axi_wdata    => s_axi_wdata,
        s_axi_wstrb    => s_axi_wstrb,
        s_axi_wlast    => s_axi_wlast,
        s_axi_wuser    => s_axi_wuser,
        s_axi_wvalid   => s_axi_wvalid,
        s_axi_wready   => s_axi_wready,
        s_axi_bid      => s_axi_bid,
        s_axi_bresp    => s_axi_bresp,
        s_axi_buser    => s_axi_buser,
        s_axi_bvalid   => s_axi_bvalid,
        s_axi_bready   => s_axi_bready,

        s_axi_arid     => s_axi_arid,
        s_axi_araddr   => s_axi_araddr,
        s_axi_arlen    => s_axi_arlen,
        s_axi_arsize   => s_axi_arsize,
        s_axi_arburst  => s_axi_arburst,
        s_axi_arlock   => s_axi_arlock,
        s_axi_arcache  => s_axi_arcache,
        s_axi_arprot   => s_axi_arprot,
        s_axi_arqos    => s_axi_arqos,
        s_axi_arregion => s_axi_arregion,
        s_axi_aruser   => s_axi_aruser,
        s_axi_arvalid  => s_axi_arvalid,
        s_axi_arready  => s_axi_arready,
        s_axi_rid      => s_axi_rid,
        s_axi_rdata    => s_axi_rdata,
        s_axi_rresp    => s_axi_rresp,
        s_axi_rlast    => s_axi_rlast,
        s_axi_ruser    => s_axi_ruser,
        s_axi_rvalid   => s_axi_rvalid,
        s_axi_rready   => s_axi_rready,

        m_axi_aclk    => m_axi_aclk,
        m_axi_aresetn => m_axi_aresetn,
        m_axi_awid    => m_axi_awid,
        m_axi_awaddr  => m_axi_awaddr,
        m_axi_awlen   => m_axi_awlen,
        m_axi_awsize  => m_axi_awsize,
        m_axi_awburst => m_axi_awburst,
        m_axi_awlock  => m_axi_awlock,
        m_axi_awcache => m_axi_awcache,
        m_axi_awprot  => m_axi_awprot,
        m_axi_awqos   => m_axi_awqos,
        m_axi_awuser  => m_axi_awuser,
        m_axi_awvalid => m_axi_awvalid,
        m_axi_awready => m_axi_awready,
        m_axi_wdata   => m_axi_wdata,
        m_axi_wstrb   => m_axi_wstrb,
        m_axi_wlast   => m_axi_wlast,
        m_axi_wuser   => m_axi_wuser,
        m_axi_wvalid  => m_axi_wvalid,
        m_axi_wready  => m_axi_wready,
        m_axi_bid     => m_axi_bid,
        m_axi_bresp   => m_axi_bresp,
        m_axi_buser   => m_axi_buser,
        m_axi_bvalid  => m_axi_bvalid,
        m_axi_bready  => m_axi_bready,

        m_axi_arid    => m_axi_arid,
        m_axi_araddr  => m_axi_araddr,
        m_axi_arlen   => m_axi_arlen,
        m_axi_arsize  => m_axi_arsize,
        m_axi_arburst => m_axi_arburst,
        m_axi_arlock  => m_axi_arlock,
        m_axi_arcache => m_axi_arcache,
        m_axi_arprot  => m_axi_arprot,
        m_axi_arqos   => m_axi_arqos,
        m_axi_aruser  => m_axi_aruser,
        m_axi_arvalid => m_axi_arvalid,
        m_axi_arready => m_axi_arready,
        m_axi_rid     => m_axi_rid,
        m_axi_rdata   => m_axi_rdata,
        m_axi_rresp   => m_axi_rresp,
        m_axi_rlast   => m_axi_rlast,
        m_axi_ruser   => m_axi_ruser,
        m_axi_rvalid  => m_axi_rvalid,
        m_axi_rready  => m_axi_rready
        );
  end generate prince_cbc;

  aes_cbc : if CRYPTO_CONFIG = 6 generate
    memsec : entity work.memsec_block_encryption
      generic map(
        C_S_AXI_ID_WIDTH     => C_S_AXI_ID_WIDTH,
        C_S_AXI_DATA_WIDTH   => C_S_AXI_DATA_WIDTH,
        C_S_AXI_ADDR_WIDTH   => C_S_AXI_ADDR_WIDTH,
        C_S_AXI_ARUSER_WIDTH => C_S_AXI_ARUSER_WIDTH,
        C_S_AXI_AWUSER_WIDTH => C_S_AXI_AWUSER_WIDTH,
        C_S_AXI_WUSER_WIDTH  => C_S_AXI_WUSER_WIDTH,
        C_S_AXI_RUSER_WIDTH  => C_S_AXI_RUSER_WIDTH,
        C_S_AXI_BUSER_WIDTH  => C_S_AXI_BUSER_WIDTH,

        C_M_AXI_ID_WIDTH     => C_M_AXI_ID_WIDTH,
        C_M_AXI_DATA_WIDTH   => C_M_AXI_DATA_WIDTH,
        C_M_AXI_ADDR_WIDTH   => C_M_AXI_ADDR_WIDTH,
        C_M_AXI_ARUSER_WIDTH => C_M_AXI_ARUSER_WIDTH,
        C_M_AXI_AWUSER_WIDTH => C_M_AXI_AWUSER_WIDTH,
        C_M_AXI_WUSER_WIDTH  => C_M_AXI_WUSER_WIDTH,
        C_M_AXI_RUSER_WIDTH  => C_M_AXI_RUSER_WIDTH,
        C_M_AXI_BUSER_WIDTH  => C_M_AXI_BUSER_WIDTH,

        CRYPTO_CONFIG     => CRYPTO_AES_CBC,
        DATA_BLOCK_SIZE   => 16*BLOCKS_PER_SECTOR,
        BLOCKS_PER_SECTOR => BLOCKS_PER_SECTOR
        )
      port map(
        s_axi_aclk     => s_axi_aclk,
        s_axi_aresetn  => s_axi_aresetn,
        s_axi_awid     => s_axi_awid,
        s_axi_awaddr   => s_axi_awaddr,
        s_axi_awlen    => s_axi_awlen,
        s_axi_awsize   => s_axi_awsize,
        s_axi_awburst  => s_axi_awburst,
        s_axi_awlock   => s_axi_awlock,
        s_axi_awcache  => s_axi_awcache,
        s_axi_awprot   => s_axi_awprot,
        s_axi_awqos    => s_axi_awqos,
        s_axi_awregion => s_axi_awregion,
        s_axi_awuser   => s_axi_awuser,
        s_axi_awvalid  => s_axi_awvalid,
        s_axi_awready  => s_axi_awready,
        s_axi_wdata    => s_axi_wdata,
        s_axi_wstrb    => s_axi_wstrb,
        s_axi_wlast    => s_axi_wlast,
        s_axi_wuser    => s_axi_wuser,
        s_axi_wvalid   => s_axi_wvalid,
        s_axi_wready   => s_axi_wready,
        s_axi_bid      => s_axi_bid,
        s_axi_bresp    => s_axi_bresp,
        s_axi_buser    => s_axi_buser,
        s_axi_bvalid   => s_axi_bvalid,
        s_axi_bready   => s_axi_bready,

        s_axi_arid     => s_axi_arid,
        s_axi_araddr   => s_axi_araddr,
        s_axi_arlen    => s_axi_arlen,
        s_axi_arsize   => s_axi_arsize,
        s_axi_arburst  => s_axi_arburst,
        s_axi_arlock   => s_axi_arlock,
        s_axi_arcache  => s_axi_arcache,
        s_axi_arprot   => s_axi_arprot,
        s_axi_arqos    => s_axi_arqos,
        s_axi_arregion => s_axi_arregion,
        s_axi_aruser   => s_axi_aruser,
        s_axi_arvalid  => s_axi_arvalid,
        s_axi_arready  => s_axi_arready,
        s_axi_rid      => s_axi_rid,
        s_axi_rdata    => s_axi_rdata,
        s_axi_rresp    => s_axi_rresp,
        s_axi_rlast    => s_axi_rlast,
        s_axi_ruser    => s_axi_ruser,
        s_axi_rvalid   => s_axi_rvalid,
        s_axi_rready   => s_axi_rready,

        m_axi_aclk    => m_axi_aclk,
        m_axi_aresetn => m_axi_aresetn,
        m_axi_awid    => m_axi_awid,
        m_axi_awaddr  => m_axi_awaddr,
        m_axi_awlen   => m_axi_awlen,
        m_axi_awsize  => m_axi_awsize,
        m_axi_awburst => m_axi_awburst,
        m_axi_awlock  => m_axi_awlock,
        m_axi_awcache => m_axi_awcache,
        m_axi_awprot  => m_axi_awprot,
        m_axi_awqos   => m_axi_awqos,
        m_axi_awuser  => m_axi_awuser,
        m_axi_awvalid => m_axi_awvalid,
        m_axi_awready => m_axi_awready,
        m_axi_wdata   => m_axi_wdata,
        m_axi_wstrb   => m_axi_wstrb,
        m_axi_wlast   => m_axi_wlast,
        m_axi_wuser   => m_axi_wuser,
        m_axi_wvalid  => m_axi_wvalid,
        m_axi_wready  => m_axi_wready,
        m_axi_bid     => m_axi_bid,
        m_axi_bresp   => m_axi_bresp,
        m_axi_buser   => m_axi_buser,
        m_axi_bvalid  => m_axi_bvalid,
        m_axi_bready  => m_axi_bready,

        m_axi_arid    => m_axi_arid,
        m_axi_araddr  => m_axi_araddr,
        m_axi_arlen   => m_axi_arlen,
        m_axi_arsize  => m_axi_arsize,
        m_axi_arburst => m_axi_arburst,
        m_axi_arlock  => m_axi_arlock,
        m_axi_arcache => m_axi_arcache,
        m_axi_arprot  => m_axi_arprot,
        m_axi_arqos   => m_axi_arqos,
        m_axi_aruser  => m_axi_aruser,
        m_axi_arvalid => m_axi_arvalid,
        m_axi_arready => m_axi_arready,
        m_axi_rid     => m_axi_rid,
        m_axi_rdata   => m_axi_rdata,
        m_axi_rresp   => m_axi_rresp,
        m_axi_rlast   => m_axi_rlast,
        m_axi_ruser   => m_axi_ruser,
        m_axi_rvalid  => m_axi_rvalid,
        m_axi_rready  => m_axi_rready
        );
  end generate aes_cbc;

  prince_xts : if CRYPTO_CONFIG = 7 generate
    memsec : entity work.memsec_block_encryption
      generic map(
        C_S_AXI_ID_WIDTH     => C_S_AXI_ID_WIDTH,
        C_S_AXI_DATA_WIDTH   => C_S_AXI_DATA_WIDTH,
        C_S_AXI_ADDR_WIDTH   => C_S_AXI_ADDR_WIDTH,
        C_S_AXI_ARUSER_WIDTH => C_S_AXI_ARUSER_WIDTH,
        C_S_AXI_AWUSER_WIDTH => C_S_AXI_AWUSER_WIDTH,
        C_S_AXI_WUSER_WIDTH  => C_S_AXI_WUSER_WIDTH,
        C_S_AXI_RUSER_WIDTH  => C_S_AXI_RUSER_WIDTH,
        C_S_AXI_BUSER_WIDTH  => C_S_AXI_BUSER_WIDTH,

        C_M_AXI_ID_WIDTH     => C_M_AXI_ID_WIDTH,
        C_M_AXI_DATA_WIDTH   => C_M_AXI_DATA_WIDTH,
        C_M_AXI_ADDR_WIDTH   => C_M_AXI_ADDR_WIDTH,
        C_M_AXI_ARUSER_WIDTH => C_M_AXI_ARUSER_WIDTH,
        C_M_AXI_AWUSER_WIDTH => C_M_AXI_AWUSER_WIDTH,
        C_M_AXI_WUSER_WIDTH  => C_M_AXI_WUSER_WIDTH,
        C_M_AXI_RUSER_WIDTH  => C_M_AXI_RUSER_WIDTH,
        C_M_AXI_BUSER_WIDTH  => C_M_AXI_BUSER_WIDTH,

        CRYPTO_CONFIG     => CRYPTO_PRINCE_XTS,
        DATA_BLOCK_SIZE   => 8,
        BLOCKS_PER_SECTOR => BLOCKS_PER_SECTOR
        )
      port map(
        s_axi_aclk     => s_axi_aclk,
        s_axi_aresetn  => s_axi_aresetn,
        s_axi_awid     => s_axi_awid,
        s_axi_awaddr   => s_axi_awaddr,
        s_axi_awlen    => s_axi_awlen,
        s_axi_awsize   => s_axi_awsize,
        s_axi_awburst  => s_axi_awburst,
        s_axi_awlock   => s_axi_awlock,
        s_axi_awcache  => s_axi_awcache,
        s_axi_awprot   => s_axi_awprot,
        s_axi_awqos    => s_axi_awqos,
        s_axi_awregion => s_axi_awregion,
        s_axi_awuser   => s_axi_awuser,
        s_axi_awvalid  => s_axi_awvalid,
        s_axi_awready  => s_axi_awready,
        s_axi_wdata    => s_axi_wdata,
        s_axi_wstrb    => s_axi_wstrb,
        s_axi_wlast    => s_axi_wlast,
        s_axi_wuser    => s_axi_wuser,
        s_axi_wvalid   => s_axi_wvalid,
        s_axi_wready   => s_axi_wready,
        s_axi_bid      => s_axi_bid,
        s_axi_bresp    => s_axi_bresp,
        s_axi_buser    => s_axi_buser,
        s_axi_bvalid   => s_axi_bvalid,
        s_axi_bready   => s_axi_bready,

        s_axi_arid     => s_axi_arid,
        s_axi_araddr   => s_axi_araddr,
        s_axi_arlen    => s_axi_arlen,
        s_axi_arsize   => s_axi_arsize,
        s_axi_arburst  => s_axi_arburst,
        s_axi_arlock   => s_axi_arlock,
        s_axi_arcache  => s_axi_arcache,
        s_axi_arprot   => s_axi_arprot,
        s_axi_arqos    => s_axi_arqos,
        s_axi_arregion => s_axi_arregion,
        s_axi_aruser   => s_axi_aruser,
        s_axi_arvalid  => s_axi_arvalid,
        s_axi_arready  => s_axi_arready,
        s_axi_rid      => s_axi_rid,
        s_axi_rdata    => s_axi_rdata,
        s_axi_rresp    => s_axi_rresp,
        s_axi_rlast    => s_axi_rlast,
        s_axi_ruser    => s_axi_ruser,
        s_axi_rvalid   => s_axi_rvalid,
        s_axi_rready   => s_axi_rready,

        m_axi_aclk    => m_axi_aclk,
        m_axi_aresetn => m_axi_aresetn,
        m_axi_awid    => m_axi_awid,
        m_axi_awaddr  => m_axi_awaddr,
        m_axi_awlen   => m_axi_awlen,
        m_axi_awsize  => m_axi_awsize,
        m_axi_awburst => m_axi_awburst,
        m_axi_awlock  => m_axi_awlock,
        m_axi_awcache => m_axi_awcache,
        m_axi_awprot  => m_axi_awprot,
        m_axi_awqos   => m_axi_awqos,
        m_axi_awuser  => m_axi_awuser,
        m_axi_awvalid => m_axi_awvalid,
        m_axi_awready => m_axi_awready,
        m_axi_wdata   => m_axi_wdata,
        m_axi_wstrb   => m_axi_wstrb,
        m_axi_wlast   => m_axi_wlast,
        m_axi_wuser   => m_axi_wuser,
        m_axi_wvalid  => m_axi_wvalid,
        m_axi_wready  => m_axi_wready,
        m_axi_bid     => m_axi_bid,
        m_axi_bresp   => m_axi_bresp,
        m_axi_buser   => m_axi_buser,
        m_axi_bvalid  => m_axi_bvalid,
        m_axi_bready  => m_axi_bready,

        m_axi_arid    => m_axi_arid,
        m_axi_araddr  => m_axi_araddr,
        m_axi_arlen   => m_axi_arlen,
        m_axi_arsize  => m_axi_arsize,
        m_axi_arburst => m_axi_arburst,
        m_axi_arlock  => m_axi_arlock,
        m_axi_arcache => m_axi_arcache,
        m_axi_arprot  => m_axi_arprot,
        m_axi_arqos   => m_axi_arqos,
        m_axi_aruser  => m_axi_aruser,
        m_axi_arvalid => m_axi_arvalid,
        m_axi_arready => m_axi_arready,
        m_axi_rid     => m_axi_rid,
        m_axi_rdata   => m_axi_rdata,
        m_axi_rresp   => m_axi_rresp,
        m_axi_rlast   => m_axi_rlast,
        m_axi_ruser   => m_axi_ruser,
        m_axi_rvalid  => m_axi_rvalid,
        m_axi_rready  => m_axi_rready
        );
  end generate prince_xts;

  aes_xts : if CRYPTO_CONFIG = 8 generate
    memsec : entity work.memsec_block_encryption
      generic map(
        C_S_AXI_ID_WIDTH     => C_S_AXI_ID_WIDTH,
        C_S_AXI_DATA_WIDTH   => C_S_AXI_DATA_WIDTH,
        C_S_AXI_ADDR_WIDTH   => C_S_AXI_ADDR_WIDTH,
        C_S_AXI_ARUSER_WIDTH => C_S_AXI_ARUSER_WIDTH,
        C_S_AXI_AWUSER_WIDTH => C_S_AXI_AWUSER_WIDTH,
        C_S_AXI_WUSER_WIDTH  => C_S_AXI_WUSER_WIDTH,
        C_S_AXI_RUSER_WIDTH  => C_S_AXI_RUSER_WIDTH,
        C_S_AXI_BUSER_WIDTH  => C_S_AXI_BUSER_WIDTH,

        C_M_AXI_ID_WIDTH     => C_M_AXI_ID_WIDTH,
        C_M_AXI_DATA_WIDTH   => C_M_AXI_DATA_WIDTH,
        C_M_AXI_ADDR_WIDTH   => C_M_AXI_ADDR_WIDTH,
        C_M_AXI_ARUSER_WIDTH => C_M_AXI_ARUSER_WIDTH,
        C_M_AXI_AWUSER_WIDTH => C_M_AXI_AWUSER_WIDTH,
        C_M_AXI_WUSER_WIDTH  => C_M_AXI_WUSER_WIDTH,
        C_M_AXI_RUSER_WIDTH  => C_M_AXI_RUSER_WIDTH,
        C_M_AXI_BUSER_WIDTH  => C_M_AXI_BUSER_WIDTH,

        CRYPTO_CONFIG     => CRYPTO_AES_XTS,
        DATA_BLOCK_SIZE   => 16,
        BLOCKS_PER_SECTOR => BLOCKS_PER_SECTOR
        )
      port map(
        s_axi_aclk     => s_axi_aclk,
        s_axi_aresetn  => s_axi_aresetn,
        s_axi_awid     => s_axi_awid,
        s_axi_awaddr   => s_axi_awaddr,
        s_axi_awlen    => s_axi_awlen,
        s_axi_awsize   => s_axi_awsize,
        s_axi_awburst  => s_axi_awburst,
        s_axi_awlock   => s_axi_awlock,
        s_axi_awcache  => s_axi_awcache,
        s_axi_awprot   => s_axi_awprot,
        s_axi_awqos    => s_axi_awqos,
        s_axi_awregion => s_axi_awregion,
        s_axi_awuser   => s_axi_awuser,
        s_axi_awvalid  => s_axi_awvalid,
        s_axi_awready  => s_axi_awready,
        s_axi_wdata    => s_axi_wdata,
        s_axi_wstrb    => s_axi_wstrb,
        s_axi_wlast    => s_axi_wlast,
        s_axi_wuser    => s_axi_wuser,
        s_axi_wvalid   => s_axi_wvalid,
        s_axi_wready   => s_axi_wready,
        s_axi_bid      => s_axi_bid,
        s_axi_bresp    => s_axi_bresp,
        s_axi_buser    => s_axi_buser,
        s_axi_bvalid   => s_axi_bvalid,
        s_axi_bready   => s_axi_bready,

        s_axi_arid     => s_axi_arid,
        s_axi_araddr   => s_axi_araddr,
        s_axi_arlen    => s_axi_arlen,
        s_axi_arsize   => s_axi_arsize,
        s_axi_arburst  => s_axi_arburst,
        s_axi_arlock   => s_axi_arlock,
        s_axi_arcache  => s_axi_arcache,
        s_axi_arprot   => s_axi_arprot,
        s_axi_arqos    => s_axi_arqos,
        s_axi_arregion => s_axi_arregion,
        s_axi_aruser   => s_axi_aruser,
        s_axi_arvalid  => s_axi_arvalid,
        s_axi_arready  => s_axi_arready,
        s_axi_rid      => s_axi_rid,
        s_axi_rdata    => s_axi_rdata,
        s_axi_rresp    => s_axi_rresp,
        s_axi_rlast    => s_axi_rlast,
        s_axi_ruser    => s_axi_ruser,
        s_axi_rvalid   => s_axi_rvalid,
        s_axi_rready   => s_axi_rready,

        m_axi_aclk    => m_axi_aclk,
        m_axi_aresetn => m_axi_aresetn,
        m_axi_awid    => m_axi_awid,
        m_axi_awaddr  => m_axi_awaddr,
        m_axi_awlen   => m_axi_awlen,
        m_axi_awsize  => m_axi_awsize,
        m_axi_awburst => m_axi_awburst,
        m_axi_awlock  => m_axi_awlock,
        m_axi_awcache => m_axi_awcache,
        m_axi_awprot  => m_axi_awprot,
        m_axi_awqos   => m_axi_awqos,
        m_axi_awuser  => m_axi_awuser,
        m_axi_awvalid => m_axi_awvalid,
        m_axi_awready => m_axi_awready,
        m_axi_wdata   => m_axi_wdata,
        m_axi_wstrb   => m_axi_wstrb,
        m_axi_wlast   => m_axi_wlast,
        m_axi_wuser   => m_axi_wuser,
        m_axi_wvalid  => m_axi_wvalid,
        m_axi_wready  => m_axi_wready,
        m_axi_bid     => m_axi_bid,
        m_axi_bresp   => m_axi_bresp,
        m_axi_buser   => m_axi_buser,
        m_axi_bvalid  => m_axi_bvalid,
        m_axi_bready  => m_axi_bready,

        m_axi_arid    => m_axi_arid,
        m_axi_araddr  => m_axi_araddr,
        m_axi_arlen   => m_axi_arlen,
        m_axi_arsize  => m_axi_arsize,
        m_axi_arburst => m_axi_arburst,
        m_axi_arlock  => m_axi_arlock,
        m_axi_arcache => m_axi_arcache,
        m_axi_arprot  => m_axi_arprot,
        m_axi_arqos   => m_axi_arqos,
        m_axi_aruser  => m_axi_aruser,
        m_axi_arvalid => m_axi_arvalid,
        m_axi_arready => m_axi_arready,
        m_axi_rid     => m_axi_rid,
        m_axi_rdata   => m_axi_rdata,
        m_axi_rresp   => m_axi_rresp,
        m_axi_rlast   => m_axi_rlast,
        m_axi_ruser   => m_axi_ruser,
        m_axi_rvalid  => m_axi_rvalid,
        m_axi_rready  => m_axi_rready
        );
  end generate aes_xts;

  meas : if CRYPTO_CONFIG = 9 generate
    memsec : entity work.memsec_meas
      generic map(
        C_S_AXI_ID_WIDTH     => C_S_AXI_ID_WIDTH,
        C_S_AXI_DATA_WIDTH   => C_S_AXI_DATA_WIDTH,
        C_S_AXI_ADDR_WIDTH   => C_S_AXI_ADDR_WIDTH,
        C_S_AXI_ARUSER_WIDTH => C_S_AXI_ARUSER_WIDTH,
        C_S_AXI_AWUSER_WIDTH => C_S_AXI_AWUSER_WIDTH,
        C_S_AXI_WUSER_WIDTH  => C_S_AXI_WUSER_WIDTH,
        C_S_AXI_RUSER_WIDTH  => C_S_AXI_RUSER_WIDTH,
        C_S_AXI_BUSER_WIDTH  => C_S_AXI_BUSER_WIDTH,

        C_M_AXI_ID_WIDTH     => C_M_AXI_ID_WIDTH,
        C_M_AXI_DATA_WIDTH   => C_M_AXI_DATA_WIDTH,
        C_M_AXI_ADDR_WIDTH   => C_M_AXI_ADDR_WIDTH,
        C_M_AXI_ARUSER_WIDTH => C_M_AXI_ARUSER_WIDTH,
        C_M_AXI_AWUSER_WIDTH => C_M_AXI_AWUSER_WIDTH,
        C_M_AXI_WUSER_WIDTH  => C_M_AXI_WUSER_WIDTH,
        C_M_AXI_RUSER_WIDTH  => C_M_AXI_RUSER_WIDTH,
        C_M_AXI_BUSER_WIDTH  => C_M_AXI_BUSER_WIDTH,

        DATA_BLOCK_SIZE      => DATA_BLOCK_SIZE,
        DATA_MEMORY_SIZE     => DATA_MEMORY_SIZE,
        DATA_TAGSIZE         => DATA_TAG_SIZE,
        TREE_ARITY           => TREE_ARITY,
        TREE_ROOTS           => TREE_ROOTS,
        TREE_NODE_CACHE_SIZE => TREE_NODE_CACHE_SIZE,
        TREE_ECB             => false
        )
      port map(
        s_axi_aclk     => s_axi_aclk,
        s_axi_aresetn  => s_axi_aresetn,
        s_axi_awid     => s_axi_awid,
        s_axi_awaddr   => s_axi_awaddr,
        s_axi_awlen    => s_axi_awlen,
        s_axi_awsize   => s_axi_awsize,
        s_axi_awburst  => s_axi_awburst,
        s_axi_awlock   => s_axi_awlock,
        s_axi_awcache  => s_axi_awcache,
        s_axi_awprot   => s_axi_awprot,
        s_axi_awqos    => s_axi_awqos,
        s_axi_awregion => s_axi_awregion,
        s_axi_awuser   => s_axi_awuser,
        s_axi_awvalid  => s_axi_awvalid,
        s_axi_awready  => s_axi_awready,
        s_axi_wdata    => s_axi_wdata,
        s_axi_wstrb    => s_axi_wstrb,
        s_axi_wlast    => s_axi_wlast,
        s_axi_wuser    => s_axi_wuser,
        s_axi_wvalid   => s_axi_wvalid,
        s_axi_wready   => s_axi_wready,
        s_axi_bid      => s_axi_bid,
        s_axi_bresp    => s_axi_bresp,
        s_axi_buser    => s_axi_buser,
        s_axi_bvalid   => s_axi_bvalid,
        s_axi_bready   => s_axi_bready,

        s_axi_arid     => s_axi_arid,
        s_axi_araddr   => s_axi_araddr,
        s_axi_arlen    => s_axi_arlen,
        s_axi_arsize   => s_axi_arsize,
        s_axi_arburst  => s_axi_arburst,
        s_axi_arlock   => s_axi_arlock,
        s_axi_arcache  => s_axi_arcache,
        s_axi_arprot   => s_axi_arprot,
        s_axi_arqos    => s_axi_arqos,
        s_axi_arregion => s_axi_arregion,
        s_axi_aruser   => s_axi_aruser,
        s_axi_arvalid  => s_axi_arvalid,
        s_axi_arready  => s_axi_arready,
        s_axi_rid      => s_axi_rid,
        s_axi_rdata    => s_axi_rdata,
        s_axi_rresp    => s_axi_rresp,
        s_axi_rlast    => s_axi_rlast,
        s_axi_ruser    => s_axi_ruser,
        s_axi_rvalid   => s_axi_rvalid,
        s_axi_rready   => s_axi_rready,

        m_axi_aclk    => m_axi_aclk,
        m_axi_aresetn => m_axi_aresetn,
        m_axi_awid    => m_axi_awid,
        m_axi_awaddr  => m_axi_awaddr,
        m_axi_awlen   => m_axi_awlen,
        m_axi_awsize  => m_axi_awsize,
        m_axi_awburst => m_axi_awburst,
        m_axi_awlock  => m_axi_awlock,
        m_axi_awcache => m_axi_awcache,
        m_axi_awprot  => m_axi_awprot,
        m_axi_awqos   => m_axi_awqos,
        m_axi_awuser  => m_axi_awuser,
        m_axi_awvalid => m_axi_awvalid,
        m_axi_awready => m_axi_awready,
        m_axi_wdata   => m_axi_wdata,
        m_axi_wstrb   => m_axi_wstrb,
        m_axi_wlast   => m_axi_wlast,
        m_axi_wuser   => m_axi_wuser,
        m_axi_wvalid  => m_axi_wvalid,
        m_axi_wready  => m_axi_wready,
        m_axi_bid     => m_axi_bid,
        m_axi_bresp   => m_axi_bresp,
        m_axi_buser   => m_axi_buser,
        m_axi_bvalid  => m_axi_bvalid,
        m_axi_bready  => m_axi_bready,

        m_axi_arid    => m_axi_arid,
        m_axi_araddr  => m_axi_araddr,
        m_axi_arlen   => m_axi_arlen,
        m_axi_arsize  => m_axi_arsize,
        m_axi_arburst => m_axi_arburst,
        m_axi_arlock  => m_axi_arlock,
        m_axi_arcache => m_axi_arcache,
        m_axi_arprot  => m_axi_arprot,
        m_axi_arqos   => m_axi_arqos,
        m_axi_aruser  => m_axi_aruser,
        m_axi_arvalid => m_axi_arvalid,
        m_axi_arready => m_axi_arready,
        m_axi_rid     => m_axi_rid,
        m_axi_rdata   => m_axi_rdata,
        m_axi_rresp   => m_axi_rresp,
        m_axi_rlast   => m_axi_rlast,
        m_axi_ruser   => m_axi_ruser,
        m_axi_rvalid  => m_axi_rvalid,
        m_axi_rready  => m_axi_rready
        );
  end generate meas;

  meas_ecb : if CRYPTO_CONFIG = 10 generate
    memsec : entity work.memsec_meas
      generic map(
        C_S_AXI_ID_WIDTH     => C_S_AXI_ID_WIDTH,
        C_S_AXI_DATA_WIDTH   => C_S_AXI_DATA_WIDTH,
        C_S_AXI_ADDR_WIDTH   => C_S_AXI_ADDR_WIDTH,
        C_S_AXI_ARUSER_WIDTH => C_S_AXI_ARUSER_WIDTH,
        C_S_AXI_AWUSER_WIDTH => C_S_AXI_AWUSER_WIDTH,
        C_S_AXI_WUSER_WIDTH  => C_S_AXI_WUSER_WIDTH,
        C_S_AXI_RUSER_WIDTH  => C_S_AXI_RUSER_WIDTH,
        C_S_AXI_BUSER_WIDTH  => C_S_AXI_BUSER_WIDTH,

        C_M_AXI_ID_WIDTH     => C_M_AXI_ID_WIDTH,
        C_M_AXI_DATA_WIDTH   => C_M_AXI_DATA_WIDTH,
        C_M_AXI_ADDR_WIDTH   => C_M_AXI_ADDR_WIDTH,
        C_M_AXI_ARUSER_WIDTH => C_M_AXI_ARUSER_WIDTH,
        C_M_AXI_AWUSER_WIDTH => C_M_AXI_AWUSER_WIDTH,
        C_M_AXI_WUSER_WIDTH  => C_M_AXI_WUSER_WIDTH,
        C_M_AXI_RUSER_WIDTH  => C_M_AXI_RUSER_WIDTH,
        C_M_AXI_BUSER_WIDTH  => C_M_AXI_BUSER_WIDTH,

        DATA_BLOCK_SIZE      => DATA_BLOCK_SIZE,
        DATA_MEMORY_SIZE     => DATA_MEMORY_SIZE,
        DATA_TAGSIZE         => DATA_TAG_SIZE,
        TREE_ARITY           => TREE_ARITY,
        TREE_ROOTS           => TREE_ROOTS,
        TREE_NODE_CACHE_SIZE => TREE_NODE_CACHE_SIZE,
        TREE_ECB             => true
        )
      port map(
        s_axi_aclk     => s_axi_aclk,
        s_axi_aresetn  => s_axi_aresetn,
        s_axi_awid     => s_axi_awid,
        s_axi_awaddr   => s_axi_awaddr,
        s_axi_awlen    => s_axi_awlen,
        s_axi_awsize   => s_axi_awsize,
        s_axi_awburst  => s_axi_awburst,
        s_axi_awlock   => s_axi_awlock,
        s_axi_awcache  => s_axi_awcache,
        s_axi_awprot   => s_axi_awprot,
        s_axi_awqos    => s_axi_awqos,
        s_axi_awregion => s_axi_awregion,
        s_axi_awuser   => s_axi_awuser,
        s_axi_awvalid  => s_axi_awvalid,
        s_axi_awready  => s_axi_awready,
        s_axi_wdata    => s_axi_wdata,
        s_axi_wstrb    => s_axi_wstrb,
        s_axi_wlast    => s_axi_wlast,
        s_axi_wuser    => s_axi_wuser,
        s_axi_wvalid   => s_axi_wvalid,
        s_axi_wready   => s_axi_wready,
        s_axi_bid      => s_axi_bid,
        s_axi_bresp    => s_axi_bresp,
        s_axi_buser    => s_axi_buser,
        s_axi_bvalid   => s_axi_bvalid,
        s_axi_bready   => s_axi_bready,

        s_axi_arid     => s_axi_arid,
        s_axi_araddr   => s_axi_araddr,
        s_axi_arlen    => s_axi_arlen,
        s_axi_arsize   => s_axi_arsize,
        s_axi_arburst  => s_axi_arburst,
        s_axi_arlock   => s_axi_arlock,
        s_axi_arcache  => s_axi_arcache,
        s_axi_arprot   => s_axi_arprot,
        s_axi_arqos    => s_axi_arqos,
        s_axi_arregion => s_axi_arregion,
        s_axi_aruser   => s_axi_aruser,
        s_axi_arvalid  => s_axi_arvalid,
        s_axi_arready  => s_axi_arready,
        s_axi_rid      => s_axi_rid,
        s_axi_rdata    => s_axi_rdata,
        s_axi_rresp    => s_axi_rresp,
        s_axi_rlast    => s_axi_rlast,
        s_axi_ruser    => s_axi_ruser,
        s_axi_rvalid   => s_axi_rvalid,
        s_axi_rready   => s_axi_rready,

        m_axi_aclk    => m_axi_aclk,
        m_axi_aresetn => m_axi_aresetn,
        m_axi_awid    => m_axi_awid,
        m_axi_awaddr  => m_axi_awaddr,
        m_axi_awlen   => m_axi_awlen,
        m_axi_awsize  => m_axi_awsize,
        m_axi_awburst => m_axi_awburst,
        m_axi_awlock  => m_axi_awlock,
        m_axi_awcache => m_axi_awcache,
        m_axi_awprot  => m_axi_awprot,
        m_axi_awqos   => m_axi_awqos,
        m_axi_awuser  => m_axi_awuser,
        m_axi_awvalid => m_axi_awvalid,
        m_axi_awready => m_axi_awready,
        m_axi_wdata   => m_axi_wdata,
        m_axi_wstrb   => m_axi_wstrb,
        m_axi_wlast   => m_axi_wlast,
        m_axi_wuser   => m_axi_wuser,
        m_axi_wvalid  => m_axi_wvalid,
        m_axi_wready  => m_axi_wready,
        m_axi_bid     => m_axi_bid,
        m_axi_bresp   => m_axi_bresp,
        m_axi_buser   => m_axi_buser,
        m_axi_bvalid  => m_axi_bvalid,
        m_axi_bready  => m_axi_bready,

        m_axi_arid    => m_axi_arid,
        m_axi_araddr  => m_axi_araddr,
        m_axi_arlen   => m_axi_arlen,
        m_axi_arsize  => m_axi_arsize,
        m_axi_arburst => m_axi_arburst,
        m_axi_arlock  => m_axi_arlock,
        m_axi_arcache => m_axi_arcache,
        m_axi_arprot  => m_axi_arprot,
        m_axi_arqos   => m_axi_arqos,
        m_axi_aruser  => m_axi_aruser,
        m_axi_arvalid => m_axi_arvalid,
        m_axi_arready => m_axi_arready,
        m_axi_rid     => m_axi_rid,
        m_axi_rdata   => m_axi_rdata,
        m_axi_rresp   => m_axi_rresp,
        m_axi_rlast   => m_axi_rlast,
        m_axi_ruser   => m_axi_ruser,
        m_axi_rvalid  => m_axi_rvalid,
        m_axi_rready  => m_axi_rready
        );
  end generate meas_ecb;
end arch_imp;
