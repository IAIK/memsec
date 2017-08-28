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

library IEEE;
use IEEE.STD_LOGIC_1164.all;
use IEEE.NUMERIC_STD.all;
use IEEE.std_logic_textio.all;
use work.tb_utils_pkg.all;

library std;
use std.textio.all;

entity tb_rw_blockram is
  generic(
    ENTITY_NAME : string := "tb_rw_blockram";
    CLK_PERIOD  : time   := 5.0 ns;

    -- Parameters of Axi Slave Bus Interface S_AXI
    C_S_AXI_ID_WIDTH     : integer := 12;
    C_S_AXI_DATA_WIDTH   : integer := 32;
    C_S_AXI_ADDR_WIDTH   : integer := 32;
    C_S_AXI_AWUSER_WIDTH : integer := 0;
    C_S_AXI_ARUSER_WIDTH : integer := 0;
    C_S_AXI_WUSER_WIDTH  : integer := 0;
    C_S_AXI_RUSER_WIDTH  : integer := 0;
    C_S_AXI_BUSER_WIDTH  : integer := 0;

    -- Parameters of Axi Master Bus Interface M_AXI
    C_M_AXI_ID_WIDTH     : integer := 6;
    C_M_AXI_ADDR_WIDTH   : integer := 32;
    C_M_AXI_DATA_WIDTH   : integer := 64;
    C_M_AXI_AWUSER_WIDTH : integer := 0;
    C_M_AXI_ARUSER_WIDTH : integer := 0;
    C_M_AXI_WUSER_WIDTH  : integer := 0;
    C_M_AXI_RUSER_WIDTH  : integer := 0;
    C_M_AXI_BUSER_WIDTH  : integer := 0;

    -- Crypto parameters
    CRYPTO_CONFIG : integer := 1;

    DATA_MEMORY_SIZE     : integer := 8192;
    TREE_ARITY           : integer := 4;
    TREE_ROOTS           : integer := 4;
    TREE_NODE_CACHE_SIZE : integer := 1024;
    DATA_BLOCK_SIZE      : integer := 32;

    BLOCKS_PER_SECTOR : integer := 4;

    -- Testbench parameters
    SIMULATION_ITERATIONS : integer := 50
    );
end tb_rw_blockram;

architecture Behavioral of tb_rw_blockram is
  signal ClkxC  : std_logic := '0';
  signal RstxRB : std_logic;

  type mem_t is array (0 to 255) of std_logic_vector(C_S_AXI_DATA_WIDTH-1 downto 0);

  signal s_axi_awid     : std_logic_vector(C_S_AXI_ID_WIDTH - 1 downto 0)         := (others => '0');
  signal s_axi_awaddr   : std_logic_vector(C_S_AXI_ADDR_WIDTH - 1 downto 0)       := (others => '0');
  signal s_axi_awlen    : std_logic_vector(7 downto 0)                            := (others => '0');
  signal s_axi_awsize   : std_logic_vector(2 downto 0)                            := (others => '0');
  signal s_axi_awburst  : std_logic_vector(1 downto 0)                            := (others => '0');
  signal s_axi_awlock   : std_logic                                               := '0';
  signal s_axi_awcache  : std_logic_vector(3 downto 0)                            := (others => '0');
  signal s_axi_awprot   : std_logic_vector(2 downto 0)                            := (others => '0');
  signal s_axi_awqos    : std_logic_vector(3 downto 0)                            := (others => '0');
  signal s_axi_awregion : std_logic_vector(3 downto 0)                            := (others => '0');
  signal s_axi_awuser   : std_logic_vector(C_S_AXI_AWUSER_WIDTH - 1 downto 0)     := (others => '0');
  signal s_axi_awvalid  : std_logic                                               := '0';
  signal s_axi_awready  : std_logic;
  signal s_axi_wdata    : std_logic_vector(C_S_AXI_DATA_WIDTH - 1 downto 0)       := (others => '0');
  signal s_axi_wstrb    : std_logic_vector((C_S_AXI_DATA_WIDTH / 8) - 1 downto 0) := (others => '0');
  signal s_axi_wlast    : std_logic                                               := '0';
  signal s_axi_wuser    : std_logic_vector(C_S_AXI_WUSER_WIDTH - 1 downto 0)      := (others => '0');
  signal s_axi_wvalid   : std_logic                                               := '0';
  signal s_axi_wready   : std_logic;
  signal s_axi_bid      : std_logic_vector(C_S_AXI_ID_WIDTH - 1 downto 0);
  signal s_axi_bresp    : std_logic_vector(1 downto 0);
  signal s_axi_buser    : std_logic_vector(C_S_AXI_BUSER_WIDTH - 1 downto 0);
  signal s_axi_bvalid   : std_logic;
  signal s_axi_bready   : std_logic                                               := '1';
  signal s_axi_arid     : std_logic_vector(C_S_AXI_ID_WIDTH - 1 downto 0)         := (others => '0');
  signal s_axi_araddr   : std_logic_vector(C_S_AXI_ADDR_WIDTH - 1 downto 0)       := (others => '0');
  signal s_axi_arlen    : std_logic_vector(7 downto 0)                            := (others => '0');
  signal s_axi_arsize   : std_logic_vector(2 downto 0)                            := (others => '0');
  signal s_axi_arburst  : std_logic_vector(1 downto 0)                            := (others => '0');
  signal s_axi_arlock   : std_logic                                               := '0';
  signal s_axi_arcache  : std_logic_vector(3 downto 0)                            := (others => '0');
  signal s_axi_arprot   : std_logic_vector(2 downto 0)                            := (others => '0');
  signal s_axi_arqos    : std_logic_vector(3 downto 0)                            := (others => '0');
  signal s_axi_arregion : std_logic_vector(3 downto 0)                            := (others => '0');
  signal s_axi_aruser   : std_logic_vector(C_S_AXI_ARUSER_WIDTH - 1 downto 0)     := (others => '0');
  signal s_axi_arvalid  : std_logic                                               := '0';
  signal s_axi_arready  : std_logic;
  signal s_axi_rid      : std_logic_vector(C_S_AXI_ID_WIDTH - 1 downto 0);
  signal s_axi_rdata    : std_logic_vector(C_S_AXI_DATA_WIDTH - 1 downto 0);
  signal s_axi_rresp    : std_logic_vector(1 downto 0);
  signal s_axi_rlast    : std_logic;
  signal s_axi_ruser    : std_logic_vector(C_S_AXI_RUSER_WIDTH - 1 downto 0);
  signal s_axi_rvalid   : std_logic;
  signal s_axi_rready   : std_logic                                               := '1';

  signal m_axi_awid     : std_logic_vector(C_M_AXI_ID_WIDTH - 1 downto 0);
  signal m_axi_awaddr   : std_logic_vector(C_M_AXI_ADDR_WIDTH - 1 downto 0);
  signal m_axi_awregion : std_logic_vector(3 downto 0);
  signal m_axi_awlen    : std_logic_vector(7 downto 0);
  signal m_axi_awsize   : std_logic_vector(2 downto 0);
  signal m_axi_awburst  : std_logic_vector(1 downto 0);
  signal m_axi_awlock   : std_logic;
  signal m_axi_awcache  : std_logic_vector(3 downto 0);
  signal m_axi_awprot   : std_logic_vector(2 downto 0);
  signal m_axi_awqos    : std_logic_vector(3 downto 0);
  signal m_axi_awuser   : std_logic_vector(C_M_AXI_AWUSER_WIDTH - 1 downto 0);
  signal m_axi_awvalid  : std_logic;
  signal m_axi_awready  : std_logic;
  signal m_axi_wdata    : std_logic_vector(C_M_AXI_DATA_WIDTH - 1 downto 0);
  signal m_axi_wstrb    : std_logic_vector(C_M_AXI_DATA_WIDTH / 8 - 1 downto 0);
  signal m_axi_wlast    : std_logic;
  signal m_axi_wuser    : std_logic_vector(C_M_AXI_WUSER_WIDTH - 1 downto 0);
  signal m_axi_wvalid   : std_logic;
  signal m_axi_wready   : std_logic;
  signal m_axi_bid      : std_logic_vector(C_M_AXI_ID_WIDTH - 1 downto 0);
  signal m_axi_bresp    : std_logic_vector(1 downto 0);
  signal m_axi_buser    : std_logic_vector(C_M_AXI_BUSER_WIDTH - 1 downto 0);
  signal m_axi_bvalid   : std_logic;
  signal m_axi_bready   : std_logic;
  signal m_axi_arid     : std_logic_vector(C_M_AXI_ID_WIDTH - 1 downto 0);
  signal m_axi_araddr   : std_logic_vector(C_M_AXI_ADDR_WIDTH - 1 downto 0);
  signal m_axi_arlen    : std_logic_vector(7 downto 0);
  signal m_axi_arsize   : std_logic_vector(2 downto 0);
  signal m_axi_arburst  : std_logic_vector(1 downto 0);
  signal m_axi_arlock   : std_logic;
  signal m_axi_arcache  : std_logic_vector(3 downto 0);
  signal m_axi_arprot   : std_logic_vector(2 downto 0);
  signal m_axi_arqos    : std_logic_vector(3 downto 0);
  signal m_axi_arregion : std_logic_vector(3 downto 0);
  signal m_axi_aruser   : std_logic_vector(C_M_AXI_ARUSER_WIDTH - 1 downto 0);
  signal m_axi_arvalid  : std_logic;
  signal m_axi_arready  : std_logic;
  signal m_axi_rid      : std_logic_vector(C_M_AXI_ID_WIDTH - 1 downto 0);
  signal m_axi_rdata    : std_logic_vector(C_M_AXI_DATA_WIDTH - 1 downto 0);
  signal m_axi_rresp    : std_logic_vector(1 downto 0);
  signal m_axi_rlast    : std_logic;
  signal m_axi_ruser    : std_logic_vector(C_M_AXI_RUSER_WIDTH - 1 downto 0);
  signal m_axi_rvalid   : std_logic;
  signal m_axi_rready   : std_logic;

begin
  -- Generate clock and reset
  ClkxC  <= not ClkxC after CLK_PERIOD;
  RstxRB <= '0', '1'  after 20 ns;

  m_axi_awregion <= (others => '0');
  m_axi_arregion <= (others => '0');

  -- Memory implementation
  memory : entity work.axi_block_memory
    port map (
      s_aclk        => ClkxC,
      s_aresetn     => RstxRB,
      s_axi_awid    => m_axi_awid,
      s_axi_awaddr  => m_axi_awaddr,
      s_axi_awlen   => m_axi_awlen,
      s_axi_awsize  => m_axi_awsize,
      s_axi_awburst => m_axi_awburst,
      s_axi_awvalid => m_axi_awvalid,
      s_axi_awready => m_axi_awready,
      s_axi_wdata   => m_axi_wdata,
      s_axi_wstrb   => m_axi_wstrb,
      s_axi_wlast   => m_axi_wlast,
      s_axi_wvalid  => m_axi_wvalid,
      s_axi_wready  => m_axi_wready,
      s_axi_bid     => m_axi_bid,
      s_axi_bresp   => m_axi_bresp,
      s_axi_bvalid  => m_axi_bvalid,
      s_axi_bready  => m_axi_bready,
      s_axi_arid    => m_axi_arid,
      s_axi_araddr  => m_axi_araddr,
      s_axi_arlen   => m_axi_arlen,
      s_axi_arsize  => m_axi_arsize,
      s_axi_arburst => m_axi_arburst,
      s_axi_arvalid => m_axi_arvalid,
      s_axi_arready => m_axi_arready,
      s_axi_rid     => m_axi_rid,
      s_axi_rdata   => m_axi_rdata,
      s_axi_rresp   => m_axi_rresp,
      s_axi_rlast   => m_axi_rlast,
      s_axi_rvalid  => m_axi_rvalid,
      s_axi_rready  => m_axi_rready
      );

  MEMSEC : entity work.memsec
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
      CRYPTO_CONFIG        => CRYPTO_CONFIG,
      DATA_MEMORY_SIZE     => DATA_MEMORY_SIZE,
      TREE_ROOTS           => TREE_ROOTS,
      TREE_ARITY           => TREE_ARITY,
      TREE_NODE_CACHE_SIZE => TREE_NODE_CACHE_SIZE,
      DATA_BLOCK_SIZE      => DATA_BLOCK_SIZE,
      BLOCKS_PER_SECTOR    => BLOCKS_PER_SECTOR
      )
    port map(
      s_axi_aclk     => ClkxC,
      s_axi_aresetn  => RstxRB,
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

      m_axi_aclk    => ClkxC,
      m_axi_aresetn => RstxRB,
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

  rw_testcase : process
    variable line_number        : integer := 0;
    variable space              : character;
    variable v_burst_type       : std_logic_vector(1 downto 0);
    variable v_addr             : std_logic_vector(C_M_AXI_ADDR_WIDTH-1 downto 0);
    variable v_arsize           : std_logic_vector(2 downto 0);
    variable v_arlen            : std_logic_vector(7 downto 0);
    variable v_wlen             : std_logic_vector(7 downto 0);
    variable data               : std_logic_vector(C_S_AXI_DATA_WIDTH-1 downto 0);
    variable v_passed_testcases : integer := 0;
    variable error_occured      : boolean := false;

    variable iteration : integer;
    variable address   : integer;

    variable v_count_expected_data : integer;
    variable v_expected_data       : mem_t;
    variable v_count_read_data     : integer;
    variable v_read_data           : mem_t;

    variable value          : std_logic_vector(C_S_AXI_DATA_WIDTH-1 downto 0);
    variable value_expected : std_logic_vector(C_S_AXI_DATA_WIDTH-1 downto 0);
  begin

    s_axi_arsize  <= (others => '0');
    s_axi_arlen   <= (others => '0');
    s_axi_araddr  <= (others => '0');
    s_axi_arburst <= (others => '0');
    s_axi_arvalid <= '0';
    s_axi_awaddr  <= (others => '0');
    s_axi_awsize  <= (others => '0');
    s_axi_awlen   <= (others => '0');
    s_axi_awid    <= (others => '0');
    s_axi_awvalid <= '0';

    -- Wait until reset done
    wait until rising_edge(RstxRB);

    iteration := 0;

    v_burst_type := "10";
    v_addr       := x"40000080";
    v_arsize     := "010";
    v_arlen      := x"07";

    while iteration <= SIMULATION_ITERATIONS loop
      iteration := iteration + 1;
      wait until falling_edge(ClkxC);

      -- Apply read information stimuli
      s_axi_arburst <= v_burst_type;
      s_axi_araddr  <= v_addr;
      s_axi_arsize  <= v_arsize;
      s_axi_arlen   <= v_arlen;
      s_axi_arid    <= x"000";

      s_axi_arlock   <= '0';
      s_axi_arcache  <= (others => '0');
      s_axi_arprot   <= (others => '0');
      s_axi_arqos    <= (others => '0');
      s_axi_arregion <= (others => '0');

      -- Start transfer
      s_axi_arvalid <= '1';
      loop
        wait until rising_edge(ClkxC);
        exit when s_axi_arready = '1';
      end loop;
      s_axi_arvalid <= '0';

      v_count_expected_data := 0;
      -- Wait for valid data
      loop
        loop
          wait until falling_edge(ClkxC);
          exit when s_axi_rvalid = '1';
        end loop;

        -- Save data to buffer
        v_expected_data(v_count_expected_data) := s_axi_rdata;
        v_count_expected_data                  := v_count_expected_data + 1;

        if unsigned(s_axi_rresp) /= 0 then
          report "ERROR: Read Response";
          error_occured := true;
        end if;

        exit when s_axi_rlast = '1';
      end loop;

      -- Transmission finished
      wait until s_axi_rlast = '0';
      wait for 2*CLK_PERIOD;

      -- Start Write
      v_expected_data(0) := not(v_expected_data(0));
      v_wlen             := x"0f";
      s_axi_awburst      <= "01";
      s_axi_awaddr       <= v_addr;
      s_axi_awsize       <= v_arsize;
      s_axi_awlen        <= v_wlen;
      s_axi_awid         <= x"000";

      -- Start transfer
      s_axi_awvalid <= '1';

      loop
        wait until rising_edge(ClkxC);
        exit when s_axi_awready = '1';
      end loop;

      wait until falling_edge(ClkxC);
      s_axi_awvalid <= '0';

      s_axi_wdata  <= v_expected_data(0);
      s_axi_wstrb  <= x"f";
      s_axi_wvalid <= '1';
      loop
        if unsigned(v_wlen) = 0 then
          s_axi_wlast <= '1';
        end if;
        wait until rising_edge(ClkxC) and s_axi_wready = '1';
        s_axi_wstrb <= x"0";
        exit when unsigned(v_wlen) = 0;
        v_wlen      := std_logic_vector(unsigned(v_wlen) - 1);
      end loop;

      s_axi_wvalid <= '1';
      s_axi_wlast  <= '0';

      if s_axi_bvalid = '0' then
        loop
          wait until rising_edge(ClkxC);
          exit when s_axi_bvalid = '1';
        end loop;
      end if;

      if unsigned(s_axi_bresp) /= 0 then
        report "ERROR: Write Response";
        error_occured := true;
      end if;

      -- Start transfer
      s_axi_arvalid <= '1';
      loop
        wait until rising_edge(ClkxC);
        exit when s_axi_arready = '1';
      end loop;
      s_axi_arvalid <= '0';

      -- Wait for valid data
      v_count_read_data := 0;
      loop
        loop
          wait until falling_edge(ClkxC);
          exit when s_axi_rvalid = '1';
        end loop;

        -- Save data to buffer
        v_read_data(v_count_read_data) := s_axi_rdata;
        v_count_read_data              := v_count_read_data + 1;

        if unsigned(s_axi_rresp) /= 0 then
          report "ERROR: Read Response";
          error_occured := true;
        end if;

        exit when s_axi_rlast = '1';
      end loop;

      -- Check data

      for i in 0 to v_count_read_data-1 loop
        if v_expected_data(i) /= v_read_data(i) then
          report "Expected " & to_hstring(v_expected_data(i));
          report "Got      " & to_hstring(v_read_data(i));
          error_occured := true;
        end if;

        if v_count_expected_data /= v_count_read_data then
          report "Expected length " & integer'image(v_count_expected_data);
          report "Got length      " & integer'image(v_count_read_data);
          report "ERROR: Data length mismatch";
          error_occured := true;
        end if;

        if error_occured then
          write_tb_fail(ENTITY_NAME);
          report "ERROR" severity failure;
        end if;

        v_passed_testcases := v_passed_testcases + 1;
      end loop;

      v_addr := std_logic_vector(unsigned(v_addr)+4);
      if v_addr = x"40002000" then
        v_addr := x"40000000";
      end if;
    end loop;

    write_tb_success(ENTITY_NAME);
    report integer'image(v_passed_testcases) & " testcases passed";
    report "Simulation complete" severity failure;
  end process;

end Behavioral;
