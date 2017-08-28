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

entity memsec_ascon is
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

    DATA_BLOCK_SIZE : integer := 64  -- Size of one block in the virtual address space in byte.
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
end memsec_ascon;

architecture arch_imp of memsec_ascon is
  constant SPLIT_REQUESTS : boolean := true;
  constant METADATA       : integer := 16;  -- Meta data size in byte

  -- request modifier to issuer over scheduler
  signal read_request, write_request, request                   : StreamType;
  signal read_request_ready, write_request_ready, request_ready : std_logic;

  -- to register and issuer
  signal registered_request, crypto_request, issuer_request, request_locker                         : StreamType;
  signal registered_request_ready, crypto_request_ready, issuer_request_ready, request_locker_ready : std_logic;

  -- issuer to register stage
  signal issue_to_reg       : StreamType;
  signal issue_to_reg_ready : std_logic;

  -- register stage to fetcher
  signal reg_to_fetch       : StreamType;
  signal reg_to_fetch_ready : std_logic;

  -- request fetcher to decryption
  signal fetch_to_dec       : StreamType;
  signal fetch_to_dec_ready : std_logic;

  -- request fetcher to decryption
  signal dec_to_init       : StreamType;
  signal dec_to_init_ready : std_logic;

  -- decryption to read responder and data modifier
  signal plain_request, plain_request_read, plain_request_write                   : StreamType;
  signal plain_request_ready, plain_request_read_ready, plain_request_write_ready : std_logic;

  -- filtered read
  signal filtered_read_request       : StreamType;
  signal filtered_read_request_ready : std_logic;

  -- wrap burst cached read
  signal cached_read_request       : StreamType;
  signal cached_read_request_ready : std_logic;

  -- data modifier to nonce incrementer
  signal data_to_nonce_inc       : StreamType;
  signal data_to_nonce_inc_ready : std_logic;

  -- nonce incrementer to reg
  signal nonce_inc_to_write_issue       : StreamType;
  signal nonce_inc_to_write_issue_ready : std_logic;

  -- data register stage to encryption
  signal reg_to_enc       : StreamType;
  signal reg_to_enc_ready : std_logic;

  -- encryption to writer
  signal enc_to_write_data        : StreamType;
  signal enc_to_write_data_ready  : std_logic;
  signal write_issue_to_reg       : StreamType;
  signal write_issue_to_reg_ready : std_logic;
  signal data_to_responder        : StreamType;
  signal data_to_responder_ready  : std_logic;

  -- lock the pipeline
  signal release_lock, release_lock_ready : std_logic;
begin
  m_axi_arregion <= (others => '0');
  m_axi_awregion <= (others => '0');

  req_mod_read : entity work.cpu_request_modifier
    generic map(
      C_S_AXI_ID_WIDTH    => C_S_AXI_ID_WIDTH,
      C_S_AXI_ADDR_WIDTH  => C_S_AXI_ADDR_WIDTH,
      C_S_AXI_AUSER_WIDTH => C_S_AXI_ARUSER_WIDTH,
      READ                => '1',
      DOUBLE_LINEFILL     => (DATA_BLOCK_SIZE = 64)
      )
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      s_axi_aid     => s_axi_arid,
      s_axi_aaddr   => s_axi_araddr,
      s_axi_alen    => s_axi_arlen,
      s_axi_asize   => s_axi_arsize,
      s_axi_aburst  => s_axi_arburst,
      s_axi_alock   => s_axi_arlock,
      s_axi_acache  => s_axi_arcache,
      s_axi_aprot   => s_axi_arprot,
      s_axi_aqos    => s_axi_arqos,
      s_axi_aregion => s_axi_arregion,
      s_axi_auser   => s_axi_aruser,
      s_axi_avalid  => s_axi_arvalid,
      s_axi_aready  => s_axi_arready,

      m_request       => read_request,
      m_request_ready => read_request_ready);

  req_mod_write : entity work.cpu_request_modifier
    generic map(
      C_S_AXI_ID_WIDTH    => C_S_AXI_ID_WIDTH,
      C_S_AXI_ADDR_WIDTH  => C_S_AXI_ADDR_WIDTH,
      C_S_AXI_AUSER_WIDTH => C_S_AXI_AWUSER_WIDTH,
      READ                => '0',
      DOUBLE_LINEFILL     => (DATA_BLOCK_SIZE = 64)
      )
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      s_axi_aid     => s_axi_awid,
      s_axi_aaddr   => s_axi_awaddr,
      s_axi_alen    => s_axi_awlen,
      s_axi_asize   => s_axi_awsize,
      s_axi_aburst  => s_axi_awburst,
      s_axi_alock   => s_axi_awlock,
      s_axi_acache  => s_axi_awcache,
      s_axi_aprot   => s_axi_awprot,
      s_axi_aqos    => s_axi_awqos,
      s_axi_aregion => s_axi_awregion,
      s_axi_auser   => s_axi_awuser,
      s_axi_avalid  => s_axi_awvalid,
      s_axi_aready  => s_axi_awready,

      m_request       => write_request,
      m_request_ready => write_request_ready);

  scheduler : entity work.stream_scheduler
    port map (
      clk               => s_axi_aclk,
      resetn            => s_axi_aresetn,
      s_request_1       => read_request,
      s_request_1_ready => read_request_ready,
      s_request_2       => write_request,
      s_request_2_ready => write_request_ready,
      m_request         => request,
      m_request_ready   => request_ready);

  request_splitter : if SPLIT_REQUESTS = true generate
    scheduler_register_stage : entity work.stream_multi_register_stage
      generic map(
        REGISTERS => 1
        )
      port map (
        clk    => s_axi_aclk,
        resetn => s_axi_aresetn,

        in_data  => request,
        in_valid => request.valid,
        in_ready => request_ready,

        out_data  => registered_request,
        out_valid => open,
        out_ready => registered_request_ready
        );

    request_splitter : entity work.stream_request_splitter
      generic map(
        DATA_BLOCK_SIZE => DATA_BLOCK_SIZE
        )
      port map(
        clk    => s_axi_aclk,
        resetn => s_axi_aresetn,

        s_request       => registered_request,
        s_request_ready => registered_request_ready,

        m_request       => crypto_request,
        m_request_ready => crypto_request_ready
        );
  end generate;

  no_splitter : if SPLIT_REQUESTS = false generate
    crypto_request <= request;
    request_ready  <= crypto_request_ready;
  end generate;

  crypto_req_mod : entity work.stream_crypto_request_modifier
    generic map(
      C_M_AXI_DATA_WIDTH => C_M_AXI_DATA_WIDTH,
      DATA_START_ADDRESS => C_S_AXI_TARGET_SLAVE_BASE_ADDR,
      DATA_ALIGNMENT     => DATA_BLOCK_SIZE,
      DATA_METADATA      => METADATA
      )
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      s_request       => crypto_request,
      s_request_ready => crypto_request_ready,

      m_request       => request_locker,
      m_request_ready => request_locker_ready);

  pipeline_guard : entity work.pipeline_guard
    generic map (
      BLOCK_SIZE => DATA_BLOCK_SIZE,
      FIFO_SIZE  => 4
      )
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      s_request       => request_locker,
      s_request_ready => request_locker_ready,

      m_request       => issuer_request,
      m_request_ready => issuer_request_ready,

      release       => release_lock,
      release_ready => release_lock_ready
      );

  read_request_issuer : entity work.memory_read_issuer
    generic map(
      C_M_AXI_ID_WIDTH     => C_M_AXI_ID_WIDTH,
      C_M_AXI_DATA_WIDTH   => C_M_AXI_DATA_WIDTH,
      C_M_AXI_ADDR_WIDTH   => C_M_AXI_ADDR_WIDTH,
      C_M_AXI_ARUSER_WIDTH => C_M_AXI_ARUSER_WIDTH
      )
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

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

      s_request       => issuer_request,
      s_request_ready => issuer_request_ready,

      m_request       => issue_to_reg,
      m_request_ready => issue_to_reg_ready
      );

  issuer_reg_stage : entity work.stream_multi_register_stage
    generic map(
      REGISTERS => 10
      )
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      in_data  => issue_to_reg,
      in_valid => issue_to_reg.valid,
      in_ready => issue_to_reg_ready,

      out_data  => reg_to_fetch,
      out_valid => open,
      out_ready => reg_to_fetch_ready
      );

  fetcher : entity work.memory_read_fetcher
    generic map(
      C_M_AXI_ID_WIDTH    => C_M_AXI_ID_WIDTH,
      C_M_AXI_DATA_WIDTH  => C_M_AXI_DATA_WIDTH,
      C_M_AXI_RUSER_WIDTH => C_M_AXI_RUSER_WIDTH
      )
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      m_axi_rid    => m_axi_rid,
      m_axi_rdata  => m_axi_rdata,
      m_axi_rresp  => m_axi_rresp,
      m_axi_rlast  => m_axi_rlast,
      m_axi_ruser  => m_axi_ruser,
      m_axi_rvalid => m_axi_rvalid,
      m_axi_rready => m_axi_rready,

      s_request       => reg_to_fetch,
      s_request_ready => reg_to_fetch_ready,

      m_request       => fetch_to_dec,
      m_request_ready => fetch_to_dec_ready
      );

  decryption : entity work.stream_ascon
    generic map (
      DATA_ALIGNMENT => DATA_BLOCK_SIZE
      )
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      s_request       => fetch_to_dec,
      s_request_ready => fetch_to_dec_ready,

      m_request       => dec_to_init,
      m_request_ready => dec_to_init_ready,

      KeyxDI    => (others => '0'),
      DecryptxS => '1'
      );

  zero_initializer : entity work.stream_request_zero_initializer
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      s_request       => dec_to_init,
      s_request_ready => dec_to_init_ready,

      m_request       => plain_request,
      m_request_ready => plain_request_ready
      );

  -- forward reads to the read responder and writes to the data modifier
  switch_plain_data : process(plain_request, plain_request_read_ready, plain_request_write_ready) is
    variable address_req_availablexDV : std_logic;
  begin
    plain_request_read  <= StreamType_default;
    plain_request_write <= StreamType_default;
    plain_request_ready <= '0';

    if plain_request.valid = '1' and plain_request.read = '1' then
      plain_request_read  <= plain_request;
      plain_request_ready <= plain_request_read_ready;
    elsif plain_request.valid = '1' and plain_request.read = '0' then
      plain_request_write <= plain_request;
      plain_request_ready <= plain_request_write_ready;
    end if;
  end process switch_plain_data;

  data_filter : entity work.stream_data_block_filter
    generic map (
      DATASTREAM_OUT_WIDTH => C_S_AXI_DATA_WIDTH,
      ERROR_ACCUMULATION   => true
      )
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      s_request       => plain_request_read,
      s_request_ready => plain_request_read_ready,

      m_request       => filtered_read_request,
      m_request_ready => filtered_read_request_ready
      );

  wrap_burst_cache : entity work.stream_axi_wrap_burst_cache
    generic map (
      DATASTREAM_WIDTH     => C_S_AXI_DATA_WIDTH,
      CACHE_SIZE           => DATA_BLOCK_SIZE*8,
      NARROW_BURST_SUPPORT => (DATA_BLOCK_SIZE = 64)
      )
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      s_request       => filtered_read_request,
      s_request_ready => filtered_read_request_ready,

      m_request       => cached_read_request,
      m_request_ready => cached_read_request_ready
      );

  read_responder : entity work.cpu_read_responder
    generic map(
      C_S_AXI_ID_WIDTH    => C_S_AXI_ID_WIDTH,
      C_S_AXI_DATA_WIDTH  => C_S_AXI_DATA_WIDTH,
      C_S_AXI_RUSER_WIDTH => C_S_AXI_RUSER_WIDTH
      )
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      s_axi_rid    => s_axi_rid,
      s_axi_rdata  => s_axi_rdata,
      s_axi_rresp  => s_axi_rresp,
      s_axi_rlast  => s_axi_rlast,
      s_axi_ruser  => s_axi_ruser,
      s_axi_rvalid => s_axi_rvalid,
      s_axi_rready => s_axi_rready,

      s_request       => cached_read_request,
      s_request_ready => cached_read_request_ready
      );

  data_modifier : entity work.cpu_write_data
    generic map(
      C_S_AXI_DATA_WIDTH  => C_S_AXI_DATA_WIDTH,
      C_S_AXI_WUSER_WIDTH => C_S_AXI_WUSER_WIDTH
      )
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      s_axi_wdata  => s_axi_wdata,
      s_axi_wstrb  => s_axi_wstrb,
      s_axi_wlast  => s_axi_wlast,
      s_axi_wuser  => s_axi_wuser,
      s_axi_wvalid => s_axi_wvalid,
      s_axi_wready => s_axi_wready,

      s_request       => plain_request_write,
      s_request_ready => plain_request_write_ready,

      m_request       => data_to_nonce_inc,
      m_request_ready => data_to_nonce_inc_ready
      );

  nonce_incrementer : entity work.stream_nonce_incrementer
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      s_request       => data_to_nonce_inc,
      s_request_ready => data_to_nonce_inc_ready,

      m_request       => nonce_inc_to_write_issue,
      m_request_ready => nonce_inc_to_write_issue_ready
      );

  write_issuer : entity work.memory_write_issuer
    generic map(
      C_M_AXI_ID_WIDTH     => C_M_AXI_ID_WIDTH,
      C_M_AXI_ADDR_WIDTH   => C_M_AXI_ADDR_WIDTH,
      C_M_AXI_DATA_WIDTH   => C_M_AXI_DATA_WIDTH,
      C_M_AXI_AWUSER_WIDTH => C_M_AXI_AWUSER_WIDTH,
      IGNORE_METADATA      => false
      )
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

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

      s_request       => nonce_inc_to_write_issue,
      s_request_ready => nonce_inc_to_write_issue_ready,

      m_request       => write_issue_to_reg,
      m_request_ready => write_issue_to_reg_ready
      );

  reg_stage : entity work.stream_register_stage
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      in_data  => write_issue_to_reg,
      in_valid => write_issue_to_reg.valid,
      in_ready => write_issue_to_reg_ready,

      out_data  => reg_to_enc,
      out_valid => open,
      out_ready => reg_to_enc_ready
      );

  encryption : entity work.stream_ascon
    generic map (
      DATA_ALIGNMENT => DATA_BLOCK_SIZE
      )
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      s_request       => reg_to_enc,
      s_request_ready => reg_to_enc_ready,

      m_request       => enc_to_write_data,
      m_request_ready => enc_to_write_data_ready,

      KeyxDI    => (others => '0'),
      DecryptxS => '0'
      );

  write_data : entity work.memory_write_data
    generic map(
      C_M_AXI_DATA_WIDTH  => C_M_AXI_DATA_WIDTH,
      C_M_AXI_WUSER_WIDTH => C_M_AXI_WUSER_WIDTH
      )
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      m_axi_wdata  => m_axi_wdata,
      m_axi_wstrb  => m_axi_wstrb,
      m_axi_wlast  => m_axi_wlast,
      m_axi_wuser  => m_axi_wuser,
      m_axi_wvalid => m_axi_wvalid,
      m_axi_wready => m_axi_wready,

      s_request       => enc_to_write_data,
      s_request_ready => enc_to_write_data_ready,

      m_request       => data_to_responder,
      m_request_ready => data_to_responder_ready
      );

  write_responder : entity work.memory_to_cpu_write_responder
    generic map(
      C_M_AXI_ID_WIDTH    => C_M_AXI_ID_WIDTH,
      C_M_AXI_BUSER_WIDTH => C_M_AXI_BUSER_WIDTH,
      C_S_AXI_ID_WIDTH    => C_S_AXI_ID_WIDTH,
      C_S_AXI_BUSER_WIDTH => C_S_AXI_BUSER_WIDTH
      )
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      m_axi_bid    => m_axi_bid,
      m_axi_bresp  => m_axi_bresp,
      m_axi_buser  => m_axi_buser,
      m_axi_bvalid => m_axi_bvalid,
      m_axi_bready => m_axi_bready,

      s_axi_bid    => s_axi_bid,
      s_axi_bresp  => s_axi_bresp,
      s_axi_buser  => s_axi_buser,
      s_axi_bvalid => s_axi_bvalid,
      s_axi_bready => s_axi_bready,

      s_request       => data_to_responder,
      s_request_ready => data_to_responder_ready,

      release_lock       => release_lock,
      release_lock_ready => release_lock_ready
      );

end arch_imp;
