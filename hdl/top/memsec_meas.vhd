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

entity memsec_meas is
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

    DATA_BLOCK_SIZE      : integer := 64;            -- Size of one block in the virtual address space in byte.
    DATA_MEMORY_SIZE     : integer := 256*1024*1024; -- Size of the protected memory in byte. (virtual address space)
    TREE_ARITY           : integer := 4;             -- Number of elements in one tree node.
    TREE_ROOTS           : integer := 1024;          -- Number of trees which are used to protect the data memory.
    TREE_NODE_CACHE_SIZE : integer := 1024;          -- Number of entries which can be stored in the tree node cache.
    TREE_KEYSIZE         : integer := 16;            -- Size of keys stored in tree
    DATA_TAGSIZE         : integer := 16;            -- Size of tags in data nodes
    TREE_ECB             : boolean := false          -- ECB mode for Tree Intermdiate Nodes
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
end memsec_meas;

architecture arch_imp of memsec_meas is
  constant TREE_KEYSIZE_BITS  : integer := 8*TREE_KEYSIZE;
  constant TREE_METADATA      : integer := 0;  -- Meta data size in byte
  constant DATA_METADATA      : integer := DATA_TAGSIZE;
  constant CACHE_ADDR_WIDTH   : integer := 26;
  constant CACHE_DATA_WIDTH   : integer := TREE_KEYSIZE_BITS;
  constant ROOT_NUMBER_WIDTH  : integer := log2_ceil(TREE_ROOTS);
  constant TREE_START_ADDRESS : std_logic_vector(ADDRESS_WIDTH-1 downto 0) :=
    std_logic_vector(to_unsigned(DATA_MEMORY_SIZE, ADDRESS_WIDTH) + unsigned(C_S_AXI_TARGET_SLAVE_BASE_ADDR));
  -- request modifier to issuer over scheduler
  signal read_request, read_request_crypto, write_request, write_request_crypto, request                               : StreamType;
  signal read_request_ready, read_request_crypto_ready, write_request_ready, write_request_crypto_ready, request_ready : std_logic;

  -- tree requests
  signal registered_request, tree_request             : StreamType;
  signal registered_request_ready, tree_request_ready : std_logic;

  -- Request splitter
  signal split_request       : StreamType;
  signal split_request_ready : std_logic;

  -- tree request modifier
  signal aligned_tree_request       : StreamType;
  signal aligned_tree_request_ready : std_logic;

  -- tree node cache lookup
  signal cache_request_issued           : StreamType;
  signal cache_request_issued_ready     : std_logic;
  signal cache_request_issued_reg       : StreamType;
  signal cache_request_issued_reg_ready : std_logic;
  signal cache_request_fetched          : StreamType;
  signal cache_request_fetched_ready    : std_logic;

  -- pre pipeline guard register
  signal pre_guard_reg       : StreamType;
  signal pre_guard_reg_ready : std_logic;

  -- pipeline locker
  signal request_locker       : StreamType;
  signal request_locker_ready : std_logic;

  -- issuer to register stage
  signal issue_to_reg       : StreamType;
  signal issue_to_reg_ready : std_logic;

  -- register stage to fetcher
  signal reg_to_fetch       : StreamType;
  signal reg_to_fetch_ready : std_logic;

  -- request fetcher to injector
  signal fetch_to_inj       : StreamType;
  signal fetch_to_inj_ready : std_logic;

  -- request from injector to decryption
  signal inj_to_dec       : StreamType;
  signal inj_to_dec_ready : std_logic;

  -- request from decryption to initializer
  signal dec_to_init       : StreamType;
  signal dec_to_init_ready : std_logic;

  -- decryption to read responder and data modifier
  signal plain_request, plain_request_read, plain_request_write                   : StreamType;
  signal plain_request_ready, plain_request_read_ready, plain_request_write_ready : std_logic;
  signal plain_request_nonce                                                      : StreamType;
  signal plain_request_nonce_ready                                                : std_logic;
  signal plain_request_write_access                                               : std_logic;

  -- filtered read
  signal filtered_read_request       : StreamType;
  signal filtered_read_request_ready : std_logic;

  -- wrap burst cached read
  signal cached_read_request       : StreamType;
  signal cached_read_request_ready : std_logic;

  -- data modifiers to register stage
  signal modified_request, data_to_treemod, treemod_to_metamod, metamod_to_write_issue : StreamType;
  signal data_to_treemod_ready, treemod_to_metamod_ready, metamod_to_write_issue_ready : std_logic;
  signal modified_request_ready                                                        : std_logic;
  signal nonce_treemod_valid, nonce_metamod_valid                                      : std_logic;
  signal nonce_treemod_ready, nonce_metamod_ready                                      : std_logic;

  signal write_issue_to_reg       : StreamType;
  signal write_issue_to_reg_ready : std_logic;

  -- data register stage to encryption
  signal reg_to_enc       : StreamType;
  signal reg_to_enc_ready : std_logic;

  -- encryption to writer
  signal enc_to_remover              : StreamType;
  signal enc_to_remover_ready        : std_logic;
  signal remover_to_write_data       : StreamType;
  signal remover_to_write_data_ready : std_logic;
  signal data_to_responder           : StreamType;
  signal data_to_responder_ready     : std_logic;


  -- tree node cache
  signal cache_araddr   : std_logic_vector(CACHE_ADDR_WIDTH - 1 downto 0);
  signal cache_ardelete : std_logic;
  signal cache_arvalid  : std_logic;
  signal cache_arready  : std_logic;
  signal cache_rdata    : std_logic_vector(CACHE_DATA_WIDTH - 1 downto 0);
  signal cache_rhit     : std_logic;
  signal cache_rvalid   : std_logic;
  signal cache_rready   : std_logic;
  signal cache_waddr    : std_logic_vector(CACHE_ADDR_WIDTH - 1 downto 0);
  signal cache_wdata    : std_logic_vector(CACHE_DATA_WIDTH - 1 downto 0);
  signal cache_wvalid   : std_logic;
  signal cache_wready   : std_logic;

  -- root node signals
  signal root_number                                       : std_logic_vector(ROOT_NUMBER_WIDTH-1 downto 0);
  signal root_update, root_number_valid, root_number_ready : std_logic;
  signal root_nonce, root_next_nonce                       : std_logic_vector(TREE_KEYSIZE_BITS-1 downto 0);
  signal root_nonce_valid, root_nonce_ready                : std_logic;
  signal root_next_nonce_valid, root_next_nonce_ready      : std_logic;

  -- nonce read feedback and forward signals
  signal nonce_fb, nonce_fb_reg, nonce_update                                     : std_logic_vector(TREE_KEYSIZE_BITS-1 downto 0);
  signal nonce_address, nonce_update_address                                      : std_logic_vector(ADDRESS_WIDTH-1 downto 0);
  signal nonce_is_read                                                            : std_logic;
  signal nonce_update_cache_writer_valid, nonce_cache_writer_valid                : std_logic;
  signal nonce_update_cache_writer_ready, nonce_cache_writer_ready                : std_logic;
  signal nonce_fb_reg_valid, nonce_update_valid, to_fb_reg_valid, to_update_valid : std_logic;
  signal nonce_fb_reg_ready, nonce_update_ready, to_fb_reg_ready, to_update_ready : std_logic;

  -- randomness for new key
  signal random_key                                                            : std_logic_vector(TREE_KEYSIZE_BITS-1 downto 0);
  signal random_key_valid, random_key_ready                                    : std_logic;
  signal random_key_updt                                                       : std_logic_vector(TREE_KEYSIZE_BITS-1 downto 0);
  signal random_key_root                                                       : std_logic_vector(TREE_KEYSIZE_BITS-1 downto 0);
  signal random_key_updt_valid, random_key_updt_ready, random_key_updt_request : std_logic;
  signal random_key_root_valid, random_key_root_ready, random_key_root_request : std_logic;

  -- lock the pipeline
  signal release_lock, release_lock_ready : std_logic;
begin
  m_axi_arregion <= (others => '0');
  m_axi_awregion <= (others => '0');

  req_mod_read : entity work.cpu_request_modifier
    generic map(
      C_S_AXI_ID_WIDTH    => C_S_AXI_ID_WIDTH,
      C_S_AXI_ADDR_WIDTH  => C_S_AXI_ADDR_WIDTH,
      C_S_AXI_DATA_WIDTH  => C_S_AXI_DATA_WIDTH,
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
      C_S_AXI_DATA_WIDTH  => C_S_AXI_DATA_WIDTH,
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

      m_request       => split_request,
      m_request_ready => split_request_ready
      );

  tree_generator : entity work.stream_tree_request_generator
    generic map(
      MEMORY_START_ADDRESS => C_S_AXI_TARGET_SLAVE_BASE_ADDR,
      DATA_MEMORY_SIZE     => DATA_MEMORY_SIZE,
      DATA_BLOCK_SIZE      => DATA_BLOCK_SIZE,
      TREE_DATA_SIZE       => TREE_KEYSIZE,
      TREE_ARITY           => TREE_ARITY,
      TREE_ROOTS           => TREE_ROOTS
      )
    port map(
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      root_number       => root_number,
      root_update       => root_update,
      root_number_valid => root_number_valid,
      root_number_ready => root_number_ready,

      s_request       => split_request,
      s_request_ready => split_request_ready,

      m_request       => tree_request,
      m_request_ready => tree_request_ready
      );

  crypto_mod : entity work.stream_crypto_request_modifier
    generic map(
      C_M_AXI_DATA_WIDTH         => C_M_AXI_DATA_WIDTH,
      DATA_START_ADDRESS         => C_S_AXI_TARGET_SLAVE_BASE_ADDR,
      DATA_ALIGNMENT             => DATA_BLOCK_SIZE,
      DATA_METADATA              => DATA_METADATA,
      TREE_START_ADDRESS         => TREE_START_ADDRESS,
      TREE_ALIGNMENT_READ        => TREE_KEYSIZE,
      TREE_ALIGNMENT_READ_ENABLE => TREE_ECB,
      TREE_ALIGNMENT             => TREE_ARITY*TREE_KEYSIZE,
      TREE_METADATA              => TREE_METADATA,
      TREE_ENABLE                => true
      )
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      s_request       => tree_request,
      s_request_ready => tree_request_ready,

      m_request       => aligned_tree_request,
      m_request_ready => aligned_tree_request_ready
      );

  pre_guard_register_stage : entity work.stream_multi_register_stage
    generic map(
      REGISTERS => 1
      )
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      in_data  => aligned_tree_request,
      in_valid => aligned_tree_request.valid,
      in_ready => aligned_tree_request_ready,

      out_data  => pre_guard_reg,
      out_valid => open,
      out_ready => pre_guard_reg_ready
      );

  pipeline_guard : entity work.pipeline_guard
    generic map (
      BLOCK_SIZE         => min(DATA_BLOCK_SIZE, TREE_ARITY*TREE_KEYSIZE),
      FIFO_SIZE          => 4,
      RELEASE_REGISTERED => true
      )
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      s_request       => pre_guard_reg,
      s_request_ready => pre_guard_reg_ready,

      m_request       => request_locker,
      m_request_ready => request_locker_ready,

      release       => release_lock,
      release_ready => release_lock_ready
      );

  cache_request_issuer : entity work.node_cache_read_issuer
    generic map(
      CACHE_ADDR_WIDTH => CACHE_ADDR_WIDTH,
      DATA_MEMORY_SIZE => DATA_MEMORY_SIZE,
      CACHE_DATA_WIDTH => CACHE_DATA_WIDTH
      )
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      araddr   => cache_araddr,
      ardelete => cache_ardelete,
      arvalid  => cache_arvalid,
      arready  => cache_arready,

      s_request       => request_locker,
      s_request_ready => request_locker_ready,

      m_request       => cache_request_issued,
      m_request_ready => cache_request_issued_ready
      );

  cache_register_stage : entity work.stream_multi_register_stage
    generic map(
      REGISTERS => 1
      )
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      in_data  => cache_request_issued,
      in_valid => cache_request_issued.valid,
      in_ready => cache_request_issued_ready,

      out_data  => cache_request_issued_reg,
      out_valid => open,
      out_ready => cache_request_issued_reg_ready
      );

  cache_request_fetcher : entity work.node_cache_read_fetcher
    generic map(
      CACHE_DATA_WIDTH => CACHE_DATA_WIDTH
      )
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      rdata  => cache_rdata,
      rhit   => cache_rhit,
      rvalid => cache_rvalid,
      rready => cache_rready,

      s_request       => cache_request_issued_reg,
      s_request_ready => cache_request_issued_reg_ready,

      m_request       => cache_request_fetched,
      m_request_ready => cache_request_fetched_ready
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

      s_request       => cache_request_fetched,
      s_request_ready => cache_request_fetched_ready,

      m_request       => issue_to_reg,
      m_request_ready => issue_to_reg_ready
      );

  issuer_reg_stage : entity work.stream_multi_register_stage
    generic map(
      REGISTERS => 2
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

      m_request       => fetch_to_inj,
      m_request_ready => fetch_to_inj_ready
      );

  secure_root : entity work.secure_root
    generic map(
      ROOT_WIDTH  => TREE_KEYSIZE_BITS,
      TREE_ROOTS  => TREE_ROOTS,
      USE_COUNTER => false
      )
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      root_number       => root_number,
      root_update       => root_update,
      root_number_valid => root_number_valid,
      root_number_ready => root_number_ready,

      root       => root_nonce,
      root_valid => root_nonce_valid,
      root_ready => root_nonce_ready,

      root_next       => root_next_nonce,
      root_next_valid => root_next_nonce_valid,
      root_next_ready => root_next_nonce_ready,

      random         => random_key_root,
      random_valid   => random_key_root_valid,
      random_request => random_key_root_request,
      random_ready   => random_key_root_ready
      );

  metadata_injector : entity work.stream_metadata_injector
    generic map(
      METADATA_WIDTH  => TREE_KEYSIZE_BITS,
      INJECT_POSITION => 0
      )
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      s_request       => fetch_to_inj,
      s_request_ready => fetch_to_inj_ready,

      m_request       => inj_to_dec,
      m_request_ready => inj_to_dec_ready,

      metadata       => nonce_fb_reg,
      metadata_ready => nonce_fb_reg_ready,
      metadata_valid => nonce_fb_reg_valid,

      root_metadata => root_nonce,
      root_valid    => root_nonce_valid,
      root_ready    => root_nonce_ready
      );

  decryption_ecb : if TREE_ECB generate
    decryption : entity work.stream_lrae_ascon_prince_ecb
      generic map (
        DATA_ALIGNMENT => DATA_BLOCK_SIZE,
        TREE_ALIGNMENT => TREE_ARITY*TREE_KEYSIZE,
        TAG_SIZE       => DATA_TAGSIZE,
        DECRYPTION     => true
        )
      port map (
        clk    => s_axi_aclk,
        resetn => s_axi_aresetn,

        s_request       => inj_to_dec,
        s_request_ready => inj_to_dec_ready,

        m_request       => dec_to_init,
        m_request_ready => dec_to_init_ready
        );
  end generate;

  decryption_std : if not(TREE_ECB) generate
    decryption : entity work.stream_lrae_ascon_prince_delay
      generic map (
        DATA_ALIGNMENT => DATA_BLOCK_SIZE,
        TREE_ALIGNMENT => TREE_ARITY*TREE_KEYSIZE,
        TAG_SIZE       => DATA_TAGSIZE,
        DECRYPTION     => true
        )
      port map (
        clk    => s_axi_aclk,
        resetn => s_axi_aresetn,

        s_request       => inj_to_dec,
        s_request_ready => inj_to_dec_ready,

        m_request       => dec_to_init,
        m_request_ready => dec_to_init_ready
        );
  end generate;

  zero_initializer : entity work.stream_request_zero_initializer
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      s_request       => dec_to_init,
      s_request_ready => dec_to_init_ready,

      m_request       => plain_request,
      m_request_ready => plain_request_ready
      );

  key_filter : entity work.stream_data_filter_to_stdlogic
    generic map (
      DATASTREAM_OUT_WIDTH => TREE_KEYSIZE_BITS,
      TREE_FILTER          => true,
      DATA_LEAF_FILTER     => false
      )
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      s_request       => plain_request_nonce,
      s_request_ready => plain_request_nonce_ready,

      m_request            => nonce_fb,
      m_request_address    => nonce_address,
      m_request_is_read    => nonce_is_read,
      m_request_read_valid => to_fb_reg_valid,
      m_request_read_ready => to_fb_reg_ready,

      m_request_write_valid => to_update_valid,
      m_request_write_ready => to_update_ready,

      m_request_cache_valid => nonce_cache_writer_valid,
      m_request_cache_ready => nonce_cache_writer_ready
      );

  key_fb_register : entity work.register_stage
    generic map(
      WIDTH        => TREE_KEYSIZE_BITS,
      READY_BYPASS => false,
      REGISTERED   => true
      )
    port map(
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      in_data  => nonce_fb,
      in_valid => to_fb_reg_valid,
      in_ready => to_fb_reg_ready,

      out_data  => nonce_fb_reg,
      out_valid => nonce_fb_reg_valid,
      out_ready => nonce_fb_reg_ready
      );

  key_fb_synchronizer_stream : entity work.stream_ready_synchronizer
    generic map(
      OUT_WIDTH => 3,
      REGISTERS => 0
      )
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      s_request       => plain_request,
      s_request_ready => plain_request_ready,

      m_requests(0)        => plain_request_nonce,
      m_requests(1)        => plain_request_read,
      m_requests(2)        => plain_request_write,
      m_requests_active(0) => '1',
      m_requests_active(1) => plain_request.read,
      m_requests_active(2) => plain_request_write_access,
      m_requests_ready(0)  => plain_request_nonce_ready,
      m_requests_ready(1)  => plain_request_read_ready,
      m_requests_ready(2)  => plain_request_write_ready
      );

  plain_request_write_access <= not(plain_request.read);

  data_filter : entity work.stream_data_block_filter
    generic map (
      DATASTREAM_OUT_WIDTH => C_S_AXI_DATA_WIDTH,
      TREE_FILTER          => false,
      DATA_LEAF_FILTER     => true,
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

      m_request       => modified_request,
      m_request_ready => modified_request_ready
      );

  delay_register_stage : entity work.stream_multi_register_stage
    generic map(
      REGISTERS => 2
      )
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      in_data  => modified_request,
      in_valid => modified_request.valid,
      in_ready => modified_request_ready,

      out_data  => data_to_treemod,
      out_valid => open,
      out_ready => data_to_treemod_ready
      );

  key_updater : entity work.key_updater
    generic map(
      KEY_WIDTH  => TREE_KEYSIZE_BITS,
      REGISTERED => true
      )
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      s_request         => nonce_fb,
      s_request_address => nonce_address,
      s_request_valid   => to_update_valid,
      s_request_ready   => to_update_ready,

      m_request         => nonce_update,
      m_request_address => nonce_update_address,
      m_request_valid   => nonce_update_valid,
      m_request_ready   => nonce_update_ready,

      random         => random_key_updt,
      random_valid   => random_key_updt_valid,
      random_ready   => random_key_updt_ready,
      random_request => random_key_updt_request
      );

  data_dispatch : entity work.data_dispatcher
    generic map(
      DATA_WIDTH     => TREE_KEYSIZE_BITS,
      DISPATCH_WIDTH => 2,
      REGISTERED     => true
      )
    port map(
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      in_data  => random_key,
      in_valid => random_key_valid,
      in_ready => random_key_ready,

      out_data(127 downto 0)   => random_key_updt,
      out_data(255 downto 128) => random_key_root,
      out_request(0)           => random_key_updt_request,
      out_request(1)           => random_key_root_request,
      out_valid(0)             => random_key_updt_valid,
      out_valid(1)             => random_key_root_valid,
      out_ready(0)             => random_key_updt_ready,
      out_ready(1)             => random_key_root_ready
      );

  randomness : entity work.prng
    generic map(
      WIDTH => TREE_KEYSIZE_BITS
      )
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      random       => random_key,
      random_valid => random_key_valid,
      random_ready => random_key_ready,

      random_init => (others => '0')
      );

  key_update_synchronizer : entity work.ready_synchronizer
    generic map(
      OUT_WIDTH => 3
      )
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      in_valid => nonce_update_valid,
      in_ready => nonce_update_ready,

      out_valid(0)  => nonce_treemod_valid,
      out_valid(1)  => nonce_metamod_valid,
      out_valid(2)  => nonce_update_cache_writer_valid,
      out_active(0) => '1',
      out_active(1) => '1',
      out_active(2) => '1',
      out_ready(0)  => nonce_treemod_ready,
      out_ready(1)  => nonce_metamod_ready,
      out_ready(2)  => nonce_update_cache_writer_ready
      );

  treedata_modifier : entity work.stream_treedata_modifier
    generic map(
      METADATA_WIDTH => TREE_KEYSIZE_BITS
      )
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      metadata       => nonce_update,
      metadata_valid => nonce_treemod_valid,
      metadata_ready => nonce_treemod_ready,

      s_request       => data_to_treemod,
      s_request_ready => data_to_treemod_ready,

      m_request       => treemod_to_metamod,
      m_request_ready => treemod_to_metamod_ready
      );

  metadata_modifier : entity work.stream_metadata_modifier
    generic map(
      METADATA_WIDTH => TREE_KEYSIZE_BITS
      )
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      metadata       => nonce_update,
      metadata_valid => nonce_metamod_valid,
      metadata_ready => nonce_metamod_ready,

      root       => root_next_nonce,
      root_valid => root_next_nonce_valid,
      root_ready => root_next_nonce_ready,

      s_request       => treemod_to_metamod,
      s_request_ready => treemod_to_metamod_ready,

      m_request       => metamod_to_write_issue,
      m_request_ready => metamod_to_write_issue_ready
      );

  cache_request_writer : entity work.node_cache_writer
    generic map(
      CACHE_ADDR_WIDTH => CACHE_ADDR_WIDTH,
      DATA_MEMORY_SIZE => DATA_MEMORY_SIZE,
      CACHE_DATA_WIDTH => CACHE_DATA_WIDTH
      )
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      waddr  => cache_waddr,
      wdata  => cache_wdata,
      wvalid => cache_wvalid,
      wready => cache_wready,

      s_old_entry   => nonce_fb,
      s_old_address => nonce_address,
      s_old_is_read => nonce_is_read,
      s_old_valid   => nonce_cache_writer_valid,
      s_old_ready   => nonce_cache_writer_ready,

      s_new_entry   => nonce_update,
      s_new_address => nonce_update_address,
      s_new_valid   => nonce_update_cache_writer_valid,
      s_new_ready   => nonce_update_cache_writer_ready
      );

  write_issuer : entity work.memory_write_issuer
    generic map(
      C_M_AXI_ID_WIDTH     => C_M_AXI_ID_WIDTH,
      C_M_AXI_ADDR_WIDTH   => C_M_AXI_ADDR_WIDTH,
      C_M_AXI_DATA_WIDTH   => C_M_AXI_DATA_WIDTH,
      C_M_AXI_AWUSER_WIDTH => C_M_AXI_AWUSER_WIDTH
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

      s_request       => metamod_to_write_issue,
      s_request_ready => metamod_to_write_issue_ready,

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


  encryption_ecb : if TREE_ECB generate
    encryption : entity work.stream_lrae_ascon_prince_ecb
      generic map (
        DATA_ALIGNMENT => DATA_BLOCK_SIZE,
        TREE_ALIGNMENT => TREE_ARITY*TREE_KEYSIZE,
        TAG_SIZE       => DATA_TAGSIZE,
        DECRYPTION     => false
        )
      port map (
        clk    => s_axi_aclk,
        resetn => s_axi_aresetn,

        s_request       => reg_to_enc,
        s_request_ready => reg_to_enc_ready,

        m_request       => enc_to_remover,
        m_request_ready => enc_to_remover_ready
        );
  end generate;

  encryption_std : if not(TREE_ECB) generate
    encryption : entity work.stream_lrae_ascon_prince_delay
      generic map (
        DATA_ALIGNMENT => DATA_BLOCK_SIZE,
        TREE_ALIGNMENT => TREE_ARITY*TREE_KEYSIZE,
        TAG_SIZE       => DATA_TAGSIZE,
        DECRYPTION     => false
        )
      port map (
        clk    => s_axi_aclk,
        resetn => s_axi_aresetn,

        s_request       => reg_to_enc,
        s_request_ready => reg_to_enc_ready,

        m_request       => enc_to_remover,
        m_request_ready => enc_to_remover_ready
        );
  end generate;

  beat_remover : entity work.stream_beat_remover
    generic map (
      DROP_POSITION => 0,
      DROP_COUNT    => TREE_KEYSIZE_BITS/DATASTREAM_DATA_WIDTH
      )
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      s_request       => enc_to_remover,
      s_request_ready => enc_to_remover_ready,

      m_request       => remover_to_write_data,
      m_request_ready => remover_to_write_data_ready
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

      s_request       => remover_to_write_data,
      s_request_ready => remover_to_write_data_ready,

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

  cache : entity work.node_cache
    generic map(
      ADDR_WIDTH => CACHE_ADDR_WIDTH,
      DATA_WIDTH => CACHE_DATA_WIDTH,
      CACHE_SIZE => TREE_NODE_CACHE_SIZE
      )
    port map (
      clk    => s_axi_aclk,
      resetn => s_axi_aresetn,

      araddr   => cache_araddr,
      ardelete => cache_ardelete,
      arvalid  => cache_arvalid,
      arready  => cache_arready,

      rdata  => cache_rdata,
      rhit   => cache_rhit,
      rvalid => cache_rvalid,
      rready => cache_rready,

      waddr  => cache_waddr,
      wdata  => cache_wdata,
      wvalid => cache_wvalid,
      wready => cache_wready
      );
end arch_imp;
