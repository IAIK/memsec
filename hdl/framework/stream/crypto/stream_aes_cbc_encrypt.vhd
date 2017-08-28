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

--! Encrypts transactions in AES CBC mode.
--!
--! First, the IV for the encryption is read from the internal stream. Next,
--! the actual data encryption is performed. Note that only properly aligned
--! transactions are supported.
entity stream_aes_cbc_encrypt is
  generic(
    BLOCK_INDEX_WIDTH : integer := 1
    );
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    s_request       : in  StreamType;
    s_request_ready : out std_logic;

    m_request       : out StreamType;
    m_request_ready : in  std_logic;

    KeyCipherxDI : in std_logic_vector(127 downto 0);
    KeyIvxDI     : in std_logic_vector(127 downto 0)
    );
end stream_aes_cbc_encrypt;

architecture Behavioral of stream_aes_cbc_encrypt is
  constant DATASTREAM_BYTE_FIELD_ADDR_WIDTH : integer                                := log2_ceil(DATASTREAM_DATA_WIDTH/8);
  constant FIELD_ADDR_WIDTH                 : integer                                := log2_ceil(128/DATASTREAM_DATA_WIDTH);
  constant MAX_FIELD_COUNTER_VALUE          : unsigned(FIELD_ADDR_WIDTH-1 downto 0)  := (others => '1');
  constant MAX_BLOCK_INDEX_COUNTER_VALUE    : unsigned(BLOCK_INDEX_WIDTH-1 downto 0) := (others => '1');

  -- signals for the deserialization
  signal full_in_block                            : std_logic_vector(127 downto 0);
  signal full_in_block_valid, full_in_block_ready : std_logic;
  signal full_in_block_masked                     : std_logic_vector(127 downto 0);

  -- signals for the request register stage
  signal request_reg                                  : StreamType;
  signal request_reg_full_data                        : std_logic_vector(127 downto 0);
  signal request_reg_in_valid                         : std_logic;
  signal request_reg_out_valid, request_reg_out_ready : std_logic;

  -- signals for the crypto unit
  signal crypto_in, crypto_out              : std_logic_vector(127 downto 0);
  signal crypto_out_masked                  : std_logic_vector(127 downto 0);
  signal crypto_key                         : std_logic_vector(127 downto 0);
  signal crypto_in_valid, crypto_in_ready   : std_logic;
  signal crypto_out_valid, crypto_out_ready : std_logic;
  signal EncryptxS                          : std_logic;

  -- signals for the mask management
  signal mask_in, mask_out              : std_logic_vector(127 downto 0);
  signal mask_in_valid, mask_in_ready   : std_logic;
  signal mask_out_valid, mask_out_ready : std_logic;

  -- synchronizer block
  signal sync_valid_in, sync_ready_in     : std_logic;
  signal sync_valid_mask, sync_ready_mask : std_logic;

  -- signals for the deserialization
  signal out_block                        : std_logic_vector(127 downto 0);
  signal out_block_valid, out_block_ready : std_logic;
  signal full_out_block                   : std_logic_vector(DATASTREAM_DATA_WIDTH-1 downto 0);
  signal full_out_field_addr              : std_logic_vector(FIELD_ADDR_WIDTH-1 downto 0);
  signal full_out_block_valid             : std_logic;

  signal m_requestxS       : StreamType;
  signal s_request_validxS : std_logic;
  signal s_request_readyxS : std_logic;

  -- State machine states and register
  type StateType is (IDLE, READ_IV, WAIT_IV, PROCESS_DATA);
  signal StatexDP, StatexDN     : StateType;
  signal blockNrxDP, blockNrxDN : std_logic_vector(BLOCK_INDEX_WIDTH downto 0);
begin

  data_deserialization : entity work.deserialization
    generic map(
      IN_DATA_WIDTH  => DATASTREAM_DATA_WIDTH,
      OUT_DATA_WIDTH => 128,
      REGISTERED     => false
      )
    port map (
      clk    => clk,
      resetn => resetn,

      -- only aligned blocks are expected with multiple of OUT_DATA_WIDTH are expected
      in_field_start_offset => (others => '0'),
      in_last               => '0',

      in_data  => s_request.data,
      in_valid => s_request_validxS,
      in_ready => s_request_readyxS,

      out_data         => full_in_block,
      out_field_offset => open,
      out_field_len    => open,
      out_valid        => full_in_block_valid,
      out_ready        => full_in_block_ready
      );
  full_in_block_masked <= full_in_block xor mask_out;
  s_request_ready      <= s_request_readyxS;

  reg_stream_data : entity work.register_stage
    generic map(
      WIDTH      => 128,
      REGISTERED => true
      )
    port map(
      clk    => clk,
      resetn => resetn,

      in_data  => full_in_block,
      in_valid => request_reg_in_valid,
      in_ready => open,

      out_data  => request_reg_full_data,
      out_valid => open,
      out_ready => request_reg_out_ready
      );

  reg_stream : entity work.stream_register_stage
    generic map(
      REGISTERED => true
      )
    port map(
      clk    => clk,
      resetn => resetn,

      in_data  => s_request,
      in_valid => request_reg_in_valid,
      in_ready => open,

      out_data  => request_reg,
      out_valid => request_reg_out_valid,
      out_ready => request_reg_out_ready
      );

  mask_reg : entity work.register_stage
    generic map(
      WIDTH        => 128,
      READY_BYPASS => false,
      REGISTERED   => true
      )
    port map(
      clk    => clk,
      resetn => resetn,

      in_data  => mask_in,
      in_valid => mask_in_valid,
      in_ready => mask_in_ready,

      out_data  => mask_out,
      out_valid => mask_out_valid,
      out_ready => mask_out_ready
      );

  crypto : entity work.aes128_hs
    port map(
      ClkxCI     => clk,
      RstxRBI    => resetn,
      KeyxDI     => crypto_key,
      DataxDI    => crypto_in,
      DataxDO    => crypto_out,
      EncryptxSI => EncryptxS,
      in_ready   => crypto_in_ready,
      in_valid   => crypto_in_valid,
      out_ready  => crypto_out_ready,
      out_valid  => crypto_out_valid
      );
  crypto_out_masked <= crypto_out xor mask_out;

  synchronization : entity work.ready_synchronizer
    generic map(
      OUT_WIDTH => 2
      )
    port map(
      clk    => clk,
      resetn => resetn,

      in_ready => sync_ready_in,
      in_valid => sync_valid_in,

      out_ready(0)  => out_block_ready,
      out_ready(1)  => sync_ready_mask,
      out_active(0) => '1',
      out_active(1) => '1',
      out_valid(0)  => out_block_valid,
      out_valid(1)  => sync_valid_mask
      );

  data_serialization : entity work.serialization
    generic map(
      IN_DATA_WIDTH  => 128,
      OUT_DATA_WIDTH => DATASTREAM_DATA_WIDTH,
      REGISTERED     => false
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_last         => '1',
      in_data         => out_block,
      in_field_offset => (others => '0'),
      in_field_len    => (others => '1'),
      in_valid        => out_block_valid,
      in_ready        => out_block_ready,

      out_data         => full_out_block,
      out_field_offset => full_out_field_addr,
      out_last         => open,
      out_valid        => full_out_block_valid,
      out_ready        => m_request_ready
      );

  regs : process(clk) is
  begin
    if rising_edge(clk) then
      if resetn = '0' then
        StatexDP   <= IDLE;
        blockNrxDP <= (others => '0');
      else
        StatexDP   <= StatexDN;
        blockNrxDP <= blockNrxDN;
      end if;
    end if;
  end process regs;

  control : process(KeyCipherxDI, KeyIvxDI, StatexDP,
                    blockNrxDP, crypto_in_ready, crypto_out, crypto_out_masked,
                    crypto_out_valid, full_in_block, full_in_block_masked,
                    full_in_block_valid, m_request_ready,
                    m_requestxS.block_len, mask_in_ready, mask_in_valid,
                    mask_out_valid, out_block_ready, request_reg.block_len,
                    request_reg_full_data, request_reg_out_valid,
                    s_request.valid, sync_ready_in, sync_valid_mask) is
  begin
    StatexDN   <= StatexDP;
    blockNrxDN <= blockNrxDP;

    crypto_key <= KeyCipherxDI;
    crypto_in  <= full_in_block;

    out_block <= crypto_out_masked;

    crypto_in_valid      <= '0';
    request_reg_in_valid <= '0';

    mask_in          <= request_reg_full_data;
    mask_in_valid    <= '0';
    mask_out_ready   <= '0';
    crypto_out_ready <= '0';

    full_in_block_ready <= '0';

    sync_valid_in         <= '0';
    sync_ready_mask       <= '0';
    crypto_out_ready      <= '0';
    request_reg_in_valid  <= '0';
    request_reg_out_ready <= '0';
    EncryptxS             <= '1';

    s_request_validxS <= s_request.valid;
    if request_reg_out_valid = '1' and to_integer(unsigned(request_reg.block_len)) = 0 then
      s_request_validxS <= '0';
    end if;

    case StatexDP is
      when IDLE =>
        blockNrxDN <= (others => '0');
        if full_in_block_valid = '1' then
          StatexDN <= READ_IV;
        end if;
      when READ_IV =>
        mask_in             <= full_in_block;
        mask_in_valid       <= full_in_block_valid;
        full_in_block_ready <= mask_in_ready;

        if mask_in_valid = '1' and mask_in_ready = '1' then
          StatexDN <= WAIT_IV;
        end if;
      when WAIT_IV =>
        mask_in          <= crypto_out;
        mask_in_valid    <= crypto_out_valid;
        crypto_out_ready <= mask_in_ready;

        if mask_out_valid = '1' and mask_in_valid = '0' then
          StatexDN <= PROCESS_DATA;
        end if;
      when PROCESS_DATA =>
        -- count the number acknowledged blocks at the cipher input
        if crypto_in_ready = '1' then
          blockNrxDN <= std_logic_vector(unsigned(blockNrxDP) + 1);
        end if;

        -- cipher output signals
        sync_valid_in         <= crypto_out_valid;
        crypto_out_ready      <= sync_ready_in;
        request_reg_out_ready <= out_block_ready;

        mask_in   <= crypto_out;
        out_block <= crypto_out;

        -- ignore the mask output by default (overriden for blockNr < maxValue
        sync_ready_mask <= sync_valid_mask;

        if to_integer(unsigned(blockNrxDP)) <= to_integer(MAX_BLOCK_INDEX_COUNTER_VALUE) then
          -- cipher input signals

          crypto_in_valid      <= full_in_block_valid and mask_out_valid;
          request_reg_in_valid <= full_in_block_valid and mask_out_valid;
          full_in_block_ready  <= crypto_in_ready;
          mask_out_ready       <= crypto_in_ready;

          mask_in_valid   <= sync_valid_mask;
          sync_ready_mask <= mask_in_ready;

          crypto_in <= full_in_block_masked;

        elsif full_in_block_valid = '1' and crypto_out_valid = '0' and mask_out_valid = '0' then
          -- calculate the next iv
          StatexDN   <= READ_IV;
          blockNrxDN <= (others => '0');
        end if;

        if m_request_ready = '1' and unsigned(m_requestxS.block_len) = 0 then
          -- request has been handled, wait for the next one
          StatexDN <= IDLE;
        end if;
      when others => assert false report "Invalid state" severity error;
    end case;
  end process control;

  -- adapt the lenght, address and data from the register to the output
  output : process(full_out_block, full_out_block_valid, full_out_field_addr,
                   request_reg) is
  begin
    m_requestxS <= request_reg;

    m_requestxS.virt_address  <= request_reg.virt_address(ADDRESS_WIDTH-1 downto FIELD_ADDR_WIDTH+DATASTREAM_BYTE_FIELD_ADDR_WIDTH) & full_out_field_addr & zeros(DATASTREAM_BYTE_FIELD_ADDR_WIDTH);
    m_requestxS.block_address <= request_reg.block_address(ADDRESS_WIDTH-1 downto FIELD_ADDR_WIDTH+DATASTREAM_BYTE_FIELD_ADDR_WIDTH) & full_out_field_addr & zeros(DATASTREAM_BYTE_FIELD_ADDR_WIDTH);
    m_requestxS.block_len     <= request_reg.block_len(AXI_LEN_WIDTH-1 downto FIELD_ADDR_WIDTH) & std_logic_vector(MAX_FIELD_COUNTER_VALUE - unsigned(full_out_field_addr));

    m_requestxS.data  <= full_out_block;
    m_requestxS.valid <= full_out_block_valid;
  end process output;
  m_request <= m_requestxS;

end Behavioral;
