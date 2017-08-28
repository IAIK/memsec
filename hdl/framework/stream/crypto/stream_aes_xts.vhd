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

--! Encrypts or decrypts transactions in AES XTS mode.
--!
--! First, the initial tweak is generated, either by decrypting the sector
--! address (XTS decryption) or by reading it from the stream (XTS encryption).
--! Next, in the case of XTS decryption, the calculated tweak is output on the
--! internal stream to permit later encryption. Finally, the actual data
--! encryption/decryption is performed.
entity stream_aes_xts is
  generic(
    DECRYPTION        : boolean := true;
    BLOCK_INDEX_WIDTH : integer := 1
    );
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    s_request       : in  StreamType;
    s_request_ready : out std_logic;

    m_request       : out StreamType;
    m_request_ready : in  std_logic;

    KeyTweakxDI  : in std_logic_vector(127 downto 0);
    KeyCipherxDI : in std_logic_vector(127 downto 0)
    );
end stream_aes_xts;

architecture Behavioral of stream_aes_xts is
  constant DATASTREAM_BYTE_FIELD_ADDR_WIDTH : integer                               := log2_ceil(DATASTREAM_DATA_WIDTH/8);
  constant FIELD_ADDR_WIDTH                 : integer                               := log2_ceil(128/DATASTREAM_DATA_WIDTH);
  constant MAX_FIELD_COUNTER_VALUE          : unsigned(FIELD_ADDR_WIDTH-1 downto 0) := (others => '1');

  -- signals for the deserialization
  signal full_in_block                            : std_logic_vector(127 downto 0);
  signal full_in_block_valid, full_in_block_ready : std_logic;
  signal full_in_block_tweaked                    : std_logic_vector(127 downto 0);

  -- signals for the request register stage
  signal request_reg                                  : StreamType;
  signal request_reg_in_valid                         : std_logic;
  signal request_reg_out_valid, request_reg_out_ready : std_logic;

  -- signals for the crypto unit
  signal crypto_in, crypto_out              : std_logic_vector(127 downto 0);
  signal crypto_out_tweaked                 : std_logic_vector(127 downto 0);
  signal crypto_key                         : std_logic_vector(127 downto 0);
  signal crypto_in_valid, crypto_in_ready   : std_logic;
  signal crypto_out_valid, crypto_out_ready : std_logic;
  signal EncryptxS                          : std_logic;

  -- signals for the tweak generation
  signal tweak_in, tweak_out, tweak_out_delayed : std_logic_vector(127 downto 0);
  signal tweak_start_block_number               : std_logic_vector(BLOCK_INDEX_WIDTH-1 downto 0);
  signal tweak_start_mul_number                 : std_logic_vector(BLOCK_INDEX_WIDTH-1 downto 0);
  signal tweak_in_valid, tweak_in_ready         : std_logic;
  signal tweak_out_valid, tweak_out_ready       : std_logic;

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
  type StateType is (IDLE, CALC_TWEAK, CALC_TWEAK_WAIT, READ_TWEAK, TWEAK_WAIT, OUTPUT_TWEAK, PROCESS_DATA);
  signal StatexDP, StatexDN : StateType;
  signal output_tweakxS     : std_logic;
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
  full_in_block_tweaked <= full_in_block xor tweak_out;
  s_request_ready       <= s_request_readyxS;

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

  tweak_gen : entity work.xts_tweak_generator
    generic map(
      WIDTH             => 128,
      BLOCK_INDEX_WIDTH => BLOCK_INDEX_WIDTH
      )
    port map(
      clk    => clk,
      resetn => resetn,

      in_tweak   => tweak_in,
      in_blockNr => tweak_start_block_number,
      in_mulNr   => tweak_start_mul_number,
      in_valid   => tweak_in_valid,
      in_ready   => tweak_in_ready,

      out_tweak => tweak_out,
      out_valid => tweak_out_valid,
      out_ready => tweak_out_ready
      );

  last_tweak : entity work.register_stage
    generic map(
      WIDTH      => 128,
      REGISTERED => true
      )
    port map(
      clk    => clk,
      resetn => resetn,

      in_data  => tweak_out,
      in_valid => tweak_out_valid,
      in_ready => open,

      out_data  => tweak_out_delayed,
      out_valid => open,
      out_ready => tweak_out_ready
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
  crypto_out_tweaked <= crypto_out xor tweak_out_delayed;

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
        StatexDP <= IDLE;
      else
        StatexDP <= StatexDN;
      end if;
    end if;
  end process regs;

  control : process(KeyCipherxDI, KeyTweakxDI, StatexDP,
                    crypto_in_ready, crypto_out, crypto_out_tweaked, full_in_block,
                    crypto_out_valid, full_in_block_tweaked, request_reg.block_len,
                    full_in_block_valid, out_block_ready, s_request.valid,
                    s_request.block_address, tweak_in_ready, tweak_out_valid,
                    m_request_ready, m_requestxS.block_len, request_reg_out_valid) is
    variable GENERATE_TWEAK_STATE : StateType;
  begin
    StatexDN <= StatexDP;

    crypto_key           <= KeyCipherxDI;
    crypto_in            <= full_in_block_tweaked;
    crypto_in_valid      <= '0';
    request_reg_in_valid <= '0';
    EncryptxS            <= '0';

    tweak_in                 <= crypto_out;
    tweak_start_block_number <= (others => '0');
    tweak_start_mul_number   <= s_request.block_address(BLOCK_INDEX_WIDTH+3 downto 4);
    tweak_in_valid           <= '0';
    crypto_out_ready         <= '0';

    full_in_block_ready <= '0';
    tweak_out_ready     <= '0';

    out_block             <= crypto_out_tweaked;
    out_block_valid       <= '0';
    crypto_out_ready      <= '0';
    request_reg_in_valid  <= '0';
    request_reg_out_ready <= '0';

    output_tweakxS <= '0';

    s_request_validxS <= s_request.valid;

    GENERATE_TWEAK_STATE := CALC_TWEAK;
    if DECRYPTION = false then
      EncryptxS            <= '1';
      GENERATE_TWEAK_STATE := READ_TWEAK;

      tweak_start_block_number <= s_request.block_address(BLOCK_INDEX_WIDTH+3 downto 4);
      tweak_start_mul_number   <= (others => '0');
    end if;

    case StatexDP is
      when IDLE =>
        if full_in_block_valid = '1' then
          StatexDN <= GENERATE_TWEAK_STATE;
        end if;
      when CALC_TWEAK =>
        -- use the crypto core to calculate the tweak
        crypto_key      <= KeyTweakxDI;
        crypto_in       <= zeros(128-ADDRESS_WIDTH) & (s_request.block_address and not(mask(BLOCK_INDEX_WIDTH+4, ADDRESS_WIDTH)));
        crypto_in_valid <= '1';
        EncryptxS       <= '0';

        tweak_in_valid   <= crypto_out_valid;
        crypto_out_ready <= tweak_in_ready;

        if crypto_in_ready = '1' then
          StatexDN <= CALC_TWEAK_WAIT;  -- wait in the next state until the tweak is ready
        end if;
      when READ_TWEAK =>
        tweak_in            <= full_in_block;
        tweak_in_valid      <= full_in_block_valid;
        full_in_block_ready <= tweak_in_ready;
        EncryptxS           <= '0';

        if tweak_in_valid = '1' and tweak_in_ready = '1' then
          StatexDN <= TWEAK_WAIT;
        end if;
      when CALC_TWEAK_WAIT =>
        -- wait for the tweak crypto computation to be ready
        crypto_key <= KeyTweakxDI;
        EncryptxS  <= '0';

        tweak_in_valid   <= crypto_out_valid;
        crypto_out_ready <= tweak_in_ready;

        if crypto_out_valid = '1' and tweak_in_ready = '1' then
          StatexDN <= TWEAK_WAIT;
        end if;
      when TWEAK_WAIT =>
        -- wait for the tweak to be ready
        crypto_key <= KeyTweakxDI;
        EncryptxS  <= '0';

        tweak_in_valid   <= crypto_out_valid;
        crypto_out_ready <= tweak_in_ready;

        if tweak_out_valid = '1' and tweak_in_valid = '0' then
          StatexDN <= PROCESS_DATA;
          if DECRYPTION and s_request.read = '0' then
            StatexDN <= OUTPUT_TWEAK;
          end if;
        end if;
      when OUTPUT_TWEAK =>
        output_tweakxS  <= '1';
        out_block_valid <= tweak_out_valid;
        out_block       <= tweak_out;
        EncryptxS       <= '0';
        if out_block_ready = '1' then
          StatexDN <= PROCESS_DATA;
        end if;
      when PROCESS_DATA =>
        -- process the data using the tweak from the tweak generator
        crypto_in_valid      <= full_in_block_valid and tweak_out_valid;
        request_reg_in_valid <= full_in_block_valid and tweak_out_valid;
        full_in_block_ready  <= crypto_in_ready;
        tweak_out_ready      <= crypto_in_ready;

        out_block_valid       <= crypto_out_valid;
        crypto_out_ready      <= out_block_ready;
        request_reg_out_ready <= out_block_ready;

        if request_reg_out_valid = '1' and to_integer(unsigned(request_reg.block_len)) = 0 then
          s_request_validxS <= '0';
        end if;

        -- calculate the next tweak when necessary
        if full_in_block_valid = '1' and tweak_out_valid = '0' and crypto_out_valid = '0' then
          StatexDN <= GENERATE_TWEAK_STATE;
        end if;

        if m_request_ready = '1' and unsigned(m_requestxS.block_len) = 0 then
          StatexDN <= IDLE;
        end if;
      when others => assert false report "Invalid state" severity error;
    end case;
  end process control;

  -- adapt the length, address and data from the register to the output
  output : process(full_out_block, full_out_block_valid, full_out_field_addr,
                   request_reg, output_tweakxS, s_request) is
  begin
    m_requestxS <= request_reg;

    m_requestxS.virt_address  <= request_reg.virt_address(ADDRESS_WIDTH-1 downto FIELD_ADDR_WIDTH+DATASTREAM_BYTE_FIELD_ADDR_WIDTH) & full_out_field_addr & zeros(DATASTREAM_BYTE_FIELD_ADDR_WIDTH);
    m_requestxS.block_address <= request_reg.block_address(ADDRESS_WIDTH-1 downto FIELD_ADDR_WIDTH+DATASTREAM_BYTE_FIELD_ADDR_WIDTH) & full_out_field_addr & zeros(DATASTREAM_BYTE_FIELD_ADDR_WIDTH);
    m_requestxS.block_len     <= request_reg.block_len(AXI_LEN_WIDTH-1 downto FIELD_ADDR_WIDTH) & std_logic_vector(MAX_FIELD_COUNTER_VALUE - unsigned(full_out_field_addr));

    if output_tweakxS = '1' then
      m_requestxS               <= s_request;
      m_requestxS.block_address <= s_request.block_address(ADDRESS_WIDTH-1 downto FIELD_ADDR_WIDTH+DATASTREAM_BYTE_FIELD_ADDR_WIDTH) & full_out_field_addr & zeros(DATASTREAM_BYTE_FIELD_ADDR_WIDTH);
      m_requestxS.block_len     <= (others => '1');
      m_requestxS.metadata      <= '1';
    end if;

    m_requestxS.data  <= full_out_block;
    m_requestxS.valid <= full_out_block_valid;
  end process output;
  m_request <= m_requestxS;
end Behavioral;
