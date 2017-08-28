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

--! Encrypts or decrypts transactions in AES ECB mode.
entity stream_aes_ecb is
  generic(
    DECRYPTION : boolean := true
    );
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    s_request       : in  StreamType;
    s_request_ready : out std_logic;

    m_request       : out StreamType;
    m_request_ready : in  std_logic;

    KeyxDI : in std_logic_vector(127 downto 0)
    );
end stream_aes_ecb;

architecture Behavioral of stream_aes_ecb is
  constant DATASTREAM_BYTE_FIELD_ADDR_WIDTH : integer                               := log2_ceil(DATASTREAM_DATA_WIDTH/8);
  constant FIELD_ADDR_WIDTH                 : integer                               := log2_ceil(128/DATASTREAM_DATA_WIDTH);
  constant MAX_FIELD_COUNTER_VALUE          : unsigned(FIELD_ADDR_WIDTH-1 downto 0) := (others => '1');


  signal enc_block                        : std_logic_vector(127 downto 0);
  signal enc_block_valid, enc_block_ready : std_logic;

  signal dec_block                        : std_logic_vector(127 downto 0);
  signal dec_block_valid, dec_block_ready : std_logic;

  signal out_block_data                   : std_logic_vector(DATASTREAM_DATA_WIDTH-1 downto 0);
  signal out_field_addr                   : std_logic_vector(FIELD_ADDR_WIDTH-1 downto 0);
  signal out_block_valid, out_block_ready : std_logic;
  signal out_last                         : std_logic;

  signal aes_input_valid, aes_input_ready             : std_logic;
  signal register_input_valid, register_input_ready   : std_logic;
  signal register_output_valid, register_output_ready : std_logic;

  signal reg_valid : std_logic;

  signal request_reg : StreamType;

  signal EncryptxS : std_logic;
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

      -- only aligned blocks with multiple of OUT_DATA_WIDTH are expected
      in_field_start_offset => (others => '0'),
      in_last               => '0',

      in_data  => s_request.data,
      in_valid => s_request.valid,
      in_ready => s_request_ready,

      out_data         => enc_block,
      out_field_offset => open,
      out_field_len    => open,
      out_valid        => enc_block_valid,
      out_ready        => enc_block_ready
      );

  ready_synchronizer : entity work.ready_synchronizer
    generic map(
      OUT_WIDTH => 2
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_valid => enc_block_valid,
      in_ready => enc_block_ready,

      out_valid(0) => aes_input_valid,
      out_valid(1) => register_input_valid,

      out_active(0) => '1',
      out_active(1) => '1',

      out_ready(0) => aes_input_ready,
      out_ready(1) => register_input_ready
      );

  reg_stream : entity work.stream_register_stage
    generic map(
      REGISTERED => true
      )
    port map(
      clk    => clk,
      resetn => resetn,

      in_data  => s_request,
      in_valid => register_input_valid,
      in_ready => register_input_ready,

      out_data  => request_reg,
      out_valid => register_output_valid,
      out_ready => register_output_ready
      );

  EncryptxS <= '0' when DECRYPTION else '1';

  crypto : entity work.aes128_hs
    port map(
      ClkxCI     => clk,
      RstxRBI    => resetn,
      KeyxDI     => KeyxDI,
      DataxDI    => enc_block,
      DataxDO    => dec_block,
      EncryptxSI => EncryptxS,
      in_ready   => aes_input_ready,
      in_valid   => aes_input_valid,
      out_ready  => dec_block_ready,
      out_valid  => dec_block_valid
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
      in_data         => dec_block,
      in_field_offset => (others => '0'),
      in_field_len    => (others => '1'),
      in_valid        => dec_block_valid,
      in_ready        => dec_block_ready,

      out_data         => out_block_data,
      out_field_offset => out_field_addr,
      out_last         => out_last,
      out_valid        => out_block_valid,
      out_ready        => m_request_ready
      );

  -- adapt the length, address and data from the register to the output
  output : process(out_block_data, out_block_valid, out_field_addr, out_last,
                   request_reg, m_request_ready, register_output_valid) is
  begin
    register_output_ready <= '0';

    m_request <= request_reg;

    m_request.virt_address  <= request_reg.virt_address(ADDRESS_WIDTH-1 downto FIELD_ADDR_WIDTH+DATASTREAM_BYTE_FIELD_ADDR_WIDTH) & out_field_addr & zeros(DATASTREAM_BYTE_FIELD_ADDR_WIDTH);
    m_request.block_address <= request_reg.block_address(ADDRESS_WIDTH-1 downto FIELD_ADDR_WIDTH+DATASTREAM_BYTE_FIELD_ADDR_WIDTH) & out_field_addr & zeros(DATASTREAM_BYTE_FIELD_ADDR_WIDTH);
    m_request.block_len     <= request_reg.block_len(AXI_LEN_WIDTH-1 downto FIELD_ADDR_WIDTH) & std_logic_vector(MAX_FIELD_COUNTER_VALUE - unsigned(out_field_addr));
    m_request.data          <= out_block_data;
    m_request.valid         <= out_block_valid and register_output_valid;

    if out_last = '1' and m_request_ready = '1' then
      register_output_ready <= '1';
    end if;

  end process output;

end Behavioral;
