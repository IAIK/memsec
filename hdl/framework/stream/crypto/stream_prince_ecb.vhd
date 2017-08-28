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

--! Encrypts or decrypts transactions in Prince ECB mode.
entity stream_prince_ecb is
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

    Key0xDI : in std_logic_vector(63 downto 0);
    Key1xDI : in std_logic_vector(63 downto 0)
    );
end stream_prince_ecb;

architecture Behavioral of stream_prince_ecb is
  constant DATASTREAM_BYTE_FIELD_ADDR_WIDTH : integer                               := log2_ceil(DATASTREAM_DATA_WIDTH/8);
  constant FIELD_ADDR_WIDTH                 : integer                               := log2_ceil(64/DATASTREAM_DATA_WIDTH);
  constant MAX_FIELD_COUNTER_VALUE          : unsigned(FIELD_ADDR_WIDTH-1 downto 0) := (others => '1');


  signal enc_block                        : std_logic_vector(63 downto 0);
  signal enc_block_valid, enc_block_ready : std_logic;

  signal dec_block                        : std_logic_vector(63 downto 0);
  signal dec_block_valid, dec_block_ready : std_logic;

  signal out_block_data                   : std_logic_vector(DATASTREAM_DATA_WIDTH-1 downto 0);
  signal out_field_addr                   : std_logic_vector(FIELD_ADDR_WIDTH-1 downto 0);
  signal out_block_valid, out_block_ready : std_logic;

  signal request_reg : StreamType;
begin

  data_deserialization : entity work.deserialization
    generic map(
      IN_DATA_WIDTH  => DATASTREAM_DATA_WIDTH,
      OUT_DATA_WIDTH => 64,
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

  reg_stream : entity work.stream_register_stage
    generic map(
      REGISTERED => true
      )
    port map(
      clk    => clk,
      resetn => resetn,

      in_data  => s_request,
      in_valid => enc_block_valid,
      in_ready => enc_block_ready,

      out_data  => request_reg,
      out_valid => dec_block_valid,
      out_ready => dec_block_ready
      );

  crypto : entity work.prince
    generic map(
      DECRYPTION => DECRYPTION,
      BLOCK_SIZE => 64
      )
    port map(
      ClkxCI        => clk,
      RstxRBI       => resetn,
      Key0xDI       => Key0xDI,
      Key1xDI       => Key1xDI,
      MessagexDI    => enc_block,
      CiphertextxDO => dec_block,
      in_ready      => open,
      in_valid      => enc_block_valid,
      out_ready     => dec_block_ready,
      out_valid     => open
      );

  data_serialization : entity work.serialization
    generic map(
      IN_DATA_WIDTH  => 64,
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
      out_last         => open,
      out_valid        => out_block_valid,
      out_ready        => m_request_ready
      );

  -- adapt the length, address and data from the register to the output
  output : process(out_block_data, out_block_valid, out_field_addr,
                   request_reg) is
  begin
    m_request <= request_reg;

    m_request.virt_address  <= request_reg.virt_address(ADDRESS_WIDTH-1 downto FIELD_ADDR_WIDTH+DATASTREAM_BYTE_FIELD_ADDR_WIDTH) & out_field_addr & zeros(DATASTREAM_BYTE_FIELD_ADDR_WIDTH);
    m_request.block_address <= request_reg.block_address(ADDRESS_WIDTH-1 downto FIELD_ADDR_WIDTH+DATASTREAM_BYTE_FIELD_ADDR_WIDTH) & out_field_addr & zeros(DATASTREAM_BYTE_FIELD_ADDR_WIDTH);
    m_request.block_len     <= request_reg.block_len(AXI_LEN_WIDTH-1 downto FIELD_ADDR_WIDTH) & std_logic_vector(MAX_FIELD_COUNTER_VALUE - unsigned(out_field_addr));
    m_request.data          <= out_block_data;
    m_request.valid         <= out_block_valid;
  end process output;

end Behavioral;
