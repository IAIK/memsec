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

--! Inserts a metadata block in front of the memory transaction.
--!
--! If the current transaction is a tree root, then the root_metadata is
--! injected. Otherwise, metadata which has to be extracted from the previous
--! transaction gets injected.
entity stream_metadata_injector is
  generic(
    METADATA_WIDTH  : integer := DATASTREAM_DATA_WIDTH;
    INJECT_POSITION : integer := 0
    );
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    s_request       : in  StreamType;
    s_request_ready : out std_logic;

    m_request       : out StreamType;
    m_request_ready : in  std_logic;

    metadata       : in  std_logic_vector(METADATA_WIDTH-1 downto 0);
    metadata_valid : in  std_logic;
    metadata_ready : out std_logic;

    root_metadata : in  std_logic_vector(METADATA_WIDTH-1 downto 0);
    root_valid    : in  std_logic;
    root_ready    : out std_logic
    );
end stream_metadata_injector;

architecture behavioral of stream_metadata_injector is
  constant CONVERSION_FACTOR : integer := METADATA_WIDTH/DATASTREAM_DATA_WIDTH;

  signal BlockCounterxDP, BlockCounterxDN             : std_logic_vector(s_request.len'length-1 downto 0);
  signal expecting_metadataxDP, expecting_metadataxDN : std_logic;

  signal fifo_input, fifo_output             : std_logic_vector(DATASTREAM_DATA_WIDTH-1 downto 0);
  signal fifo_input_valid, fifo_output_valid : std_logic;
  signal fifo_input_ready, fifo_output_ready : std_logic;
  signal fifo_input_full                     : std_logic;

  signal root_out, metadata_out             : std_logic_vector(DATASTREAM_DATA_WIDTH-1 downto 0);
  signal root_out_valid, metadata_out_valid : std_logic;
  signal root_out_ready, metadata_out_ready : std_logic;
  signal root_out_last, metadata_out_last   : std_logic;

begin

  metadata_fifo : entity work.fifo
    generic map(
      WIDTH    => DATASTREAM_DATA_WIDTH,
      ELEMENTS => CONVERSION_FACTOR
      )
    port map(
      clk    => clk,
      resetn => resetn,

      in_data  => fifo_input,
      in_valid => fifo_input_valid,
      in_ready => fifo_input_ready,
      in_full  => fifo_input_full,

      out_data  => fifo_output,
      out_valid => fifo_output_valid,
      out_ready => fifo_output_ready
      );

  root_rate_conversion : entity work.rate_converter
    generic map(
      IN_DATA_WIDTH  => METADATA_WIDTH,
      OUT_DATA_WIDTH => DATASTREAM_DATA_WIDTH,
      REGISTERED     => false
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_field_offset => (others => '0'),
      in_field_len    => (others => '1'),

      in_last  => '1',
      in_data  => root_metadata,
      in_valid => root_valid,
      in_ready => root_ready,

      out_data         => root_out,
      out_last         => root_out_last,
      out_field_offset => open,
      out_field_len    => open,
      out_valid        => root_out_valid,
      out_ready        => root_out_ready
      );

  metadata_rate_conversion : entity work.rate_converter
    generic map(
      IN_DATA_WIDTH  => METADATA_WIDTH,
      OUT_DATA_WIDTH => DATASTREAM_DATA_WIDTH,
      REGISTERED     => false
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_field_offset => (others => '0'),
      in_field_len    => (others => '1'),

      in_last  => '1',
      in_data  => metadata,
      in_valid => metadata_valid,
      in_ready => metadata_ready,

      out_data         => metadata_out,
      out_last         => metadata_out_last,
      out_field_offset => open,
      out_field_len    => open,
      out_valid        => metadata_out_valid,
      out_ready        => metadata_out_ready
      );



  regs : process(clk) is
  begin
    if rising_edge(clk) then
      if resetn = '0' then
        BlockCounterxDP       <= (others => '0');
        expecting_metadataxDP <= '0';
      else
        BlockCounterxDP       <= BlockCounterxDN;
        expecting_metadataxDP <= expecting_metadataxDN;
      end if;
    end if;
  end process regs;

  comb : process(s_request, m_request_ready, BlockCounterxDP, expecting_metadataxDP,
                 fifo_input_ready, fifo_output, fifo_output_valid, fifo_input_full,
                 root_out, metadata_out, root_out_valid, metadata_out_valid,
                 root_out_last, metadata_out_last, metadata_out_ready, root_valid) is
    variable vBlockCounter : integer;
    variable vInjecting    : std_logic;
  begin
    BlockCounterxDN       <= BlockCounterxDP;
    expecting_metadataxDN <= expecting_metadataxDP;

    m_request          <= s_request;
    s_request_ready    <= m_request_ready;
    root_out_ready     <= '0';
    metadata_out_ready <= '0';

    fifo_input        <= (others => '0');
    fifo_input_valid  <= '0';
    fifo_output_ready <= '0';

    -- Drop metadata blocks from the stream and store the data into the internal register.
    -- They are actually cache hits.
    if s_request.valid = '1' and s_request.metadata = '1' then
      if s_request.request_type = REQ_TYPE_TREE_ROOT then
        -- cache hits on the root node have to drop the current root node
        if root_valid = '1' then
          m_request         <= StreamType_default;
          fifo_input        <= s_request.data;
          fifo_input_valid  <= '1';
          fifo_output_ready <= fifo_input_full;
          s_request_ready   <= fifo_input_ready;
          root_out_ready    <= fifo_input_ready;
        end if;
      else
        m_request         <= StreamType_default;
        fifo_input        <= s_request.data;
        fifo_input_valid  <= '1';
        fifo_output_ready <= fifo_input_full;
        s_request_ready   <= fifo_input_ready;
      end if;
    end if;

    vInjecting    := '0';
    vBlockCounter := to_integer(unsigned(BlockCounterxDP));
    if s_request.valid = '1' and s_request.metadata = '0' and
      vBlockCounter >= INJECT_POSITION and vBlockCounter < (INJECT_POSITION+CONVERSION_FACTOR) then
      s_request_ready     <= '0';
      m_request.metadata  <= '1';
      m_request.block_len <= (others => '1');

      vInjecting := '1';
      if fifo_output_valid = '1' then
        -- ouput the metadata from the register
        if expecting_metadataxDP = '1' then
          -- but first drop the metadata from the input
          metadata_out_ready <= metadata_out_valid;
          m_request.valid    <= '0';
        else
          -- output metadata from the register
          m_request.data    <= fifo_output;
          m_request.valid   <= '1';
          fifo_output_ready <= m_request_ready;
        end if;
      elsif s_request.request_type = REQ_TYPE_TREE_ROOT then
        if root_out_valid = '1' then
          -- output the tree root as metadata
          m_request.data  <= root_out;
          m_request.valid <= '1';
          root_out_ready  <= m_request_ready;
        end if;
      else
        -- output the metadata from the input
        m_request.data     <= metadata_out;
        m_request.valid    <= metadata_out_valid;
        metadata_out_ready <= m_request_ready;
      end if;

      if metadata_out_valid = '1' and metadata_out_ready = '1' then
        expecting_metadataxDN <= not(metadata_out_last);
      end if;
    end if;

    if to_integer(unsigned(BlockCounterxDP)) = (INJECT_POSITION+CONVERSION_FACTOR-1) and m_request_ready = '1' and (s_request.request_type = REQ_TYPE_TREE or s_request.request_type = REQ_TYPE_TREE_ROOT) then
      expecting_metadataxDN <= '1';
    end if;

    if m_request_ready = '1' then
      if s_request.block_len = zeros(s_request.block_len'length) and vInjecting = '0' then
        BlockCounterxDN <= (others => '0');
      else
        BlockCounterxDN <= std_logic_vector(unsigned(BlockCounterxDP) + 1);
      end if;
    end if;
  end process comb;

end behavioral;
