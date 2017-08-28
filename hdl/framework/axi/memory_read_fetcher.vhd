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

--! [Master] Reads data from the AXI read channel and translates them to the internal stream.
--!
--! After the memory_read_fetcher, a transaction typically consists of multiple
--! beats. (depending on the transaction and stream width)
--! Currently, only internal stream widths which are equally wide or wider are
--! are supported.
entity memory_read_fetcher is
  generic(
    C_M_AXI_ID_WIDTH    : integer := 12;
    C_M_AXI_DATA_WIDTH  : integer := 32;
    C_M_AXI_RUSER_WIDTH : integer := 0
    );
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    m_axi_rid    : in  std_logic_vector(C_M_AXI_ID_WIDTH - 1 downto 0);
    m_axi_rdata  : in  std_logic_vector(C_M_AXI_DATA_WIDTH - 1 downto 0);
    m_axi_rresp  : in  std_logic_vector(1 downto 0);
    m_axi_rlast  : in  std_logic;
    m_axi_ruser  : in  std_logic_vector(C_M_AXI_RUSER_WIDTH - 1 downto 0);
    m_axi_rvalid : in  std_logic;
    m_axi_rready : out std_logic;

    s_request       : in  StreamType;
    s_request_ready : out std_logic;

    m_request       : out StreamType;
    m_request_ready : in  std_logic
    );
end memory_read_fetcher;

architecture arch_imp of memory_read_fetcher is
  signal blockNrxDP, blockNrxDN : std_logic_vector(AXI_LEN_WIDTH-1 downto 0);

  signal bus_data  : std_logic_vector(DATASTREAM_DATA_WIDTH - 1 downto 0);
  signal bus_last  : std_logic;
  signal bus_valid : std_logic;
  signal bus_ready : std_logic;
begin

  regs : process(clk) is
  begin
    if rising_edge(clk) then
      if resetn = '0' then
        blockNrxDP <= (others => '0');
      else
        blockNrxDP <= blockNrxDN;
      end if;
    end if;
  end process regs;

  data_deserialization : entity work.deserialization
    generic map(
      IN_DATA_WIDTH  => C_M_AXI_DATA_WIDTH,
      OUT_DATA_WIDTH => DATASTREAM_DATA_WIDTH,
      REGISTERED     => true
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_field_start_offset => (others => '0'),
      in_last               => m_axi_rlast,

      in_data  => m_axi_rdata,
      in_valid => m_axi_rvalid,
      in_ready => m_axi_rready,

      out_data         => bus_data,
      out_last         => bus_last,
      out_field_offset => open,
      out_field_len    => open,
      out_valid        => bus_valid,
      out_ready        => bus_ready
      );

  work : process(blockNrxDP, bus_data, bus_last, bus_valid, m_request_ready,
                 s_request) is
    constant PADDING_BIT_COUNT : integer := log2_ceil(DATASTREAM_DATA_WIDTH/8);
  begin
    blockNrxDN <= blockNrxDP;

    m_request       <= StreamType_default;
    s_request_ready <= '0';
    bus_ready       <= '0';

    if s_request.valid = '1' and s_request.metadata = '1' then
      -- Metadata blocks are simply forwarded and ignored. These blocks are
      -- for example used for cache hits.
      m_request       <= s_request;
      s_request_ready <= m_request_ready;
    elsif s_request.valid = '1' and bus_valid = '1' then
      m_request      <= s_request;
      m_request.data <= bus_data;

      -- increment the length and address fields, assuming a 1:1 mapping
      -- other layouts have to fixup the fields after the memory_read_fetcher
      m_request.block_len     <= std_logic_vector(unsigned(s_request.block_len) - unsigned(blockNrxDP));
      m_request.block_address <= std_logic_vector(unsigned(s_request.block_address) + unsigned(blockNrxDP & zeros(PADDING_BIT_COUNT)));
      m_request.virt_address  <= std_logic_vector(unsigned(s_request.virt_address) + unsigned(blockNrxDP & zeros(PADDING_BIT_COUNT)));

      if m_request_ready = '1' then
        bus_ready  <= '1';
        blockNrxDN <= std_logic_vector(unsigned(blockNrxDP) + to_unsigned(1, blockNrxDP'length));
        if bus_last = '1' then
          blockNrxDN      <= (others => '0');
          s_request_ready <= '1';
        end if;
      end if;
    end if;

  end process work;

end arch_imp;
