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

--! Reads data from the cache into the internal stream.
--!
--! For every tree node a response from the cache is expected. If the cache
--! request is a hit, the result is stored in the internal stream as metadata.
entity node_cache_read_fetcher is
  generic(
    CACHE_DATA_WIDTH : integer := 64
    );
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    rdata  : in  std_logic_vector(CACHE_DATA_WIDTH - 1 downto 0);
    rhit   : in  std_logic;
    rvalid : in  std_logic;
    rready : out std_logic;

    s_request       : in  StreamType;
    s_request_ready : out std_logic;

    m_request       : out StreamType;
    m_request_ready : in  std_logic
    );
end node_cache_read_fetcher;

architecture arch_imp of node_cache_read_fetcher is
  signal cdata                 : std_logic_vector(DATASTREAM_DATA_WIDTH-1 downto 0);
  signal clast, cvalid, cready : std_logic;

  signal hit, miss               : std_logic;
  signal rvalid_hit, rvalid_miss : std_logic;
  signal rready_hit, rready_miss : std_logic;

begin

  hit  <= rhit and s_request.read;
  miss <= not(hit);

  synchronizer : entity work.ready_synchronizer
    generic map(
      OUT_WIDTH => 2
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_valid => rvalid,
      in_ready => rready,

      out_valid(0)  => rvalid_hit,
      out_valid(1)  => rvalid_miss,
      out_active(0) => hit,
      out_active(1) => miss,
      out_ready(0)  => rready_hit,
      out_ready(1)  => rready_miss
      );

  cache_rate_converter : entity work.rate_converter
    generic map(
      IN_DATA_WIDTH  => CACHE_DATA_WIDTH,
      OUT_DATA_WIDTH => DATASTREAM_DATA_WIDTH,
      REGISTERED     => false
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_field_offset => (others => '0'),
      in_field_len    => (others => '1'),

      in_last  => '1',
      in_data  => rdata,
      in_valid => rvalid_hit,
      in_ready => rready_hit,

      out_data         => cdata,
      out_last         => clast,
      out_field_offset => open,
      out_field_len    => open,
      out_valid        => cvalid,
      out_ready        => cready
      );

  output : process(m_request_ready, rvalid_miss, s_request, rhit, cvalid, cdata, clast) is
  begin
    m_request       <= StreamType_default;
    s_request_ready <= '0';
    cready          <= '0';
    rready_miss     <= '0';

    if s_request.valid = '1' then
      if s_request.request_type /= REQ_TYPE_TREE and s_request.request_type /= REQ_TYPE_TREE_ROOT then
        m_request       <= s_request;
        s_request_ready <= m_request_ready;
      elsif rvalid_miss = '1' then
        m_request       <= s_request;
        rready_miss     <= m_request_ready;
        s_request_ready <= m_request_ready;
      elsif cvalid = '1' then
        m_request           <= s_request;
        m_request.block_len <= (others => '1');
        m_request.data      <= cdata;
        m_request.metadata  <= '1';

        cready          <= m_request_ready;
        s_request_ready <= m_request_ready and clast;
      end if;
    end if;
  end process output;

end arch_imp;
