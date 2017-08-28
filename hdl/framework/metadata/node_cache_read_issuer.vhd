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

--! Requests data from the cache for every tree node.
--!
--! If the request is a write, the cache entry is also deleted.
entity node_cache_read_issuer is
  generic(
    CACHE_ADDR_WIDTH : integer := 32;
    DATA_MEMORY_SIZE : integer := 512;  -- Data memory size in byte
    CACHE_DATA_WIDTH : integer := 64
    );
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    araddr   : out std_logic_vector(CACHE_ADDR_WIDTH - 1 downto 0);
    ardelete : out std_logic;
    arvalid  : out std_logic;
    arready  : in  std_logic;

    s_request       : in  StreamType;
    s_request_ready : out std_logic;

    m_request       : out StreamType;
    m_request_ready : in  std_logic
    );
end node_cache_read_issuer;

architecture arch_imp of node_cache_read_issuer is
  signal m_request_valid : std_logic;

  signal tree_request : std_logic;
begin

  synchronizer : entity work.ready_synchronizer
    generic map(
      OUT_WIDTH => 2
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_valid => s_request.valid,
      in_ready => s_request_ready,

      out_valid(0)  => m_request_valid,
      out_valid(1)  => arvalid,
      out_active(0) => '1',
      out_active(1) => tree_request,
      out_ready(0)  => m_request_ready,
      out_ready(1)  => arready
      );

  tree_request <= '1' when s_request.valid = '1' and (s_request.request_type = REQ_TYPE_TREE or s_request.request_type = REQ_TYPE_TREE_ROOT)
                  else '0';

  output_cache_lookup : process(s_request.address, s_request.request_type, s_request.valid, s_request.read, tree_request) is
    constant ALIGNMENT_WIDTH : integer := log2_ceil(CACHE_DATA_WIDTH/8);
    variable addr            : unsigned(ADDRESS_WIDTH-1 downto 0);
  begin
    araddr   <= (others => '0');
    ardelete <= '0';
    if tree_request = '1' then
      addr     := unsigned(s_request.address) - to_unsigned(DATA_MEMORY_SIZE, ADDRESS_WIDTH);
      araddr   <= std_logic_vector(addr(CACHE_ADDR_WIDTH+ALIGNMENT_WIDTH-1 downto ALIGNMENT_WIDTH));
      ardelete <= not(s_request.read);
    end if;
  end process output_cache_lookup;

  output_stream : process(m_request_valid, s_request) is
  begin
    m_request       <= s_request;
    m_request.valid <= m_request_valid;
  end process output_stream;

end arch_imp;
