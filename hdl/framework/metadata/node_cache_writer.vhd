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

--! Writes data (from one of two ports) into the cache.
--!
--! The new port writes data unconditionally when it is valid. On the other
--! hand, the old port writes data only when no request from the new port is
--! pending and when the request is a read.
entity node_cache_writer is
  generic(
    CACHE_ADDR_WIDTH : integer := 32;
    DATA_MEMORY_SIZE : integer := 512;  -- Data memory size in byte
    CACHE_DATA_WIDTH : integer := 64
    );
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    waddr  : out std_logic_vector(CACHE_ADDR_WIDTH - 1 downto 0);
    wdata  : out std_logic_vector(CACHE_DATA_WIDTH - 1 downto 0);
    wvalid : out std_logic;
    wready : in  std_logic;

    s_old_entry   : in  std_logic_vector(CACHE_DATA_WIDTH - 1 downto 0);
    s_old_address : in  AddressType;
    s_old_is_read : in  std_logic;
    s_old_valid   : in  std_logic;
    s_old_ready   : out std_logic;

    s_new_entry   : in  std_logic_vector(CACHE_DATA_WIDTH - 1 downto 0);
    s_new_address : in  AddressType;
    s_new_valid   : in  std_logic;
    s_new_ready   : out std_logic
    );
end node_cache_writer;

architecture arch_imp of node_cache_writer is
begin

  work : process(s_new_address, s_new_entry, s_new_valid, s_old_address,
                 s_old_entry, s_old_is_read, s_old_valid, wready) is
    constant ALIGNMENT_WIDTH : integer := log2_ceil(CACHE_DATA_WIDTH/8);
    variable address         : unsigned(ADDRESS_WIDTH-1 downto 0);
  begin
    waddr  <= (others => '0');
    wdata  <= (others => '0');
    wvalid <= '0';

    s_old_ready <= '0';
    s_new_ready <= '0';

    address := (others => '0');
    if s_new_valid = '1' then
      address     := unsigned(s_new_address) - to_unsigned(DATA_MEMORY_SIZE, ADDRESS_WIDTH);
      wdata       <= s_new_entry;
      wvalid      <= '1';
      s_new_ready <= wready;
    elsif s_old_valid = '1' and s_old_is_read = '1' then
      address     := unsigned(s_old_address) - to_unsigned(DATA_MEMORY_SIZE, ADDRESS_WIDTH);
      wdata       <= s_old_entry;
      wvalid      <= '1';
      s_old_ready <= wready;
    end if;

    if s_old_valid = '1' and s_old_is_read = '0' then
      s_old_ready <= '1';
    end if;

    waddr <= std_logic_vector(address(CACHE_ADDR_WIDTH+ALIGNMENT_WIDTH-1 downto ALIGNMENT_WIDTH));
  end process work;

end arch_imp;
