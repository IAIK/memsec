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

--! Simple cache for nonces and keys in tree modes.
--!
--! The interface of the cache is inspired by AXI and uses separated address
--! read, read, and write channels.
entity node_cache is
  generic(
    ADDR_WIDTH : integer := 32;
    DATA_WIDTH : integer := 64;
    CACHE_SIZE : integer := 32   -- number of entries
    );
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    araddr   : in  std_logic_vector(ADDR_WIDTH - 1 downto 0);
    ardelete : in  std_logic;  -- invalidate the cache entry in case of a hit
    arvalid  : in  std_logic;
    arready  : out std_logic;

    rdata  : out std_logic_vector(DATA_WIDTH - 1 downto 0);
    rhit   : out std_logic;
    rvalid : out std_logic;
    rready : in  std_logic;

    waddr  : in  std_logic_vector(ADDR_WIDTH - 1 downto 0);
    wdata  : in  std_logic_vector(DATA_WIDTH - 1 downto 0);
    wvalid : in  std_logic;
    wready : out std_logic
    );
end node_cache;

--! Simple directly mapped cache.
architecture arch_imp of node_cache is
  constant INDEX_WIDTH       : integer := log2_ceil(CACHE_SIZE);
  constant TAG_WIDTH         : integer := ADDR_WIDTH - INDEX_WIDTH;
  constant CACHE_ENTRY_WIDTH : integer := 1 + TAG_WIDTH + DATA_WIDTH;

  signal read_index, write_index            : std_logic_vector(INDEX_WIDTH-1 downto 0);
  signal read_tag, last_read_tag, write_tag : std_logic_vector(TAG_WIDTH-1 downto 0);

  signal douta : std_logic_vector(CACHE_ENTRY_WIDTH-1 downto 0);
  signal dinb  : std_logic_vector(CACHE_ENTRY_WIDTH-1 downto 0);

  signal read_tag_valid, read_tag_ready           : std_logic;
  signal last_read_tag_valid, last_read_tag_ready : std_logic;
  signal RAM_read_req_valid, RAM_read_req_ready   : std_logic;
  signal RAM_read_data_valid, RAM_read_data_ready : std_logic;

begin
  read_index <= araddr(INDEX_WIDTH - 1 downto 0);
  read_tag   <= araddr(ADDR_WIDTH - 1 downto INDEX_WIDTH);

  write_index <= waddr(INDEX_WIDTH - 1 downto 0);
  write_tag   <= waddr(ADDR_WIDTH - 1 downto INDEX_WIDTH);

  dinb <= '1' & write_tag & wdata;

  comb : process(RAM_read_data_valid, douta, last_read_tag,
                 last_read_tag_valid, rready)
  begin
    rdata               <= (others => '0');
    rhit                <= '0';
    rvalid              <= '0';
    RAM_read_data_ready <= '0';
    last_read_tag_ready <= '0';

    if RAM_read_data_valid = '1' and last_read_tag_valid = '1' then
      rvalid              <= '1';
      last_read_tag_ready <= rready;
      RAM_read_data_ready <= rready;

      if douta(CACHE_ENTRY_WIDTH-1) = '1' and unsigned(douta(CACHE_ENTRY_WIDTH-2 downto DATA_WIDTH)) = unsigned(last_read_tag) then
        -- cache hit = valid entry and tags match
        rhit  <= '1';
        rdata <= douta(DATA_WIDTH-1 downto 0);
      end if;
    end if;
  end process comb;

  rtag_reg : entity work.register_stage
    generic map(
      WIDTH => TAG_WIDTH
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_data  => read_tag,
      in_valid => read_tag_valid,
      in_ready => read_tag_ready,

      out_data  => last_read_tag,
      out_valid => last_read_tag_valid,
      out_ready => last_read_tag_ready
      );

  ram : entity work.xilinx_TDP_RAM_synchronized
    generic map(
      ADDR_WIDTH => INDEX_WIDTH,
      DATA_WIDTH => CACHE_ENTRY_WIDTH,
      ENTRIES    => CACHE_SIZE
      )
    port map (
      clk    => clk,
      resetn => resetn,

      addra => read_index,
      dina  => (others => '0'),
      wea   => ardelete,
      vina  => RAM_read_req_valid,
      rina  => RAM_read_req_ready,

      douta => douta,
      vouta => RAM_read_data_valid,
      routa => RAM_read_data_ready,

      addrb => write_index,
      dinb  => dinb,
      web   => '1',
      vinb  => wvalid,
      rinb  => wready,

      doutb => open,
      voutb => open,
      routb => '1'
      );

  synchronizer : entity work.ready_synchronizer
    generic map(
      OUT_WIDTH => 2
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_valid => arvalid,
      in_ready => arready,

      out_valid(0)  => read_tag_valid,
      out_valid(1)  => RAM_read_req_valid,
      out_active(0) => '1',
      out_active(1) => '1',
      out_ready(0)  => read_tag_ready,
      out_ready(1)  => RAM_read_req_ready
      );

end arch_imp;
