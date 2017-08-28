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

--! Guard which ensures that at most one write request for every block is in the pipeline.
entity pipeline_guard is
  generic(
    BLOCK_SIZE         : integer := 64;    --! Size of one block in the virtual address space in byte.
    FIFO_SIZE          : integer := 4;     --! Maximum number of writes within the pipeline
    RELEASE_REGISTERED : boolean := false
    );
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    s_request       : in  StreamType;
    s_request_ready : out std_logic;

    m_request       : out StreamType;
    m_request_ready : in  std_logic;

    release       : in  std_logic;
    release_ready : out std_logic
    );
end pipeline_guard;

architecture behavioral of pipeline_guard is
  constant FIFO_SIZE_BITS  : integer                                     := log2_ceil(FIFO_SIZE);
  constant BLOCK_SIZE_BITS : integer                                     := log2_ceil(BLOCK_SIZE);
  type FifoArrayType is array(natural range <>) of std_logic_vector(ADDRESS_WIDTH-BLOCK_SIZE_BITS-1 downto 0);
  constant FIFO_MAX_IDX    : std_logic_vector(FIFO_SIZE_BITS-1 downto 0) := std_logic_vector(to_unsigned(FIFO_SIZE-1, FIFO_SIZE_BITS));

  signal FifoxDP, FifoxDN             : FifoArrayType(FIFO_SIZE-1 downto 0);
  signal FifoInIdxxDP, FifoInIdxxDN   : std_logic_vector(FIFO_SIZE_BITS-1 downto 0);
  signal FifoOutIdxxDP, FifoOutIdxxDN : std_logic_vector(FIFO_SIZE_BITS-1 downto 0);
  signal FifoValidxDP, FifoValidxDN   : std_logic_vector(FIFO_SIZE-1 downto 0);
begin

  regs : process(clk) is
  begin
    if rising_edge(clk) then
      if resetn = '0' then
        FifoxDP       <= (others => (others => '0'));
        FifoValidxDP  <= (others => '0');
        FifoInIdxxDP  <= (others => '0');
        FifoOutIdxxDP <= (others => '0');
      else
        FifoxDP       <= FifoxDN;
        FifoValidxDP  <= FifoValidxDN;
        FifoInIdxxDP  <= FifoInIdxxDN;
        FifoOutIdxxDP <= FifoOutIdxxDN;
      end if;
    end if;
  end process regs;

  comb_fifo : process(release, s_request, m_request_ready,
                      FifoxDP, FifoValidxDP, FifoInIdxxDP, FifoOutIdxxDP) is
    variable idx               : integer;
    variable block_in_pipeline : std_logic;
    variable fifo_valid        : std_logic_vector(FIFO_SIZE-1 downto 0);
  begin
    FifoxDN       <= FifoxDP;
    FifoValidxDN  <= FifoValidxDP;
    FifoInIdxxDN  <= FifoInIdxxDP;
    FifoOutIdxxDN <= FifoOutIdxxDP;

    m_request       <= s_request;
    m_request.valid <= '0';

    s_request_ready <= '0';
    release_ready   <= '0';

    fifo_valid := FifoValidxDP;

    -- remove from fifo
    idx := 0;
    if release = '1' then
      -- remove top element from FIFO
      idx               := to_integer(unsigned(FifoOutIdxxDP));
      FifoValidxDN(idx) <= '0';
      if RELEASE_REGISTERED = false then
        fifo_valid(idx) := '0';
      end if;
      release_ready <= '1';
      FifoOutIdxxDN <= std_logic_vector(unsigned(FifoOutIdxxDP)+1);
      if FifoOutIdxxDP = FIFO_MAX_IDX then
        FifoOutIdxxDN <= (others => '0');
      end if;
    end if;

    -- check if request is currently in write pipeline
    block_in_pipeline := '0';
    for i in 0 to FIFO_SIZE-1 loop
      if fifo_valid(i) = '1' and
        FifoxDP(i) = s_request.block_address(ADDRESS_WIDTH-1 downto BLOCK_SIZE_BITS) then
        block_in_pipeline := '1';
      end if;
    end loop;

    -- insert into fifo and forward data
    idx := 0;
    if block_in_pipeline = '0' then
      if s_request.read = '1' then      -- read access
        m_request.valid <= s_request.valid;
        s_request_ready <= m_request_ready;
      else                              -- write access
        idx := to_integer(unsigned(FifoInIdxxDP));
        if s_request.valid = '1' and FifoValidxDP(idx) = '0' then  -- FIFO must not be full
          m_request.valid <= s_request.valid;
          s_request_ready <= m_request_ready;
          if m_request_ready = '1' then
            FifoxDN(idx)      <= s_request.block_address(ADDRESS_WIDTH-1 downto BLOCK_SIZE_BITS);
            FifoValidxDN(idx) <= '1';
            FifoInIdxxDN      <= std_logic_vector(unsigned(FifoInIdxxDP)+1);
            if FifoInIdxxDP = FIFO_MAX_IDX then
              FifoInIdxxDN <= (others => '0');
            end if;
          end if;
        end if;
      end if;
    end if;

  end process;

end behavioral;
