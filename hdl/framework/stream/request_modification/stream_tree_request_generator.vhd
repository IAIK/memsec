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

--! Generate transactions for the full tree from the root to the leaf.
entity stream_tree_request_generator is
  generic(
    MEMORY_START_ADDRESS : std_logic_vector(ADDRESS_WIDTH-1 downto 0) := x"00000000";
    DATA_MEMORY_SIZE     : integer                                    := 8192;  --! Size of the protected memory in byte. (virtual address space)
    DATA_BLOCK_SIZE      : integer                                    := 32;    --! Size of a tree leaf node in byte. (virtual address space)
    TREE_DATA_SIZE       : integer                                    := 8;     --! Size of one element in the tree in byte
    TREE_ARITY           : integer                                    := 2;     --! Number of elements in one tree node
    TREE_ROOTS           : integer                                    := 1      --! Number of trees which are used to protect the data memory
    );
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    root_number       : out std_logic_vector(log2_ceil(TREE_ROOTS)-1 downto 0);
    root_update       : out std_logic;
    root_number_valid : out std_logic;
    root_number_ready : in  std_logic;

    s_request       : in  StreamType;
    s_request_ready : out std_logic;

    m_request       : out StreamType;
    m_request_ready : in  std_logic
    );
end stream_tree_request_generator;

architecture behavioral of stream_tree_request_generator is
  constant TREE_ARITY_BITS    : integer := log2_ceil(TREE_ARITY);
  constant NUM_DATA_BLOCKS    : integer := DATA_MEMORY_SIZE/DATA_BLOCK_SIZE;
  constant IND_TREE_SIZE      : integer := DATA_MEMORY_SIZE/TREE_ROOTS;
  constant TREE_OFFSET        : integer := DATA_MEMORY_SIZE;
  constant TREE_START_ADDRESS : std_logic_vector(ADDRESS_WIDTH-1 downto 0) :=
    std_logic_vector(to_unsigned(TREE_OFFSET, ADDRESS_WIDTH) + unsigned(MEMORY_START_ADDRESS));
  constant TREE_LEVELS : integer := (log2_ceil(NUM_DATA_BLOCKS/TREE_ROOTS)+TREE_ARITY_BITS-1)/log2_ceil(TREE_ARITY);

  constant TREE_LEVEL_BITS : integer                                      := log2_ceil(TREE_LEVELS+1);
  constant DATA_NODE_LEVEL : std_logic_vector(TREE_LEVEL_BITS-1 downto 0) := std_logic_vector(to_unsigned(TREE_LEVELS, TREE_LEVEL_BITS));

  signal TreeLevelxDP, TreeLevelxDN               : std_logic_vector(TREE_LEVEL_BITS-1 downto 0);
  signal TreeLevelAddressxDP, TreeLevelAddressxDN : std_logic_vector(ADDRESS_WIDTH-1 downto 0);

  signal request       : StreamType;
  signal request_ready : std_logic;

  signal sync_master_valid, sync_master_ready : std_logic;
  signal tree_root_request                    : std_logic;

  type StartAddressArray is array (TREE_ROOTS downto 0) of AddressType;
  signal tree_start_addresses : StartAddressArray;
begin

  -- can also be computed as constant ...
  start_addresses : process(s_request) is
    variable vTreeSize  : integer;
    variable vLastStart : AddressType;
  begin
    vTreeSize := ((TREE_ARITY**TREE_LEVELS)-1) / (TREE_ARITY-1);  -- number of nodes
    vTreeSize := vTreeSize * TREE_ARITY * TREE_DATA_SIZE;

    tree_start_addresses(0) <= TREE_START_ADDRESS;
    vLastStart              := TREE_START_ADDRESS;
    for I in 1 to TREE_ROOTS-1 loop
      vLastStart              := std_logic_vector(unsigned(vLastStart) + to_unsigned(vTreeSize, vLastStart'length));
      tree_start_addresses(I) <= vLastStart;
    end loop;
  end process start_addresses;

  regs : process(clk) is
  begin
    if rising_edge(clk) then
      if resetn = '0' then
        TreeLevelxDP        <= (others => '0');
        TreeLevelAddressxDP <= (others => '0');
      else
        TreeLevelxDP        <= TreeLevelxDN;
        TreeLevelAddressxDP <= TreeLevelAddressxDN;
      end if;
    end if;
  end process regs;

  comb : process(s_request, request_ready, TreeLevelxDP, TreeLevelAddressxDP, tree_start_addresses) is
    variable vTreeLevel        : unsigned(TREE_LEVEL_BITS-1 downto 0);
    variable vTreeLevelAddress : std_logic_vector(ADDRESS_WIDTH-1 downto 0);
    variable vDataNodeNum      : integer;
    variable vTreeNodeOffset   : integer;
    variable vTreeNodeAddress  : unsigned(ADDRESS_WIDTH-1 downto 0);
    variable vRootAddress      : unsigned(log2_ceil(TREE_ROOTS)-1 downto 0);
  begin
    TreeLevelxDN        <= TreeLevelxDP;
    TreeLevelAddressxDN <= TreeLevelAddressxDP;

    request         <= StreamType_Default;
    s_request_ready <= '0';
    root_number     <= (others => '0');
    root_update     <= '0';

    vTreeLevelAddress := TreeLevelAddressxDP;

    if s_request.valid = '1' then
      vRootAddress := to_unsigned(to_integer(unsigned(s_request.address) - unsigned(MEMORY_START_ADDRESS)) / IND_TREE_SIZE, log2_ceil(TREE_ROOTS));

      if TreeLevelxDP = DATA_NODE_LEVEL then
        request             <= s_request;
        TreeLevelAddressxDN <= (others => '0');
        s_request_ready     <= request_ready;

        if request_ready = '1' then
          TreeLevelxDN <= (others => '0');
        end if;
      else
        if TreeLevelxDP = zeros(TREE_LEVEL_BITS) then
          request.request_type <= REQ_TYPE_TREE_ROOT;
          vTreeLevelAddress    := tree_start_addresses(to_integer(vRootAddress));
          root_number          <= std_logic_vector(vRootAddress);
          root_update          <= not(s_request.read);
        else
          request.request_type <= REQ_TYPE_TREE;
        end if;

        vTreeLevel       := unsigned(TreeLevelxDP);
        vDataNodeNum     := (to_integer(unsigned(s_request.block_address)-unsigned(MEMORY_START_ADDRESS)) - to_integer(vRootAddress) * IND_TREE_SIZE) / DATA_BLOCK_SIZE;
        vTreeNodeOffset  := to_integer((to_unsigned(vDataNodeNum, ADDRESS_WIDTH) srl TREE_ARITY_BITS*(TREE_LEVELS-1-to_integer(vTreeLevel))));
        vTreeNodeOffset  := vTreeNodeOffset * TREE_DATA_SIZE;
        vTreeNodeAddress := unsigned(vTreeLevelAddress) + to_unsigned(vTreeNodeOffset, ADDRESS_WIDTH);

        request.block_address <= std_logic_vector(vTreeNodeAddress);
        request.address       <= std_logic_vector(vTreeNodeAddress);
        request.id            <= s_request.id;
        request.len           <= std_logic_vector(to_unsigned(TREE_DATA_SIZE/4-1, request.len'length));
        request.block_len     <= std_logic_vector(to_unsigned(TREE_DATA_SIZE/4-1, request.block_len'length));
        request.size          <= "010";
        request.burst         <= "01";
        request.cache         <= x"0";
        request.read          <= s_request.read;
        request.last_request  <= '0';
        request.valid         <= '1';

        if (request_ready = '1') then
          TreeLevelAddressxDN <= std_logic_vector(unsigned(vTreeLevelAddress) + (to_unsigned(TREE_DATA_SIZE, ADDRESS_WIDTH) sll TREE_ARITY_BITS*to_integer((vTreeLevel+1))));
          TreeLevelxDN        <= std_logic_vector(vTreeLevel+1);
        end if;
      end if;
    end if;
  end process comb;


  synchronizer : entity work.ready_synchronizer
    generic map(
      OUT_WIDTH => 2
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_valid => request.valid,
      in_ready => request_ready,

      out_valid(0)  => sync_master_valid,
      out_valid(1)  => root_number_valid,
      out_active(0) => '1',
      out_active(1) => tree_root_request,
      out_ready(0)  => m_request_ready,
      out_ready(1)  => root_number_ready
      );

  tree_root_request <= '1' when request.request_type = REQ_TYPE_TREE_ROOT else '0';

  output : process(request, sync_master_valid) is
  begin
    m_request <= StreamType_Default;

    if sync_master_valid = '1' then
      m_request <= request;
    end if;
  end process output;

end behavioral;
