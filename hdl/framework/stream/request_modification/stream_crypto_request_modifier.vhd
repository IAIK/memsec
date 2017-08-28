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

--! Widens requests to a size which is suitable for the cryptographic mode.
--!
--! How a request is widenend can be configured using the various generics.
entity stream_crypto_request_modifier is
  generic(
    C_M_AXI_DATA_WIDTH : integer := 32;

    DATA_START_ADDRESS         : std_logic_vector := x"40000000";  --! Start address offset for data accesses.
    DATA_ALIGNMENT             : integer          := 1;            --! Size of one data block in the virtual address space in byte.
    DATA_METADATA              : integer          := 0;            --! Metadata size in byte for every data block.
    TREE_START_ADDRESS         : std_logic_vector := x"40000000";  --! Start address offset for tree accesses.
    TREE_ALIGNMENT             : integer          := 1;            --! Size of one tree block in the virtual address space in byte.
    TREE_METADATA              : integer          := 0;            --! Metadata size in byte for every tree block.
    TREE_ENABLE                : boolean          := false;        --! Enable support for tree request.
    TREE_ALIGNMENT_READ        : integer          := 0;            --! Size of one tree block for reads in the virtual address space in byte.
    TREE_ALIGNMENT_READ_ENABLE : boolean          := false;        --! Enable special alignment for reads in tree blocks.
    SIMPLE_ALIGNMENT           : boolean          := true          --! Enable bit slicing based widening. (better critical path)
    );
  port(
    -- Ports of Axi Slave Bus Interface S_AXI
    clk    : in std_logic;
    resetn : in std_logic;

    s_request       : in  StreamType;
    s_request_ready : out std_logic;

    m_request       : out StreamType;
    m_request_ready : in  std_logic
    );
end stream_crypto_request_modifier;

architecture arch_imp of stream_crypto_request_modifier is
  constant M_AXI_ALIGNMENT_BIT      : integer := log2_ceil(C_M_AXI_DATA_WIDTH/8);
  constant DATASTREAM_ALIGNMENT_BIT : integer := log2_ceil(DATASTREAM_DATA_WIDTH/8);

  constant DATA_ALIGNMENT_BIT  : integer     := log2_ceil(DATA_ALIGNMENT);
  constant DATA_METADATA_BIT   : integer     := log2_ceil(DATA_METADATA);
  constant DATA_ALIGNMENT_MASK : AddressType := ones(ADDRESS_WIDTH-DATA_ALIGNMENT_BIT) & zeros(DATA_ALIGNMENT_BIT);

  constant TREE_ALIGNMENT_BIT       : integer     := log2_ceil(TREE_ALIGNMENT);
  constant TREE_ALIGNMENT_READ_BIT  : integer     := log2_ceil(TREE_ALIGNMENT_READ);
  constant TREE_METADATA_BIT        : integer     := log2_ceil(TREE_METADATA);
  constant TREE_ALIGNMENT_MASK      : AddressType := ones(ADDRESS_WIDTH-TREE_ALIGNMENT_BIT) & zeros(TREE_ALIGNMENT_BIT);
  constant TREE_ALIGNMENT_READ_MASK : AddressType := ones(ADDRESS_WIDTH-TREE_ALIGNMENT_READ_BIT) & zeros(TREE_ALIGNMENT_READ_BIT);

  constant TREE_VIRT_OFFSET : unsigned(ADDRESS_WIDTH-1 downto 0) := unsigned(TREE_START_ADDRESS)-unsigned(DATA_START_ADDRESS);
  constant TREE_PHYS_OFFSET : unsigned(ADDRESS_WIDTH-1 downto 0) := TREE_VIRT_OFFSET +
                                                                    to_unsigned(to_integer(TREE_VIRT_OFFSET)/DATA_ALIGNMENT*DATA_METADATA, ADDRESS_WIDTH);

begin
  s_request_ready <= m_request_ready;

  translate_request : process(s_request) is
    variable vBlockNum           : integer;
    variable vBlockCount         : integer;
    variable vVirtualAddress     : integer;
    variable vVirtualLenUnsigned : unsigned(AXI_LEN_WIDTH + 1 downto 0);
    variable vPhysicalAddr       : unsigned(ADDRESS_WIDTH - 1 downto 0);
    variable vPhysicalLen        : unsigned(AXI_LEN_WIDTH + 1 downto 0);

    variable vVirtAddressVec : std_logic_vector(ADDRESS_WIDTH - 1 downto 0);
    variable vVirtLenVec     : unsigned(AXI_LEN_WIDTH + 1 downto 0);

    variable vTmp : unsigned(ADDRESS_WIDTH -1 downto 0);

    variable vAxiALen      : unsigned(AXI_LEN_WIDTH + 1 downto 0);
    variable vAxiALenBytes : unsigned(AXI_LEN_WIDTH + 1 downto 0);
    variable vAxiASize     : unsigned(s_request.size'length - 1 downto 0);

    variable vAxiAAddress   : unsigned(ADDRESS_WIDTH - 1 downto 0);
    variable vAxiAAddressSL : std_logic_vector(ADDRESS_WIDTH - 1 downto 0);

    variable vAlignment  : integer;
    variable vMetadata   : integer;
    variable vPhysOffset : unsigned(ADDRESS_WIDTH - 1 downto 0);
    variable vVirtOffset : unsigned(ADDRESS_WIDTH - 1 downto 0);
  begin
    vAxiASize     := unsigned(s_request.size);
    vAxiALen      := unsigned("00" & s_request.block_len);
    vTmp          := unsigned(dynamic_mask(to_integer(vAxiASize), ADDRESS_WIDTH));
    vAxiALenBytes := (vAxiALen sll to_integer(vAxiASize)) or vTmp(AXI_LEN_WIDTH+1 downto 0);
    vAxiAAddress  := unsigned(s_request.block_address) - unsigned(DATA_START_ADDRESS);
    if (s_request.request_type = REQ_TYPE_TREE or s_request.request_type = REQ_TYPE_TREE_ROOT) then
      vAxiAAddress := unsigned(s_request.block_address) - unsigned(TREE_START_ADDRESS);
    end if;
    vAxiAAddressSL := std_logic_vector(vAxiAAddress);

    m_request <= s_request;

    m_request.address <= std_logic_vector(unsigned(s_request.address) - unsigned(DATA_START_ADDRESS));

    -- Determine number of crypto blocks to fetch
    if SIMPLE_ALIGNMENT = true and DATA_METADATA /= 0 then  -- hamming_weight(vAlignment) = 1 and hamming_weight(vMetadata) = 1 then

      if TREE_ENABLE = true and (s_request.request_type = REQ_TYPE_TREE or s_request.request_type = REQ_TYPE_TREE_ROOT) then
        if TREE_ALIGNMENT_READ_ENABLE and s_request.read = '1' then
          vBlockNum       := to_integer(vAxiAAddress srl TREE_ALIGNMENT_READ_BIT);
          vVirtAddressVec := vAxiAAddressSL(ADDRESS_WIDTH-1 downto TREE_ALIGNMENT_READ_BIT) & (TREE_ALIGNMENT_READ_BIT-1 downto 0 => '0');

          vTmp        := vAxiAAddress - unsigned(vVirtAddressVec);
          vBlockCount := to_integer((vTmp(AXI_LEN_WIDTH + 1 downto 0)+unsigned(vAxiALenBytes)) srl TREE_ALIGNMENT_READ_BIT);
          vVirtLenVec := to_unsigned(vBlockCount, AXI_LEN_WIDTH + 2);
          vVirtLenVec := vVirtLenVec(vVirtLenVec'length-TREE_ALIGNMENT_READ_BIT-1 downto 0) & (TREE_ALIGNMENT_READ_BIT-1 downto 0 => '1');
        else
          vBlockNum       := to_integer(vAxiAAddress srl TREE_ALIGNMENT_BIT);
          vVirtAddressVec := vAxiAAddressSL(ADDRESS_WIDTH-1 downto TREE_ALIGNMENT_BIT) & (TREE_ALIGNMENT_BIT-1 downto 0 => '0');

          vTmp        := vAxiAAddress - unsigned(vVirtAddressVec);
          vBlockCount := to_integer((vTmp(AXI_LEN_WIDTH + 1 downto 0)+unsigned(vAxiALenBytes)) srl TREE_ALIGNMENT_BIT);
          vVirtLenVec := to_unsigned(vBlockCount, AXI_LEN_WIDTH + 2);
          vVirtLenVec := vVirtLenVec(vVirtLenVec'length-TREE_ALIGNMENT_BIT-1 downto 0) & (TREE_ALIGNMENT_BIT-1 downto 0 => '1');
        end if;

        if TREE_METADATA = 0 or (TREE_ALIGNMENT_READ_ENABLE and s_request.read = '1') then
          vPhysicalAddr := unsigned(vVirtAddressVec) + TREE_PHYS_OFFSET;
          vPhysicalLen  := (others => '0');
        else
          vPhysicalAddr := to_unsigned(vBlockNum, ADDRESS_WIDTH);
          vPhysicalAddr := vPhysicalAddr(ADDRESS_WIDTH-TREE_METADATA_BIT-1 downto 0) & (TREE_METADATA_BIT-1 downto 0    => '0');
          vPhysicalAddr := vPhysicalAddr + unsigned(vVirtAddressVec) + TREE_PHYS_OFFSET;
          vPhysicalLen  := to_unsigned(vBlockCount+1, AXI_LEN_WIDTH + 2);
          vPhysicalLen  := vPhysicalLen(AXI_LEN_WIDTH + 1 - TREE_METADATA_BIT downto 0) & (TREE_METADATA_BIT-1 downto 0 => '0');
        end if;

        vVirtAddressVec := std_logic_vector(unsigned(vVirtAddressVec) + TREE_VIRT_OFFSET);
      else
        vBlockNum       := to_integer(vAxiAAddress srl DATA_ALIGNMENT_BIT);
        vVirtAddressVec := vAxiAAddressSL(ADDRESS_WIDTH-1 downto DATA_ALIGNMENT_BIT) & (DATA_ALIGNMENT_BIT-1 downto 0 => '0');

        vTmp        := vAxiAAddress - unsigned(vVirtAddressVec);
        vBlockCount := to_integer((vTmp(AXI_LEN_WIDTH + 1 downto 0)+unsigned(vAxiALenBytes)) srl DATA_ALIGNMENT_BIT);
        vVirtLenVec := to_unsigned(vBlockCount, AXI_LEN_WIDTH + 2);
        vVirtLenVec := vVirtLenVec(vVirtLenVec'length-DATA_ALIGNMENT_BIT-1 downto 0) & (DATA_ALIGNMENT_BIT-1 downto 0 => '1');

        vPhysicalAddr := to_unsigned(vBlockNum, ADDRESS_WIDTH);
        vPhysicalAddr := vPhysicalAddr(ADDRESS_WIDTH-DATA_METADATA_BIT-1 downto 0) & (DATA_METADATA_BIT-1 downto 0    => '0');
        vPhysicalAddr := vPhysicalAddr + unsigned(vVirtAddressVec);
        vPhysicalLen  := to_unsigned(vBlockCount+1, AXI_LEN_WIDTH + 2);
        vPhysicalLen  := vPhysicalLen(AXI_LEN_WIDTH + 1 - DATA_METADATA_BIT downto 0) & (DATA_METADATA_BIT-1 downto 0 => '0');
      end if;

      vPhysicalLen := vPhysicalLen + vVirtLenVec;
      vVirtLenVec  := (DATASTREAM_ALIGNMENT_BIT-1 downto 0 => '0') & vVirtLenVec(AXI_LEN_WIDTH + 1 downto DATASTREAM_ALIGNMENT_BIT);
      vPhysicalLen := (DATASTREAM_ALIGNMENT_BIT-1 downto 0 => '0') & vPhysicalLen(AXI_LEN_WIDTH + 1 downto DATASTREAM_ALIGNMENT_BIT);

      m_request.block_address <= std_logic_vector(vPhysicalAddr);
      m_request.block_len     <= std_logic_vector(vPhysicalLen(AXI_LEN_WIDTH - 1 downto 0));
      m_request.virt_address  <= vVirtAddressVec;
    else

      vAlignment  := DATA_ALIGNMENT;
      vMetadata   := DATA_METADATA;
      vPhysOffset := (others => '0');
      vVirtOffset := (others => '0');

      if TREE_ENABLE = true and (s_request.request_type = REQ_TYPE_TREE or s_request.request_type = REQ_TYPE_TREE_ROOT) then
        if TREE_ALIGNMENT_READ_ENABLE = true and s_request.read = '1' then
          vAlignment := TREE_ALIGNMENT_READ;
          vMetadata  := 0;
        else
          vAlignment := TREE_ALIGNMENT;
          vMetadata  := TREE_METADATA;
        end if;
        vPhysOffset := TREE_PHYS_OFFSET;
        vVirtOffset := TREE_VIRT_OFFSET;
      end if;

      vBlockNum           := to_integer(vAxiAAddress) / vAlignment;
      vVirtualAddress     := vBlockNum * vAlignment;
      vBlockCount         := (to_integer(vAxiAAddress+unsigned(vAxiALenBytes))-vVirtualAddress) / vAlignment + 1;
      vVirtualLenUnsigned := to_unsigned(vBlockCount*vAlignment-1, AXI_LEN_WIDTH+2) srl DATASTREAM_ALIGNMENT_BIT;

      -- Compute Physical Start Address
      vPhysicalAddr := to_unsigned(vBlockNum*(vMetadata+vAlignment), ADDRESS_WIDTH) + vPhysOffset;
      vPhysicalLen  := to_unsigned(vBlockCount*(vMetadata+vAlignment)-1, AXI_LEN_WIDTH + 2);
      vPhysicalLen  := vPhysicalLen srl DATASTREAM_ALIGNMENT_BIT;

      m_request.block_address <= std_logic_vector(vPhysicalAddr);
      m_request.block_len     <= std_logic_vector(vPhysicalLen(AXI_LEN_WIDTH-1 downto 0));
      m_request.virt_address  <= std_logic_vector(to_unsigned(vVirtualAddress, ADDRESS_WIDTH) + vVirtOffset);
    end if;

  end process translate_request;

end arch_imp;
