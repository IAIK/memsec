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

--! [Slave] Translates AXI read/write address requests to the internal data stream.
--!
--! Additionally, wrapping bursts get decoded. The general solution to support
--! wrapping bursts is to split the wrapping into two incremental bursts.
--! However, when the wrapping burst is small it is more efficient perform the
--! reording within the pipeline before returning the data using the
--! stream_axi_wrap_burst_cache.
--!
--! @TODO clarify why we write into block_address instead of virt_address
entity cpu_request_modifier is
  generic(
    C_S_AXI_ID_WIDTH    : integer   := 12;
    C_S_AXI_ADDR_WIDTH  : integer   := 32;
    C_S_AXI_DATA_WIDTH  : integer   := 32;
    C_S_AXI_AUSER_WIDTH : integer   := 0;
    READ                : std_logic := '0';
    DOUBLE_LINEFILL     : boolean   := false
    );
  port(
    -- Ports of Axi Slave Bus Interface S_AXI
    clk    : in std_logic;
    resetn : in std_logic;

    s_axi_aid     : in  std_logic_vector(C_S_AXI_ID_WIDTH - 1 downto 0);
    s_axi_aaddr   : in  std_logic_vector(C_S_AXI_ADDR_WIDTH - 1 downto 0);
    s_axi_alen    : in  std_logic_vector(7 downto 0);
    s_axi_asize   : in  std_logic_vector(2 downto 0);
    s_axi_aburst  : in  std_logic_vector(1 downto 0);
    s_axi_alock   : in  std_logic;
    s_axi_acache  : in  std_logic_vector(3 downto 0);
    s_axi_aprot   : in  std_logic_vector(2 downto 0);
    s_axi_aqos    : in  std_logic_vector(3 downto 0);
    s_axi_aregion : in  std_logic_vector(3 downto 0);
    s_axi_auser   : in  std_logic_vector(C_S_AXI_AUSER_WIDTH - 1 downto 0);
    s_axi_avalid  : in  std_logic;
    s_axi_aready  : out std_logic;

    m_request       : out StreamType;
    m_request_ready : in  std_logic
    );
end cpu_request_modifier;

architecture behavioral of cpu_request_modifier is

  constant STATE_DEFAULT        : std_logic := '0';
  constant STATE_WRAPPING_BURST : std_logic := '1';
  
  constant AXI_ASIZE_CACHED_BURST_MASK : std_logic_vector(2 downto 0) := std_logic_vector(to_unsigned(log2_ceil(C_S_AXI_DATA_WIDTH/8),3));

  signal StatexDP, StatexDN           : std_logic;
  signal AxiAddressxDP, AxiAddressxDN : std_logic_vector(ADDRESS_WIDTH - 1 downto 0);
  signal AxiLenxDP, AxiLenxDN         : std_logic_vector(s_axi_alen'length - 1 downto 0);
  signal AxiSizexDP, AxiSizexDN       : std_logic_vector(s_axi_asize'length - 1 downto 0);
  signal AxiIdxDP, AxiIdxDN           : std_logic_vector(s_axi_aid'length - 1 downto 0);
  signal AxiCachexDP, AxiCachexDN     : std_logic_vector(s_axi_acache'length - 1 downto 0);
  signal AxiProtxDP, AxiProtxDN       : std_logic_vector(s_axi_aprot'length - 1 downto 0);
  signal AxiLockxDP, AxiLockxDN       : std_logic;
  signal AxiQosxDP, AxiQosxDN         : std_logic_vector(s_axi_aqos'length-1 downto 0);
  signal AxiRegionxDP, AxiRegionxDN   : std_logic_vector(s_axi_aregion'length-1 downto 0);

begin

  regs : process(clk) is
  begin
    if rising_edge(clk) then
      if resetn = '0' then
        StatexDP      <= STATE_DEFAULT;
        AxiLenxDP     <= (others => '0');
        AxiSizexDP    <= (others => '0');
        AxiAddressxDP <= (others => '0');
        AxiIdxDP      <= (others => '0');
        AxiCachexDP   <= (others => '0');
        AxiProtxDP    <= (others => '0');
        AxiLockxDP    <= '0';
        AxiQosxDP     <= (others => '0');
        AxiRegionxDP  <= (others => '0');
      else
        StatexDP      <= StatexDN;
        AxiLenxDP     <= AxiLenxDN;
        AxiSizexDP    <= AxiSizexDN;
        AxiAddressxDP <= AxiAddressxDN;
        AxiIdxDP      <= AxiIdxDN;
        AxiCachexDP   <= AxiCachexDN;
        AxiProtxDP    <= AxiProtxDN;
        AxiLockxDP    <= AxiLockxDN;
        AxiQosxDP     <= AxiQosxDN;
        AxiRegionxDP  <= AxiRegionxDN;
      end if;
    end if;
  end process regs;

  form_request : process(s_axi_aaddr, s_axi_aburst, s_axi_acache, s_axi_aid, s_axi_aprot, s_axi_alock, s_axi_aqos, s_axi_aregion,
                         s_axi_alen, s_axi_asize, s_axi_avalid, m_request_ready,
                         StatexDP, AxiLenxDP, AxiSizexDP, AxiAddressxDP, AxiIdxDP, AxiCachexDP, AxiProtxDP, AxiLockxDP, AxiQosxDP, AxiRegionxDP) is
    variable vAxiALen      : unsigned(s_axi_alen'length + 1 downto 0);
    variable vAxiALenBytes : unsigned(s_axi_alen'length + 1 downto 0);
    variable vAxiASize     : unsigned(s_axi_asize'length - 1 downto 0);
    variable vAxiAAddr     : unsigned(ADDRESS_WIDTH - 1 downto 0);
    variable vVirtAddr     : unsigned(ADDRESS_WIDTH - 1 downto 0);

    variable vWrapBoundary : unsigned(ADDRESS_WIDTH - 1 downto 0);  -- lowest address in a wrapping burst
    variable vTmp          : unsigned(ADDRESS_WIDTH - 1 downto 0);
  begin
    -- Keep old register values
    StatexDN      <= StatexDP;
    AxiLenxDN     <= AxiLenxDP;
    AxiSizexDN    <= AxiSizexDP;
    AxiAddressxDN <= AxiAddressxDP;
    AxiIdxDN      <= AxiIdxDP;
    AxiCachexDN   <= AxiCachexDP;
    AxiProtxDN    <= AxiProtxDP;
    AxiLockxDN    <= AxiLockxDP;
    AxiQosxDN     <= AxiQosxDP;
    AxiRegionxDN  <= AxiRegionxDP;

    -- Original inputs
    vAxiASize := unsigned(s_axi_asize);
    vAxiALen  := unsigned("00" & s_axi_alen);
    vAxiAAddr := unsigned(to_meta_address(s_axi_aaddr));

    if StatexDP = STATE_WRAPPING_BURST then
      vAxiASize := unsigned(AxiSizexDP);
      vAxiALen  := unsigned("00" & AxiLenxDP);
      vAxiAAddr := unsigned(to_meta_address(AxiAddressxDP));
    end if;

    -- Length in bytes, wrap boundary and clean address
    vTmp          := unsigned(dynamic_mask(to_integer(vAxiASize), ADDRESS_WIDTH));
    vAxiAAddr     := (vAxiAAddr) and not(vTmp);
    vAxiALenBytes := (vAxiALen sll to_integer(vAxiASize)) or vTmp(s_axi_alen'length+1 downto 0);

    vTmp                                 := (others => '1');
    vTmp(s_axi_alen'length + 1 downto 0) := not(vAxiALenBytes);
    vWrapBoundary                        := vAxiAAddr and vTmp;
    vVirtAddr                            := vAxiAAddr;

    -- Control slave port
    s_axi_aready <= m_request_ready;

    -- Default outputs
    m_request              <= StreamType_default;
    m_request.read         <= READ;
    m_request.size         <= s_axi_asize;
    m_request.id           <= s_axi_aid;
    m_request.cache        <= s_axi_acache;
    m_request.prot         <= s_axi_aprot;
    m_request.lock         <= s_axi_alock;
    m_request.qos          <= s_axi_aqos;
    m_request.burst        <= s_axi_aburst;
    m_request.region       <= s_axi_aregion;
    m_request.last_request <= '1';
    m_request.valid        <= s_axi_avalid;


    case StatexDP is
      when STATE_DEFAULT =>
        if s_axi_aburst = "01" or (vWrapBoundary = vAxiAAddr) then
          -- Incremental Burst
          m_request.burst <= "01";

        elsif s_axi_aburst = "10" and vAxiALenBytes = "000011111" and s_axi_asize = AXI_ASIZE_CACHED_BURST_MASK then
          -- Optimization: Wrapping burst in cache line size 
          -- Convert into incremental burst and cache later on
          vVirtAddr := vWrapBoundary;

        elsif DOUBLE_LINEFILL = true and s_axi_aburst = "10" and vAxiALenBytes = "000111111" and s_axi_asize = AXI_ASIZE_CACHED_BURST_MASK then
          vVirtAddr := vWrapBoundary;

        elsif s_axi_aburst = "10" then
          -- Wrapping Burst
          -- Issue first incremental burst

          -- Adapt variables
          vTmp          := vAxiAAddr - vWrapBoundary;
          vAxiALenBytes := vAxiALenBytes - vTmp(s_axi_alen'length + 1 downto 0);

          m_request.last_request <= '0';
          m_request.burst        <= "01";

          -- Save requests
          AxiLenxDN     <= s_axi_alen;
          AxiSizexDN    <= s_axi_asize;
          AxiAddressxDN <= s_axi_aaddr;
          AxiIdxDN      <= s_axi_aid;
          AxiCachexDN   <= s_axi_acache;
          AxiProtxDN    <= s_axi_aprot;
          AxiLockxDN    <= s_axi_alock;
          AxiQosxDN     <= s_axi_aqos;
          AxiRegionxDN  <= s_axi_aregion;

          if m_request_ready = '1' then
            StatexDN <= STATE_WRAPPING_BURST;
          end if;
        end if;

      when STATE_WRAPPING_BURST =>
        -- Issue second incremental burst
        vTmp          := vAxiAAddr - vWrapBoundary - 1;
        vAxiALenBytes := vTmp(s_axi_alen'length + 1 downto 0);
        vAxiAAddr     := vWrapBoundary;
        vVirtAddr     := vWrapBoundary;

        m_request.size         <= AxiSizexDP;
        m_request.id           <= AxiIdxDP;
        m_request.cache        <= AxiCachexDP;
        m_request.prot         <= AxiProtxDP;
        m_request.lock         <= AxiLockxDP;
        m_request.burst        <= "01";
        m_request.qos          <= AxiQosxDP;
        m_request.region       <= AxiRegionxDP;
        m_request.last_request <= '1';
        m_request.valid        <= '1';
        s_axi_aready           <= '0';

        if m_request_ready = '1' then
          StatexDN <= STATE_DEFAULT;
        end if;
      when others => null;
    end case;

    vAxiALen                := vAxiALenBytes srl to_integer(vAxiASize);
    m_request.address       <= std_logic_vector(vAxiAAddr);
    m_request.len           <= std_logic_vector(vAxiALen(s_axi_alen'length-1 downto 0));
    m_request.block_address <= std_logic_vector(vVirtAddr);
  end process form_request;

end behavioral;
