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

--! Deserializes the AXI-4 write channel into a sequence of aligned blocks.
--!
--! AXI-4 supports various optimizations on the data write channel like write
--! strobes, unaligned transfers, and narrow transfers. Additionally, the bus
--! width is configurable. This module decodes the write channel and outputs
--! a sequence of aligned blocks with strobes and block addresses which removes
--! removes narrow transfers. The width of the output blocks is configurable and
--! can be equal or a multiple of the input AXI write channel width.
--! The address information is extracted from the StreamType interface which
--! is expected to provide the information from the AXI write address channel.
--! Per request, only one beat (i.e., no data) is expected.
entity axi_deserialization is
  generic(
    ADDR_WIDTH     : integer := 32;
    IN_DATA_WIDTH  : integer := 32;
    OUT_DATA_WIDTH : integer := 32;  -- has to be (1,2,4,8,...) * IN_DATA_WIDTH

    -- use the address to make sure that only valid strobes are generated
    ENFORCE_STROBES : boolean := false;
    REGISTERED      : boolean := true
    );
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    wdata  : in  std_logic_vector(IN_DATA_WIDTH - 1 downto 0);
    wstrb  : in  std_logic_vector((IN_DATA_WIDTH / 8) - 1 downto 0);
    wlast  : in  std_logic;
    wvalid : in  std_logic;
    wready : out std_logic;

    s_request       : in  StreamType;
    s_request_ready : out std_logic;

    m_data         : out BlockStreamType;
    m_data_address : out AddressType;
    m_data_ready   : in  std_logic
    );
end axi_deserialization;

architecture arch_imp of axi_deserialization is
  constant IN_STROBE_WIDTH      : integer := IN_DATA_WIDTH/8;
  constant OUT_STROBE_WIDTH     : integer := OUT_DATA_WIDTH/8;
  constant IN_FIELD_ADDR_WIDTH  : integer := log2_ceil(IN_DATA_WIDTH/8);
  constant OUT_FIELD_ADDR_WIDTH : integer := log2_ceil(OUT_DATA_WIDTH/8);

  signal bus_beatxDP, bus_beatxDN                   : std_logic_vector(AXI_LEN_WIDTH-1 downto 0);
  signal bus_block_beatxDP, bus_block_beatxDN       : std_logic_vector(AXI_LEN_WIDTH-1 downto 0);
  signal bus_block_dataxDP, bus_block_dataxDN       : std_logic_vector(IN_DATA_WIDTH - 1 downto 0);
  signal bus_block_strobesxDP, bus_block_strobesxDN : std_logic_vector(IN_STROBE_WIDTH - 1 downto 0);

  -- helper signals for connecting the individual processes
  signal bus_beat_address : std_logic_vector(ADDR_WIDTH - 1 downto 0);
  signal bus_strobes      : std_logic_vector(IN_STROBE_WIDTH - 1 downto 0);
  signal bus_field_addr   : std_logic_vector(IN_FIELD_ADDR_WIDTH - 1 downto 0);
  signal bus_last_field   : std_logic_vector(IN_FIELD_ADDR_WIDTH - 1 downto 0);

  -- output signals from the deserialization to IN_DATA_WIDTH sized bus blocks
  signal bus_block_address : std_logic_vector(ADDR_WIDTH - 1 downto 0);
  signal bus_block_data    : std_logic_vector(IN_DATA_WIDTH - 1 downto 0);
  signal bus_block_strobes : std_logic_vector(IN_STROBE_WIDTH - 1 downto 0);
  signal bus_block_valid   : std_logic;
  signal bus_block_ready   : std_logic;

  signal data_block_address : std_logic_vector(ADDR_WIDTH - 1 downto 0);

  signal address : std_logic_vector(ADDR_WIDTH - 1 downto 0);
  signal data    : std_logic_vector(OUT_DATA_WIDTH - 1 downto 0);
  signal strobes : std_logic_vector(OUT_DATA_WIDTH/8 - 1 downto 0);
  signal last    : std_logic;
  signal valid   : std_logic;

  function size_to_strobemask (
    SIZE : integer range 0 to 7)
    return std_logic_vector is
    variable res : std_logic_vector(127 downto 0);
  begin  -- size_to_strobemask
    case SIZE is
      when 0 => res := mask(1, 128);
      when 1 => res := mask(2, 128);
      when 2 => res := mask(4, 128);
      when 3 => res := mask(8, 128);
      when 4 => res := mask(16, 128);
      when 5 => res := mask(32, 128);
      when 6 => res := mask(64, 128);
      when 7 => res := ones(128);
    end case;
    return res;
  end size_to_strobemask;

begin

  regs : process(clk) is
  begin
    if rising_edge(clk) then
      if resetn = '0' then
        bus_beatxDP          <= (others => '0');
        bus_block_beatxDP    <= (others => '0');
        bus_block_dataxDP    <= (others => '0');
        bus_block_strobesxDP <= (others => '0');
      else
        bus_beatxDP          <= bus_beatxDN;
        bus_block_beatxDP    <= bus_block_beatxDN;
        bus_block_dataxDP    <= bus_block_dataxDN;
        bus_block_strobesxDP <= bus_block_strobesxDN;
      end if;
    end if;
  end process regs;

  -- calculates the addresses of the current bus block, output block, and the bus beat
  p_address : process(bus_beatxDP, bus_block_beatxDP, s_request) is
    variable transfer_size                  : integer range 0 to 7;
    variable transfer_aligned_start_address : unsigned(ADDRESS_WIDTH-1 downto 0);
    variable block_aligned_start_address    : unsigned(ADDRESS_WIDTH-1 downto 0);
    variable block_address                  : unsigned(ADDRESS_WIDTH-1 downto 0);
  begin
    bus_block_address  <= (others => '0');
    data_block_address <= (others => '0');
    bus_beat_address   <= (others => '0');

    if s_request.valid = '1' then
      transfer_size                  := to_integer(unsigned(s_request.size));
      transfer_aligned_start_address := unsigned(s_request.address and not(dynamic_mask(transfer_size, ADDRESS_WIDTH)));
      block_aligned_start_address    := unsigned(s_request.address and not(mask(IN_FIELD_ADDR_WIDTH, ADDRESS_WIDTH)));

      block_address      := block_aligned_start_address + unsigned(bus_block_beatxDP) * IN_DATA_WIDTH/8;
      bus_block_address  <= std_logic_vector(block_address);
      data_block_address <= std_logic_vector(block_address) and not(mask(OUT_FIELD_ADDR_WIDTH, ADDRESS_WIDTH));

      -- The first bus beat has the address from the original request and is
      -- possibly unaligned. All subsequent beats have transfer size alignment.
      bus_beat_address <= s_request.address;
      if unsigned(bus_beatxDP) /= 0 then
        bus_beat_address <= std_logic_vector(transfer_aligned_start_address + unsigned(bus_beatxDP) * 2**transfer_size);
      end if;
    end if;
  end process p_address;

  -- generates bus strobes and the current field address from the bus beat address
  p_bus_strobes : process(bus_beat_address, bus_beatxDP, s_request, wstrb,
                          wvalid) is
    variable address_strobes : std_logic_vector(IN_STROBE_WIDTH - 1 downto 0);
    variable address_mask    : AddressType;
    variable transfer_size   : integer range 0 to 7;
    variable offset          : integer range 0 to IN_DATA_WIDTH/8 - 1;
    variable sub_field       : integer range 0 to 2**IN_FIELD_ADDR_WIDTH-1;
  begin
    bus_strobes    <= (others => '0');
    bus_field_addr <= (others => '0');
    bus_last_field <= (others => '0');

    address_strobes := (others => '0');
    address_mask    := (others => '0');
    transfer_size   := 0;
    offset          := 0;
    sub_field       := 0;

    if wvalid = '1' and s_request.valid = '1' then
      transfer_size := to_integer(unsigned(s_request.size));

      -- Generate strobes with correct width for aligned bursts.
      -- The width here only takes narrow bursts into account but ignores potential misalignment.
      -- Additionally, the real alignment of narrow strobes is ignored here.
      address_strobes := size_to_strobemask(transfer_size)(IN_STROBE_WIDTH - 1 downto 0);

      -- Update the strobes for unaligned accesses.
      -- Unalignment only is relevant in the first beat. All subsequent beats are aligned.
      -- (requests with size 0 (=1 byte) are always aligned)
      if unsigned(bus_beatxDP) = 0 and transfer_size > 0 then
        address_mask    := dynamic_mask(transfer_size, ADDRESS_WIDTH);
        offset          := to_integer(unsigned(s_request.address and address_mask));
        address_strobes := address_strobes and not(dynamic_mask(offset, IN_STROBE_WIDTH));
      end if;

      -- shift strobes to the correct alignment in the case of narrow transfers
      if transfer_size < log2_ceil(IN_DATA_WIDTH/8) then
        address_mask    := mask(IN_FIELD_ADDR_WIDTH, ADDRESS_WIDTH);
        sub_field       := to_integer(unsigned(bus_beat_address and address_mask) srl transfer_size);
        address_strobes := std_logic_vector(unsigned(address_strobes) sll (sub_field*2**transfer_size));
      end if;

      if ENFORCE_STROBES = true then
        bus_strobes <= address_strobes and wstrb;
      else
        bus_strobes <= wstrb;
      end if;
      bus_field_addr <= std_logic_vector(to_unsigned(sub_field, IN_FIELD_ADDR_WIDTH));
      bus_last_field <= std_logic_vector(to_unsigned(2**(IN_FIELD_ADDR_WIDTH-transfer_size)-1, IN_FIELD_ADDR_WIDTH));
    end if;
  end process p_bus_strobes;

  p_deserialization : process(bus_beatxDP, bus_block_beatxDP,
                              bus_block_dataxDP, bus_block_ready,
                              bus_block_strobesxDP, bus_block_valid,
                              bus_field_addr, bus_last_field, bus_strobes,
                              s_request, wdata, wlast, wvalid) is
    variable combined_data    : std_logic_vector(IN_DATA_WIDTH - 1 downto 0);
    variable combined_strobes : std_logic_vector(IN_STROBE_WIDTH - 1 downto 0);
  begin
    bus_block_dataxDN    <= bus_block_dataxDP;
    bus_block_strobesxDN <= bus_block_strobesxDP;
    bus_beatxDN          <= bus_beatxDP;
    bus_block_beatxDN    <= bus_block_beatxDP;

    wready            <= '0';
    s_request_ready   <= '0';
    bus_block_data    <= (others => '0');
    bus_block_strobes <= (others => '0');
    bus_block_valid   <= '0';

    combined_data    := wdata;  -- use the full signal to get nice sensitivity lists from emacs
    combined_strobes := (others => '0');

    -- skip non data requests which should not occure anyway
    if s_request.valid = '1' and s_request.request_type /= REQ_TYPE_DATA then
      s_request_ready <= '1';
    end if;

    -- react on the ready from the interface
    if bus_block_valid = '1' and bus_block_ready = '1' then
      bus_block_dataxDN    <= (others => '0');
      bus_block_strobesxDN <= (others => '0');
      wready               <= '1';
      s_request_ready      <= wlast;
      if wlast = '0' then
        bus_beatxDN       <= std_logic_vector(unsigned(bus_beatxDP)+1);
        bus_block_beatxDN <= std_logic_vector(unsigned(bus_block_beatxDP)+1);
      else
        bus_beatxDN       <= (others => '0');
        bus_block_beatxDN <= (others => '0');
      end if;
    end if;

    if wvalid = '1' and s_request.valid = '1' and s_request.request_type = REQ_TYPE_DATA then
      -- There is data from the bus which should be processed
      -- Combine the data and the strobes with the data from the register.
      combined_data := bus_block_dataxDP;
      for I in 0 to IN_STROBE_WIDTH - 1 loop
        if bus_strobes(I) = '1' then
          combined_data(I*8+7 downto I*8) := wdata(I*8+7 downto I*8);
        end if;
      end loop;

      combined_strobes := bus_block_strobesxDP or bus_strobes;

      -- check if enough data the output block is full
      if unsigned(bus_field_addr) < unsigned(bus_last_field) and wlast = '0' then
        -- not enough data present
        -- copy the data into the register and wait for more
        wready               <= '1';
        bus_beatxDN          <= std_logic_vector(unsigned(bus_beatxDP)+1);
        bus_block_dataxDN    <= combined_data;
        bus_block_strobesxDN <= combined_strobes;
      else
        -- with the new data the block is full
        -- forward it to the output and wait for the ready
        bus_block_data    <= combined_data;
        bus_block_strobes <= combined_strobes;
        bus_block_valid   <= '1';
      end if;
    end if;
  end process p_deserialization;

  addr_reg : entity work.register_stage
    generic map(
      WIDTH      => ADDR_WIDTH,
      REGISTERED => REGISTERED
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_data  => data_block_address,
      in_valid => bus_block_ready,
      in_ready => open,  -- data_deserialization handles the synchronization

      out_data  => address,
      out_valid => open,  -- data_deserialization handles the synchronization
      out_ready => m_data_ready
      );

  data_deserialization : entity work.deserialization
    generic map(
      IN_DATA_WIDTH  => IN_DATA_WIDTH,
      OUT_DATA_WIDTH => OUT_DATA_WIDTH,
      REGISTERED     => REGISTERED
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_field_start_offset => bus_block_address(OUT_FIELD_ADDR_WIDTH - 1 downto IN_FIELD_ADDR_WIDTH),

      in_last  => wlast,
      in_data  => bus_block_data,
      in_valid => bus_block_valid,
      in_ready => bus_block_ready,

      out_data         => data,
      out_field_offset => open,
      out_field_len    => open,
      out_last         => last,
      out_valid        => valid,
      out_ready        => m_data_ready
      );

  strobe_deserialization : entity work.deserialization
    generic map(
      IN_DATA_WIDTH  => IN_STROBE_WIDTH,
      OUT_DATA_WIDTH => OUT_STROBE_WIDTH,
      REGISTERED     => REGISTERED
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_field_start_offset => bus_block_address(OUT_FIELD_ADDR_WIDTH - 1 downto IN_FIELD_ADDR_WIDTH),

      in_last  => wlast,
      in_data  => bus_block_strobes,
      in_valid => bus_block_valid,
      in_ready => open,  -- data_deserialization handles the synchronization

      out_data         => strobes,
      out_field_offset => open,
      out_field_len    => open,
      out_last         => open,  -- data_deserialization handles the synchronization
      out_valid        => open,  -- data_deserialization handles the synchronization
      out_ready        => m_data_ready
      );

  p_output : process(address, data, last, strobes, valid) is
  begin
    m_data         <= BlockStreamType_default;
    m_data_address <= (others => '0');

    if valid = '1' then
      m_data_address <= address;
      m_data.data    <= data;
      m_data.strobes <= strobes;
      m_data.last    <= last;
      m_data.valid   <= '1';
    end if;
  end process p_output;
end arch_imp;
