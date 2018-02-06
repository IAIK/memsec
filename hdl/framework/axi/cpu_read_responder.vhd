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

--! [Slave] Translates the internal data stream into beats on the AXI read channel.
--!
--! The stream is expected to be in correct sequence and to contain only data
--! beats which are relevant for the receiver. When a narrow transfers has been
--! requested, each data block from the stream is placed on the AXI read channel
--! for the correct number of transfer cycles.
entity cpu_read_responder is
  generic(
    C_S_AXI_ID_WIDTH    : integer := 12;
    C_S_AXI_DATA_WIDTH  : integer := 32;
    C_S_AXI_RUSER_WIDTH : integer := 0
    );
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    s_axi_rid    : out std_logic_vector(C_S_AXI_ID_WIDTH - 1 downto 0);
    s_axi_rdata  : out std_logic_vector(C_S_AXI_DATA_WIDTH - 1 downto 0);
    s_axi_rresp  : out std_logic_vector(1 downto 0);
    s_axi_rlast  : out std_logic;
    s_axi_ruser  : out std_logic_vector(C_S_AXI_RUSER_WIDTH - 1 downto 0);
    s_axi_rvalid : out std_logic;
    s_axi_rready : in  std_logic;

    s_request       : in  StreamType;
    s_request_ready : out std_logic
    );
end cpu_read_responder;

architecture arch_imp of cpu_read_responder is
  constant BUS_BYTE_FIELD_ADDR_WIDTH : integer := log2_ceil(C_S_AXI_DATA_WIDTH/8);

  signal BlockCounterxDP, BlockCounterxDN : std_logic_vector(s_request.len'length downto 0);

  type tASizeToMaskLUT is array (0 to 2**2 - 1) of std_logic_vector(2 downto 0);
  constant ASIZE_MASKING_LUT : tASizeToMaskLUT := (
    0 => "111",
    1 => "110",
    2 => "100",
    3 => "000");

begin

  regs : process(clk) is
  begin
    if rising_edge(clk) then
      if resetn = '0' then
        BlockCounterxDP <= (others => '0');
      else
        BlockCounterxDP <= BlockCounterxDN;
      end if;
    end if;
  end process regs;

  -- read back channel
  collapse_logic : process(BlockCounterxDP, s_axi_rready, s_request) is
    variable vAddrOffset : std_logic_vector(BlockCounterxDP'length-1 downto 0);
    variable vCurBlock   : unsigned(BlockCounterxDP'length-1 downto 0);
    variable vSizeInt    : integer;
    variable vSize       : unsigned(BlockCounterxDP'length-1 downto 0);
    variable vLen        : std_logic_vector(BlockCounterxDP'length-1 downto 0);
  begin
    -- Default outputs
    BlockCounterxDN <= BlockCounterxDP;
    s_request_ready <= '0';

    s_axi_rid    <= s_request.id;
    s_axi_ruser  <= (others => '0');
    s_axi_rdata  <= s_request.data(C_S_AXI_DATA_WIDTH-1 downto 0);
    s_axi_rvalid <= '0';
    s_axi_rlast  <= '0';
    s_axi_rresp  <= s_request.error & '0';

    if s_request.valid = '1' then
      s_request_ready <= '0';
      s_axi_rvalid    <= '1';

      vSizeInt    := to_integer(unsigned(s_request.size));
      vSize       := shift_left((vSize'left downto 1                            => '0') & '1', vSizeInt);
      vLen        := (vLen'length-1 downto s_request.len'length                 => '0') & s_request.len;
      vLen        := std_logic_vector(shift_left(unsigned(vLen), to_integer(unsigned(s_request.size))));
      vAddrOffset := (BlockCounterxDP'length-1 downto BUS_BYTE_FIELD_ADDR_WIDTH => '0') & (s_request.address(BUS_BYTE_FIELD_ADDR_WIDTH-1 downto 0) and ASIZE_MASKING_LUT(to_integer(unsigned(s_request.size)))(BUS_BYTE_FIELD_ADDR_WIDTH-1 downto 0));
      vCurBlock   := unsigned(BlockCounterxDP) + unsigned(vAddrOffset);

      if s_axi_rready = '1' then
        -- Increase counter and current address depending on size
        BlockCounterxDN <= std_logic_vector(unsigned(BlockCounterxDP) + vSize(BlockCounterxDP'length-1 downto 0));

        -- Last subblock before data stream width is reached
        if vSizeInt > 0 and vSizeInt < ASIZE_MASKING_LUT'length then
          if std_logic_vector(vCurBlock(BUS_BYTE_FIELD_ADDR_WIDTH-1 downto 0)) = ASIZE_MASKING_LUT(vSizeInt)(BUS_BYTE_FIELD_ADDR_WIDTH-1 downto 0) then 
            s_request_ready <= '1'; 
          end if;
        end if;

        -- Last block within transfer
        if (BlockCounterxDP = vLen) then
          s_request_ready <= '1';
          s_axi_rlast     <= s_request.last_request;
          BlockCounterxDN <= (others => '0');
        end if;
      end if;
    end if;
  end process collapse_logic;

end arch_imp;
