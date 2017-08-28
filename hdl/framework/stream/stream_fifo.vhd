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

--! FIFO for the internal stream type.
entity stream_fifo is
  generic(
    WIDTH    : integer := 32;
    ELEMENTS : integer := 1
    );
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    in_data  : in  StreamType;
    in_valid : in  std_logic;
    in_ready : out std_logic;

    out_data  : out StreamType;
    out_valid : out std_logic;
    out_ready : in  std_logic
    );
end stream_fifo;

architecture arch_imp of stream_fifo is
  type FifoArray is array(integer range <>) of StreamType;
  signal FifoxDP, FifoxDN : FifoArray(ELEMENTS-1 downto 0);

  signal IndexxDP, IndexxDN : std_logic_vector(log2_ceil(ELEMENTS) downto 0);

begin
  regs : process(clk) is
  begin
    if rising_edge(clk) then
      if resetn = '0' then
        FifoxDP  <= (others => StreamType_default);
        IndexxDP <= (others => '0');
      else
        FifoxDP  <= FifoxDN;
        IndexxDP <= IndexxDN;
      end if;
    end if;
  end process regs;

  comb : process(in_data, in_valid, out_ready, FifoxDP, IndexxDP) is
    variable vIndex : integer range 0 to ELEMENTS;
  begin
    FifoxDN  <= FifoxDP;
    IndexxDN <= IndexxDP;

    in_ready  <= '0';
    out_valid <= '0';
    out_data  <= FifoxDP(0);

    vIndex := to_integer(unsigned(IndexxDP));
    -- output
    if vIndex > 0 then
      out_valid <= '1';

      if out_ready = '1' then
        vIndex                       := vIndex - 1;
        FifoxDN(ELEMENTS-2 downto 0) <= FifoxDP(ELEMENTS-1 downto 1);
        FifoxDN(ELEMENTS-1)          <= StreamType_default;
      end if;
    end if;

    if in_valid = '1' and vIndex < ELEMENTS then
      FifoxDN(vIndex) <= in_data;
      vIndex          := vIndex + 1;
      in_ready        <= '1';
    end if;

    IndexxDN <= std_logic_vector(to_unsigned(vIndex, IndexxDP'length));
  end process comb;
end arch_imp;
