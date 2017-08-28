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

entity xts_tweak_generator is
  generic(
    WIDTH             : integer := 64;
    BLOCK_INDEX_WIDTH : integer := 2
    );
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    in_tweak   : in  std_logic_vector(WIDTH - 1 downto 0);
    in_blockNr : in  std_logic_vector(BLOCK_INDEX_WIDTH - 1 downto 0);  -- the index of the in block
    in_mulNr   : in  std_logic_vector(BLOCK_INDEX_WIDTH - 1 downto 0);  -- the number of initial multiplications
    in_valid   : in  std_logic;  -- new tweak and block index are valid and should be used
    in_ready   : out std_logic;

    out_tweak : out std_logic_vector(WIDTH - 1 downto 0);
    out_valid : out std_logic;
    out_ready : in  std_logic  -- the outputed tweak has been processed and the next one can be computed
    );
end xts_tweak_generator;

architecture Behavioral of xts_tweak_generator is
  constant BLOCK_INDEX_MAX : integer := 2**BLOCK_INDEX_WIDTH-1;

  signal tweakxDP, tweakxDN           : std_logic_vector(WIDTH - 1 downto 0);
  signal mulxDP, mulxDN               : std_logic_vector(BLOCK_INDEX_WIDTH - 1 downto 0);  -- number of multiplications till valid
  signal blockTotalxDP, blockTotalxDN : std_logic_vector(BLOCK_INDEX_WIDTH - 1 downto 0);
  signal validxDP, validxDN           : std_logic;

  -- helper signals
  signal tweak_calc_in, tweak_calc_out : std_logic_vector(WIDTH - 1 downto 0);
  signal in_readyxS                    : std_logic;
  signal out_validxS                   : std_logic;

begin

  tweak_mul : entity work.xts_tweak_mul
    generic map(
      WIDTH => WIDTH
      )
    port map (
      in_tweak  => tweak_calc_in,
      out_tweak => tweak_calc_out
      );

  regs : process(clk) is
  begin
    if rising_edge(clk) then
      if resetn = '0' then
        tweakxDP      <= (others => '0');
        mulxDP        <= (others => '0');
        blockTotalxDP <= (others => '0');
        validxDP      <= '0';
      else
        tweakxDP      <= tweakxDN;
        mulxDP        <= mulxDN;
        blockTotalxDP <= blockTotalxDN;
        validxDP      <= validxDN;
      end if;
    end if;
  end process regs;

  control : process(mulxDP, in_blockNr, in_tweak, in_valid, out_ready, validxDP,
                    tweak_calc_out, tweakxDP, blockTotalxDP, in_blockNr, in_mulNr) is
  begin
    -- hold the values in the registers by default
    tweakxDN      <= tweakxDP;
    mulxDN        <= mulxDP;
    blockTotalxDN <= blockTotalxDP;
    validxDN      <= validxDP;

    in_readyxS <= '0';

    -- calculate the next tweak from the register and output it by default
    tweak_calc_in <= tweakxDP;
    out_tweak     <= tweakxDP;

    -- start a new tweak calculation by loading the input data into the registers
    if in_valid = '1' then
      tweakxDN      <= in_tweak;
      mulxDN        <= in_mulNr;
      in_readyxS    <= '1';
      blockTotalxDN <= in_blockNr;
      validxDN      <= '0';
      if to_integer(unsigned(in_mulNr)) = 0 then
        validxDN <= '1';
      end if;
    end if;

    -- loop until the first tweak is generated
    if to_integer(unsigned(mulxDP)) /= 0 then
      tweakxDN      <= tweak_calc_out;
      mulxDN        <= std_logic_vector(unsigned(mulxDP) - 1);
      blockTotalxDN <= std_logic_vector(unsigned(blockTotalxDP) + 1);
      if to_integer(unsigned(mulxDP)) = 1 then
        validxDN <= '1';
      end if;
    end if;

    -- update the tweak when it has been in_read
    if validxDP = '1' and out_ready = '1' then
      tweakxDN      <= tweak_calc_out;
      blockTotalxDN <= std_logic_vector(unsigned(blockTotalxDP) + 1);
      if to_integer(unsigned(blockTotalxDP)) = BLOCK_INDEX_MAX then
        validxDN <= '0';
      end if;
    end if;
  end process control;

  out_valid <= validxDP;
  in_ready  <= in_readyxS;

end Behavioral;

