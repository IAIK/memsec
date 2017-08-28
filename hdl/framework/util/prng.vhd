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
use work.keccak_package.all;

--! Simple PRNG based on the Keccak permutation.
entity prng is
  generic (
    WIDTH : integer := 128
    );
  port (
    clk    : in std_logic;
    resetn : in std_logic;

    random       : out std_logic_vector(WIDTH-1 downto 0);
    random_valid : out std_logic;
    random_ready : in  std_logic;

    random_init : in std_logic_vector(LANE_BITWIDTH*25-1 downto 0)
    );
end prng;

architecture Behavioral of prng is
  constant RATE          : integer                      := (8*LANE_BITWIDTH)*(LANE_BITWIDTH/8);
  constant STATE_INIT    : std_logic_vector(1 downto 0) := "00";
  constant STATE_PERMUTE : std_logic_vector(1 downto 0) := "01";
  constant STATE_VALID   : std_logic_vector(1 downto 0) := "11";

  signal StatexDP, StatexDN : std_logic_vector(1 downto 0);

  signal KeccakOutxD                                     : std_logic_vector(RATE-1 downto 0);
  signal KeccakInitxS, KeccakSqueezexS, KeccakFinishedxS : std_logic;
  signal KeccakZeroxS                                    : std_logic;

  signal random_internal                              : std_logic_vector(RATE-1 downto 0);
  signal random_internal_valid, random_internal_ready : std_logic;
begin

  keccak : entity work.keccak_parallel
    generic map (
      UNROLLED_ROUNDS => 16/LANE_BITWIDTH,
      RATE            => RATE,
      ROUNDS          => 2*log2ceil(LANE_BITWIDTH)+12
      )
    port map (
      ClkxCI   => clk,
      RstxRBI  => resetn,
      BlockxDO => KeccakOutxD,
      BlockxDI => (others => '0'),
      IVxDI    => random_init,

      StartInitxSI     => KeccakInitxS,
      StartAbsorbxSI   => '0',
      StartSqueezexSI  => KeccakSqueezexS,
      PermutateDonexSO => KeccakFinishedxS
      );

  random_internal <= KeccakOutxD;
  KeccakZeroxS    <= '1' when KeccakOutxD = zeros(KeccakOutxD'length) else '0';

  comb : process(KeccakFinishedxS, random_internal_ready, StatexDP, KeccakZeroxS)
  begin
    StatexDN <= StatexDP;

    KeccakInitxS    <= '0';
    KeccakSqueezexS <= '0';

    random_internal_valid <= '0';

    case StatexDP is
      when STATE_INIT =>
        KeccakInitxS <= '1';
        StatexDN     <= STATE_PERMUTE;
      when STATE_PERMUTE =>
        random_internal_valid <= KeccakFinishedxS and not(KeccakZeroxS);
        KeccakSqueezexS       <= random_internal_ready;
        if KeccakFinishedxS = '1' then
          if random_internal_ready = '1' or KeccakZeroxS = '1' then
            KeccakSqueezexS <= '1';
          else
            StatexDN <= STATE_VALID;
          end if;
        end if;
      when STATE_VALID =>
        random_internal_valid <= '1';
        if random_internal_ready = '1' then
          StatexDN        <= STATE_PERMUTE;
          KeccakSqueezexS <= '1';
        end if;
      when others =>
    end case;

  end process comb;

  output_conversion : entity work.rate_converter
    generic map(
      IN_DATA_WIDTH  => RATE,
      OUT_DATA_WIDTH => WIDTH,
      REGISTERED     => false
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_field_offset => (others => '0'),
      in_field_len    => (others => '1'),

      in_last  => '0',
      in_data  => random_internal,
      in_valid => random_internal_valid,
      in_ready => random_internal_ready,

      out_data         => random,
      out_last         => open,
      out_field_offset => open,
      out_field_len    => open,
      out_valid        => random_valid,
      out_ready        => random_ready
      );

  regs : process(clk) is
  begin
    if rising_edge(clk) then
      if resetn = '0' then
        StatexDP <= STATE_INIT;
      else
        StatexDP <= StatexDN;
      end if;
    end if;
  end process regs;
end Behavioral;
