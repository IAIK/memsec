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

entity xts_tweak_mul is
  generic(
    WIDTH : integer := 64
    );
  port(
    in_tweak  : in  std_logic_vector(WIDTH - 1 downto 0);
    out_tweak : out std_logic_vector(WIDTH - 1 downto 0)
    );
end xts_tweak_mul;

architecture Behavioral of xts_tweak_mul is
-- GCM polynomials: (http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf)
--
-- 128-bit: 1 + a + a^2 + a^7 + a^128  => x"87"
--  64-bit: 1 + a + a^3 + a^4 + a^64   => x"1B"
--
  signal multiplied : std_logic_vector(WIDTH - 1 downto 0);

  function polynomial (
    constant SIZE : natural)
    return std_logic_vector is
    variable res : std_logic_vector(WIDTH - 1 downto 0);
  begin  -- polynomial
    res := (others => '0');
    case SIZE is
      when 64     => res(7 downto 0) := x"1B";
      when 128    => res(7 downto 0) := x"87";
      when others => assert false report "WIDTH is not supported" severity error;
    end case;
    return res;
  end polynomial;
begin
  multiplied <= in_tweak(WIDTH - 2 downto 0) & '0';
  out_tweak  <= multiplied xor polynomial(WIDTH) when in_tweak(WIDTH-1) = '1' else multiplied;
end Behavioral;
