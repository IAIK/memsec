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

library std;
use std.textio.all;


package tb_utils_pkg is
  type AxiMemoryType is array (0 to 511) of std_logic_vector(32-1 downto 0);
  -- Converts std_logic_vector to hex string
  function to_hstring (value          :    std_logic_vector) return string;
  -- Writes  success message that testbench succeeds
  procedure write_tb_success(filename : in string);
  -- Writes  error message that testbench failed
  procedure write_tb_fail(filename    : in string);
end package;

package body tb_utils_pkg is

  function to_hstring (value : std_logic_vector) return string is
    constant ne     : integer := (value'length+3)/4;
    variable pad    : std_logic_vector(0 to (ne*4 - value'length) - 1);
    variable ivalue : std_logic_vector(0 to ne*4 - 1);
    variable result : string(1 to ne);
    variable quad   : std_logic_vector(0 to 3);
  begin
    if value'length < 1 then
      return "Error";
    else
      if value (value'left) = 'Z' then
        pad := (others => 'Z');
      else
        pad := (others => '0');
      end if;
      ivalue := pad & value;
      for i in 0 to ne-1 loop
        quad := To_X01Z(ivalue(4*i to 4*i+3));
        case quad is
          when x"0"   => result(i+1) := '0';
          when x"1"   => result(i+1) := '1';
          when x"2"   => result(i+1) := '2';
          when x"3"   => result(i+1) := '3';
          when x"4"   => result(i+1) := '4';
          when x"5"   => result(i+1) := '5';
          when x"6"   => result(i+1) := '6';
          when x"7"   => result(i+1) := '7';
          when x"8"   => result(i+1) := '8';
          when x"9"   => result(i+1) := '9';
          when x"A"   => result(i+1) := 'A';
          when x"B"   => result(i+1) := 'B';
          when x"C"   => result(i+1) := 'C';
          when x"D"   => result(i+1) := 'D';
          when x"E"   => result(i+1) := 'E';
          when x"F"   => result(i+1) := 'F';
          when "ZZZZ" => result(i+1) := 'Z';
          when others => result(i+1) := 'X';
        end case;
      end loop;
      return result;
    end if;
  end function to_hstring;


  procedure write_tb_success(filename : in string) is
    file outfile     : text is out filename & "_log.txt";
    variable outline : line;
  begin
    write(outline, 1);
    writeline(outfile, outline);
  end procedure;


  procedure write_tb_fail(filename : in string) is
    file outfile     : text is out filename & "_log.txt";
    variable outline : line;
  begin
    write(outline, 0);
    writeline(outfile, outline);
  end procedure;

end package body;
