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

--! Synchronization block which dispatches an input to one of the available outputs.
entity valid_dispatcher is
  generic (
    WIDTH : integer := 2
    );
  port (
    clk    : in std_logic;
    resetn : in std_logic;

    in_valid : in  std_logic;
    in_ready : out std_logic;

    out_request : in  std_logic_vector(WIDTH-1 downto 0);
    out_valid   : out std_logic_vector(WIDTH-1 downto 0);
    out_ready   : in  std_logic_vector(WIDTH-1 downto 0)
    );
end valid_dispatcher;

architecture Behavioral of valid_dispatcher is
  signal ActiveSignalxDP, ActiveSignalxDN : std_logic_vector(log2_ceil(WIDTH)-1 downto 0);
begin

  comb : process(out_request, out_ready, in_valid, ActiveSignalxDP)
    variable vRequest       : std_logic;
    variable vRequestNo     : integer;
    variable vActiveRequest : integer;
    variable i              : integer;
    variable vOutRequests   : std_logic_vector(out_request'range);
  begin
    ActiveSignalxDN <= ActiveSignalxDP;

    in_ready  <= '0';
    out_valid <= (others => '0');

    vActiveRequest := to_integer(unsigned(ActiveSignalxDP));
    vOutRequests   := std_logic_vector(unsigned(out_request) rol vActiveRequest);
    vRequest       := '0';
    vRequestNo     := 0;
    for i in 0 to WIDTH-1 loop
      if vOutRequests(i) = '1' then
        vRequest   := '1';
        vRequestNo := i;
      end if;
    end loop;
    vRequestNo := vRequestNo + vActiveRequest;
    if vRequestNo >= WIDTH then
      vRequestNo := vRequestNo-WIDTH;
    end if;

    if vRequest = '1' then
      out_valid(vRequestNo) <= in_valid;
      in_ready              <= out_ready(vRequestNo);
      if out_ready(vRequestNo) = '1' then
        if vRequestNo = WIDTH-1 then
          ActiveSignalxDN <= (others => '0');
        else
          ActiveSignalxDN <= std_logic_vector(to_unsigned(vRequestNo+1, log2_ceil(WIDTH)));
        end if;
      end if;
    end if;

  end process comb;

  regs : process(clk) is
  begin
    if rising_edge(clk) then
      if resetn = '0' then
        ActiveSignalxDP <= (others => '0');
      else
        ActiveSignalxDP <= ActiveSignalxDN;
      end if;
    end if;
  end process regs;

end Behavioral;
