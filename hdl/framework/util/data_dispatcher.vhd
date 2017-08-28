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

--! Synchronization block which dispatches an input block to one of the available outputs.
entity data_dispatcher is
  generic (
    DISPATCH_WIDTH : integer := 2;
    DATA_WIDTH     : integer := 128;
    REGISTERED     : boolean := false
    );
  port (
    clk    : in std_logic;
    resetn : in std_logic;

    in_data  : in  std_logic_vector(DATA_WIDTH-1 downto 0);
    in_valid : in  std_logic;
    in_ready : out std_logic;

    out_data    : out std_logic_vector(DATA_WIDTH*DISPATCH_WIDTH-1 downto 0);
    out_request : in  std_logic_vector(DISPATCH_WIDTH-1 downto 0);
    out_valid   : out std_logic_vector(DISPATCH_WIDTH-1 downto 0);
    out_ready   : in  std_logic_vector(DISPATCH_WIDTH-1 downto 0)
    );
end data_dispatcher;

architecture Behavioral of data_dispatcher is
  signal valid_reg   : std_logic_vector(DISPATCH_WIDTH-1 downto 0);
  signal ready_reg   : std_logic_vector(DISPATCH_WIDTH-1 downto 0);
  signal request_reg : std_logic_vector(DISPATCH_WIDTH-1 downto 0);
  signal valid_out   : std_logic_vector(DISPATCH_WIDTH-1 downto 0);
begin

  valid_dispatch : entity work.valid_dispatcher
    generic map(
      WIDTH => DISPATCH_WIDTH
      )
    port map(
      clk    => clk,
      resetn => resetn,

      in_valid => in_valid,
      in_ready => in_ready,

      out_request => request_reg,
      out_valid   => valid_reg,
      out_ready   => ready_reg
      );

  registers : for i in 0 to DISPATCH_WIDTH-1 generate
    reg : entity work.register_stage
      generic map(
        WIDTH        => DATA_WIDTH,
        READY_BYPASS => true,
        REGISTERED   => REGISTERED
        )
      port map(
        clk    => clk,
        resetn => resetn,

        in_data  => in_data,
        in_valid => valid_reg(i),
        in_ready => ready_reg(i),

        out_data  => out_data((i+1)*DATA_WIDTH-1 downto i*DATA_WIDTH),
        out_valid => valid_out(i),
        out_ready => out_ready(i)
        );
  end generate registers;

  comb_reg : if REGISTERED generate
    request_reg <= not(valid_out);
    out_valid   <= valid_out;
  end generate comb_reg;

  comb_noreg : if not(REGISTERED) generate
    request_reg <= out_request;
    out_valid   <= valid_out;
  end generate comb_noreg;

end Behavioral;
