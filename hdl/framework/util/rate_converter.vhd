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

--! Data rate converter which supports both, serialization and deserialization.
entity rate_converter is
  generic(
    IN_DATA_WIDTH    : integer := 32;
    OUT_DATA_WIDTH   : integer := 64;
    IN_STROBE_WIDTH  : integer := 2;
    OUT_STROBE_WIDTH : integer := 3;
    REGISTERED       : boolean := false  -- option to cut the critical path
    );
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    -- Signals that the current transaction is over and that the output should
    -- be generated immediately. The output bits which are missing are zero.
    in_last         : in  std_logic;
    in_data         : in  std_logic_vector(IN_DATA_WIDTH - 1 downto 0);
    in_field_offset : in  std_logic_vector(offset_width(IN_DATA_WIDTH, OUT_DATA_WIDTH)-1 downto 0);
    in_field_len    : in  std_logic_vector(offset_width(IN_DATA_WIDTH, OUT_DATA_WIDTH)-1 downto 0);
    in_valid        : in  std_logic;
    in_ready        : out std_logic;

    -- output with handshake signals
    out_data         : out std_logic_vector(OUT_DATA_WIDTH - 1 downto 0);
    out_field_offset : out std_logic_vector(offset_width(IN_DATA_WIDTH, OUT_DATA_WIDTH)-1 downto 0);
    out_field_len    : out std_logic_vector(offset_width(IN_DATA_WIDTH, OUT_DATA_WIDTH)-1 downto 0);
    out_last         : out std_logic;
    out_valid        : out std_logic;
    out_ready        : in  std_logic
    );
end rate_converter;

architecture Behavioral of rate_converter is

begin

  deserializer : if OUT_DATA_WIDTH > IN_DATA_WIDTH generate
    data_deserialization : entity work.deserialization
      generic map(
        IN_DATA_WIDTH  => IN_DATA_WIDTH,
        OUT_DATA_WIDTH => OUT_DATA_WIDTH,
        REGISTERED     => REGISTERED
        )
      port map (
        clk    => clk,
        resetn => resetn,

        in_field_start_offset => in_field_offset,

        in_last  => in_last,
        in_data  => in_data,
        in_valid => in_valid,
        in_ready => in_ready,

        out_last         => out_last,
        out_data         => out_data,
        out_field_offset => out_field_offset,
        out_field_len    => out_field_len,
        out_valid        => out_valid,
        out_ready        => out_ready
        );

  end generate deserializer;


  serializer : if IN_DATA_WIDTH > OUT_DATA_WIDTH generate
    data_serialization : entity work.serialization
      generic map(
        IN_DATA_WIDTH  => IN_DATA_WIDTH,
        OUT_DATA_WIDTH => OUT_DATA_WIDTH,
        REGISTERED     => REGISTERED
        )
      port map (
        clk    => clk,
        resetn => resetn,

        in_last         => in_last,
        in_data         => in_data,
        in_field_offset => in_field_offset,
        in_field_len    => in_field_len,
        in_valid        => in_valid,
        in_ready        => in_ready,

        out_last         => out_last,
        out_data         => out_data,
        out_field_offset => out_field_offset,
        out_valid        => out_valid,
        out_ready        => out_ready
        );

    out_field_len <= (others => '0');
  end generate serializer;

  identity : if IN_DATA_WIDTH = OUT_DATA_WIDTH generate
    data_reg : entity work.register_stage
      generic map(
        WIDTH      => (1+IN_DATA_WIDTH),
        REGISTERED => REGISTERED
        )
      port map (
        clk    => clk,
        resetn => resetn,

        in_data(IN_DATA_WIDTH-1 downto 0) => in_data,
        in_data(IN_DATA_WIDTH)            => in_last,
        in_valid                          => in_valid,
        in_ready                          => in_ready,

        out_data(IN_DATA_WIDTH-1 downto 0) => out_data,
        out_data(IN_DATA_WIDTH)            => out_last,
        out_valid                          => out_valid,
        out_ready                          => out_ready
        );

    out_field_offset <= (others => '0');
    out_field_len    <= (others => '0');
  end generate;

end Behavioral;
