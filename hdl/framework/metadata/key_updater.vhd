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

--! Updates keys/nonces by replacing s_request through random data.
entity key_updater is
  generic(
    KEY_WIDTH  : integer := DATASTREAM_DATA_WIDTH;
    REGISTERED : boolean := false
    );
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    s_request         : in  std_logic_vector(KEY_WIDTH-1 downto 0);
    s_request_address : in  std_logic_vector(ADDRESS_WIDTH-1 downto 0);
    s_request_valid   : in  std_logic;
    s_request_ready   : out std_logic;

    m_request         : out std_logic_vector(KEY_WIDTH-1 downto 0);
    m_request_address : out std_logic_vector(ADDRESS_WIDTH-1 downto 0);
    m_request_valid   : out std_logic;
    m_request_ready   : in  std_logic;

    random         : in  std_logic_vector(KEY_WIDTH-1 downto 0);
    random_valid   : in  std_logic;
    random_ready   : out std_logic;
    random_request : out std_logic
    );
end key_updater;

architecture structural of key_updater is
  signal request         : std_logic_vector(KEY_WIDTH-1 downto 0);
  signal request_address : std_logic_vector(ADDRESS_WIDTH-1 downto 0);
  signal request_valid   : std_logic;
  signal request_ready   : std_logic;
begin
  request         <= random;
  request_address <= s_request_address;
  request_valid   <= s_request_valid and random_valid;

  s_request_ready <= request_ready;
  random_ready    <= request_ready;
  random_request  <= s_request_valid;


  register_stage : entity work.register_stage
    generic map(
      WIDTH      => KEY_WIDTH+ADDRESS_WIDTH,
      REGISTERED => REGISTERED
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_data(KEY_WIDTH-1 downto 0)                       => request,
      in_data(KEY_WIDTH+ADDRESS_WIDTH-1 downto KEY_WIDTH) => request_address,
      in_valid                                            => request_valid,
      in_ready                                            => request_ready,

      out_data(KEY_WIDTH-1 downto 0)                       => m_request,
      out_data(KEY_WIDTH+ADDRESS_WIDTH-1 downto KEY_WIDTH) => m_request_address,
      out_valid                                            => m_request_valid,
      out_ready                                            => m_request_ready
      );
end structural;
