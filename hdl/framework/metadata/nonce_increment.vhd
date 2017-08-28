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

--! Increments the nonce from the s_request input and returns it on m_request.
--!
--! If the nonce wraps to zero, one is returned instead. This is necessary to
--! ensure that the zero nonce is reserved for identifiying uninitialized memory.
entity nonce_increment is
  generic(
    NONCE_WIDTH : integer := DATASTREAM_DATA_WIDTH
    );
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    s_request         : in  std_logic_vector(NONCE_WIDTH-1 downto 0);
    s_request_address : in  std_logic_vector(ADDRESS_WIDTH-1 downto 0);
    s_request_valid   : in  std_logic;
    s_request_ready   : out std_logic;

    m_request         : out std_logic_vector(NONCE_WIDTH-1 downto 0);
    m_request_address : out std_logic_vector(ADDRESS_WIDTH-1 downto 0);
    m_request_valid   : out std_logic;
    m_request_ready   : in  std_logic
    );
end nonce_increment;

architecture structural of nonce_increment is
begin
  m_request_valid <= s_request_valid;
  s_request_ready <= m_request_ready;

  work : process(s_request, s_request_address) is
    variable res : unsigned(NONCE_WIDTH-1 downto 0);
  begin
    res := unsigned(s_request) + 1;
    if res = 0 then
      res := to_unsigned(1, NONCE_WIDTH);
    end if;
    m_request         <= std_logic_vector(res);
    m_request_address <= s_request_address;
  end process work;

end structural;
