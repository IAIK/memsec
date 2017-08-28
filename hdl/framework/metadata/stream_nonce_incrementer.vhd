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

--! Increments the metadata block in front of a memory transaction.
entity stream_nonce_incrementer is
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    s_request       : in  StreamType;
    s_request_ready : out std_logic;

    m_request       : out StreamType;
    m_request_ready : in  std_logic
    );
end stream_nonce_incrementer;

architecture arch_imp of stream_nonce_incrementer is
  signal data : BlockStreamType;

  signal inc_nonce                        : std_logic_vector(DATASTREAM_DATA_WIDTH-1 downto 0);
  signal inc_nonce_valid, inc_nonce_ready : std_logic;
begin

  modifier : entity work.stream_data_modifier
    generic map(
      MATCH_TYPE      => 2,     -- block numbers should be matched
      IGNORE_METADATA => false,
      IGNORE_TREE_REQ => false,
      IGNORE_DATA_REQ => false
      )
    port map (
      clk    => clk,
      resetn => resetn,

      s_data               => data,
      s_data_address       => (others => '0'),
      s_data_address_valid => '1',
      s_data_ready         => open,

      s_request       => s_request,
      s_request_ready => s_request_ready,

      m_request       => m_request,
      m_request_ready => m_request_ready
      );


  work : process(s_request.data, s_request.valid) is
    variable res : unsigned(DATASTREAM_DATA_WIDTH-1 downto 0);
  begin
    data <= BlockStreamType_default;
    res  := (others => '0');

    if s_request.valid = '1' then
      data.strobes <= (others => '1');
      data.last    <= '1';
      data.valid   <= '1';

      res := unsigned(s_request.data) + 1;
      if res = 0 then
        res := to_unsigned(1, DATASTREAM_DATA_WIDTH);
      end if;

      data.data <= std_logic_vector(res);
    end if;
  end process work;

end arch_imp;
