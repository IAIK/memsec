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

--! Replaces data within the stream through externally specified data.
--!
--! Provides the foundation for basically all stream modification operations.
--! Various types of addressing (virtual, physical, beat number) can be used to
--! match the modification positions. Furthermore, byte strobes are supported.
entity stream_data_modifier is
  generic(
    -- 0 .. virtual address
    -- 1 .. physical/block address
    -- 2 .. block number
    MATCH_TYPE      : integer := 0;
    IGNORE_METADATA : boolean := true;
    IGNORE_TREE_REQ : boolean := true;
    IGNORE_DATA_REQ : boolean := false
    );
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    s_data               : in  BlockStreamType;
    s_data_address       : in  AddressType;
    s_data_address_valid : in  std_logic;
    s_data_ready         : out std_logic;

    s_request       : in  StreamType;
    s_request_ready : out std_logic;

    m_request       : out StreamType;
    m_request_ready : in  std_logic
    );
end stream_data_modifier;

architecture arch_imp of stream_data_modifier is
  signal data_was_lastxDP, data_was_lastxDN : std_logic;
  signal block_counterxDP, block_counterxDN : std_logic_vector(AXI_LEN_WIDTH-1 downto 0);

  -- helper signals to make the outputs readable
  signal data_ready   : std_logic;
  signal req_ready    : std_logic;
  signal modified_req : StreamType;
begin

  regs : process(clk) is
  begin
    if rising_edge(clk) then
      if resetn = '0' then
        data_was_lastxDP <= '0';
        block_counterxDP <= (others => '0');
      else
        data_was_lastxDP <= data_was_lastxDN;
        block_counterxDP <= block_counterxDN;
      end if;
    end if;
  end process regs;

  block_ctr : process(block_counterxDP, req_ready, s_request.block_len,
                      s_request.valid) is
  begin
    block_counterxDN <= block_counterxDP;

    if s_request.valid = '1' and req_ready = '1' then
      if unsigned(s_request.block_len) = 0 then
        block_counterxDN <= (others => '0');
      else
        block_counterxDN <= std_logic_vector(unsigned(block_counterxDP) + 1);
      end if;
    end if;
  end process block_ctr;

  work : process(block_counterxDP, data_ready, data_was_lastxDP,
                 m_request_ready, modified_req, req_ready, s_data, s_request,
                 s_data_address_valid, s_data_address) is
    variable current_address : AddressType;
  begin
    data_was_lastxDN <= data_was_lastxDP;
    modified_req     <= StreamType_default;
    data_ready       <= '0';
    req_ready        <= '0';

    current_address := (others => '0');
    case MATCH_TYPE is
      when 0 =>
        current_address := s_request.virt_address;
      when 1 =>
        current_address := s_request.block_address;
      when 2 =>
        current_address := zeros(ADDRESS_WIDTH - AXI_LEN_WIDTH) & block_counterxDP;
      when others =>
        assert false report "unhandled generic case" severity failure;
    end case;

    if s_data.valid = '1' and s_data.last = '1' and data_ready = '1' then
      data_was_lastxDN <= '1';
    end if;

    if s_request.valid = '1' then
      modified_req       <= s_request;
      modified_req.valid <= '0';

      if req_ready = '1' and unsigned(s_request.block_len) = 0 then
        data_was_lastxDN <= '0';
      end if;

      -- check if the data modification can be performed
      if (IGNORE_METADATA and s_request.metadata = '1') or
        (IGNORE_TREE_REQ and (s_request.request_type = REQ_TYPE_TREE_ROOT or s_request.request_type = REQ_TYPE_TREE)) or
        (IGNORE_DATA_REQ and s_request.request_type = REQ_TYPE_DATA) or
        data_was_lastxDP = '1' or
        (s_data_address_valid = '1' and unsigned(current_address) < unsigned(s_data_address)) then
        -- The block from the request is forwarded without modification.
        -- This happens for data blocks before and after the actual write.
        modified_req.valid <= '1';
        req_ready          <= m_request_ready;
      elsif s_data.valid = '1' and s_data_address_valid = '1' and unsigned(current_address) = unsigned(s_data_address) then
        -- The addresses of the request matches the address of the data input.
        for I in 0 to DATASTREAM_DATA_WIDTH/8 - 1 loop
          if s_data.strobes(I) = '1' then
            modified_req.data(I*8+7 downto I*8) <= s_data.data(I*8+7 downto I*8);
          end if;
        end loop;
        modified_req.valid <= '1';
        data_ready         <= m_request_ready;
        req_ready          <= m_request_ready;
      end if;

    end if;

    m_request       <= modified_req;
    s_request_ready <= req_ready;
    s_data_ready    <= data_ready;
  end process work;

end arch_imp;
