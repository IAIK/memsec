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

--! [Master+Slave] Forwards the AXI write response channel from the master to the slave.
--!
--! Additionally, if present, errors from the internal data stream are
--! incorporated into the response. Such errors occure for example when
--! an authentication failure has been detected.
entity memory_to_cpu_write_responder is
  generic(
    C_M_AXI_ID_WIDTH    : integer := 6;
    C_M_AXI_BUSER_WIDTH : integer := 0;
    C_S_AXI_ID_WIDTH    : integer := 12;
    C_S_AXI_BUSER_WIDTH : integer := 0;
    REGISTERED          : boolean := true
    );
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    m_axi_bid    : in  std_logic_vector(C_M_AXI_ID_WIDTH - 1 downto 0);
    m_axi_bresp  : in  std_logic_vector(1 downto 0);
    m_axi_buser  : in  std_logic_vector(C_M_AXI_BUSER_WIDTH - 1 downto 0);
    m_axi_bvalid : in  std_logic;
    m_axi_bready : out std_logic;

    s_axi_bid    : out std_logic_vector(C_S_AXI_ID_WIDTH - 1 downto 0);
    s_axi_bresp  : out std_logic_vector(1 downto 0);
    s_axi_buser  : out std_logic_vector(C_S_AXI_BUSER_WIDTH - 1 downto 0);
    s_axi_bvalid : out std_logic;
    s_axi_bready : in  std_logic;

    s_request       : in  StreamType;
    s_request_ready : out std_logic;

    release_lock       : out std_logic;
    release_lock_ready : in  std_logic
    );
end memory_to_cpu_write_responder;

architecture arch_imp of memory_to_cpu_write_responder is

  signal req_sentxDP, req_sentxDN   : std_logic;
  signal data_sentxDP, data_sentxDN : std_logic;
  signal id_sentxDP, id_sentxDN     : std_logic;

  signal request       : StreamType;
  signal request_ready : std_logic;

  -- helper signals for the write response stream
  signal axi_bid    : std_logic_vector(C_S_AXI_ID_WIDTH - 1 downto 0);
  signal axi_bresp  : std_logic_vector(1 downto 0);
  signal axi_bvalid : std_logic;

  -- helper signal for master ready / valid
  signal m_bvalid, m_bready : std_logic;

  signal error_accxDP, error_accxDN : std_logic;
begin

  reg_stage : entity work.stream_register_stage
    generic map(
      REGISTERED => REGISTERED
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_data  => s_request,
      in_valid => s_request.valid,
      in_ready => s_request_ready,

      out_data  => request,
      out_valid => open,
      out_ready => request_ready
      );

  regs : process(clk) is
  begin
    if rising_edge(clk) then
      if resetn = '0' then
        error_accxDP <= '0';
      else
        error_accxDP <= error_accxDN;
      end if;
    end if;
  end process regs;

  accumulate_and_respond_errors : process(axi_bvalid, error_accxDP, m_bvalid,
                                          request.error, request.id,
                                          request.last_request, request.valid,
                                          s_axi_bready) is
  begin
    error_accxDN  <= error_accxDP;
    m_bready      <= '0';
    request_ready <= '0';

    axi_bid    <= (others => '0');
    axi_bresp  <= (others => '0');
    axi_bvalid <= '0';

    -- reset as soon as the transfer has been acknowledged
    if axi_bvalid = '1' and s_axi_bready = '1' then
      error_accxDN <= '0';
    end if;

    if request.valid = '1' and m_bvalid = '1' and request.last_request = '1' then
      -- respond the error accumulation result to the slave at the end of the transfer
      axi_bid       <= request.id;
      axi_bvalid    <= '1';
      m_bready      <= s_axi_bready;
      request_ready <= s_axi_bready;
      if error_accxDP = '1' or request.error = '1' then
        axi_bresp <= "10";
      end if;
    elsif request.valid = '1' and m_bvalid = '1' then
      -- accumulate error flags accross the individual sub requests
      error_accxDN  <= error_accxDP or request.error;
      m_bready      <= '1';
      request_ready <= '1';
    end if;
  end process accumulate_and_respond_errors;

  ready_synchronizer : entity work.ready_synchronizer
    generic map(
      OUT_WIDTH => 2
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_valid => m_axi_bvalid,
      in_ready => m_axi_bready,

      out_valid(0)  => m_bvalid,
      out_valid(1)  => release_lock,
      out_active(0) => '1',
      out_active(1) => '1',
      out_ready(0)  => m_bready,
      out_ready(1)  => release_lock_ready
      );

  -- map to slave write resonse stream
  s_axi_bid    <= axi_bid;
  s_axi_bresp  <= axi_bresp;
  s_axi_buser  <= (others => '0');      -- no user data support
  s_axi_bvalid <= axi_bvalid;
end arch_imp;
