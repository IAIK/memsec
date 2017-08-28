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

--! [Master] Writes data from the internal stream to the AXI write channel.
entity memory_write_data is
  generic(
    C_M_AXI_DATA_WIDTH  : integer := 32;
    C_M_AXI_WUSER_WIDTH : integer := 0;
    REGISTERED          : boolean := true
    );
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    m_axi_wdata  : out std_logic_vector(C_M_AXI_DATA_WIDTH - 1 downto 0);
    m_axi_wstrb  : out std_logic_vector(C_M_AXI_DATA_WIDTH / 8 - 1 downto 0);
    m_axi_wlast  : out std_logic;
    m_axi_wuser  : out std_logic_vector(C_M_AXI_WUSER_WIDTH - 1 downto 0);
    m_axi_wvalid : out std_logic;
    m_axi_wready : in  std_logic;

    s_request       : in  StreamType;
    s_request_ready : out std_logic;

    m_request       : out StreamType;
    m_request_ready : in  std_logic
    );
end memory_write_data;

architecture arch_imp of memory_write_data is
  constant LAST_FIELD_ADDR : integer := DATASTREAM_DATA_WIDTH/C_M_AXI_DATA_WIDTH - 1;

  -- helper signals for the write stream
  signal axi_wdata  : std_logic_vector(C_M_AXI_DATA_WIDTH - 1 downto 0);
  signal axi_wlast  : std_logic;
  signal axi_wvalid : std_logic;

  -- helper signals for the bit rate conversion
  signal stream_in_last : std_logic;
  signal stream_data    : std_logic_vector(C_M_AXI_DATA_WIDTH - 1 downto 0);
  signal stream_last    : std_logic;
  signal stream_valid   : std_logic;
  signal stream_ready   : std_logic;

  -- helper signals for the register stage at the stream input
  signal stream_request_type : std_logic_vector(1 downto 0);
  signal stream_id           : std_logic_vector(ID_WIDTH-1 downto 0);
  signal stream_last_request : std_logic;
  signal stream_error        : std_logic;
  signal stream_regs_ready   : std_logic;

  -- registers to remember the state across multiple beats of the request or transfer
  signal error_accxDP, error_accxDN : std_logic;

  signal data_send_valid, data_send_ready : std_logic;
  signal error_acc_valid, error_acc_ready : std_logic;
begin

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

  send_data : process(data_send_valid, m_axi_wready, stream_data, stream_last) is
  begin
    axi_wdata  <= (others => '0');
    axi_wlast  <= '0';
    axi_wvalid <= '0';

    data_send_ready <= '0';

    -- send the data to the memory
    if data_send_valid = '1' then
      axi_wdata       <= stream_data;
      axi_wlast       <= stream_last;
      axi_wvalid      <= '1';
      data_send_ready <= m_axi_wready;
    end if;
  end process send_data;

  accumulate_and_forward_errors : process(error_acc_valid, error_accxDP,
                                          m_request_ready, stream_error,
                                          stream_id, stream_last,
                                          stream_last_request, stream_ready,
                                          stream_request_type, stream_valid) is
  begin
    error_accxDN    <= error_accxDP;
    m_request       <= StreamType_default;
    error_acc_ready <= '0';

    -- reset as soon as the request ends
    if stream_valid = '1' and stream_last = '1' and stream_ready = '1' then
      error_accxDN <= '0';
    end if;

    if error_acc_valid = '1' and stream_last = '1' then
      -- forward error accumulation result including id via the master interface
      m_request.id           <= stream_id;
      m_request.last_request <= stream_last_request;
      m_request.request_type <= stream_request_type;
      m_request.error        <= error_accxDP or stream_error;
      m_request.valid        <= '1';
      error_acc_ready        <= m_request_ready;
    elsif error_acc_valid = '1' then
      -- accumulate error flags within the beat
      error_accxDN    <= error_accxDP or stream_error;
      error_acc_ready <= '1';
    end if;
  end process accumulate_and_forward_errors;

  data_serialization : entity work.serialization
    generic map(
      IN_DATA_WIDTH  => DATASTREAM_DATA_WIDTH,
      OUT_DATA_WIDTH => C_M_AXI_DATA_WIDTH,
      REGISTERED     => REGISTERED
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_last         => stream_in_last,
      in_data         => s_request.data,
      in_field_offset => (others => '0'),
      in_field_len    => (others => '1'),
      in_valid        => s_request.valid,
      in_ready        => s_request_ready,

      out_data         => stream_data,
      out_field_offset => open,
      out_last         => stream_last,
      out_valid        => stream_valid,
      out_ready        => stream_ready
      );
  stream_in_last    <= to_std_logic(unsigned(s_request.block_len) = 0);
  stream_regs_ready <= stream_ready and stream_last;

  request_type_reg : entity work.register_stage
    generic map(
      WIDTH      => 2,
      REGISTERED => REGISTERED
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_data  => s_request.request_type,
      in_valid => s_request.valid,
      in_ready => open,  -- data_serialization handles the synchronization

      out_data  => stream_request_type,
      out_valid => open,  -- data_serialization handles the synchronization
      out_ready => stream_regs_ready
      );

  id_reg : entity work.register_stage
    generic map(
      WIDTH      => ID_WIDTH,
      REGISTERED => REGISTERED
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_data  => s_request.id,
      in_valid => s_request.valid,
      in_ready => open,  -- data_serialization handles the synchronization

      out_data  => stream_id,
      out_valid => open,  -- data_serialization handles the synchronization
      out_ready => stream_regs_ready
      );

  last_request_reg : entity work.register_stage
    generic map(
      WIDTH      => 1,
      REGISTERED => REGISTERED
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_data(0) => s_request.last_request,
      in_valid   => s_request.valid,
      in_ready   => open,  -- data_serialization handles the synchronization

      out_data(0) => stream_last_request,
      out_valid   => open,  -- data_serialization handles the synchronization
      out_ready   => stream_regs_ready
      );

  error_reg : entity work.register_stage
    generic map(
      WIDTH      => 1,
      REGISTERED => REGISTERED
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_data(0) => s_request.error,
      in_valid   => s_request.valid,
      in_ready   => open,  -- data_serialization handles the synchronization

      out_data(0) => stream_error,
      out_valid   => open,  -- data_serialization handles the synchronization
      out_ready   => stream_ready
      );

  ready_synchronizer : entity work.ready_synchronizer
    generic map(
      OUT_WIDTH => 2
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_valid => stream_valid,
      in_ready => stream_ready,

      out_valid(0)  => data_send_valid,
      out_valid(1)  => error_acc_valid,
      out_active(0) => '1',
      out_active(1) => '1',
      out_ready(0)  => data_send_ready,
      out_ready(1)  => error_acc_ready
      );

  -- map to master write stream
  m_axi_wdata  <= axi_wdata;
  m_axi_wstrb  <= (others => '1');      -- write all bytes
  m_axi_wlast  <= axi_wlast;
  m_axi_wuser  <= (others => '0');      -- no user data support
  m_axi_wvalid <= axi_wvalid;

end arch_imp;
