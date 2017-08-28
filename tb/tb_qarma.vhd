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

library IEEE;
use IEEE.STD_LOGIC_1164.all;
use work.tb_utils_pkg.all;

entity tb_qarma is
  generic(
    ENTITY_NAME : string  := "tb_qarma";
    CLK_PERIOD  : time    := 5.0 ns;
    ROUNDS      : integer := 6
    );
end tb_qarma;

architecture Behavioral of tb_qarma is
  signal ClkxC  : std_logic := '0';
  signal RstxRB : std_logic;

  signal KeyxD           : std_logic_vector(127 downto 0);
  signal TweakxD         : std_logic_vector(63 downto 0);
  signal MessagexD       : std_logic_vector(63 downto 0);
  signal MessageVerifyxD : std_logic_vector(63 downto 0);
  signal CiphertextxD    : std_logic_vector(63 downto 0);
  signal ExpCiphertextxD : std_logic_vector(63 downto 0);

  signal EnryptionValidxS, EnryptionReadyxS : std_logic;
  signal DecryptionValidxS                  : std_logic;
begin
  -- Generate clock and reset
  ClkxC  <= not ClkxC after CLK_PERIOD;
  RstxRB <= '0', '1'  after 20 ns;

  inst_enc_qarma : entity work.qarma
    generic map(
      DECRYPTION => false,
      ROUNDS     => ROUNDS
      )
    port map(
      ClkxCI        => ClkxC,
      RstxRBI       => RstxRB,
      KeyxDI        => KeyxD,
      TweakxDI      => TweakxD,
      MessagexDI    => MessagexD,
      CiphertextxDO => CiphertextxD,

      in_ready  => open,
      in_valid  => '1',
      out_ready => EnryptionReadyxS,
      out_valid => EnryptionValidxS
      );


  inst_dec_qarma : entity work.qarma
    generic map(
      DECRYPTION => true,
      ROUNDS     => ROUNDS
      )
    port map(
      ClkxCI        => ClkxC,
      RstxRBI       => RstxRB,
      KeyxDI        => KeyxD,
      TweakxDI      => TweakxD,
      MessagexDI    => CiphertextxD,
      CiphertextxDO => MessageVerifyxD,

      in_ready  => EnryptionReadyxS,
      in_valid  => EnryptionValidxS,
      out_ready => '1',
      out_valid => DecryptionValidxS
      );

  rw_testcase : process
    variable error_occured : boolean := false;
  begin
    wait until rising_edge(RstxRB);

    KeyxD     <= x"84be85ce9804e94bec2802d4e0a488e9";
    MessagexD <= x"fb623599da6e8127";
    TweakxD   <= x"477d469dec0b8762";

    case ROUNDS is
      when 5 => ExpCiphertextxD <= x"544b0ab95bda7c3a";
      when 6 => ExpCiphertextxD <= x"a512dd1e4e3ec582";
      when 7 => ExpCiphertextxD <= x"edf67ff370a483f2";
      when others =>
        write_tb_fail(ENTITY_NAME);
        report "Test Vector is unknown" severity failure;
    end case;

    wait until EnryptionValidxS = '1' and falling_edge(ClkxC);
    if CiphertextxD /= ExpCiphertextxD then
      report "ERROR: Encryption failed. Ciphertext mismatch.";
      error_occured := true;
    end if;

    wait until DecryptionValidxS = '1' and falling_edge(ClkxC);
    if MessageVerifyxD /= MessagexD then
      report "ERROR: Decryption failed. Plaintext mismatch.";
      error_occured := true;
    end if;

    if error_occured then
      write_tb_fail(ENTITY_NAME);
      report "Simulation failed" severity failure;
    else
      write_tb_success(ENTITY_NAME);
      report "Simulation succeeded" severity failure;
    end if;
  end process;
end Behavioral;
