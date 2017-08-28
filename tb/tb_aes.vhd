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

entity tb_aes is
  generic(
    ENTITY_NAME : string := "tb_aes";
    CLK_PERIOD  : time   := 5.0 ns
    );
end tb_aes;

architecture Behavioral of tb_aes is
  signal ClkxC  : std_logic := '0';
  signal RstxRB : std_logic;

  signal KeyxD, KeyInvxD : std_logic_vector(127 downto 0);
  signal MessagexD       : std_logic_vector(127 downto 0);
  signal MessageVerifyxD : std_logic_vector(127 downto 0);
  signal CiphertextxD    : std_logic_vector(127 downto 0);
  signal ExpCiphertextxD : std_logic_vector(127 downto 0);

  signal PlainValidxS, PlainReadyxS           : std_logic;
  signal EncryptionValidxS, EncryptionReadyxS : std_logic;
  signal DecryptionValidxS, DecryptionReadyxS : std_logic;
begin
  -- Generate clock and reset
  ClkxC  <= not ClkxC after CLK_PERIOD;
  RstxRB <= '0', '1'  after 20 ns;

  inst_enc_aes : entity work.aes128_hs
    port map(
      ClkxCI     => ClkxC,
      RstxRBI    => RstxRB,
      KeyxDI     => KeyxD,
      DataxDI    => MessagexD,
      DataxDO    => CiphertextxD,
      EncryptxSI => '1',
      in_ready   => PlainReadyxS,
      in_valid   => PlainValidxS,
      out_ready  => EncryptionReadyxS,
      out_valid  => EncryptionValidxS
      );

  inst_dec_aes : entity work.aes128_hs
    port map(
      ClkxCI     => ClkxC,
      RstxRBI    => RstxRB,
      KeyxDI     => KeyInvxD,
      DataxDI    => CiphertextxD,
      DataxDO    => MessageVerifyxD,
      EncryptxSI => '0',
      in_ready   => EncryptionReadyxS,
      in_valid   => EncryptionValidxS,
      out_ready  => DecryptionReadyxS,
      out_valid  => DecryptionValidxS
      );

  rw_testcase : process
    variable error_occured : boolean      := false;
    type testvector_t is array (0 to 3) of std_logic_vector(127 downto 0);
    variable message_v     : testvector_t := (x"80000000000000000000000000000000", x"ffffffffffffffffffffffffffffffff", x"00000000000000000000000000000000", x"00000000000000000000000000000000");
    variable key_v         : testvector_t := (x"00000000000000000000000000000000", x"00000000000000000000000000000000", x"80000000000000000000000000000000", x"ffffffffffffffffffffffffffffffff");
    variable keyInv_v      : testvector_t := (x"b4ef5bcb3e92e21123e951cf6f8f188e", x"b4ef5bcb3e92e21123e951cf6f8f188e", x"b5b125173ecce2cd22e951136f8f1852", x"d60a3588e472f07b82d2d7858cd7c326");
    variable cipher_v      : testvector_t := (x"3ad78e726c1ec02b7ebfe92b23d9ec34", x"3f5b8cc9ea855a0afa7347d23e8d664e", x"0edd33d3c621e546455bd8ba1418bec8", x"a1f6258c877d5fcd8964484538bfc92c");
  begin
    wait until rising_edge(RstxRB);
    DecryptionReadyxS <= '0';
    for I in 0 to message_v'length-1 loop
      KeyxD           <= key_v(I);
      KeyInvxD        <= keyInv_v(I);
      MessagexD       <= message_v(I);
      ExpCiphertextxD <= cipher_v(I);
      PlainValidxS    <= '1';

      wait until PlainReadyxS = '1' and rising_edge(ClkxC);
      PlainValidxS <= '0';

      wait until EncryptionValidxS = '1' and falling_edge(ClkxC);
      if CiphertextxD /= ExpCiphertextxD then
        report "ERROR: Encryption failed. Ciphertext mismatch.";
        error_occured := true;
      end if;

      wait until DecryptionValidxS = '1' and falling_edge(ClkxC);
      if MessageVerifyxD /= MessagexD then
        report "ERROR: Decryption failed. Plaintext mismatch.";
        error_occured := true;
      end if;
      DecryptionReadyxS <= '1';

      wait until DecryptionValidxS = '0' and falling_edge(ClkxC);
      DecryptionReadyxS <= '0';
    end loop;

    if error_occured then
      write_tb_fail(ENTITY_NAME);
      report "Simulation failed" severity failure;
    else
      write_tb_success(ENTITY_NAME);
      report "Simulation succeeded" severity failure;
    end if;
  end process;
end Behavioral;
