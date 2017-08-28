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

entity tb_prince is
  generic(
    ENTITY_NAME : string := "tb_prince";
    CLK_PERIOD  : time   := 5.0 ns
    );
end tb_prince;

architecture Behavioral of tb_prince is
  signal ClkxC  : std_logic := '0';
  signal RstxRB : std_logic;

  signal Key0xD, Key1xD  : std_logic_vector(63 downto 0);
  signal MessagexD       : std_logic_vector(63 downto 0);
  signal MessageVerifyxD : std_logic_vector(63 downto 0);
  signal CiphertextxD    : std_logic_vector(63 downto 0);
  signal ExpCiphertextxD : std_logic_vector(63 downto 0);

  signal PlainValidxS, PlainReadyxS           : std_logic;
  signal EncryptionValidxS, EncryptionReadyxS : std_logic;
  signal DecryptionValidxS, DecryptionReadyxS : std_logic;
begin
  -- Generate clock and reset
  ClkxC  <= not ClkxC after CLK_PERIOD;
  RstxRB <= '0', '1'  after 20 ns;

  inst_enc_prince : entity work.prince
    generic map(
      DECRYPTION => false
      )
    port map(
      ClkxCI        => ClkxC,
      RstxRBI       => RstxRB,
      Key0xDI       => Key0xD,
      Key1xDI       => Key1xD,
      MessagexDI    => MessagexD,
      CiphertextxDO => CiphertextxD,
      in_ready      => PlainReadyxS,
      in_valid      => PlainValidxS,
      out_ready     => EncryptionReadyxS,
      out_valid     => EncryptionValidxS
      );

  inst_dec_prince : entity work.prince
    generic map(
      DECRYPTION => true
      )
    port map(
      ClkxCI        => ClkxC,
      RstxRBI       => RstxRB,
      Key0xDI       => Key0xD,
      Key1xDI       => Key1xD,
      MessagexDI    => CiphertextxD,
      CiphertextxDO => MessageVerifyxD,
      in_ready      => EncryptionReadyxS,
      in_valid      => EncryptionValidxS,
      out_ready     => DecryptionReadyxS,
      out_valid     => DecryptionValidxS
      );

  rw_testcase : process
    variable error_occured : boolean      := false;
    type testvector_t is array (0 to 4) of std_logic_vector(63 downto 0);
    variable message_v     : testvector_t := (x"0000000000000000", x"ffffffffffffffff", x"0000000000000000", x"0000000000000000", x"0123456789abcdef");
    variable key0_v        : testvector_t := (x"0000000000000000", x"0000000000000000", x"ffffffffffffffff", x"0000000000000000", x"0000000000000000");
    variable key1_v        : testvector_t := (x"0000000000000000", x"0000000000000000", x"0000000000000000", x"ffffffffffffffff", x"fedcba9876543210");
    variable cipher_v      : testvector_t := (x"818665aa0d02dfda", x"604ae6ca03c20ada", x"9fb51935fc3df524", x"78a54cbe737bb7ef", x"ae25ad3ca8fa9ccf");
  begin
    wait until rising_edge(RstxRB);
    DecryptionReadyxS <= '0';
    for I in 0 to message_v'length-1 loop
      Key0xD          <= key0_v(I);
      Key1xD          <= key1_v(I);
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
