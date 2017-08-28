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

entity tb_ascon is
  generic(
    ENTITY_NAME    : string  := "tb_ascon";
    CLK_PERIOD     : time    := 5.0 ns;
    UNROLED_ROUNDS : integer := 1       -- 1,2,3 or 6 for Ascon-128
    );
end tb_ascon;

architecture Behavioral of tb_ascon is
  signal ClkxC  : std_logic := '0';
  signal RstxRB : std_logic;

  signal KeyxD           : std_logic_vector(127 downto 0);
  signal NoncexD         : std_logic_vector(127 downto 0);
  signal ADxD            : std_logic_vector(63 downto 0);
  signal MessagexD       : std_logic_vector(63 downto 0);
  signal CiphertextxD    : std_logic_vector(63 downto 0);
  signal TagxD           : std_logic_vector(127 downto 0);
  signal ExpCiphertextxD : std_logic_vector(63 downto 0);
  signal ExpTagxD        : std_logic_vector(127 downto 0);

  signal DataOutxD                                                                 : std_logic_vector(63 downto 0);
  signal DataInxD                                                                  : std_logic_vector(127 downto 0);
  signal AsconTagxD                                                                : std_logic_vector(127 downto 0);
  signal InitxS, AssociatexS, EncryptxS, DecryptxS, FinalEncryptxS, FinalDecryptxS : std_logic;
  signal DonexS                                                                    : std_logic;
begin
  -- Generate clock and reset
  ClkxC  <= not ClkxC after CLK_PERIOD;
  RstxRB <= '0', '1'  after 20 ns;

  -- Ascon 128
  ascon : entity work.ascon
    generic map (
      UNROLED_ROUNDS  => UNROLED_ROUNDS,  -- 1,2,3 or 6 for Ascon-128
      DATA_BLOCK_SIZE => 64,              -- select Ascon-128
      ROUNDS_A        => 12,
      ROUNDS_B        => 6,
      DATA_BUS_WIDTH  => 128)             -- 128 bit nonces
    port map (
      ClkxCI             => ClkxC,
      RstxRBI            => RstxRB,
      KeyxDI             => KeyxD,
      CP_InitxSI         => InitxS,
      CP_AssociatexSI    => AssociatexS,
      CP_EncryptxSI      => EncryptxS,
      CP_DecryptxSI      => DecryptxS,
      CP_FinalEncryptxSI => FinalEncryptxS,
      CP_FinalDecryptxSI => FinalDecryptxS,
      DataWritexDI       => DataInxD,
      IODataxDO          => DataOutxD,
      CP_DonexSO         => DonexS,
      TagxDO             => AsconTagxD
      );

  rw_testcase : process
    variable error_occured : boolean         := false;
    type testvector128_t is array (0 to 5) of std_logic_vector(127 downto 0);
    type testvector64_t is array (0 to 5) of std_logic_vector(63 downto 0);
    variable message_v     : testvector64_t  := (x"0000000000000080", x"FFFFFFFFFFFFFF80", x"0000000000000080", x"0000000000000080", x"0000000000000080", x"8e75dbc06af19480");
    variable ad_v          : testvector64_t  := (x"0000000000000080", x"0000000000000080", x"FFFFFFFFFFFFFF80", x"0000000000000080", x"0000000000000080", x"2aa76532c281ec80");
    variable key_v         : testvector128_t := (x"00000000000000000000000000000000", x"00000000000000000000000000000000", x"00000000000000000000000000000000", x"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", x"00000000000000000000000000000000", x"857ad7a4fb7b83364c817d011b8ea261");
    variable nonce_v       : testvector128_t := (x"00000000000000000000000000000000", x"00000000000000000000000000000000", x"00000000000000000000000000000000", x"00000000000000000000000000000000", x"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", x"e722702b7b568c9786a8b975e7c04a48");
    variable cipher_v      : testvector64_t  := (x"44d7bff2549e8637", x"bb28400dab617937", x"046692d6c5161b41", x"de303af2de242294", x"5d1feaad4eb19ddb", x"19b4dc8720914f7d");
    variable tag_v         : testvector128_t := (x"313e35b92cb72503b2557c9a0d57a881", x"33b88367855720ba7ec8eb26bad56298", x"0fe2eeacd55836cf85d61cc06b6f0c9d", x"60401b4323ed0bf2412c564f15140a87", x"4b8a46cc110826f8e562013cc05a166b", x"4bdc08b3379383c2cb6141b1c3a2b592");
  begin
    InitxS         <= '0';
    AssociatexS    <= '0';
    EncryptxS      <= '0';
    DecryptxS      <= '0';
    FinalEncryptxS <= '0';
    FinalDecryptxS <= '0';

    wait until rising_edge(RstxRB);
    for I in 0 to message_v'length-1 loop
      ExpCiphertextxD <= cipher_v(I);
      ExpTagxD        <= tag_v(I);
      NoncexD         <= nonce_v(I);
      KeyxD           <= key_v(I);
      ADxD            <= ad_v(I);
      MessagexD       <= message_v(I);
      wait until rising_edge(ClkxC);

      DataInxD <= NoncexD;
      InitxS   <= '1';

      wait until DonexS = '1' and rising_edge(ClkxC);
      InitxS                <= '0';
      DataInxD(63 downto 0) <= ADxD;
      AssociatexS           <= '1';

      wait until DonexS = '1' and rising_edge(ClkxC);
      AssociatexS           <= '0';
      DataInxD(63 downto 0) <= MessagexD;

      -- wait one clock cycle to make sure that DataOutxD has stabilized
      wait until rising_edge(ClkxC);
      CiphertextxD <= DataOutxD;
      if DataOutxD /= ExpCiphertextxD then
        report "ERROR: Encryption failed. Ciphertext mismatch.";
        error_occured := true;
      end if;
      FinalEncryptxS <= '1';

      wait until DonexS = '1' and rising_edge(ClkxC);
      FinalEncryptxS <= '0';

      wait until falling_edge(ClkxC);
      TagxD <= AsconTagxD;
      if AsconTagxD /= ExpTagxD then
        report "ERROR: Encryption failed. Tag mismatch.";
        error_occured := true;
      end if;

      wait until falling_edge(ClkxC);
      DataInxD <= NoncexD;
      InitxS   <= '1';

      wait until DonexS = '1' and rising_edge(ClkxC);
      InitxS                <= '0';
      DataInxD(63 downto 0) <= ADxD;
      AssociatexS           <= '1';

      wait until DonexS = '1' and rising_edge(ClkxC);
      AssociatexS           <= '0';
      DataInxD(63 downto 0) <= CiphertextxD;

      -- wait one clock cycle to make sure that DataOutxD has stabilized
      wait until rising_edge(ClkxC);
      if DataOutxD /= MessagexD then
        report "ERROR: Decryption failed. Plaintext mismatch.";
        error_occured := true;
      end if;
      FinalDecryptxS <= '1';

      wait until DonexS = '1' and rising_edge(ClkxC);
      FinalDecryptxS <= '0';

      wait until falling_edge(ClkxC);
      if AsconTagxD /= TagxD then
        report "ERROR: Decryption failed. Tag mismatch.";
        error_occured := true;
      end if;
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
