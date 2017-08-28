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

-------------------------------------------------------------------------------
-- Title      : Prince block cipher
-- Project    :
-------------------------------------------------------------------------------
-- File       : prince.vhdl
-- Author     : Erich Wenger  <erichwenger@erich.wenger@iaik.tugraz.at>
-- Company    :
-- Created    : 2014-05-23
-- Last update: 2014-05-30
-- Platform   :
-- Standard   : VHDL'93/02
-------------------------------------------------------------------------------
-- Description:
-------------------------------------------------------------------------------
-- Copyright (c) 2014
-------------------------------------------------------------------------------
-- Revisions  :
-- Date        Version  Author  Description
-- 2014-05-23  1.0      erichwenger     Created
-------------------------------------------------------------------------------

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity prince is
  generic(
    DECRYPTION : boolean := false;
    BLOCK_SIZE : integer := 64
    );
  port(
    ClkxCI        : in  std_logic;
    RstxRBI       : in  std_logic;
    Key0xDI       : in  std_logic_vector(63 downto 0);
    Key1xDI       : in  std_logic_vector(63 downto 0);
    MessagexDI    : in  std_logic_vector(BLOCK_SIZE-1 downto 0);
    CiphertextxDO : out std_logic_vector(BLOCK_SIZE-1 downto 0);

    in_ready  : out std_logic;
    in_valid  : in  std_logic;
    out_ready : in  std_logic;
    out_valid : out std_logic
    );

end entity prince;

architecture structural of prince is

  type state_type is array (10 downto 1) of std_logic_vector(BLOCK_SIZE-1 downto 0);
  type round_const_type is array (0 to 11) of std_logic_vector(BLOCK_SIZE-1 downto 0);
  type sbox_type is array (0 to 15) of std_logic_vector(3 downto 0);
  type shift_rows_type is array (0 to 15) of integer;

  signal MsgCorexD        : std_logic_vector(BLOCK_SIZE-1 downto 0);
  signal CiphertextCorexD : std_logic_vector(BLOCK_SIZE-1 downto 0);

  signal InRxD                       : state_type;
  signal OutRxD                      : state_type;
  signal Key0xD, Key0PrimexD, Key1xD : std_logic_vector(63 downto 0);

  signal AfterSBoxxD, AfterMatrixxD, AfterRoundConstxD, AfterKeyAddxD : state_type;

  signal OutRxDP, OutRxDN : std_logic_vector(63 downto 0);

  constant AlphaxD : std_logic_vector(63 downto 0) := x"c0ac29b7c97c50dd";

  constant RoundConstxD : round_const_type := (
    (x"0000000000000000"),
    (x"13198a2e03707344"),
    (x"a4093822299f31d0"),
    (x"082efa98ec4e6c89"),
    (x"452821e638d01377"),
    (x"be5466cf34e90c6c"),
    (x"7ef84f78fd955cb1"),
    (x"85840851f1ac43aa"),
    (x"c882d32f25323c54"),
    (x"64a51195e0e3610d"),
    (x"d3b5a399ca0c2399"),
    (x"c0ac29b7c97c50dd"));

  constant SboxxD : sbox_type := (
    (x"B"), (x"F"), (x"3"), (x"2"),
    (x"A"), (x"C"), (x"9"), (x"1"),
    (x"6"), (x"7"), (x"8"), (x"0"),
    (x"E"), (x"5"), (x"D"), (x"4"));

  constant InvSboxxD : sbox_type := (
    (x"B"), (x"7"), (x"3"), (x"2"),
    (x"F"), (x"D"), (x"8"), (x"9"),
    (x"A"), (x"6"), (x"4"), (x"0"),
    (x"5"), (x"E"), (x"C"), (x"1"));

  constant ShiftRowsxD : shift_rows_type := (0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11);

  function SHIFT_ROWS (
    InxD : std_logic_vector(63 downto 0))
    return std_logic_vector is
    variable OutxD : std_logic_vector(63 downto 0);
    variable j     : integer;
  begin
    for i in 0 to 15 loop
      j                       := 15 - ShiftRowsxD(15 - i);
      OutxD(i*4+3 downto i*4) := InxD(j*4+3 downto j*4);
    end loop;  -- i
    return OutxD;
  end SHIFT_ROWS;

  function SHIFT_ROWS_INV (
    InxD : std_logic_vector(63 downto 0))
    return std_logic_vector is
    variable OutxD : std_logic_vector(63 downto 0);
    variable j     : integer;
  begin
    for i in 0 to 15 loop
      j                       := 15 - ShiftRowsxD(15 - i);
      OutxD(j*4+3 downto j*4) := InxD(i*4+3 downto i*4);
    end loop;  -- i
    return OutxD;
  end SHIFT_ROWS_INV;

  function SBOX (
    InxD : std_logic_vector(63 downto 0))
    return std_logic_vector is
    variable OutxD : std_logic_vector(63 downto 0);
  begin
    for i in 0 to 15 loop
      OutxD(i*4+3 downto i*4) := SboxxD(to_integer(unsigned(InxD(i*4+3 downto i*4))));
    end loop;  -- i
    return OutxD;
  end SBOX;

  function SBOX_INV (
    InxD : std_logic_vector(63 downto 0))
    return std_logic_vector is
    variable OutxD : std_logic_vector(63 downto 0);
  begin
    for i in 0 to 15 loop
      OutxD(i*4+3 downto i*4) := InvSboxxD(to_integer(unsigned(InxD(i*4+3 downto i*4))));
    end loop;  -- i
    return OutxD;
  end SBOX_INV;

  function LINEAR_MATRIX (
    InxD : std_logic_vector(63 downto 0))
    return std_logic_vector is
    variable OutxD    : std_logic_vector(63 downto 0);
    variable LinOutxD : std_logic_vector(63 downto 0);
    variable LinInxD  : std_logic_vector(63 downto 0);
  begin  -- ROTATE_STATE_WORD
    for i in 0 to 63 loop
      LinInxD(i) := InxD(63 - i);
    end loop;  -- i

    LinOutxD(0)  := LinInxD(4) xor LinInxD(8) xor LinInxD(12);
    LinOutxD(1)  := LinInxD(1) xor LinInxD(9) xor LinInxD(13);
    LinOutxD(2)  := LinInxD(2) xor LinInxD(6) xor LinInxD(14);
    LinOutxD(3)  := LinInxD(3) xor LinInxD(7) xor LinInxD(11);
    LinOutxD(4)  := LinInxD(0) xor LinInxD(4) xor LinInxD(8);
    LinOutxD(5)  := LinInxD(5) xor LinInxD(9) xor LinInxD(13);
    LinOutxD(6)  := LinInxD(2) xor LinInxD(10) xor LinInxD(14);
    LinOutxD(7)  := LinInxD(3) xor LinInxD(7) xor LinInxD(15);
    LinOutxD(8)  := LinInxD(0) xor LinInxD(4) xor LinInxD(12);
    LinOutxD(9)  := LinInxD(1) xor LinInxD(5) xor LinInxD(9);
    LinOutxD(10) := LinInxD(6) xor LinInxD(10) xor LinInxD(14);
    LinOutxD(11) := LinInxD(3) xor LinInxD(11) xor LinInxD(15);
    LinOutxD(12) := LinInxD(0) xor LinInxD(8) xor LinInxD(12);
    LinOutxD(13) := LinInxD(1) xor LinInxD(5) xor LinInxD(13);
    LinOutxD(14) := LinInxD(2) xor LinInxD(6) xor LinInxD(10);
    LinOutxD(15) := LinInxD(7) xor LinInxD(11) xor LinInxD(15);
    LinOutxD(16) := LinInxD(16) xor LinInxD(20) xor LinInxD(24);
    LinOutxD(17) := LinInxD(21) xor LinInxD(25) xor LinInxD(29);
    LinOutxD(18) := LinInxD(18) xor LinInxD(26) xor LinInxD(30);
    LinOutxD(19) := LinInxD(19) xor LinInxD(23) xor LinInxD(31);
    LinOutxD(20) := LinInxD(16) xor LinInxD(20) xor LinInxD(28);
    LinOutxD(21) := LinInxD(17) xor LinInxD(21) xor LinInxD(25);
    LinOutxD(22) := LinInxD(22) xor LinInxD(26) xor LinInxD(30);
    LinOutxD(23) := LinInxD(19) xor LinInxD(27) xor LinInxD(31);
    LinOutxD(24) := LinInxD(16) xor LinInxD(24) xor LinInxD(28);
    LinOutxD(25) := LinInxD(17) xor LinInxD(21) xor LinInxD(29);
    LinOutxD(26) := LinInxD(18) xor LinInxD(22) xor LinInxD(26);
    LinOutxD(27) := LinInxD(23) xor LinInxD(27) xor LinInxD(31);
    LinOutxD(28) := LinInxD(20) xor LinInxD(24) xor LinInxD(28);
    LinOutxD(29) := LinInxD(17) xor LinInxD(25) xor LinInxD(29);
    LinOutxD(30) := LinInxD(18) xor LinInxD(22) xor LinInxD(30);
    LinOutxD(31) := LinInxD(19) xor LinInxD(23) xor LinInxD(27);
    LinOutxD(32) := LinInxD(32) xor LinInxD(36) xor LinInxD(40);
    LinOutxD(33) := LinInxD(37) xor LinInxD(41) xor LinInxD(45);
    LinOutxD(34) := LinInxD(34) xor LinInxD(42) xor LinInxD(46);
    LinOutxD(35) := LinInxD(35) xor LinInxD(39) xor LinInxD(47);
    LinOutxD(36) := LinInxD(32) xor LinInxD(36) xor LinInxD(44);
    LinOutxD(37) := LinInxD(33) xor LinInxD(37) xor LinInxD(41);
    LinOutxD(38) := LinInxD(38) xor LinInxD(42) xor LinInxD(46);
    LinOutxD(39) := LinInxD(35) xor LinInxD(43) xor LinInxD(47);
    LinOutxD(40) := LinInxD(32) xor LinInxD(40) xor LinInxD(44);
    LinOutxD(41) := LinInxD(33) xor LinInxD(37) xor LinInxD(45);
    LinOutxD(42) := LinInxD(34) xor LinInxD(38) xor LinInxD(42);
    LinOutxD(43) := LinInxD(39) xor LinInxD(43) xor LinInxD(47);
    LinOutxD(44) := LinInxD(36) xor LinInxD(40) xor LinInxD(44);
    LinOutxD(45) := LinInxD(33) xor LinInxD(41) xor LinInxD(45);
    LinOutxD(46) := LinInxD(34) xor LinInxD(38) xor LinInxD(46);
    LinOutxD(47) := LinInxD(35) xor LinInxD(39) xor LinInxD(43);
    LinOutxD(48) := LinInxD(52) xor LinInxD(56) xor LinInxD(60);
    LinOutxD(49) := LinInxD(49) xor LinInxD(57) xor LinInxD(61);
    LinOutxD(50) := LinInxD(50) xor LinInxD(54) xor LinInxD(62);
    LinOutxD(51) := LinInxD(51) xor LinInxD(55) xor LinInxD(59);
    LinOutxD(52) := LinInxD(48) xor LinInxD(52) xor LinInxD(56);
    LinOutxD(53) := LinInxD(53) xor LinInxD(57) xor LinInxD(61);
    LinOutxD(54) := LinInxD(50) xor LinInxD(58) xor LinInxD(62);
    LinOutxD(55) := LinInxD(51) xor LinInxD(55) xor LinInxD(63);
    LinOutxD(56) := LinInxD(48) xor LinInxD(52) xor LinInxD(60);
    LinOutxD(57) := LinInxD(49) xor LinInxD(53) xor LinInxD(57);
    LinOutxD(58) := LinInxD(54) xor LinInxD(58) xor LinInxD(62);
    LinOutxD(59) := LinInxD(51) xor LinInxD(59) xor LinInxD(63);
    LinOutxD(60) := LinInxD(48) xor LinInxD(56) xor LinInxD(60);
    LinOutxD(61) := LinInxD(49) xor LinInxD(53) xor LinInxD(61);
    LinOutxD(62) := LinInxD(50) xor LinInxD(54) xor LinInxD(58);
    LinOutxD(63) := LinInxD(55) xor LinInxD(59) xor LinInxD(63);

    for i in 0 to 63 loop
      OutxD(i) := LinOutxD(63 - i);
    end loop;  -- i

    return OutxD;
  end LINEAR_MATRIX;
begin  -- architecture structural

  decryption_key : if DECRYPTION generate
    Key0xD      <= (Key0xDI(0 downto 0) & Key0xDI(63 downto 1)) xor ((62 downto 0 => '0') & Key0xDI(63 downto 63));
    Key0PrimexD <= Key0xDI;
    Key1xD      <= Key1xDI xor AlphaxD;
  end generate;

  encryption_key : if not DECRYPTION generate
    Key0xD      <= Key0xDI;
    Key0PrimexD <= (Key0xDI(0 downto 0) & Key0xDI(63 downto 1)) xor ((62 downto 0 => '0') & Key0xDI(63 downto 63));
    Key1xD      <= Key1xDI;
  end generate;

  data_reg : entity work.register_stage
    generic map(
      WIDTH      => 64,
      REGISTERED => true
      )
    port map (
      clk    => ClkxCI,
      resetn => RstxRBI,

      in_data  => OutRxDN,
      in_valid => in_valid,
      in_ready => in_ready,

      out_data  => OutRxDP,
      out_valid => out_valid,
      out_ready => out_ready
      );

  --sync: process
  --begin
  --  wait until rising_edge(ClkxCI);
  --  if RstxRBI = '0' then
  --    OutRxDP <= (others => '0');
  --  else
  --    OutRxDP <= OutRxDN;
  --  end if;
  --end process;

  MsgCorexD        <= MessagexDI xor Key0xD;
  CiphertextxDO    <= CiphertextCorexD xor Key0PrimexD;
  CiphertextCorexD <= OutRxD(10) xor RoundConstxD(11) xor Key1xD;

  InRxD(1) <= MsgCorexD xor Key1xD xor RoundConstxD(0);
  InRxD(2) <= OutRxD(1);
  InRxD(3) <= OutRxD(2);
  InRxD(4) <= OutRxD(3);
  InRxD(5) <= OutRxD(4);

  InRxD(6)  <= SBOX_INV(LINEAR_MATRIX(SBOX(OutRxDP)));
  InRxD(7)  <= OutRxD(6);
  InRxD(8)  <= OutRxD(7);
  InRxD(9)  <= OutRxD(8);
  InRxD(10) <= OutRxD(9);

  R1to5 : for i in 1 to 4 generate
    AfterSBoxxD(i)       <= SBOX(InRxD(i));
    AfterMatrixxD(i)     <= SHIFT_ROWS(LINEAR_MATRIX(AfterSBoxxD(i)));
    AfterRoundConstxD(i) <= AfterMatrixxD(i) xor RoundConstxD(i);
    AfterKeyAddxD(i)     <= AfterRoundConstxD(i) xor Key1xD;
    OutRxD(i)            <= AfterKeyAddxD(i);
  end generate R1to5;

  AfterSBoxxD(5)       <= SBOX(InRxD(5));
  AfterMatrixxD(5)     <= SHIFT_ROWS(LINEAR_MATRIX(AfterSBoxxD(5)));
  AfterRoundConstxD(5) <= AfterMatrixxD(5) xor RoundConstxD(5);
  AfterKeyAddxD(5)     <= AfterRoundConstxD(5) xor Key1xD;
  OutRxDN              <= AfterKeyAddxD(5);

  R6to10 : for i in 6 to 10 generate
    AfterKeyAddxD(i)     <= InRxD(i) xor Key1xD;
    AfterRoundConstxD(i) <= AfterKeyAddxD(i) xor RoundConstxD(i);
    AfterMatrixxD(i)     <= LINEAR_MATRIX(SHIFT_ROWS_INV(AfterRoundConstxD(i)));
    AfterSBoxxD(i)       <= SBOX_INV(AfterMatrixxD(i));
    OutRxD(i)            <= AfterSBoxxD(i);
  end generate R6to10;

end architecture structural;
