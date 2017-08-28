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

entity qarma is
  generic(
    DECRYPTION : boolean := false;
    ROUNDS     : integer := 7
    );
  port(
    ClkxCI        : in  std_logic;
    RstxRBI       : in  std_logic;
    KeyxDI        : in  std_logic_vector(127 downto 0);
    TweakxDI      : in  std_logic_vector(63 downto 0);
    MessagexDI    : in  std_logic_vector(63 downto 0);
    CiphertextxDO : out std_logic_vector(63 downto 0);

    in_ready  : out std_logic;
    in_valid  : in  std_logic;
    out_ready : in  std_logic;
    out_valid : out std_logic
    );
end qarma;

architecture Behavioral of qarma is
  signal W0xD, K0xD : std_logic_vector(63 downto 0);
  signal W1xD, K1xD : std_logic_vector(63 downto 0);

  type sbox_type is array (0 to 15) of std_logic_vector(3 downto 0);
  type permutation_type is array(0 to 15) of integer range 0 to 15;
  type round_const_type is array (0 to 7) of std_logic_vector(63 downto 0);
  type state_type is array (0 to ROUNDS) of std_logic_vector(63 downto 0);

  signal State0xD, State1xD             : state_type;
  signal StateMiddle0xD, StateMiddle1xD : std_logic_vector(63 downto 0);
  signal TweakxD                        : state_type;

  signal RegisterInxD, RegisterOutxD           : std_logic_vector(63 downto 0);
  signal RegisterInReadyxS, RegisterOutReadyxS : std_logic;
  signal RegisterInValidxS, RegisterOutValidxS : std_logic;

  constant AlphaxD : std_logic_vector(63 downto 0) := x"c0ac29b7c97c50dd";

  constant RoundConstxD : round_const_type := (
    (x"0000000000000000"),
    (x"13198a2e03707344"),
    (x"a4093822299f31d0"),
    (x"082efa98ec4e6c89"),
    (x"452821e638d01377"),
    (x"be5466cf34e90c6c"),
    (x"3F84D5B5B5470917"),
    (x"9216D5D98979FB1B"));

  -- Sigma1 is an involution
  constant SboxSigma1xD : sbox_type := (
    (x"A"), (x"D"), (x"E"), (x"6"),
    (x"F"), (x"7"), (x"3"), (x"5"),
    (x"9"), (x"8"), (x"0"), (x"C"),
    (x"B"), (x"1"), (x"2"), (x"4"));

  constant InvSboxSigma1xD : sbox_type := (
    (x"A"), (x"D"), (x"E"), (x"6"),
    (x"F"), (x"7"), (x"3"), (x"5"),
    (x"9"), (x"8"), (x"0"), (x"C"),
    (x"B"), (x"1"), (x"2"), (x"4"));

  constant PermTauxD : permutation_type := (
       0, 11,  6, 13,
      10,  1, 12,  7,
       5, 14,  3,  8,
      15,  4,  9,  2);

  constant PermTauInvxD : permutation_type := (
       0,  5, 15, 10,
      13,  8,  2,  7,
      11, 14,  4,  1,
       6,  3,  9, 12);

  constant PermHxD : permutation_type := (
       6,  5, 14, 15,
       0,  1,  2,  3,
       7, 12, 13,  4,
       8,  9, 10, 11);

  constant PermHInvxD : permutation_type := (
       4,  5,  6,  7,
      11,  1,  0,  8,
      12, 13, 14, 15,
       9, 10,  2,  3);

  function LFSR(
    InxD : std_logic_vector(3 downto 0))
    return std_logic_vector is
    variable OutxD : std_logic_vector(3 downto 0);
  begin
    OutxD(2 downto 0) := InxD(3 downto 1);
    OutxD(3)          := InxD(0) xor InxD(1);
    return OutxD;
  end LFSR;

  function LFSR_OMEGA(
    InxD : std_logic_vector(63 downto 0))
    return std_logic_vector is
    variable OutxD : std_logic_vector(63 downto 0);
  begin
    OutxD               := InxD;
    OutxD(63 downto 60) := LFSR(InxD(63 downto 60));  -- 0
    OutxD(59 downto 56) := LFSR(InxD(59 downto 56));  -- 1
    OutxD(51 downto 48) := LFSR(InxD(51 downto 48));  -- 3
    OutxD(47 downto 44) := LFSR(InxD(47 downto 44));  -- 4
    OutxD(31 downto 28) := LFSR(InxD(31 downto 28));  -- 8
    OutxD(19 downto 16) := LFSR(InxD(19 downto 16));  -- 11
    OutxD(11 downto 8)  := LFSR(InxD(11 downto 8));   -- 13
    return OutxD;
  end LFSR_OMEGA;

  function FUNC_O(
    InxD : std_logic_vector(63 downto 0))
    return std_logic_vector is
    variable OutxD : std_logic_vector(63 downto 0);
  begin
    OutxD    := InxD(0) & InxD(63 downto 1);
    OutxD(0) := OutxD(0) xor InxD(63);
    return OutxD;
  end FUNC_O;

  function SUB_CELLS (
    InxD : std_logic_vector(63 downto 0))
    return std_logic_vector is
    variable OutxD : std_logic_vector(63 downto 0);
  begin
    for i in 0 to 15 loop
      OutxD(i*4+3 downto i*4) := SboxSigma1xD(to_integer(unsigned(InxD(i*4+3 downto i*4))));
    end loop;  -- i
    return OutxD;
  end SUB_CELLS;

  function INV_SUB_CELLS (
    InxD : std_logic_vector(63 downto 0))
    return std_logic_vector is
    variable OutxD : std_logic_vector(63 downto 0);
  begin
    for i in 0 to 15 loop
      OutxD(i*4+3 downto i*4) := InvSboxSigma1xD(to_integer(unsigned(InxD(i*4+3 downto i*4))));
    end loop;  -- i
    return OutxD;
  end INV_SUB_CELLS;

  function SHUFFLE_CELLS (
    InxD : std_logic_vector(63 downto 0))
    return std_logic_vector is
    variable OutxD      : std_logic_vector(63 downto 0);
    variable index_dest : integer;
    variable index_src  : integer;
  begin
    for i in 0 to 15 loop
      index_dest                                := 15-i;
      index_src                                 := 15-PermTauxD(i);
      OutxD(index_dest*4+3 downto index_dest*4) := InxD(index_src*4+3 downto index_src*4);
    end loop;  -- i
    return OutxD;
  end SHUFFLE_CELLS;

  function INV_SHUFFLE_CELLS (
    InxD : std_logic_vector(63 downto 0))
    return std_logic_vector is
    variable OutxD      : std_logic_vector(63 downto 0);
    variable index_dest : integer;
    variable index_src  : integer;
  begin
    for i in 0 to 15 loop
      index_dest                                := 15-i;
      index_src                                 := 15-PermTauInvxD(i);
      OutxD(index_dest*4+3 downto index_dest*4) := InxD(index_src*4+3 downto index_src*4);
    end loop;  -- i
    return OutxD;
  end INV_SHUFFLE_CELLS;

  function PERMUTATION_H (
    InxD : std_logic_vector(63 downto 0))
    return std_logic_vector is
    variable OutxD      : std_logic_vector(63 downto 0);
    variable index_dest : integer;
    variable index_src  : integer;
  begin
    for i in 0 to 15 loop
      index_dest                                := 15-i;
      index_src                                 := 15-PermHxD(i);
      OutxD(index_dest*4+3 downto index_dest*4) := InxD(index_src*4+3 downto index_src*4);
    end loop;  -- i
    return OutxD;
  end PERMUTATION_H;

  function PERMUTATION_H_INV (
    InxD : std_logic_vector(63 downto 0))
    return std_logic_vector is
    variable OutxD      : std_logic_vector(63 downto 0);
    variable index_dest : integer;
    variable index_src  : integer;
  begin
    for i in 0 to 15 loop
      index_dest                                := 15-i;
      index_src                                 := 15-PermHInvxD(i);
      OutxD(index_dest*4+3 downto index_dest*4) := InxD(index_src*4+3 downto index_src*4);
    end loop;  -- i
    return OutxD;
  end PERMUTATION_H_INV;

  function ROTATE_LEFT(
    InxD     : std_logic_vector(3 downto 0);
    rotation : integer)
    return std_logic_vector is
    variable OutxD : std_logic_vector(3 downto 0);
  begin
    OutxD(3 downto ROTATION)   := InxD(3-ROTATION downto 0);
    OutxD(ROTATION-1 downto 0) := InxD(3 downto 4-ROTATION);
    return OutxD;
  end ROTATE_LEFT;

  function MULTIPLY_M4_2 (
    InxD : std_logic_vector(15 downto 0))
    return std_logic_vector is
    variable OutxD : std_logic_vector(15 downto 0);
  begin
    OutxD(15 downto 12) := ROTATE_LEFT(InxD(11 downto 8), 1) xor ROTATE_LEFT(InxD(7 downto 4), 2) xor ROTATE_LEFT(InxD(3 downto 0), 1);
    OutxD(11 downto 8)  := ROTATE_LEFT(InxD(15 downto 12), 1) xor ROTATE_LEFT(InxD(7 downto 4), 1) xor ROTATE_LEFT(InxD(3 downto 0), 2);
    OutxD(7 downto 4)   := ROTATE_LEFT(InxD(15 downto 12), 2) xor ROTATE_LEFT(InxD(11 downto 8), 1) xor ROTATE_LEFT(InxD(3 downto 0), 1);
    OutxD(3 downto 0)   := ROTATE_LEFT(InxD(15 downto 12), 1) xor ROTATE_LEFT(InxD(11 downto 8), 2) xor ROTATE_LEFT(InxD(7 downto 4), 1);
    return OutxD;
  end MULTIPLY_M4_2;

  function MIX_COLUMNS (
    InxD : std_logic_vector(63 downto 0))
    return std_logic_vector is
    variable OutxD       : std_logic_vector(63 downto 0);
    variable ColumnInxD  : std_logic_vector(15 downto 0);
    variable ColumnOutxD : std_logic_vector(15 downto 0);
    variable i           : integer;
  begin  -- MIX COLUMNS
    for i in 0 to 3 loop
      ColumnInxD                  := InxD(i*4+51 downto i*4+48) & InxD(i*4+35 downto i*4+32) & InxD(i*4+19 downto i*4+16) & InxD(i*4+3 downto i*4);
      ColumnOutxD                 := MULTIPLY_M4_2 (ColumnInxD);
      OutxD(i*4+51 downto i*4+48) := ColumnOutxD(15 downto 12);
      OutxD(i*4+35 downto i*4+32) := ColumnOutxD(11 downto 8);
      OutxD(i*4+19 downto i*4+16) := ColumnOutxD(7 downto 4);
      OutxD(i*4+3 downto i*4)     := ColumnOutxD(3 downto 0);
    end loop;  -- i
    return OutxD;
  end MIX_COLUMNS;


  function ROUND (
    InStatexD    : std_logic_vector(63 downto 0);
    InTweakKeyxD : std_logic_vector(63 downto 0))
    return std_logic_vector is
    variable OutxD      : std_logic_vector(63 downto 0);
    variable AdditionxD : std_logic_vector(63 downto 0);
    variable ShuffledxD : std_logic_vector(63 downto 0);
    variable MixingxD   : std_logic_vector(63 downto 0);
  begin  -- ROUND
    AdditionxD := InStatexD xor InTweakKeyxD;
    ShuffledxD := SHUFFLE_CELLS(AdditionxD);
    MixingxD   := MIX_COLUMNS(ShuffledxD);
    OutxD      := SUB_CELLS(MixingxD);
    return OutxD;
  end ROUND;

  function ROUND_SHORT (
    InStatexD    : std_logic_vector(63 downto 0);
    InTweakKeyxD : std_logic_vector(63 downto 0))
    return std_logic_vector is
    variable AdditionxD : std_logic_vector(63 downto 0);
    variable OutxD      : std_logic_vector(63 downto 0);
  begin  -- ROUND_SHORT
    AdditionxD := InStatexD xor InTweakKeyxD;
    OutxD      := SUB_CELLS(AdditionxD);
    return OutxD;
  end ROUND_SHORT;

  function ROUND_INV (
    InStatexD    : std_logic_vector(63 downto 0);
    InTweakKeyxD : std_logic_vector(63 downto 0))
    return std_logic_vector is
    variable SubstitutionxD : std_logic_vector(63 downto 0);
    variable MixingxD       : std_logic_vector(63 downto 0);
    variable ShufflingxD    : std_logic_vector(63 downto 0);
    variable OutxD          : std_logic_vector(63 downto 0);
  begin  -- ROUND_INV
    SubstitutionxD := INV_SUB_CELLS(InStatexD);
    MixingxD       := MIX_COLUMNS(SubstitutionxD);
    ShufflingxD    := INV_SHUFFLE_CELLS(MixingxD);
    OutxD          := ShufflingxD xor InTweakKeyxD;
    return OutxD;
  end ROUND_INV;

  function ROUND_INV_SHORT (
    InStatexD    : std_logic_vector(63 downto 0);
    InTweakKeyxD : std_logic_vector(63 downto 0))
    return std_logic_vector is
    variable SubstitutionxD : std_logic_vector(63 downto 0);
    variable OutxD          : std_logic_vector(63 downto 0);
  begin  -- ROUND_INV_SHORT
    SubstitutionxD := INV_SUB_CELLS(InStatexD);
    OutxD          := SubstitutionxD xor InTweakKeyxD;
    return OutxD;
  end ROUND_INV_SHORT;

  function PSEUDO_REFLECTOR (
    InStatexD    : std_logic_vector(63 downto 0);
    InTweakKeyxD : std_logic_vector(63 downto 0))
    return std_logic_vector is
    variable ShufflingxD : std_logic_vector(63 downto 0);
    variable MultiplyxD  : std_logic_vector(63 downto 0);
    variable AdditionxD  : std_logic_vector(63 downto 0);
    variable OutxD       : std_logic_vector(63 downto 0);
  begin  -- PSEUDO_REFLECTOR
    ShufflingxD := SHUFFLE_CELLS(InStatexD);
    MultiplyxD  := MIX_COLUMNS(ShufflingxD);
    AdditionxD  := MultiplyxD xor InTweakKeyxD;
    OutxD       := INV_SHUFFLE_CELLS(AdditionxD);
    return OutxD;
  end PSEUDO_REFLECTOR;

begin

  encryption_properties : if not(DECRYPTION) generate
    W0xD <= KeyxDI(127 downto 64);
    K0xD <= KeyxDI(63 downto 0);
    W1xD <= FUNC_O(W0xD);
    K1xD <= K0xD;
  end generate;

  decryption_properties : if DECRYPTION generate
    W1xD <= KeyxDI(127 downto 64);
    K0xD <= KeyxDI(63 downto 0) xor AlphaxD;
    W0xD <= FUNC_O(W1xD);
    K1xD <= MIX_COLUMNS(KeyxDI(63 downto 0));
  end generate;

  State0xD(0) <= MessagexDI xor W0xD;
  TweakxD(0)  <= TweakxDI;

  State0xD(1) <= ROUND_SHORT(State0xD(0), K0xD xor TweakxD(0) xor RoundConstxD(0));
  TweakxD(1)  <= LFSR_OMEGA(PERMUTATION_H(TweakxD(0)));

  rounds_0 : for r in 1 to ROUNDS-1 generate
    State0xD(r+1) <= ROUND(State0xD(r), K0xD xor TweakxD(r) xor RoundConstxD(r));
    TweakxD(r+1)  <= LFSR_OMEGA(PERMUTATION_H(TweakxD(r)));
  end generate rounds_0;


  StateMiddle0xD <= ROUND(State0xD(ROUNDS), W1xD xor TweakxD(ROUNDS));
  StateMiddle1xD <= PSEUDO_REFLECTOR(StateMiddle0xD, K1xD);

  RegisterInxD      <= StateMiddle1xD;
  RegisterInValidxS <= in_valid;
  in_ready          <= RegisterInReadyxS;

  out_valid          <= RegisterOutValidxS;
  RegisterOutReadyxS <= out_ready;
  State1xD(0)        <= ROUND_INV(RegisterOutxD, W0xD xor TweakxD(ROUNDS));

  internal_reg : entity work.register_stage
    generic map(
      WIDTH      => 64,
      REGISTERED => true
      )
    port map(
      clk    => ClkxCI,
      resetn => RstxRBI,

      in_data  => RegisterInxD,
      in_valid => RegisterInValidxS,
      in_ready => RegisterInReadyxS,

      out_data  => RegisterOutxD,
      out_valid => RegisterOutValidxS,
      out_ready => RegisterOutReadyxS
      );

  rounds_1 : for r in 0 to ROUNDS-2 generate
    State1xD(r+1) <= ROUND_INV(State1xD(r), K0xD xor TweakxD(ROUNDS-1-r) xor RoundConstxD(ROUNDS-1-r) xor AlphaxD);
  end generate rounds_1;

  State1xD(ROUNDS) <= ROUND_INV_SHORT(State1xD(ROUNDS-1), K0xD xor TweakxD(0) xor RoundConstxD(0) xor AlphaxD);

  CiphertextxDO <= State1xD(ROUNDS) xor W1xD;
end Behavioral;
