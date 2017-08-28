-------------------------------------------------------------------------------
-- Title      : A generic implementation of Ascon
-- Project    : 
-------------------------------------------------------------------------------
-- File       : 
-- Author     : Hannes Gross <hannes.gross@iaik.tugraz.at>
-- Company    : 
-- Created    : 2016-05-25
-- Last update: 2016-06-14
-- Platform   : 
-- Standard   : VHDL'93/02
-------------------------------------------------------------------------------
-- Description: 
-------------------------------------------------------------------------------
-- Copyright 2014 Graz University of Technology
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
-------------------------------------------------------------------------------
-- Revisions  :
-- Date        Version  Author           Description
-- 2016-05-25  1.0      Hannes Gross     Created
-- 2017-??-??  1.1      T. Unterluggauer Updated to Ascon 1.2 and removed bus
--                                       interface for nonces
-------------------------------------------------------------------------------

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity ascon is
  generic (
    UNROLED_ROUNDS  : integer := 1;  -- 1,2,3 or 6 for Ascon-128; 1,2,4 for Ascon-128a
    DATA_BLOCK_SIZE : integer := 64;  -- 64 or 128, (selects between Ascon-128 and Ascon-128a)
    ROUNDS_A        : integer := 12;    -- 12 for Ascon-128 and Ascon-128a
    ROUNDS_B        : integer := 6;     -- 6 for Ascon-128, 8 for Ascon-128a
    DATA_BUS_WIDTH  : integer := 64);  -- 64 or 128 (limits the max nonce size)
  port (
    ClkxCI             : in  std_logic;
    RstxRBI            : in  std_logic;
    KeyxDI             : in  std_logic_vector(127 downto 0);
    CP_InitxSI         : in  std_logic;
    CP_AssociatexSI    : in  std_logic;
    CP_EncryptxSI      : in  std_logic;
    CP_DecryptxSI      : in  std_logic;
    CP_FinalEncryptxSI : in  std_logic;
    CP_FinalDecryptxSI : in  std_logic;
    DataWritexDI       : in  std_logic_vector(DATA_BUS_WIDTH-1 downto 0);
    IODataxDO          : out std_logic_vector(DATA_BLOCK_SIZE-1 downto 0);
    CP_DonexSO         : out std_logic;
    TagxDO             : out std_logic_vector(127 downto 0)
    );

end entity ascon;

architecture structural of ascon is
  constant CONTROL_STATE_SIZE : integer := 4;
  constant STATE_WORD_SIZE    : integer := 64;
  constant KEY_SIZE           : integer := 128;

  constant CONST_UNROLED_R : std_logic_vector(7 downto 0) := std_logic_vector(to_unsigned(UNROLED_ROUNDS, 8));
  constant CONST_KEY_SIZE  : std_logic_vector(7 downto 0) := std_logic_vector(to_unsigned(KEY_SIZE, 8));
  constant CONST_ROUNDS_A  : std_logic_vector(7 downto 0) := std_logic_vector(to_unsigned(ROUNDS_A, 8));
  constant CONST_ROUNDS_B  : std_logic_vector(7 downto 0) := std_logic_vector(to_unsigned(ROUNDS_B, 8));
  constant CONST_RATE      : std_logic_vector(7 downto 0) := std_logic_vector(to_unsigned(DATA_BLOCK_SIZE, 8));

  signal State0xDP, State0xDN             : std_logic_vector(STATE_WORD_SIZE-1 downto 0);
  signal State1xDP, State1xDN             : std_logic_vector(STATE_WORD_SIZE-1 downto 0);
  signal State2xDP, State2xDN             : std_logic_vector(STATE_WORD_SIZE-1 downto 0);
  signal State3xDP, State3xDN             : std_logic_vector(STATE_WORD_SIZE-1 downto 0);
  signal State4xDP, State4xDN             : std_logic_vector(STATE_WORD_SIZE-1 downto 0);
  signal ControlStatexDP, ControlStatexDN : std_logic_vector(CONTROL_STATE_SIZE-1 downto 0);

  signal DP_ControlStatexD                                    : std_logic_vector(CONTROL_STATE_SIZE-1 downto 0);
  signal DP_InitxS                                            : std_logic;
  signal DP_XorZKeyxS                                         : std_logic;
  signal DP_XorKeyZxS                                         : std_logic;
  signal DP_XorZOnexS                                         : std_logic;
  signal DP_EncryptxS                                         : std_logic;
  signal DP_DecryptxS                                         : std_logic;
  signal DP_AssociatexS                                       : std_logic;
  signal CP_DonexS                                            : std_logic;
  signal DP_RoundxSN, DP_RoundxSP                             : std_logic;
  signal CP_FinalAssociatedDataxSN, CP_FinalAssociatedDataxSP : std_logic;

  function ZEROS (
    constant WIDTH : natural)
    return std_logic_vector is
    variable x : std_logic_vector(WIDTH-1 downto 0);
  begin  -- ZEROS
    x := (others => '0');
    return x;
  end ZEROS;

  function ROTATE_STATE_WORD (
    word            : std_logic_vector(STATE_WORD_SIZE-1 downto 0);
    constant rotate : integer)
    return std_logic_vector is
    variable x : std_logic_vector(STATE_WORD_SIZE-1 downto 0);
  begin  -- ROTATE_STATE_WORD
    x := word(ROTATE-1 downto 0) & word(STATE_WORD_SIZE-1 downto ROTATE);
    return x;
  end ROTATE_STATE_WORD;

begin  -- architecture structural
  CP_DonexSO <= CP_DonexS;

  -- purpose: Defines all registers
  -- type   : sequential
  -- inputs : ClkxCI, RstxRBI, *xDN signals
  -- outputs: *xDP signals
  RegisterProc : process (ClkxCI, RstxRBI) is
  begin  -- process RegisterProc
    if RstxRBI = '0' then               -- asynchronous reset (active low)
      State0xDP                 <= (others => '0');
      State1xDP                 <= (others => '0');
      State2xDP                 <= (others => '0');
      State3xDP                 <= (others => '0');
      State4xDP                 <= (others => '0');
      ControlStatexDP           <= (others => '0');
      CP_FinalAssociatedDataxSP <= '0';
      DP_RoundxSP               <= '0';
    elsif ClkxCI'event and ClkxCI = '1' then  -- rising clock edge
      State0xDP                 <= State0xDN;
      State1xDP                 <= State1xDN;
      State2xDP                 <= State2xDN;
      State3xDP                 <= State3xDN;
      State4xDP                 <= State4xDN;
      ControlStatexDP           <= ControlStatexDN;
      CP_FinalAssociatedDataxSP <= CP_FinalAssociatedDataxSN;
      DP_RoundxSP               <= DP_RoundxSN;
    end if;
  end process RegisterProc;

  -- purpose: Controlpath of Ascon
  -- type   : combinational
  ControlProc : process (CP_AssociatexSI, CP_DecryptxSI, CP_EncryptxSI,
                         CP_FinalAssociatedDataxSP, CP_FinalDecryptxSI,
                         CP_FinalEncryptxSI, CP_InitxSI, ControlStatexDP) is
    variable ControlStatexDV : integer;
  begin  -- process ControlProc

    CP_FinalAssociatedDataxSN <= CP_FinalAssociatedDataxSP;

    DP_InitxS      <= '0';
    DP_RoundxSN    <= '0';
    DP_XorZKeyxS   <= '0';
    DP_XorKeyZxS   <= '0';
    DP_XorZOnexS   <= '0';
    DP_EncryptxS   <= '0';
    DP_DecryptxS   <= '0';
    CP_DonexS      <= '0';
    DP_AssociatexS <= '0';

    ControlStatexDV   := to_integer(unsigned(ControlStatexDP));
    ControlStatexDN   <= ControlStatexDP;
    DP_ControlStatexD <= ControlStatexDP;

    if ControlStatexDV = 0 then
      DP_InitxS      <= CP_InitxSI;
      DP_AssociatexS <= CP_AssociatexSI;
      DP_EncryptxS   <= CP_EncryptxSI or CP_FinalEncryptxSI;
      DP_DecryptxS   <= CP_DecryptxSI or CP_FinalDecryptxSI;
      DP_XorKeyZxS   <= CP_FinalEncryptxSI or CP_FinalDecryptxSI;

      if CP_InitxSI = '1' then
        CP_FinalAssociatedDataxSN <= '0';
      end if;
      if (CP_EncryptxSI = '1') or (CP_DecryptxSI = '1') or (CP_FinalEncryptxSI = '1') or (CP_FinalDecryptxSI = '1') then
        CP_FinalAssociatedDataxSN <= '1';
        if CP_FinalAssociatedDataxSP = '0' then
          DP_XorZOnexS <= '1';
        end if;
      end if;
    end if;

    if (CP_InitxSI = '1') or (CP_AssociatexSI = '1') or (CP_EncryptxSI = '1') or (CP_DecryptxSI = '1') or (CP_FinalEncryptxSI = '1') or (CP_FinalDecryptxSI = '1') then
      ControlStatexDN <= std_logic_vector(unsigned(ControlStatexDP) + UNROLED_ROUNDS);
      DP_RoundxSN     <= '1';
    end if;

    if ((CP_InitxSI = '1') or (CP_FinalEncryptxSI = '1') or (CP_FinalDecryptxSI = '1')) and (ControlStatexDV = ROUNDS_A-UNROLED_ROUNDS) then
      ControlStatexDN <= (others => '0');
      DP_XorZKeyxS    <= '1';
      CP_DonexS       <= '1';
    end if;

    if ((CP_AssociatexSI = '1') or (CP_EncryptxSI = '1') or (CP_DecryptxSI = '1')) and (ControlStatexDV = ROUNDS_B-UNROLED_ROUNDS) then
      ControlStatexDN <= (others => '0');
      CP_DonexS       <= '1';
    end if;

    if CP_FinalEncryptxSI = '1' or CP_InitxSI = '1' or CP_FinalDecryptxSI = '1' then
      DP_ControlStatexD <= std_logic_vector(unsigned(ControlStatexDP) + (12-ROUNDS_A));
    end if;

    if CP_AssociatexSI = '1' or CP_EncryptxSI = '1' or CP_DecryptxSI = '1' then
      DP_ControlStatexD <= std_logic_vector(unsigned(ControlStatexDP) + (12-ROUNDS_B));
    end if;
  end process ControlProc;

  -- purpose: Datapath of Ascon
  -- type   : combinational
  DatapathProc : process (DP_AssociatexS, DP_ControlStatexD,
                          DP_DecryptxS, DP_EncryptxS, DP_InitxS, DP_RoundxSN,
                          DP_XorKeyZxS, DP_XorZKeyxS, DP_XorZOnexS,
                          DataWritexDI, KeyxDI, State0xDP, State1xDP, State2xDP,
                          State3xDP, State4xDP) is
    variable P0xDV, P1xDV, P2xDV, P3xDV, P4xDV : std_logic_vector(STATE_WORD_SIZE-1 downto 0);
    variable R0xDV, R1xDV, R2xDV, R3xDV, R4xDV : std_logic_vector(STATE_WORD_SIZE-1 downto 0);
    variable S0xDV, S1xDV, S2xDV, S3xDV, S4xDV : std_logic_vector(STATE_WORD_SIZE-1 downto 0);
    variable T0xDV, T1xDV, T2xDV, T3xDV, T4xDV : std_logic_vector(STATE_WORD_SIZE-1 downto 0);
    variable U0xDV, U1xDV, U2xDV, U3xDV, U4xDV : std_logic_vector(STATE_WORD_SIZE-1 downto 0);
    variable RoundConstxDV                     : std_logic_vector(63 downto 0);
    variable State0XorIODataxDV                : std_logic_vector(63 downto 0);
    variable State1XorIODataxDV                : std_logic_vector(63 downto 0);
  begin  -- process DatapathProc

    -- default
    State0xDN <= State0xDP;
    State1xDN <= State1xDP;
    State2xDN <= State2xDP;
    State3xDN <= State3xDP;
    State4xDN <= State4xDP;

    P0xDV := State0xDP;
    P1xDV := State1xDP;
    P2xDV := State2xDP;
    P3xDV := State3xDP;
    P4xDV := State4xDP;

    if DP_InitxS = '1' then
      P0xDV := CONST_KEY_SIZE & CONST_RATE & CONST_ROUNDS_A & CONST_ROUNDS_B & ZEROS(32);
      P1xDV := KeyxDI(127 downto 64);
      P2xDV := KeyxDI(63 downto 0);
      -- directly use nonce from DataWrite input
      if DATA_BUS_WIDTH = 128 then
        P3xDV := DataWritexDI(127 downto 64);
      else
        -- when a 64-bit data bus is used, also only 64-bit nonces possible
        P3xDV := (others => '0');
      end if;
      P4xDV := DataWritexDI(63 downto 0);
    end if;

    TagxDO <= State3xDP & State4xDP;
    --- for 128 variant
    if DATA_BLOCK_SIZE = 64 then
      State0XorIODataxDV := State0xDP xor DataWritexDI(63 downto 0);
      IODataxDO          <= State0XorIODataxDV;

      -- finalization
      if DP_XorKeyZxS = '1' then
        P1xDV := State1xDP xor KeyxDI(127 downto 64);
        P2xDV := State2xDP xor KeyxDI(63 downto 0);
      end if;

      if (DP_EncryptxS = '1') or (DP_AssociatexS = '1') then
        P0xDV := State0XorIODataxDV;
      end if;
    -- for 128a variant
    elsif DATA_BLOCK_SIZE = 128 then
      State0XorIODataxDV := State0xDP xor DataWritexDI(127 downto 64);
      State1XorIODataxDV := State1xDP xor DataWritexDI(63 downto 0);
      IODataxDO          <= State0XorIODataxDV & State1XorIODataxDV;

      -- finalization
      if DP_XorKeyZxS = '1' then
        P2xDV := State2xDP xor KeyxDI(127 downto 64);
        P3xDV := State3xDP xor KeyxDI(63 downto 0);
      end if;

      if (DP_EncryptxS = '1') or (DP_AssociatexS = '1') then
        P0xDV := State0XorIODataxDV;
        P1xDV := State1XorIODataxDV;
      end if;
    end if;

    P4xDV(0) := P4xDV(0) xor DP_XorZOnexS;

    if DP_DecryptxS = '1' then
      P0xDV := DataWritexDI(63 downto 0);
    end if;

    -- Unrole combinatorial path
    for r in 0 to UNROLED_ROUNDS-1 loop
      RoundConstxDV := ZEROS(64-8) & not std_logic_vector(unsigned(DP_ControlStatexD(3 downto 0)) + r) & std_logic_vector(unsigned(DP_ControlStatexD(3 downto 0)) + r);

      R0xDV := P0xDV xor P4xDV;
      R1xDV := P1xDV;
      R2xDV := P2xDV xor P1xDV xor RoundConstxDV;
      R3xDV := P3xDV;
      R4xDV := P4xDV xor P3xDV;

      S0xDV := R0xDV xor (not R1xDV and R2xDV);
      S1xDV := R1xDV xor (not R2xDV and R3xDV);
      S2xDV := R2xDV xor (not R3xDV and R4xDV);
      S3xDV := R3xDV xor (not R4xDV and R0xDV);
      S4xDV := R4xDV xor (not R0xDV and R1xDV);

      T0xDV := S0xDV xor S4xDV;
      T1xDV := S1xDV xor S0xDV;
      T2xDV := not S2xDV;
      T3xDV := S3xDV xor S2xDV;
      T4xDV := S4xDV;

      U0xDV := T0xDV xor ROTATE_STATE_WORD(T0xDV, 19) xor ROTATE_STATE_WORD(T0xDV, 28);
      U1xDV := T1xDV xor ROTATE_STATE_WORD(T1xDV, 61) xor ROTATE_STATE_WORD(T1xDV, 39);
      U2xDV := T2xDV xor ROTATE_STATE_WORD(T2xDV, 1) xor ROTATE_STATE_WORD(T2xDV, 6);
      U3xDV := T3xDV xor ROTATE_STATE_WORD(T3xDV, 10) xor ROTATE_STATE_WORD(T3xDV, 17);
      U4xDV := T4xDV xor ROTATE_STATE_WORD(T4xDV, 7) xor ROTATE_STATE_WORD(T4xDV, 41);

      P0xDV := U0xDV;
      P1xDV := U1xDV;
      P2xDV := U2xDV;
      P3xDV := U3xDV;
      P4xDV := U4xDV;
    end loop;

    if DP_XorZKeyxS = '1' then
      U3xDV := U3xDV xor KeyxDI(127 downto 64);
      U4xDV := U4xDV xor KeyxDI(63 downto 0);
    end if;

    if DP_RoundxSN = '1' then
      State0xDN <= U0xDV;
      State1xDN <= U1xDV;
      State2xDN <= U2xDV;
      State3xDN <= U3xDV;
      State4xDN <= U4xDV;
    end if;
  end process DatapathProc;

end architecture structural;
