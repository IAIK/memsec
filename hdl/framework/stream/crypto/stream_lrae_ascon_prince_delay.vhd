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

--! Encrypts or decrypts transactions in a leakage resilient AE mode.
--!
--! For tree and data nodes, an Ascon-like sponge mode is used for key stream
--! generation and authentication tag calculation. The key stream is then used
--! in a block cipher (Prince or Qarma) to perform the real encryption. Details
--! for this mode of operation can be found in the Journal version of the MEAS
--! paper. (see MEASv1)
--!
--! Regarding memory layout, first the key, second the data, and third the
--! authentication tag is expected/generated.
entity stream_lrae_ascon_prince_delay is
  generic(
    DATA_ALIGNMENT        : integer := 64;
    TREE_ALIGNMENT        : integer := 32;
    TAG_SIZE              : integer := 8;
    DECRYPTION            : boolean := false;
    OUTPUT_REGISTER       : boolean := true;
    ENC_ABSORB_CIPHERTEXT : boolean := false
    );
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    s_request       : in  StreamType;
    s_request_ready : out std_logic;

    m_request       : out StreamType;
    m_request_ready : in  std_logic
    );
end stream_lrae_ascon_prince_delay;

architecture Behavioral of stream_lrae_ascon_prince_delay is
  constant ASCON_DATA_BUS_WIDTH   : integer                                     := 128;
  constant ALIGNMENT              : integer                                     := max(DATA_ALIGNMENT, TREE_ALIGNMENT);
  constant METADATA               : integer                                     := 16;
  constant TRANSLATION_FACTOR     : integer                                     := (64/DATASTREAM_DATA_WIDTH);
  constant TRANSLATION_FACTOR_BIT : integer                                     := log2_ceil(TRANSLATION_FACTOR);
  constant MAX_COUNTER_VALUE      : unsigned(TRANSLATION_FACTOR_BIT-1 downto 0) := (others => '1');

  constant STATE_IDLE            : std_logic_vector(log2_ceil(ALIGNMENT/8) downto 0) := (others                                  => '0');
  constant STATE_INIT            : std_logic_vector(log2_ceil(ALIGNMENT/8) downto 0) := (log2_ceil(ALIGNMENT/8) downto 2         => '0') & "01";
  constant STATE_CRYPT           : std_logic_vector(log2_ceil(ALIGNMENT/8) downto 0) := '1' & (log2_ceil(ALIGNMENT/8)-1 downto 0 => '0');
  constant STATE_TREE_CRYPT_LAST : std_logic_vector(log2_ceil(ALIGNMENT/8) downto 0) := '1' & std_logic_vector(to_unsigned(TREE_ALIGNMENT/8-1, log2_ceil(ALIGNMENT/8)));
  constant STATE_CRYPT_LAST      : std_logic_vector(log2_ceil(ALIGNMENT/8) downto 0) := '1' & std_logic_vector(to_unsigned(DATA_ALIGNMENT/8-1, log2_ceil(ALIGNMENT/8)));
  constant STATE_VERIFY          : std_logic_vector(log2_ceil(ALIGNMENT/8) downto 0) := (log2_ceil(ALIGNMENT/8) downto 2         => '0') & "10";
  constant STATE_VERIFY_2        : std_logic_vector(log2_ceil(ALIGNMENT/8) downto 0) := (log2_ceil(ALIGNMENT/8) downto 2         => '0') & "11";
  signal last_block              : std_logic;

  signal enc_block                        : std_logic_vector(63 downto 0);
  signal enc_block_valid, enc_block_ready : std_logic;

  signal block64, block64_reg                       : std_logic_vector(63 downto 0);
  signal block64_offset, block64_len                : std_logic_vector(offset_width(DATASTREAM_DATA_WIDTH, 64)-1 downto 0);
  signal block64_offset_reg, block64_len_reg        : std_logic_vector(offset_width(DATASTREAM_DATA_WIDTH, 64)-1 downto 0);
  signal block64_valid, block64_ready, block64_last : std_logic;
  signal block64_last_reg                           : std_logic;
  signal block64_reg_valid, block64_reg_ready       : std_logic;

  signal block128, block128_mod                                                                : std_logic_vector(127 downto 0);
  signal block128_offset, block128_len                                                         : std_logic_vector(offset_width(DATASTREAM_DATA_WIDTH, 128)-1 downto 0);
  signal block128_valid, block128_ready, block128_last, block128_mod_valid, block128_mod_ready : std_logic;

  signal dec_block                        : std_logic_vector(63 downto 0);
  signal dec_block_valid, dec_block_ready : std_logic;

  signal out_block                                        : std_logic_vector(DATASTREAM_DATA_WIDTH-1 downto 0);
  signal out_block_addr                                   : std_logic_vector(TRANSLATION_FACTOR_BIT-1 downto 0);
  signal out_block_valid, out_block_ready, out_block_last : std_logic;

  signal out_block64                                            : std_logic_vector(DATASTREAM_DATA_WIDTH-1 downto 0);
  signal out_block64_valid, out_block64_ready, out_block64_last : std_logic;

  signal out_block128                                              : std_logic_vector(DATASTREAM_DATA_WIDTH-1 downto 0);
  signal out_block128_valid, out_block128_ready, out_block128_last : std_logic;

  signal AsconInitxS, AsconPermutexS, AsconPermuteFinalizexS : std_logic;
  signal AsconKeyInputxD                                     : std_logic_vector(127 downto 0);
  signal AsconDonexS, AsconOutputTagxS                       : std_logic;
  signal AsconDataInxD, AsconDataOutxD                       : std_logic_vector(ASCON_DATA_BUS_WIDTH-1 downto 0);

  signal CtrlStatexDP, CtrlStatexDN         : std_logic_vector(log2_ceil(ALIGNMENT/8) downto 0);
  signal AsconSyncxDP, AsconSyncxDN         : std_logic;
  signal AsconFinishedxDP, AsconFinishedxDN : std_logic;

  signal PrinceKeyxD, PrinceKeyInxD                                                       : std_logic_vector(127 downto 0);
  signal PrinceKeyxDP, PrinceKeyxDN                                                       : std_logic_vector(127 downto 0);
  signal PrinceInputxD, PrinceOutputxD, PrinceOutputRegxD                                 : std_logic_vector(63 downto 0);
  signal PrinceOutputRegInputxD                                                           : std_logic_vector(63 downto 0);
  signal PrinceOutputRegInputValidxS, PrinceOutputRegInputReadyxS                         : std_logic;
  signal PrinceInputReadyxS, PrinceInputValidxS, PrinceOutputReadyxS, PrinceOutputValidxS : std_logic;
  signal PrinceOutputRegValidxS, PrinceOutputRegReadyxS                                   : std_logic;
  signal PrinceFinishedxDP, PrinceFinishedxDN                                             : std_logic;
  signal PrinceRunningxDP, PrinceRunningxDN                                               : std_logic;

  signal InputRequestxD, InputRequestRegxD, OutputRequestxD : StreamType;
  signal InputRequestRegValidxS                             : std_logic;

  signal out_request                                : StreamType;
  signal virtualAddrRegxDP, virtualAddrRegxDN       : std_logic_vector(ADDRESS_WIDTH-1 downto 0);
  signal requestProcessedxDBP, requestProcessedxDBN : std_logic;
  signal inputBlockCounterxDP, inputBlockCounterxDN : std_logic_vector(log2_ceil(128/DATASTREAM_DATA_WIDTH)-1 downto 0);

  signal DataRequestxS, TreeRequestxS : std_logic;
  signal CtrlLastStatexD              : std_logic_vector(CtrlStatexDP'length-1 downto 0);

  signal BufInputxD, BufOutputxD                                              : StreamType;
  signal BufInputValidxS, BufOutputValidxS, BufInputReadyxS, BufOutputReadyxS : std_logic;

  signal AuthenticationErrorxSP, AuthenticationErrorxSN : std_logic;

  signal AuthenticationErrorxS                  : std_logic;
  signal InputConversion128xS                   : std_logic;
  signal InputConversion64xS                    : std_logic;
  signal OutputConversion128xS                  : std_logic;
  signal s_request64_valid, s_request64_ready   : std_logic;
  signal s_request128_valid, s_request128_ready : std_logic;
  signal s_requestReg_valid, s_requestReg_ready : std_logic;
  signal s_request128_last                      : std_logic;

  signal SkipDecryptionxS : std_logic;
  signal SkipTagxS        : std_logic;

  signal DecryptionDonexDP, DecryptionDonexDN : std_logic;
begin
  InputConversion64xS <= not(InputConversion128xS);

  synchronizer : entity work.ready_synchronizer
    generic map(
      OUT_WIDTH => 3
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_valid => s_request.valid,
      in_ready => s_request_ready,

      out_valid(0)  => s_request64_valid,
      out_valid(1)  => s_request128_valid,
      out_valid(2)  => s_requestReg_valid,
      out_active(0) => InputConversion64xS,
      out_active(1) => InputConversion128xS,
      out_active(2) => '1',
      out_ready(0)  => s_request64_ready,
      out_ready(1)  => s_request128_ready,
      out_ready(2)  => s_requestReg_ready
      );

  input_conversion128 : entity work.rate_converter
    generic map(
      IN_DATA_WIDTH  => DATASTREAM_DATA_WIDTH,
      OUT_DATA_WIDTH => 128,
      REGISTERED     => false
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_field_offset => (others => '0'),  --s_request.block_address(TRANSLATION_FACTOR downto 2),
      in_field_len    => (others => '1'),

      in_last  => s_request128_last,
      in_data  => s_request.data,
      in_valid => s_request128_valid,
      in_ready => s_request128_ready,

      out_data         => block128,
      out_last         => block128_last,
      out_field_offset => block128_offset,
      out_field_len    => block128_len,
      out_valid        => block128_valid,
      out_ready        => block128_ready
      );

  inputBlockCounterxDN <= std_logic_vector(unsigned(inputBlockCounterxDP) + 1) when s_request128_ready = '1'                                          else inputBlockCounterxDP;
  s_request128_last    <= '1'                                                  when inputBlockCounterxDP = ones(log2_ceil(128/DATASTREAM_DATA_WIDTH)) else '0';

  input_conversion64 : entity work.rate_converter
    generic map(
      IN_DATA_WIDTH  => DATASTREAM_DATA_WIDTH,
      OUT_DATA_WIDTH => 64,
      REGISTERED     => false
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_field_offset => (others => '0'),  --s_request.block_address(TRANSLATION_FACTOR downto 2),
      in_field_len    => (others => '1'),
      in_last         => last_block,
      in_data         => s_request.data,
      in_valid        => s_request64_valid,
      in_ready        => s_request64_ready,

      out_data         => block64,
      out_field_offset => block64_offset,
      out_field_len    => block64_len,
      out_valid        => block64_valid,
      out_ready        => block64_ready,
      out_last         => block64_last
      );

  block64_ready <= enc_block_ready;

  last_block <= '1' when (to_integer(unsigned(s_request.block_len)) = 0) else '0';

  InputRequestxD  <= s_request;
  OutputRequestxD <= InputRequestRegxD;

  request_type : process (OutputRequestxD)
    variable vTreeRequest, vDataRequest : std_logic;
    variable vCtrlLastState             : std_logic_vector(CtrlStatexDP'length-1 downto 0);
  begin
    vTreeRequest   := '0';
    vDataRequest   := '0';
    vCtrlLastState := STATE_CRYPT_LAST;
    if OutputRequestxD.request_type = REQ_TYPE_DATA then
      vDataRequest   := '1';
      vCtrlLastState := STATE_CRYPT_LAST;
    elsif (OutputRequestxD.request_type = REQ_TYPE_TREE or OutputRequestxD.request_type = REQ_TYPE_TREE_ROOT) then
      vTreeRequest   := '1';
      vCtrlLastState := STATE_TREE_CRYPT_LAST;
    end if;

    DataRequestxS   <= vDataRequest;
    TreeRequestxS   <= vTreeRequest;
    CtrlLastStatexD <= vCtrlLastState;
  end process request_type;

  -- Ascon 128
  ascon_1 : entity work.ascon_mac
    generic map (
      UNROLED_ROUNDS  => 3,                     -- 1,2,3,4 or 6
      DATA_BLOCK_SIZE => ASCON_DATA_BUS_WIDTH,  -- rate
      ROUNDS_A        => 12,
      ROUNDS_B        => 9,
      DATA_BUS_WIDTH  => ASCON_DATA_BUS_WIDTH)
    port map (
      ClkxCI             => clk,
      RstxRBI            => resetn,
      KeyxDI             => AsconKeyInputxD,
      CP_InitxSI         => AsconInitxS,
      CP_PermutexSI      => AsconPermutexS,
      CP_FinalPermutexSI => AsconPermuteFinalizexS,
      CP_OutputTagxSI    => AsconOutputTagxS,
      DataWritexDI       => change_endianess(AsconDataInxD),
      IODataxDO          => AsconDataOutxD,
      CP_DonexSO         => AsconDonexS
      );

  prince_1 : entity work.prince
    generic map(
      DECRYPTION => DECRYPTION,
      BLOCK_SIZE => 64
      )
    port map(
      ClkxCI        => clk,
      RstxRBI       => resetn,
      Key0xDI       => PrinceKeyxD(63 downto 0),
      Key1xDI       => PrinceKeyxD(127 downto 64),
      MessagexDI    => PrinceInputxD,
      CiphertextxDO => PrinceOutputxD,
      in_ready      => PrinceInputReadyxS,
      in_valid      => PrinceInputValidxS,
      out_ready     => PrinceOutputReadyxS,
      out_valid     => PrinceOutputValidxS
      );

  prince_key : process(PrinceKeyInxD, PrinceKeyxDP, PrinceInputValidxS, PrinceInputReadyxS) is
  begin
    PrinceKeyxDN <= PrinceKeyxDP;
    PrinceKeyxD  <= PrinceKeyxDP;

    if PrinceInputValidxS = '1' and PrinceInputReadyxS = '1' then
      PrinceKeyxDN <= PrinceKeyInxD;
      PrinceKeyxD  <= PrinceKeyInxD;
    end if;
  end process prince_key;

  prince_reg : entity work.register_stage
    generic map(
      WIDTH      => 64,
      REGISTERED => false
      )
    port map(
      clk    => clk,
      resetn => resetn,

      in_data  => PrinceOutputRegInputxD,
      in_valid => PrinceOutputRegInputValidxS,
      in_ready => PrinceOutputRegInputReadyxS,

      out_data  => PrinceOutputRegxD,
      out_valid => PrinceOutputRegValidxS,
      out_ready => PrinceOutputRegReadyxS
      );

  block64reg_v1 : if block64_offset'length = 0 generate

    block64_register : entity work.register_stage
      generic map(
        WIDTH => 1
        )
      port map(
        clk    => clk,
        resetn => resetn,

        in_data(0) => block64_last,
        in_valid   => block64_valid,
        in_ready   => open,

        out_data(0) => block64_last_reg,
        out_valid   => open,
        out_ready   => block64_reg_ready
        );

  end generate;

  block64reg_v2 : if block64_offset'length /= 0 generate

    block64_register : entity work.register_stage
      generic map(
        WIDTH => block64_len'length+block64_offset'length+1
        )
      port map(
        clk    => clk,
        resetn => resetn,

        in_data(0)                                                => block64_last,
        in_data(block64_len'length downto 1)                      => block64_len,
        in_data(2*block64_len'length downto block64_len'length+1) => block64_offset,
        in_valid                                                  => block64_valid,
        in_ready                                                  => open,

        out_data(0)                                                => block64_last_reg,
        out_data(block64_len'length downto 1)                      => block64_len_reg,
        out_data(2*block64_len'length downto block64_len'length+1) => block64_offset_reg,
        out_valid                                                  => open,
        out_ready                                                  => block64_reg_ready
        );

  end generate;

  block64_decryption : if DECRYPTION generate
    block64_data_register : entity work.register_stage
      generic map(
        WIDTH => block64'length
        )
      port map(
        clk    => clk,
        resetn => resetn,

        in_data  => block64,
        in_valid => block64_valid,
        in_ready => open,

        out_data  => block64_reg,
        out_valid => block64_reg_valid,
        out_ready => block64_reg_ready
        );
  end generate;

  block64_encryption : if not(DECRYPTION) generate
    block64_data_register : entity work.register_stage
      generic map(
        WIDTH => block64'length
        )
      port map(
        clk    => clk,
        resetn => resetn,

        in_data  => PrinceOutputRegxD,
        in_valid => PrinceOutputRegValidxS,
        in_ready => open,

        out_data  => block64_reg,
        out_valid => block64_reg_valid,
        out_ready => block64_reg_ready
        );
  end generate;

  input_fifo : entity work.stream_fifo
    generic map(
      ELEMENTS => 128/DATASTREAM_DATA_WIDTH
      )
    port map(
      clk    => clk,
      resetn => resetn,

      in_data  => InputRequestxD,
      in_valid => s_requestReg_valid,
      in_ready => s_requestReg_ready,

      out_data  => InputRequestRegxD,
      out_valid => InputRequestRegValidxS,
      out_ready => out_block_ready
      );

  output_conversion64 : entity work.rate_converter
    generic map(
      IN_DATA_WIDTH  => 64,
      OUT_DATA_WIDTH => DATASTREAM_DATA_WIDTH,
      REGISTERED     => false
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_last         => block64_last_reg,
      in_data         => dec_block,
      in_field_offset => block64_offset_reg,
      in_field_len    => block64_len_reg,
      in_valid        => dec_block_valid,
      in_ready        => dec_block_ready,

      out_data         => out_block64,
      out_field_offset => open,         --out_block_addr,
      out_field_len    => open,
      out_last         => out_block64_last,
      out_valid        => out_block64_valid,
      out_ready        => out_block64_ready
      );

  output_conversion128 : entity work.rate_converter
    generic map(
      IN_DATA_WIDTH  => 128,
      OUT_DATA_WIDTH => DATASTREAM_DATA_WIDTH,
      REGISTERED     => true
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_last         => block128_last,
      in_data         => block128_mod,
      in_field_offset => block128_offset,
      in_field_len    => block128_len,
      in_valid        => block128_mod_valid,
      in_ready        => block128_mod_ready,

      out_data         => out_block128,
      out_field_offset => open,         --out_block_addr,
      out_field_len    => open,
      out_last         => out_block128_last,
      out_valid        => out_block128_valid,
      out_ready        => out_block128_ready
      );

  out_mux : process (out_block64, out_block64_last, out_block64_valid, OutputConversion128xS,
                     out_block128, out_block128_last, out_block128_valid, out_block_ready)
  begin
    out_block128_ready <= '0';
    out_block64_ready  <= '0';
    if OutputConversion128xS = '1' then
      out_block          <= out_block128;
      out_block_valid    <= out_block128_valid;
      out_block_last     <= out_block128_last;
      out_block128_ready <= out_block_ready;
    else
      out_block         <= out_block64;
      out_block_valid   <= out_block64_valid;
      out_block_last    <= out_block64_last;
      out_block64_ready <= out_block_ready;
    end if;
  end process out_mux;

  address_filter : process(InputRequestRegxD)
    variable vSize         : unsigned(s_request.size'length-1 downto 0);
    variable vTmp          : std_logic_vector(ADDRESS_WIDTH-1 downto 0);
    variable vStartAddress : unsigned(ADDRESS_WIDTH-1 downto 0);
    variable vEndAddress   : unsigned(ADDRESS_WIDTH-1 downto 0);
    variable vLenBytes     : unsigned(s_request.len'length + 1 downto 0);
    type tASizeToMaskLUT is array (0 to 2**2 - 1) of std_logic_vector(1 downto 0);
    constant ASIZE_MASKING_LUT : tASizeToMaskLUT := (
      0 => "11",
      1 => "10",
      2 => "00",
      3 => "00");
  begin
    -- Compute start and end address
    vSize                                   := shift_left((vSize'left downto 1                      => '0') & '1', to_integer(unsigned(InputRequestRegxD.size)));
    vTmp                                    := InputRequestRegxD.address(ADDRESS_WIDTH - 1 downto 2) & (InputRequestRegxD.address(1 downto 0) and ASIZE_MASKING_LUT(to_integer(unsigned(InputRequestRegxD.size))));
    vStartAddress                           := unsigned(vTmp);
    assert(unsigned(InputRequestRegxD.size) <= 2);
    vTmp                                    := (ADDRESS_WIDTH-1 downto InputRequestRegxD.len'length => '0') & InputRequestRegxD.len;
    vEndAddress                             := vStartAddress + (unsigned(vTmp) sll to_integer(unsigned(InputRequestRegxD.size)));

    SkipDecryptionxS <= '0';
    if (InputRequestRegxD.request_type = REQ_TYPE_TREE or InputRequestRegxD.request_type = REQ_TYPE_TREE_ROOT) and
      InputRequestRegxD.read = '1' and
      DECRYPTION and
      InputRequestRegxD.metadata = '0' and
      (unsigned(InputRequestRegxD.virt_address) < vStartAddress or unsigned(InputRequestRegxD.virt_address) > vEndAddress) then
      SkipDecryptionxS <= '1';
    end if;

    SkipTagxS <= '0';
    if (InputRequestRegxD.request_type = REQ_TYPE_TREE or InputRequestRegxD.request_type = REQ_TYPE_TREE_ROOT) then
      SkipTagxS <= '1';
    end if;
  end process address_filter;

  control : process(enc_block_valid, enc_block, dec_block_ready, CtrlStatexDP, CtrlLastStatexD,
                    TreeRequestxS, DataRequestxS, s_request.error,
                    AsconDonexS, AsconDataOutxD, AsconSyncxDP, AsconFinishedxDP, PrinceOutputxD,
                    PrinceOutputRegInputReadyxS, PrinceOutputValidxS,
                    PrinceOutputRegxD, PrinceInputReadyxS, PrinceOutputRegValidxS, PrinceFinishedxDP,
                    InputRequestRegxD, PrinceRunningxDP,
                    block128, block128_valid, out_block128_ready, block128_mod_ready, AuthenticationErrorxSP,
                    block64, block64_valid, block64_reg_valid, block64_reg, PrinceOutputxD,
                    SkipDecryptionxS, SkipTagxS, DecryptionDonexDP, InputRequestRegValidxS)
    variable vLastBlock      : std_logic;
    variable vPrinceFinished : std_logic;
    variable vAsconFinished  : std_logic;
  begin
    CtrlStatexDN           <= CtrlStatexDP;
    AsconSyncxDN           <= AsconSyncxDP;
    AsconFinishedxDN       <= AsconFinishedxDP;
    PrinceFinishedxDN      <= PrinceFinishedxDP;
    PrinceRunningxDN       <= PrinceRunningxDP;
    AuthenticationErrorxSN <= AuthenticationErrorxSP;

    AsconInitxS                <= '0';
    AsconPermuteFinalizexS     <= '0';
    AsconPermutexS             <= '0';
    AsconOutputTagxS           <= '0';
    AsconKeyInputxD            <= block128;
    AsconDataInxD              <= (others => '0');
    AsconDataInxD(63 downto 0) <= block64_reg;

    PrinceInputxD                                  <= enc_block;
    PrinceInputValidXS                             <= '0';
    PrinceOutputRegReadyxS                         <= '0';
    PrinceKeyInxD                                  <= (others => '0');
    PrinceKeyInxD(ASCON_DATA_BUS_WIDTH-1 downto 0) <= AsconDataOutxD;

    PrinceOutputRegInputxD      <= PrinceOutputxD;
    PrinceOutputRegInputValidxS <= PrinceOutputValidxS;
    PrinceOutputReadyxS         <= PrinceOutputRegInputReadyxS;

    dec_block       <= PrinceOutputRegxD;
    dec_block_valid <= '0';
    enc_block       <= block64;
    enc_block_valid <= block64_valid;
    enc_block_ready <= '0';

    vLastBlock := '0';
    if (CtrlStatexDP = CtrlLastStatexD) then
      vLastBlock := '1';
    end if;

    InputConversion128xS  <= '0';
    OutputConversion128xS <= '0';
    AuthenticationErrorxS <= AuthenticationErrorxSP;

    block128_mod       <= block128;
    block128_mod_valid <= block128_valid;
    block128_ready     <= block128_mod_ready;

    block64_reg_ready <= '0';

    DecryptionDonexDN <= DecryptionDonexDP;

    -- State Machine
    -- STATE IDLE
    if (CtrlStatexDP = STATE_IDLE) then
      InputConversion128xS <= '1';
      block128_mod_valid   <= '0';
      block64_reg_ready    <= block64_reg_valid;
      if block128_valid = '1' then
        AsconInitxS  <= '1';
        CtrlStatexDN <= STATE_INIT;
      end if;
    end if;

    -- STATE INIT
    if (CtrlStatexDP = STATE_INIT) then
      InputConversion128xS  <= not(AsconFinishedxDP);
      OutputConversion128xS <= '1';

      vAsconFinished := AsconFinishedxDP;
      if vAsconFinished = '0' then
        AsconInitxS <= '1';
        if AsconDonexS = '1' then
          vAsconFinished := '1';
        end if;
      end if;

      block128_mod_valid <= '0';
      if vAsconFinished = '1' then
        block128_mod_valid <= block128_valid;
        if out_block128_ready = '1' and out_block128_last = '1' then
          vAsconFinished := '0';
          CtrlStatexDN   <= STATE_CRYPT;
        end if;
      end if;

      AsconFinishedxDN <= vAsconFinished;
    end if;

    -- STATE CRYPTO
    if CtrlStatexDP = STATE_CRYPT then
      vPrinceFinished := PrinceFinishedxDP;
      vAsconFinished  := AsconFinishedxDP;

      if SkipDecryptionxS = '1' then
        PrinceOutputRegInputValidxS <= '1';
      end if;

      if enc_block_valid = '1' and InputRequestRegValidxS = '1' and PrinceFinishedxDP = '0' and PrinceRunningxDP = '0' then
        if SkipDecryptionxS = '1' then
          enc_block_ready             <= '1';
          PrinceOutputRegInputValidxS <= '1';
          PrinceInputValidxS          <= '0';
          PrinceRunningxDN            <= '0';
          vPrinceFinished             := '1';
          AsconDataInxD               <= (others => '0');
          AsconPermutexS              <= '1';
          AsconSyncxDN                <= '1';
        else
          PrinceInputValidxS <= '1';
          enc_block_ready    <= '1';
          PrinceRunningxDN   <= '1';
          PrinceFinishedxDN  <= '0';
          AsconDataInxD      <= (others => '0');

          AsconPermutexS    <= '1';
          AsconSyncxDN      <= '1';
          DecryptionDonexDN <= '1';
        end if;
      end if;

      if PrinceOutputRegValidxS = '1' and vPrinceFinished = '0' then
        PrinceRunningxDN <= '0';
        vPrinceFinished  := '1';
      end if;

      if AsconSyncxDP = '1' then
        AsconPermutexS <= '1';
        AsconSyncxDN   <= '1';
        if AsconDonexS = '1' then
          vAsconFinished := '1';
          AsconSyncxDN   <= '0';
        end if;
      end if;


      dec_block_valid <= PrinceOutputRegValidxS and vAsconFinished and vPrinceFinished and block64_reg_valid;

      if dec_block_ready = '1' then
        vAsconFinished         := '0';
        vPrinceFinished        := '0';
        PrinceOutputRegReadyxS <= '1';
        CtrlStatexDN           <= std_logic_vector(unsigned(CtrlStatexDP) + 1);
      end if;

      AsconFinishedxDN  <= vAsconFinished;
      PrinceFinishedxDN <= vPrinceFinished;
    end if;

    if (CtrlStatexDP > STATE_CRYPT and CtrlStatexDP <= CtrlLastStatexD) then
      vPrinceFinished := PrinceFinishedxDP;
      vAsconFinished  := AsconFinishedxDP;

      if not(ENC_ABSORB_CIPHERTEXT) and
        (InputRequestRegxD.request_type = REQ_TYPE_TREE or InputRequestRegxD.request_type = REQ_TYPE_TREE_ROOT) then
        AsconDataInxD <= (others => '0');
      end if;

      if SkipDecryptionxS = '1' then
        PrinceOutputRegInputValidxS <= '1';
      end if;

      if enc_block_valid = '1' and InputRequestRegValidxS = '1' and PrinceFinishedxDP = '0' and PrinceRunningxDP = '0' and block64_reg_valid = '1' then
        if SkipDecryptionxS = '1' then
          enc_block_ready    <= '1';
          block64_reg_ready  <= '1';
          PrinceInputValidxS <= '0';
          PrinceRunningxDN   <= '0';
          vPrinceFinished    := '1';
          AsconPermutexS     <= not(DecryptionDonexDP) and (not(vLastBlock) or not(SkipTagxS));
          AsconSyncxDN       <= not(DecryptionDonexDP) and (not(vLastBlock) or not(SkipTagxS));
          vAsconFinished     := DecryptionDonexDP or (vLastBlock and SkipTagxS);
        else
          PrinceInputValidxS <= '1';
          enc_block_ready    <= '1';
          PrinceRunningxDN   <= '1';
          block64_reg_ready  <= '1';
          DecryptionDonexDN  <= '1';

          AsconPermutexS <= not(vLastBlock) or not(SkipTagxS);
          AsconSyncxDN   <= not(vLastBlock) or not(SkipTagxS);
          vAsconFinished := vLastBlock and SkipTagxS;
        end if;
      end if;

      if PrinceOutputRegValidxS = '1' and vPrinceFinished = '0' then
        PrinceRunningxDN <= '0';
        vPrinceFinished  := '1';
      end if;

      if AsconSyncxDP = '1' then
        AsconPermutexS <= '1';
        AsconSyncxDN   <= '1';
        if AsconDonexS = '1' then
          vAsconFinished := '1';
          AsconSyncxDN   <= '0';
        end if;
      end if;

      dec_block_valid <= PrinceOutputRegValidxS and vAsconFinished and vPrinceFinished and block64_reg_valid;
      if dec_block_ready = '1' then
        vAsconFinished         := '0';
        vPrinceFinished        := '0';
        PrinceOutputRegReadyxS <= '1';
        CtrlStatexDN           <= std_logic_vector(unsigned(CtrlStatexDP) + 1);
        if vLastBlock = '1' then
          DecryptionDonexDN <= '0';
          if DataRequestxS = '1' then
            CtrlStatexDN <= STATE_VERIFY;
          else
            CtrlStatexDN <= STATE_IDLE;
          end if;
        end if;
      end if;

      AsconFinishedxDN  <= vAsconFinished;
      PrinceFinishedxDN <= vPrinceFinished;
    end if;

    if TAG_SIZE = 16 then

      -- STATE VERIFY
      if (CtrlStatexDP = STATE_VERIFY) then
        vAsconFinished := AsconFinishedxDP;

        if block64_reg_valid = '1' then
          block64_reg_ready      <= '1';
          AsconPermuteFinalizexS <= '1';
          AsconSyncxDN           <= '1';
        end if;

        if AsconSyncxDP = '1' then
          AsconPermuteFinalizexS <= '1';
          AsconSyncxDN           <= '1';
          if AsconDonexS = '1' then
            vAsconFinished := '1';
            AsconSyncxDN   <= '0';
          end if;
        end if;

        InputConversion128xS <= '1';
        block128_mod_valid   <= '0';
        if vAsconFinished = '1' then
          AsconOutputTagxS <= '1';
          if block128_valid = '1' then
            vAsconFinished                                := '0';
            block128_mod                                  <= (others => '0');
            block128_mod(ASCON_DATA_BUS_WIDTH-1 downto 0) <= change_endianess(AsconDataOutxD);
            block128_mod_valid                            <= '1';
            CtrlStatexDN                                  <= STATE_VERIFY_2;
            if change_endianess(AsconDataOutxD) /= block128(ASCON_DATA_BUS_WIDTH-1 downto 0) and DECRYPTION then
              AuthenticationErrorxSN <= '1';
            end if;
          end if;
        end if;
        AsconFinishedxDN <= vAsconFinished;
      end if;

      if (CtrlStatexDP = STATE_VERIFY_2) then
        OutputConversion128xS <= '1';
        if (out_block128_ready = '1' and out_block128_last = '1') then
          AuthenticationErrorxSN <= '0';
          CtrlStatexDN           <= STATE_IDLE;
        end if;
      end if;
    elsif TAG_SIZE = 8 then

      -- STATE VERIFY
      if (CtrlStatexDP = STATE_VERIFY) then
        vAsconFinished := AsconFinishedxDP;

        if block64_reg_valid = '1' then
          block64_reg_ready      <= '1';
          AsconPermuteFinalizexS <= '1';
          AsconSyncxDN           <= '1';
        end if;

        if AsconSyncxDP = '1' then
          AsconPermuteFinalizexS <= '1';
          AsconSyncxDN           <= '1';
          if AsconDonexS = '1' then
            vAsconFinished := '1';
            AsconSyncxDN   <= '0';
          end if;
        end if;

        enc_block_valid <= '0';
        if vAsconFinished = '1' then
          AsconOutputTagxS       <= '1';
          vAsconFinished         := '0';
          dec_block_valid        <= '1';
          dec_block(63 downto 0) <= change_endianess(AsconDataOutxD(63 downto 0));
          if change_endianess(AsconDataOutxD(63 downto 0)) /= block64 and DECRYPTION then
            AuthenticationErrorxS <= '1';
          end if;
          if dec_block_ready = '1' then
            enc_block_ready <= '1';
            CtrlStatexDN    <= STATE_IDLE;
          end if;
        end if;

        AsconFinishedxDN <= vAsconFinished;
      end if;
    end if;

  end process control;

  output : process(CtrlStatexDP, enc_block_valid, s_request, out_block, out_block_addr, out_block_valid, AsconSyncxDP,
                   virtualAddrRegxDP, requestProcessedxDBP, out_block_ready, AuthenticationErrorxS, CtrlLastStatexD, OutputRequestxD) is
    variable vOutBlockCounter       : std_logic_vector(TRANSLATION_FACTOR_BIT-1 downto 0);
    variable vPhysicalLen           : std_logic_vector(s_request.block_len'length-1 downto 0);
    variable vPhysicalAddr          : std_logic_vector(s_request.block_address'length-1 downto 0);
    variable vBlockCount, vBlockNum : integer;
    variable vInBlockNum            : integer;
    variable vVirtAddr              : integer;
  begin
    virtualAddrRegxDN    <= virtualAddrRegxDP;
    requestProcessedxDBN <= requestProcessedxDBP;

    -- Virtual Address Setup
    vVirtAddr := to_integer(unsigned(virtualAddrRegxDP));
    if (out_block_valid = '1') then
      if (requestProcessedxDBP = '0' and OutputRequestxD.metadata = '0') then
        vVirtAddr            := to_integer(unsigned(OutputRequestxD.virt_address));
        requestProcessedxDBN <= '1';
      end if;
    end if;

    -- Defaults for output
    vOutBlockCounter := std_logic_vector(MAX_COUNTER_VALUE - unsigned(out_block_addr));
    vPhysicalLen     := OutputRequestxD.block_len(OutputRequestxD.block_len'length-1 downto TRANSLATION_FACTOR_BIT) & vOutBlockCounter;
    vPhysicalAddr    := OutputRequestxD.block_address(OutputRequestxD.block_address'length-1 downto TRANSLATION_FACTOR_BIT+2) & out_block_addr & "00";

    out_request               <= OutputRequestxD;
    out_request.block_len     <= vPhysicalLen;
    out_request.block_address <= vPhysicalAddr;
    out_request.virt_address  <= (others => '0');

    -- Output overwrites
    if (CtrlStatexDP >= STATE_CRYPT and CtrlStatexDP <= CtrlLastStatexD) then
      out_request.virt_address <= std_logic_vector(to_unsigned(vVirtAddr, s_request.virt_address'length));

      if (out_block_ready = '1') then
        vVirtAddr := vVirtAddr + (DATASTREAM_DATA_WIDTH/8);
      end if;
    else
      out_request.metadata <= '1';
      out_request.error    <= OutputRequestxD.error or AuthenticationErrorxS;
    end if;

    if to_integer(unsigned(vPhysicalLen)) = 0 and out_block_ready = '1' then
      requestProcessedxDBN <= '0';
    end if;

    out_request.valid <= out_block_valid;

    if CtrlStatexDP /= STATE_INIT and CtrlStatexDP /= STATE_IDLE then
      out_request.data <= out_block;
    end if;

    virtualAddrRegxDN <= std_logic_vector(to_unsigned(vVirtAddr, s_request.virt_address'length));
  end process output;

  out_reg : if OUTPUT_REGISTER = true generate
    output_buf : entity work.stream_register_stage_fifo
      port map(
        clk    => clk,
        resetn => resetn,

        in_data  => BufInputxD,
        in_valid => BufInputValidxS,
        in_ready => BufInputReadyxS,

        out_data  => BufOutputxD,
        out_valid => BufOutputValidxS,
        out_ready => BufOutputReadyxS
        );
  end generate out_reg;

  ascon_buffer : process (BufOutputValidxS, BufOutputxD, m_request_ready, out_request, BufInputReadyxS)
  begin
    if OUTPUT_REGISTER then
      BufInputxD       <= out_request;
      BufInputValidxS  <= out_request.valid;
      out_block_ready  <= BufInputReadyxS;
      m_request        <= BufOutputxD;
      BufOutputReadyxS <= m_request_ready;
    else
      m_request       <= out_request;
      out_block_ready <= m_request_ready;
    end if;
  end process ascon_buffer;


  regs : process(clk) is
  begin
    if rising_edge(clk) then
      if resetn = '0' then
        CtrlStatexDP           <= STATE_IDLE;
        AsconSyncxDP           <= '0';
        PrinceRunningxDP       <= '0';
        PrinceFinishedxDP      <= '0';
        AsconFinishedxDP       <= '0';
        AuthenticationErrorxSP <= '0';
        PrinceKeyxDP           <= (others => '0');
        virtualAddrRegxDP      <= (others => '0');
        requestProcessedxDBP   <= '0';
        inputBlockCounterxDP   <= (others => '0');
        DecryptionDonexDP      <= '0';
      else
        CtrlStatexDP           <= CtrlStatexDN;
        AsconSyncxDP           <= AsconSyncxDN;
        PrinceRunningxDP       <= PrinceRunningxDN;
        PrinceFinishedxDP      <= PrinceFinishedxDN;
        AsconFinishedxDP       <= AsconFinishedxDN;
        AuthenticationErrorxSP <= AuthenticationErrorxSN;
        PrinceKeyxDP           <= PrinceKeyxDN;
        virtualAddrRegxDP      <= virtualAddrRegxDN;
        requestProcessedxDBP   <= requestProcessedxDBN;
        inputBlockCounterxDP   <= inputBlockCounterxDN;
        DecryptionDonexDP      <= DecryptionDonexDN;
      end if;
    end if;
  end process regs;

end Behavioral;
