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

--! Encrypts or decrypts transactions with Ascon.
--!
--! Regarding memory layout, first the nonce, second the data, and third the
--! authentication tag is expected/generated.
entity stream_ascon is
  generic(
    DATA_ALIGNMENT  : integer := 64;
    TREE_ALIGNMENT  : integer := 32;
    OUTPUT_REGISTER : boolean := true
    );
  port(
    clk    : in std_logic;
    resetn : in std_logic;

    s_request       : in  StreamType;
    s_request_ready : out std_logic;

    m_request       : out StreamType;
    m_request_ready : in  std_logic;

    KeyxDI    : in std_logic_vector(127 downto 0);
    DecryptxS : in std_logic
    );
end stream_ascon;

architecture Behavioral of stream_ascon is
  constant ALIGNMENT              : integer                                     := max(DATA_ALIGNMENT, TREE_ALIGNMENT);
  constant METADATA               : integer                                     := 16;
  constant TRANSLATION_FACTOR     : integer                                     := (64/DATASTREAM_DATA_WIDTH);
  constant TRANSLATION_FACTOR_BIT : integer                                     := log2_ceil(TRANSLATION_FACTOR);
  constant MAX_COUNTER_VALUE      : unsigned(TRANSLATION_FACTOR_BIT-1 downto 0) := (others => '1');

  constant ASCON_IDLE            : std_logic_vector(log2_ceil(ALIGNMENT/8) downto 0) := (others                                  => '0');
  constant ASCON_INIT            : std_logic_vector(log2_ceil(ALIGNMENT/8) downto 0) := (log2_ceil(ALIGNMENT/8) downto 2         => '0') & "11";
  constant ASCON_CRYPT           : std_logic_vector(log2_ceil(ALIGNMENT/8) downto 0) := '1' & (log2_ceil(ALIGNMENT/8)-1 downto 0 => '0');
  constant ASCON_TREE_CRYPT_LAST : std_logic_vector(log2_ceil(ALIGNMENT/8) downto 0) := '1' & std_logic_vector(to_unsigned(TREE_ALIGNMENT/8-1, log2_ceil(ALIGNMENT/8)));
  constant ASCON_CRYPT_LAST      : std_logic_vector(log2_ceil(ALIGNMENT/8) downto 0) := '1' & std_logic_vector(to_unsigned(DATA_ALIGNMENT/8-1, log2_ceil(ALIGNMENT/8)));
  constant ASCON_VERIFY          : std_logic_vector(log2_ceil(ALIGNMENT/8) downto 0) := (log2_ceil(ALIGNMENT/8) downto 2         => '0') & "10";
  signal last_block              : std_logic;

  signal enc_block                        : std_logic_vector(63 downto 0);
  signal enc_block_valid, enc_block_ready : std_logic;

  signal dec_block                        : std_logic_vector(63 downto 0);
  signal dec_block_valid, dec_block_ready : std_logic;

  signal out_block                                        : std_logic_vector(DATASTREAM_DATA_WIDTH-1 downto 0);
  signal out_block_addr                                   : std_logic_vector(TRANSLATION_FACTOR_BIT-1 downto 0);
  signal out_block_valid, out_block_ready, out_block_last : std_logic;

  signal AsconInitxS, AsconDecryptxS, AsconEncryptxS, AsconEncryptFinalizexS : std_logic;
  signal AsconDecryptFinalizexS, AsconWriteNoncexS, AsconDonexS              : std_logic;
  signal AsconDataInxD, AsconDataOutxD                                       : std_logic_vector(63 downto 0);
  signal AsconTagxD                                                          : std_logic_vector(127 downto 0);

  signal AsconStatexDP, AsconStatexDN : std_logic_vector(log2_ceil(ALIGNMENT/8) downto 0);
  signal AsconSyncxDP, AsconSyncxDN   : std_logic;

  signal requestRegxDP, requestRegxDN, out_request : StreamType;
  signal virtualAddrRegxDP, virtualAddrRegxDN      : std_logic_vector(ADDRESS_WIDTH-1 downto 0);
  signal requestProcessedxDP, requestProcessedxDN  : std_logic;

  signal DataRequestxS, TreeRequestxS : std_logic;
  signal AsconLastStatexD             : std_logic_vector(AsconStatexDP'length-1 downto 0);

  signal BufInputxD, BufOutputxD, BufferxDP, BufferxDN                                                      : StreamType;
  signal BufInputValidxS, BufOutputValidxS, BufInputReadyxS, BufOutputReadyxS, BufferFullxDP, BufferFullxDN : std_logic;

  signal AuthenticationErrorxS : std_logic;
begin

  data_deserialization : entity work.deserialization
    generic map(
      IN_DATA_WIDTH  => DATASTREAM_DATA_WIDTH,
      OUT_DATA_WIDTH => 64,
      REGISTERED     => false
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_field_start_offset => s_request.block_address(TRANSLATION_FACTOR downto 2),

      in_last  => last_block,
      in_data  => s_request.data,
      in_valid => s_request.valid,
      in_ready => s_request_ready,

      out_data         => enc_block,
      out_field_offset => open,
      out_field_len    => open,
      out_valid        => enc_block_valid,
      out_ready        => enc_block_ready
      );

  last_block <= '1' when (to_integer(unsigned(s_request.block_len(TRANSLATION_FACTOR_BIT-1 downto 0))) = 0) else '0';

  -- Ascon 128
  ascon_1 : entity work.ascon
    generic map (
      UNROLED_ROUNDS  => 3,             -- 1,2,3 or 6 for Ascon-128
      DATA_BLOCK_SIZE => 64,            -- select Ascon-128
      ROUNDS_A        => 12,            -- 12 for Ascon-128 and Ascon-128a
      ROUNDS_B        => 6,             -- 6 for Ascon-128
      DATA_BUS_WIDTH  => 64)            -- 64-bit nonce and rate
    port map (
      ClkxCI             => clk,
      RstxRBI            => resetn,
      KeyxDI             => KeyxDI,
      CP_InitxSI         => AsconInitxS,
      CP_AssociatexSI    => '0',
      CP_EncryptxSI      => AsconEncryptxS,
      CP_DecryptxSI      => AsconDecryptxS,
      CP_FinalEncryptxSI => AsconEncryptFinalizexS,
      CP_FinalDecryptxSI => AsconDecryptFinalizexS,
      DataWritexDI       => change_endianess(AsconDataInxD),
      IODataxDO          => AsconDataOutxD,
      CP_DonexSO         => AsconDonexS,
      TagxDO             => AsconTagxD
      );

  data_serialization : entity work.serialization
    generic map(
      IN_DATA_WIDTH  => 64,
      OUT_DATA_WIDTH => DATASTREAM_DATA_WIDTH,
      REGISTERED     => false
      )
    port map (
      clk    => clk,
      resetn => resetn,

      in_last         => '1',
      in_data         => dec_block,
      in_field_offset => (others => '0'),
      in_field_len    => (others => '1'),
      in_valid        => dec_block_valid,
      in_ready        => dec_block_ready,

      out_data         => out_block,
      out_field_offset => out_block_addr,
      out_last         => out_block_last,
      out_valid        => out_block_valid,
      out_ready        => out_block_ready
      );

  input : process (s_request, enc_block_valid, requestRegxDP)
  begin
    requestRegxDN <= requestRegxDP;
    if (enc_block_valid = '1') then
      requestRegxDN <= s_request;
    end if;
  end process input;

  control : process(enc_block_valid, enc_block, dec_block_ready, AsconDonexS, AsconLastStatexD,
                    AsconStatexDP, AsconDataOutxD, AsconSyncxDP, DecryptxS, TreeRequestxS, DataRequestxS,
                    s_request.error)

    variable vLastBlock : std_logic;
  begin
    AsconStatexDN <= AsconStatexDP;
    AsconSyncxDN  <= AsconSyncxDP;

    AsconDataInxD          <= enc_block;
    AsconInitxS            <= '0';
    AsconDecryptFinalizexS <= '0';
    AsconEncryptFinalizexS <= '0';
    AsconDecryptxS         <= '0';
    AsconEncryptxS         <= '0';

    enc_block_ready <= '0';
    dec_block       <= change_endianess(AsconDataOutxD);
    dec_block_valid <= '0';

    vLastBlock := '0';
    if (AsconStatexDP = AsconLastStatexD) then
      vLastBlock := '1';
    end if;

    AuthenticationErrorxS <= s_request.error;

    -- State Machine
    if (AsconStatexDP = ASCON_IDLE) then
      if enc_block_valid = '1' then
        dec_block_valid <= '1';
        if dec_block_ready = '1' then
          enc_block_ready <= '1';
          AsconInitxS     <= '1';
          if DecryptxS = '0' then
            AsconDataInxD <= std_logic_vector(unsigned(enc_block)+0);
          end if;
          AsconStatexDN <= ASCON_INIT;
        end if;
      end if;
    end if;
    if (AsconStatexDP = ASCON_INIT) then
      AsconInitxS <= '1';
      if AsconDonexS = '1' then
        AsconStatexDN <= ASCON_CRYPT;
      end if;
    end if;
    if (AsconStatexDP >= ASCON_CRYPT and AsconStatexDP <= AsconLastStatexD) then
      if enc_block_valid = '1' then
        dec_block_valid <= '1';
        if dec_block_ready = '1' then
          enc_block_ready <= '1';
          if vLastBlock = '1' then
            AsconDecryptFinalizexS <= DecryptxS;
            AsconEncryptFinalizexS <= not(DecryptxS);
          else
            AsconDecryptxS <= DecryptxS;
            AsconEncryptxS <= not(DecryptxS);
          end if;
          if AsconDonexS = '1' then
            AsconStatexDN <= std_logic_vector(unsigned(AsconStatexDP) + 1);
            if vLastBlock = '1' then
              AsconStatexDN <= ASCON_VERIFY;
            end if;
          else
            AsconSyncxDN <= '1';
          end if;
        end if;
      end if;
      if AsconSyncxDP = '1' then
        if vLastBlock = '1' then
          AsconDecryptFinalizexS <= DecryptxS;
          AsconEncryptFinalizexS <= not(DecryptxS);
        else
          AsconDecryptxS <= DecryptxS;
          AsconEncryptxS <= not(DecryptxS);
        end if;
        if AsconDonexS = '1' then
          AsconSyncxDN  <= '0';
          AsconStatexDN <= std_logic_vector(unsigned(AsconStatexDP) + 1);
          if vLastBlock = '1' then
            AsconStatexDN <= ASCON_VERIFY;
          end if;
        end if;
      end if;
    end if;
    if (AsconStatexDP = ASCON_VERIFY) then
      dec_block <= change_endianess(AsconTagxD(63 downto 0));
      if enc_block_valid = '1' then
        dec_block_valid <= '1';
        if (dec_block_ready = '1') then
          enc_block_ready <= '1';
          AsconStatexDN   <= ASCON_IDLE;
        end if;
        if change_endianess(AsconTagxD(63 downto 0)) /= enc_block and DecryptxS = '1' then
          AuthenticationErrorxS <= '1';
        end if;
      end if;
    end if;
  end process control;

  output : process(AsconStatexDP, enc_block_valid, s_request, requestRegxDP, out_block, out_block_addr, out_block_valid, AsconSyncxDP,
                   virtualAddrRegxDP, requestProcessedxDP, out_block_ready, AuthenticationErrorxS) is
    variable vOutBlockCounter           : std_logic_vector(TRANSLATION_FACTOR_BIT-1 downto 0);
    variable vPhysicalLen               : std_logic_vector(s_request.block_len'length-1 downto 0);
    variable vPhysicalAddr              : std_logic_vector(s_request.block_address'length-1 downto 0);
    variable vBlockCount, vBlockNum     : integer;
    variable vInBlockNum                : integer;
    variable vVirtAddr                  : integer;
    variable vRequest                   : StreamType;
    variable vTreeRequest, vDataRequest : std_logic;
    variable vAsconLastState            : std_logic_vector(AsconStatexDP'length-1 downto 0);
  begin
    virtualAddrRegxDN   <= virtualAddrRegxDP;
    requestProcessedxDN <= requestProcessedxDP;

    vRequest  := requestRegxDP;
    vVirtAddr := to_integer(unsigned(virtualAddrRegxDP));
    if (enc_block_valid = '1') then
      vRequest := s_request;
      if (requestProcessedxDP = '1') then
        vVirtAddr           := to_integer(unsigned(s_request.virt_address));
        requestProcessedxDN <= '0';
      end if;
    end if;

    vTreeRequest    := '0';
    vDataRequest    := '0';
    vAsconLastState := ASCON_CRYPT_LAST;
    if vRequest.request_type = REQ_TYPE_DATA then
      vDataRequest    := '1';
      vAsconLastState := ASCON_CRYPT_LAST;
    elsif (vRequest.request_type = REQ_TYPE_TREE or vRequest.request_type = REQ_TYPE_TREE_ROOT) then
      vTreeRequest    := '1';
      vAsconLastState := ASCON_TREE_CRYPT_LAST;
    end if;
    DataRequestxS    <= vDataRequest;
    TreeRequestxS    <= vTreeRequest;
    AsconLastStatexD <= vAsconLastState;

    -- Defaults for output
    vOutBlockCounter := std_logic_vector(MAX_COUNTER_VALUE - unsigned(out_block_addr));
    vPhysicalLen     := vRequest.block_len(s_request.block_len'length-1 downto TRANSLATION_FACTOR_BIT) & vOutBlockCounter;
    vPhysicalAddr    := vRequest.block_address(s_request.block_address'length-1 downto TRANSLATION_FACTOR_BIT+2) & out_block_addr & "00";

    out_request               <= vRequest;
    out_request.block_len     <= vPhysicalLen;
    out_request.block_address <= vPhysicalAddr;
    out_request.virt_address  <= (others => '0');

    -- Output overwrites
    if (AsconStatexDP >= ASCON_CRYPT and AsconStatexDP <= vAsconLastState) then
      out_request.virt_address <= std_logic_vector(to_unsigned(vVirtAddr, s_request.virt_address'length));

      if (out_block_ready = '1') then
        vVirtAddr := vVirtAddr + (DATASTREAM_DATA_WIDTH/8);
      end if;
    else
      if AsconStatexDP = ASCON_VERIFY and to_integer(unsigned(vPhysicalLen)) = 0 and out_block_ready = '1' then
        requestProcessedxDN <= '1';
      end if;
      out_request.metadata <= '1';
      out_request.error    <= AuthenticationErrorxS;
    end if;

    out_request.valid <= out_block_valid and not(AsconSyncxDP);

    if AsconStatexDP /= ASCON_INIT and AsconStatexDP /= ASCON_IDLE then
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
        AsconStatexDP       <= ASCON_IDLE;
        AsconSyncxDP        <= '0';
        requestRegxDP       <= StreamType_default;
        virtualAddrRegxDP   <= (others => '0');
        requestProcessedxDP <= '1';
        BufferFullxDP       <= '0';
        BufferxDP           <= StreamType_default;
      else
        AsconStatexDP       <= AsconStatexDN;
        AsconSyncxDP        <= AsconSyncxDN;
        requestRegxDP       <= requestRegxDN;
        virtualAddrRegxDP   <= virtualAddrRegxDN;
        requestProcessedxDP <= requestProcessedxDN;
        BufferFullxDP       <= BufferFullxDN;
        BufferxDP           <= BufferxDN;
      end if;
    end if;
  end process regs;

end Behavioral;
