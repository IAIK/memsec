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
use work.memsec_config.all;

package memsec_pkg is
  -- Crypto configs
  type CryptoConfig is (CRYPTO_PLAIN, CRYPTO_AES_ECB, CRYPTO_AES_CBC, CRYPTO_AES_XTS, CRYPTO_PRINCE_ECB, CRYPTO_PRINCE_CBC, CRYPTO_PRINCE_XTS);

  -- constants for the master interface
  constant ADDRESS_WIDTH : integer := 32;
  constant ID_WIDTH      : integer := 12;

  -- constants for the slave interface
  constant DATASTREAM_DATA_WIDTH : integer := work.memsec_config.DATASTREAM_DATA_WIDTH;
  constant AXI_LEN_WIDTH         : integer := 8;   -- always 8 in AXI4
  constant AXI_DATA_WIDTH        : integer := 32;  -- always 32 on Zynq

  subtype AddressType is std_logic_vector(ADDRESS_WIDTH-1 downto 0);

  -- constants for types
  constant REQ_TYPE_DATA      : std_logic_vector(1 downto 0) := "00";
  constant REQ_TYPE_TREE      : std_logic_vector(1 downto 0) := "10";
  constant REQ_TYPE_TREE_ROOT : std_logic_vector(1 downto 0) := "11";

  --! Stream type for the main internal data stream.
  --!
  --! The stream models transactions which can consists of multiple requests.
  --! The last request in a transaction is marked with the respective flag.
  --! Additionally, every request can again consist of multiple data beats.
  --! The number of remaining beats in a request is communicated via the
  --! block_len field.
  type StreamType is record
    request_type  : std_logic_vector(1 downto 0);                          --! Distinguish data from tree and tree root requests.
    virt_address  : AddressType;                                           --! Virtual address of the beat.
    block_address : AddressType;                                           --! Physical/block address of the beat.
    block_len     : std_logic_vector(AXI_LEN_WIDTH-1 downto 0);            --! Remaining beats in the request. (0...last beat, 0xFF unkown)
    address       : AddressType;                                           --! Originally requested virtual address from the bus.
    id            : std_logic_vector(ID_WIDTH-1 downto 0);                 --! Originally requested id from the bus.
    len           : std_logic_vector(AXI_LEN_WIDTH-1 downto 0);            --! Originally requested length from the bus.
    size          : std_logic_vector(2 downto 0);                          --! Originally requested size from the bus.
    burst         : std_logic_vector(1 downto 0);                          --! Originally requested burst type from the bus.
    cache         : std_logic_vector(3 downto 0);                          --! Originally requested cache config from the bus.
    prot          : std_logic_vector(2 downto 0);                          --! Originally requested protection config from the bus.
    lock          : std_logic;                                             --! Originally requested locking config from the bus.
    qos           : std_logic_vector(3 downto 0);                          --! Originally requested qos config from the bus.
    region        : std_logic_vector(3 downto 0);                          --! Originally requested region specifier from the bus.
    read          : std_logic;                                             --! Mark transaction as data read.
    last_request  : std_logic;                                             --! Mark transaction as last within a request.
    data          : std_logic_vector(DATASTREAM_DATA_WIDTH - 1 downto 0);  --! Actual data which is transfered during one beat.
    valid         : std_logic;                                             --! Mark beat (and all its config flags) as valid.
    metadata      : std_logic;                                             --! Mark beat as metadata.
    error         : std_logic;                                             --! Signal an error in the transaction.
  end record;

  constant StreamType_default : StreamType := (
    request_type  => REQ_TYPE_DATA,
    virt_address  => (others => '0'),
    block_address => (others => '0'),
    block_len     => (others => '0'),
    address       => (others => '0'),
    id            => (others => '0'),
    len           => (others => '0'),
    size          => (others => '0'),
    burst         => (others => '0'),
    cache         => (others => '0'),
    prot          => (others => '0'),
    lock          => '0',
    qos           => (others => '0'),
    region        => (others => '0'),
    read          => '0',
    last_request  => '0',
    data          => (others => '0'),
    valid         => '0',
    metadata      => '0',
    error         => '0'
    );

  type StreamArrayType is array(natural range <>) of StreamType;

  --! Data stream type with support for transactions and strobes
  type BlockStreamType is record
    data    : std_logic_vector(DATASTREAM_DATA_WIDTH - 1 downto 0);   --! data bits of the beat
    strobes : std_logic_vector(DATASTREAM_DATA_WIDTH/8 - 1 downto 0); --! byte strobes, one bit marks 8 data bits as valid if set to true
    last    : std_logic;                                              --! marks the last beat in transaction
    valid   : std_logic;                                              --! marks the beat as valid
  end record;

  constant BlockStreamType_default : BlockStreamType := (
    data    => (others => '0'),
    strobes => (others => '0'),
    last    => '0',
    valid   => '0'
    );
end package;
