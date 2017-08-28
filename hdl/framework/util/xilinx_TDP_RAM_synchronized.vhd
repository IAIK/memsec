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

--! Dual port RAM where each channel is fully synchronized with handshake signals.
entity xilinx_TDP_RAM_synchronized is
  generic(
    ADDR_WIDTH : integer := 32;
    DATA_WIDTH : integer := 64;
    ENTRIES    : integer := 32  -- number of entries  (should be a power of 2)
    );
  port(
    clk    : in std_logic;  -- clock
    resetn : in std_logic;  -- reset for the internal registers, the RAM is not reset

    addra : in  std_logic_vector(ADDR_WIDTH-1 downto 0);  -- Port A Address bus, width determined from RAM_DEPTH
    dina  : in  std_logic_vector(DATA_WIDTH-1 downto 0);  -- Port A RAM input data
    wea   : in  std_logic;                                -- Port A Write enable
    vina  : in  std_logic;                                -- Port A Input data is valid
    rina  : out std_logic;                                -- Port A Input data has been processed (=ready)

    douta : out std_logic_vector(DATA_WIDTH-1 downto 0);  -- Port A RAM output data
    vouta : out std_logic;                                -- Port A Output data is valid
    routa : in  std_logic;                                -- Port A Output data has been processed (=ready)

    addrb : in  std_logic_vector(ADDR_WIDTH-1 downto 0);  -- Port B Address bus, width determined from RAM_DEPTH
    dinb  : in  std_logic_vector(DATA_WIDTH-1 downto 0);  -- Port B RAM input data
    web   : in  std_logic;                                -- Port B Write enable
    vinb  : in  std_logic;                                -- Port B Input data is valid
    rinb  : out std_logic;                                -- Port B Input data has been processed (=ready)

    doutb : out std_logic_vector(DATA_WIDTH-1 downto 0);  -- Port B RAM output data
    voutb : out std_logic;                                -- Port B Output data is valid
    routb : in  std_logic                                 -- Port B Output data has been processed (=ready)
    );
end xilinx_TDP_RAM_synchronized;

architecture arch_imp of xilinx_TDP_RAM_synchronized is
  signal out_reg_axDP, out_reg_axDN     : std_logic_vector(DATA_WIDTH-1 downto 0);
  signal out_reg_bxDP, out_reg_bxDN     : std_logic_vector(DATA_WIDTH-1 downto 0);
  signal reg_a_validxDP, reg_a_validxDN : std_logic;
  signal reg_b_validxDP, reg_b_validxDN : std_logic;
  signal ram_data_a_validxDP            : std_logic;
  signal ram_data_b_validxDP            : std_logic;

  signal enable_a, enable_b     : std_logic;
  signal ram_data_a, ram_data_b : std_logic_vector(DATA_WIDTH-1 downto 0);
begin

  regs : process(clk) is
  begin
    if rising_edge(clk) then
      if resetn = '0' then
        out_reg_axDP        <= (others => '0');
        out_reg_bxDP        <= (others => '0');
        reg_a_validxDP      <= '0';
        reg_b_validxDP      <= '0';
        ram_data_a_validxDP <= '0';
        ram_data_b_validxDP <= '0';
      else
        out_reg_axDP        <= out_reg_axDN;
        out_reg_bxDP        <= out_reg_bxDN;
        reg_a_validxDP      <= reg_a_validxDN;
        reg_b_validxDP      <= reg_b_validxDN;
        ram_data_a_validxDP <= enable_a;
        ram_data_b_validxDP <= enable_b;
      end if;
    end if;
  end process regs;

  comb : process(out_reg_axDP, out_reg_bxDP, ram_data_a, ram_data_a_validxDP,
                 ram_data_b, ram_data_b_validxDP, reg_a_validxDP,
                 reg_b_validxDP, routa, routb, vina, vinb)
  begin
    out_reg_axDN   <= out_reg_axDP;
    out_reg_bxDN   <= out_reg_bxDP;
    reg_a_validxDN <= reg_a_validxDP;
    reg_b_validxDN <= reg_b_validxDP;
    enable_a       <= '0';
    enable_b       <= '0';
    rina           <= '0';
    rinb           <= '0';

    -- By default the data from the RAM is directly output.
    -- But if data is in the output registers, this data is returned instead.
    douta <= ram_data_a;
    doutb <= ram_data_b;
    vouta <= ram_data_a_validxDP;
    voutb <= ram_data_b_validxDP;
    if reg_a_validxDP = '1' then
      douta <= out_reg_axDP;
      vouta <= '1';
      if routa = '1' then
        reg_a_validxDN <= '0';
      end if;
    end if;
    if reg_b_validxDP = '1' then
      doutb <= out_reg_bxDP;
      voutb <= '1';
      if routb = '1' then
        reg_b_validxDN <= '0';
      end if;
    end if;

    -- Write the output data from the RAM into the output registers when it is
    -- not read from the output.
    if ram_data_a_validxDP = '1' and routa = '0' then
      out_reg_axDN   <= ram_data_a;
      reg_a_validxDN <= '1';
    end if;
    if ram_data_b_validxDP = '1' and routb = '0' then
      out_reg_bxDN   <= ram_data_b;
      reg_b_validxDN <= '1';
    end if;

    -- Perform the actual RAM operation given that the result can always be
    -- stored in the output register.
    if vina = '1' and reg_a_validxDP = '0' and (ram_data_a_validxDP = '0' or routa = '1') then
      enable_a <= '1';
      rina     <= '1';
    end if;
    if vinb = '1' and reg_b_validxDP = '0' and (ram_data_b_validxDP = '0' or routb = '1') then
      enable_b <= '1';
      rinb     <= '1';
    end if;

  end process comb;

  ram : entity work.xilinx_TDP_RAM
    generic map(
      ADDR_WIDTH => ADDR_WIDTH,
      DATA_WIDTH => DATA_WIDTH,
      ENTRIES    => ENTRIES
      )
    port map (
      clk => clk,

      addra => addra,
      addrb => addrb,
      dina  => dina,
      dinb  => dinb,

      wea => wea,
      web => web,
      ena => enable_a,
      enb => enable_b,

      douta => ram_data_a,
      doutb => ram_data_b
      );

end arch_imp;
