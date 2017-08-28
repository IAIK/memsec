[![Build Status](https://travis-ci.org/IAIK/memsec.svg?branch=develop)](https://travis-ci.org/IAIK/memsec)

# Transparent Memory Encryption and Authentication

VHDL code of the [Transparent Memory Encryption and Authentication](https://eprint.iacr.org/2017/674) framework which has been published at [FPL 2017](https://www.fpl2017.org/). Additionally, the implemenation of a novel side-channel secure memory encryption scheme called [MEAS](https://eprint.iacr.org/2017/663) is included.

RAM encryption and authentication, as shown by the implementation of [Intel SGX](https://eprint.iacr.org/2016/204) and [AMD SME](http://developer.amd.com/wordpress/media/2013/12/AMD_Memory_Encryption_Whitepaper_v7-Public.pdf), is an important measure to implement a secure system. However, no open source implementations exist which can be used in free hardware designs or to evaluate new schemes.

To address this problem, we present a modular open-source framework for building transparent RAM encryption and authentication solutions. Our framework comprises a comprehensive collection of modular building blocks which can be used  to built efficient hardware designs with different cryptographic primitives in arbitrary modes of operation. At the moment only AXI-4 is supported as bus interface. However, due to the separation between external bus interface and internal data stream, we expect that porting other (possibly less feature rich) interconnects is easily possibly.

The top modules in the `hdl/top` directory contain example pipelines (e.g., `memsec_block_encryption` and `memsec_ascon`) which are built using our framework. The `memsec` top level entity, on the other hand, is simply used to multiplex between the different designs for simulation and bitfile generation.

## Cryptographic Primitives and Modes

Used primitives:
* [AES-128](https://doi.org/10.6028/NIST.FIPS.197): Currently no implementation bundled!
* [Ascon-128 v1.2](http://ascon.iaik.tugraz.at/specification.html): [Original implementation](https://github.com/IAIK/ascon_hardware) by Hannes Groß
* [PRINCE](https://eprint.iacr.org/2012/529): Implementation by Erich Wenger
* [QARMA-64 (sigma1)](https://eprint.iacr.org/2016/444): Implementation by Thomas Unterluggauer
* [Keccak-f[400]](http://keccak.noekeon.org/): Implemenation by Thomas Kastner, Christian Maierhofer, and Mario Werner

Modes and tested primitives:
* ECB/Standalone
  * AES
  * Ascon
  * PRINCE
* [CBC-ESSIV](http://clemens.endorphin.org/nmihde/nmihde-A4-os.pdf)
  * AES
  * PRINCE
* [MEAS](https://eprint.iacr.org/2017/663) (with different re-keying approaches for the tree nodes)
  * Ascon + PRINCE + Keccak PRNG
  * Ascon + QARMA + Keccak PRNG
* [TEC-Tree](https://www.iacr.org/archive/ches2007/47270289/47270289.pdf) 
  * Ascon (= AE cipher instead of AREA construction)
* [XTS](https://doi.org/10.1109%2FIEEESTD.2008.4493450) (tweak is computed using decryption instead of encryption)
  * AES
  * PRINCE

All these configurations have been tested using HDL simulation as well as in practice for encrypting Linux on a [ZedBoard](http://zedboard.org/product/zedboard) featuring a Xilinx Zynq-7020 SoC FPGA. As EDA tool, Vivado 2016.2 has been used.

## The HDL Flow

The framework comes with a Makefile-based HDL flow. This flow can be used to run simulations, and to build bitstream files from the command line. Conceptually, the flow acts as custom front-end for the EDA (e.g., Vivado) tools which perform the real work and is controlled by environment variables and via command line parameters. Like any other make invocation the basic syntax of calling the flow looks the following:

`make <target> [Varibles and Definitions]`

Important Targets:
* `clean`: Delete the binary directory of the module.
* `distclean`: Delete the binary root directory.
* `info`: Print information about discovered flow variables and the module which is built. (Lists even the source files when `VERBOSE=1` is specified.)
* `hdlsb`: Simulate the module (batch mode).
* `hdlsg`: Simulate the module (GUI).
* `synthcb`: Synthesize the module (batch mode).
* `implcb`: Implement the module (batch mode).

### Flow Variables

Variables and variable overrides are the most powerful and complex part of the flow which permit to customize how the framework is simulated or built. The default configuration for the build-able modules is rather simple and can be found in the `Makefile` and mostly touch the following variables:

* `FLOW_MODULE=<modulename>`: (default: `memsec`) The flow supports to manage multiple different modules in one source tree. This variable selects which module is currently active.
* `BINARY_ROOT_DIR=<path>`: (default: `_build` when make is called in-source or `.` when make is called out-of-source) All build artifacts are generated out-of-source in a build directory which can be overwritten using this variable.
* `FLOW_HDLTOP=<entity>`: The top module of the design. Important when the module gets packaged as IP core for the use in a block design.
* `FLOW_SIMTOP=<entity>`: The top module which gets simulated.
* `FLOW_HDL_FILES=<hdlfiles>`: The HDL files which make up the module. (typically not overwritten via the command line)
* `FLOW_SIMHDL_FILES=<hdlfiles>`:The HDL files which make up the test bench of the module. (typically not overwritten via the command line)
* `FLOW_SIMULATION_TIME=<duration>`: (default: `500us`) The time duration which is run in a simulation.

Besides these more or less static configuration options, also more dynamic options like generics can be specified as simple environment or command line variables. The syntax for overriding generics is as follows: `GENERIC_<parameter>=<value>`

Last but not least, also a few Vivado specific options exist. These options mainly deal with Vivado specifics like tcl files to generate block designs and IP cores which can be used for simulation. However, when a block design is used, also the generics for the instantiated IP cores have to be overwritten using the Vivado specific variables.

* `FLOW_VIVADO_SIMIP_FILES=<xcifiles>`: The Vivado IP files (.xci) which are used in the test bench. (typically not overwritten via the command line)
* `FLOW_VIVADO_IP_REPO_PATHS=<repopaths>`: Paths where the used IP cores are located.
* `FLOW_VIVADO_BD_TCL_FILE=<tclfile>`: The tcl file which is used to generate the block design in Vivado. (typically exported via the tcl command `write_bd_tcl`)
* `FLOW_VIVADO_BD_GENERIC_<parameter>_AT_<bdnode>=<value>`: Block design equivalent to the `GENERIC_<parameter>=<value>` variables.

###  Module Variable Overrides

All previously discussed variables get exported from the Makefile when they are defined. However, in order to support multiple modules in the same source tree, module specific versions of these variables are required. The module specific versions of the discussed variables follow the pattern `<modulename><variablename>=<value>` (e.g., `memsecFLOW_HDLTOP=memsec`). Based on the specified `FLOW_MODULE`, the flow assigns these prefixed variables to the variables without prefix if they are not already defined, and exports them as before.

### Examples

* Simulate the default configuration of the framework: `make hdlsb`
* Simulate the Ascon TEC-Tree (i.e., CRYPTO_CONFIG=2): `make hdlsb GENERIC_CRYPTO_CONFIG=2`
* Build a bitfile with Prince ECB (i.e., CRYPTO_CONFIG=3): `make vivado_package; make implcb FLOW_MODULE=full_memenc FLOW_VIVADO_BD_GENERIC_CRYPTO_CONFIG_AT_memsec_0=3`

As can be seen, specifying multiple parameters potentially leads to very long parameter argument strings, especially during bitfile generation. Therefore, additionally some python tooling is provided to generate the argument lists. Examples for this can be found in `build_bitfiles_fpl_paper.py` and `run_tests.py`.

## License

The framework itself is licensed under GPLv3. On the other hand, the crypto implementations may have different licenses. For example, the Ascon implementation is licensed under Apache-2.0.

## Authors

The majority of the framework was designed and implemented by Thomas Unterluggauer (<thomas.unterluggauer@iaik.tugraz.at>) and Mario Werner (<mario.werner@iaik.tugraz.at>). Additionally, code and concepts from Hannes Groß, Thomas Kastner, Christian Maierhofer, David Schaffenrath, Robert Schilling, and Erich Wenger have been used.

## Open Tasks and Current Limitations

* *Add Open Source AES Implementation*: The AES core which was initially used can not be open-sourced. Therefore, another open source core has to be integrated to restore the original functionality.
* *Open-sourcing new Test Bench*: Unfortunately, the python high level implementation which was used as golden model during development, is not well suited for public release. Therefore, we are currently working on a new reference implementation which eventually will be used for the open source test bench. Furthermore, GHDL support will be added. However, until it is ready, the simple read-write smoke test (which only runs on vivado) has to suffice.
* *Releasing Benchmark Results*: Numerous different hardware configurations have been measured for the FPL publication of which only few have been highlighted in the paper. Publishing all these results in an easily comparable way is planned. However, some tooling has to be developed first to make them easily accessible.
* *Code Refactoring*: During the development of the framework, most of the building blocks where designed when a certain functionality was needed more often. Therefore, sometimes old code still exists which does not yet use all available blocks. Refactoring such code parts is an ongoing effort.
