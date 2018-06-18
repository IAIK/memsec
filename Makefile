#
# MEMSEC - Framework for building transparent memory encryption and authentication solutions.
# Copyright (C) 2017-2018 Graz University of Technology, IAIK <mario.werner@iaik.tugraz.at>
#
# This file is part of MEMSEC.
#
# MEMSEC is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# MEMSEC is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with MEMSEC.  If not, see <http://www.gnu.org/licenses/>.
#

# determine the source directory and the default script directory based on the Makefile
override FLOW_SOURCE_SCRIPT := $(realpath $(firstword $(MAKEFILE_LIST)))
override FLOW_SOURCE_DIR    := $(shell dirname $(FLOW_SOURCE_SCRIPT))
FLOW_DIR                    ?= ${FLOW_SOURCE_DIR}/flow

FLOW_MODULE ?= memsec

# The used test benches write the result into a file inside the simulation
# directory where 1 means success and 0 means failure.
${FLOW_MODULE}FLOW_SIM_RESULT_FILE  ?= ${${FLOW_MODULE}FLOW_SIM_TOP}_log.txt
${FLOW_MODULE}FLOW_SIM_RESULT_REGEX ?= ^1
${FLOW_MODULE}FLOW_SIM_RESULT_RULE  ?= file-success

include $(FLOW_DIR)/binary_directory_defines.mk
###############################################################################
# memsec IP module
###############################################################################
FLOW_MODULES                   += memsec
memsecFLOW_HDL_FILES           ?= $(shell find ${FLOW_SOURCE_DIR}/hdl -iname *.vhd | xargs) $(shell find ${FLOW_SOURCE_DIR}/hdl -iname *.vhdl | xargs)
memsecFLOW_SIM_HDL_FILES       ?= $(shell find ${FLOW_SOURCE_DIR}/tb -maxdepth 1 -iname *.vhd | xargs)
memsecFLOW_VIVADO_SIM_IP_FILES ?= $(shell find ${FLOW_SOURCE_DIR}/tb -iname *.xci | xargs)
memsecFLOW_HDL_TOP             ?= memsec
memsecFLOW_SIM_TOP             ?= tb_rw_blockram

###############################################################################
# integration module which embeds the memsec IP core into a block design
###############################################################################
FLOW_MODULES                           += full_memenc
full_memencFLOW_VIVADO_IP_DEPENDENCIES ?= memsec
full_memencFLOW_VIVADO_IP_REPO_PATHS   ?= ${FLOW_SOURCE_DIR}
full_memencFLOW_VIVADO_BD_TCL_FILE     ?= ${FLOW_SOURCE_DIR}/examples/full_memenc_bd.tcl

full_memencFLOW_VIVADO_BD_GENERIC_PCW_FPGA0_PERIPHERAL_FREQMHZ_AT_processing_system7_0 ?= 50
full_memencFLOW_VIVADO_BD_GENERIC_PCW_FCLK0_PERIPHERAL_CLKSRC_AT_processing_system7_0  ?= IO PLL

default: help

include $(FLOW_DIR)/global_defines.mk
include $(FLOW_DIR)/ghdl.mk
include $(FLOW_DIR)/vivado.mk
include $(FLOW_DIR)/default.mk
