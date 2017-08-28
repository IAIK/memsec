#
# MEMSEC - Framework for building transparent memory encryption and authentication solutions.
# Copyright (C) 2017 Graz University of Technology, IAIK <mario.werner@iaik.tugraz.at>
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
FLOW_SOURCE_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
FLOW_SCRIPT_DIR ?= ${FLOW_SOURCE_DIR}/flow

FLOW_MODULE ?= memsec

###############################################################################
# memsec IP module
###############################################################################
FLOW_MODULES                  += memsec
memsecFLOW_HDL_FILES          ?= $(shell find ${FLOW_SOURCE_DIR}/hdl -iname *.vhd | xargs) $(shell find ${FLOW_SOURCE_DIR}/hdl -iname *.vhdl | xargs)
memsecFLOW_SIMHDL_FILES       ?= $(shell find ${FLOW_SOURCE_DIR}/tb -maxdepth 1 -iname *.vhd | xargs)
memsecFLOW_VIVADO_SIMIP_FILES ?= $(shell find ${FLOW_SOURCE_DIR}/tb -iname *.xci | xargs)
memsecFLOW_HDLTOP             ?= memsec
memsecFLOW_SIMTOP             ?= tb_rw_blockram

###############################################################################
# integration module which embeds the memsec IP core into a block design
###############################################################################
FLOW_MODULES                         += full_memenc
full_memencFLOW_VIVADO_IP_REPO_PATHS ?= ${FLOW_SOURCE_DIR}
full_memencFLOW_VIVADO_BD_TCL_FILE   ?= ${FLOW_SOURCE_DIR}/examples/full_memenc_bd.tcl

full_memencFLOW_VIVADO_BD_GENERIC_PCW_FPGA0_PERIPHERAL_FREQMHZ_AT_processing_system7_0 ?= 50
full_memencFLOW_VIVADO_BD_GENERIC_PCW_FCLK0_PERIPHERAL_CLKSRC_AT_processing_system7_0  ?= IO PLL

default: help

include $(FLOW_SCRIPT_DIR)/global_defines.mk
include $(FLOW_SCRIPT_DIR)/vivado.mk
include $(FLOW_SCRIPT_DIR)/ghdl.mk
include $(FLOW_SCRIPT_DIR)/default.mk
