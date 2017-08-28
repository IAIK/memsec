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

# check if vivado is available
FLOW_VIVADO_BINARY ?= $(shell which vivado)
ifneq (${FLOW_VIVADO_BINARY},)
FLOW_BACKENDS        += vivado
FLOW_DEFAULT_BACKEND ?= vivado

###############################################################################
# Backend specific variables
###############################################################################

# vivado default settings
FLOW_VIVADO_PARTNAME ?= xc7z020clg484-1
FLOW_VIVADO_BOARD    ?= em.avnet.com:zed:part0:1.3

# Syntesis defaults:
# Vivado Synthesis Defaults, Flow_AreaOptimized_high, Flow_AlternateRoutability,
# Flow_PerfOptimized_high, Flow_PerfThresholdCarry, Flow_RuntimeOptimized, ...
FLOW_VIVADO_SYNTH_STRATEGY ?= Vivado Synthesis Defaults

# Implementation defaults:
# Vivado Implementation Defaults, Performance_Explore, Performance_NetDelay_low
FLOW_VIVADO_IMPL_STRATEGY  ?= Vivado Implementation Defaults

# define which variables should be shown on the info screen
BACKEND_INFO_VARS += $(filter FLOW_VIVADO_%,$(.VARIABLES))

###############################################################################
# Backend specific targets
###############################################################################

# Intuitively, the xpr file would be the correct artifact for the project
# generation. Unfortunately, this file gets always updated when the project is
# openend. Therefore, a helper file in the project directory is used instead.
.PHONY: vivado_project
PROJECT := ${FLOW_BINARY_DIR}/vivado_generated
${PROJECT}:
	mkdir -p ${FLOW_BINARY_DIR}
	cd ${FLOW_BINARY_DIR}; ${FLOW_VIVADO_BINARY} -nojournal -log ${FLOW_BINARY_ROOT_DIR}/${FLOW_MODULE}_project_generation.log -mode batch -source ${FLOW_SCRIPT_DIR}/vivado/generate_project.tcl
	touch $@
vivado_project: ${PROJECT}

.PHONY: vivado_hdlsb
vivado_hdlsb: ${PROJECT}
	cd ${FLOW_BINARY_DIR}; ${FLOW_VIVADO_BINARY} -nojournal -log ${FLOW_BINARY_ROOT_DIR}/${FLOW_MODULE}_simulation.log -mode batch -source ${FLOW_SCRIPT_DIR}/vivado/run_simulation.tcl

.PHONY: vivado_hdlsg
vivado_hdlsg: ${PROJECT}
	cd ${FLOW_BINARY_DIR}; FLOW_VIVADO_GUI=1 ${FLOW_VIVADO_BINARY} -nojournal -log ${FLOW_BINARY_ROOT_DIR}/${FLOW_MODULE}_simulation.log -mode batch -source ${FLOW_SCRIPT_DIR}/vivado/run_simulation.tcl

.PHONY: vivado_synthcb
SYNTH_DCP := ${FLOW_BINARY_ROOT_DIR}/${FLOW_MODULE}-synth.dcp
${SYNTH_DCP}: ${PROJECT}
	cd ${FLOW_BINARY_DIR}; ${FLOW_VIVADO_BINARY} -nojournal -log ${FLOW_BINARY_ROOT_DIR}/${FLOW_MODULE}_synthesis.log -mode batch -source ${FLOW_SCRIPT_DIR}/vivado/run_synthesis.tcl
vivado_synthcb: ${SYNTH_DCP}

.PHONY: vivado_implcb
BITSTREAM_FILE := ${FLOW_BINARY_ROOT_DIR}/${FLOW_MODULE}.bit
${BITSTREAM_FILE}: ${SYNTH_DCP}
	cd ${FLOW_BINARY_DIR}; ${FLOW_VIVADO_BINARY} -nojournal -log ${FLOW_BINARY_ROOT_DIR}/${FLOW_MODULE}_implementation.log -mode batch -source ${FLOW_SCRIPT_DIR}/vivado/run_implementation.tcl
	mv ${FLOW_BINARY_DIR}/${FLOW_MODULE}.runs/impl_1/bd_wrapper.bit $@
vivado_implcb: ${BITSTREAM_FILE}

#------------------------------------------------------------------------------
# Custom targets
#------------------------------------------------------------------------------

.PHONY: vivado_open
BACKEND_HELP_TEXT += $(subst ${space},+,"vivado_open.......Open the vivado project of the module.")
vivado_open: ${PROJECT}
	cd ${FLOW_BINARY_DIR}; ${FLOW_VIVADO_BINARY} ${FLOW_MODULE}.xpr

.PHONY: vivado_package
BACKEND_HELP_TEXT += $(subst ${space},+,"vivado_package....Package the module as Vivado IP core.")
PACKAGE_XML := ${FLOW_SOURCE_DIR}/component.xml
${PACKAGE_XML}: ${PROJECT}
	cd ${FLOW_BINARY_DIR}; ${FLOW_VIVADO_BINARY} -nojournal -log ${FLOW_BINARY_ROOT_DIR}/${FLOW_MODULE}_package.log -mode batch -source ${FLOW_SCRIPT_DIR}/vivado/package_ip.tcl
vivado_package: ${PACKAGE_XML}

endif # FLOW_VIVADO_BINARY not empty
