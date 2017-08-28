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

# check if ghdl is available
FLOW_GHDL_BINARY ?= $(shell which ghdl)
ifneq (${FLOW_GHDL_BINARY},)
FLOW_BACKENDS        += ghdl
FLOW_DEFAULT_BACKEND ?= ghdl

###############################################################################
# Backend specific variables
###############################################################################
FLOW_GTKWAVE_BINARY ?= $(shell which gtkwave)

FLOW_GHDL_CFLAGS ?=
FLOW_GHDL_RFLAGS ?=

# define which variables should be shown on the info screen
BACKEND_INFO_VARS += $(filter FLOW_GHDL_%,$(.VARIABLES)) FLOW_GTKWAVE_BINARY

###############################################################################
# Backend specific targets
###############################################################################

.PHONY: ghdl_project
PROJECT := ${FLOW_BINARY_DIR}/${FLOW_SIMTOP}.stamp
${PROJECT}:
	mkdir -p ${FLOW_BINARY_DIR}
	cd ${FLOW_BINARY_DIR}; sh ${FLOW_SCRIPT_DIR}/ghdl/generate_project.sh
	touch $@
ghdl_project: ${PROJECT}

.PHONY: ghdl_hdlsb
ghdl_hdlsb: ${PROJECT}
	cd ${FLOW_BINARY_DIR}; sh ${FLOW_SCRIPT_DIR}/ghdl/run_simulation.sh

.PHONY: ghdl_hdlsg
ghdl_hdlsg: ${PROJECT}
	cd ${FLOW_BINARY_DIR}; FLOW_GTKWAVE_GUI=1 sh ${FLOW_SCRIPT_DIR}/ghdl/run_simulation.sh

.PHONY: ghdl_synthcb
ghdl_synthcb:
	echo "Synthesis is not supported by GHDL!"
	exit 1

.PHONY: ghdl_implcb
ghdl_implcb:
	echo "Implementation is not supported by GHDL!"
	exit 1

endif # FLOW_GHDL_BINARY not empty
