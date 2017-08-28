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

# (re)export all FLOW and GENERIC variables into the environment for the use in the tcl files
GENERICS  := $(filter GENERIC_%,$(.VARIABLES))
FLOW_VARS := $(filter FLOW_%,$(.VARIABLES))
export ${GENERICS}
export ${FLOW_VARS}

DEFAULT_INFO_VARS := FLOW_DEFAULT_BACKEND \
                     FLOW_SOURCE_DIR \
                     FLOW_SCRIPT_DIR \
                     FLOW_BINARY_ROOT_DIR \
                     FLOW_BINARY_DIR \
                     FLOW_MODULE \
                     FLOW_HDLTOP \
                     FLOW_SIMTOP \
                     FLOW_HDL_FILES \
                     FLOW_SIMHDL_FILES \
                     FLOW_SIMULATION_TIME \
                     FLOW_MODULES \
                     FLOW_BACKENDS
OTHER_FLOW_VARS := $(filter-out ${DEFAULT_INFO_VARS} ${BACKEND_INFO_VARS},${FLOW_VARS})

# assert that a default backend exists
ifndef FLOW_DEFAULT_BACKEND
$(error No FLOW_DEFAULT_BACKEND backend has been found! Make sure that the necessary EDA tools are installed.)
endif

# aliases for the backend specific targets
.PHONY: project hdlsb hdlsg synthcb implcb
project: info ${FLOW_DEFAULT_BACKEND}_project
hdlsb: info ${FLOW_DEFAULT_BACKEND}_hdlsb
hdlsg: info ${FLOW_DEFAULT_BACKEND}_hdlsg
synthcb: info ${FLOW_DEFAULT_BACKEND}_synthcb
implcb: info ${FLOW_DEFAULT_BACKEND}_implcb

.PHONY: info
info:
	@echo "SOURCE_DIR:      ${FLOW_SOURCE_DIR}"
	@echo "SCRIPT_DIR:      ${FLOW_SCRIPT_DIR}"
	@echo "BINARY_ROOT_DIR: ${FLOW_BINARY_ROOT_DIR}"
	@echo "BINARY_DIR:      ${FLOW_BINARY_DIR}"
	@echo ""
	@echo "Available modules:"
	@$(foreach var,$(sort ${FLOW_MODULES}),echo "    ${var}";)
	@echo ""
	@echo "Available Backends:"
	@$(foreach var,$(sort ${FLOW_BACKENDS}),echo "    ${var}";)
	@echo ""
	@echo "FLOW_DEFAULT_BACKEND: ${FLOW_DEFAULT_BACKEND}"
	@echo "FLOW_MODULE:          ${FLOW_MODULE}"
ifdef FLOW_HDLTOP
	@echo "FLOW_HDLTOP:          ${FLOW_HDLTOP}"
endif # FLOW_HDLTOP
ifdef FLOW_SIMTOP
	@echo "FLOW_SIMTOP:          ${FLOW_SIMTOP}"
endif # FLOW_SIMTOP
ifdef FLOW_SIMULATION_TIME
	@echo "FLOW_SIMULATION_TIME: ${FLOW_SIMULATION_TIME}"
endif # FLOW_SIMULATION_TIME
ifdef GENERICS
	@echo ""
	@echo "Overwritten generics: (GENERIC_*)"
	@$(foreach var,$(sort ${GENERICS}),echo "    $(subst GENERIC_,,${var})=${${var}}";)
endif # GENERICS
ifdef BACKEND_INFO_VARS
	@echo ""
	@echo "Backend specific variables:"
	@$(foreach var,$(sort ${BACKEND_INFO_VARS}),echo "    ${var}=${${var}}";)
endif # BACKEND_INFO_VARS
ifdef OTHER_FLOW_VARS
	@echo ""
	@echo "Other variables: (FLOW_*)"
	@$(foreach var,$(sort ${OTHER_FLOW_VARS}),echo "    ${var}=${${var}}";)
endif # OTHER_FLOW_VARS
ifdef VERBOSE
	@echo ""
	@echo "HDL files: (FLOW_HDL_FILES)"
	@$(foreach var,$(sort ${FLOW_HDL_FILES}),echo "    ${var}";)
	@echo ""
	@echo "SIMHDL files: (FLOW_SIMHDL_FILES)"
	@$(foreach var,$(sort ${FLOW_SIMHDL_FILES}),echo "    ${var}";)
endif # VERBOSE
	@echo ""

.PHONY: help
help:
	@echo "Usage: make <target> [FLOW_MODULE=<module>] [additional options]"
	@echo ""
	@echo "Available modules: (selected \"${FLOW_MODULE}\")"
	@$(foreach var,$(sort ${FLOW_MODULES}),echo "    ${var}";)
	@echo ""
	@echo "Common targets:"
	@echo "    clean.............Delete the binary directory of the module."
	@echo "    distclean.........Delete the binary root directory."
	@echo "    info [VERBOSE=1]..Print information about the module and the flow."
	@echo "    project...........Generate a project for the module into the binary directory."
	@echo ""
	@echo "    hdlsb.............Simulate the module (batch mode)."
	@echo "    hdlsg.............Simulate the module (GUI)."
	@echo ""
	@echo "    synthcb...........Synthesize the module (batch mode)."
	@echo ""
	@echo "    implcb............Implement the module (batch mode)."
ifdef BACKEND_HELP_TEXT
	@echo ""
	@echo "Backend specific targets:"
	@$(foreach var,$(sort ${BACKEND_HELP_TEXT}),echo "    $(subst +,${space},${var})";)
endif # BACKEND_HELP_TEXT
	@echo ""

.PHONY: clean
clean:
	rm -rf ${FLOW_BINARY_DIR}

.PHONY: distclean
distclean:
	rm -rf ${FLOW_BINARY_ROOT_DIR}
