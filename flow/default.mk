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

# (re)export all FLOW and GENERIC variables into the environment for the use in the sh and tcl files
GENERICS  := $(filter GENERIC_%,$(.VARIABLES))
FLOW_VARS := $(filter FLOW_%,$(.VARIABLES))
export ${GENERICS}
export ${FLOW_VARS}

OTHER_FLOW_VARS := $(filter-out ${DEFAULT_INFO_VARS} ${HIDDEN_INFO_VARS} ${STANDARD_MODULE_PROPERTIES} ${BACKEND_INFO_VARS},${FLOW_VARS})

# assert that a default backend exists
ifndef FLOW_BACKEND
$(error No FLOW_BACKEND backend has been found! Make sure that the necessary EDA tools are installed.)
endif

# aliases for the backend specific targets
.PHONY: project hdlsb hdlsg synthcb implcb
project: ${FLOW_BACKEND}_project
hdlsb: ${FLOW_BACKEND}_hdlsb
hdlsg: ${FLOW_BACKEND}_hdlsg
synthcb: ${FLOW_BACKEND}_synthcb
implcb: ${FLOW_BACKEND}_implcb

.PHONY: info
info:
	@$(call printStep,"### ${FLOW_MODULE}: calling $@")
ifdef VERBOSE
	@echo "Directory configuration:"
	@echo "FLOW_DIR:        ${FLOW_DIR}"
	@echo "BINARY_DIR:      ${FLOW_BINARY_DIR}"
	@echo "BINARY_ROOT_DIR: ${FLOW_BINARY_ROOT_DIR}"
	@echo "SOURCE_DIR:      ${FLOW_SOURCE_DIR}"
	@echo "SOURCE_SCRIPT:   ${FLOW_SOURCE_SCRIPT}"
	@echo ""
	@echo "Available Backends:"
	@$(foreach var,$(sort ${FLOW_BACKENDS}),echo "    ${var}";)
	@echo ""
	@echo "Available modules:"
	@$(foreach var,$(sort ${FLOW_MODULES}),echo "    ${var}";)
	@echo ""
endif # VERBOSE
	@echo "FLOW_BACKEND:           ${FLOW_BACKEND}"
	@echo "FLOW_MODULE:            ${FLOW_MODULE}"
ifdef FLOW_HDL_TOP
	@echo "FLOW_HDL_TOP:           ${FLOW_HDL_TOP}"
endif # FLOW_HDL_TOP
ifdef FLOW_SIM_TOP
	@echo "FLOW_SIM_TOP:           ${FLOW_SIM_TOP}"
endif # FLOW_SIM_TOP
ifdef FLOW_LIBRARY_NAME
	@echo "FLOW_LIBRARY_NAME:      ${FLOW_LIBRARY_NAME}"
endif # FLOW_LIBRARY_NAME
ifdef FLOW_DEPENDENCIES
	@echo "FLOW_DEPENDENCIES:      ${FLOW_DEPENDENCIES}"
endif # FLOW_DEPENDENCIES
ifdef FLOW_SIM_DEPENDENCIES
	@echo "FLOW_SIM_DEPENDENCIES:  ${FLOW_SIM_DEPENDENCIES}"
endif # FLOW_SIM_DEPENDENCIES
ifdef FLOW_FULL_DEPENDENCIES
	@echo "FLOW_FULL_DEPENDENCIES: ${FLOW_FULL_DEPENDENCIES}"
endif # FLOW_FULL_DEPENDENCIES
ifdef FLOW_SIM_RESULT_FILE
	@echo "FLOW_SIM_RESULT_FILE:   ${FLOW_SIM_RESULT_FILE}"
endif # FLOW_SIM_RESULT_FILE
ifdef FLOW_SIM_RESULT_REGEX
	@echo "FLOW_SIM_RESULT_REGEX:  ${FLOW_SIM_RESULT_REGEX}"
endif # FLOW_SIM_RESULT_REGEX
ifdef FLOW_SIM_RESULT_RULE
	@echo "FLOW_SIM_RESULT_RULE:   ${FLOW_SIM_RESULT_RULE}"
endif # FLOW_SIM_RESULT_RULE
ifdef FLOW_SIM_TIME
	@echo "FLOW_SIM_TIME:          ${FLOW_SIM_TIME}"
endif # FLOW_SIM_TIME
ifdef VERBOSE
	@echo ""
ifdef FLOW_FULL_DEPENDENCY_DIRS
	@echo "FLOW_FULL_DEPENDENCY_DIRS: ${FLOW_FULL_DEPENDENCY_DIRS}"
endif # FLOW_FULL_DEPENDENCY_DIRS
ifdef FLOW_FILES
	@echo ""
	@echo "Files: (FLOW_FILES)"
	@$(foreach var,$(sort ${FLOW_FILES}),echo "    ${var}";)
endif # FLOW_FILES
ifdef FLOW_HDL_FILES
	@echo ""
	@echo "HDL files: (FLOW_HDL_FILES)"
	@$(foreach var,$(sort ${FLOW_HDL_FILES}),echo "    ${var}";)
endif # FLOW_HDL_FILES
ifdef FLOW_SIM_FILES
	@echo ""
	@echo "SIML files: (FLOW_SIM_FILES)"
	@$(foreach var,$(sort ${FLOW_SIM_FILES}),echo "    ${var}";)
endif # FLOW_SIM_FILES
ifdef FLOW_SIM_HDL_FILES
	@echo ""
	@echo "SIM_HDL files: (FLOW_SIM_HDL_FILES)"
	@$(foreach var,$(sort ${FLOW_SIM_HDL_FILES}),echo "    ${var}";)
endif # FLOW_SIM_HDL_FILES
endif # VERBOSE
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
	@echo ""
ifeq (${FLOW_VERBOSITY},3)
	@$(foreach module,$(FLOW_FULL_DEPENDENCIES),$(call makeTarget,FLOW_MODULE=$(module) FLOW_VERBOSITY=2 $@);)
endif

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
	@$(call printStep,"### ${FLOW_MODULE}: removing the binary directory of the module")
	@$(call printStep,"$$ rm -rf ${FLOW_BINARY_DIR}")
	@rm -rf ${FLOW_BINARY_DIR}
	@$(call printStep,"")

.PHONY: distclean
distclean:
	@$(call printStep,"### removing all binary directories")
	@$(call printStep,"$$ rm -rf ${FLOW_BINARY_ROOT_DIR}")
	@rm -rf ${FLOW_BINARY_ROOT_DIR}
	@$(call printStep,"")
