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

# check if ghdl is available
FLOW_GHDL_BINARY ?= $(shell which ghdl)
ifneq (${FLOW_GHDL_BINARY},)
FLOW_BACKEND  ?= ghdl
FLOW_BACKENDS += ghdl

ifeq (${FLOW_BACKEND},ghdl)
###############################################################################
# Backend specific variables
###############################################################################
FLOW_GTKWAVE_BINARY ?= $(shell which gtkwave)
FLOW_LCOV_BINARY ?= $(shell which lcov)
FLOW_GENHTML_BINARY ?= $(shell which genhtml)

FLOW_GHDL_GCC ?= $(shell ! ${FLOW_GHDL_BINARY} -v | grep -q "GCC back-end code generator"; echo $$?)

# Additional flags that are passed to ghdl during project generation
# (i.e., in the analysis and elaboration phase).
ifeq (${FLOW_GHDL_GCC},1)
FLOW_GHDL_CFLAGS += -Wc,-ftest-coverage -Wc,-fprofile-arcs -Wl,--coverage
endif

# Additional flags that are passed to ghdl during simulation
# (i.e., in the run phase).
# FLOW_GHDL_RFLAGS ?=

# define which variables should be shown on the info screen
BACKEND_INFO_VARS += $(filter FLOW_GHDL_%,$(.VARIABLES)) FLOW_GTKWAVE_BINARY FLOW_LCOV_BINARY FLOW_GENHTML_BINARY

###############################################################################
# Backend specific targets
###############################################################################

.PHONY: ghdl_project ghdl_subproject
GHDL_PROJECT := ${FLOW_BINARY_DIR}/${FLOW_MODULE}-${FLOW_SIM_TOP}.stamp
${GHDL_PROJECT}: ${FLOW_HDL_FILES} ${FLOW_SIM_HDL_FILES}
	@mkdir -p ${FLOW_BINARY_DIR}
	@cd ${FLOW_BINARY_DIR}; FLOW_LOG_FILE="${FLOW_BINARY_ROOT_DIR}/${FLOW_MODULE}_${FLOW_SIM_TOP}_project.log" bash ${FLOW_DIR}/ghdl/project.sh
	@touch $@

ghdl_project:
	@$(call printStep,"### ${FLOW_MODULE}: processing dependencies")
	@$(foreach entry,$(FLOW_SIM_FILES),mkdir -p $(dir $(lastword $(subst :, ,$(entry)))) && cp $(firstword $(subst :, ,$(entry))) $(lastword $(subst :, ,$(entry)));)
	@$(foreach module,$(FLOW_FULL_DEPENDENCIES),$(call makeTarget,FLOW_MODULE=$(module) ghdl_subproject);)
	@$(call printStep,"### ${FLOW_MODULE}: configuring as top-level project")
	@$(call makeTarget,$(GHDL_PROJECT))
	@$(call printStep,"")

ghdl_subproject:
	@$(call printStep,"### ${FLOW_MODULE}: configuring as sub project")
	@$(call makeTarget,$(GHDL_PROJECT))
	@$(call printStep,"")

.PHONY: ghdl_hdlsb
ghdl_hdlsb: ghdl_project
	@$(call printStep,"### ${FLOW_MODULE}: simulating in batch mode")
	@cd ${FLOW_BINARY_DIR}; FLOW_LOG_FILE="${FLOW_BINARY_ROOT_DIR}/${FLOW_MODULE}_${FLOW_SIM_TOP}_simulation.log" bash ${FLOW_DIR}/ghdl/run_simulation.sh
	@$(call printStep,"")

.PHONY: ghdl_hdlsg
ghdl_hdlsg: ghdl_project
	@$(call printStep,"### ${FLOW_MODULE}: simulating in graphical mode")
	@cd ${FLOW_BINARY_DIR}; FLOW_LOG_FILE="${FLOW_BINARY_ROOT_DIR}/${FLOW_MODULE}_${FLOW_SIM_TOP}_simulation.log" FLOW_GTKWAVE_GUI=1 bash ${FLOW_DIR}/ghdl/run_simulation.sh
	@$(call printStep,"")

.PHONY: ghdl_synthcb
ghdl_synthcb:
	@echo "Synthesis is not supported by GHDL!"
	@exit 1

.PHONY: ghdl_implcb
ghdl_implcb:
	@echo "Implementation is not supported by GHDL!"
	@exit 1

ifeq (${FLOW_GHDL_GCC},1)
BACKEND_HELP_TEXT += $(subst ${space},+,"ghdl_covReset.....Reset the coverage counters.")
BACKEND_HELP_TEXT += $(subst ${space},+,"ghdl_covGenerate..Generate coverage report.")
.PHONY: ghdl_covReset ghdl_covGenerate
ghdl_covReset:
	@${FLOW_LCOV_BINARY} -z -d ${FLOW_BINARY_DIR}

ghdl_covGenerate:
	@${FLOW_LCOV_BINARY} -c -d ${FLOW_BINARY_DIR} -o ${FLOW_BINARY_DIR}/coverage.info
	@${FLOW_LCOV_BINARY} --remove ${FLOW_BINARY_DIR}/coverage.info '${FLOW_BINARY_DIR}/e~*' -o ${FLOW_BINARY_DIR}/coverage.info
	@cd ${FLOW_BINARY_DIR}; ${FLOW_GENHTML_BINARY} coverage.info -o html
endif

endif # FLOW_BACKEND is ghdl
endif # FLOW_GHDL_BINARY not empty
