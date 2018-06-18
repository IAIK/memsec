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

# check if vivado is available
FLOW_VIVADO_BINARY ?= $(shell which vivado)
ifneq (${FLOW_VIVADO_BINARY},)
FLOW_BACKEND  ?= vivado
FLOW_BACKENDS += vivado

ifeq (${FLOW_BACKEND},vivado)
###############################################################################
# Backend specific variables
###############################################################################

# vivado default settings
FLOW_VIVADO_PARTNAME ?= xc7z020clg484-1
FLOW_VIVADO_BOARD    ?= em.avnet.com:zed:part0:1.3

# Syntesis defaults:
# Vivado Synthesis Defaults, Flow_AreaOptimized_high, Flow_AlternateRoutability,
# Flow_PerfOptimized_high, Flow_PerfThresholdCarry, Flow_RuntimeOptimized, ...
FLOW_VIVADO_SYNTH_FLOW     ?= Vivado Synthesis 2016
FLOW_VIVADO_SYNTH_STRATEGY ?= Vivado Synthesis Defaults

# Implementation defaults:
# Vivado Implementation Defaults, Performance_Explore, Performance_NetDelay_low
FLOW_VIVADO_IMPL_FLOW      ?= Vivado Implementation 2016
FLOW_VIVADO_IMPL_STRATEGY  ?= Vivado Implementation Defaults

FLOW_VIVADO_PROJECT        ?= ${FLOW_BINARY_DIR}/${FLOW_MODULE}.xpr
FLOW_VIVADO_PROJECT_RECIPE ?= ${FLOW_BINARY_DIR}/${FLOW_MODULE}_recipe.tcl
FLOW_VIVADO_PROJECT_STAMP  ?= ${FLOW_BINARY_DIR}/${FLOW_MODULE}.tcl

FLOW_VIVADO_PACKAGE_XML    ?= ${FLOW_SOURCE_DIR}/component.xml

# The current project based flow can only copy simulation files into the
# simulation directory itself and does not support paths relative to it or
# renaming. The destination part is therefore removed from the FLOW_SIM_FILES
# variable and a warning is issued.
define filter_wrong_sim_dir
  $(eval abssrcpath := $(call srcFunc,$1))
	$(eval srcfile := $(notdir $(abssrcpath)))
	$(eval absdestpath := $(call destFunc,$1))
	$(eval destfile := $(notdir $(absdestpath)))
  $(if $(filter $(absdestpath),$(FLOW_BINARY_DIR)/$(srcfile)),,$(srcfile))
endef
VIVADO_WRONG_SIM_DIRS := $(strip $(foreach entry,$(FLOW_SIM_FILES),$(call filter_wrong_sim_dir,$(entry))))
ifneq (${VIVADO_WRONG_SIM_DIRS},)
$(info ### WARNING: ${FLOW_MODULE} simulation may fail due to invalid paths. Affected files: $(VIVADO_WRONG_SIM_DIRS))
endif
FLOW_SIM_FILES := $(foreach entry,$(FLOW_SIM_FILES),$(call srcFunc,$(entry)))

# Convert relative FLOW_SIM_RESULT_FILE paths into absolute paths inside the
# vivado simulation directory.
ABS_FLOW_SIM_RESULT_FILE := $(abspath ${FLOW_SIM_RESULT_FILE})
ifneq ($(ABS_FLOW_SIM_RESULT_FILE),$(FLOW_SIM_RESULT_FILE))
  override FLOW_SIM_RESULT_FILE := ${FLOW_BINARY_DIR}/memsec.sim/sim_1/behav/${FLOW_SIM_RESULT_FILE}
endif

# define which variables should be shown on the info screen
BACKEND_INFO_VARS += $(filter FLOW_VIVADO_%,$(.VARIABLES))

ENVSUBST_VARS := ${DEFAULT_INFO_VARS} ${HIDDEN_INFO_VARS} ${STANDARD_MODULE_PROPERTIES} $(filter FLOW_VIVADO_%,$(.VARIABLES))
ENVSUBST_VARS := $(foreach var,$(ENVSUBST_VARS),\$${$(var)})
###############################################################################
# Backend specific targets
###############################################################################
.PHONY: vivado_add_HDL_to_RECIPE
vivado_add_HDL_to_RECIPE:
	@$(call printStep,"### ${FLOW_MODULE}: adding HDL sources to project recipe")
	@cat ${FLOW_DIR}/vivado/add_HDL_sources.frag | envsubst "${ENVSUBST_VARS}" >> ${FLOW_VIVADO_ROOT_RECIPE}

.PHONY: ${FLOW_VIVADO_PROJECT_RECIPE}
${FLOW_VIVADO_PROJECT_RECIPE}:
	@$(call printStep,"### ${FLOW_MODULE}: creating project recipe")
	@mkdir -p ${FLOW_BINARY_DIR}
	@cat ${FLOW_DIR}/vivado/generate_base_project.frag | envsubst "${ENVSUBST_VARS}" > $@
	@$(foreach module,$(FLOW_FULL_DEPENDENCIES),$(call makeTarget,FLOW_MODULE=$(module) FLOW_VIVADO_ROOT_RECIPE=$(FLOW_VIVADO_PROJECT_RECIPE) vivado_add_HDL_to_RECIPE);)
	@cat ${FLOW_DIR}/vivado/add_HDL_sources.frag | envsubst "${ENVSUBST_VARS}" >> $@
	@cat ${FLOW_DIR}/vivado/add_SIM_sources.frag | envsubst "${ENVSUBST_VARS}" >> $@
	@cat ${FLOW_DIR}/vivado/generate_block_design.frag | envsubst "${ENVSUBST_VARS}" >> $@
	@cat ${FLOW_DIR}/vivado/configure_synthesis.frag | envsubst "${ENVSUBST_VARS}" >> $@
	@cat ${FLOW_DIR}/vivado/configure_implementation.frag | envsubst "${ENVSUBST_VARS}" >> $@
	@cat ${FLOW_DIR}/vivado/configure_simulation.frag | envsubst "${ENVSUBST_VARS}" >> $@
	@cat ${FLOW_DIR}/vivado/finalize_recipe.frag | envsubst "${ENVSUBST_VARS}" >> $@

# Intuitively, the project file would be the correct artifact for the project
# generation. Unfortunately, this file gets always updated when the project is
# openend. Therefore, a copy of the recipe is used instead.
${FLOW_VIVADO_PROJECT_STAMP}:
	@$(call printStep,"### ${FLOW_MODULE}: processing IP dependencies")
	@$(foreach module,$(FLOW_VIVADO_IP_DEPENDENCIES),$(call makeTarget,FLOW_MODULE=$(module) vivado_package);)
	@$(call printStep,"### ${FLOW_MODULE}: building project")
	@$(call makeTarget,$(FLOW_VIVADO_PROJECT_RECIPE))
	@cd ${FLOW_BINARY_DIR}; FLOW_LOG_FILE="${FLOW_BINARY_ROOT_DIR}/${FLOW_MODULE}_project.log" sh ${FLOW_DIR}/vivado/project.sh
	@cp ${FLOW_VIVADO_PROJECT_RECIPE} $@

.PHONY: vivado_project
vivado_project: ${FLOW_VIVADO_PROJECT_STAMP}
	@$(call printStep,"")

.PHONY: vivado_hdlsb
vivado_hdlsb: vivado_project
	@$(call printStep,"### ${FLOW_MODULE}: simulating in batch mode")
	@cd ${FLOW_BINARY_DIR}; FLOW_LOG_FILE="${FLOW_BINARY_ROOT_DIR}/${FLOW_MODULE}_${FLOW_SIM_TOP}_simulation.log" sh ${FLOW_DIR}/vivado/run_simulation.sh
	@$(call printStep,"")

.PHONY: vivado_hdlsg
vivado_hdlsg: vivado_project
	@$(call printStep,"### ${FLOW_MODULE}: simulating in graphical mode")
	@cd ${FLOW_BINARY_DIR}; FLOW_VIVADO_GUI=1 FLOW_LOG_FILE="${FLOW_BINARY_ROOT_DIR}/${FLOW_MODULE}_${FLOW_SIM_TOP}_simulation.log" sh ${FLOW_DIR}/vivado/run_simulation.sh
	@$(call printStep,"")


SYNTH_DCP := ${FLOW_BINARY_ROOT_DIR}/${FLOW_MODULE}-synth.dcp
${SYNTH_DCP}: | ${FLOW_VIVADO_PROJECT_STAMP}
	@$(call printStep,"### ${FLOW_MODULE}: synthesizing in bash mode")
	@cd ${FLOW_BINARY_DIR}; FLOW_LOG_FILE="${FLOW_BINARY_ROOT_DIR}/${FLOW_MODULE}_synthesis.log" sh ${FLOW_DIR}/vivado/run_synthesis.sh
	@$(call printStep,"")

.PHONY: vivado_synthcb
BACKEND_HELP_TEXT += $(subst ${space},+,"vivado_synthcb.......Perform synthesis in batch mode.")
vivado_synthcb: | ${SYNTH_DCP}

BITSTREAM_FILE := ${FLOW_BINARY_ROOT_DIR}/${FLOW_MODULE}.bit
${BITSTREAM_FILE}: | ${SYNTH_DCP}
	@$(call printStep,"### ${FLOW_MODULE}: implementing in bash mode")
	@cd ${FLOW_BINARY_DIR}; FLOW_LOG_FILE="${FLOW_BINARY_ROOT_DIR}/${FLOW_MODULE}_implementation.log" sh ${FLOW_DIR}/vivado/run_implementation.sh
	@mv ${FLOW_BINARY_DIR}/${FLOW_MODULE}.runs/impl_1/${FLOW_MODULE}.bit $@
	@$(call printStep,"")

.PHONY: vivado_implcb
BACKEND_HELP_TEXT += $(subst ${space},+,"vivado_implcb........Implement the design in batch mode.")
vivado_implcb: | ${BITSTREAM_FILE}

${FLOW_VIVADO_PACKAGE_XML}: ${FLOW_VIVADO_PROJECT_STAMP}
	@$(call printStep,"### ${FLOW_MODULE}: packaging IP in bash mode")
	@cd ${FLOW_BINARY_DIR}; FLOW_LOG_FILE="${FLOW_BINARY_ROOT_DIR}/${FLOW_MODULE}_package.log" sh ${FLOW_DIR}/vivado/package_ip.sh
	@$(call printStep,"")

.PHONY: vivado_package
BACKEND_HELP_TEXT += $(subst ${space},+,"vivado_package.......Package the module with vivado.")
vivado_package: ${FLOW_VIVADO_PACKAGE_XML}

#------------------------------------------------------------------------------
# Custom targets
#------------------------------------------------------------------------------

.PHONY: vivado_open
BACKEND_HELP_TEXT += $(subst ${space},+,"vivado_open.......Open the vivado project of the module.")
vivado_open: vivado_project
	@$(call printStep,"### ${FLOW_MODULE}: opening vivado")
	@cd ${FLOW_BINARY_DIR}; ${FLOW_VIVADO_BINARY} -nojournal -applog -log ${FLOW_BINARY_DIR}/${FLOW_MODULE}_$@.log ${FLOW_VIVADO_PROJECT}
	@$(call printStep,"")

endif # FLOW_BACKEND is vivado
endif # FLOW_VIVADO_BINARY not empty
