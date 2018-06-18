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

# helpers for escaping spaces (used in the BACKEND_HELP_TEXT)
empty :=
space := $(empty) $(empty)

${FLOW_MODULE}FLOW_SIM_TOP          ?= ${${FLOW_MODULE}FLOW_HDL_TOP}
${FLOW_MODULE}FLOW_SIM_TIME         ?= 500us
${FLOW_MODULE}FLOW_BINARY_DIR       ?= ${FLOW_BINARY_ROOT_DIR}/${FLOW_MODULE}
${FLOW_MODULE}FLOW_SIM_RESULT_RULE  ?= sim-return
$(foreach prop,${STANDARD_PROPERTIES},$(eval ${FLOW_MODULE}${prop} ?= ))

# Overwrite variables by version which are prefixed with the module name,
# Note that we override FLOW_BINARY_DIR first such that it is already usable
# in other expansions,
# e.g.: GENERIC_foobar := ${${FLOW_MODULE}GENERIC_foobar}
NAMES := ${FLOW_MODULE}FLOW_BINARY_DIR
$(foreach var,${NAMES},$(eval $(subst ${FLOW_MODULE},,${var}) := ${${var}}))
NAMES := $(filter ${FLOW_MODULE}%,$(.VARIABLES))
$(foreach var,${NAMES},$(eval $(subst ${FLOW_MODULE},,${var}) := ${${var}}))

# Configure a verbosity level for the output
# 0 ..... no output
# 1 ..... output only the performed steps
# 2 ..... (default) tool output in adition to the output of level 1
# 3 ..... include all dependent modules in info and output of level 2
FLOW_VERBOSITY ?= 2

# if VERBOSITY is 0, steps are not printed and make is quiet
define printStep
endef
define makeTarget
  $(MAKE) --quiet --no-print-directory -f ${FLOW_SOURCE_SCRIPT} $1
endef

# otherwise steps get printed and make is less quiet
ifneq (${FLOW_VERBOSITY},0)
define printStep
  echo $1
endef
define makeTarget
  $(MAKE) --no-print-directory -f ${FLOW_SOURCE_SCRIPT} $1
endef
endif

# calculate dependencies
DEPENDENCIES_HIER1 := ${FLOW_DEPENDENCIES} ${FLOW_SIM_DEPENDENCIES}
DEPENDENCIES_HIER2 := $(foreach m,$(DEPENDENCIES_HIER1),$($(m)FLOW_DEPENDENCIES))
DEPENDENCIES_HIER3 := $(foreach m,$(DEPENDENCIES_HIER2),$($(m)FLOW_DEPENDENCIES))
DEPENDENCIES_HIER4 := $(foreach m,$(DEPENDENCIES_HIER3),$($(m)FLOW_DEPENDENCIES))
DEPENDENCIES_HIER5 := $(foreach m,$(DEPENDENCIES_HIER4),$($(m)FLOW_DEPENDENCIES))
DEPENDENCIES_HIER6 := $(foreach m,$(DEPENDENCIES_HIER5),$($(m)FLOW_DEPENDENCIES))
DEPENDENCIES_HIER7 := $(foreach m,$(DEPENDENCIES_HIER6),$($(m)FLOW_DEPENDENCIES))
DEPENDENCIES_HIER8 := $(foreach m,$(DEPENDENCIES_HIER7),$($(m)FLOW_DEPENDENCIES))
DEPENDENCIES_HIER9 := $(foreach m,$(DEPENDENCIES_HIER8),$($(m)FLOW_DEPENDENCIES))

define uniq
  $(eval seen :=)
  $(foreach _,$1,$(if $(filter $_,${seen}),,$(eval seen += $_)))
  ${seen}
endef

FLOW_FULL_DEPENDENCIES    := $(strip $(call uniq,$(foreach m,9 8 7 6 5 4 3 2 1,$(DEPENDENCIES_HIER$(m)))))
FLOW_FULL_DEPENDENCY_DIRS := $(strip $(call uniq,$(foreach module, $(FLOW_FULL_DEPENDENCIES),$(if $($(module)FLOW_BINARY_DIR),$($(module)FLOW_BINARY_DIR),$(FLOW_BINARY_ROOT_DIR)/$(module)))))

# normalize SIM_FILES format into the <srcfile>:<destfile> format from either
# * <srcfile>
# * <srcfile>:<destdir>
# * <srcfile>:<destfile>
par2Func = $(lastword $(subst :, ,$1))

srcFunc         = $(firstword $(subst :, ,$1))
srcFileNameFunc = $(notdir $(call srcFunc,$1))
destFunc        = $(if $(findstring :,$1),$(if $(notdir $(call par2Func,$1)),$(call par2Func,$1),$(call par2Func,$1)$(call srcFileNameFunc,$1)),$(FLOW_BINARY_DIR)/$(call srcFileNameFunc,$1))
FLOW_SIM_FILES := $(foreach entry,$(FLOW_SIM_FILES),$(call srcFunc,$(entry)):$(call destFunc,$(entry)))
