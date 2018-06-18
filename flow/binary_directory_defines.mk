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

# default binary root directory configuration
FLOW_BINARY_ROOT_DIR ?= $(shell pwd)
override FLOW_BINARY_ROOT_DIR := $(abspath ${FLOW_BINARY_ROOT_DIR})
ifeq (${FLOW_SOURCE_DIR},${FLOW_BINARY_ROOT_DIR})
override FLOW_BINARY_ROOT_DIR := ${FLOW_SOURCE_DIR}/_build
endif # FLOW_SOURCE_DIR equal to FLOW_BINARY_ROOT_DIR

DEFAULT_INFO_VARS := FLOW_BACKEND \
                     FLOW_BACKENDS \
                     FLOW_BINARY_ROOT_DIR \
                     FLOW_DIR \
                     FLOW_FULL_DEPENDENCIES \
                     FLOW_MODULE \
                     FLOW_MODULES \
                     FLOW_SOURCE_DIR \
                     FLOW_SOURCE_SCRIPT

HIDDEN_INFO_VARS :=  FLOW_FULL_DEPENDENCY_DIRS \
                     FLOW_VERBOSITY

# setup default settings for the standard properties
# FLOW_BINARY_DIR       Absolute path to the directory where the module will
#                       be built and simulated.
# FLOW_DEPENDENCIES     List of modules on which the current module depends.
# FLOW_FILES            List of absolute paths to non-HDL files of the module.
# FLOW_HDL_FILES        List of absolute paths to the HDL files of the module.
# FLOW_HDL_TOP          Name of the TOP entitiy of the module.
# FLOW_LIBRARY_NAME     Name of the library into which the module should be
#                       built.
# FLOW_SIM_DEPENDENCIES List of modules solely the simulation depends on.
# FLOW_SIM_FILES        List of absolute paths to support files needed for
#                       simulating the module. By default, the files are copied
#                       into the FLOW_BINARY_DIR before starting the simulation.
#                       However, when needed the destination can be overwritten
#                       using a <srcfile>:<destfile> syntax. If <destfile> ends
#                       with / then it is considered as directory.
# FLOW_SIM_HDL_FILES    List of absolute paths to the HDL files needed for
#                       simulating the module.
# FLOW_SIM_RESULT_FILE  Absolute path to the file which contains the test
#                       result. For determining the result FLOW_SIM_RESULT_REGEX
#                       is matched against the content. If the file does not
#                       exist a timeout is reported. If no file is specified,
#                       stdout of the simulation command is matched instead.
# FLOW_SIM_RESULT_REGEX The regex which is matched against the test output.
# FLOW_SIM_RESULT_RULE  Defines how the simulation result is determined.
#                       At the moment "file-success", "file-failure", and
#                       "sim-return" are supported. Both file modes
#                       match FLOW_SIM_RESULT_REGEX on FLOW_SIM_RESULT_FILE to
#                       determine success or failure. "sim-return", on the other
#                       hand simply uses the simulator return value as result
#                       (0 is success).
# FLOW_SIM_TIME         Defines how long the simulation is executed.
# FLOW_SIM_TOP          Name of the TOP entitiy for simulating the module.

#
# TODO support relative paths for the FILES and DIR properties in the future
STANDARD_MODULE_PROPERTIES := FLOW_BINARY_DIR \
                              FLOW_DEPENDENCIES \
                              FLOW_FILES \
                              FLOW_HDL_FILES \
                              FLOW_HDL_TOP \
                              FLOW_LIBRARY_NAME \
                              FLOW_SIM_DEPENDENCIES \
                              FLOW_SIM_FILES \
                              FLOW_SIM_HDL_FILES \
                              FLOW_SIM_RESULT_FILE \
                              FLOW_SIM_RESULT_REGEX \
                              FLOW_SIM_RESULT_RULE \
                              FLOW_SIM_TIME \
                              FLOW_SIM_TOP

ifneq (${FLOW_MODULE},)
# clear all flow vars which can be set later on and only keep those which
# have already sensible values or are save to propagate
WHITELISTED_VARS := FLOW_BACKEND \
                    FLOW_BINARY_ROOT_DIR \
                    FLOW_DIR \
                    FLOW_MODULE \
                    FLOW_SOURCE_DIR \
                    FLOW_SOURCE_SCRIPT \
                    FLOW_VERBOSITY \
                    FLOW_VIVADO_BINARY \
                    FLOW_VIVADO_ROOT_RECIPE

VIVADO_VARS := $(filter FLOW_VIVADO_%,$(.VARIABLES))
CLEAR_VARS := $(filter-out ${WHITELISTED_VARS},${DEFAULT_INFO_VARS} ${HIDDEN_INFO_VARS} ${STANDARD_MODULE_PROPERTIES} ${CUSTOM_MODULE_PROPERTIES} ${VIVADO_VARS})
unexport ${CLEAR_VARS}
$(foreach var,${CLEAR_VARS},$(eval override undefine ${var}))

# clear all generics
CLEAR_VARS  := $(filter GENERIC_%,$(.VARIABLES))
$(foreach var,${CLEAR_VARS},$(eval ${var} := ))
unexport ${CLEAR_VARS}
$(foreach var,${CLEAR_VARS},$(eval override undefine ${var}))
endif # FLOW_MODULE not empty
