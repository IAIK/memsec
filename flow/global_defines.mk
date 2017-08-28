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

# directory configuration
FLOW_BINARY_ROOT_DIR ?= $(shell pwd)
override FLOW_BINARY_ROOT_DIR := $(abspath ${FLOW_BINARY_ROOT_DIR})
ifeq (${FLOW_SOURCE_DIR},${FLOW_BINARY_ROOT_DIR})
override FLOW_BINARY_ROOT_DIR := ${FLOW_SOURCE_DIR}/_build
endif # FLOW_SOURCE_DIR equal to FLOW_BINARY_ROOT_DIR

FLOW_BINARY_DIR      := ${FLOW_BINARY_ROOT_DIR}/${FLOW_MODULE}

# helpers for escaping spaces (used in the BACKEND_HELP_TEXT)
empty :=
space := $(empty) $(empty)

# overwrite variables by version which are prefixed with the module name
# e.g.: GENERIC_foobar ?= ${${FLOW_MODULE}GENERIC_foobar}
NAMES := $(filter ${FLOW_MODULE}%,$(.VARIABLES))
$(foreach var,${NAMES},$(eval $(subst ${FLOW_MODULE},,${var}) ?= ${${var}}))

# default settings
FLOW_SIMULATION_TIME ?= 500us
