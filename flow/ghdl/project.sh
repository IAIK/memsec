#!/bin/bash
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
shopt -s expand_aliases
PWD=$(pwd)
DATE=$(date)

# define the log command which writes to the logfile and possibly to stdout
if [ ${FLOW_VERBOSITY} -ge 2 ]; then
  alias log='tee -a "${FLOW_LOG_FILE}"'
else
  alias log='cat >> "${FLOW_LOG_FILE}"'
fi

echo "" >> "${FLOW_LOG_FILE}"
echo "###############################################################################" >> "${FLOW_LOG_FILE}"
echo "# ${DATE}" >> "${FLOW_LOG_FILE}"
echo "###############################################################################" >> "${FLOW_LOG_FILE}"
echo "\$ cd ${PWD}" 2>&1 | log

# generate the ghdl command line flags
GHDL_COMPILE_OPTIONS=""
if [ -n "${FLOW_LIBRARY_NAME}" ]; then
  GHDL_COMPILE_OPTIONS="${GHDL_COMPILE_OPTIONS} --work=${FLOW_LIBRARY_NAME}"
fi

# add the directories of all dependencies to the compile options
for I in ${FLOW_FULL_DEPENDENCY_DIRS}
do
  GHDL_COMPILE_OPTIONS="${GHDL_COMPILE_OPTIONS} -P${I}"
done

echo "\$ ${FLOW_GHDL_BINARY} -i ${GHDL_COMPILE_OPTIONS} ${FLOW_HDL_FILES} ${FLOW_SIM_HDL_FILES}" 2>&1 | log
${FLOW_GHDL_BINARY} -i ${GHDL_COMPILE_OPTIONS} ${FLOW_HDL_FILES} ${FLOW_SIM_HDL_FILES} 2>&1 | log
RETURN_VALUE=${PIPESTATUS[0]}

exit $RETURN_VALUE
