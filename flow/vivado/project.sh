#!/bin/sh
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
PWD=$(pwd)
DATE=$(date)

# define the log command which writes to the logfile and possibly to stdout
if [ ${FLOW_VERBOSITY} -ge 2 ]; then
  alias log='tee -a "${FLOW_LOG_FILE}"'
else
  alias log='cat >> "${FLOW_LOG_FILE}"'
fi

# check if we need to generate a new project
if [ -f "${FLOW_VIVADO_PROJECT_STAMP}" ]; then
  RETVAL=$(diff "${FLOW_VIVADO_PROJECT_RECIPE}" "${FLOW_VIVADO_PROJECT_STAMP}" > /dev/null; echo $?)
  if [ "${RETVAL}" -eq "0" ]; then
    echo "Project is uptodate."
    exit 0
  fi
fi

echo "" >> "${FLOW_LOG_FILE}"
echo "###############################################################################" >> "${FLOW_LOG_FILE}"
echo "# ${DATE}" >> "${FLOW_LOG_FILE}"
echo "###############################################################################" >> "${FLOW_LOG_FILE}"
echo "\$ cd ${PWD}" 2>&1 | log

# delete the vivado project if it exists already
echo "\$ rm -rf \"${FLOW_VIVADO_PROJECT}\" \"${FLOW_MODULE}.cache\" \"${FLOW_MODULE}.hw\" \"${FLOW_MODULE}.ip_user_files\" \"${FLOW_MODULE}.sim\"" 2>&1 | log
rm -rf "${FLOW_VIVADO_PROJECT}"  "${FLOW_MODULE}.cache" "${FLOW_MODULE}.hw" "${FLOW_MODULE}.ip_user_files" "${FLOW_MODULE}.sim" 2>&1 | log

echo "\$ ${FLOW_VIVADO_BINARY} -nojournal -nolog -mode batch -source ${FLOW_VIVADO_PROJECT_RECIPE}" 2>&1 | log
${FLOW_VIVADO_BINARY} -nojournal -nolog -mode batch -source ${FLOW_VIVADO_PROJECT_RECIPE} 2>&1 | log
