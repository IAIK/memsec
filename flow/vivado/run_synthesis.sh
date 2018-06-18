#!/bin/sh
#
# MEMSEC - Framework for building transparent memory encryption and authentication solutions.
# Copyright (C) 2018 Graz University of Technology, IAIK <mario.werner@iaik.tugraz.at>
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
LATEST_SYNTH_LOG_FILE=${FLOW_MODULE}_latest_synthesis.log

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

# run the synthesis
echo "\$ ${FLOW_VIVADO_BINARY} -nojournal -nolog -mode batch -source ${FLOW_DIR}/vivado/run_synthesis.tcl" 2>&1 | log
${FLOW_VIVADO_BINARY} -nojournal -nolog -mode batch -source ${FLOW_DIR}/vivado/run_synthesis.tcl 2>&1 | tee "${LATEST_SYNTH_LOG_FILE}" | log

# unfortunately, vivado does not return errors -> grep for simulation launch error message
LAUNCH_FAIL=$(cat "${LATEST_SYNTH_LOG_FILE}" | grep -Eq  "^ERROR: synthesis failed"; echo $?)
if [ ${LAUNCH_FAIL} -eq "0" ]; then
  echo "RESULT: Syntesis failed." 2>&1 | log
  exit 1
fi
