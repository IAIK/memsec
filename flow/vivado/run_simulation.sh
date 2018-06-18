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
LATEST_SIM_LOG_FILE=${FLOW_MODULE}_${FLOW_SIM_TOP}_latest_simulation.log

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

if [ -z "${FLOW_SIM_TOP}" ]; then
  echo "No top module defined. Simulation not possible!"
  exit 1
fi

# delete result files if used
case ${FLOW_SIM_RESULT_RULE} in
  file-*)
  # set the result file to the log file if it is undefined
  if [ -z "${FLOW_SIM_RESULT_FILE}" ]; then
    FLOW_SIM_RESULT_FILE="${LATEST_SIM_LOG_FILE}"
  fi
  # delete the result file if it is used and already exists
  if [ -f ${FLOW_SIM_RESULT_FILE} ]; then
    echo "\$ rm ${FLOW_SIM_RESULT_FILE}" 2>&1 | log
    rm ${FLOW_SIM_RESULT_FILE} 2>&1 | log
  fi
  ;;
esac

# run the simulation
echo "\$ ${FLOW_VIVADO_BINARY} -nojournal -nolog -mode batch -source ${FLOW_DIR}/vivado/run_simulation.tcl" 2>&1 | log
${FLOW_VIVADO_BINARY} -nojournal -nolog -mode batch -source ${FLOW_DIR}/vivado/run_simulation.tcl 2>&1 | tee "${LATEST_SIM_LOG_FILE}" | log

# unfortunately, vivado does not return errors -> grep for simulation launch error message
LAUNCH_FAIL=$(cat "${LATEST_SIM_LOG_FILE}" | grep -Eq  "^Launching the simulation failed!"; echo $?)
if [ ${LAUNCH_FAIL} -eq "0" ] && [ "sim-return" = "${FLOW_SIM_RESULT_RULE}" ]; then
  echo "RESULT: Simulation failed." 2>&1 | log
  exit 1
fi

# determine the exit code of the simulation
case ${FLOW_SIM_RESULT_RULE} in
  file-success)
  EXIT_CODE=1
  # check if the result file exists and check its contents
  if [ -f ${FLOW_SIM_RESULT_FILE} ]; then
    COMP=$(cat "${FLOW_SIM_RESULT_FILE}" | grep -Eq "${FLOW_SIM_RESULT_REGEX}"; echo $?)
    if [ ${COMP} -eq "0" ]; then
      echo "RESULT: Simulation succeeded" 2>&1 | log
      EXIT_CODE=0
    else
      echo "RESULT: Simulation failed." 2>&1 | log
    fi
  else
    echo "RESULT: Timeout. Result file \"${FLOW_SIM_RESULT_FILE}\" not found." 2>&1 | log
    EXIT_CODE=2
  fi
  ;;

  file-failure)
  EXIT_CODE=0
  # check if the result file exists and check its contents
  if [ -f ${FLOW_SIM_RESULT_FILE} ]; then
    COMP=$(cat "${FLOW_SIM_RESULT_FILE}" | grep -Eq "${FLOW_SIM_RESULT_REGEX}"; echo $?)
    if [ ${COMP} -eq "0" ]; then
      echo "RESULT: Simulation failed." 2>&1 | log
      EXIT_CODE=1
    else
      echo "RESULT: Simulation succeeded" 2>&1 | log
    fi
  else
    echo "RESULT: Timeout. Result file \"${FLOW_SIM_RESULT_FILE}\" not found." 2>&1 | log
    EXIT_CODE=2
  fi
  ;;

  sim-return)
  ;;

  *)
  echo "ERROR: unsupported RESULT_RULE '${FLOW_SIM_RESULT_RULE}' used" 2>&1 | log
  EXIT_CODE=1
  ;;
esac

exit ${EXIT_CODE}
