#!/bin/sh
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
RESULT_FILE_NAME="${FLOW_SIMTOP}_log.txt"

# generate the ghdl command line flags
GHDL_OPTIONS="${FLOW_GHDL_RFLAGS} --stop-time=${FLOW_SIMULATION_TIME}"
if [ "1" = "${FLOW_GTKWAVE_GUI}" ]; then
  GHDL_OPTIONS="${GHDL_OPTIONS} --vcd=${FLOW_SIMTOP}.vcd"
fi

# delete the result file if it exists
if [ -f ${RESULT_FILE_NAME} ]; then
  echo "\$ rm ${RESULT_FILE_NAME}"
  rm ${RESULT_FILE_NAME}
fi

# convert the generics into ghdl options
GENERICS=$(env | grep -e "^GENERIC_" | xargs)
for I in ${GENERICS}
do
  GHDL_OPTIONS="${GHDL_OPTIONS} -g${I#GENERIC_}"
done

# run the simulation
echo "\$ ${FLOW_GHDL_BINARY} -r ${FLOW_SIMTOP} ${GHDL_OPTIONS} 2>&1 | tee \"${FLOW_BINARY_ROOT_DIR}/${FLOW_MODULE}_${FLOW_SIMTOP}_simulation.log\""
${FLOW_GHDL_BINARY} -r ${FLOW_SIMTOP} ${GHDL_OPTIONS} 2>&1 | tee "${FLOW_BINARY_ROOT_DIR}/${FLOW_MODULE}_${FLOW_SIMTOP}_simulation.log"

# launch gtkwave if requested
if [ "1" = "${FLOW_GTKWAVE_GUI}" ]; then
  if [ "" = "${FLOW_GTKWAVE_BINARY}" ]; then
    echo ""
    echo "ERROR: gtkwave has not been found, consider opening the vcd file manually"
    echo "ERROR: vcd-file: ${FLOW_BINARY_DIR}/${FLOW_SIMTOP}.vcd"
    echo ""
  else
    echo "${FLOW_GTKWAVE_BINARY} ${FLOW_SIMTOP}.vcd"
    ${FLOW_GTKWAVE_BINARY} ${FLOW_SIMTOP}.vcd
  fi
fi

# determine the exit code of the simulation
EXIT_CODE=0
if [ -f ${RESULT_FILE_NAME} ]; then
  RESULT=$(cat ${RESULT_FILE_NAME})
  if [ "1" = "${RESULT}" ]; then
    echo "Simulation succeeded"
  else
    echo "Simulation failed. Result: \"${RESULT}\""
    EXIT_CODE=1
  fi
else
  echo "Timeout. Result file \"${RESULT_FILE_NAME}\" not found."
  EXIT_CODE=2
fi
exit ${EXIT_CODE}
