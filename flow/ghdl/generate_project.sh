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
LOG_FILE_NAME="${FLOW_BINARY_ROOT_DIR}/${FLOW_MODULE}_${FLOW_SIMTOP}_project_generation.log"

echo "\$ ${FLOW_GHDL_BINARY} -i ${FLOW_GHDL_CFLAGS} \${FLOW_HDL_FILES} \${FLOW_SIMHDL_FILES} > ${LOG_FILE_NAME}" 2>&1
${FLOW_GHDL_BINARY} -i ${FLOW_GHDL_CFLAGS} ${FLOW_HDL_FILES} ${FLOW_SIMHDL_FILES} > ${LOG_FILE_NAME} 2>&1
RETURN_VALUE=$?
if [ $RETURN_VALUE -ne "0" ]; then
  cat ${LOG_FILE_NAME}
  exit $RETURN_VALUE
fi

echo "\$ ${FLOW_GHDL_BINARY} -m ${FLOW_GHDL_CFLAGS} ${FLOW_SIMTOP} >> ${LOG_FILE_NAME}" 2>&1
${FLOW_GHDL_BINARY} -m ${FLOW_GHDL_CFLAGS} ${FLOW_SIMTOP} >> ${LOG_FILE_NAME} 2>&1
RETURN_VALUE=$?
if [ $RETURN_VALUE -ne "0" ]; then
  cat ${LOG_FILE_NAME}
  exit $RETURN_VALUE
fi

cat ${LOG_FILE_NAME}
exit 0
