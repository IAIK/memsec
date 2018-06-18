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

# generating project for module ${FLOW_MODULE}
create_project -force -part ${FLOW_VIVADO_PARTNAME} ${FLOW_MODULE} .
if {"${FLOW_VIVADO_BOARD}" ne ""} {
  set_property board_part ${FLOW_VIVADO_BOARD} [current_project]
}

# generate filesets for sources, constraints, and simulation
if {[string equal [get_filesets -quiet sources_1] ""]} {
  create_fileset -srcset sources_1
}
if {[string equal [get_filesets -quiet constrs_1] ""]} {
  create_fileset -constrset constrs_1
}
if {[string equal [get_filesets -quiet sim_1] ""]} {
  create_fileset -simset sim_1
}

