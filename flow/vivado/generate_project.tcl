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
create_project -force -part $env(FLOW_VIVADO_PARTNAME) $env(FLOW_MODULE) .

set_property board_part $env(FLOW_VIVADO_BOARD) [current_project]

# generate sources fileset and add files
if {[string equal [get_filesets -quiet sources_1] ""]} {
  create_fileset -srcset sources_1
}
if { [info exists env(FLOW_HDL_FILES)] == 1 } {
  add_files -fileset sources_1 -norecurse $env(FLOW_HDL_FILES)
  set_property "top" $env(FLOW_HDLTOP) [get_filesets sources_1]
}
update_compile_order -fileset sources_1

# generate simulation fileset and add files
if {[string equal [get_filesets -quiet sim_1] ""]} {
  create_fileset -simset sim_1
}
if { [info exists env(FLOW_SIMHDL_FILES)] == 1 } {
  add_files -fileset sim_1 -norecurse $env(FLOW_SIMHDL_FILES)
  set_property "top" $env(FLOW_SIMTOP) [get_filesets sim_1]
}
if { [info exists env(FLOW_VIVADO_SIMIP_FILES)] == 1 } {
  add_files -fileset sim_1 -norecurse $env(FLOW_VIVADO_SIMIP_FILES)
  generate_target Simulation [get_files $env(FLOW_VIVADO_SIMIP_FILES)]
  export_ip_user_files -of_objects [get_files $env(FLOW_VIVADO_SIMIP_FILES)] -no_script -force -quiet
}
update_compile_order -fileset sim_1

# generate contraints fileset
if {[string equal [get_filesets -quiet constrs_1] ""]} {
  create_fileset -constrset constrs_1
}

# generate synthesis run
if {[string equal [get_runs -quiet synth_1] ""]} {
  create_run -name synth_1 -part $env(FLOW_VIVADO_PARTNAME) -flow {Vivado Synthesis 2016} -strategy "$env(FLOW_VIVADO_SYNTH_STRATEGY)" -constrset constrs_1
} else {
  set_property strategy "$env(FLOW_VIVADO_SYNTH_STRATEGY)" [get_runs synth_1]
  set_property flow "Vivado Synthesis 2016" [get_runs synth_1]
}
current_run -synthesis [get_runs synth_1]

# generate implementation run
if {[string equal [get_runs -quiet impl_1] ""]} {
  create_run -name impl_1 -part $env(FLOW_VIVADO_PARTNAME) -flow {Vivado Implementation 2016} -strategy "$env(FLOW_VIVADO_IMPL_STRATEGY)" -constrset constrs_1 -parent_run synth_1
} else {
  set_property strategy "$env(FLOW_VIVADO_IMPL_STRATEGY)" [get_runs impl_1]
  set_property flow "Vivado Implementation 2016" [get_runs impl_1]
}
current_run -implementation [get_runs impl_1]

if { [info exists env(FLOW_VIVADO_IP_REPO_PATHS)] == 1 } {
  set_property  ip_repo_paths "$env(FLOW_VIVADO_IP_REPO_PATHS)" [current_project]
  update_ip_catalog
}

set generics ""
foreach index [array names env] {
  if {[string match "GENERIC_*" "$index"] == 0} {
    continue
  }
  set generic_name [string range "$index" [string length "GENERIC_"] [string length "$index"]]
  set generics "$generics $generic_name=$env($index)"
  puts "$generic_name=$env($index)"
}
set generics [string trim $generics]
set_property -name generic -value $generics -objects [get_filesets sources_1]

if { [info exists env(FLOW_VIVADO_BD_TCL_FILE)] == 1 } {
  source $env(FLOW_VIVADO_BD_TCL_FILE)
  set wrapper [make_wrapper [get_files *.bd] -top]
  add_files -norecurse $wrapper
  update_compile_order -fileset sources_1
  update_compile_order -fileset sim_1

  # Update the config of cells in the block diagram with values from the environment
  # Every variable of the form FLOW_VIVADO_BD_GENERIC_<name>_AT_<cell>=<value> gets
  # applied to the open block design.
  foreach index [array names env] {
    if {[string match "FLOW_VIVADO_BD_GENERIC_*" "$index"] == 0} {
      continue
    }
    set generic_name_and_cell [string range "$index" [string length "FLOW_VIVADO_BD_GENERIC_"] [string length "$index"]]
    set generic_name [string range "$generic_name_and_cell" 0 [expr {[string first "_AT_" "$generic_name_and_cell"]-1}]]
    set generic_cell [string range "$generic_name_and_cell" [expr {[string first "_AT_" "$generic_name_and_cell"]+4}] [string length "$generic_name_and_cell"]]
    puts "$generic_name@$generic_cell=$env($index)"
    set_property -dict [list CONFIG.$generic_name "$env($index)"] [get_bd_cells $generic_cell]
  }

  save_bd_design
  generate_target all [get_files *.bd]
}

close_project
exit
