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
open_project $env(FLOW_MODULE).xpr

puts "Simulation top module: $env(FLOW_SIMTOP)"
set_property -name top -value $env(FLOW_SIMTOP) -objects [get_filesets sim_1]
set_property -name {xsim.simulate.runtime} -value {0s} -objects [get_filesets sim_1]
update_compile_order -fileset sim_1

# Extend the generic property with values from the environment
# Every variable which starts with GENERIC_* is added to the property without
# the prefix.
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
set_property -name generic -value $generics -objects [get_filesets sim_1]

# delete simulation folder to make sure that no result files are lingering around
set simulation_dir "$env(FLOW_MODULE).sim/sim_1/behav"
file delete -force $simulation_dir

launch_simulation -quiet

# check for simulation launching errors and display log files if possible
if { {} == [current_sim] } {
  puts "Launching the simulation failed!"
  set log_file_name ""
  set elaborate_log_file_name "$simulation_dir/elaborate.log"
  set xvhdl_log_file_name "$simulation_dir/xvhdl.log"
  if { [file exists $elaborate_log_file_name] == 1 } {
    puts "Elaborate Log:"
    set log_file_name $elaborate_log_file_name
  } elseif { [file exists $xvhdl_log_file_name] == 1 } {
    puts "XVHDL Log:"
    set log_file_name $xvhdl_log_file_name
  } else {
    puts "No log file found!"
    close_project
    exit 3
  }
  set fd [open "$log_file_name" "r"]
  puts [read $fd [file size $log_file_name]]
  close $fd
  close_project
  exit 3
}

if { [info exists env(FLOW_VIVADO_GUI)] == 1 } {
  start_gui
}

run $env(FLOW_SIMULATION_TIME)

set result_file_name "$simulation_dir/$env(FLOW_SIMTOP)_log.txt"

set exit_code 0
if { [file exists $result_file_name] == 1 } {
  set result_file [open "$result_file_name" "r"]
  gets $result_file result
  if { $result == 1 } {
    puts "Simulation succeeded"
  } else {
    puts "Simulation failed. Result: \"$result\""
    set exit_code 1
  }
} else {
  puts "Timeout. Result file \"$result_file_name\" not found."
  set exit_code 2
}

set time [current_time]
puts "Execution stopped after $time"

if { [info exists env(FLOW_VIVADO_GUI)] == 0 } {
  close_project
  exit $exit_code
}
