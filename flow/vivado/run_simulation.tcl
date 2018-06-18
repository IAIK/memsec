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
open_project $env(FLOW_MODULE).xpr

source [file join [file dirname [info script]] "configure_simulation.frag"]

launch_simulation -quiet

# check for simulation launching errors and display log files if possible
set simulation_dir "$env(FLOW_MODULE).sim/sim_1/behav"
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

run $env(FLOW_SIM_TIME)

set time [current_time]
puts "Execution stopped after $time"

if { [info exists env(FLOW_VIVADO_GUI)] == 0 } {
  close_project
}
