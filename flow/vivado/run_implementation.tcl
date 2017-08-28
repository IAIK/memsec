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

if { [info exists env(FLOW_VIVADO_GUI)] == 1 } {
  start_gui
}

# change the strategy when requested or reset incomplete or out of date run
if {[get_property strategy [get_runs impl_1]] != "$env(FLOW_VIVADO_IMPL_STRATEGY)" } {
  puts "Switching synthesis strategy to $env(FLOW_VIVADO_IMPL_STRATEGY)"
  set_property strategy "$env(FLOW_VIVADO_IMPL_STRATEGY)" [get_runs impl_1]
  reset_run impl_1
} elseif {[get_property PROGRESS [get_runs impl_1]] != "100%" || [get_property NEEDS_REFRESH [get_runs impl_1]] != 0 } {
  reset_run impl_1
}

if {[get_property PROGRESS [get_runs impl_1]] != "100%" } {
  launch_runs impl_1 -to_step write_bitstream
  wait_on_run impl_1
}

if {[get_property PROGRESS [get_runs impl_1]] != "100%"} {
  error "ERROR: implementation failed"
  close_project
  exit -1
} else {
  open_run impl_1
  write_checkpoint -force "$env(FLOW_BINARY_ROOT_DIR)/$env(FLOW_MODULE)-impl.dcp"
  report_timing_summary -file "$env(FLOW_BINARY_ROOT_DIR)/$env(FLOW_MODULE)-impl_timing_summary.txt" -delay_type min_max -report_unconstrained -check_timing_verbose -max_paths 10 -input_pins
  report_utilization -hierarchical -file "$env(FLOW_BINARY_ROOT_DIR)/$env(FLOW_MODULE)-impl_utilization.txt"

  set exit_code 0
  if {[get_property STATS.WNS [get_runs impl_1]] < 0 } {
    puts "Timing constraints are not met."
    set exit_code -2
  }

  if { [info exists env(FLOW_VIVADO_GUI)] == 0 } {
    close_project
    exit $exit_code
  }
}
