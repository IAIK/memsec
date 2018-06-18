###############################################################################
# generate block design for module ${FLOW_MODULE} if specified
###############################################################################
if { [info exists env(FLOW_VIVADO_IP_REPO_PATHS)] == 1 } {
  set_property  ip_repo_paths "$env(FLOW_VIVADO_IP_REPO_PATHS)" [current_project]
  update_ip_catalog
}

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

