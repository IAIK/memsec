###############################################################################
# adding simulation sources for module ${FLOW_MODULE}
###############################################################################
if {"${FLOW_SIM_HDL_FILES} ${FLOW_SIM_FILES}" ne " "} {
  add_files -fileset sim_1 -norecurse ${FLOW_SIM_HDL_FILES} ${FLOW_SIM_FILES}
}

if { [info exists env(FLOW_VIVADO_SIM_IP_FILES)] == 1 } {
  add_files -fileset sim_1 -norecurse $env(FLOW_VIVADO_SIM_IP_FILES)
  generate_target Simulation [get_files $env(FLOW_VIVADO_SIM_IP_FILES)]
  export_ip_user_files -of_objects [get_files $env(FLOW_VIVADO_SIM_IP_FILES)] -no_script -force -quiet
}
