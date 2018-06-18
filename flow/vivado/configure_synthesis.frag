###############################################################################
# generate and/or configure synthesis run
###############################################################################
if { [info exists env(FLOW_HDL_TOP)] == 1 } {
  set_property "top" $env(FLOW_HDL_TOP) [get_filesets sources_1]
}
if {[string equal [get_runs -quiet synth_1] ""]} {
  create_run -name synth_1 -part $env(FLOW_VIVADO_PARTNAME) -flow {$env(FLOW_VIVADO_SYNTH_FLOW)} -strategy "$env(FLOW_VIVADO_SYNTH_STRATEGY)" -constrset constrs_1
} else {
  set_property strategy "$env(FLOW_VIVADO_SYNTH_STRATEGY)" [get_runs synth_1]
  set_property flow "$env(FLOW_VIVADO_SYNTH_FLOW)" [get_runs synth_1]
}
current_run -synthesis [get_runs synth_1]

