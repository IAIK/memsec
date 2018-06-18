###############################################################################
# generate and/or configure implementation run
###############################################################################
if {[string equal [get_runs -quiet impl_1] ""]} {
  create_run -name impl_1 -part $env(FLOW_VIVADO_PARTNAME) -flow {$env(FLOW_VIVADO_IMPL_FLOW)} -strategy "$env(FLOW_VIVADO_IMPL_STRATEGY)" -constrset constrs_1 -parent_run synth_1
} else {
  set_property strategy "$env(FLOW_VIVADO_IMPL_STRATEGY)" [get_runs impl_1]
  set_property flow "$env(FLOW_VIVADO_IMPL_FLOW)" [get_runs impl_1]
}
current_run -implementation [get_runs impl_1]

