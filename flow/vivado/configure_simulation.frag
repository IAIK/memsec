###############################################################################
# configure simulation for module ${FLOW_MODULE}
###############################################################################
set_property -name top -value $env(FLOW_SIM_TOP) -objects [get_filesets sim_1]
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

