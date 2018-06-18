###############################################################################
# adding HDL sources for module ${FLOW_MODULE}
###############################################################################
if {"${FLOW_HDL_FILES}" ne ""} {
  add_files -fileset sources_1 -norecurse ${FLOW_HDL_FILES}
  if {"${FLOW_LIBRARY_NAME}" ne ""} {
    foreach path [list ${FLOW_HDL_FILES}] {
      set_property library ${FLOW_LIBRARY_NAME} [get_files $path]
    }
  }
}

if {"${FLOW_FILES}" ne ""} {
  add_files -fileset constrs_1 -norecurse ${FLOW_FILES}
}

