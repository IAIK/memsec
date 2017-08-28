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

set package_file "$env(FLOW_SOURCE_DIR)/component.xml"
if { [file exists "$package_file"] == 1 } {
  ipx::open_core $package_file
  set revision [get_property core_revision [ipx::current_core]]
  puts "REVISION: $revision"
  set revision [expr {$revision + 1}]
  set_property core_revision "$revision" [ipx::current_core]
  ipx::merge_project_changes files [ipx::current_core]
  ipx::merge_project_changes ports [ipx::current_core]
} else {
  ipx::package_project -root_dir $env(FLOW_SOURCE_DIR) -vendor IAIK -library IAIK -taxonomy /UserIP -force
  set_property core_revision 1 [ipx::current_core]
  set_property supported_families {zynq Beta} [ipx::current_core]
}
ipx::create_xgui_files [ipx::current_core]
ipx::update_checksums [ipx::current_core]
ipx::save_core [ipx::current_core]
update_ip_catalog
ipx::unload_core [ipx::current_core]

close_project
exit
