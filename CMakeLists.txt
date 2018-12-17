cmake_minimum_required(VERSION 2.8)

project(MCPC_dissect)
set(CMAKE_BUILD_TYPE DEBUG)
#RelWithDebInfo)
add_definitions("-DHAVE_CONFIG_H")
add_library(MCPC_dissect SHARED "mcpc.c" "VarUtils.c" "VarUtils.h")
include_directories("/usr/include/glib-2.0" "/usr/lib/glib-2.0/include"	"/usr/include/wireshark")
