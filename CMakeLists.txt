cmake_minimum_required(VERSION 2.8)
project(MCPC_dissect)

set(CMAKE_BUILD_TYPE DEBUG)
#RelWithDebInfo)
add_compile_options(-Wall -Wextra -pedantic -fvisibility=hidden -fuse-linker-plugin -Wno-pointer-arith)
add_definitions("-DHAVE_CONFIG_H")
include_directories("/usr/include/glib-2.0" "/usr/lib/glib-2.0/include"	"/usr/include/wireshark")

add_library(MCPC_dissect SHARED "mcpc.c" "protocol.c" "protocol_constants.c" "protocol.h" "protocol_constants.h")
