cmake_minimum_required(VERSION 2.8)
project(MCPC_dissect)

add_compile_options(-Wall -Wno-pointer-arith -Wextra -pedantic -fvisibility=hidden -fuse-linker-plugin -Wno-pointer-arith)
include_directories("/usr/include/glib-2.0" "/usr/lib/glib-2.0/include" "/usr/lib64/glib-2.0/include" "/usr/include/wireshark")

add_library(MCPC_dissect SHARED "mcpc.c" "protocol.c" "protocol_tree.c" "protocol_tree_play.c" "protocol_constants.c" "protocol.h" "protocol_tree.h" "protocol_constants.h")
