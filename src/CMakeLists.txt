cmake_minimum_required(VERSION 3.13)
add_library("codec" STATIC "codec.cpp")
set_property(TARGET "codec" PROPERTY CXX_STANDARD 20)
target_include_directories("codec" INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}")
