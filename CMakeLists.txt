cmake_minimum_required(VERSION 3.5)
project(llunveil C)

add_library(llunveil llunveil/llunveil.c)
target_include_directories(llunveil PUBLIC llunveil)
set_property(TARGET llunveil PROPERTY C_STANDARD 11)
set_property(TARGET llunveil PROPERTY C_STANDARD_REQUIRED TRUE)

option(LLUNVILE_BUILD_EXAMPLES "Build examples" ON)
if(LLUNVILE_BUILD_EXAMPLES)
	add_executable(lljail examples/lljail.c)
	target_link_libraries(lljail PRIVATE llunveil)
endif()
