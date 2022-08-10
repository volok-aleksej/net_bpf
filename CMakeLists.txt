cmake_minimum_required(VERSION 3.6.2)

set(BPF_PROJECT_NAME net)

set(CMAKE_CXX_COMPILER "/usr/bin/g++")
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")
set(CMAKE_FIND_LIBRARY_PREFIXES "lib")
set(CMAKE_FIND_LIBRARY_SUFFIXES ".so")
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
FIND_PACKAGE(Confuse REQUIRED)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(common)
add_subdirectory(googletest)
add_subdirectory(unit_tests)
add_subdirectory(loader)
add_subdirectory(monitor)

project(${BPF_PROJECT_NAME} C)
include(cmake/toolchain.cmake)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I /usr/include/x86_64-linux-gnu")
add_library(${PROJECT_NAME} OBJECT bpf/outlb.bpf.c)

add_custom_target(copy_bpf_object ALL
                   COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_OBJECTS:${PROJECT_NAME}> ${PROJECT_NAME}.bpf)
add_dependencies(copy_bpf_object ${PROJECT_NAME})


