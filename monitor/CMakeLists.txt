cmake_minimum_required(VERSION 3.6.2)

project(net_bpf_monitor CXX)
add_executable(${PROJECT_NAME} monitor.cpp)
target_compile_definitions(${PROJECT_NAME} PUBLIC XDP_OBJ="${BPF_PROJECT_NAME}.bpf")
target_link_libraries(${PROJECT_NAME} PRIVATE net_common)
