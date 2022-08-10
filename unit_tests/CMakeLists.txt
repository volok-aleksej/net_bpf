cmake_minimum_required(VERSION 3.6.2)

project(net_bpf_unit CXX)
add_executable(${PROJECT_NAME} unit_test.cpp ipv4_tests.cpp ipv6_tests.cpp)
target_compile_definitions(${PROJECT_NAME} PUBLIC XDP_OBJ="${BPF_PROJECT_NAME}.bpf")
target_include_directories(${PROJECT_NAME} PUBLIC ../googletest/googletest/include)
target_link_directories(${PROJECT_NAME} PRIVATE build/lib)
target_link_libraries(${PROJECT_NAME} PRIVATE net_common gtest_main pthread)
