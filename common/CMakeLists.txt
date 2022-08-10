cmake_minimum_required(VERSION 3.6.2)

project(net_common CXX)
FILE(GLOB ${PROJECT_NAME}_SRC "*.cpp")
add_library(${PROJECT_NAME} STATIC ${${PROJECT_NAME}_SRC})
target_compile_definitions(${PROJECT_NAME} PUBLIC XDP_OBJ="${BPF_PROJECT_NAME}.bpf")
target_link_libraries(${PROJECT_NAME} PRIVATE bpf)
target_link_libraries(${PROJECT_NAME} PUBLIC ${Confuse_LIBRARIES})
