set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_BUILD_TYPE Release)
set (CMAKE_CXX_STANDARD 11)

# Clang target triple.
SET(triple bpf)

# Set clang as a compiler.
set(CMAKE_C_COMPILER /usr/bin/clang)
set(BPFTOOL /usr/sbin/bpftool)

# Flags used in src folder. For samples folder, the flags are hardcoded.
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -g -target bpf")

set(CMAKE_OBJCOPY llvm-objcopy CACHE INTERNAL "objcopy tool")
set(CMAKE_SIZE_UTIL llvm-size CACHE INTERNAL "size tool")

