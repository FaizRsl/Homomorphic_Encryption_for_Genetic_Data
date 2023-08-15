cmake_minimum_required(VERSION 3.17)
project(FYP)  # Replace "YourProjectName" with your actual project name

# Add all your source files here
add_executable(main main.cpp)  # Add all your .cpp files here

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")

# Set the path to the TFHE library
set(TFHE_PREFIX "/usr/local/")

# Add the TFHE include directory to the header search paths
include_directories(${TFHE_PREFIX}/include)

# Link your executable with the TFHE library
target_link_libraries(main ${TFHE_PREFIX}/lib/libtfhe-spqlios-fma.dylib)
