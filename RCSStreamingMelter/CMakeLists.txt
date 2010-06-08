cmake_minimum_required(VERSION 2.6)
project(Melter)

cmake_policy(SET CMP0015 NEW)

option (optHAS_OPTIMIZED "Turn Optimizations ON"    OFF)
option (optHAS_SYMBOLS   "Build with debug symbols" ON)

if (optHAS_OPTIMIZED)
    if (optHAS_SYMBOLS)
        set (CMAKE_BUILD_TYPE ReleaseWithDebugInfo)
    else (optHAS_SYMBOLS)
        set (CMAKE_BUILD_TYPE Release)
    endif (optHAS_SYMBOLS)
else (optHAS_OPTIMIZED)
    if (optHAS_SYMBOLS)
        set (CMAKE_BUILD_TYPE Debug)
    else (optHAS_SYMBOLS)
        set (CMAKE_BUILD_TYPE Debug)
    endif (optHAS_SYMBOLS)
endif (optHAS_OPTIMIZED)

set (Melter_VERSION_MAJOR 1)
set (Melter_VERSION_MINOR 0)
set (Melter_VERSION_BUILD 1)
set (Melter_BUILD_TYPE ${CMAKE_BUILD_TYPE})

message("-- building Melter version ${Melter_VERSION_MAJOR}.${Melter_VERSION_MINOR}.${Melter_VERSION_BUILD}")
message("-- build type is ${Melter_BUILD_TYPE}")
message("-- building on ${CMAKE_SYSTEM_NAME}")

configure_file(
	"${PROJECT_SOURCE_DIR}/MelterConfig.h.in"
	"${PROJECT_BINARY_DIR}/MelterConfig.h"
)
include_directories("${PROJECT_BINARY_DIR}")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules")

find_package(Boost)
include_directories(${Boost_INCLUDE_DIRS})

find_package(OpenSSL)
include_directories(${OpenSSL_INCLUDE_DIRS})

include_directories("include")
include_directories("beaEngine")
include_directories("AsmJit/AsmJit")

link_directories("beaEngine")
link_directories("AsmJit/Build")

# enable errors on warking for all build types
add_definitions(-Wall -Wextra)

if (Melter_BUILD_TYPE STREQUAL Release)
    add_definitions(-O2)
endif()

if (Melter_BUILD_TYPE STREQUAL Debug) 
    add_definitions(-ggdb)
    set(CMAKE_C_FLAGS_DEBUG "-D_DEBUG")
    set(CMAKE_CXX_FLAGS_DEBUG "-D_DEBUG")
endif()

if (Melter_BUILD_TYPE STREQUAL ReleaseWithDebugInfo)
    add_definitions(-O2 -ggdb)
endif()

add_subdirectory(lib)
add_subdirectory(melter)
