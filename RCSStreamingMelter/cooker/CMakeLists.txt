# Reguire minimum version of CMake
CMake_Minimum_Required(VERSION 2.6)

# AsmJit project - Need to use both C and C++
Project(RCSCooker C CXX)

# If ASMJIT_DIR is not specified, assume that we are building it from here
If(NOT COOKER_DIR)
  Set(COOKER_DIR ${CMAKE_CURRENT_SOURCE_DIR})
EndIf(NOT COOKER_DIR)

# RCSCoooker C++ sources
Set(COOKER_SOURCES
  Components.cpp
  Cooker.cpp
  DropperCode.cpp
  RCS.cpp
  main.cpp
)

# RCSCoooker C++ headers
Set(COOKER_HEADERS
	Components.h
	Cooker.h
	DropperCode.h
	RCS.h
	resource.h
	smc.h
	XRefNames.h
)

# common header files
include_directories("../include")

# Boost libraries
SET(Boost_ADDITIONAL_VERSIONS "1.42" "1.42.0")
find_package(Boost 1.42.0 REQUIRED)
include_directories(${Boost_INCLUDE_DIR})
link_directories(${Boost_LIBRARY_DIRS})

# Debugging support is indicated through _DEBUG macro, add it if needed
If(${CMAKE_BUILD_TYPE} MATCHES "Debug")
  Add_Definitions(-D_DEBUG)
EndIf(${CMAKE_BUILD_TYPE} MATCHES "Debug")

Add_Executable(RCSCooker ${COOKER_SOURCES} ${COOKER_HEADERS})
target_link_libraries(RCSCooker "version.lib")

# Visual Studio specific settings
if(WIN32)
	set_target_properties(RCSCooker PROPERTIES COMPILE_DEFINITIONS_RELEASE "/EHsc /MD")
	set_target_properties(RCSCooker PROPERTIES LINK_FLAGS "/DYNAMICBASE:NO /INCREMENTAL:NO /NXCOMPAT:NO /SUBSYSTEM:CONSOLE")
endif(WIN32)
