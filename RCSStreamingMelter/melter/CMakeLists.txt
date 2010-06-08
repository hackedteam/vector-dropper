include_directories("${MELTER_SOURCE_DIR}/melter")

set(melter_SRCS main.cpp)

add_executable(melter ${melter_SRCS})

MESSAGE(STATUS ${Boost_INCLUDE_DIRS})
MESSAGE(STATUS ${Boost_LIBRARY_DIRS})

target_link_libraries(melter melt boost_regex boost_program_options boost_system boost_filesystem BeaEngine_s_d AsmJit)
