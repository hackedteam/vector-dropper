include_directories("${MELTER_SOURCE_DIR}/melter")

set(melter_SRCS main.cpp)

add_executable(melter ${melter_SRCS})

MESSAGE(STATUS ${Boost_INCLUDE_DIRS})
MESSAGE(STATUS ${Boost_LIBRARY_DIRS})

target_link_libraries(melter melt boost_regex-mt boost_program_options-mt boost_system-mt boost_filesystem-mt BeaEngine_s AsmJit)
