cmake_minimum_required(VERSION 2.6)

set(melt_SRCS
    Common.cpp
    RCSDropper.cpp
    StreamingMelter.cpp
    Defective.cpp 
    ParseHeaders.cpp 
    ParseEntryPoint.cpp
    InjectStage1Trampoline.cpp
    InjectDropper.cpp
    BIO_melt.cpp
    )

add_library(melt ${melt_SRCS})

target_link_libraries(melt crypto)