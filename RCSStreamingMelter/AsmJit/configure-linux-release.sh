#!/bin/sh
mkdir Build
cd Build
cmake .. -DCMAKE_BUILD_TYPE=Release -DASMJIT_BUILD_LIBRARY=1 -DASMJIT_BUILD_TEST=0 -G"Unix Makefiles"
cd ..
