#!/bin/sh
SHRED_PATH='/home/pi/build_llvm/lib'
clang   -Xclang -load -Xclang $SHRED_PATH/SHRED.so test.c shred_wrapper.c -Xlinker -T /home/pi/shred_ld.x  -mllvm -debug-only=SHRED_DEBUG_ANALYZER -Xlinker -l -Xlinker shred -g -o test_seq
clang   -Xclang -load -Xclang $SHRED_PATH/SHRED.so test2.c shred_wrapper.c -Xlinker -T /home/pi/shred_ld.x  -mllvm -debug-only=SHRED_DEBUG_ANALYZER -Xlinker -l -Xlinker shred -Xlinker -l -Xlinker pthread -g -o test_conc
clang   -Xclang -load -Xclang $SHRED_PATH/SHRED.so shred_test_conc.c shred_wrapper.c -Xlinker -T /home/pi/shred_ld.x  -mllvm -debug-only=SHRED_DEBUG_ANALYZER -Xlinker -l -Xlinker shred -Xlinker -l -Xlinker pthread -g -o shred_test_conc
