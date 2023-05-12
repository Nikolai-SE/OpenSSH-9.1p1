#!/bin/bash

#include "fuzz-libfuzzer.h" to sshd

cd ../../
rm -rf build-with-libfuzzer
make clean
make sshd LIBFUZZER_FLAG=-fsanitize=fuzzer  #,memory
mkdir build-with-libfuzzer && cp sshd* build-with-libfuzzer
#make clean

