#!/bin/bash

cd ../../
make clean
make sshd
rm -rf build-with-libfuzzer
mkdir build-with-libfuzzer && cp sshd* build-with-libfuzzer
make clean

