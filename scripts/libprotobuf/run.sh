#!/bin/bash

CUR_DIR=scripts/libprotobuf
OUT_DIR=sshd-libprotobuf-mutator-out
mkdir $OUT_DIR
cd ../../
./sshd-libprotobuf-mutator $CUR_DIR/$OUT_DIR
