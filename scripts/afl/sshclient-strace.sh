#!/bin/bash

BUILD_PATH=/home/nik/openssh-custom
PORT=2022
OUT_FILE_NAME=strace-write-time

strace -e trace=write -o trace-log/$OUT_FILE_NAME.log -f -s 8192 $BUILD_PATH/bin/./ssh -p $PORT -c none nik@127.0.0.1
./format-strace.sh $OUT_FILE_NAME
