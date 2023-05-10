#!/bin/bash

BUILD_PATH=/home/nik/openssh-custom
PORT=2022

#strace -e trace=write -o ../strace.log -f -s 8192 $BUILD_PATH/bin/./ssh -p $PORT -c none nik@127.0.0.1
# -F $BUILD_PATH/etc/ssh_config
strace -e trace=write -o trace-log/strace.log -f -s 8192 $BUILD_PATH/bin/./ssh -p $PORT -c none nik@127.0.0.1
