#!/bin/bash

BUILD_PATH=/home/nik/openssh-custom
PORT=2023
TEST_CASE=testcase-time

./gen-testcase.py > $TEST_CASE

sudo $BUILD_PATH/sbin/./sshd -ddd -e -p $PORT -r -f $BUILD_PATH/etc/sshd_config -i < $TEST_CASE & echo $!
#gdb attach 12271
