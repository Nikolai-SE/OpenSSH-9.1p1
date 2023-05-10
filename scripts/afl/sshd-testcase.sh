#!/bin/bash

BUILD_PATH=/home/nik/openssh-custom
PORT=2023

sudo $BUILD_PATH/sbin/./sshd -ddd -e -p $PORT -r -f $BUILD_PATH/etc/sshd_config -i < testcase1
