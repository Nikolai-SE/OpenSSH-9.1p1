#!/bin/bash

BUILD_PATH=/home/nik/openssh-custom
PORT=2022

sudo $BUILD_PATH/sbin/./sshd -ddd -e -p $PORT -r -f $BUILD_PATH/etc/sshd_config
