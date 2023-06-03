#!/bin/bash

CUR_DIR=scripts/libprotobuf
SEEDS=sshd-libprotobuf-mutator-seeds
MY_CORPUS=sshd-libprotobuf-mutator-corpus
CRASHES=sshd-libprotobuf-mutator-crashes
NUMBER_OF_JOBS=1

mkdir $MY_CORPUS
mkdir $SEEDS
mkdir $CRASHES
cd $CRASHES || exit 1
sudo .././sshd-libprotobuf-mutator.out ../$MY_CORPUS ../$SEEDS -jobs=$NUMBER_OF_JOBS -max_len=8128
