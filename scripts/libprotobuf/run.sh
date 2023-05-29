#!/bin/bash

CUR_DIR=scripts/libprotobuf
SEEDS=sshd-libprotobuf-mutator-seeds
MY_CORPUS=sshd-libprotobuf-mutator-corpus
CRASHES=sshd-libprotobuf-mutator-crashes

mkdir $MY_CORPUS
mkdir $SEEDS
mkdir $CRASHES
cd $CRASHES || exit 1
../../.././sshd-libprotobuf-mutator ../$MY_CORPUS ../$SEEDS -jobs=4
