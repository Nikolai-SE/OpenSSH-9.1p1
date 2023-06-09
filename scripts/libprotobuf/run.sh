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

#export LSAN_OPTIONS=verbosity=1:log_threads=1
#export ASAN_OPTIONS=report_objects=1:sleep_before_dying=1
sudo .././sshd-libprotobuf-mutator.out ../$MY_CORPUS ../$SEEDS -jobs=$NUMBER_OF_JOBS -max_len=8128 \
  -detect_leaks=1  -print_pcs=1 # -help=1
