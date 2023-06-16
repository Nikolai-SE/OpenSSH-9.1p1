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

# -jobs=$NUMBER_OF_JOBS
# -fork=2

#sudo .././sshd-libprotobuf-mutator.out ../$MY_CORPUS ../$SEEDS  -max_len=8128 \
#  -detect_leaks=1  -print_pcs=1 -detect_leaks=0 # 1>run_out.txt  2>run_debug.txt   # -help=1

sudo .././sshd-libprotobuf-mutator.out  -max_len=8128 \
  -detect_leaks=1  -print_pcs=1 # 1>run_out.txt  2>run_debug.txt   # -help=1
