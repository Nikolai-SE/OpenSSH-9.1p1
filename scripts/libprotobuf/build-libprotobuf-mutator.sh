#!/bin/bash

PROTO_SRC_DIR=.
PROTO_DST_DIR=.

cd ../../
#make clean
rm $PROTO_SRC_DIR/message.pb*
rm sshd-libprotobuf-mutator.out
rm fuzz-libprotobuff.o


protoc -I=$PROTO_SRC_DIR --cpp_out=$PROTO_DST_DIR $PROTO_SRC_DIR/message.proto
make fuzz-libprotobuff.o
make sshd-libprotobuf-mutator
cp sshd-libprotobuf-mutator scripts/libprotobuf/sshd-libprotobuf-mutator.out