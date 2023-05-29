#!/bin/bash

PROTO_SRC_DIR=.
PROTO_DST_DIR=.

cd ../../
make clean
rm $PROTO_SRC_DIR/*.pb.*

protoc -I=$PROTO_SRC_DIR --cpp_out=$PROTO_DST_DIR $PROTO_SRC_DIR/message.proto
make fuzz-libprotobuff.o
make sshd-libprotobuf-mutator
