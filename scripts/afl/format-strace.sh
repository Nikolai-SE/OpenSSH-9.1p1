#!/bin/bash

TRACE_DIR=trace-log
TRACE_NAME=strace1

cat $TRACE_DIR/$TRACE_NAME.log| grep 'write(3' | cut -d' ' -f3- | rev | cut -d' ' -f4- | rev | cut -d' ' -f2- > $TRACE_DIR/$TRACE_NAME-format.log

# \d{5} \w{5}\(3,
#(\d{5} \w{5}\(3, )|, \d*(\) = \d*)