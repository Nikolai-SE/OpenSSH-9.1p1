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

export LSAN_OPTIONS=verbosity=1:log_threads=1
export ASAN_OPTIONS=report_objects=1:sleep_before_dying=1
sudo gdb --args .././sshd-libprotobuf-mutator.out ../$MY_CORPUS ../$SEEDS -jobs=$NUMBER_OF_JOBS -max_len=8128
# set follow-fork-mode child

### apt source glibc
### sudo apt install libc6-dbg
# directory /home/nik/glibc-2.31
# directory /home/nik/glibc
# handle SIG33 nostop
# handle all nostop

# b sshd.c:1591 +
# b sshd.c:1805 -
# b sshd.c:1925 +
# b sshd.c:2049 +
#
# b sshd.c:1569
# b sshd.c:1591
# b sshd.c:1763
# b sshd.c:1925
# b sshd.c:2049 +
#
# b sshd.c:2068 +
# b sshd.c:2104 +
# b sshd.c:2117 -
# b sshd.c:2149
# b sshd.c:2259
# b sshd.c:2260 +
# b sshd.c:2272
# b sshd.c:2319


# ensure_minimum_time_since
# b sshd.c:2049 +
#
# b sshd.c:2068 +
# b sshd.c:2267                    mm_send_keystate(ssh, pmonitor);

# b sshd.c:2260
