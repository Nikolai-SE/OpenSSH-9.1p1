# CMake generated Testfile for 
# Source directory: /home/nik/libprotobuf-mutator/src/libfuzzer
# Build directory: /home/nik/libprotobuf-mutator/src/libfuzzer
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test([=[test.protobuf_libfuzzer_test]=] "libfuzzer_test" "--gtest_color=yes" "AUTO")
set_tests_properties([=[test.protobuf_libfuzzer_test]=] PROPERTIES  _BACKTRACE_TRIPLES "/home/nik/libprotobuf-mutator/src/libfuzzer/CMakeLists.txt;40;add_test;/home/nik/libprotobuf-mutator/src/libfuzzer/CMakeLists.txt;0;")
