//
// Created by nik on 11.05.23.
//

// comment to build sshd and comment LIBFUZZER_FLAG in Makefile
#ifndef FUZZ_LIBPROTOBUFF
#define FUZZ_LIBPROTOBUFF


/* FOR FUZZING */

//#define FUZZING_PTHREAD_EXIT

#ifdef FUZZING_PTHREAD_EXIT
#define _OPEN_THREADS
#include <pthread.h>  // sudo apt-get install libpthread-stubs0-dev
//#define pthread_exit(x) pthread_exit(x)
//#define pthread_exit(x); pthread_exit(x);
//#define _exit(x) pthread_exit(x)
//#define _exit(...); pthread_exit(__VA_ARGS__);
#endif



#endif
