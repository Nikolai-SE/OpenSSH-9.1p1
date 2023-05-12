//
// Created by nik on 11.05.23.
//

#ifndef FUZZ_LIBFUZZER
#define FUZZ_LIBFUZZER

#include "auth.h"

int hellofuzz(){
    fprintf(stderr, "hellofuzz");
    return 1;
}

#include <stdint.h>
#include <stddef.h>


//extern "C"
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size){
    if(Data == NULL)
        return 0;
    if(Size < sizeof(struct ssh))
        return 0;
    do_authentication2(Data);
    return 0;
}

//extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
//    if (size > 0 && data[0] == 'H')
//        if (size > 1 && data[1] == 'I')
//            if (size > 2 && data[2] == '!')
//                __builtin_trap();
//    return 0;
//}

#endif // FUZZ_LIBFUZZER