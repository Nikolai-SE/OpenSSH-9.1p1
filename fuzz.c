//
// Created by nik on 11.05.23.
//
#include "auth.h"
#include "mutator.h"
#include "mutator.cc"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    uint8_t Uncompressed[100];
    size_t UncompressedLen = sizeof(Uncompressed);
    if (Z_OK != uncompress(Uncompressed, &UncompressedLen, Data, Size))
        return 0;
    if (UncompressedLen < 2) return 0;
    if (Uncompressed[0] == 'F' && Uncompressed[1] == 'U')
        abort();  // Boom
    return 0;
}

//extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
//    uint8_t Uncompressed[100];
//    size_t UncompressedLen = sizeof(Uncompressed);
//    if (Z_OK != uncompress(Uncompressed, &UncompressedLen, Data, Size))
//        return 0;
//    if (UncompressedLen < 2) return 0;
//    if (Uncompressed[0] == 'F' && Uncompressed[1] == 'U')
//        abort();  // Boom
//    return 0;
//}
