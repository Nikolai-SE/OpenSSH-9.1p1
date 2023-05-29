//
// Created by nik on 11.05.23.
//

#ifdef __cplusplus

#include <cmath>
#include <stdio.h>

#include <libprotobuf-mutator/port/protobuf.h>
#include <libprotobuf-mutator/src/mutator.h>
#include <libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h>


#include "message.pb.h"
#include "src/mutator.h"

extern "C"
{
//#ifndef memmem
//#define memmem memmem2
#include "includes.h"
#include "auth.h"
//#undef memmem
//#endif
}


int hellofuzz() {
    printf("hellofuzz");
    return 1;
}



template <class Proto>
using PostProcessor =
    protobuf_mutator::libfuzzer::PostProcessorRegistration<Proto>;

static PostProcessor<Msg> reg1 = {
    [](Msg* message, unsigned int seed) {
      message->set_optional_uint64(
          std::hash<std::string>{}(message->optional_string()));
    }};

static PostProcessor<google::protobuf::Any> reg2 = {
    [](google::protobuf::Any* any, unsigned int seed) {
      // Guide mutator to usefull 'Any' types.
      static const char* const expected_types[] = {
          "type.googleapis.com/google.protobuf.DescriptorProto",
          "type.googleapis.com/google.protobuf.FileDescriptorProto",
      };

      if (!std::count(std::begin(expected_types), std::end(expected_types),
                      any->type_url())) {
        const size_t num =
            (std::end(expected_types) - std::begin(expected_types));
        any->set_type_url(expected_types[seed % num]);
      }
    }};

DEFINE_PROTO_FUZZER(const Msg& message) {
//  google::protobuf::FileDescriptorProto file;

  // Emulate a bug.
  if (
//      message.optional_uint64() == std::hash<std::string>{}(message.optional_string()) &&
      message.optional_string().size() > 0 &&
      message.optional_string()[0] == 'a' &&
      message.optional_string().size() > 1 &&
      message.optional_string()[1] == 'b' &&
      !std::isnan(message.optional_float()) &&
      std::fabs(message.optional_float()) > 1000
//      && message.any().UnpackTo(&file) && !file.name().empty()
      ) {
    std::cerr << message.DebugString() << "\n";
    abort();
  }
}



#endif // __cplusplus
