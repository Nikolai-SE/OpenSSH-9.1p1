//
// Created by nik on 11.05.23.
//

#include "fuzz-libprotobuff.h"

#ifdef __cplusplus

#define SHOW_LOG

#include <cmath>
#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <thread>
#include <vector>
#include <fcntl.h>
#include <pthread.h>

#include <string>
#include <map>

#include <libprotobuf-mutator/port/protobuf.h>
#include <libprotobuf-mutator/src/mutator.h>
#include <libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h>

#include "message.pb.h"
#include "src/mutator.h"


extern "C" const char *__asan_default_options() {
    return "detect_leaks=0";
}

extern "C"
{
#include "includes.h"
#include "auth.h"
int main_sshd(int ac, char **av);
}

const char *PORT = "2022";
////              -ddd -e -p $PORT -r -f $BUILD_PATH/etc/sshd_config -i
//const char* args_literals[] = {"sshd", "-ddd", "-e", "-r", "-p", PORT,
//                "-f", "/home/nik/Fuzzing/OpenSSH/OpenSSH-9.1p1-copy/sshd_config", "-i"};
const char *args_literals[] = {"sshd", "-d", "-e", "-f", "/home/nik/Fuzzing/OpenSSH/OpenSSH-9.1p1-copy/sshd_config", "-i"};

char **args = nullptr;
const int argc = sizeof(args_literals) / sizeof(const char *);

void init_args() {
    args = new char *[argc];
    for (int i = 0; i < argc; ++i) {
        size_t len = strlen(args_literals[i]);
        args[i] = new char[len + 1]{};
        memcpy(args[i], args_literals[i], len);
    }
}

void free_args() {
    for (int i = 0; i < argc; ++i) {
        delete[] args[i];
    }
    delete[] args;
    args = nullptr;
}

template<class Proto>
using PostProcessor =
        protobuf_mutator::libfuzzer::PostProcessorRegistration<Proto>;

static PostProcessor<PacketsData> reg1 = {
    [](PacketsData* packet, unsigned int seed) {
        // SSH-2.0-PuTTY_Release_0.64
        packet->set_optional_string_client_type("SSH-2.0-PuTTY_Release_0." + packet->optional_string_client_type());
//        packet->set_optional_string_client_type("SSH-2.0-PuTTY_Release_0.64");

        switch (packet->optional_uint64_user_id()) {
            case 0:
                packet->set_optional_string_user_name("user");
                packet->set_optional_string_user_password("user");
                break;
            case 1:
                packet->set_optional_string_user_name("nik");
                packet->set_optional_string_user_password("nik");
                break;
            default:
                packet->set_optional_string_user_name("");
                packet->set_optional_string_user_password("");
                break;
        }

#ifdef SHOW_LOG
        fprintf(stderr, "\n I'm here \n"
                        "packet->optional_string_client_type(): %s\n"
                        "packet->optional_string_user_name(): %s\n"
                        "packet->optional_string_user_password(): %s\n",
                        packet->optional_string_client_type().c_str(),
                        packet->optional_string_user_name().c_str(),
                        packet->optional_string_user_password().c_str()
                        );
#endif

    }};

//// Example
//static PostProcessor<Msg> reg1 = {
//    [](Msg* message, unsigned int seed) {
//      message->set_optional_uint64(
//          std::hash<std::string>{}(message->optional_string()));
//    }};

//static PostProcessor<google::protobuf::Any> reg2 = {
//    [](google::protobuf::Any* any, unsigned int seed) {
//      // Guide mutator to usefull 'Any' types.
//      static const char* const expected_types[] = {
//          "type.googleapis.com/google.protobuf.DescriptorProto",
//          "type.googleapis.com/google.protobuf.FileDescriptorProto",
//      };
//
//      if (!std::count(std::begin(expected_types), std::end(expected_types),
//                      any->type_url())) {
//        const size_t num =
//            (std::end(expected_types) - std::begin(expected_types));
//        any->set_type_url(expected_types[seed % num]);
//      }
//    }};

size_t
format_with_zero(const char *format_array, size_t format_array_length, const std::vector<std::string> &format_args,
                 char *&result) {
    size_t size = format_array_length - format_args.size(); // %s -> <len>[]
    for (const auto &arg: format_args) {
        size += arg.size();
    }
    result = new char[size + 1]{};
    size_t write_index = 0;
    size_t arg_index = 0;
    for (size_t i = 0; i < format_array_length;) {
        while (i < format_array_length - 1 && arg_index < format_args.size()
               && format_array[i] == '%' && format_array[i + 1] == 's') {
            result[write_index++] = (char) format_args[arg_index].size();
            memcpy(result + write_index, format_args[arg_index].c_str(), format_args[arg_index].size());
            i += 2;
            write_index += format_args[arg_index++].size();
        }
        if (i >= format_array_length)
            break;
        result[write_index++] = format_array[i++];
    }
    assert(arg_index == format_args.size());
    return size;
}

struct packet {
    std::string str;

    const char *data() const noexcept {
        return str.c_str();
    }

    const size_t size;

    [[nodiscard]] uint32_t get_uint(size_t pos) const {
        return uint32_t((unsigned char) (data()[pos]) << 24 |
                        (unsigned char) (data()[pos + 1]) << 16 |
                        (unsigned char) (data()[pos + 2]) << 8 |
                        (unsigned char) (data()[pos + 3]));
    }

    static uint32_t get_uint(const char *data, size_t pos) {
        return uint32_t((unsigned char) (data[pos]) << 24 |
                        (unsigned char) (data[pos + 1]) << 16 |
                        (unsigned char) (data[pos + 2]) << 8 |
                        (unsigned char) (data[pos + 3]));
    }

    static void set_uint(char *data, uint32_t i, size_t pos) {
        data[pos] = (unsigned char) (i >> 24);
        data[pos + 1] = (unsigned char) (i >> 16);
        data[pos + 2] = (unsigned char) (i >> 8);
        data[pos + 3] = (unsigned char) i;
    }

    [[nodiscard]] uint32_t get_packet_length() const {
        return get_uint(0);
    }

    [[nodiscard]] uint8_t get_byte(size_t pos) const {
        return str[pos];
    }

    static void set_byte(char *data, uint8_t byte, size_t pos) {
        data[pos] = (char) byte;
    }

    [[nodiscard]] uint32_t get_padding_length() const {
        return get_byte(4);
    }

    packet(const char *data, size_t size) : str(data, size), size(size) {}

    packet(std::string &&str) : str(str), size(str.size()) {}

    static constexpr size_t SIZE_OF_PACKET_LENGTH = 4;
    static constexpr size_t SIZE_OF_PADDING_LENGTH = 1;
    static constexpr size_t ADDITION_LENGTH = SIZE_OF_PACKET_LENGTH + SIZE_OF_PADDING_LENGTH;
    static constexpr const char *padding_padding = "PADDINGPADDINGPADDINGPADDING";

    static packet create_packet(const char *payload, size_t payload_size, size_t mac_length = 0) {
        constexpr size_t redundancy_ratio = 8;
        size_t size = payload_size + ADDITION_LENGTH;
        uint8_t padding_size = redundancy_ratio - size % redundancy_ratio;
        if (padding_size < 4)
            padding_size += redundancy_ratio;
        size += padding_size;
        size += mac_length;

        char *data = new char[size + 1]{};
        set_uint(data, size - SIZE_OF_PACKET_LENGTH - mac_length, 0);
        set_byte(data, padding_size, 4);
        memcpy(data + ADDITION_LENGTH, payload, payload_size);
        memcpy(data + ADDITION_LENGTH + payload_size, padding_padding, padding_size);
        packet res = {std::string(data, size)};
        delete[] data;
        return res;
    }
};


// user logout
// regex
// <(\d)\)(\s)> -> <$1\),$2>,
//<        "> -><        packet(u8">
//<^"> -> <        packet(u8">

const std::vector<packet> original_packets = {
/*00*/  packet(u8"SSH-2.0-OpenSSH_9.1\r\n", 21),
/*01*/
        packet(u8"\0\0\3\304\6\24\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\0\0\1\24sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,ext-info-c\0\0\1\317ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256\0\0\0\tnone,none\0\0\0\tnone,none\0\0\0+none,hmac-md5,hmac-sha1,umac-64@openssh.com\0\0\0+none,hmac-md5,hmac-sha1,umac-64@openssh.com\0\0\0\32none,zlib@openssh.com,zlib\0\0\0\32none,zlib@openssh.com,zlib\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
               968),
/*02*/           // 1204
        packet(u8"\0\0\4\264\10\36\0\0\4\246\256\330\203\2\17O\6\3\336\344O\3W\311fu/\307\221\266\271\0366\225\340W]\33\325\33\2474J\312\310\231\256\230 \341zR\371\372\0261E;\232\344\25 \344cD\345\23\17\246\274\311\344H\244W\31\236\261\205\374\331\10\220\274\2612\0320\254Bv:\302\213t\2\331\266\213\177\276'Hm\307\363'\34E\264}w\242\372S;]\274\304\344\201\321\372HTU\257G\260\337Z^z\263\201\246\26\377\24\277\f\252\307\247\210qkT\377\207Og[pW\365$\201\222\314fQ\207Y\244\22\6\340\304\241\334\223\265\362\203p<B\34\323\253\273\4$\225\317\37\376f\255a\221\305\25\0\314\24\251E\353\302M\227\3\274\34\243\317\304\341\254\31\335\233\254\2662LO\365>\3z\313\366(Mg{\210\341[\352~\240\323\\\342\27C\323\221\362\\\220\234\355\351]\3014\177\203t#\3001\203\234UM\16:\26\321\244v\365H\274BL<\300m\16N\235\306\201\3407=\321\252\260w\357\365\270>t!S\252\216\332\314\203\2\17O\6\3\336\344O\3W\311fu/\307\221\266\271\0366\225\340W]\33\325\33\2474J\312\310\231\256\230 \341zR\371\372\0261E;\232\344\25 \344cD\345\23\17\246\274\311\344H\244W\31\236\261\205\374\331\10\220\274\2612\0320\254Bv:\302\213t\2\331\266\213\177\276'Hm\307\363'\34E\264}w\242\372S;]\274\304\344\201\321\372HTU\257G\260\337Z^z\263\201\246\26\377\24\277\f\252\307\247\210qkT\377\207Og[pW\365$\201\222\314fQ\207Y\244\22\6\340\304\241\334\223\265\362\203p<B\34\323\253\273\4$\225\317\37\376f\255a\221\305\25\0\314\24\251E\353\302M\227\3\274\34\243\317\304\341\254\31\335\233\254\2662LO\365>\3z\313\366(Mg{\210\341[\352~\240\323\\\342\27C\323\221\362\\\220\234\355\351]\3014\177\203t#\3001\203\234UM\16:\26\321\244v\365H\274BL<\300m\16N\235\306\201\3407=\321\252\260w\357\365\270>t!S\252\216\332\314\203\2\17O\6\3\336\344O\3W\311fu/\307\221\266\271\0366\225\340W]\33\325\33\2474J\312\310\231\256\230 \341zR\371\372\0261E;\232\344\25 \344cD\345\23\17\246\274\311\344H\244W\31\236\261\205\374\331\10\220\274\2612\0320\254Bv:\302\213t\2\331\266\213\177\276'Hm\307\363'\34E\264}w\242\372S;]\274\304\344\201\321\372HTU\257G\260\337Z^z\263\201\246\26\377\24\277\f\252\307\247\210qkT\377\207Og[pW\365$\201\222\314fQ\207Y\244\22\6\340\304\241\334\223\265\362\203p<B\34\323\253\273\4$\225\317\37\376f\255a\221\305\25\0\314\24\251o\354<\23\250\r\317\375<\360!7\206\v\7\364\2506\3407\242M\21\375\331\312\366\332>\36\207-\304:\370JL\274\223\2\327\227\220\242\256\212\253:\4\324v\313\225\3\3208P\377:\211a+N\224\36\24\334\252~z\32\273t\241V\334`\246\347\277\257\"\2426\302\307;u\335P\210\235\240\211P\23Z\361\246w\267\217\200\2246\0274\37\352\332\236?\300\357\261z\317\376e@\2(e\320&J\323\224g\325\314\205\5\240\205\341F\351\315T\303\334<o\354<\23\250\r\317\375<\360!7\206\v\7\364\2506\3407\242M\21\375\331\312\366\332>\36\207-\304:\370JL\274\223\2\327\227\220\242\256\212\253\337\26\265\227w\312\356\217\207\351\321\273\377\6\216z\32Bs6>\332\2675\364\301\266\345\2425\375\262\330\256}\274\371\247\250\253I-\v\255%39\227\343\3p\v\202Ps~@G\7\3632\344\2741#\f\312\265+\377\363\233!\254\276\307\32\266G\322\205\335\33}Z\206e\252\2663\335\200\0247b\363qn\362\225\340*R\" \226_\\\254\344\360C\320P(\207\343\264\337\263uC\202\v\221u@\263#\23*,\351\265\362N=\30\324\310\350x)\312\376\5\244\327\347p3\331d\2\36\271\3^\307\7\21\317%\1\204\301\242\35\246\27\2724w\300\366\323\253\273\276wf\n\255\335\215\356\361}7\340\25\255\365wD\227\350j\306v\1\204\346\251i\330A\5W\333K5\237#\256^\24nN%\22\5g\4r%\0064\214\25\f\24u=\f\223=\4\324!\0\0\0\0\0\0\0\0",
               1208),
/*03*/  packet(u8"\0\0\0\f\n\25\0\0\0\0\0\0\0\0\0\0", 16),

//// Starts mac: mac_length \= 12 (none) ??  =>  mac_length = 20 (none), так как none изменено на основе hmac-sha1
//                 len=28  10                      20->|           28->|
/*04*/  packet(u8"\0\0\0\34\n\5\0\0\0\fssh-userauth\0\0\0\0\0\0\0\0\0\0?#voe\20_J=8\273h\222K=\236\26d\272\253", 52),
/*05*/
        packet(u8"\0\0\0,\0102\0\0\0\4user\0\0\0\16ssh-connection\0\0\0\4none\0\0\0\0\0\0\0\0\216f\315_8\332c\22Z\362\221\244\220\336\204\26{\301k\0",
               68),
/*06*/
        packet(u8"\0\0\2\\\0072\0\0\0\4user\0\0\0\16ssh-connection\0\0\0\tpublickey\0\0\0\0\frsa-sha2-512\0\0\2\27\0\0\0\7ssh-rsa\0\0\0\3\1\0\1\0\0\2\1\0\327[:\234X\220\343\257v\2140\333\343\266v\264{J0\366\316\347<\313if\252N\242\2160B%\301\262\7;\217\207\320'\272\3\332\\\16#\261*::\350T\356\225\256\264\350\2211nK\371\256\23\24\251Q\241*\263\257\227\322\250\326^\0203\254+\233%sm\2132Mr\357\322d\247\21\331\243\352\317\270z\353i\371J\375,O\337\254\267\2639\221R\243\257\1C\377\3526N\250G\3665\252\311\226\231\373\17\347\206`x\343W\24\306\373V\203\31501\373\324]\220\177=RNm\364\320~\326\316\320S\244\213\253\304)!\300\263\253\335%\n>\364\265\323\326C\250:?\331{\31|C(Da\346*\224\31\222)\254\215\336\231\202p+\3\34\r\254&='\331\203\17\232Q# F\v\346\276\312\316\367f\312\342\304`W\224\372`\16*\256\25\177^\312\356\242?\256a\333X)\25056\227\3123\325\10\364:.6\t\326\247\263\333\333@\2606;NU\312\21\222\31\377\231\351_U\223\362\35G\233\327\277R'\2470x\230\\\322\217\363\271X\370\374\312\334\207\2679\227\365\356\304[$Q\317\35\5<6\345V\2\215\0340;\235s4\332\264J\264\330G\330xFI\261\2258\37\264\3\276OmKk\250\307\335\347\232\326:\34\332\224Q \32\213\311\307\7\307\200\344u\374\\X\312<\355\233j\v\262q\21\271\351\234<\271\370\364f\310[\211\33/\337|C\233\203\3303\331\207\275\356\346\337>b\201\250a'\230\33+\202\270\312\340\231\\\324\203\334\31,\267\3571\350\352\346B\346+\361\304\2\7'q\34\322\345\357\205t^\372q\3047\302\363pB\3204\205\374\30\206\213da\0106R\327\256\3043\277\334H\265\222\263c\t*\256\342\216b\2\346\206\f\24\277\354{\270\23\37$km~>zx\332\213\275\235\267\0\0\0\0\0\0\0?N\262w\310\273\210S\376+a9t\374/\243\311\10\237\2",
               628),
/*07*/
        packet(u8"\0\0\0D\0102\0\0\0\4user\0\0\0\16ssh-connection\0\0\0\24keyboard-interactive\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\326\350\313<\233\25\247!\356x\253\363\372\357\321\235\304\244'f",
               92),
/*08*/
        packet(u8"\0\0\0|K2\0\0\0\4user\0\0\0\16ssh-connection\0\0\0\10password\0\0\0\0\4user\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\35s#G\5\276\26\202,~\331cI\177\352\267\2660\204\227",
               148),
/*09.0*/  //      len=36 11                          20 ->|                            36->|                             +20->|
        packet(u8"\0\0\0$\vZ\0\0\0\7session\0\0\0\0\0\20\0\0\0\0@\0\0\0\0\0\0\0\0\0\0\0\0001%1\316d{/Jn\0267 {x\273B\265},\272",
               60),
/*09.1*/  //
        packet(u8"\0\0\0,\tP\0\0\0\34no-more-sessions@openssh.com\0\0\0\0\0\0\0\0\0\0n\335\3\177]q\352\256=\243\370}\351\320\337q\267_\301\5",
               68),
/*10.0*/  //      len=324;7
        packet(u8"\0\0\1D\7b\0\0\0\0\0\0\0\7pty-req\1\0\0\0\16xterm-256color\0\0\0\243\0\0\0\v\0\0\0\0\0\0\0\0\0\0\1\5\201\0\0\226\0\200\0\0\226\0\1\0\0\0\3\2\0\0\0\34\3\0\0\0\177\4\0\0\0\25\5\0\0\0\4\6\0\0\0\0\7\0\0\0\0\10\0\0\0\21\t\0\0\0\23\n\0\0\0\32\f\0\0\0\22\r\0\0\0\27\16\0\0\0\26\22\0\0\0\17\36\0\0\0\0\37\0\0\0\0 \0\0\0\0!\0\0\0\0\"\0\0\0\0#\0\0\0\0$\0\0\0\1%\0\0\0\0&\0\0\0\1'\0\0\0\0(\0\0\0\0)\0\0\0\0*\0\0\0\0002\0\0\0\0013\0\0\0\0014\0\0\0\0005\0\0\0\0016\0\0\0\0017\0\0\0\18\0\0\0\09\0\0\0\0:\0\0\0\0;\0\0\0\1<\0\0\0\1=\0\0\0\1>\0\0\0\0F\0\0\0\1G\0\0\0\0H\0\0\0\1I\0\0\0\0J\0\0\0\0K\0\0\0\0Z\0\0\0\1[\0\0\0\1\\\0\0\0\0]\0\0\0\0\0\0\0\0\0\0\0\0\373\300a\320i\202\375S8z\33\235\331\204m5\275s\360\302",
               348),
/*10.1*/  //         len=20;4                                   |
        packet(u8"\0\0\0\24\4b\0\0\0\0\0\0\0\5shell\1\0\0\0\0004\241\0356\215\237\213`\321\7,(BgTU;?\356\332",
               44),
/*11*/  packet(u8"\0\0\0\24\t^\0\0\0\0\0\0\0\1l\0\0\0\0\0\0\0\0\0e\3~\270Q3\307#\35\232\255|\r\277\336\7\233A\242~",
               44),
/*12*/
        packet(u8"\0\0\0\24\t^\0\0\0\0\0\0\0\1o\0\0\0\0\0\0\0\0\0r\32\215\313\274\354\234+g\333\227\26\223\302\224`\305@\20`",
               44),
/*13*/
        packet(u8"\0\0\0\24\t^\0\0\0\0\0\0\0\1g\0\0\0\0\0\0\0\0\0\0250\2062\333F\230\302t\244\261\10\216\372\204k\334\231\215k",
               44),
/*14*/  packet(u8"\0\0\0\24\t^\0\0\0\0\0\0\0\1i\0\0\0\0\0\0\0\0\0`\375;\222\35\32\277C\204:}YK\352\265\344\240:\324\n",
               44),
/*15*/
        packet(u8"\0\0\0\24\t^\0\0\0\0\0\0\0\1\177\0\0\0\0\0\0\0\0\0k\331\1\2101a\202\205\26\\\30\247:\22\347T\362-%\255",
               44),
        packet(u8"\0\0\0\24\t^\0\0\0\0\0\0\0\1o\0\0\0\0\0\0\0\0\0wt\252\377\6\255\323\313\230i\332\326\340\356\333\242D\320\32\35",
               44),
        packet(u8"\0\0\0\24\t^\0\0\0\0\0\0\0\1u\0\0\0\0\0\0\0\0\0\177NTR\202\273\276EyM\263\n\22\26\216\325\32\203\202\7",
               44),
        packet(u8"\0\0\0\24\t^\0\0\0\0\0\0\0\1t\0\0\0\0\0\0\0\0\0Y0=\373\263\275\232\347W3\7\216\22@\\\262\340\3244B",
               44),
        packet(u8"\0\0\0\24\t^\0\0\0\0\0\0\0\1\r\0\0\0\0\0\0\0\0\0\307\0\306\21r\203G\366}0\245\214\371\264\7\n\366)f(",
               44),
        packet(u8"\0\0\0\f\6a\0\0\0\0\0\0\0\0\0\0x+\262i\342\344\202@\334v\221\3\356\260\347\351w\214\376\214", 36),
        packet(u8"\0\0\0,\n\1\0\0\0\v\0\0\0\24disconnected by user\0\0\0\0\0\0\0\0\0\0\0\0\0\0\245q2\35\6^m\302Fl\274\204\215\357.\0p\217e'",
               68)
};

#define PAIR_CHAR_SIZE(str) std::make_pair((str), (sizeof (str)) - 1)
const std::vector<std::pair<const char *, size_t>> payload_format = {
/*00*/  PAIR_CHAR_SIZE(u8"SSH-2.0-OpenSSH_9.1\r\n"),
        // <packet_len: uint32><padding_size: byte>
/*01*/  PAIR_CHAR_SIZE(
                u8"\0\0\3\304\6\24\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\0\0\1\24sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,ext-info-c\0\0\1\317ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256\0\0\0\tnone,none\0\0\0\tnone,none\0\0\0+none,hmac-md5,hmac-sha1,umac-64@openssh.com\0\0\0+none,hmac-md5,hmac-sha1,umac-64@openssh.com\0\0\0\32none,zlib@openssh.com,zlib\0\0\0\32none,zlib@openssh.com,zlib\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"),
/*02*/  PAIR_CHAR_SIZE(
                u8"\0\0\4\264\10\36\0\0\4\246\256\330\203\2\17O\6\3\336\344O\3W\311fu/\307\221\266\271\0366\225\340W]\33\325\33\2474J\312\310\231\256\230 \341zR\371\372\0261E;\232\344\25 \344cD\345\23\17\246\274\311\344H\244W\31\236\261\205\374\331\10\220\274\2612\0320\254Bv:\302\213t\2\331\266\213\177\276'Hm\307\363'\34E\264}w\242\372S;]\274\304\344\201\321\372HTU\257G\260\337Z^z\263\201\246\26\377\24\277\f\252\307\247\210qkT\377\207Og[pW\365$\201\222\314fQ\207Y\244\22\6\340\304\241\334\223\265\362\203p<B\34\323\253\273\4$\225\317\37\376f\255a\221\305\25\0\314\24\251E\353\302M\227\3\274\34\243\317\304\341\254\31\335\233\254\2662LO\365>\3z\313\366(Mg{\210\341[\352~\240\323\\\342\27C\323\221\362\\\220\234\355\351]\3014\177\203t#\3001\203\234UM\16:\26\321\244v\365H\274BL<\300m\16N\235\306\201\3407=\321\252\260w\357\365\270>t!S\252\216\332\314\203\2\17O\6\3\336\344O\3W\311fu/\307\221\266\271\0366\225\340W]\33\325\33\2474J\312\310\231\256\230 \341zR\371\372\0261E;\232\344\25 \344cD\345\23\17\246\274\311\344H\244W\31\236\261\205\374\331\10\220\274\2612\0320\254Bv:\302\213t\2\331\266\213\177\276'Hm\307\363'\34E\264}w\242\372S;]\274\304\344\201\321\372HTU\257G\260\337Z^z\263\201\246\26\377\24\277\f\252\307\247\210qkT\377\207Og[pW\365$\201\222\314fQ\207Y\244\22\6\340\304\241\334\223\265\362\203p<B\34\323\253\273\4$\225\317\37\376f\255a\221\305\25\0\314\24\251E\353\302M\227\3\274\34\243\317\304\341\254\31\335\233\254\2662LO\365>\3z\313\366(Mg{\210\341[\352~\240\323\\\342\27C\323\221\362\\\220\234\355\351]\3014\177\203t#\3001\203\234UM\16:\26\321\244v\365H\274BL<\300m\16N\235\306\201\3407=\321\252\260w\357\365\270>t!S\252\216\332\314\203\2\17O\6\3\336\344O\3W\311fu/\307\221\266\271\0366\225\340W]\33\325\33\2474J\312\310\231\256\230 \341zR\371\372\0261E;\232\344\25 \344cD\345\23\17\246\274\311\344H\244W\31\236\261\205\374\331\10\220\274\2612\0320\254Bv:\302\213t\2\331\266\213\177\276'Hm\307\363'\34E\264}w\242\372S;]\274\304\344\201\321\372HTU\257G\260\337Z^z\263\201\246\26\377\24\277\f\252\307\247\210qkT\377\207Og[pW\365$\201\222\314fQ\207Y\244\22\6\340\304\241\334\223\265\362\203p<B\34\323\253\273\4$\225\317\37\376f\255a\221\305\25\0\314\24\251o\354<\23\250\r\317\375<\360!7\206\v\7\364\2506\3407\242M\21\375\331\312\366\332>\36\207-\304:\370JL\274\223\2\327\227\220\242\256\212\253:\4\324v\313\225\3\3208P\377:\211a+N\224\36\24\334\252~z\32\273t\241V\334`\246\347\277\257\"\2426\302\307;u\335P\210\235\240\211P\23Z\361\246w\267\217\200\2246\0274\37\352\332\236?\300\357\261z\317\376e@\2(e\320&J\323\224g\325\314\205\5\240\205\341F\351\315T\303\334<o\354<\23\250\r\317\375<\360!7\206\v\7\364\2506\3407\242M\21\375\331\312\366\332>\36\207-\304:\370JL\274\223\2\327\227\220\242\256\212\253\337\26\265\227w\312\356\217\207\351\321\273\377\6\216z\32Bs6>\332\2675\364\301\266\345\2425\375\262\330\256}\274\371\247\250\253I-\v\255%39\227\343\3p\v\202Ps~@G\7\3632\344\2741#\f\312\265+\377\363\233!\254\276\307\32\266G\322\205\335\33}Z\206e\252\2663\335\200\0247b\363qn\362\225\340*R\" \226_\\\254\344\360C\320P(\207\343\264\337\263uC\202\v\221u@\263#\23*,\351\265\362N=\30\324\310\350x)\312\376\5\244\327\347p3\331d\2\36\271\3^\307\7\21\317%\1\204\301\242\35\246\27\2724w\300\366\323\253\273\276wf\n\255\335\215\356\361}7\340\25\255\365wD\227\350j\306v\1\204\346\251i\330A\5W\333K5\237#\256^\24nN%\22\5g\4r%\0064\214\25\f\24u=\f\223=\4\324!\0\0\0\0\0\0\0\0"),
        PAIR_CHAR_SIZE(u8"\0\0\0\f\n\25\0\0\0\0\0\0\0\0\0\0"),
/*04*/  PAIR_CHAR_SIZE(
                u8"\0\0\0\34\n\5\0\0\0\fssh-userauth\0\0\0\0\0\0\0\0\0\0?#voe\20_J=8\273h\222K=\236\26d\272\253"),
/*05*/  PAIR_CHAR_SIZE(
                u8"\0\0\0,\0102\0\0\0%s" /* <username length> <username> */ "\0\0\0\16ssh-connection\0\0\0\4none\0\0\0\0\0\0\0\0\216f\315_8\332c\22Z\362\221\244\220\336\204\26{\301k\0"),
/*06*/  PAIR_CHAR_SIZE(
                u8"\0\0\2\\\0072\0\0\0%s" /* <username length> <username> */ "\0\0\0\16ssh-connection\0\0\0\tpublickey\0\0\0\0\frsa-sha2-512\0\0\2\27\0\0\0\7ssh-rsa\0\0\0\3\1\0\1\0\0\2\1\0\327[:\234X\220\343\257v\2140\333\343\266v\264{J0\366\316\347<\313if\252N\242\2160B%\301\262\7;\217\207\320'\272\3\332\\\16#\261*::\350T\356\225\256\264\350\2211nK\371\256\23\24\251Q\241*\263\257\227\322\250\326^\0203\254+\233%sm\2132Mr\357\322d\247\21\331\243\352\317\270z\353i\371J\375,O\337\254\267\2639\221R\243\257\1C\377\3526N\250G\3665\252\311\226\231\373\17\347\206`x\343W\24\306\373V\203\31501\373\324]\220\177=RNm\364\320~\326\316\320S\244\213\253\304)!\300\263\253\335%\n>\364\265\323\326C\250:?\331{\31|C(Da\346*\224\31\222)\254\215\336\231\202p+\3\34\r\254&='\331\203\17\232Q# F\v\346\276\312\316\367f\312\342\304`W\224\372`\16*\256\25\177^\312\356\242?\256a\333X)\25056\227\3123\325\10\364:.6\t\326\247\263\333\333@\2606;NU\312\21\222\31\377\231\351_U\223\362\35G\233\327\277R'\2470x\230\\\322\217\363\271X\370\374\312\334\207\2679\227\365\356\304[$Q\317\35\5<6\345V\2\215\0340;\235s4\332\264J\264\330G\330xFI\261\2258\37\264\3\276OmKk\250\307\335\347\232\326:\34\332\224Q \32\213\311\307\7\307\200\344u\374\\X\312<\355\233j\v\262q\21\271\351\234<\271\370\364f\310[\211\33/\337|C\233\203\3303\331\207\275\356\346\337>b\201\250a'\230\33+\202\270\312\340\231\\\324\203\334\31,\267\3571\350\352\346B\346+\361\304\2\7'q\34\322\345\357\205t^\372q\3047\302\363pB\3204\205\374\30\206\213da\0106R\327\256\3043\277\334H\265\222\263c\t*\256\342\216b\2\346\206\f\24\277\354{\270\23\37$km~>zx\332\213\275\235\267\0\0\0\0\0\0\0?N\262w\310\273\210S\376+a9t\374/\243\311\10\237\2"),
/*07*/  PAIR_CHAR_SIZE(
                u8"\0\0\0D\0102\0\0\0%s" /* <username length> <username> */ "\0\0\0\16ssh-connection\0\0\0\24keyboard-interactive\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\326\350\313<\233\25\247!\356x\253\363\372\357\321\235\304\244'f"),
/*08*/  PAIR_CHAR_SIZE(
                u8"\0\0\0|K2\0\0\0%s" /* <username length> <username> */ "\0\0\0\16ssh-connection\0\0\0\10password\0\0\0\0%s" /* <username length> <username> */ "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\35s#G\5\276\26\202,~\331cI\177\352\267\2660\204\227"),
/*09.0*/
        PAIR_CHAR_SIZE(
                u8"\0\0\0$\vZ\0\0\0\7session\0\0\0\0\0\20\0\0\0\0@\0\0\0\0\0\0\0\0\0\0\0\0001%1\316d{/Jn\0267 {x\273B\265},\272"),
/*09.1*/
        PAIR_CHAR_SIZE(
                u8"\0\0\0,\tP\0\0\0\34no-more-sessions@openssh.com\0\0\0\0\0\0\0\0\0\0n\335\3\177]q\352\256=\243\370}\351\320\337q\267_\301\5"),
/*10.0*/
        PAIR_CHAR_SIZE(
                u8"\0\0\1D\7b\0\0\0\0\0\0\0\7pty-req\1\0\0\0\16xterm-256color\0\0\0\243\0\0\0\v\0\0\0\0\0\0\0\0\0\0\1\5\201\0\0\226\0\200\0\0\226\0\1\0\0\0\3\2\0\0\0\34\3\0\0\0\177\4\0\0\0\25\5\0\0\0\4\6\0\0\0\0\7\0\0\0\0\10\0\0\0\21\t\0\0\0\23\n\0\0\0\32\f\0\0\0\22\r\0\0\0\27\16\0\0\0\26\22\0\0\0\17\36\0\0\0\0\37\0\0\0\0 \0\0\0\0!\0\0\0\0\"\0\0\0\0#\0\0\0\0$\0\0\0\1%\0\0\0\0&\0\0\0\1'\0\0\0\0(\0\0\0\0)\0\0\0\0*\0\0\0\0002\0\0\0\0013\0\0\0\0014\0\0\0\0005\0\0\0\0016\0\0\0\0017\0\0\0\18\0\0\0\09\0\0\0\0:\0\0\0\0;\0\0\0\1<\0\0\0\1=\0\0\0\1>\0\0\0\0F\0\0\0\1G\0\0\0\0H\0\0\0\1I\0\0\0\0J\0\0\0\0K\0\0\0\0Z\0\0\0\1[\0\0\0\1\\\0\0\0\0]\0\0\0\0\0\0\0\0\0\0\0\0\373\300a\320i\202\375S8z\33\235\331\204m5\275s\360\302"),
/*10.1*/
        PAIR_CHAR_SIZE(u8"\0\0\0\24\4b\0\0\0\0\0\0\0\5shell\1\0\0\0\0004\241\0356\215\237\213`\321\7,(BgTU;?\356\332"),
        PAIR_CHAR_SIZE(
                u8"\0\0\0\24\t^\0\0\0\0\0\0\0\1l\0\0\0\0\0\0\0\0\0e\3~\270Q3\307#\35\232\255|\r\277\336\7\233A\242~"),
        PAIR_CHAR_SIZE(
                u8"\0\0\0\24\t^\0\0\0\0\0\0\0\1o\0\0\0\0\0\0\0\0\0r\32\215\313\274\354\234+g\333\227\26\223\302\224`\305@\20`"),
        PAIR_CHAR_SIZE(
                u8"\0\0\0\24\t^\0\0\0\0\0\0\0\1g\0\0\0\0\0\0\0\0\0\0250\2062\333F\230\302t\244\261\10\216\372\204k\334\231\215k"),
        PAIR_CHAR_SIZE(
                u8"\0\0\0\24\t^\0\0\0\0\0\0\0\1i\0\0\0\0\0\0\0\0\0`\375;\222\35\32\277C\204:}YK\352\265\344\240:\324\n"),
        PAIR_CHAR_SIZE(
                u8"\0\0\0\24\t^\0\0\0\0\0\0\0\1\177\0\0\0\0\0\0\0\0\0k\331\1\2101a\202\205\26\\\30\247:\22\347T\362-%\255"),
        PAIR_CHAR_SIZE(
                u8"\0\0\0\24\t^\0\0\0\0\0\0\0\1o\0\0\0\0\0\0\0\0\0wt\252\377\6\255\323\313\230i\332\326\340\356\333\242D\320\32\35"),
        PAIR_CHAR_SIZE(
                u8"\0\0\0\24\t^\0\0\0\0\0\0\0\1u\0\0\0\0\0\0\0\0\0\177NTR\202\273\276EyM\263\n\22\26\216\325\32\203\202\7"),
        PAIR_CHAR_SIZE(
                u8"\0\0\0\24\t^\0\0\0\0\0\0\0\1t\0\0\0\0\0\0\0\0\0Y0=\373\263\275\232\347W3\7\216\22@\\\262\340\3244B"),
        PAIR_CHAR_SIZE(
                u8"\0\0\0\24\t^\0\0\0\0\0\0\0\1\r\0\0\0\0\0\0\0\0\0\307\0\306\21r\203G\366}0\245\214\371\264\7\n\366)f("),
        PAIR_CHAR_SIZE(u8"\0\0\0\f\6a\0\0\0\0\0\0\0\0\0\0x+\262i\342\344\202@\334v\221\3\356\260\347\351w\214\376\214"),
        PAIR_CHAR_SIZE(
                u8"\0\0\0,\n\1\0\0\0\v\0\0\0\24disconnected by user\0\0\0\0\0\0\0\0\0\0\0\0\0\0\245q2\35\6^m\302Fl\274\204\215\357.\0p\217e'")
};


std::vector<packet> ProtoToPacket(const PacketsData &data) {
    std::vector<packet> packets;

#ifdef SHOW_LOG
    fprintf(stderr,"Client type:%s\n", data.optional_string_client_type().c_str());
#endif

    packets.emplace_back(data.optional_string_client_type() + "\r\n");
//    packets.emplace_back("SSH-2.0-OpenSSH_9.1" "\r\n");
    {
        /**
         * cve-2023-25136
         * f"SSH-2.0-{CLIENT_ID}" "PuTTY_Release_0.64"
         */
//        packets.emplace_back("SSH-2.0-PuTTY_Release_0.64" "\r\n");
        /*
         * ==169464==ERROR: AddressSanitizer: heap-use-after-free on address 0x612000011140 at pc 0x0000007f34c0 bp 0x7f2e5a3c81d0 sp 0x7f2e5a3c81c8
    READ of size 1 at 0x612000011140 thread T2
        #0 0x7f34bf in kex_assemble_names /home/nik/Fuzzing/OpenSSH/OpenSSH-9.1p1-copy/kex.c:234:24
        #1 0x60175a in assemble_algorithms /home/nik/Fuzzing/OpenSSH/OpenSSH-9.1p1-copy/servconf.c:233:2
        #2 0x61e993 in copy_set_server_options /home/nik/Fuzzing/OpenSSH/OpenSSH-9.1p1-copy/servconf.c:2658:2
        #3 0x615d88 in parse_server_match_config /home/nik/Fuzzing/OpenSSH/OpenSSH-9.1p1-copy/servconf.c:2539:2
        #4 0x639eaf in getpwnamallow /home/nik/Fuzzing/OpenSSH/OpenSSH-9.1p1-copy/auth.c:478:2
        #5 0x644ba2 in input_userauth_request /home/nik/Fuzzing/OpenSSH/OpenSSH-9.1p1-copy/auth2.c:286:18
        #6 0x7aac8d in ssh_dispatch_run /home/nik/Fuzzing/OpenSSH/OpenSSH-9.1p1-copy/dispatch.c:113:8
        #7 0x7aaf90 in ssh_dispatch_run_fatal /home/nik/Fuzzing/OpenSSH/OpenSSH-9.1p1-copy/dispatch.c:133:11
        #8 0x63e6f6 in do_authentication2 /home/nik/Fuzzing/OpenSSH/OpenSSH-9.1p1-copy/auth2.c:177:2
        #9 0x5e5b78 in main_sshd /home/nik/Fuzzing/OpenSSH/OpenSSH-9.1p1-copy/sshd.c:2275:2
        #10 0x572c39 in int std::__invoke_impl<int, int (*)(int, char**), int, char**>(std::__invoke_other, int (*&&)(int, char**), int&&, char**&&) (/home/nik/Fuzzing/OpenSSH/OpenSSH-9.1p1-copy/scripts/libprotobuf/sshd-libprotobuf-mutator.out+0x572c39)
        #11 0x572986 in std::__invoke_result<int (*)(int, char**), int, char**>::type std::__invoke<int (*)(int, char**), int, char**>(int (*&&)(int, char**), int&&, char**&&) (/home/nik/Fuzzing/OpenSSH/OpenSSH-9.1p1-copy/scripts/libprotobuf/sshd-libprotobuf-mutator.out+0x572986)
        #12 0x5728dd in int std::thread::_Invoker<std::tuple<int (*)(int, char**), int, char**> >::_M_invoke<0ul, 1ul, 2ul>(std::_Index_tuple<0ul, 1ul, 2ul>) (/home/nik/Fuzzing/OpenSSH/OpenSSH-9.1p1-copy/scripts/libprotobuf/sshd-libprotobuf-mutator.out+0x5728dd)
        #13 0x572834 in std::thread::_Invoker<std::tuple<int (*)(int, char**), int, char**> >::operator()() (/home/nik/Fuzzing/OpenSSH/OpenSSH-9.1p1-copy/scripts/libprotobuf/sshd-libprotobuf-mutator.out+0x572834)
        #14 0x57223e in std::thread::_State_impl<std::thread::_Invoker<std::tuple<int (*)(int, char**), int, char**> > >::_M_run() (/home/nik/Fuzzing/OpenSSH/OpenSSH-9.1p1-copy/scripts/libprotobuf/sshd-libprotobuf-mutator.out+0x57223e)
        #15 0x7f2e5fd29ecf  (/lib/x86_64-linux-gnu/libstdc++.so.6+0xceecf)
        #16 0x7f2e5fbe0ea6 in start_thread nptl/pthread_create.c:477:8
        #17 0x7f2e5f0fba2e in clone misc/../sysdeps/unix/sysv/linux/x86_64/clone.S:95
         */
    }

    auto username = data.optional_string_user_name();
    auto user_password = data.optional_string_user_password();
    std::map<size_t, std::vector<std::string>> args_map{
            {5, {username}},
            {6, {username}},
            {7, {username}},
            {8, {username, user_password}}
    };

    for (size_t i = 1; i < payload_format.size(); ++i) {
        if (true) { // || 5 <= i && i <= 8
            char *data_pointer = nullptr;
            size_t mac_length = (i > 3 ? 20 : 0);
            const size_t prefix_len = 5;
            auto size = format_with_zero(payload_format[i].first + prefix_len,
                                         payload_format[i].second - prefix_len
                                         - (int)/*padding*/payload_format[i].first[4] - mac_length,
                                         args_map[i],
                                         data_pointer);
            packets.push_back(packet::create_packet(data_pointer, size, mac_length));
            delete[] data_pointer;
        } else {
            packets.push_back(original_packets[i]);
        }
    }
    return packets;
}

DEFINE_PROTO_FUZZER(const PacketsData &data) {
    init_args();
#ifdef SHOW_LOG
    fprintf(stderr, "\n Test \n");
#endif

    char data_file_name[100]{};
    sprintf(data_file_name, "data%d.in", gettid());

    {
        FILE *data_in = fopen(data_file_name, "wb");
        std::vector<packet> packs = ProtoToPacket(data);
        for (auto &pack: packs) {
            write(fileno(data_in), pack.data(), pack.size);
        }
        fclose(data_in);
#ifdef SHOW_LOG
        fprintf(stderr, "write %zu packets;\n", packs.size());
#endif
    }
    {
        int fd1 = open(data_file_name, O_RDONLY);
        if (dup2(fd1, STDIN_FILENO) == -1) {
            fprintf(stderr,"error: could not redirect %s to stdin", data_file_name);
            assert(false);
        }
        close(fd1);
        remove(data_file_name);
    }
#ifdef SHOW_LOG
    fprintf(stderr,"thread will creating\n");
#endif

    std::thread main_sshd_thread(main_sshd, argc, args);
#ifdef SHOW_LOG
    fprintf(stderr,"thread is runned\n");
#endif

    main_sshd_thread.join();
#ifdef SHOW_LOG
    fprintf(stderr,"thread was joined\n");
#endif

    free_args();
}

#ifdef SHOW_LOG
#undef SHOW_LOG
#endif

#endif // __cplusplus
