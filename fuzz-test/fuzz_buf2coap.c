#include "main_entry.h"
#include "coap.h"

bool fuzz_one_input(const uint8_t *data, size_t size)
{
    struct o_coap_packet coap_packet;
    struct byte_array in;
    in.ptr = data;
    in.len = size;
    OscoreError error = buf2coap(&in, &coap_packet);
    return (error == OscoreNoError);
}