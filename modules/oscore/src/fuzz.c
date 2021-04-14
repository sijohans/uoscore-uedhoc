#include <stdint.h>
#include <stddef.h>
#include "coap.h"

/*
 * $ clang -g3 fuzz.c -I../inc -fsanitize=fuzzer,address coap.c memcpy_s.c -o buf2coap.fuzz
 * $ ./buf2coap.fuzz
 */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

	struct o_coap_packet coap_packet;
	struct byte_array in;
	in.ptr = data;
	in.len = size;

	buf2coap(&in, &coap_packet);
	
	return 0;  // Non-zero return values are reserved for future use.
}