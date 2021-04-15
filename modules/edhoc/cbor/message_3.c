/*
 * Generated with cddl_gen.py (https://github.com/oyvindronningstad/cddl_gen)
 * Generated with a default_maxq of 3
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "cbor_encode.h"
#include "message_3.h"

#if DEFAULT_MAXQ != 3
#error "The type file was generated with a different default_maxq than this file"
#endif


static bool encode_repeated_C_R(
		cbor_state_t *state, const struct C_R_ *input)
{
	cbor_print("%s\n", __func__);

	bool tmp_result = (((((*input)._C_R_choice == _C_R_bstr) ? ((bstrx_encode(state, (&(*input)._C_R_bstr))))
	: (((*input)._C_R_choice == _C_R_int) ? ((intx32_encode(state, (&(*input)._C_R_int))))
	: false))));

	if (!tmp_result)
		cbor_trace();

	return tmp_result;
}

static bool encode_C_R(
		cbor_state_t *state, const struct C_R__ *input)
{
	cbor_print("%s\n", __func__);

	bool tmp_result = (present_encode(&((*input)._C_R_present), (void *)encode_repeated_C_R, state, (&(*input)._C_R)));

	if (!tmp_result)
		cbor_trace();

	return tmp_result;
}

static bool encode_message_3(
		cbor_state_t *state, const struct message_3 *input)
{
	cbor_print("%s\n", __func__);

	bool tmp_result = (((((encode_C_R(state, (&(*input)._message_3__data_3))))
	&& ((bstrx_encode(state, (&(*input)._message_3_CIPHERTEXT_3)))))));

	if (!tmp_result)
		cbor_trace();

	return tmp_result;
}



__attribute__((unused)) static bool type_test_encode_message_3(
		const struct message_3 *input)
{
	/* This function should not be called, it is present only to test that
	 * the types of the function and struct match, since this information
	 * is lost with the casts in the entry function.
	 */
	return encode_message_3(NULL, input);
}


bool cbor_encode_message_3(
		uint8_t *payload, size_t payload_len,
		const struct message_3 *input,
		size_t *payload_len_out)
{
	return entry_function(payload, payload_len, (const void *)input,
		payload_len_out, (void *)encode_message_3,
		2, 1);
}