#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include "oscore.h"
#include "test_vectors_oscore.h"

static void hex_dump(const char *str, uint8_t *data, size_t size)
{
    printf("%s (%zu): ", str, size);
    for (size_t i = 0; i < size; ++i)
    {
	printf("%02x", data[i]);
    } printf("\r\n");
}

static void hex_dump_array(const char * str, const struct byte_array *in)
{
    hex_dump(str, in->ptr, in->len);
}

#define HEXDUMP(data, size) hex_dump(#data, data, size)
#define HEXDUMP_ARRAY(array) hex_dump_array(#array, &array)

static void edhoc_test(void);

int main(void)
{
    OscoreError r;
    struct context c_client;
    struct context c_server;
    struct oscore_init_params client_params = {
    	.dev_type = CLIENT,
    	.master_secret.ptr = T1__MASTER_SECRET,
    	.master_secret.len = T1__MASTER_SECRET_LEN,
    	.sender_id.ptr = T1__SENDER_ID,
    	.sender_id.len = T1__SENDER_ID_LEN,
    	.recipient_id.ptr = T1__RECIPIENT_ID,
    	.recipient_id.len = T1__RECIPIENT_ID_LEN,
    	.master_salt.ptr = T1__MASTER_SALT,
    	.master_salt.len = T1__MASTER_SALT_LEN,
    	.id_context.ptr = T1__ID_CONTEXT,
    	.id_context.len = T1__ID_CONTEXT_LEN,
    	.aead_alg = AES_CCM_16_64_128,
    	.hkdf = SHA_256,
    };

    r = oscore_context_init(&client_params, &c_client);
    assert(r == OscoreNoError);
    c_client.sc.sender_seq_num = 20;

    HEXDUMP_ARRAY(c_client.rc.recipient_key);
    HEXDUMP_ARRAY(c_client.rc.recipient_id);
    HEXDUMP_ARRAY(c_client.sc.sender_key);
    HEXDUMP_ARRAY(c_client.sc.sender_id);

	struct oscore_init_params server_params = {
	    .dev_type = SERVER,
	    .master_secret.ptr = T1__MASTER_SECRET,
	    .master_secret.len = T1__MASTER_SECRET_LEN,
	    .sender_id.ptr = T1__RECIPIENT_ID,
	    .sender_id.len = T1__RECIPIENT_ID_LEN,
	    .recipient_id.ptr = T1__SENDER_ID,
	    .recipient_id.len = T1__SENDER_ID_LEN,
	    .master_salt.ptr = T1__MASTER_SALT,
	    .master_salt.len = T1__MASTER_SALT_LEN,
	    .id_context.ptr = T1__ID_CONTEXT,
	    .id_context.len = T1__ID_CONTEXT_LEN,
	    .aead_alg = AES_CCM_16_64_128,
	    .hkdf = SHA_256,
	};

	r = oscore_context_init(&server_params, &c_server);
	assert(r == OscoreNoError);
	c_server.sc.sender_seq_num = 20;

    HEXDUMP_ARRAY(c_server.rc.recipient_key);
    HEXDUMP_ARRAY(c_server.rc.recipient_id);
    HEXDUMP_ARRAY(c_server.sc.sender_key);
    HEXDUMP_ARRAY(c_server.sc.sender_id);

	assert(c_client.cc.common_iv.len == c_server.cc.common_iv.len);

    uint8_t buf_oscore[256];
    uint16_t buf_oscore_len = sizeof(buf_oscore);

    HEXDUMP(T1__COAP_REQ, T1__COAP_REQ_LEN);

    r = coap2oscore(T1__COAP_REQ, T1__COAP_REQ_LEN, (uint8_t *)&buf_oscore,
    		&buf_oscore_len, &c_client);
    assert(r == OscoreNoError);
    HEXDUMP(buf_oscore, buf_oscore_len);

	/*Test decrypting of an incoming request*/
    uint8_t buf_coap[256];
    uint16_t buf_coap_len = sizeof(buf_coap);
    bool oscore_present_flag = false;

    r = oscore2coap(buf_oscore, buf_oscore_len, buf_coap,
    		&buf_coap_len, &oscore_present_flag, &c_server);
    assert(r == OscoreNoError);
    HEXDUMP(buf_coap, buf_coap_len);
    assert(oscore_present_flag == true);


    edhoc_test();



    return 0;
}

static void edhoc_test(void)
{

}
