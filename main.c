#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include "modules/oscore/oscore.h"

/*Test vector C1.1: Key derivation with Master Salt*/
uint8_t T1__MASTER_SECRET[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
				  0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
				  0x0d, 0x0e, 0x0f, 0x10 };
uint8_t T1__MASTER_SECRET_LEN = sizeof(T1__MASTER_SECRET);

uint8_t *T1__SENDER_ID = NULL;
uint8_t T1__SENDER_ID_LEN = 0;

uint8_t T1__RECIPIENT_ID[1] = { 0x01 };
uint8_t T1__RECIPIENT_ID_LEN = sizeof(T1__RECIPIENT_ID);

uint8_t T1__MASTER_SALT[8] = { 0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40 };
uint8_t T1__MASTER_SALT_LEN = sizeof(T1__MASTER_SALT);

uint8_t *T1__ID_CONTEXT = NULL;
uint8_t T1__ID_CONTEXT_LEN = 0;

/*Test vector C4: Generating a OSCORE Packet with key material form test vector C.1 */
uint8_t T1__COAP_REQ[] = { 0x44, 0x01, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74,
			   0x39, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f,
			   0x73, 0x74, 0x83, 0x74, 0x76, 0x31 };
uint16_t T1__COAP_REQ_LEN = sizeof(T1__COAP_REQ);

/*Expected result*/
uint8_t T1__SENDER_KEY[] = { 0xf0, 0x91, 0x0e, 0xd7, 0x29, 0x5e, 0x6a, 0xd4,
			     0xb5, 0x4f, 0xc7, 0x93, 0x15, 0x43, 0x02, 0xff };
uint8_t T1__SENDER_KEY_LEN = sizeof(T1__SENDER_KEY);

uint8_t T1__RECIPIENT_KEY[] = { 0xff, 0xb1, 0x4e, 0x09, 0x3c, 0x94, 0xc9, 0xca,
				0xc9, 0x47, 0x16, 0x48, 0xb4, 0xf9, 0x87, 0x10 };
uint8_t T1__RECIPIENT_KEY_LEN = sizeof(T1__RECIPIENT_KEY);

uint8_t T1__COMMON_IV[] = { 0x46, 0x22, 0xd4, 0xdd, 0x6d, 0x94, 0x41,
			    0x68, 0xee, 0xfb, 0x54, 0x98, 0x7c };
uint8_t T1__COMMON_IV_LEN = sizeof(T1__COMMON_IV);

uint8_t T1__OSCORE_REQ[] = { 0x44, 0x02, 0x5d, 0x1f, 0x00, 0x00, 0x39,
			     0x74, 0x39, 0x6c, 0x6f, 0x63, 0x61, 0x6c,
			     0x68, 0x6f, 0x73, 0x74, 0x62, 0x09, 0x14,
			     0xff, 0x61, 0x2f, 0x10, 0x92, 0xf1, 0x77,
			     0x6f, 0x1c, 0x16, 0x68, 0xb3, 0x82, 0x5e };
uint8_t T1__OSCORE_REQ_LEN = sizeof(T1__OSCORE_REQ);


static void hex_dump(const char *str, uint8_t *data, size_t size)
{
    printf("%s (%zu): ", str, size);
    for (size_t i = 0; i < size; ++i)
    {
	printf("%02x", data[i]);
    } printf("\r\n");
}
#define HEXDUMP(data, size) hex_dump(#data, data, size)

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

    HEXDUMP(c_client.rc.recipient_key.ptr, c_client.rc.recipient_key.len);
    HEXDUMP(c_client.rc.recipient_id.ptr, c_client.rc.recipient_id.len);
    HEXDUMP(c_client.sc.sender_key.ptr, c_client.sc.sender_key.len);
    HEXDUMP(c_client.sc.sender_id.ptr, c_client.sc.sender_id.len);

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

	HEXDUMP(c_server.rc.recipient_key.ptr, c_server.rc.recipient_key.len);
	HEXDUMP(c_server.rc.recipient_id.ptr, c_server.rc.recipient_id.len);
	HEXDUMP(c_server.sc.sender_key.ptr, c_server.sc.sender_key.len);
	HEXDUMP(c_server.sc.sender_id.ptr, c_server.sc.sender_id.len);

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

    return 0;
}