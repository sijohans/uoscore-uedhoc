#include "main_entry.h"
#include "oscore.h"
#include "test_vectors_oscore.h"
#include <stdlib.h>

bool fuzz_one_input(const uint8_t *data, size_t size)
{
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
    struct context c_server;
    OscoreError error = oscore_context_init(&server_params, &c_server);
    if (error != OscoreNoError) { return false; }
    c_server.sc.sender_seq_num = 20;
    uint8_t *buf_coap = malloc(size);
    uint16_t buf_coap_len = size;
    if (NULL == buf_coap)
    {
        return false;
    }

    bool oscore_present_flag = false;

    //error = oscore2coap(data, size, buf_coap, &buf_coap_len, &oscore_present_flag, &c_server);

    free(buf_coap);
    return (error == OscoreNoError);

}