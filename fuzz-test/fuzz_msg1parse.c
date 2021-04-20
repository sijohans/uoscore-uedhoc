#include "main_entry.h"
#include "edhoc.h"
#include "credentials.h"
#include <string.h>

static const uint8_t *in_data;
static size_t in_data_size;
static bool msg1_valid = false;

EdhocError tx(uint8_t *data, uint32_t data_len)
{
    (void) data;
    (void) data_len;
    msg1_valid = true;
    return DestBufferToSmall;
}

EdhocError rx(uint8_t *data, uint32_t *data_len)
{
    uint32_t to_read = in_data_size;
    if (in_data_size > *data_len)
    {
        to_read = *data_len;
    }

    memcpy(data, in_data, to_read);
    *data_len = to_read;

    return EdhocNoError;
}

bool fuzz_one_input(const uint8_t *data, size_t size)
{

    in_data = data;
    in_data_size = size;

    /* edhoc declarations */
    uint8_t PRK_4x3m[PRK_DEFAULT_SIZE];
    uint8_t th4[SHA_DEFAULT_SIZE];
    uint8_t err_msg[ERR_MSG_DEFAULT_SIZE];
    uint32_t err_msg_len = sizeof(err_msg);
    uint8_t ad_1[AD_DEFAULT_SIZE];
    uint64_t ad_1_len = sizeof(ad_1);
    uint8_t ad_3[AD_DEFAULT_SIZE];
    uint64_t ad_3_len = sizeof(ad_1);
    EdhocError r;

    struct other_party_cred cred_i = { { ID_CRED_I_LEN, ID_CRED_I },
                                       { CRED_I_LEN, CRED_I },
                                       { PK_I_LEN, PK_I },
                                       { G_I_LEN, G_I },
                                       { CA_LEN, CA },
                                       { CA_PK_LEN, CA_PK } };
    uint16_t cred_num = 1;
    struct edhoc_responder_context c_r = { { SUITES_R_LEN, SUITES_R },
                                           { G_Y_LEN, G_Y },
                                           { Y_LEN, Y },
                                           { C_R_LEN, C_R },
                                           { G_R_LEN, G_R },
                                           { R_LEN, R },
                                           { AD_2_LEN, AD_2 },
                                           { ID_CRED_R_LEN, ID_CRED_R },
                                           { CRED_R_LEN, CRED_R },
                                           { SK_R_LEN, SK_R },
                                           { PK_R_LEN, PK_R } };

    r = edhoc_responder_run(&c_r, &cred_i, cred_num, err_msg,
                            &err_msg_len, (uint8_t *)&ad_1,
                            &ad_1_len, (uint8_t *)&ad_3, &ad_3_len,
                            PRK_4x3m, sizeof(PRK_4x3m), th4,
                            sizeof(th4));
    return msg1_valid;


}
