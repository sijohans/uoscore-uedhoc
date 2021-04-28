#include "edhoc.h"

/* Initiator */
uint8_t ID_CRED_I[128];
uint8_t CRED_I[1024];
uint8_t PK_I[64];
uint8_t G_I[64];
uint8_t CA[512];
uint8_t CA_PK[64];

/* Responder */
const uint8_t SUITES_R[] = { 0 };

int main(void)
{

    struct other_party_cred cred_i = {
        { sizeof(ID_CRED_I), ID_CRED_I },
        { sizeof(CRED_I), CRED_I },
        { sizeof(PK_I), PK_I },
        { sizeof(G_I), G_I },
        { sizeof(CA), CA },
        { sizeof(CA_PK), CA_PK },
    };

    uint16_t cred_num = 1;

    struct edhoc_responder_context c_r = { { sizeof(SUITES_R), SUITES_R },
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

    return 0;
}