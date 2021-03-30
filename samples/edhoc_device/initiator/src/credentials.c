/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#ifndef CREDENTIALS_H
#define CREDENTIALS_H

#include <stddef.h>
#include <stdint.h>

#include <edhoc.h>
#include "credentials_select.h"

/*


Test 1 
see https://github.com/EricssonResearch/EDHOC/blob/master/Test%20Vectors/vectors.txt

line 0 - 290
produces the result
PRK_4x3m(size 32)
EC 62 92 A0 67 F1 37 FC 7F 59 62 9D 22 6F BF C4 
        E0 68 89 49 F6 62 A9 7F D8 2F BE B7 99 71 39 4A 
th4(size 32)
36 45 7C 25 90 0B 01 26 36 77 90 2D 34 02 E6 DC 
        96 D3 8C 45 73 79 F0 DC CA 1E 9B 3A AF 34 2E 43 
info (size 58):
        84 0A 58 20 36 45 7C 25 90 0B 01 26 36 77 90 2D 
        34 02 E6 DC 96 D3 8C 45 73 79 F0 DC CA 1E 9B 3A 
        AF 34 2E 43 74 4F 53 43 4F 52 45 20 4D 61 73 74 
        65 72 20 53 65 63 72 65 74 10 
OSCORE Master Secret(size 16)
EB 9E 7C 08 16 37 41 54 C8 EC D8 39 84 5F 25 62 
info (size 56):
        84 0A 58 20 36 45 7C 25 90 0B 01 26 36 77 90 2D 
        34 02 E6 DC 96 D3 8C 45 73 79 F0 DC CA 1E 9B 3A 
        AF 34 2E 43 72 4F 53 43 4F 52 45 20 4D 61 73 74 
        65 72 20 73 61 6C 74 08 
OSCORE Master salt(size 8)
4C C6 AB 0C 7C AF 24 76 

*/

#ifdef INITIATOR_TEST_1

enum method_type METHOD_TYPE = INITIATOR_SK_RESPONDER_SK;
uint8_t CORR = 1;

uint8_t SUITES_I[] = {0};
uint32_t SUITES_I_LEN = sizeof(SUITES_I);

uint8_t G_X[] = {0x89, 0x8f, 0xf7, 0x9a, 0x02, 0x06, 0x7a, 0x16, 0xea, 0x1e, 0xcc, 0xb9, 0x0f, 0xa5, 0x22, 0x46, 0xf5, 0xaa, 0x4d, 0xd6, 0xec, 0x07, 0x6b, 0xba, 0x02, 0x59, 0xd9, 0x04, 0xb7, 0xec, 0x8b, 0x0c};
uint32_t G_X_LEN = sizeof(G_X);

uint8_t X[] = {0x8f, 0x78, 0x1a, 0x09, 0x53, 0x72, 0xf8, 0x5b, 0x6d, 0x9f, 0x61, 0x09, 0xae, 0x42, 0x26, 0x11, 0x73, 0x4d, 0x7d, 0xbf, 0xa0, 0x06, 0x9a, 0x2d, 0xf2, 0x93, 0x5b, 0xb2, 0xe0, 0x53, 0xbf, 0x35};
uint32_t X_LEN = sizeof(X);

uint8_t* C_I = NULL;
uint32_t C_I_LEN = 0;

uint8_t* AD_1 = NULL;
uint32_t AD_1_LEN = 0;

uint8_t* AD_3 = NULL;
uint32_t AD_3_LEN = 0;

uint8_t ID_CRED_I[] = {0xa1, 0x18, 0x22, 0x82, 0x2e, 0x48, 0x5b, 0x78, 0x69, 0x88, 0x43, 0x9e, 0xbc, 0xf2};
uint32_t ID_CRED_I_LEN = sizeof(ID_CRED_I);

uint8_t CRED_I[] = {0x58, 0x65, 0xfa, 0x34, 0xb2, 0x2a, 0x9c, 0xa4, 0xa1, 0xe1, 0x29, 0x24, 0xea, 0xe1, 0xd1, 0x76, 0x60, 0x88, 0x09, 0x84, 0x49, 0xcb, 0x84, 0x8f, 0xfc, 0x79, 0x5f, 0x88, 0xaf, 0xc4, 0x9c, 0xbe, 0x8a, 0xfd, 0xd1, 0xba, 0x00, 0x9f, 0x21, 0x67, 0x5e, 0x8f, 0x6c, 0x77, 0xa4, 0xa2, 0xc3, 0x01, 0x95, 0x60, 0x1f, 0x6f, 0x0a, 0x08, 0x52, 0x97, 0x8b, 0xd4, 0x3d, 0x28, 0x20, 0x7d, 0x44, 0x48, 0x65, 0x02, 0xff, 0x7b, 0xdd, 0xa6, 0x32, 0xc7, 0x88, 0x37, 0x00, 0x16, 0xb8, 0x96, 0x5b, 0xdb, 0x20, 0x74, 0xbf, 0xf8, 0x2e, 0x5a, 0x20, 0xe0, 0x9b, 0xec, 0x21, 0xf8, 0x40, 0x6e, 0x86, 0x44, 0x2b, 0x87, 0xec, 0x3f, 0xf2, 0x45, 0xb7};
uint32_t CRED_I_LEN = sizeof(CRED_I);

uint8_t* I = NULL;
uint32_t I_LEN = 0;

uint8_t* G_I = NULL;
uint32_t G_I_LEN = 0;

uint8_t SK_I[] = {0x2f, 0xfc, 0xe7, 0xa0, 0xb2, 0xb8, 0x25, 0xd3, 0x97, 0xd0, 0xcb, 0x54, 0xf7, 0x46, 0xe3, 0xda, 0x3f, 0x27, 0x59, 0x6e, 0xe0, 0x6b, 0x53, 0x71, 0x48, 0x1d, 0xc0, 0xe0, 0x12, 0xbc, 0x34, 0xd7};
uint32_t SK_I_LEN = sizeof(SK_I);

uint8_t PK_I[] = {0x38, 0xe5, 0xd5, 0x45, 0x63, 0xc2, 0xb6, 0xa4, 0xba, 0x26, 0xf3, 0x01, 0x5f, 0x61, 0xbb, 0x70, 0x6e, 0x5c, 0x2e, 0xfd, 0xb5, 0x56, 0xd2, 0xe1, 0x69, 0x0b, 0x97, 0xfc, 0x3c, 0x6d, 0xe1, 0x49};
uint32_t PK_I_LEN = sizeof(PK_I);

/*other party credentials*/
uint8_t ID_CRED_R[] = {0xa1, 0x18, 0x22, 0x82, 0x2e, 0x48, 0xfc, 0x79, 0x99, 0x0f, 0x24, 0x31, 0xa3, 0xf5};
uint32_t ID_CRED_R_LEN = sizeof(ID_CRED_R);

uint8_t CRED_R[] = {0x58, 0x6e, 0x47, 0x62, 0x4d, 0xc9, 0xcd, 0xc6, 0x82, 0x4b, 0x2a, 0x4c, 0x52, 0xe9, 0x5e, 0xc9, 0xd6, 0xb0, 0x53, 0x4b, 0x71, 0xc2, 0xb4, 0x9e, 0x4b, 0xf9, 0x03, 0x15, 0x00, 0xce, 0xe6, 0x86, 0x99, 0x79, 0xc2, 0x97, 0xbb, 0x5a, 0x8b, 0x38, 0x1e, 0x98, 0xdb, 0x71, 0x41, 0x08, 0x41, 0x5e, 0x5c, 0x50, 0xdb, 0x78, 0x97, 0x4c, 0x27, 0x15, 0x79, 0xb0, 0x16, 0x33, 0xa3, 0xef, 0x62, 0x71, 0xbe, 0x5c, 0x22, 0x5e, 0xb2, 0x8f, 0x9c, 0xf6, 0x18, 0x0b, 0x5a, 0x6a, 0xf3, 0x1e, 0x80, 0x20, 0x9a, 0x08, 0x5c, 0xfb, 0xf9, 0x5f, 0x3f, 0xdc, 0xf9, 0xb1, 0x8b, 0x69, 0x3d, 0x6c, 0x0e, 0x0d, 0x0f, 0xfb, 0x8e, 0x3f, 0x9a, 0x32, 0xa5, 0x08, 0x59, 0xec, 0xd0, 0xbf, 0xcf, 0xf2, 0xc2, 0x18};
uint32_t CRED_R_LEN = sizeof(CRED_R);

uint8_t PK_R[32] = {0xdb, 0xd9, 0xdc, 0x8c, 0xd0, 0x3f, 0xb7, 0xc3, 0x91, 0x35, 0x11, 0x46, 0x2b, 0xb2, 0x38, 0x16, 0x47, 0x7c, 0x6b, 0xd8, 0xd6, 0x6e, 0xf5, 0xa1, 0xa0, 0x70, 0xac, 0x85, 0x4e, 0xd7, 0x3f, 0xd2};
uint8_t PK_R_LEN = sizeof(PK_R);

uint8_t G_R[] = {};
uint8_t G_R_LEN = sizeof(G_R);

uint8_t CA[] = {};
uint8_t CA_LEN = sizeof(CA);

uint8_t CA_PK[] = {};
uint8_t CA_PK_LEN = sizeof(CA_PK);
#endif

#ifdef RESPONDER_TEST_1
uint8_t SUITES_R[] = {0};
uint32_t SUITES_R_LEN = sizeof(SUITES_R);

uint8_t G_Y[] = {0x71, 0xa3, 0xd5, 0x99, 0xc2, 0x1d, 0xa1, 0x89, 0x02, 0xa1, 0xae, 0xa8, 0x10, 0xb2, 0xb6, 0x38, 0x2c, 0xcd, 0x8d, 0x5f, 0x9b, 0xf0, 0x19, 0x52, 0x81, 0x75, 0x4c, 0x5e, 0xbc, 0xaf, 0x30, 0x1e};
uint32_t G_Y_LEN = sizeof(G_Y);

uint8_t Y[] = {0xfd, 0x8c, 0xd8, 0x77, 0xc9, 0xea, 0x38, 0x6e, 0x6a, 0xf3, 0x4f, 0xf7, 0xe6, 0x06, 0xc4, 0xb6, 0x4c, 0xa8, 0x31, 0xc8, 0xba, 0x33, 0x13, 0x4f, 0xd4, 0xcd, 0x71, 0x67, 0xca, 0xba, 0xec, 0xda};
uint32_t Y_LEN = sizeof(Y);

uint8_t C_R[] = {0x2b};
uint32_t C_R_LEN = sizeof(C_R);

uint8_t ID_CRED_R[] = {0xa1, 0x18, 0x22, 0x82, 0x2e, 0x48, 0xfc, 0x79, 0x99, 0x0f, 0x24, 0x31, 0xa3, 0xf5};
uint32_t ID_CRED_R_LEN = sizeof(ID_CRED_R);

uint8_t CRED_R[] = {0x58, 0x6e, 0x47, 0x62, 0x4d, 0xc9, 0xcd, 0xc6, 0x82, 0x4b, 0x2a, 0x4c, 0x52, 0xe9, 0x5e, 0xc9, 0xd6, 0xb0, 0x53, 0x4b, 0x71, 0xc2, 0xb4, 0x9e, 0x4b, 0xf9, 0x03, 0x15, 0x00, 0xce, 0xe6, 0x86, 0x99, 0x79, 0xc2, 0x97, 0xbb, 0x5a, 0x8b, 0x38, 0x1e, 0x98, 0xdb, 0x71, 0x41, 0x08, 0x41, 0x5e, 0x5c, 0x50, 0xdb, 0x78, 0x97, 0x4c, 0x27, 0x15, 0x79, 0xb0, 0x16, 0x33, 0xa3, 0xef, 0x62, 0x71, 0xbe, 0x5c, 0x22, 0x5e, 0xb2, 0x8f, 0x9c, 0xf6, 0x18, 0x0b, 0x5a, 0x6a, 0xf3, 0x1e, 0x80, 0x20, 0x9a, 0x08, 0x5c, 0xfb, 0xf9, 0x5f, 0x3f, 0xdc, 0xf9, 0xb1, 0x8b, 0x69, 0x3d, 0x6c, 0x0e, 0x0d, 0x0f, 0xfb, 0x8e, 0x3f, 0x9a, 0x32, 0xa5, 0x08, 0x59, 0xec, 0xd0, 0xbf, 0xcf, 0xf2, 0xc2, 0x18};
uint32_t CRED_R_LEN = sizeof(CRED_R);

uint8_t* AD_2;
uint32_t AD_2_LEN = 0;

uint8_t SK_R[] = {0xdf, 0x69, 0x27, 0x4d, 0x71, 0x32, 0x96, 0xe2, 0x46, 0x30, 0x63, 0x65, 0x37, 0x2b, 0x46, 0x83, 0xce, 0xd5, 0x38, 0x1b, 0xfc, 0xad, 0xcd, 0x44, 0x0a, 0x24, 0xc3, 0x91, 0xd2, 0xfe, 0xdb, 0x94};
uint8_t SK_R_LEN = sizeof(SK_R);

uint8_t PK_R[32] = {0xdb, 0xd9, 0xdc, 0x8c, 0xd0, 0x3f, 0xb7, 0xc3, 0x91, 0x35, 0x11, 0x46, 0x2b, 0xb2, 0x38, 0x16, 0x47, 0x7c, 0x6b, 0xd8, 0xd6, 0x6e, 0xf5, 0xa1, 0xa0, 0x70, 0xac, 0x85, 0x4e, 0xd7, 0x3f, 0xd2};
uint8_t PK_R_LEN = sizeof(PK_R);

uint8_t* G_R;
uint32_t G_R_LEN = 0;

uint8_t* R;
uint32_t R_LEN = 0;

/*other party credentials*/
uint8_t ID_CRED_I[] = {0xa1, 0x18, 0x22, 0x82, 0x2e, 0x48, 0x5b, 0x78, 0x69, 0x88, 0x43, 0x9e, 0xbc, 0xf2};
uint32_t ID_CRED_I_LEN = sizeof(ID_CRED_I);

uint8_t CRED_I[] = {0x58, 0x65, 0xfa, 0x34, 0xb2, 0x2a, 0x9c, 0xa4, 0xa1, 0xe1, 0x29, 0x24, 0xea, 0xe1, 0xd1, 0x76, 0x60, 0x88, 0x09, 0x84, 0x49, 0xcb, 0x84, 0x8f, 0xfc, 0x79, 0x5f, 0x88, 0xaf, 0xc4, 0x9c, 0xbe, 0x8a, 0xfd, 0xd1, 0xba, 0x00, 0x9f, 0x21, 0x67, 0x5e, 0x8f, 0x6c, 0x77, 0xa4, 0xa2, 0xc3, 0x01, 0x95, 0x60, 0x1f, 0x6f, 0x0a, 0x08, 0x52, 0x97, 0x8b, 0xd4, 0x3d, 0x28, 0x20, 0x7d, 0x44, 0x48, 0x65, 0x02, 0xff, 0x7b, 0xdd, 0xa6, 0x32, 0xc7, 0x88, 0x37, 0x00, 0x16, 0xb8, 0x96, 0x5b, 0xdb, 0x20, 0x74, 0xbf, 0xf8, 0x2e, 0x5a, 0x20, 0xe0, 0x9b, 0xec, 0x21, 0xf8, 0x40, 0x6e, 0x86, 0x44, 0x2b, 0x87, 0xec, 0x3f, 0xf2, 0x45, 0xb7};
uint32_t CRED_I_LEN = sizeof(CRED_I);

uint8_t PK_I[] = {0x38, 0xe5, 0xd5, 0x45, 0x63, 0xc2, 0xb6, 0xa4, 0xba, 0x26, 0xf3, 0x01, 0x5f, 0x61, 0xbb, 0x70, 0x6e, 0x5c, 0x2e, 0xfd, 0xb5, 0x56, 0xd2, 0xe1, 0x69, 0x0b, 0x97, 0xfc, 0x3c, 0x6d, 0xe1, 0x49};
uint8_t PK_I_LEN = sizeof(PK_I);

uint8_t* G_I = NULL;
uint32_t G_I_LEN = 0;

uint8_t CA[] = {};
uint8_t CA_LEN = sizeof(CA);

uint8_t CA_PK[] = {};
uint8_t CA_PK_LEN = sizeof(CA_PK);
#endif

#if (defined INITIATOR_TEST_1) || (defined RESPONDER_TEST_1)
uint8_t MSG_1[] = {0x01, 0x00, 0x58, 0x20, 0x89, 0x8f, 0xf7, 0x9a, 0x02, 0x06, 0x7a, 0x16, 0xea, 0x1e, 0xcc, 0xb9, 0x0f, 0xa5, 0x22, 0x46, 0xf5, 0xaa, 0x4d, 0xd6, 0xec, 0x07, 0x6b, 0xba, 0x02, 0x59, 0xd9, 0x04, 0xb7, 0xec, 0x8b, 0x0c, 0x40};
uint32_t MSG_1_LEN = sizeof(MSG_1);

uint8_t MSG_2[] = {0x58, 0x20, 0x71, 0xa3, 0xd5, 0x99, 0xc2, 0x1d, 0xa1, 0x89, 0x02, 0xa1, 0xae, 0xa8, 0x10, 0xb2, 0xb6, 0x38, 0x2c, 0xcd, 0x8d, 0x5f, 0x9b, 0xf0, 0x19, 0x52, 0x81, 0x75, 0x4c, 0x5e, 0xbc, 0xaf, 0x30, 0x1e, 0x13, 0x58, 0x50, 0x99, 0xd5, 0x38, 0x01, 0xa7, 0x25, 0xbf, 0xd6, 0xa4, 0xe7, 0x1d, 0x04, 0x84, 0xb7, 0x55, 0xec, 0x38, 0x3d, 0xf7, 0x7a, 0x91, 0x6e, 0xc0, 0xdb, 0xc0, 0x2b, 0xba, 0x7c, 0x21, 0xa2, 0x00, 0x80, 0x7b, 0x4f, 0x58, 0x5f, 0x72, 0x8b, 0x67, 0x1a, 0xd6, 0x78, 0xa4, 0x3a, 0xac, 0xd3, 0x3b, 0x78, 0xeb, 0xd5, 0x66, 0xcd, 0x00, 0x4f, 0xc6, 0xf1, 0xd4, 0x06, 0xf0, 0x1d, 0x97, 0x04, 0xe7, 0x05, 0xb2, 0x15, 0x52, 0xa9, 0xeb, 0x28, 0xea, 0x31, 0x6a, 0xb6, 0x50, 0x37, 0xd7, 0x17, 0x86, 0x2e};
uint32_t MSG_2_LEN = sizeof(MSG_2);

uint8_t MSG_3[] = {0x13, 0x58, 0x58, 0x2d, 0x88, 0xff, 0x86, 0xda, 0x47, 0x48, 0x2c, 0x0d, 0xfa, 0x55, 0x9a, 0xc8, 0x24, 0xa4, 0xa7, 0x83, 0xd8, 0x70, 0xc9, 0xdb, 0xa4, 0x78, 0x05, 0xe8, 0xaa, 0xfb, 0xad, 0x69, 0x74, 0xc4, 0x96, 0x46, 0x58, 0x65, 0x03, 0xfa, 0x9b, 0xbf, 0x3e, 0x00, 0x01, 0x2c, 0x03, 0x7e, 0xaf, 0x56, 0xe4, 0x5e, 0x30, 0x19, 0x20, 0x83, 0x9b, 0x81, 0x3a, 0x53, 0xf6, 0xd4, 0xc5, 0x57, 0x48, 0x0f, 0x6c, 0x79, 0x7d, 0x5b, 0x76, 0xf0, 0xe4, 0x62, 0xf5, 0xf5, 0x7a, 0x3d, 0xb6, 0xd2, 0xb5, 0x0c, 0x32, 0x31, 0x9f, 0x34, 0x0f, 0x4a, 0xc5, 0xaf, 0x9a};
uint32_t MSG_3_LEN = sizeof(MSG_3);
#endif

/*


Test 2
see https://github.com/EricssonResearch/EDHOC/blob/master/Test%20Vectors/vectors.txt

INITIATOR_SDHK_RESPONDER_SDHK with RPK

line 292 - 540

Produces the result: 

PRK_4x3m(size 32)
02 56 2F 1F 01 78 5C 0A A5 F5 94 64 0C 49 CB F6 
        9F 72 2E 9E 6C 57 83 7D 8E 15 79 EC 45 FE 64 7A 
th4(size 32)
B2 56 AC 0D 51 AD D3 EB D5 4A 2D 8D 91 56 D3 E3 
        A7 C6 89 AE 03 AD DC 6B AA EF 9F C6 BF 47 38 6A 
info (size 58):
        84 0A 58 20 B2 56 AC 0D 51 AD D3 EB D5 4A 2D 8D 
        91 56 D3 E3 A7 C6 89 AE 03 AD DC 6B AA EF 9F C6 
        BF 47 38 6A 74 4F 53 43 4F 52 45 20 4D 61 73 74 
        65 72 20 53 65 63 72 65 74 10 
OSCORE Master Secret(size 16)
E7 AE AF DB 28 57 4A 9F 79 70 F0 59 15 9D EE 68 
info (size 56):
        84 0A 58 20 B2 56 AC 0D 51 AD D3 EB D5 4A 2D 8D 
        91 56 D3 E3 A7 C6 89 AE 03 AD DC 6B AA EF 9F C6 
        BF 47 38 6A 72 4F 53 43 4F 52 45 20 4D 61 73 74 
        65 72 20 73 61 6C 74 08 
OSCORE Master salt(size 8)
DE 22 71 86 8B A1 72 F3 

*/

#ifdef INITIATOR_TEST_2

enum method_type METHOD_TYPE = INITIATOR_SDHK_RESPONDER_SDHK;
uint8_t CORR = 1;

uint8_t SUITES_I[] = {0}; /*Selected Cipher Suite*/
uint32_t SUITES_I_LEN = sizeof(SUITES_I);

uint8_t G_X[] = {0x8d, 0x3e, 0xf5, 0x6d, 0x1b, 0x75, 0x0a, 0x43, 0x51, 0xd6, 0x8a, 0xc2, 0x50, 0xa0, 0xe8, 0x83, 0x79, 0x0e, 0xfc, 0x80, 0xa5, 0x38, 0xa4, 0x44, 0xee, 0x9e, 0x2b, 0x57, 0xe2, 0x44, 0x1a, 0x7c};
uint32_t G_X_LEN = sizeof(G_X);

uint8_t X[] = {0xae, 0x11, 0xa0, 0xdb, 0x86, 0x3c, 0x02, 0x27, 0xe5, 0x39, 0x92, 0xfe, 0xb8, 0xf5, 0x92, 0x4c, 0x50, 0xd0, 0xa7, 0xba, 0x6e, 0xea, 0xb4, 0xad, 0x1f, 0xf2, 0x45, 0x72, 0xf4, 0xf5, 0x7c, 0xfa};
uint32_t X_LEN = sizeof(X);

uint8_t C_I[] = {0x16};
uint32_t C_I_LEN = sizeof(C_I);

uint8_t* AD_1 = NULL;
uint32_t AD_1_LEN = 0;

uint8_t* AD_3 = NULL;
uint32_t AD_3_LEN = 0;

uint8_t ID_CRED_I[] = {0xa1, 0x04, 0x41, 0x24};
uint32_t ID_CRED_I_LEN = sizeof(ID_CRED_I);

uint8_t CRED_I[] = {0xa4, 0x01, 0x01, 0x20, 0x04, 0x21, 0x58, 0x20, 0x2c, 0x44, 0x0c, 0xc1, 0x21, 0xf8, 0xd7, 0xf2, 0x4c, 0x3b, 0x0e, 0x41, 0xae, 0xda, 0xfe, 0x9c, 0xaa, 0x4f, 0x4e, 0x7a, 0xbb, 0x83, 0x5e, 0xc3, 0x0f, 0x1d, 0xe8, 0x8a, 0xdb, 0x96, 0xff, 0x71, 0x6c, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x20, 0x6e, 0x61, 0x6d, 0x65, 0x60};
uint32_t CRED_I_LEN = sizeof(CRED_I);

uint8_t I[] = {0x2b, 0xbe, 0xa6, 0x55, 0xc2, 0x33, 0x71, 0xc3, 0x29, 0xcf, 0xbd, 0x3b, 0x1f, 0x02, 0xc6, 0xc0, 0x62, 0x03, 0x38, 0x37, 0xb8, 0xb5, 0x90, 0x99, 0xa4, 0x43, 0x6f, 0x66, 0x60, 0x81, 0xb0, 0x8e};
uint32_t I_LEN = sizeof(I);

uint8_t G_I[] = {0x2c, 0x44, 0x0c, 0xc1, 0x21, 0xf8, 0xd7, 0xf2, 0x4c, 0x3b, 0x0e, 0x41, 0xae, 0xda, 0xfe, 0x9c, 0xaa, 0x4f, 0x4e, 0x7a, 0xbb, 0x83, 0x5e, 0xc3, 0x0f, 0x1d, 0xe8, 0x8a, 0xdb, 0x96, 0xff, 0x71};
uint32_t G_I_LEN = sizeof(G_I);

uint8_t SK_I[] = {};
uint32_t SK_I_LEN = sizeof(SK_I);

uint8_t PK_I[] = {};
uint32_t PK_I_LEN = sizeof(PK_I);

/*other party credentials*/
uint8_t ID_CRED_R[] = {0xa1, 0x04, 0x41, 0x07};
uint32_t ID_CRED_R_LEN = sizeof(ID_CRED_R);

uint8_t CRED_R[] = {0xa4, 0x01, 0x01, 0x20, 0x04, 0x21, 0x58, 0x20, 0xa3, 0xff, 0x26, 0x35, 0x95, 0xbe, 0xb3, 0x77, 0xd1, 0xa0, 0xce, 0x1d, 0x04, 0xda, 0xd2, 0xd4, 0x09, 0x66, 0xac, 0x6b, 0xcb, 0x62, 0x20, 0x51, 0xb8, 0x46, 0x59, 0x18, 0x4d, 0x5d, 0x9a, 0x32, 0x6c, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x20, 0x6e, 0x61, 0x6d, 0x65, 0x60};
uint32_t CRED_R_LEN = sizeof(CRED_R);

uint8_t G_R[] = {0xa3, 0xff, 0x26, 0x35, 0x95, 0xbe, 0xb3, 0x77, 0xd1, 0xa0, 0xce, 0x1d, 0x04, 0xda, 0xd2, 0xd4, 0x09, 0x66, 0xac, 0x6b, 0xcb, 0x62, 0x20, 0x51, 0xb8, 0x46, 0x59, 0x18, 0x4d, 0x5d, 0x9a, 0x32};
uint8_t G_R_LEN = sizeof(G_R);

uint8_t PK_R[] = {};
uint8_t PK_R_LEN = sizeof(PK_R);

uint8_t CA[] = {};
uint8_t CA_LEN = sizeof(CA);

uint8_t CA_PK[] = {};
uint8_t CA_PK_LEN = sizeof(CA_PK);
#endif

#ifdef RESPONDER_TEST_2
uint8_t SUITES_R[] = {0};
uint32_t SUITES_R_LEN = sizeof(SUITES_R);

uint8_t G_Y[] = {0x52, 0xfb, 0xa0, 0xbd, 0xc8, 0xd9, 0x53, 0xdd, 0x86, 0xce, 0x1a, 0xb2, 0xfd, 0x7c, 0x05, 0xa4, 0x65, 0x8c, 0x7c, 0x30, 0xaf, 0xdb, 0xfc, 0x33, 0x01, 0x04, 0x70, 0x69, 0x45, 0x1b, 0xaf, 0x35};
uint32_t G_Y_LEN = sizeof(G_Y);

uint8_t Y[] = {0xc6, 0x46, 0xcd, 0xdc, 0x58, 0x12, 0x6e, 0x18, 0x10, 0x5f, 0x01, 0xce, 0x35, 0x05, 0x6e, 0x5e, 0xbc, 0x35, 0xf4, 0xd4, 0xcc, 0x51, 0x07, 0x49, 0xa3, 0xa5, 0xe0, 0x69, 0xc1, 0x16, 0x16, 0x9a};
uint32_t Y_LEN = sizeof(Y);

uint8_t C_R[] = {0x20};
uint32_t C_R_LEN = sizeof(C_R);

uint8_t ID_CRED_R[] = {0xa1, 0x04, 0x41, 0x07};
uint32_t ID_CRED_R_LEN = sizeof(ID_CRED_R);

uint8_t CRED_R[] = {0xa4, 0x01, 0x01, 0x20, 0x04, 0x21, 0x58, 0x20, 0xa3, 0xff, 0x26, 0x35, 0x95, 0xbe, 0xb3, 0x77, 0xd1, 0xa0, 0xce, 0x1d, 0x04, 0xda, 0xd2, 0xd4, 0x09, 0x66, 0xac, 0x6b, 0xcb, 0x62, 0x20, 0x51, 0xb8, 0x46, 0x59, 0x18, 0x4d, 0x5d, 0x9a, 0x32, 0x6c, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x20, 0x6e, 0x61, 0x6d, 0x65, 0x60};
uint32_t CRED_R_LEN = sizeof(CRED_R);

uint8_t* AD_2;
uint32_t AD_2_LEN = 0;

uint8_t SK_R[] = {};
uint8_t SK_R_LEN = sizeof(SK_R);

uint8_t PK_R[] = {};
uint8_t PK_R_LEN = sizeof(PK_R);

uint8_t R[] = {0xbb, 0x50, 0x1a, 0xac, 0x67, 0xb9, 0xa9, 0x5f, 0x97, 0xe0, 0xed, 0xed, 0x6b, 0x82, 0xa6, 0x62, 0x93, 0x4f, 0xbb, 0xfc, 0x7a, 0xd1, 0xb7, 0x4c, 0x1f, 0xca, 0xd6, 0x6a, 0x07, 0x94, 0x22, 0xd0};
uint8_t R_LEN = sizeof(R);

uint8_t G_R[] = {0xa3, 0xff, 0x26, 0x35, 0x95, 0xbe, 0xb3, 0x77, 0xd1, 0xa0, 0xce, 0x1d, 0x04, 0xda, 0xd2, 0xd4, 0x09, 0x66, 0xac, 0x6b, 0xcb, 0x62, 0x20, 0x51, 0xb8, 0x46, 0x59, 0x18, 0x4d, 0x5d, 0x9a, 0x32};
uint8_t G_R_LEN = sizeof(G_R);

/*other party credentials*/
uint8_t ID_CRED_I[] = {0xa1, 0x04, 0x41, 0x24};
uint32_t ID_CRED_I_LEN = sizeof(ID_CRED_I);

uint8_t CRED_I[] = {0xa4, 0x01, 0x01, 0x20, 0x04, 0x21, 0x58, 0x20, 0x2c, 0x44, 0x0c, 0xc1, 0x21, 0xf8, 0xd7, 0xf2, 0x4c, 0x3b, 0x0e, 0x41, 0xae, 0xda, 0xfe, 0x9c, 0xaa, 0x4f, 0x4e, 0x7a, 0xbb, 0x83, 0x5e, 0xc3, 0x0f, 0x1d, 0xe8, 0x8a, 0xdb, 0x96, 0xff, 0x71, 0x6c, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x20, 0x6e, 0x61, 0x6d, 0x65, 0x60};
uint32_t CRED_I_LEN = sizeof(CRED_I);

uint8_t G_I[] = {0x2c, 0x44, 0x0c, 0xc1, 0x21, 0xf8, 0xd7, 0xf2, 0x4c, 0x3b, 0x0e, 0x41, 0xae, 0xda, 0xfe, 0x9c, 0xaa, 0x4f, 0x4e, 0x7a, 0xbb, 0x83, 0x5e, 0xc3, 0x0f, 0x1d, 0xe8, 0x8a, 0xdb, 0x96, 0xff, 0x71};
uint32_t G_I_LEN = sizeof(G_I);

uint8_t PK_I[] = {};
uint8_t PK_I_LEN = sizeof(PK_I);

uint8_t CA[] = {};
uint8_t CA_LEN = sizeof(CA);

uint8_t CA_PK[] = {};
uint8_t CA_PK_LEN = sizeof(CA_PK);
#endif

#if (defined INITIATOR_TEST_2) || (defined RESPONDER_TEST_2)
uint8_t MSG_1[] = {0x0d, 0x00, 0x58, 0x20, 0x8d, 0x3e, 0xf5, 0x6d, 0x1b, 0x75, 0x0a, 0x43, 0x51, 0xd6, 0x8a, 0xc2, 0x50, 0xa0, 0xe8, 0x83, 0x79, 0x0e, 0xfc, 0x80, 0xa5, 0x38, 0xa4, 0x44, 0xee, 0x9e, 0x2b, 0x57, 0xe2, 0x44, 0x1a, 0x7c, 0x21};
uint32_t MSG_1_LEN = sizeof(MSG_1);

uint8_t MSG_2[] = {0x58, 0x20, 0x52, 0xfb, 0xa0, 0xbd, 0xc8, 0xd9, 0x53, 0xdd, 0x86, 0xce, 0x1a, 0xb2, 0xfd, 0x7c, 0x05, 0xa4, 0x65, 0x8c, 0x7c, 0x30, 0xaf, 0xdb, 0xfc, 0x33, 0x01, 0x04, 0x70, 0x69, 0x45, 0x1b, 0xaf, 0x35, 0x08, 0x4a, 0xdc, 0xf6, 0xfe, 0x9c, 0x52, 0x4c, 0x22, 0x45, 0x4d, 0xeb};
uint32_t MSG_2_LEN = sizeof(MSG_2);

uint8_t MSG_3[] = {0x08, 0x52, 0x53, 0xc3, 0x99, 0x19, 0x99, 0xa5, 0xff, 0xb8, 0x69, 0x21, 0xe9, 0x9b, 0x60, 0x7c, 0x06, 0x77, 0x70, 0xe0};
uint32_t MSG_3_LEN = sizeof(MSG_3);
#endif




/*

Test 4

ID_CRED_R and ID_CRED_I contain a x5chain single cerificate.
The certificates contains authentication public key


Their is no reference for this test

The result which we achieve:
PRK_4x3m(size 32)
EC 62 92 A0 67 F1 37 FC 7F 59 62 9D 22 6F BF C4 
	E0 68 89 49 F6 62 A9 7F D8 2F BE B7 99 71 39 4A 
th4(size 32)
B6 72 FF 74 8A 1D EE 56 23 EA 66 3A 0A 61 97 C7 
	5A 3F 97 C8 FF 8B 8F 4A 48 92 3E 1D FB 07 65 38 
info (size 58):
	84 0A 58 20 B6 72 FF 74 8A 1D EE 56 23 EA 66 3A 
	0A 61 97 C7 5A 3F 97 C8 FF 8B 8F 4A 48 92 3E 1D 
	FB 07 65 38 74 4F 53 43 4F 52 45 20 4D 61 73 74 
	65 72 20 53 65 63 72 65 74 10 
OSCORE Master Secret(size 16)
8D A2 2A E3 4B F5 FA 20 72 87 DA 24 C5 B1 FA 83 
info (size 56):
	84 0A 58 20 B6 72 FF 74 8A 1D EE 56 23 EA 66 3A 
	0A 61 97 C7 5A 3F 97 C8 FF 8B 8F 4A 48 92 3E 1D 
	FB 07 65 38 72 4F 53 43 4F 52 45 20 4D 61 73 74 
	65 72 20 73 61 6C 74 08 
OSCORE Master salt(size 8)
8F 1B 19 86 03 FA 01 78 

*/

#ifdef INITIATOR_TEST_4

enum method_type METHOD_TYPE = INITIATOR_SK_RESPONDER_SK;
uint8_t CORR = 1;

uint8_t SUITES_I[] = {0};
uint32_t SUITES_I_LEN = sizeof(SUITES_I);

uint8_t G_X[] = {0x89, 0x8f, 0xf7, 0x9a, 0x02, 0x06, 0x7a, 0x16, 0xea, 0x1e, 0xcc, 0xb9, 0x0f, 0xa5, 0x22, 0x46, 0xf5, 0xaa, 0x4d, 0xd6, 0xec, 0x07, 0x6b, 0xba, 0x02, 0x59, 0xd9, 0x04, 0xb7, 0xec, 0x8b, 0x0c};
uint32_t G_X_LEN = sizeof(G_X);

uint8_t X[] = {0x8f, 0x78, 0x1a, 0x09, 0x53, 0x72, 0xf8, 0x5b, 0x6d, 0x9f, 0x61, 0x09, 0xae, 0x42, 0x26, 0x11, 0x73, 0x4d, 0x7d, 0xbf, 0xa0, 0x06, 0x9a, 0x2d, 0xf2, 0x93, 0x5b, 0xb2, 0xe0, 0x53, 0xbf, 0x35};
uint32_t X_LEN = sizeof(X);

uint8_t* C_I = NULL;
uint32_t C_I_LEN = 0;

uint8_t* AD_1 = NULL;
uint32_t AD_1_LEN = 0;

uint8_t* AD_3 = NULL;
uint32_t AD_3_LEN = 0;



uint8_t ID_CRED_I[] = {0xa1, 0x18, 0x21, 0x58, 0x87, 0x00, 0x43, 0x12, 0x82, 0x69, 0x6b, 0x52, 0x46, 0x43, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x43, 0x41, 0x1a, 0x5e, 0x0b, 0xe1, 0x00, 0x1a, 0x60, 0x18, 0x96, 0x00, 0x46, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x58, 0x20, 0x38, 0xe5, 0xd5, 0x45, 0x63, 0xc2, 0xb6, 0xa4, 0xba, 0x26, 0xf3, 0x01, 0x5f, 0x61, 0xbb, 0x70, 0x6e, 0x5c, 0x2e, 0xfd, 0xb5, 0x56, 0xd2, 0xe1, 0x69, 0x0b, 0x97, 0xfc, 0x3c, 0x6d, 0xe1, 0x49, 0x05, 0x58, 0x40, 0xab, 0x33, 0xe1, 0xc4, 0xcb, 0xcc, 0x6c, 0x5b, 0xcc, 0xcb, 0x8e, 0x93, 0x9b, 0x22, 0xe4, 0xd7, 0x16, 0xec, 0x1a, 0x53, 0x68, 0x88, 0x9e, 0xfd, 0x31, 0xa7, 0xd3, 0x43, 0x2d, 0x57, 0x8d, 0x88, 0xef, 0x83, 0x55, 0x5c, 0x7f, 0x3f, 0x4f, 0xb3, 0x24, 0x82, 0x82, 0x2f, 0x60, 0xa3, 0x98, 0x4f, 0xdc, 0x23, 0xc7, 0x23, 0x7c, 0x94, 0xee, 0x78, 0x86, 0x92, 0xf0, 0x1d, 0x15, 0xa9, 0xf1, 0x06}; /* the certificate encoded as ID_CRED_I = {33 : COSE_X509 }*/

uint32_t ID_CRED_I_LEN = sizeof(ID_CRED_I);

uint8_t CRED_I[] = {0x00, 0x43, 0x12, 0x82, 0x69, 0x6b, 0x52, 0x46, 0x43, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x43, 0x41, 0x1a, 0x5e, 0x0b, 0xe1, 0x00, 0x1a, 0x60, 0x18, 0x96, 0x00, 0x46, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x58, 0x20, 0x38, 0xe5, 0xd5, 0x45, 0x63, 0xc2, 0xb6, 0xa4, 0xba, 0x26, 0xf3, 0x01, 0x5f, 0x61, 0xbb, 0x70, 0x6e, 0x5c, 0x2e, 0xfd, 0xb5, 0x56, 0xd2, 0xe1, 0x69, 0x0b, 0x97, 0xfc, 0x3c, 0x6d, 0xe1, 0x49, 0x05, 0x58, 0x40, 0xab, 0x33, 0xe1, 0xc4, 0xcb, 0xcc, 0x6c, 0x5b, 0xcc, 0xcb, 0x8e, 0x93, 0x9b, 0x22, 0xe4, 0xd7, 0x16, 0xec, 0x1a, 0x53, 0x68, 0x88, 0x9e, 0xfd, 0x31, 0xa7, 0xd3, 0x43, 0x2d, 0x57, 0x8d, 0x88, 0xef, 0x83, 0x55, 0x5c, 0x7f, 0x3f, 0x4f, 0xb3, 0x24, 0x82, 0x82, 0x2f, 0x60, 0xa3, 0x98, 0x4f, 0xdc, 0x23, 0xc7, 0x23, 0x7c, 0x94, 0xee, 0x78, 0x86, 0x92, 0xf0, 0x1d, 0x15, 0xa9, 0xf1, 0x06}; /*the cbor certificate*/

uint32_t CRED_I_LEN = sizeof(CRED_I);

uint8_t* I = NULL;
uint32_t I_LEN = 0;

uint8_t* G_I = NULL;
uint32_t G_I_LEN = 0;

uint8_t SK_I[] = {0x2f, 0xfc, 0xe7, 0xa0, 0xb2, 0xb8, 0x25, 0xd3, 0x97, 0xd0, 0xcb, 0x54, 0xf7, 0x46, 0xe3, 0xda, 0x3f, 0x27, 0x59, 0x6e, 0xe0, 0x6b, 0x53, 0x71, 0x48, 0x1d, 0xc0, 0xe0, 0x12, 0xbc, 0x34, 0xd7};
uint32_t SK_I_LEN = sizeof(SK_I);

uint8_t PK_I[] = {0x38, 0xe5, 0xd5, 0x45, 0x63, 0xc2, 0xb6, 0xa4, 0xba, 0x26, 0xf3, 0x01, 0x5f, 0x61, 0xbb, 0x70, 0x6e, 0x5c, 0x2e, 0xfd, 0xb5, 0x56, 0xd2, 0xe1, 0x69, 0x0b, 0x97, 0xfc, 0x3c, 0x6d, 0xe1, 0x49};
uint32_t PK_I_LEN = sizeof(PK_I);

/*other party credentials*/
uint8_t* ID_CRED_R = NULL;
uint32_t ID_CRED_R_LEN = 0;

uint8_t* CRED_R = NULL;
uint32_t CRED_R_LEN = 0;

uint8_t* PK_R = NULL;
uint8_t PK_R_LEN = 0;

uint8_t G_R[] = {};
uint8_t G_R_LEN = sizeof(G_R);

uint8_t CA[] = {"RFC test CA"};
uint8_t CA_LEN = sizeof(CA);

uint8_t CA_PK[] = {0xdb, 0xd9, 0xdc, 0x8c, 0xd0, 0x3f, 0xb7, 0xc3, 0x91, 0x35, 0x11, 0x46, 0x2b, 0xb2, 0x38, 0x16, 0x47, 0x7c, 0x6b, 0xd8, 0xd6, 0x6e, 0xf5, 0xa1, 0xa0, 0x70, 0xac, 0x85, 0x4e, 0xd7, 0x3f, 0xd2};
uint8_t CA_PK_LEN = sizeof(CA_PK);
#endif

#ifdef RESPONDER_TEST_4
uint8_t SUITES_R[] = {0};
uint32_t SUITES_R_LEN = sizeof(SUITES_R);

uint8_t G_Y[] = {0x71, 0xa3, 0xd5, 0x99, 0xc2, 0x1d, 0xa1, 0x89, 0x02, 0xa1, 0xae, 0xa8, 0x10, 0xb2, 0xb6, 0x38, 0x2c, 0xcd, 0x8d, 0x5f, 0x9b, 0xf0, 0x19, 0x52, 0x81, 0x75, 0x4c, 0x5e, 0xbc, 0xaf, 0x30, 0x1e};
uint32_t G_Y_LEN = sizeof(G_Y);

uint8_t Y[] = {0xfd, 0x8c, 0xd8, 0x77, 0xc9, 0xea, 0x38, 0x6e, 0x6a, 0xf3, 0x4f, 0xf7, 0xe6, 0x06, 0xc4, 0xb6, 0x4c, 0xa8, 0x31, 0xc8, 0xba, 0x33, 0x13, 0x4f, 0xd4, 0xcd, 0x71, 0x67, 0xca, 0xba, 0xec, 0xda};
uint32_t Y_LEN = sizeof(Y);

uint8_t C_R[] = {0x2b};
uint32_t C_R_LEN = sizeof(C_R);

uint8_t ID_CRED_R[] = {0xa1, 0x18, 0x21, 0x58, 0x87, 0x00, 0x43, 0x12, 0x82, 0x69, 0x6b, 0x52, 0x46, 0x43, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x43, 0x41, 0x1a, 0x5e, 0x0b, 0xe1, 0x00, 0x1a, 0x60, 0x18, 0x96, 0x00, 0x46, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x58, 0x20, 0xdb, 0xd9, 0xdc, 0x8c, 0xd0, 0x3f, 0xb7, 0xc3, 0x91, 0x35, 0x11, 0x46, 0x2b, 0xb2, 0x38, 0x16, 0x47, 0x7c, 0x6b, 0xd8, 0xd6, 0x6e, 0xf5, 0xa1, 0xa0, 0x70, 0xac, 0x85, 0x4e, 0xd7, 0x3f, 0xd2, 0x05, 0x58, 0x40, 0x63, 0x94, 0xb6, 0x42, 0xc6, 0xa5, 0x1d, 0x82, 0xce, 0x31, 0xf3, 0x9a, 0x38, 0x75, 0xae, 0x46, 0x6e, 0x4e, 0xcb, 0xd6, 0x78, 0x4d, 0x17, 0xeb, 0xb2, 0x52, 0x84, 0x14, 0xe7, 0xd0, 0xa3, 0x51, 0x65, 0xc9, 0x05, 0x56, 0x95, 0xf3, 0x68, 0x11, 0x8a, 0x8e, 0x0e, 0x64, 0xb8, 0xad, 0x59, 0x5a, 0x98, 0xe8, 0x40, 0x4f, 0x36, 0xed, 0x03, 0xe9, 0x65, 0x5c, 0xbd, 0xd1, 0x1e, 0xc2, 0xb7, 0x08};
uint32_t ID_CRED_R_LEN = sizeof(ID_CRED_R);

uint8_t CRED_R[] = {0x00, 0x43, 0x12, 0x82, 0x69, 0x6b, 0x52, 0x46, 0x43, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x43, 0x41, 0x1a, 0x5e, 0x0b, 0xe1, 0x00, 0x1a, 0x60, 0x18, 0x96, 0x00, 0x46, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x58, 0x20, 0xdb, 0xd9, 0xdc, 0x8c, 0xd0, 0x3f, 0xb7, 0xc3, 0x91, 0x35, 0x11, 0x46, 0x2b, 0xb2, 0x38, 0x16, 0x47, 0x7c, 0x6b, 0xd8, 0xd6, 0x6e, 0xf5, 0xa1, 0xa0, 0x70, 0xac, 0x85, 0x4e, 0xd7, 0x3f, 0xd2, 0x05, 0x58, 0x40, 0x63, 0x94, 0xb6, 0x42, 0xc6, 0xa5, 0x1d, 0x82, 0xce, 0x31, 0xf3, 0x9a, 0x38, 0x75, 0xae, 0x46, 0x6e, 0x4e, 0xcb, 0xd6, 0x78, 0x4d, 0x17, 0xeb, 0xb2, 0x52, 0x84, 0x14, 0xe7, 0xd0, 0xa3, 0x51, 0x65, 0xc9, 0x05, 0x56, 0x95, 0xf3, 0x68, 0x11, 0x8a, 0x8e, 0x0e, 0x64, 0xb8, 0xad, 0x59, 0x5a, 0x98, 0xe8, 0x40, 0x4f, 0x36, 0xed, 0x03, 0xe9, 0x65, 0x5c, 0xbd, 0xd1, 0x1e, 0xc2, 0xb7, 0x08};
uint32_t CRED_R_LEN = sizeof(CRED_R);

uint8_t* AD_2;
uint32_t AD_2_LEN = 0;

uint8_t SK_R[] = {0xdf, 0x69, 0x27, 0x4d, 0x71, 0x32, 0x96, 0xe2, 0x46, 0x30, 0x63, 0x65, 0x37, 0x2b, 0x46, 0x83, 0xce, 0xd5, 0x38, 0x1b, 0xfc, 0xad, 0xcd, 0x44, 0x0a, 0x24, 0xc3, 0x91, 0xd2, 0xfe, 0xdb, 0x94};
uint8_t SK_R_LEN = sizeof(SK_R);

uint8_t PK_R[32] = {0xdb, 0xd9, 0xdc, 0x8c, 0xd0, 0x3f, 0xb7, 0xc3, 0x91, 0x35, 0x11, 0x46, 0x2b, 0xb2, 0x38, 0x16, 0x47, 0x7c, 0x6b, 0xd8, 0xd6, 0x6e, 0xf5, 0xa1, 0xa0, 0x70, 0xac, 0x85, 0x4e, 0xd7, 0x3f, 0xd2};
uint8_t PK_R_LEN = sizeof(PK_R);

uint8_t* G_R;
uint32_t G_R_LEN = 0;

uint8_t* R;
uint32_t R_LEN = 0;



/*other party credentials*/
uint8_t ID_CRED_I[] = {};
uint32_t ID_CRED_I_LEN = sizeof(ID_CRED_I);

uint8_t CRED_I[] = {};
uint32_t CRED_I_LEN = sizeof(CRED_I);

uint8_t PK_I[] = {};
uint8_t PK_I_LEN = sizeof(PK_I);

uint8_t* G_I = NULL;
uint32_t G_I_LEN = 0;

uint8_t CA[] = {"RFC test CA"};
uint8_t CA_LEN = sizeof(CA);

uint8_t CA_PK[] = {0xdb, 0xd9, 0xdc, 0x8c, 0xd0, 0x3f, 0xb7, 0xc3, 0x91, 0x35, 0x11, 0x46, 0x2b, 0xb2, 0x38, 0x16, 0x47, 0x7c, 0x6b, 0xd8, 0xd6, 0x6e, 0xf5, 0xa1, 0xa0, 0x70, 0xac, 0x85, 0x4e, 0xd7, 0x3f, 0xd2};
uint8_t CA_PK_LEN = sizeof(CA_PK);

#endif

#if (defined INITIATOR_TEST_4) || (defined RESPONDER_TEST_4)
uint8_t MSG_1[] = {0x01, 0x00, 0x58, 0x20, 0x89, 0x8f, 0xf7, 0x9a, 0x02, 0x06, 0x7a, 0x16, 0xea, 0x1e, 0xcc, 0xb9, 0x0f, 0xa5, 0x22, 0x46, 0xf5, 0xaa, 0x4d, 0xd6, 0xec, 0x07, 0x6b, 0xba, 0x02, 0x59, 0xd9, 0x04, 0xb7, 0xec, 0x8b, 0x0c, 0x40};
uint32_t MSG_1_LEN = sizeof(MSG_1);

uint8_t MSG_2[] = {0x58, 0x20, 0x71, 0xA3, 0xD5, 0x99, 0xC2, 0x1D, 0xA1, 0x89, 0x02, 0xA1, 0xAE, 0xA8, 0x10, 0xB2, 0xB6, 0x38, 0x2C, 0xCD, 0x8D, 0x5F, 0x9B, 0xF0, 0x19, 0x52, 0x81, 0x75, 0x4C, 0x5E, 0xBC, 0xAF, 0x30, 0x1E, 0x13, 0x58, 0xCE, 0x55, 0xFD, 0x49, 0x11, 0xD6, 0x0E, 0xF2, 0x1F, 0x4C, 0xD2, 0xB4, 0x56, 0x8E, 0x9B, 0x68, 0x74, 0xD8, 0x41, 0x4E, 0x9B, 0x8C, 0x18, 0x47, 0x1C, 0x1C, 0x09, 0x07, 0xAA, 0x09, 0x2F, 0xDA, 0x80, 0x6D, 0x06, 0xE5, 0x73, 0x25, 0xF8, 0x9C, 0x52, 0x4D, 0xBE, 0xBE, 0x32, 0xF2, 0xB8, 0xD0, 0xAC, 0x32, 0xDF, 0xBB, 0xEA, 0xA1, 0xAD, 0xC2, 0x2A, 0xB1, 0x14, 0xE0, 0xC0, 0x46, 0x98, 0xEC, 0x6B, 0x78, 0x0F, 0xD6, 0x32, 0x2B, 0x1E, 0xC1, 0xD8, 0xD8, 0x28, 0xB5, 0x90, 0x62, 0xB7, 0x80, 0x3A, 0xC9, 0xE4, 0xC8, 0xC8, 0x2A, 0x65, 0x44, 0xC0, 0x51, 0xF2, 0xA4, 0x61, 0x63, 0xB7, 0xC2, 0x49, 0x4C, 0x1A, 0x26, 0xB3, 0xC4, 0x65, 0xFB, 0xEB, 0x55, 0x8D, 0x70, 0xCA, 0x5D, 0x2B, 0xD8, 0x4B, 0x10, 0x41, 0xFB, 0xBB, 0x28, 0xE3, 0x3B, 0x7D, 0xE7, 0xE9, 0x22, 0xDA, 0x34, 0xAF, 0x3D, 0x49, 0x98, 0x39, 0xF0, 0xF4, 0x41, 0xE2, 0xEE, 0xB4, 0xD8, 0xE6, 0x21, 0x85, 0x55, 0x21, 0xF2, 0x14, 0x6F, 0xE1, 0x17, 0x1E, 0x32, 0x92, 0x60, 0x50, 0xA5, 0xD8, 0x61, 0xE6, 0xFA, 0xF7, 0xB4, 0x1C, 0x5C, 0x46, 0x99, 0xD2, 0x1B, 0xEF, 0x08, 0x1B, 0x83, 0x18, 0xE2, 0xA5, 0x9B, 0x77, 0x0A, 0x1C, 0xF9, 0xD0, 0x34, 0x5A, 0xC5, 0xDB, 0x0A, 0xC9, 0x00, 0xE0, 0x51, 0x16, 0xDB, 0xFF, 0xC9, 0x8D, 0x32, 0x9F, 0xBE, 0x8F, 0x71, 0x08, 0xE0, 0x66, 0x98, 0xEC, 0x58, 0x03, 0x00, 0xDC};
uint32_t MSG_2_LEN = sizeof(MSG_2);

uint8_t MSG_3[] = {0x13, 0x58, 0xD6, 0x98, 0xCB, 0x63, 0x18, 0xAD, 0x28, 0x6E, 0x45, 0x18, 0xD0, 0x08, 0x41, 0x9A, 0xFC, 0x1B, 0xFE, 0xC2, 0x27, 0x57, 0x33, 0xCC, 0x14, 0x12, 0x0D, 0xDE, 0xC7, 0x87, 0x3B, 0xFF, 0xF2, 0x72, 0x77, 0xA4, 0x2C, 0x0E, 0x7A, 0x44, 0x24, 0x3A, 0xC8, 0x6D, 0x57, 0x7D, 0x24, 0xBD, 0xB6, 0xA4, 0x72, 0x2D, 0x70, 0x38, 0xC2, 0xDC, 0xEE, 0x36, 0x1C, 0xC2, 0xBA, 0x7B, 0x58, 0x08, 0x61, 0xF6, 0x94, 0x57, 0xF0, 0x6E, 0xAA, 0x4F, 0x8E, 0x50, 0x31, 0xFE, 0x97, 0x09, 0x64, 0x5F, 0x46, 0x80, 0xC5, 0x21, 0x86, 0xDB, 0x68, 0x43, 0x84, 0x9C, 0x1C, 0xEF, 0xB9, 0x55, 0xF5, 0xE4, 0x5C, 0xEE, 0xF8, 0x63, 0xDF, 0x36, 0xDA, 0xE7, 0x9A, 0x2E, 0x6A, 0xC1, 0x10, 0x7E, 0xB2, 0xC1, 0xC8, 0x18, 0x04, 0xE1, 0x87, 0x38, 0x4F, 0xB4, 0x68, 0x57, 0x14, 0xA1, 0x0A, 0x53, 0x89, 0xDA, 0x1E, 0x5F, 0x4B, 0xE4, 0x32, 0xC7, 0xDE, 0xB5, 0xA0, 0x56, 0x85, 0x08, 0x54, 0xA6, 0xAE, 0x69, 0x3A, 0xCE, 0x16, 0x57, 0xA2, 0x13, 0x11, 0x2E, 0xC3, 0x01, 0x71, 0x79, 0xF5, 0x0C, 0xA7, 0x9F, 0xF4, 0xAC, 0x09, 0x33, 0x3E, 0x30, 0x42, 0x77, 0x4E, 0x07, 0x57, 0x18, 0xB7, 0x69, 0x91, 0xD7, 0xCE, 0x9A, 0x73, 0x07, 0x99, 0xD4, 0x07, 0xA8, 0x8E, 0x70, 0x5E, 0xB4, 0x90, 0x6C, 0x7D, 0xDC, 0x0D, 0x74, 0xB1, 0xB7, 0x16, 0xE5, 0x0E, 0x0D, 0xCF, 0xA8, 0x19, 0xA0, 0x6C, 0xA0, 0xF4, 0x96, 0xCB, 0x8F, 0xC4, 0xE5, 0x7F, 0xC0, 0x8F, 0x49, 0x29};
uint32_t MSG_3_LEN = sizeof(MSG_3);
#endif

/*


Test 5

ID_CRED_R and ID_CRED_I contain a x5chain single cerificate.
The certificates contain static public DH key


Their is no reference for this test

The result which we achieve:
PRK_4x3m(size 32)
02 56 2F 1F 01 78 5C 0A A5 F5 94 64 0C 49 CB F6 
        9F 72 2E 9E 6C 57 83 7D 8E 15 79 EC 45 FE 64 7A 
th4(size 32)
18 05 3D 1D E0 03 3A 06 71 7C 99 96 7B 0A EC EC 
        04 E8 4E 83 2A 8F B9 51 BD 67 22 46 43 C4 2B A8 
info (size 58):
        84 0A 58 20 18 05 3D 1D E0 03 3A 06 71 7C 99 96 
        7B 0A EC EC 04 E8 4E 83 2A 8F B9 51 BD 67 22 46 
        43 C4 2B A8 74 4F 53 43 4F 52 45 20 4D 61 73 74 
        65 72 20 53 65 63 72 65 74 10 
OSCORE Master Secret(size 16)
76 FE B5 D6 35 47 53 CC E7 B4 56 99 E6 33 87 CF 
info (size 56):
        84 0A 58 20 18 05 3D 1D E0 03 3A 06 71 7C 99 96 
        7B 0A EC EC 04 E8 4E 83 2A 8F B9 51 BD 67 22 46 
        43 C4 2B A8 72 4F 53 43 4F 52 45 20 4D 61 73 74 
        65 72 20 73 61 6C 74 08 
OSCORE Master salt(size 8)
1F 8C A1 A1 1E FE 1C 86 

*/

#ifdef INITIATOR_TEST_5

enum method_type METHOD_TYPE = INITIATOR_SDHK_RESPONDER_SDHK;
uint8_t CORR = 1;

uint8_t SUITES_I[] = {0};
uint32_t SUITES_I_LEN = sizeof(SUITES_I);

uint8_t G_X[] = {0x8d, 0x3e, 0xf5, 0x6d, 0x1b, 0x75, 0x0a, 0x43, 0x51, 0xd6, 0x8a, 0xc2, 0x50, 0xa0, 0xe8, 0x83, 0x79, 0x0e, 0xfc, 0x80, 0xa5, 0x38, 0xa4, 0x44, 0xee, 0x9e, 0x2b, 0x57, 0xe2, 0x44, 0x1a, 0x7c};
uint32_t G_X_LEN = sizeof(G_X);

uint8_t X[] = {0xae, 0x11, 0xa0, 0xdb, 0x86, 0x3c, 0x02, 0x27, 0xe5, 0x39, 0x92, 0xfe, 0xb8, 0xf5, 0x92, 0x4c, 0x50, 0xd0, 0xa7, 0xba, 0x6e, 0xea, 0xb4, 0xad, 0x1f, 0xf2, 0x45, 0x72, 0xf4, 0xf5, 0x7c, 0xfa};
uint32_t X_LEN = sizeof(X);

uint8_t* C_I = NULL;
uint32_t C_I_LEN = 0;

uint8_t* AD_1 = NULL;
uint32_t AD_1_LEN = 0;

uint8_t* AD_3 = NULL;
uint32_t AD_3_LEN = 0;



uint8_t ID_CRED_I[] = {0xa1, 0x18, 0x21, 0x58, 0x87, 0x00, 0x43, 0x12, 0x82, 0x69, 0x6b, 0x52, 0x46, 0x43, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x43, 0x41, 0x1a, 0x5e, 0x0b, 0xe1, 0x00, 0x1a, 0x60, 0x18, 0x96, 0x00, 0x46, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x58, 0x20, 0x2c, 0x44, 0x0c, 0xc1, 0x21, 0xf8, 0xd7, 0xf2, 0x4c, 0x3b, 0x0e, 0x41, 0xae, 0xda, 0xfe, 0x9c, 0xaa, 0x4f, 0x4e, 0x7a, 0xbb, 0x83, 0x5e, 0xc3, 0x0f, 0x1d, 0xe8, 0x8a, 0xdb, 0x96, 0xff, 0x71, 0x05, 0x58, 0x40, 0xc2, 0xc2, 0xcd, 0x6d, 0x28, 0x52, 0x7f, 0x80, 0xd6, 0xe5, 0x5a, 0xcd, 0x1a, 0x9e, 0xca, 0x43, 0x77, 0xd8, 0x6b, 0x52, 0x23, 0xf7, 0xe2, 0x5e, 0xbb, 0x49, 0xb3, 0xef, 0xd4, 0x9c, 0x55, 0xb1, 0x71, 0x92, 0xd2, 0x5d, 0x89, 0xe7, 0xd9, 0xbc, 0x0b, 0x49, 0x9f, 0xcc, 0xe5, 0x46, 0x74, 0xcf, 0x88, 0x90, 0xc0, 0xfc, 0x25, 0x45, 0x1b, 0x55, 0x73, 0xc5, 0xbd, 0xa2, 0x0e, 0x0d, 0x2f, 0x0f}; /* the certificate encoded as ID_CRED_I = {33 : COSE_X509 }*/

uint32_t ID_CRED_I_LEN = sizeof(ID_CRED_I);

uint8_t CRED_I[] = {0x00, 0x43, 0x12, 0x82, 0x69, 0x6b, 0x52, 0x46, 0x43, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x43, 0x41, 0x1a, 0x5e, 0x0b, 0xe1, 0x00, 0x1a, 0x60, 0x18, 0x96, 0x00, 0x46, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x58, 0x20, 0x2c, 0x44, 0x0c, 0xc1, 0x21, 0xf8, 0xd7, 0xf2, 0x4c, 0x3b, 0x0e, 0x41, 0xae, 0xda, 0xfe, 0x9c, 0xaa, 0x4f, 0x4e, 0x7a, 0xbb, 0x83, 0x5e, 0xc3, 0x0f, 0x1d, 0xe8, 0x8a, 0xdb, 0x96, 0xff, 0x71, 0x05, 0x58, 0x40, 0xc2, 0xc2, 0xcd, 0x6d, 0x28, 0x52, 0x7f, 0x80, 0xd6, 0xe5, 0x5a, 0xcd, 0x1a, 0x9e, 0xca, 0x43, 0x77, 0xd8, 0x6b, 0x52, 0x23, 0xf7, 0xe2, 0x5e, 0xbb, 0x49, 0xb3, 0xef, 0xd4, 0x9c, 0x55, 0xb1, 0x71, 0x92, 0xd2, 0x5d, 0x89, 0xe7, 0xd9, 0xbc, 0x0b, 0x49, 0x9f, 0xcc, 0xe5, 0x46, 0x74, 0xcf, 0x88, 0x90, 0xc0, 0xfc, 0x25, 0x45, 0x1b, 0x55, 0x73, 0xc5, 0xbd, 0xa2, 0x0e, 0x0d, 0x2f, 0x0f}; /*the cbor certificate*/

uint32_t CRED_I_LEN = sizeof(CRED_I);

uint8_t I[] = {0x2b, 0xbe, 0xa6, 0x55, 0xc2, 0x33, 0x71, 0xc3, 0x29, 0xcf, 0xbd, 0x3b, 0x1f, 0x02, 0xc6, 0xc0, 0x62, 0x03, 0x38, 0x37, 0xb8, 0xb5, 0x90, 0x99, 0xa4, 0x43, 0x6f, 0x66, 0x60, 0x81, 0xb0, 0x8e};
uint32_t I_LEN = sizeof(I);

uint8_t G_I[] = {0x2c, 0x44, 0x0c, 0xc1, 0x21, 0xf8, 0xd7, 0xf2, 0x4c, 0x3b, 0x0e, 0x41, 0xae, 0xda, 0xfe, 0x9c, 0xaa, 0x4f, 0x4e, 0x7a, 0xbb, 0x83, 0x5e, 0xc3, 0x0f, 0x1d, 0xe8, 0x8a, 0xdb, 0x96, 0xff, 0x71};
uint32_t G_I_LEN = sizeof(G_I);

uint8_t SK_I[] = {};
uint32_t SK_I_LEN = sizeof(SK_I);

uint8_t PK_I[] = {};
uint32_t PK_I_LEN = sizeof(PK_I);

/*other party credentials*/
uint8_t* ID_CRED_R = NULL;
uint32_t ID_CRED_R_LEN = 0;

uint8_t* CRED_R = NULL;
uint32_t CRED_R_LEN = 0;

uint8_t* PK_R = NULL;
uint8_t PK_R_LEN = 0;

uint8_t G_R[] = {};
uint8_t G_R_LEN = sizeof(G_R);

uint8_t CA[] = {"RFC test CA"};
uint8_t CA_LEN = sizeof(CA);

uint8_t CA_PK[] = {0xdb, 0xd9, 0xdc, 0x8c, 0xd0, 0x3f, 0xb7, 0xc3, 0x91, 0x35, 0x11, 0x46, 0x2b, 0xb2, 0x38, 0x16, 0x47, 0x7c, 0x6b, 0xd8, 0xd6, 0x6e, 0xf5, 0xa1, 0xa0, 0x70, 0xac, 0x85, 0x4e, 0xd7, 0x3f, 0xd2};
uint8_t CA_PK_LEN = sizeof(CA_PK);
#endif

#ifdef RESPONDER_TEST_5
uint8_t SUITES_R[] = {0};
uint32_t SUITES_R_LEN = sizeof(SUITES_R);

uint8_t G_Y[] = {0x52, 0xfb, 0xa0, 0xbd, 0xc8, 0xd9, 0x53, 0xdd, 0x86, 0xce, 0x1a, 0xb2, 0xfd, 0x7c, 0x05, 0xa4, 0x65, 0x8c, 0x7c, 0x30, 0xaf, 0xdb, 0xfc, 0x33, 0x01, 0x04, 0x70, 0x69, 0x45, 0x1b, 0xaf, 0x35};
uint32_t G_Y_LEN = sizeof(G_Y);

uint8_t Y[] = {0xc6, 0x46, 0xcd, 0xdc, 0x58, 0x12, 0x6e, 0x18, 0x10, 0x5f, 0x01, 0xce, 0x35, 0x05, 0x6e, 0x5e, 0xbc, 0x35, 0xf4, 0xd4, 0xcc, 0x51, 0x07, 0x49, 0xa3, 0xa5, 0xe0, 0x69, 0xc1, 0x16, 0x16, 0x9a};
uint32_t Y_LEN = sizeof(Y);

uint8_t C_R[] = {0x2b};
uint32_t C_R_LEN = sizeof(C_R);

uint8_t ID_CRED_R[] = {0xa1, 0x18, 0x21, 0x58, 0x87, 0x00, 0x43, 0x12, 0x82, 0x69, 0x6b, 0x52, 0x46, 0x43, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x43, 0x41, 0x1a, 0x5e, 0x0b, 0xe1, 0x00, 0x1a, 0x60, 0x18, 0x96, 0x00, 0x46, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x58, 0x20, 0xa3, 0xff, 0x26, 0x35, 0x95, 0xbe, 0xb3, 0x77, 0xd1, 0xa0, 0xce, 0x1d, 0x04, 0xda, 0xd2, 0xd4, 0x09, 0x66, 0xac, 0x6b, 0xcb, 0x62, 0x20, 0x51, 0xb8, 0x46, 0x59, 0x18, 0x4d, 0x5d, 0x9a, 0x32, 0x05, 0x58, 0x40, 0xf4, 0xf3, 0xbe, 0xf5, 0x7a, 0x0f, 0x95, 0x2a, 0xa4, 0xfe, 0x92, 0x49, 0x7a, 0xe9, 0xeb, 0x99, 0xce, 0xcb, 0x3f, 0xde, 0x16, 0xf3, 0x48, 0x40, 0x12, 0x6f, 0x56, 0x17, 0xe1, 0xe5, 0xa8, 0x39, 0x6c, 0xe5, 0xbb, 0xcf, 0xb4, 0xe9, 0xd1, 0x85, 0x8b, 0x1a, 0x5d, 0x98, 0xf4, 0xeb, 0xa8, 0x23, 0x4b, 0x19, 0x40, 0x1a, 0x88, 0xbb, 0xe8, 0xe3, 0xf7, 0x00, 0xb7, 0x77, 0x1d, 0x6e, 0xf2, 0x00};
uint32_t ID_CRED_R_LEN = sizeof(ID_CRED_R);

uint8_t CRED_R[] = {0x00, 0x43, 0x12, 0x82, 0x69, 0x6b, 0x52, 0x46, 0x43, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x43, 0x41, 0x1a, 0x5e, 0x0b, 0xe1, 0x00, 0x1a, 0x60, 0x18, 0x96, 0x00, 0x46, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x58, 0x20, 0xa3, 0xff, 0x26, 0x35, 0x95, 0xbe, 0xb3, 0x77, 0xd1, 0xa0, 0xce, 0x1d, 0x04, 0xda, 0xd2, 0xd4, 0x09, 0x66, 0xac, 0x6b, 0xcb, 0x62, 0x20, 0x51, 0xb8, 0x46, 0x59, 0x18, 0x4d, 0x5d, 0x9a, 0x32, 0x05, 0x58, 0x40, 0xf4, 0xf3, 0xbe, 0xf5, 0x7a, 0x0f, 0x95, 0x2a, 0xa4, 0xfe, 0x92, 0x49, 0x7a, 0xe9, 0xeb, 0x99, 0xce, 0xcb, 0x3f, 0xde, 0x16, 0xf3, 0x48, 0x40, 0x12, 0x6f, 0x56, 0x17, 0xe1, 0xe5, 0xa8, 0x39, 0x6c, 0xe5, 0xbb, 0xcf, 0xb4, 0xe9, 0xd1, 0x85, 0x8b, 0x1a, 0x5d, 0x98, 0xf4, 0xeb, 0xa8, 0x23, 0x4b, 0x19, 0x40, 0x1a, 0x88, 0xbb, 0xe8, 0xe3, 0xf7, 0x00, 0xb7, 0x77, 0x1d, 0x6e, 0xf2, 0x00};
uint32_t CRED_R_LEN = sizeof(CRED_R);

uint8_t* AD_2;
uint32_t AD_2_LEN = 0;

uint8_t SK_R[] = {};
uint8_t SK_R_LEN = sizeof(SK_R);

uint8_t PK_R[32] = {};
uint8_t PK_R_LEN = sizeof(PK_R);

uint8_t R[] = {0xbb, 0x50, 0x1a, 0xac, 0x67, 0xb9, 0xa9, 0x5f, 0x97, 0xe0, 0xed, 0xed, 0x6b, 0x82, 0xa6, 0x62, 0x93, 0x4f, 0xbb, 0xfc, 0x7a, 0xd1, 0xb7, 0x4c, 0x1f, 0xca, 0xd6, 0x6a, 0x07, 0x94, 0x22, 0xd0};
uint8_t R_LEN = sizeof(R);

uint8_t G_R[] = {0xa3, 0xff, 0x26, 0x35, 0x95, 0xbe, 0xb3, 0x77, 0xd1, 0xa0, 0xce, 0x1d, 0x04, 0xda, 0xd2, 0xd4, 0x09, 0x66, 0xac, 0x6b, 0xcb, 0x62, 0x20, 0x51, 0xb8, 0x46, 0x59, 0x18, 0x4d, 0x5d, 0x9a, 0x32};
uint8_t G_R_LEN = sizeof(G_R);



/*other party credentials*/
uint8_t ID_CRED_I[] = {};
uint32_t ID_CRED_I_LEN = sizeof(ID_CRED_I);

uint8_t CRED_I[] = {};
uint32_t CRED_I_LEN = sizeof(CRED_I);

uint8_t PK_I[] = {};
uint8_t PK_I_LEN = sizeof(PK_I);

uint8_t* G_I = NULL;
uint32_t G_I_LEN = 0;

uint8_t CA[] = {"RFC test CA"};
uint8_t CA_LEN = sizeof(CA);

uint8_t CA_PK[] = {0xdb, 0xd9, 0xdc, 0x8c, 0xd0, 0x3f, 0xb7, 0xc3, 0x91, 0x35, 0x11, 0x46, 0x2b, 0xb2, 0x38, 0x16, 0x47, 0x7c, 0x6b, 0xd8, 0xd6, 0x6e, 0xf5, 0xa1, 0xa0, 0x70, 0xac, 0x85, 0x4e, 0xd7, 0x3f, 0xd2};
uint8_t CA_PK_LEN = sizeof(CA_PK);

#endif

#if (defined INITIATOR_TEST_5) || (defined RESPONDER_TEST_5)
uint8_t MSG_1[] = {0x0D, 0x00, 0x58, 0x20, 0x8D, 0x3E, 0xF5, 0x6D, 0x1B, 0x75, 0x0A, 0x43, 0x51, 0xD6, 0x8A, 0xC2, 0x50, 0xA0, 0xE8, 0x83, 0x79, 0x0E, 0xFC, 0x80, 0xA5, 0x38, 0xA4, 0x44, 0xEE, 0x9E, 0x2B, 0x57, 0xE2, 0x44, 0x1A, 0x7C, 0x40};
uint32_t MSG_1_LEN = sizeof(MSG_1);

uint8_t MSG_2[] = {0x58, 0x20, 0x52, 0xFB, 0xA0, 0xBD, 0xC8, 0xD9, 0x53, 0xDD, 0x86, 0xCE, 0x1A, 0xB2, 0xFD, 0x7C, 0x05, 0xA4, 0x65, 0x8C, 0x7C, 0x30, 0xAF, 0xDB, 0xFC, 0x33, 0x01, 0x04, 0x70, 0x69, 0x45, 0x1B, 0xAF, 0x35, 0x13, 0x58, 0x95, 0x99, 0xE8, 0xC8, 0x3E, 0x8D, 0x84, 0xCB, 0x63, 0xED, 0x10, 0x87, 0x15, 0xD5, 0xA8, 0xFE, 0xF4, 0x64, 0x2F, 0xE5, 0x0D, 0xAA, 0xD9, 0xDE, 0xD8, 0xC3, 0x7D, 0xB9, 0x87, 0xDC, 0x87, 0x1D, 0xC7, 0x08, 0xB1, 0x0C, 0x27, 0x51, 0x92, 0x44, 0x4F, 0x5F, 0x10, 0x54, 0xE3, 0x17, 0x19, 0xA0, 0x5C, 0x72, 0xBD, 0x07, 0x9C, 0x7A, 0xEB, 0xB3, 0x24, 0xFD, 0xCE, 0x18, 0x4B, 0x5D, 0xA7, 0x50, 0x44, 0xDE, 0x71, 0xDC, 0xFF, 0x46, 0x91, 0x75, 0xBA, 0x91, 0x3B, 0xDA, 0x9B, 0x4C, 0xA0, 0x18, 0x5F, 0x4B, 0x85, 0x1B, 0x8F, 0x6D, 0xCE, 0xD6, 0x42, 0x87, 0xA7, 0x1A, 0xD1, 0xE2, 0x3C, 0x54, 0xEC, 0xC9, 0xBF, 0x8B, 0x50, 0x56, 0xDE, 0xAC, 0x16, 0x33, 0x75, 0xF7, 0xFF, 0xBF, 0x59, 0x08, 0x2D, 0x1D, 0x08, 0x53, 0xD5, 0x00, 0xB7, 0x8D, 0x9B, 0x52, 0xCE, 0x06, 0x79, 0xC6, 0xF3, 0xD2, 0xA2, 0x43, 0xD5, 0x47, 0xCE, 0x6E, 0x1B, 0x7E, 0x66, 0x46, 0x30, 0xB2, 0xD7, 0x2A, 0x13, 0x31, 0xD9, 0xBB, 0x80, 0x5F, 0x4C, 0x26};
uint32_t MSG_2_LEN = sizeof(MSG_2);

uint8_t MSG_3[] = {0x13, 0x58, 0x9D, 0xD3, 0x4F, 0x03, 0x11, 0xB8, 0xF0, 0x88, 0x24, 0x0F, 0x64, 0xCD, 0xCD, 0x86, 0x07, 0x6A, 0xFC, 0x3A, 0xB8, 0xFB, 0xF9, 0x37, 0x30, 0x46, 0x3D, 0x59, 0xE8, 0xBE, 0x01, 0x81, 0x4B, 0xBD, 0x6D, 0xF6, 0x2C, 0x90, 0xB6, 0x10, 0x46, 0xAB, 0x99, 0xE5, 0x3E, 0xB3, 0x30, 0xE0, 0x6A, 0xF3, 0x00, 0x74, 0x89, 0xCF, 0xE4, 0x12, 0x0E, 0xCE, 0x43, 0x39, 0x4B, 0x77, 0xF6, 0x27, 0x4A, 0xF2, 0x3E, 0xE4, 0xBC, 0x6A, 0x56, 0x56, 0x3B, 0x89, 0x75, 0x9F, 0x35, 0x7A, 0x3A, 0x37, 0xAB, 0x2C, 0xD0, 0x2E, 0xEE, 0xC9, 0xBB, 0x0F, 0xC1, 0x89, 0x69, 0x31, 0xB8, 0x9C, 0xF2, 0x30, 0xCC, 0xE5, 0xCC, 0x16, 0xBC, 0x51, 0xB8, 0xFA, 0xD3, 0x96, 0x3C, 0x37, 0x5B, 0x7D, 0xE4, 0xBA, 0x7A, 0xCE, 0x7C, 0x24, 0xB3, 0x7A, 0x63, 0xAD, 0x90, 0x8B, 0x21, 0x22, 0xD6, 0x29, 0x90, 0x63, 0xDB, 0xE2, 0xA4, 0x90, 0x2E, 0x8F, 0x32, 0x99, 0x14, 0x3F, 0x09, 0x12, 0x69, 0x2B, 0x20, 0x4C, 0xD2, 0x54, 0x5C, 0xC5, 0xE1, 0x92, 0x51, 0x0A, 0x21, 0x9A, 0x53, 0x6D, 0xB0, 0x1E, 0x2E, 0x75};
uint32_t MSG_3_LEN = sizeof(MSG_3);
#endif

#endif
