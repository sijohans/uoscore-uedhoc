project(coap-evaluation)
cmake_minimum_required(VERSION 3.10)

macro(add_sanitizer TARGET)
    set_property(TARGET ${TARGET} APPEND_STRING
        PROPERTY COMPILE_FLAGS " -fsanitize=address")
    set_property(TARGET ${TARGET} APPEND_STRING
        PROPERTY LINK_FLAGS " -fsanitize=address")
endmacro()

add_library(oscore
    modules/oscore/src/aad.c
    modules/oscore/src/byte_array.c
    modules/oscore/src/coap2oscore.c
    modules/oscore/src/coap.c
    modules/oscore/src/crypto_wrapper.c
    modules/oscore/src/hkdf_info.c
    modules/oscore/src/memcpy_s.c
    modules/oscore/src/nonce.c
    modules/oscore/src/option.c
    modules/oscore/src/oscore2coap.c
    modules/oscore/src/oscore_cose.c
    modules/oscore/src/print_util.c
    modules/oscore/src/security_context.c)

add_library(cbor
    externals/tinycbor/src/cborencoder.c
    externals/tinycbor/src/cborparser.c
    externals/tinycbor/src/cbor_buf_writer.c)

add_library(tinycrypt
    externals/tinycrypt/lib/source/aes_decrypt.c
    externals/tinycrypt/lib/source/aes_encrypt.c
    externals/tinycrypt/lib/source/cbc_mode.c
    externals/tinycrypt/lib/source/ccm_mode.c
    externals/tinycrypt/lib/source/cmac_mode.c
    externals/tinycrypt/lib/source/ctr_mode.c
    externals/tinycrypt/lib/source/ctr_prng.c
    externals/tinycrypt/lib/source/ecc.c
    externals/tinycrypt/lib/source/ecc_dh.c
    externals/tinycrypt/lib/source/ecc_dsa.c
    externals/tinycrypt/lib/source/ecc_platform_specific.c
    externals/tinycrypt/lib/source/hmac.c
    externals/tinycrypt/lib/source/hmac_prng.c
    externals/tinycrypt/lib/source/sha256.c
    externals/tinycrypt/lib/source/utils.c)

target_compile_options(oscore PRIVATE -Wall -Wextra -Wpedantic -Wshadow -Wcast-qual -std=c99)
include_directories(externals/tinycbor/src
    modules/oscore/inc
    externals/tinycrypt/lib/include)

add_definitions(-DOSCORE_WITH_TINYCRYPT)

add_executable(main main.c)
target_link_libraries(main oscore cbor tinycrypt)

add_sanitizer(main)
add_sanitizer(cbor)
add_sanitizer(tinycrypt)
add_sanitizer(oscore)
