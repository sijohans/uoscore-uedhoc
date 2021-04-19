project(uoscore-uedhoc)
cmake_minimum_required(VERSION 3.10)
enable_language(C)
enable_language(CXX)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
find_package(Sanitizers)
#include(cmake/coverage.cmake)
include(cmake/utils.cmake)

add_library(cbor
    externals/tinycbor/src/cborencoder.c
    externals/tinycbor/src/cborparser.c
    externals/tinycbor/src/cbor_buf_writer.c)
add_sanitizers(cbor)
target_include_directories(cbor PUBLIC externals/tinycbor/src)

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
target_include_directories(tinycrypt PUBLIC externals/tinycrypt/lib/include)
add_sanitizers(tinycrypt)

add_library(compact25519
    externals/compact25519/src/c25519/ed25519.c
    externals/compact25519/src/c25519/edsign.c
    externals/compact25519/src/c25519/sha512.c
    externals/compact25519/src/c25519/c25519.c
    externals/compact25519/src/c25519/f25519.c
    externals/compact25519/src/c25519/fprime.c
    externals/compact25519/src/compact_ed25519.c
    externals/compact25519/src/compact_x25519.c
    externals/compact25519/src/compact_wipe.c)
target_include_directories(compact25519 PUBLIC
    externals/compact25519/src
    externals/compact25519/src/c25519)
add_sanitizers(compact25519)

add_library(edhoc
    modules/edhoc/src/plaintext.c
    modules/edhoc/src/suites.c
    modules/edhoc/src/err_msg.c
    modules/edhoc/src/signature_or_mac_msg.c
    modules/edhoc/src/prk.c
    modules/edhoc/src/memcpy_s.c
    modules/edhoc/src/th.c
    modules/edhoc/src/edhoc_method_type.c
    modules/edhoc/src/byte_array.c
    modules/edhoc/src/hkdf_info.c
    modules/edhoc/src/crypto_wrapper.c
    modules/edhoc/src/edhoc_exporter.c
    modules/edhoc/src/cbor_decoder.c
    modules/edhoc/src/print_util.c
    modules/edhoc/src/initiator.c
    modules/edhoc/src/a_Xae_encode.c
    modules/edhoc/src/responder.c
    modules/edhoc/src/retrieve_cred.c
    modules/edhoc/src/okm.c)

target_include_directories(edhoc PUBLIC modules/edhoc)
target_compile_definitions(edhoc PUBLIC -DEDHOC_WITH_TINYCRYPT_AND_C25519)
target_link_libraries(edhoc compact25519 tinycrypt cbor)
add_sanitizers(edhoc)
set_strict_compiler_warnings(edhoc)

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
target_include_directories(oscore PUBLIC
    modules/oscore
    modules/oscore/inc)
target_link_libraries(oscore tinycrypt cbor)
target_compile_definitions(oscore PUBLIC -DOSCORE_WITH_TINYCRYPT)
add_sanitizers(oscore)
set_strict_compiler_warnings(oscore)

add_library(test_vectors
    test/src/test_vectors_edhoc.c
    test/src/test_vectors_oscore.c)
target_include_directories(test_vectors PUBLIC test/src)
target_link_libraries(test_vectors oscore edhoc)

option(BUILD_PLAYGROUND "Build playground" ON)
if(BUILD_PLAYGROUND)
    add_executable(playground playground/main.c)
    target_link_libraries(playground oscore cbor tinycrypt edhoc test_vectors)
    add_sanitizers(playground)
endif(BUILD_PLAYGROUND)
add_subdirectory(fuzz-test)
