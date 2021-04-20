
add_library(main_entry main_entry.c)
add_sanitizers(main_entry)

macro(add_fuzz arg)
    add_executable(${arg} ${arg}.c)
    add_sanitizers(${arg})
    target_link_libraries(${arg} main_entry ${ARGN})

endmacro(add_fuzz)

add_library(responder_credentials ../samples/edhoc_linux/responder/src/credentials.c)
target_include_directories(responder_credentials PUBLIC ../samples/edhoc_linux/responder/src)
add_sanitizers(responder_credentials)
add_library(initiator_credentials ../samples/edhoc_linux/initiator/src/credentials.c)
target_include_directories(initiator_credentials PUBLIC ../samples/edhoc_linux/initiator/src)
add_sanitizers(initiator_credentials)

add_fuzz(fuzz_buf2coap oscore)
add_fuzz(fuzz_oscore2coap oscore test_vectors)
add_fuzz(fuzz_msg1parse edhoc responder_credentials)