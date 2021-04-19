
add_library(main_entry main_entry.c)
add_sanitizers(main_entry)

macro(add_fuzz arg)
    add_executable(${arg} ${arg}.c)
    add_sanitizers(${arg})
    target_link_libraries(${arg} main_entry ${ARGN})

endmacro(add_fuzz)

add_fuzz(fuzz_buf2coap oscore)
add_fuzz(fuzz_oscore2coap oscore test_vectors)