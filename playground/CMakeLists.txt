
add_executable(playground main.c)
target_link_libraries(playground oscore cbor tinycrypt edhoc test_vectors)
add_sanitizers(playground)

#add_executable(edhoc_playground edhoc.c)
#target_link_libraries(edhoc_playground test_vectors edhoc cbor compact25519 tinycrypt)