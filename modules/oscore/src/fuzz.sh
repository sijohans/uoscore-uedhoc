clang -g3 fuzz.c -I../inc -fsanitize=fuzzer,address coap.c memcpy_s.c -o buf2coap.o
./buf2coap.o

