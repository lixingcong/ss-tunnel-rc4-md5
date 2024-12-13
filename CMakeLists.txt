cmake_minimum_required(VERSION 3.16)

set(BIN_TUNNEL ss-tunnel-rc4-md5)
project(${BIN_TUNNEL} LANGUAGES C)

aux_source_directory(. TUNNEL_SRC)
add_executable(${BIN_TUNNEL} ${TUNNEL_SRC})

target_compile_definitions(${BIN_TUNNEL} PUBLIC MODULE_TUNNEL)

target_link_libraries(${BIN_TUNNEL} PRIVATE ev)
target_link_libraries(${BIN_TUNNEL} PRIVATE m)


set(BUILD_TEST_CASE OFF CACHE BOOL "Build test cases")
if(BUILD_TEST_CASE)
    set(BIN_TEST_CASE test_case)

    add_executable(${BIN_TEST_CASE}
        test/main.c
        test/test_rc4.c
        test/test_cipher.c
        test/test_crypto_utils.c
        test/test_md5.c
        test/tap.c test/tap.h
        utils.c
        cork2.c
        crypto.c
        crypto-rc4-md5.c
        crypto_utils.c
        rc4.c
        md5.c
    )
endif()


