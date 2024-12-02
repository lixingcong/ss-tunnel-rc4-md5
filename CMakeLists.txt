cmake_minimum_required(VERSION 3.16)

set(DEMO_NAME libev-demo)
project(${DEMO_NAME} LANGUAGES C)

add_executable(${DEMO_NAME}
    tunnel.c
    utils.c
    netutils.c
    udprelay.c
    common.c
    cache.c
)

target_compile_definitions(${DEMO_NAME} PUBLIC MODULE_TUNNEL)

target_link_libraries(${DEMO_NAME} PRIVATE ev)
