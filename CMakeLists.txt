cmake_minimum_required(VERSION 3.16)

set(DEMO_NAME libev-demo)
project(${DEMO_NAME} LANGUAGES C)

add_executable(${DEMO_NAME} main.c)

target_link_libraries(${DEMO_NAME} PRIVATE ev)
