cmake_minimum_required(VERSION 3.22)
project(web_server C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

add_executable(web_server main.c)

TARGET_LINK_LIBRARIES(web_server curl cjson)
