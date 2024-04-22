CMAKE_MINIMUM_REQUIRED(VERSION 3.12.1)
SET(CMAKE_CXX_COMPILER "/usr/bin/g++")
PROJECT(gala-gopher-test)

SET(EXECUTABLE_OUTPUT_PATH ../../)
SET(EXECUTABLE_TARGET submodule_test)

SET(SRC_DIR         ../../src)
SET(BASE_DIR        ${SRC_DIR}/lib)
SET(RESOURCE_DIR    ${SRC_DIR}/resource)
SET(CONFIG_DIR      ${SRC_DIR}/lib/config)
SET(EGRESS_DIR      ${SRC_DIR}/egress)
SET(INGRESS_DIR     ${SRC_DIR}/ingress)
SET(WEB_SERVER_DIR  ${SRC_DIR}/web_server)
SET(FIFO_DIR        ${SRC_DIR}/lib/fifo)
SET(META_DIR        ${SRC_DIR}/lib/meta)
SET(PROBE_DIR       ${SRC_DIR}/lib/probe)
SET(IMDB_DIR        ${SRC_DIR}/lib/imdb)
SET(CMD_DIR         ${SRC_DIR}/cmd)
SET(COMMON_DIR      ${SRC_DIR}/common)
SET(RESTAPI_DIR     ${SRC_DIR}/api)
SET(HTTPSERVER_DIR  ${SRC_DIR}/lib/http_server)
SET(EBPF_PROBE_DIR  ${SRC_DIR}/probes/extends/ebpf.probe)


SET(CMAKE_C_FLAGS "-g -DUTEST")
SET(CMAKE_CXX_FLAGS "-g -DUTEST")

find_package(jsoncpp REQUIRED)
message("FOUND CONFIG: ${jsoncpp_CONFIG}")
get_target_property(JSON_INC_PATH jsoncpp_lib INTERFACE_INCLUDE_DIRECTORIES)
include_directories(${JSON_INC_PATH})

SET(SOURCES main.c
    test_fifo.c
    test_kafka.c
    test_meta.c
    test_imdb.c
    test_logs.c
    ${CONFIG_DIR}/config.c
    ${EGRESS_DIR}/egress.c
    ${INGRESS_DIR}/ingress.c
    ${INGRESS_DIR}/event2json.c

    ${FIFO_DIR}/fifo.c
    ${META_DIR}/meta.c
    ${HTTPSERVER_DIR}/http_server.c

    ${IMDB_DIR}/imdb.c
    ${IMDB_DIR}/metrics.c
    ${IMDB_DIR}/container_cache.c

    ${PROBE_DIR}/ext_label.c
    ${COMMON_DIR}/container.c
    ${COMMON_DIR}/util.c
    ${COMMON_DIR}/event.c
    ${COMMON_DIR}/logs.c
    ${COMMON_DIR}/json_tool.cpp
    ${COMMON_DIR}/strbuf.c
    ${COMMON_DIR}/histogram.c

    ${WEB_SERVER_DIR}/web_server.c
    ${EBPF_PROBE_DIR}/src/lib/java_support.c
)

SET(INC_DIRECTORIES
    ${BASE_DIR}
    ${RESOURCE_DIR}
    ${CONFIG_DIR}
    ${EGRESS_DIR}
    ${INGRESS_DIR}
    ${WEB_SERVER_DIR}
    ${RESTAPI_DIR}

    ${FIFO_DIR}
    ${META_DIR}

    ${PROBE_DIR}
    ${IMDB_DIR}
    ${LIBRDKAFKA_DIR}
    ${LIBELF_DIR}

    ${CMD_DIR}
    ${COMMON_DIR}
    ${JSON_INC_PATH}
    ${HTTPSERVER_DIR}
    ${EBPF_PROBE_DIR}/src/include
)

SET(LINK_LIBRARIES cunit config pthread dl rt jsoncpp_lib ssl event event_openssl crypto)

if(NOT DEFINED KAFKA_CHANNEL)
    SET(KAFKA_CHANNEL 1)
endif()

if("${KAFKA_CHANNEL}" EQUAL 1)
    add_definitions(-DKAFKA_CHANNEL)
    SET(KAFKA_DIR ${SRC_DIR}/lib/kafka)
    SET(SOURCES ${SOURCES} ${KAFKA_DIR}/kafka.c)
    SET(INC_DIRECTORIES ${INC_DIRECTORIES}  ${KAFKA_DIR})
    SET(LINK_LIBRARIES ${LINK_LIBRARIES} rdkafka)
endif()

ADD_EXECUTABLE(${EXECUTABLE_TARGET} ${SOURCES})
TARGET_INCLUDE_DIRECTORIES(${EXECUTABLE_TARGET} PRIVATE ${INC_DIRECTORIES})
TARGET_LINK_LIBRARIES(${EXECUTABLE_TARGET} PRIVATE ${LINK_LIBRARIES})