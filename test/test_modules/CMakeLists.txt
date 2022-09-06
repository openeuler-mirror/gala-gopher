CMAKE_MINIMUM_REQUIRED(VERSION 3.12.1)
SET(CMAKE_CXX_COMPILER "/usr/bin/g++")
PROJECT(gala-gopher-test)

SET(EXECUTABLE_OUTPUT_PATH ../../)
SET(EXECUTABLE_TARGET submodule_test)

SET(SRC_DIR         ../../src)
SET(BASE_DIR        ${SRC_DIR}/lib)
SET(COMMON_DIR      ${SRC_DIR}/common)
SET(CONFIG_DIR      ${SRC_DIR}/lib/config)
SET(EGRESS_DIR      ${SRC_DIR}/egress)
SET(INGRESS_DIR     ${SRC_DIR}/ingress)
SET(FIFO_DIR        ${SRC_DIR}/lib/fifo)
SET(META_DIR        ${SRC_DIR}/lib/meta)
SET(KAFKA_DIR       ${SRC_DIR}/lib/kafka)
SET(PROBE_DIR       ${SRC_DIR}/lib/probe)
SET(IMDB_DIR        ${SRC_DIR}/lib/imdb)
SET(WEBSERVER_DIR  ${SRC_DIR}/web_server)

SET(LIBRDKAFKA_DIR /usr/include/librdkafka)

SET(CMAKE_C_FLAGS "-g -DUTEST")
SET(CMAKE_CXX_FLAGS "-g -DUTEST")

ADD_EXECUTABLE(${EXECUTABLE_TARGET}
    main.c
    test_fifo.c
    test_kafka.c
    test_meta.c
    test_probe.c
    test_imdb.c
    test_logs.c
    ${COMMON_DIR}/args.c
    ${CONFIG_DIR}/config.c
    ${EGRESS_DIR}/egress.c
    ${INGRESS_DIR}/ingress.c
    ${FIFO_DIR}/fifo.c
    ${META_DIR}/meta.c
    ${KAFKA_DIR}/kafka.c
    ${PROBE_DIR}/probe.c
    ${PROBE_DIR}/extend_probe.c
    ${IMDB_DIR}/imdb.c
    ${IMDB_DIR}/metrics.c
    ${WEBSERVER_DIR}/web_server.c

    ${COMMON_DIR}/util.c
    ${COMMON_DIR}/logs.cpp
)

TARGET_INCLUDE_DIRECTORIES(${EXECUTABLE_TARGET} PRIVATE ${BASE_DIR}
    ${COMMON_DIR}
    ${CONFIG_DIR}
    ${EGRESS_DIR}
    ${INGRESS_DIR}
    ${FIFO_DIR}
    ${META_DIR}
    ${KAFKA_DIR}
    ${PROBE_DIR}
    ${IMDB_DIR}
    ${WEBSERVER_DIR}
    ${LIBRDKAFKA_DIR}
)

TARGET_LINK_LIBRARIES(${EXECUTABLE_TARGET} PRIVATE cunit config pthread dl rdkafka microhttpd rt log4cplus)

