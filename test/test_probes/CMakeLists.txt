CMAKE_MINIMUM_REQUIRED(VERSION 3.12.1)
SET(CMAKE_CXX_COMPILER "/usr/bin/g++")
PROJECT(gala-gopher-test)

MESSAGE("ENV PROBES_LIST:\n"  ${PROBES_LIST})
MESSAGE("ENV PROBES_C_LIST:\n"  ${PROBES_C_LIST})
MESSAGE("ENV PROBES_META_LIST:\n"  ${PROBES_META_LIST})

SET(EXECUTABLE_OUTPUT_PATH ../../)
SET(EXECUTABLE_TARGET probes_test)

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
SET(WEBSERVER_DIR   ${SRC_DIR}/web_server)

SET(LIBRDKAFKA_DIR /usr/include/librdkafka)

SET(CMAKE_C_FLAGS "-rdynamic -g -DNATIVE_PROBE_FPRINTF \
    -DPROBES_LIST=\"${PROBES_LIST}\" \
    -DPROBES_META_LIST=\"${PROBES_META_LIST}\" "
)
SET(CMAKE_CXX_FLAGS "-rdynamic -g -DNATIVE_PROBE_FPRINTF")

SET(SOURCES main.c test_probes.c
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
    ${COMMON_DIR}/object.c
    ${COMMON_DIR}/event.c
    ${COMMON_DIR}/logs.cpp
    ${COMMON_DIR}/whitelist_config.c
    ${COMMON_DIR}/event_config.c
)

FOREACH(FILE ${PROBES_C_LIST})
    SET(SOURCES ${SOURCES} ${FILE})
ENDFOREACH()
MESSAGE("SOURCES:\n" ${SOURCES})

ADD_EXECUTABLE(${EXECUTABLE_TARGET} ${SOURCES})
TARGET_INCLUDE_DIRECTORIES(${EXECUTABLE_TARGET} PRIVATE
    ${BASE_DIR}
    ${COMMON_DIR}
    ${CONFIG_DIR}
    ${EGRESS_DIR}
    ${INGRESS_DIR}

    ${FIFO_DIR}
    ${META_DIR}
    ${KAFKA_DIR}

    ${PROBE_DIR}
    ${LIBRDKAFKA_DIR}
    ${IMDB_DIR}
    ${WEBSERVER_DIR}
)

TARGET_LINK_LIBRARIES(${EXECUTABLE_TARGET} PRIVATE config pthread dl rdkafka microhttpd cunit rt bpf log4cplus)

