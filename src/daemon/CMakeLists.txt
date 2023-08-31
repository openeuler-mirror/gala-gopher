CMAKE_MINIMUM_REQUIRED(VERSION 3.5.2)
set(CMAKE_VERBOSE_MAKEFILE ON)
SET(CMAKE_CXX_COMPILER "/usr/bin/g++")

PROJECT(gala-gopher)

MESSAGE("ENV PROBES_LIST:\n"  ${PROBES_LIST})
MESSAGE("ENV PROBES_C_LIST:\n"  ${PROBES_C_LIST})
MESSAGE("ENV PROBES_META_LIST:\n"  ${PROBES_META_LIST})
MESSAGE("ENV LIBBPF_VER_MAJOR:\n"  ${LIBBPF_VER_MAJOR})
MESSAGE("ENV LIBBPF_VER_MINOR:\n"  ${LIBBPF_VER_MINOR})

SET(EXECUTABLE_OUTPUT_PATH ../../../)
SET(EXECUTABLE_TARGET gala-gopher)
SET(EXECUTABLE_TARGET_CMD gopher-ctl)

SET(SRC_DIR         ../../src)
SET(BASE_DIR        ${SRC_DIR}/lib)
SET(RESOURCE_DIR    ${SRC_DIR}/resource)
SET(CONFIG_DIR      ${SRC_DIR}/lib/config)
SET(EGRESS_DIR      ${SRC_DIR}/egress)
SET(INGRESS_DIR     ${SRC_DIR}/ingress)
SET(WEB_SERVER_DIR  ${SRC_DIR}/web_server)
SET(FIFO_DIR        ${SRC_DIR}/lib/fifo)
SET(META_DIR        ${SRC_DIR}/lib/meta)
SET(KAFKA_DIR       ${SRC_DIR}/lib/kafka)
SET(PROBE_DIR       ${SRC_DIR}/lib/probe)
SET(IMDB_DIR        ${SRC_DIR}/lib/imdb)
SET(CMD_DIR         ${SRC_DIR}/cmd)
SET(COMMON_DIR      ${SRC_DIR}/common)
SET(RESTAPI_DIR     ${SRC_DIR}/api)
SET(EBPF_PROBE_DIR  ${SRC_DIR}/probes/extends/ebpf.probe)

SET(LIBRDKAFKA_DIR /usr/include/librdkafka)
SET(LIBELF_DIR /usr/include/libelf)

SET(CMAKE_C_FLAGS "-rdynamic -std=gnu11 -g -Wl,-z,relro,-z,now -DNATIVE_PROBE_FPRINTF \
    -DPROBES_LIST=\"${PROBES_LIST}\" \
    -DPROBES_META_LIST=\"${PROBES_META_LIST}\" \
    -DLIBBPF_VER_MAJOR=\"${LIBBPF_VER_MAJOR}\" -DLIBBPF_VER_MINOR=\"${LIBBPF_VER_MINOR}\" "
)
SET(CMAKE_CXX_FLAGS "-rdynamic -std=c++11 -g -Wl,-z,relro,-z,now -DNATIVE_PROBE_FPRINTF")

SET(SOURCES main.c daemon.c
    ${RESOURCE_DIR}/resource.c
    ${CONFIG_DIR}/config.c
    ${EGRESS_DIR}/egress.c
    ${INGRESS_DIR}/ingress.c
    ${INGRESS_DIR}/event2json.c
    ${WEB_SERVER_DIR}/web_server.c

    ${FIFO_DIR}/fifo.c
    ${META_DIR}/meta.c
    ${KAFKA_DIR}/kafka.c

    ${PROBE_DIR}/probe.c
    ${PROBE_DIR}/extend_probe.c
    ${PROBE_DIR}/pod_mng.c
    ${PROBE_DIR}/probe_mng.c
    ${PROBE_DIR}/snooper.c
    ${PROBE_DIR}/probe_params_parser.c
    ${PROBE_DIR}/ext_label.c
    ${IMDB_DIR}/imdb.c
    ${IMDB_DIR}/metrics.c

    ${CMD_DIR}/server.c
    ${COMMON_DIR}/kern_config.c
    ${COMMON_DIR}/args.c
    ${COMMON_DIR}/container.c
    ${COMMON_DIR}/util.c
    ${COMMON_DIR}/object.c
    ${COMMON_DIR}/event.c
    ${COMMON_DIR}/logs.cpp
    ${COMMON_DIR}/gopher_elf.c
    ${COMMON_DIR}/event_config.c
    ${COMMON_DIR}/kern_symb.c
    ${COMMON_DIR}/ipc.c
    ${COMMON_DIR}/strbuf.c
    ${COMMON_DIR}/histogram.c

    ${RESTAPI_DIR}/rest_server.c
    ${EBPF_PROBE_DIR}/src/lib/java_support.c
)

SET(SOURCE_CMD ${CMD_DIR}/client.c)

FOREACH(FILE ${PROBES_C_LIST})
    SET(SOURCES ${SOURCES} ${FILE})
ENDFOREACH()
MESSAGE("SOURCES:\n" ${SOURCES})

if("${GOPHER_DEBUG}" EQUAL 1)
add_definitions(-DGOPHER_DEBUG)
endif()

ADD_EXECUTABLE(${EXECUTABLE_TARGET} ${SOURCES})
ADD_EXECUTABLE(${EXECUTABLE_TARGET_CMD} ${SOURCE_CMD})

TARGET_INCLUDE_DIRECTORIES(${EXECUTABLE_TARGET} PRIVATE
    ${BASE_DIR}
    ${RESOURCE_DIR}
    ${CONFIG_DIR}
    ${EGRESS_DIR}
    ${INGRESS_DIR}
    ${WEB_SERVER_DIR}
    ${RESTAPI_DIR}

    ${FIFO_DIR}
    ${META_DIR}
    ${KAFKA_DIR}

    ${PROBE_DIR}
    ${IMDB_DIR}
    ${LIBRDKAFKA_DIR}
    ${LIBELF_DIR}

    ${CMD_DIR}
    ${COMMON_DIR}
    ${EBPF_PROBE_DIR}/src/include
)

TARGET_LINK_LIBRARIES(${EXECUTABLE_TARGET} PRIVATE config pthread rt dl bpf rdkafka microhttpd elf log4cplus gnutls
cjson)


